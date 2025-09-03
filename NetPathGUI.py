#!/usr/bin/env python3
"""
NetPath GUI — stdlib-only traceroute visualizer
Python 3.10+, no external deps.

Features:
- Text input for host/IP, Start/Stop monitoring
- Repeated traceroute runs (default every 5s)
- Hop table: Hop#, Hostname, IP, Avg RTT, Loss %, Jitter, ASN, Org, Country
- Path graph on Canvas + per-hop time-series chart (RTT over time, with jitter overlay)
- RDAP (ownership/AS/country) via urllib (https). Caches results per IP.

Notes:
- Windows: requires built-in `tracert`
- Linux/macOS: requires `traceroute` in PATH
- The app never uses raw sockets; no admin/root needed.
"""

from __future__ import annotations

import sys
import os
import platform
import subprocess
import threading
import queue
import time
import re
import math
import json
from dataclasses import dataclass, field
from collections import deque, defaultdict
from typing import List, Dict, Optional, Tuple
import subprocess
import platform
import socket
import ipaddress

TRACE_BASE_TIMEOUT_SEC = 45.0      # minimum watchdog
TRACE_HARD_CAP_SEC = 340.0         # absolute upper bound per run

#def _popen_no_window_kwargs
def _popen_no_window_kwargs():
    """Return kwargs for subprocess.Popen that avoid opening a console window on Windows."""
    kwargs = {}
    if platform.system().lower().startswith("win"):
        # Hide the console window
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        # Older Python/Windows combos benefit from STARTUPINFO as well:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        kwargs["startupinfo"] = si
    return kwargs


# --- GUI (tkinter/ttk) ---
import tkinter as tk
from tkinter import ttk, messagebox

# --- HTTP (RDAP) ---
import urllib.request
import urllib.error

# --- Concurrency ---
from concurrent.futures import ThreadPoolExecutor

APP_TITLE = "Net Path"
TRACE_INTERVAL_SEC = 5.0
HISTORY_LEN = 600         # keep last 60 traceroute runs per hop
RAPID_REDRAW_MS = 250     # UI poll rate
TRACE_TIMEOUT_SEC = 30    # safety timeout per traceroute run
HTTP_TIMEOUT_SEC = 8

# ------------------------- Data Models -------------------------

@dataclass
class HopSample:
    """One traceroute measurement cycle for a hop."""
    hop: int
    hostname: Optional[str]
    ip: Optional[str]
    rtts_ms: List[Optional[float]]  # up to 3 RTTs in ms, None for timeout


@dataclass
class HopStats:
    hop: int
    hostname: Optional[str] = None
    ip: Optional[str] = None
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LEN))  # list[List[Optional[float]]]
    last_update_ts: float = field(default_factory=time.time)
    # Enrichment
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None

    def add_sample(self, sample: HopSample):
        self.hostname = sample.hostname or self.hostname
        self.ip = sample.ip or self.ip
        self.history.append(sample.rtts_ms)
        self.last_update_ts = time.time()

    def _flatten_successes(self) -> List[float]:
        vals = []
        for triple in self.history:
            for x in triple:
                if isinstance(x, (int, float)):
                    vals.append(float(x))
        return vals

    def avg_rtt(self) -> Optional[float]:
        vals = self._flatten_successes()
        return sum(vals)/len(vals) if vals else None

    def loss_pct(self) -> float:
        total = sum(len(triple) for triple in self.history)
        lost = sum(1 for triple in self.history for x in triple if x is None)
        return (100.0 * lost / total) if total else 0.0

    def jitter(self) -> Optional[float]:
        # mean absolute difference between consecutive successful RTTs (robust)
        seq = []
        for triple in self.history:
            for x in triple:
                if isinstance(x, (int, float)):
                    seq.append(float(x))
        if len(seq) < 2:
            return None
        diffs = [abs(b - a) for a, b in zip(seq[:-1], seq[1:])]
        return sum(diffs)/len(diffs)

    def recent_series(self, max_points: int = HISTORY_LEN) -> List[Optional[float]]:
        # Take the average of each triple for the time-series plot.
        series = []
        for triple in self.history:
            vals = [x for x in triple if isinstance(x, (int, float))]
            series.append(sum(vals)/len(vals) if vals else None)
        return series[-max_points:]


@dataclass
class TraceState:
    hops: Dict[int, HopStats] = field(default_factory=dict)

    def merge_sample(self, sample: HopSample):
        hs = self.hops.get(sample.hop)
        if not hs:
            hs = HopStats(hop=sample.hop)
            self.hops[sample.hop] = hs
        hs.add_sample(sample)

    def ordered(self) -> List[HopStats]:
        return [self.hops[k] for k in sorted(self.hops.keys())]

# ------------------------- RDAP Resolver -------------------------

class RdapResolver:
    def __init__(self, max_workers: int = 2):
        self.cache: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=max_workers)

    def submit(self, ip: str, callback):
        if not ip or ip == "*":
            return
        with self.lock:
            if ip in self.cache:
                asn, org, country = self.cache[ip]
                callback(ip, asn, org, country)
                return
        def task():
            result = self.lookup_ip(ip)
            with self.lock:
                self.cache[ip] = result
            callback(ip, *result)
        self.pool.submit(task)

    def close(self):
        self.pool.shutdown(wait=False)

    def _lookup_asn_cymru(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Query Team Cymru's whois service to map IP -> (ASN, AS Name).
        Returns (None, None) on failure or if not routable/private.
        """
        # Skip private/non-routable blocks
        try:
            ipobj = ipaddress.ip_address(ip)
            if (ipobj.is_private or ipobj.is_loopback or ipobj.is_link_local or
                ipobj.is_multicast or ipobj.is_reserved or ipobj.is_unspecified):
                return (None, None)
        except ValueError:
            return (None, None)

        try:
            with socket.create_connection(("whois.cymru.com", 43), timeout=HTTP_TIMEOUT_SEC) as s:
                # Bulk/verbose format: header + one line per query
                query = f"begin\nverbose\n{ip}\nend\n"
                s.sendall(query.encode("ascii", errors="ignore"))
                chunks = []
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            text = b"".join(chunks).decode("utf-8", errors="ignore")
            # Expected row format:
            # AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
            for line in text.splitlines():
                line = line.strip()
                if not line or line.lower().startswith(("as |", "bulk", "copyright")):
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 7:
                    asn, _ip, _prefix, _cc, _reg, _alloc, as_name = parts[:7]
                    if asn and asn.upper() != "NA":
                        return (f"AS{asn}", as_name if as_name else None)
        except Exception:
            pass
        return (None, None)


    # --- Core RDAP lookup (stdlib: urllib) ---
    def lookup_ip(self, ip: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Returns (asn, org, country)
        Strategy:
          1) RDAP for org/country (+ opportunistic ASN if present)
          2) Team Cymru WHOIS to resolve ASN (and AS Name as org fallback)
        """
        asn = None
        org = None
        country = None

        # 1) RDAP pass
        urls = [
            f"https://rdap.org/ip/{ip}",
            f"https://rdap.arin.net/registry/ip/{ip}",
            f"https://rdap.db.ripe.net/ip/{ip}",
            f"https://rdap.apnic.net/ip/{ip}",
            f"https://rdap.lacnic.net/rdap/ip/{ip}",
            f"https://rdap.afrinic.net/rdap/ip/{ip}",
        ]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NetPathGUI/1.1"})
                with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
                    if resp.status != 200:
                        continue
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    asn = asn or self._extract_asn(data)
                    # prefer org from RDAP entities/registrant
                    if not org:
                        org = self._extract_org(data)
                    if not country:
                        country = self._extract_country(data)
                    # break early if we already have everything
                    if asn and org and country:
                        break
            except Exception:
                continue

        # 2) Cymru fallback for ASN (and AS Name if org is missing)
        if not asn:
            cymru_asn, cymru_name = self._lookup_asn_cymru(ip)
            if cymru_asn:
                asn = cymru_asn
                if not org and cymru_name:
                    # If RDAP didn’t yield an org, use the AS Name
                    org = cymru_name

        return (asn, org, country)


    # --- RDAP parsing helpers ---
    def _extract_asn(self, data) -> Optional[str]:
        # Try remarks/origin, or entities with "autnum", or links to autnum
        # RDAP often provides "remarks" that include origin AS; be flexible.
        try:
            # Check remarks text
            for r in data.get("remarks", []):
                for line in r.get("description", []):
                    m = re.search(r"\bAS(\d+)\b", line, re.IGNORECASE)
                    if m:
                        return f"AS{m.group(1)}"
        except Exception:
            pass
        # Entities sometimes contain autnum in publicIds
        try:
            for e in data.get("entities", []):
                for pid in e.get("publicIds", []):
                    if pid.get("type", "").lower().startswith("autnum"):
                        return pid.get("identifier")
        except Exception:
            pass
        # Networks can include "originAutnum" per some deployments
        try:
            if "originAutnum" in data:
                return f"AS{data['originAutnum']}"
        except Exception:
            pass
        return None

    def _extract_org(self, data) -> Optional[str]:
        # Find an entity with a "registrant"/"administrative"/"owner" role
        try:
            for e in data.get("entities", []):
                roles = [r.lower() for r in e.get("roles", [])]
                if any(r in roles for r in ("registrant", "administrative", "owner", "registrar")):
                    fn = self._vcard_fn(e)
                    if fn:
                        return fn
            # fallback: any entity FN
            for e in data.get("entities", []):
                fn = self._vcard_fn(e)
                if fn:
                    return fn
        except Exception:
            pass
        # fallback: top-level "name"
        name = data.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        return None

    def _extract_country(self, data) -> Optional[str]:
        # prefer top-level 'country'
        c = data.get("country")
        if isinstance(c, str) and c.strip():
            return c.strip()
        # look in vcard 'adr' fields
        try:
            for e in data.get("entities", []):
                v = e.get("vcardArray")
                if isinstance(v, list) and len(v) == 2 and isinstance(v[1], list):
                    for item in v[1]:
                        if isinstance(item, list) and item and item[0] == "adr":
                            # vCard ADR: ['', {}, ['pobox','ext','street','locality','region','zip','country']]
                            arr = item[3] if len(item) > 3 else None
                            if isinstance(arr, list) and len(arr) >= 7 and arr[6]:
                                return str(arr[6])
        except Exception:
            pass
        return None

    def _vcard_fn(self, entity) -> Optional[str]:
        v = entity.get("vcardArray")
        if isinstance(v, list) and len(v) == 2 and isinstance(v[1], list):
            for item in v[1]:
                if isinstance(item, list) and item and item[0] == "fn":
                    # ["fn", {}, "text", "Org Name"]
                    if len(item) >= 4 and isinstance(item[3], str):
                        return item[3].strip()
        return None

# ------------------------- Traceroute Runner -------------------------

class TraceRunner(threading.Thread):
    def __init__(self, target: str, out_queue: queue.Queue,
                 interval: float = TRACE_INTERVAL_SEC, max_hops: int = 30,
                 run_id: int = 0):
        super().__init__(daemon=True)
        self.target = target.strip()
        self.out_queue = out_queue
        self.interval = max(1.0, interval)
        self.max_hops = max_hops
        self._stop = threading.Event()
        self._proc = None               #  keep handle to child process
        self.run_id = run_id            #  tag all messages

    def _estimate_timeout(self) -> float:
        # We probe 3 times per hop with per-probe timeout ~1s (we pass -w 1000 on Win, -w 1 on Unix)
        per_probe_sec = 1.0
        probes = 3
        est = self.max_hops * probes * per_probe_sec + 10.0  # a little slack
        return max(TRACE_BASE_TIMEOUT_SEC, min(est, TRACE_HARD_CAP_SEC))

    def stop(self):
        self._stop.set()
        p = getattr(self, "_proc", None)
        if p:
            try:
                p.kill()
            except Exception:
                pass
      
    def run(self):
        while not self._stop.is_set():
            start = time.time()
            try:
                samples = self._run_once()
                self.out_queue.put(("trace", samples))
            except Exception as e:
                #self.out_queue.put(("error", str(e)))
                self.out_queue.put(("error", self.run_id, str(e)))
            # sleep until next tick (account for elapsed, but don’t drift negative)
            elapsed = time.time() - start
            remaining = max(0.0, self.interval - elapsed)
            self._stop.wait(remaining)

    # --- One traceroute run ---
    def _run_once(self) -> List[HopSample]:
        cmd, parser = self._build_cmd_and_parser()
        if not cmd:
            raise RuntimeError(self._no_traceroute_message())

        popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, universal_newlines=True, bufsize=1)
        popen_kwargs.update(_popen_no_window_kwargs())

        try:
            self._proc = subprocess.Popen(cmd, **popen_kwargs)
        except FileNotFoundError:
            raise RuntimeError(self._no_traceroute_message())

        lines = []
        deadline = time.time() + self._estimate_timeout()
        last_progress = time.time()
        idle_grace_sec = 8.0

        try:
            while True:
                if self._stop.is_set():
                    try: self._proc.kill()
                    except Exception: pass
                    return []  # canceled; don’t emit anything

                if time.time() > deadline and (time.time() - last_progress) > idle_grace_sec:
                    try: self._proc.kill()
                    except Exception: pass
                    raise RuntimeError("Traceroute timed out.")

                line = self._proc.stdout.readline()
                if not line:
                    if self._proc.poll() is not None:
                        break
                    time.sleep(0.02)
                    continue

                line = line.rstrip()
                if not line:
                    continue
                lines.append(line)

                # stream single-line parses
                try:
                    hop_samples = parser([line])
                    if hop_samples:
                        self.out_queue.put(("trace", self.run_id, hop_samples))  # TAGGED
                        last_progress = time.time()
                except Exception:
                    pass

            # end-of-run parse
            final_samples = parser(lines)
            return final_samples

        finally:
            try:
                self._proc.kill()
            except Exception:
                pass
            self._proc = None
       
    def old_run_once(self) -> List[HopSample]:
        cmd, parser = self._build_cmd_and_parser()
        if not cmd:
            raise RuntimeError(self._no_traceroute_message())

        popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, universal_newlines=True, bufsize=1)
        popen_kwargs.update(_popen_no_window_kwargs())

        try:
            proc = subprocess.Popen(cmd, **popen_kwargs)
        except FileNotFoundError:
            raise RuntimeError(self._no_traceroute_message())

        lines: list[str] = []
        deadline = time.time() + self._estimate_timeout()
        last_progress = time.time()
        idle_grace_sec = 8.0  # if we haven’t seen a hop line for this long, allow timeout

        try:
            while True:
                # hard cap guard
                if time.time() > deadline and (time.time() - last_progress) > idle_grace_sec:
                    proc.kill()
                    raise RuntimeError("Traceroute timed out.")

                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.02)
                    continue

                line = line.rstrip()
                if not line:
                    continue

                lines.append(line)

                # STREAMING: parse just this line
                try:
                    hop_samples = parser([line])
                    if hop_samples:
                        self.out_queue.put(("trace", hop_samples))
                        last_progress = time.time()  # we’re still making progress
                except Exception:
                    pass

            # final parse (harmless if duplicates)
            return parser(lines)

        finally:
            try:
                proc.kill()
            except Exception:
                pass

    def _build_cmd_and_parser(self):
        system = platform.system().lower()
        if system.startswith("win"):
            # Windows tracert: Sample line:
            #  1     1 ms     1 ms     1 ms  router [192.168.1.1]
            cmd = ["tracert", "-h", str(self.max_hops), "-w", "1000", self.target]
            return cmd, self._parse_windows
        else:
            # Unix traceroute: Sample line:
            #  1  router (192.168.1.1)  1.123 ms  1.234 ms  1.101 ms
            # if traceroute missing, subprocess will raise FileNotFoundError
            cmd = ["traceroute", "-m", str(self.max_hops), "-q", "3", "-w", "1", self.target]
            return cmd, self._parse_unix

    def _no_traceroute_message(self) -> str:
        if platform.system().lower().startswith("win"):
            return "Could not run 'tracert'. Is it available on this system?"
        else:
            return "Could not run 'traceroute'. Please install it (e.g., apt/yum/brew)."

    # --- Parsers ---

    def _parse_windows(self, lines: List[str]) -> List[HopSample]:
        samples: List[HopSample] = []
        hop_line_re = re.compile(r"^\s*(\d+)\s+(.*)$")
        # Windows often shows: hop, then three RTT columns, then host [ip] or just ip
        # Example good lines:
        #  2     2 ms     2 ms     2 ms  10.0.0.1
        #  5     *        *        *     Request timed out.
        #  6    15 ms    15 ms    14 ms  example.net [93.184.216.34]
        for raw in lines:
            m = hop_line_re.match(raw)
            if not m:
                continue
            hop = int(m.group(1))
            rest = m.group(2)
            # Capture three RTT tokens (either "*", "<1 ms", "1 ms", "123 ms")
            rtt_tokens = []
            token_re = re.compile(r"(<\d+\s*(?:ms|мс)|\d+(?:\.\d+)?\s*(?:ms|мс)|\*)", re.IGNORECASE)

            for t in token_re.findall(rest):
                rtt_tokens.append(t.strip())
                if len(rtt_tokens) >= 3:
                    break
            if len(rtt_tokens) < 3:
                # sometimes the hostname appears before all RTTs; try a more permissive parse
                parts = rest.split()
                # gather items ending with 'ms' or '*'
                for p in parts:
                    if p == "*" or p.lower().endswith("ms"):
                        rtt_tokens.append(p)
                        if len(rtt_tokens) >= 3:
                            break
            # Extract host/IP (after RTTs)
            tail = rest
            for t in rtt_tokens:
                tail = tail.split(t, 1)[-1]
            tail = tail.strip(" -\t")
            hostname, ip = None, None
            # cases: "host [1.2.3.4]"  or just "1.2.3.4"  or "Request timed out."
            ip_m = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", tail)
            if ip_m:
                ip = ip_m.group(1)
                hostname = tail.split("[", 1)[0].strip() or None
            else:
                ip_m2 = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", tail)
                if ip_m2:
                    ip = ip_m2.group(1)
                    # sometimes hostname precedes ip
                    pre = tail.split(ip, 1)[0].strip()
                    hostname = pre if pre and "timed out" not in pre.lower() else None
            rtts = []
            for t in rtt_tokens:
                if t == "*":
                    rtts.append(None)
                else:
                    num = re.sub(r"[^\d.]", "", t)
                    try:
                        rtts.append(float(num))
                    except ValueError:
                        rtts.append(None)
            # pad to 3
            while len(rtts) < 3:
                rtts.append(None)
            samples.append(HopSample(hop=hop, hostname=hostname, ip=ip, rtts_ms=rtts[:3]))
        return samples

    def _parse_unix(self, lines: List[str]) -> List[HopSample]:
        samples: List[HopSample] = []
        hop_line_re = re.compile(r"^\s*(\d+)\s+(.*)$")
        for raw in lines:
            m = hop_line_re.match(raw)
            if not m:
                continue
            hop = int(m.group(1))
            rest = m.group(2).strip()
            # Examples:
            # "router (192.168.1.1)  1.123 ms  1.234 ms  1.101 ms"
            # "* * *"
            if rest.startswith("*"):
                samples.append(HopSample(hop, None, None, [None, None, None]))
                continue
            hostname, ip = None, None
            ip_m = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", rest)
            if ip_m:
                ip = ip_m.group(1)
                hostname = rest.split("(", 1)[0].strip() or None
            else:
                # sometimes traceroute -n has only IP
                ip_m2 = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
                if ip_m2:
                    ip = ip_m2.group(1)
            # RTTs:
            rtt_tokens = re.findall(r"(\d+(?:\.\d+)?)\s*ms|\*", rest)
            # re.findall with alternation returns tuples; handle carefully
            ms_vals = []
            star_count = 0
            for tup in rtt_tokens:
                if isinstance(tup, tuple):
                    val = tup[0]
                else:
                    val = tup
                if val == "" or val is None:
                    # it's likely the '*' alt
                    star_count += 1
                else:
                    try:
                        ms_vals.append(float(val))
                    except ValueError:
                        ms_vals.append(None)
            # unify into 3 entries:
            rtts: List[Optional[float]] = []
            for v in ms_vals[:3]:
                rtts.append(v if isinstance(v, (int, float)) else None)
            # add stars if needed
            while len(rtts) < 3:
                if star_count > 0:
                    rtts.append(None)
                    star_count -= 1
                else:
                    rtts.append(None)
            samples.append(HopSample(hop=hop, hostname=hostname, ip=ip, rtts_ms=rtts[:3]))
        return samples

# ------------------------- UI Components -------------------------

class HopTable(ttk.Frame):
    COLS = ("hop", "hostname", "ip", "avg", "loss", "jitter", "asn", "org", "country")

    def __init__(self, master, on_select):
        super().__init__(master)
        self.tree = ttk.Treeview(self, columns=self.COLS, show="headings", height=20)
        headings = {
            "hop": "Hop",
            "hostname": "Hostname",
            "ip": "IP",
            "avg": "Avg RTT (ms)",
            "loss": "Loss %",
            "jitter": "Jitter (ms)",
            "asn": "ASN",
            "org": "Org",
            "country": "Country",
        }
        widths = {
            "hop": 40, "hostname": 180, "ip": 120, "avg": 100, "loss": 70, "jitter": 100,
            "asn": 80, "org": 220, "country": 80,
        }
        for c in self.COLS:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor=tk.W)
        self.tree.bind("<<TreeviewSelect>>", lambda e: on_select(self.selected_hop()))
        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.on_select_cb = on_select

    def selected_hop(self) -> Optional[int]:
        sel = self.tree.selection()
        if not sel:
            return None
        item = self.tree.item(sel[0])
        vals = item.get("values", [])
        if not vals:
            return None
        try:
            return int(vals[0])
        except Exception:
            return None

    def upsert_row(self, hs: HopStats):
        iid = f"hop-{hs.hop}"
        avg = f"{hs.avg_rtt():.1f}" if hs.avg_rtt() is not None else "-"
        jitter = f"{hs.jitter():.1f}" if hs.jitter() is not None else "-"
        loss = f"{hs.loss_pct():.0f}"
        vals = (hs.hop, hs.hostname or "-", hs.ip or "-", avg, loss, jitter,
                hs.asn or "-", hs.org or "-", hs.country or "-")
        if iid in self.tree.get_children(""):
            self.tree.item(iid, values=vals)
        else:
            self.tree.insert("", "end", iid=iid, values=vals)

    def clear(self):
        for iid in self.tree.get_children(""):
            self.tree.delete(iid)

    def reorder(self):
        """Ensure rows are ordered by the numeric Hop column."""
        children = list(self.tree.get_children(''))
        # remember selection to restore after moves
        selected = set(self.tree.selection())

        pairs = []
        for iid in children:
            vals = self.tree.item(iid, 'values') or ()
            try:
                hop = int(vals[0])
            except Exception:
                hop = 10**9  # push unknowns to the bottom
            pairs.append((hop, iid))

        pairs.sort(key=lambda x: x[0])
        for idx, (_, iid) in enumerate(pairs):
            self.tree.move(iid, '', idx)

        # restore selection
        if selected:
            self.tree.selection_set([iid for _, iid in pairs if iid in selected])

            
class PathGraph(ttk.Frame):
    """Canvas with two views:
    - top: path graph (nodes & edges)
    - bottom: time-series RTT chart for selected hop
    """
    def __init__(self, master, on_pick_hop):
        super().__init__(master)
        self.canvas = tk.Canvas(self, bg="#ffffff", height=360)
        self.chart = tk.Canvas(self, bg="#fafafa", height=180)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.chart.grid(row=1, column=0, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.grid_columnconfigure(0, weight=1)
        self.on_pick_hop = on_pick_hop
        self._nodes_bbox: Dict[int, Tuple[int,int,int,int]] = {}
        self._selected_hop: Optional[int] = None
        self.canvas.bind("<Button-1>", self._on_click)

    def set_selected(self, hop: Optional[int]):
        self._selected_hop = hop

    def draw_path(self, stats: List[HopStats]):
        self.canvas.delete("all")
        self._nodes_bbox.clear()
        if not stats:
            self.canvas.create_text(10, 10, anchor="nw", text="No data yet.", fill="#555")
            return
        w = self.canvas.winfo_width() or 600
        h = self.canvas.winfo_height() or 360
        n = len(stats)
        pad = 40
        y = h//2
        radius = 16
        # compute X positions
        xs = [pad + int((w - 2*pad) * i / max(1, n-1)) for i in range(n)]
        # draw edges
        for i in range(n-1):
            self.canvas.create_line(xs[i]+radius, y, xs[i+1]-radius, y, width=2, fill="#888")
        # draw nodes
        for i, hs in enumerate(stats):
            x = xs[i]
            color = "#4b9cd3" if (self._selected_hop or 0) != hs.hop else "#1f6fbf"
            # loss coloring hint
            loss = hs.loss_pct()
            if loss >= 50:
                color = "#d94c4c"
            elif loss >= 20:
                color = "#f0a202"
            self.canvas.create_oval(x-radius, y-radius, x+radius, y+radius, fill=color, outline="")
            label = hs.ip or "?"
            self.canvas.create_text(x, y, text=str(hs.hop), fill="white", font=("TkDefaultFont", 9, "bold"))
            self.canvas.create_text(x, y+radius+12, text=label, fill="#333", font=("TkDefaultFont", 9))
            # store bbox for click hit testing
            self._nodes_bbox[hs.hop] = (x-radius, y-radius, x+radius, y+radius)

    def draw_chart(self, hs: Optional[HopStats]):
        self.chart.delete("all")
        w = self.chart.winfo_width() or 600
        h = self.chart.winfo_height() or 180
        pad = 32
        # axes
        self.chart.create_rectangle(pad, 10, w-10, h-30, outline="#ddd")
        if not hs:
            self.chart.create_text(12, 12, anchor="nw", text="Select a hop to view RTT history.", fill="#555")
            return
        series = hs.recent_series()
        if not series:
            self.chart.create_text(12, 12, anchor="nw", text="No RTT samples yet.", fill="#555")
            return
        # compute scale
        valid = [v for v in series if isinstance(v, (int, float))]
        if not valid:
            self.chart.create_text(12, 12, anchor="nw", text="All samples are timeouts.", fill="#555")
            return
        vmin, vmax = min(valid), max(valid)
        if vmin == vmax:
            vmax = vmin + 1.0
        # polyline
        coords = []
        for i, v in enumerate(series):
            x = pad + int((w - pad - 10) * (i / max(1, len(series)-1)))
            if v is None:
                # gap: we’ll skip drawing a point
                coords.append(None)
                continue
            y = 10 + int((h - 40) * (1 - (v - vmin)/(vmax - vmin)))
            coords.append((x, y))
        # draw connected segments
        prev = None
        for p in coords:
            if p is None:
                prev = None
                continue
            if prev is not None:
                self.chart.create_line(prev[0], prev[1], p[0], p[1], width=2)
            prev = p
        # labels
        self.chart.create_text(w-12, 12, anchor="ne", text=f"Avg: {hs.avg_rtt():.1f} ms" if hs.avg_rtt() is not None else "Avg: -", fill="#333")
        self.chart.create_text(w-12, 28, anchor="ne", text=f"Jitter: {hs.jitter():.1f} ms" if hs.jitter() is not None else "Jitter: -", fill="#333")
        self.chart.create_text(w-12, 44, anchor="ne", text=f"Loss: {hs.loss_pct():.0f}%", fill="#333")
        # y-axis min/max
        self.chart.create_text(pad-6, h-30, anchor="ne", text=f"{vmin:.1f}", fill="#666")
        self.chart.create_text(pad-6, 10, anchor="ne", text=f"{vmax:.1f}", fill="#666")
        self.chart.create_text(pad, h-16, anchor="w", text=f"Hop {hs.hop} – {hs.ip or ''}", fill="#333", font=("TkDefaultFont", 9, "bold"))

    def _on_click(self, event):
        # hit test nodes
        for hop, (x1, y1, x2, y2) in self._nodes_bbox.items():
            if x1 <= event.x <= x2 and y1 <= event.y <= y2:
                if callable(self.on_pick_hop):
                    self.on_pick_hop(hop)
                break


class DetailsPanel(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.vars = {k: tk.StringVar(value="-") for k in ("hop","ip","host","asn","org","country")}
        grid = ttk.Frame(self)
        grid.pack(anchor="nw", padx=8, pady=8, fill="x")
        def row(r, label, key):
            ttk.Label(grid, text=label, width=8).grid(row=r, column=0, sticky="w")
            ttk.Label(grid, textvariable=self.vars[key]).grid(row=r, column=1, sticky="w")
        row(0, "Hop:", "hop")
        row(1, "IP:", "ip")
        row(2, "Host:", "host")
        row(3, "ASN:", "asn")
        row(4, "Org:", "org")
        row(5, "Country:", "country")

    def update_from(self, hs: Optional[HopStats]):
        if not hs:
            for k in self.vars:
                self.vars[k].set("-")
            return
        self.vars["hop"].set(str(hs.hop))
        self.vars["ip"].set(hs.ip or "-")
        self.vars["host"].set(hs.hostname or "-")
        self.vars["asn"].set(hs.asn or "-")
        self.vars["org"].set(hs.org or "-")
        self.vars["country"].set(hs.country or "-")


# ------------------------- Main Application -------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(1050, 600)
        self._run_seq = 0
        self._current_run_id = 0

        # top toolbar
        top = ttk.Frame(self)
        top.pack(side="top", fill="x", padx=8, pady=8)
        ttk.Label(top, text="Target:").pack(side="left")
        self.target_var = tk.StringVar(value="1.1.1.1")
        self.entry = ttk.Entry(top, textvariable=self.target_var, width=40)
        self.entry.pack(side="left", padx=6)
        self.btn_start = ttk.Button(top, text="Start", command=self.on_start)
        self.btn_stop  = ttk.Button(top, text="Stop", command=self.on_stop, state="disabled")
        self.btn_start.pack(side="left", padx=4)
        self.btn_stop.pack(side="left", padx=4)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(top, textvariable=self.status_var, foreground="#555").pack(side="right")

        # main panes
        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        # left: table
        left = ttk.Frame(paned)
        self.table = HopTable(left, on_select=self._on_table_select)
        self.table.pack(fill="both", expand=True)
        paned.add(left, weight=1)

        # right: graph + details
        right = ttk.Frame(paned)
        self.graph = PathGraph(right, on_pick_hop=self._on_graph_pick)
        self.graph.pack(fill="both", expand=True)
        self.details = DetailsPanel(right)
        self.details.pack(fill="x")
        paned.add(right, weight=1)

        # state
        self.trace_state = TraceState()
        self.ui_queue: queue.Queue = queue.Queue()
        self.runner: Optional[TraceRunner] = None
        self.rdap = RdapResolver(max_workers=2)
        self._selected_hop: Optional[int] = None

        # UI poller
        self.after(RAPID_REDRAW_MS, self._ui_tick)

        # handle close
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _drain_queue(self):
        try:
            while True:
                self.ui_queue.get_nowait()
                self.ui_queue.task_done()
        except queue.Empty:
            pass
            
    # --- UI handlers ---
    def on_start(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "Please enter a hostname or IP.")
            return

        # Stop previous run cleanly
        if self.runner:
            self.runner.stop()
            try:
                self.runner.join(timeout=2.0)  # ensure thread has exited
            except Exception:
                pass
            self.runner = None

        # Fresh state
        self._drain_queue()
        self.table.clear()
        self.trace_state = TraceState()
        self._selected_hop = None

        # New run id
        self._run_seq += 1
        self._current_run_id = self._run_seq

        # Start new runner with run_id
        self.runner = TraceRunner(target=target,
                                  out_queue=self.ui_queue,
                                  interval=TRACE_INTERVAL_SEC,
                                  max_hops=30,
                                  run_id=self._current_run_id)
        self.runner.start()
        self.status_var.set(f"Tracing {target} every {TRACE_INTERVAL_SEC:.0f}s…")
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")


    def on_stop(self):
        if self.runner:
            self.runner.stop()
            try:
                self.runner.join(timeout=2.0)
            except Exception:
                pass
            self.runner = None
        self.status_var.set("Stopped")
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")

    def on_close(self):
        self.on_stop()
        self.rdap.close()
        self.destroy()

    def _on_table_select(self, hop: Optional[int]):
        self._selected_hop = hop
        self.graph.set_selected(hop)
        self._refresh_details_and_chart()

    def _on_graph_pick(self, hop: Optional[int]):
        self._selected_hop = hop
        self.graph.set_selected(hop)
        # also select row in table if present
        if hop is not None:
            iid = f"hop-{hop}"
            try:
                self.table.tree.selection_set(iid)
                self.table.tree.see(iid)
            except Exception:
                pass
        self._refresh_details_and_chart()

    # --- Main UI loop tick ---
    def _ui_tick(self):
        try:
            while True:
                msg = self.ui_queue.get_nowait()
                if not msg:
                    break
                kind = msg[0]
                if kind in ("trace", "error", "rdap"):
                    run_id = msg[1]
                    if run_id != self._current_run_id:
                        # stale message from a previous run — drop it
                        self.ui_queue.task_done()
                        continue
                    payload = msg[2]
                    if kind == "trace":
                        samples = payload
                        self._merge_samples(samples)
                    elif kind == "rdap":
                        ip, asn, org, country = payload
                        self._apply_rdap(ip, asn, org, country)
                    elif kind == "error":
                        self.status_var.set(f"Error: {payload}")
                self.ui_queue.task_done()
        except queue.Empty:
            pass

        self._refresh_table_and_graph()
        self._refresh_details_and_chart()
        self.after(RAPID_REDRAW_MS, self._ui_tick)


    # --- Update state from samples ---
    def _merge_samples(self, samples: List[HopSample]):
        for s in samples:
            if s.hop <= 0:
                continue
            self.trace_state.merge_sample(s)
            hs = self.trace_state.hops.get(s.hop)
            if hs and hs.ip and not (hs.asn or hs.org or hs.country):
                ip = hs.ip
                # capture current run_id in the closure
                run_id = self._current_run_id
                self.rdap.submit(ip, lambda ip_, asn, org, country, run_id=run_id:
                                       self._rdap_callback(run_id, ip_, asn, org, country))


    def _rdap_callback(self, run_id: int, ip: str, asn: Optional[str],
                       org: Optional[str], country: Optional[str]):
        self.ui_queue.put(("rdap", run_id, (ip, asn, org, country)))


    def _apply_rdap(self, ip: str, asn: Optional[str], org: Optional[str], country: Optional[str]):
        # Map all hops with this IP (rare but possible in MPLS) and fill in metadata
        for hs in self.trace_state.hops.values():
            if hs.ip == ip:
                hs.asn = asn
                hs.org = org
                hs.country = country
                try:
                    ipobj = ipaddress.ip_address(hs.ip)
                    if ipobj.is_private:
                        hs.asn = hs.asn or "—"
                        hs.org = hs.org or "Private address space"
                        hs.country = hs.country or "—"
                except Exception:
                    pass
    # --- Redraw helpers ---
    def _refresh_table_and_graph(self):
        stats = self.trace_state.ordered()
        for hs in stats:
            self.table.upsert_row(hs)
        # NEW: enforce numeric ordering in the Treeview regardless of insert order
        self.table.reorder()
        self.graph.draw_path(stats)

    def _refresh_details_and_chart(self):
        hs = None
        if self._selected_hop is not None:
            hs = self.trace_state.hops.get(self._selected_hop)
        self.details.update_from(hs)
        self.graph.draw_chart(hs)

# ------------------------- Entry Point -------------------------

def main():
    app = App()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
