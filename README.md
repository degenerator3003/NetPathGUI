# NetPath GUI (stdlib-only Python traceroute visualizer)

Cross-platform traceroute GUI using only Python 3.10 stdlib (tkinter, subprocess, urllib).
- Live table of hops (RTT avg, loss %, jitter)
- Graph view of the path + per-hop RTT history
- Ownership info: ASN / Org / Country (RDAP + Team Cymru WHOIS)
- No third-party packages; no admin privileges

## Requirements
- Python 3.10+
- Windows: `tracert` (built-in)
- Linux/macOS: `traceroute` in PATH (install via your package manager)

## Run
```bash
python3 netpath_gui.py
```

Enter a target (e.g., 1.1.1.1) and click Start. Click rows/nodes to see details.

## Notes

ASN lookup uses Team Cymru WHOIS over port 43 (std lib socket) and RDAP over HTTPS (urllib). Results are cached.

Please be respectful of external services: keep default intervals, avoid aggressive polling.

This software is provided “as is” (see LICENSE).

## Credits

IP/ASN data: RDAP registries; Team Cymru IP-to-ASN service.

Trademarks are property of their respective owners.
