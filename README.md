# WebSurface

Web attack surface discovery + origin exposure triage (Cloudflare/CDN aware).

WebSurface takes a list of root domains, discovers subdomains, resolves them to IPs, probes HTTP/HTTPS services, classifies CDN vs non-CDN signals, and flags potential origin/back-end IP exposure (non-Cloudflare, not “cdnish”, web-alive).  
It then scans candidate origin IPs (top ports) and produces an Nmap summary + screenshots.

Use only on assets you own or have explicit authorization to test.

## What it does (pipeline)

1. **Subdomain discovery** (passive) – `subfinder`
2. **DNS resolve A/AAAA** – `dnsx` (JSON)
3. **Cloudflare IP range classification** – CF ranges + `grepcidr`
4. **HTTP probe + enrichment** – `httpx` (status/title/ip/cname/cdn hints)
5. **Strict “origin candidate” selection**
   - only web-alive IPs
   - **not** in Cloudflare IP ranges
   - **not** “cdnish” (cdn flag / cname patterns / cdn_name)
6. **Port scan on candidates** – `naabu` (top 100; excludes 80/443)
7. **Service fingerprint** – `nmap -sV` (+ safe scripts subset), summary report
8. **Visual triage** – `gowitness` screenshots + sqlite DB

## Requirements

Tools (must be in `$PATH`):

- `subfinder`, `dnsx`, `httpx`, `naabu`, `nmap`, `gowitness`
- `jq`, `curl`, `grepcidr`
- standard unix utils: `awk sed grep sort tr wc xargs find`

## Usage

Input file: one root domain per line.

```bash
./websurface.sh -i domains.txt
# optional:
#   -t  gowitness threads (default 30)
#   -r  naabu rate (default 2000)
#   -n  parallel nmap jobs (default 4)
#   -o  output dir
```

Each run creates:

```
run_YYYYMMDD_HHMMSS/
  subdomains/  dns/  cf/  httpx/  scan/  nmap/  gowitness/  logs/
```

## Key outputs

- `httpx/triage.csv` – fast overview (url, ip, status, title, cdn/cname, tech)
- `scan/origin_ips_strict_v4.txt` / `strict_v6.txt` – candidate origin IPs
- `scan/origin_ip_open_v4.txt` / `open_v6.txt` – open IP:PORT pairs (80/443 filtered)
- `nmap/summary.txt` – what services were found on candidate origin IPs
- `gowitness/screenshots/` + `gowitness.sqlite3` – screenshots + DB

Run local report UI:

```
gowitness report server \
  --host 127.0.0.1 --port 7171 \
  --db-uri sqlite:///PATH/TO/run_*/gowitness/gowitness.sqlite3 \
  --screenshot-path PATH/TO/run_*/gowitness/screenshots
```

## How to read the verdict

- **strict candidate IPs** = unique IPs that look like real backend targets
- **open endpoints** = IP:PORT pairs from naabu (one IP can have many ports)
- **nmap targets** = IPs that had any ports after filtering

If you see: `Potential origin exposure detected`
 → open `nmap/summary.txt` and verify whether the services/headers/certs match the public site.

## Notes / limitations

- CDN detection is heuristic (“cdnish” signals can be false positives/negatives).
- Some origins are intentionally hidden (WAF challenges, geo blocks, auth gates).
- Don’t treat findings as confirmed exposure without manual validation.

## Tools Used
WebSurface is only an orchestrator. All credit goes to the original authors of these amazing tools:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [httpx](https://github.com/projectdiscovery/httpx)
- [naabu](https://github.com/projectdiscovery/naabu)
- [nmap](https://github.com/nmap/nmap)
- [gowitness](https://github.com/sensepost/gowitness)

Huge thanks to all tool authors.
