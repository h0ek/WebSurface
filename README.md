# WebSurface

Web attack surface discovery and origin exposure triage (Cloudflare/CDN aware).

Use only on assets you own or have explicit authorization to test.

## Features

- Passive subdomain discovery and DNS resolution (A, AAAA, CNAME).
- HTTP/HTTPS verification per hostname and IP, preserving Host and TLS SNI.
- Cloudflare and CDN classification with potential backend identification.
- TCP port scanning and service fingerprinting on explicitly authorized candidate IPs.
- Optional screenshots and SQLite reports.
- CSV, JSON and text reports with execution status and tool logs.

## Requirements

- Linux, Bash and Python 3.9+.
- [subfinder](https://github.com/projectdiscovery/subfinder), [dnsx](https://github.com/projectdiscovery/dnsx) and [curl](https://curl.se/).
- Optional: [httpx](https://github.com/projectdiscovery/httpx) with pinned JSON target support; otherwise curl is used without technology fingerprinting.
- Port scanning: [naabu](https://github.com/projectdiscovery/naabu) and [nmap](https://github.com/nmap/nmap).
- Screenshots: [gowitness](https://github.com/sensepost/gowitness) v3 and a compatible Chromium browser.

Tools must be available in `$PATH`.

## Usage

Clone the repository:

```bash
git clone https://github.com/h0ek/WebSurface.git
cd WebSurface
```

Provide one root domain per line in `domains.txt` (no URLs or wildcards).

```bash
./websurface.sh -i domains.txt
```

By default, HTTP/HTTPS probes are limited to publicly routable DNS addresses of in-scope hosts. Redirects are recorded but not followed. Direct port scanning requires an explicit allowlist of authorized IP addresses or CIDRs, one per line:

```bash
./websurface.sh -i domains.txt -a authorized-ips.txt
```

The allowlist also restricts HTTP probes and does not expand discovery beyond DNS-derived addresses.

| Option | Description |
| --- | --- |
| `-i FILE` | Root domains file (required) |
| `-a FILE` | Authorized IP/CIDR file |
| `-t N` | Gowitness threads (default: 30) |
| `-r N` | Naabu rate (default: 2000) |
| `-n N` | Parallel Nmap jobs (default: 4) |
| `-o DIR` | Output directory (must not exist) |
| `--screenshots` | Enable screenshots |
| `--browser-egress-restricted` | Acknowledge external browser egress restrictions |
| `--version` | Show version |
| `-h` | Show help |

### Screenshots

```bash
./websurface.sh -i domains.txt -a authorized-ips.txt --screenshots --browser-egress-restricted
```

Screenshots require an external network policy restricting browser traffic to authorized destinations and ports. The acknowledgement flag does not configure or verify that policy. Browser screenshots are URL-level evidence, not verification of a pinned IP.

Open an existing Gowitness report locally:

```bash
gowitness report server --host 127.0.0.1 --port 7171 \
  --db-uri sqlite:///absolute/path/to/run/gowitness/gowitness.sqlite3 \
  --screenshot-path /absolute/path/to/run/gowitness/screenshots
```

For rejected pages, use the corresponding database and screenshot directory under `gowitness_rejected/` and a different port.

## Output

Each run creates a new `run_YYYYMMDD_HHMMSS_microseconds/` directory by default.

| Path | Content |
| --- | --- |
| `summary.txt`, `summary.json` | Execution status and findings |
| `subdomains/`, `dns/`, `cf/` | Discovery, DNS and Cloudflare data |
| `httpx/triage.csv`, `httpx/verified.jsonl` | Verified HTTP responses |
| `scan/origin_ips_strict_v4.txt`, `scan/origin_ips_strict_v6.txt` | Potential backend IPs |
| `scan/origin_ip_open_v4.txt`, `scan/origin_ip_open_v6.txt` | Additional open TCP endpoints |
| `nmap/summary.txt` | Service fingerprints |
| `gowitness/`, `gowitness_rejected/` | Optional screenshots and databases |
| `logs/` | Tool diagnostics |

Exit codes: `0` completed, `2` invalid input or missing prerequisites, `3` incomplete assessment, `130` interrupted.

## Limitations

- CDN classification is heuristic; unavailable Cloudflare ranges are classified as unknown.
- HTTP verification covers ports 80 and 443. The curl fallback accepts untrusted TLS certificates for discovery.
- TCP scanning uses the selected top-100 port set excluding 80/443; it is not a full TCP or UDP assessment. Nmap performs service fingerprinting without NSE scripts.
- Candidate IPs and open ports do not prove origin exposure or CDN/WAF bypass. Validate findings manually. A completed run does not rule out exposure.

## License

[MIT](LICENSE)
