# WebSurface

Web attack surface discovery + origin exposure triage (Cloudflare/CDN aware).

WebSurface discovers subdomains, resolves A/AAAA records, verifies HTTP/HTTPS services per hostname and IP, and identifies potential non-CDN backend candidates. It can scan explicitly authorized candidate IPs for additional TCP services and optionally capture screenshots.

Use only on assets you own or have explicit authorization to test. A DNS record, shared hosting address or CDN relationship does not establish authorization for direct IP scanning.

## What it does (pipeline)

1. **Subdomain discovery** (passive) – `subfinder`, restricted to the supplied root domains and their subdomains.
2. **DNS resolution** – `dnsx` A, AAAA and CNAME records.
3. **Cloudflare classification** – official IPv4/IPv6 ranges; unavailable or invalid ranges produce an unknown classification.
4. **HTTP verification** – pinned hostname/IP pairs, preserving Host and TLS SNI. Uses ProjectDiscovery `httpx` when its pinned JSON input passes a local preflight; otherwise uses `curl`. Redirect destinations are recorded but never followed. HTTP error responses are also service evidence.
5. **Candidate selection** – verified HTTP responses on IPs outside known Cloudflare ranges, without observed CDN signals. Screenshot quality does not affect candidate selection.
6. **Port scan** – `naabu` against explicitly authorized candidates only, using the TCP top-100 set with 80/443 excluded before scanning.
7. **Service fingerprinting** – `nmap -sV`, with per-target timeouts and output validation.
8. **Optional visual triage** – `gowitness` screenshots and SQLite databases, with separate clean and rejected URL lists.

## Requirements

- Linux, Bash, Python 3.9+ and `curl`.
- `subfinder`, `dnsx` in `$PATH`.
- ProjectDiscovery `httpx` with pinned JSON target support is optional. Older versions use the curl fallback, which does not provide Wappalyzer technology fingerprints.
- `naabu` and `nmap` for direct IP port scanning.
- Gowitness v3 and a compatible Chromium browser for optional screenshots.

## Usage

`domains.txt` contains one root domain per line. Blank lines and lines beginning with `#` are ignored. Enter domain names only, without URLs or wildcard prefixes.

```bash
./websurface.sh -i domains.txt
```

Without an explicit IP allowlist, WebSurface only probes publicly routable DNS addresses using the in-scope virtual host. It does not run Naabu or Nmap.

For an authorized IP-level assessment, provide an additional file containing only IP addresses or CIDRs covered by the rules of engagement:

```bash
./websurface.sh -i domains.txt -a authorized-ips.txt
```

When `-a` is supplied, HTTP probes are also restricted to those IPs. The allowlist never expands discovery to arbitrary addresses within a CIDR; only addresses associated with in-scope DNS names are considered. Loopback, link-local, multicast, unspecified and reserved addresses are excluded.

| Option | Description |
| --- | --- |
| `-i FILE` | Root domains file (required) |
| `-a FILE` | Explicitly authorized IP addresses/CIDRs |
| `-t N` | Gowitness threads (default: 30) |
| `-r N` | Naabu rate (default: 2000) |
| `-n N` | Parallel Nmap jobs (default: 4) |
| `-o DIR` | New output directory; must not already exist |
| `--screenshots` | Enable Gowitness under the conditions below |
| `--browser-egress-restricted` | Acknowledge externally enforced browser scope restrictions |
| `--version` | Print version |
| `-h` | Show help |

The default output directory is `run_YYYYMMDD_HHMMSS_microseconds/` next to the script. Files and directories are created with a restrictive umask. Proxy environment variables are not inherited by probes.

### Screenshots

Browser traffic is disabled by default. A browser may follow redirects, load third-party resources, or resolve hosts again. Only enable screenshots in an environment where an independent network policy restricts browser egress to the authorized destinations and ports. The acknowledgement flag does not configure or verify a firewall.

```bash
./websurface.sh -i domains.txt -a authorized-ips.txt --screenshots --browser-egress-restricted
```

Known out-of-scope redirect sources are excluded from screenshot inputs. Screenshots are URL-level visual evidence, not proof of a response from a particular pinned IP.

Run the local report UI against an existing screenshot database:

```bash
gowitness report server --host 127.0.0.1 --port 7171 \
  --db-uri sqlite:///absolute/path/to/run/gowitness/gowitness.sqlite3 \
  --screenshot-path /absolute/path/to/run/gowitness/screenshots
```

For rejected pages, use `gowitness_rejected/gowitness_rejected.sqlite3`, its `screenshots/` directory and a different local port. The clean list contains selected HTTP statuses without obvious challenge titles; rejected pages may include errors, access-denied pages or challenges.

## Key outputs

- `summary.txt` / `summary.json` – execution status, counts, issues and evidence-based verdict.
- `subdomains/subdomains_all.txt` and `subdomains/rejected.txt` – in-scope hosts and rejected discovery results.
- `dns/dns.json` and `dns/host_ip.csv` – raw DNS results and host-to-IP mappings.
- `httpx/httpx.json` – raw HTTP probe results (including curl fallback records when used).
- `httpx/verified.jsonl` and `httpx/triage.csv` – verified HTTP responses and enrichment.
- `httpx/unreported.jsonl` – targets missing a success/failure result.
- `httpx/redirects_out_of_scope.txt` – initial URLs with an observed out-of-scope redirect.
- `scan/unknown_cf_ips_v4.txt` / `scan/unknown_cf_ips_v6.txt` – IPs with unavailable Cloudflare classification.
- `scan/origin_ips_strict_v4.txt` / `scan/origin_ips_strict_v6.txt` – heuristic candidate IPs.
- `scan/origin_ips_authorized_v4.txt` / `scan/origin_ips_authorized_v6.txt` – candidates eligible for port scanning.
- `scan/origin_scope_unapproved.txt` and `scan/http_scope_skipped.csv` – candidates and mappings withheld from active steps.
- `scan/origin_ip_open_v4.txt` / `scan/origin_ip_open_v6.txt` – additional open TCP endpoints, with bracketed IPv6 notation.
- `nmap/targets_v4.map` / `nmap/targets_v6.map` and `nmap/summary.txt` – service scan inputs and reports.
- `gowitness/` and `gowitness_rejected/` – optional screenshots and databases.
- `logs/` – tool diagnostics and local HTTP preflight output.

## How to read the verdict

- Exit `0`: requested stages completed, or were intentionally skipped because they had no eligible targets. This does not establish that exposure is absent.
- Exit `2`: invalid input, missing dependency or unusable output directory.
- Exit `3`: incomplete run or failed stage; inspect `summary.json` and logs before drawing conclusions.
- Exit `130`: interrupted run.

Candidate IPs are unique addresses with verified HTTP service evidence and no observed CDN indicators. Open endpoints are IP/port pairs. An additional open port on a candidate is not confirmation that the public application is exposed directly or that a CDN/WAF is bypassable.

## Notes / limitations

- CDN detection is heuristic. Shared IPs, hosting providers and unobserved CDN indicators require manual review.
- HTTP verification is limited to HTTP/80 and HTTPS/443 for DNS-discovered host/IP pairs; redirects are not followed. HTTP probe failures are not evidence that a service does not exist.
- The curl fallback accepts untrusted TLS certificates for discovery; it does not validate TLS trust or provide Wappalyzer technology fingerprints.
- The TCP port scan excludes 80/443 and is not a full port or UDP scan. Nmap fingerprints selected services without NSE scripts.
- An upstream tool may return success with incomplete results. WebSurface checks reported errors and available output, but cannot prove full coverage.
- Browser egress restrictions must be enforced outside WebSurface.
- Validate findings manually against the actual authorized service, ownership and security architecture.

## Tests

```bash
bash -n websurface.sh
python3 -B -m unittest discover -s tests -v
```

The regression suite uses mocked external tools and a local loopback HTTP server. It does not scan external targets.

## Tools Used

WebSurface is an orchestrator. All credit goes to the original tool authors:

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [httpx](https://github.com/projectdiscovery/httpx)
- [curl](https://curl.se/)
- [naabu](https://github.com/projectdiscovery/naabu)
- [nmap](https://github.com/nmap/nmap)
- [gowitness](https://github.com/sensepost/gowitness)
