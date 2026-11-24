import argparse
import csv
import ipaddress
import html
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urljoin, urlsplit

VERSION = '0.4'
CDN = re.compile(r'cloudflare|cloudfront|fastly|akamai|edgesuite|edgekey|azureedge|azurefd|cdn77|stackpath|incapdns|impervadns|sucuri|vercel-dns|netlify|pantheonsite|wpengine|siteground|nginxcdn|cachefly|gcore|gcdn', re.I)
CHALLENGE = re.compile(r'just a moment|attention required|access denied|request blocked|are you human|captcha|ddos|checking your browser', re.I)
SHOT_CODES = {200, 301, 302, 307, 308, 401, 403}
PROXY_ENV = {k: v for k, v in os.environ.items() if k.lower() not in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}}
PROXY_ENV['NO_PROXY'] = '*'


def positive(value):
    n = int(value)
    if not 1 <= n <= 100000:
        raise argparse.ArgumentTypeError('expected an integer between 1 and 100000')
    return n


def domain(value):
    value = value.strip().lower().removesuffix('.')
    value = value.encode('idna').decode('ascii')
    if len(value) > 253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in value.split('.')):
        raise ValueError(f'invalid domain: {value!r}')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('expected a domain, not an IP address')


def in_scope(host, roots):
    return any(host == root or host.endswith('.' + root) for root in roots)


def address(value):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('invalid IP address')
    ip = ipaddress.ip_address(value)
    if getattr(ip, 'ipv4_mapped', None) is not None:
        raise ValueError('IPv4-mapped IPv6 is not supported')
    return ip


def contains(ip, networks):
    return any(ip.version == net.version and ip in net for net in networks)


def allowed_http(ip, networks):
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    return contains(ip, networks) if networks else ip.is_global


def lines(path):
    return [s.strip() for s in path.read_text(encoding='utf-8').splitlines() if s.strip() and not s.lstrip().startswith('#')]


def write_lines(path, values):
    path.write_text(''.join(f'{v}\n' for v in values), encoding='utf-8')


def write_jsonl(path, rows):
    write_lines(path, (json.dumps(row, ensure_ascii=True) for row in rows))


def list_field(row, key):
    value = row.get(key)
    if value is None:
        return []
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return value
    raise ValueError(f'invalid {key} field')


def csv_value(value):
    if isinstance(value, list):
        value = ';'.join(map(str, value))
    if value is None:
        return ''
    if isinstance(value, str):
        value = value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
        if value.lstrip().startswith(('=', '+', '-', '@')):
            value = "'" + value
    return value


def endpoint(ip, port):
    return f'[{ip}]:{port}' if ip.version == 6 else f'{ip}:{port}'


def redirect_scope(url, location, roots):
    if not location:
        return 'none'
    if '\\' in location or any(ord(ch) < 32 or ord(ch) == 127 for ch in location):
        return 'out_of_scope'
    try:
        dest = urlsplit(urljoin(url, location))
        if dest.scheme not in {'http', 'https'} or dest.username or dest.password or dest.port not in {None, 80 if dest.scheme == 'http' else 443}:
            return 'out_of_scope'
        return 'in_scope' if in_scope(domain(dest.hostname or ''), roots) else 'out_of_scope'
    except (ValueError, UnicodeError):
        return 'out_of_scope'


def http_key(row):
    data = json.loads(row['input'])
    url = data['target'].rstrip('/')
    ip = address(data['ip'])
    return url, ip


def http_flags(config):
    return ['httpx', '-config', str(config), '-duc', '-silent', '-j', '-nfs', '-probe', '-location', '-title', '-td', '-sc', '-cl', '-server', '-ip', '-cname', '-cdn', '-timeout', '10', '-rl', '200']


def curl_probe(run, target):
    url, ip = target
    host = urlsplit(url).hostname
    port = urlsplit(url).port or (443 if url.startswith('https:') else 80)
    pinned = f'[{ip}]' if ip.version == 6 else str(ip)
    identity = {'target': url, 'ip': str(ip)}
    row = {'input': json.dumps(identity), 'url': url, 'host_ip': str(ip), 'port': port, 'backend': 'curl'}
    with tempfile.TemporaryDirectory(prefix='probe-', dir=run.root / 'httpx') as temp:
        body, headers = Path(temp) / 'body', Path(temp) / 'headers'
        cmd = ['curl', '-q', '-sS', '-k', '--noproxy', '*', '--proto', '=http,https', '--globoff', '--max-redirs', '0', '--connect-timeout', '5', '--max-time', '10', '--max-filesize', '1048576', '--resolve', f'{host}:{port}:{pinned}', '-D', str(headers), '-o', str(body), '-w', '%{http_code}\n%{remote_ip}\n', url]
        try:
            result = subprocess.run(cmd, capture_output=True, env=PROXY_ENV, timeout=15, check=False)
            rc = result.returncode
            parts = result.stdout.decode('ascii', 'replace').splitlines()
            row['curl_rc'] = rc
            row['error'] = result.stderr.decode('utf-8', 'replace')[:2048]
            status = int(parts[0]) if parts else 0
            if status and (len(parts) < 2 or address(parts[1]) != ip):
                raise ValueError('curl peer does not match pinned target')
            if 100 <= status <= 599 and rc in {0, 18, 28, 56, 63}:
                blocks = re.split(r'\r?\n\r?\n', headers.read_text(encoding='latin1') if headers.exists() else '')
                block = next((b for b in reversed(blocks) if b.startswith('HTTP/')), '')
                hdr = {}
                for line in block.splitlines()[1:]:
                    key, sep, val = line.partition(':')
                    if sep:
                        hdr[key.lower()] = val.strip()
                text = body.read_bytes()[:1048576].decode('utf-8', 'replace') if body.exists() else ''
                title = re.search(r'<title\b[^>]*>(.*?)</title\s*>', text, re.I | re.S)
                row.update(status_code=status, title=html.unescape(title.group(1)).strip() if title else '', webserver=hdr.get('server', ''), content_length=hdr.get('content-length', ''), location=hdr.get('location', ''), cdn=bool(CDN.search(hdr.get('server', '')) or any(k in hdr for k in ('cf-ray', 'x-amz-cf-id', 'x-served-by', 'via'))), failed=False)
                return row, None
            row['failed'] = True
            if rc in {7, 28, 35, 52, 55, 56, 60, 92, 97}:
                return row, None
            return row, f'curl probe {url} [{ip}] returned {rc} without a usable response'
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            row['failed'] = True
            return row, f'curl probe {url} [{ip}]: {exc}'


def curl_fallback(run, targets, output):
    print('[*] curl pinned HTTP fallback (technology fingerprints unavailable)', flush=True)
    with ThreadPoolExecutor(max_workers=min(20, len(targets))) as pool, output.open('w', encoding='utf-8') as f:
        for row, issue in pool.map(lambda target: curl_probe(run, target), targets):
            f.write(json.dumps(row, ensure_ascii=True) + '\n')
            if issue:
                run.issue('httpx: ' + issue)
    run.status['httpx'] = 'OK' if not any(i.startswith('httpx:') for i in run.issues) else 'ERROR(curl fallback partial)'
    run.status['http_backend'] = 'curl (no Wappalyzer fingerprints)'


class Run:
    def __init__(self, root):
        self.root = root
        self.status = {}
        self.issues = []
        for directory in ('subdomains', 'dns', 'cf', 'httpx', 'scan', 'nmap', 'gowitness/screenshots', 'gowitness_rejected/screenshots', 'logs'):
            (root / directory).mkdir(parents=True, exist_ok=True)
        self.config = root / 'logs/empty.yaml'
        self.config.write_text('{}\n', encoding='utf-8')

    def issue(self, message):
        self.issues.append(message)
        print(f'[WARN] {message}', flush=True)

    def command(self, name, args, output=None, timeout=1800):
        output = output or self.root / 'logs' / f'{name}.out'
        error = self.root / 'logs' / f'{name}.err'
        with output.open('wb') as out, error.open('wb') as err:
            try:
                with subprocess.Popen(args, stdout=out, stderr=err, env=PROXY_ENV, start_new_session=True) as process:
                    try:
                        return process.wait(timeout=timeout)
                    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                        if isinstance(exc, KeyboardInterrupt):
                            raise
                        err.write(b'\nWebSurface: subprocess timed out\n')
                        return 124
            except OSError as exc:
                err.write(str(exc).encode('utf-8', 'replace'))
                return 127

    def stage(self, name, args, output=None, timeout=1800):
        print(f'[*] {name}', flush=True)
        rc = self.command(name, args, output, timeout)
        self.status[name] = 'OK' if rc == 0 else f'ERROR({rc})'
        if rc:
            self.issue(f'{name} returned {rc}')
        return rc

    def json_rows(self, path, stage):
        for index, line in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError('expected object')
                yield row
            except (ValueError, TypeError) as exc:
                self.issue(f'{stage}: invalid JSON on line {index}: {exc}')

    def cf(self, version):
        output = self.root / f'cf/cf_ipv{version}.txt'
        rc = self.stage(f'cf_v{version}', ['curl', '-q', '-fsS', '--noproxy', '*', '--proto', '=https', '--connect-timeout', '5', '--max-time', '15', '--max-filesize', '1048576', f'https://www.cloudflare.com/ips-v{version}'], output, 20)
        if rc:
            return None
        try:
            networks = [ipaddress.ip_network(line, strict=True) for line in lines(output)]
            if not networks or any(n.version != version or n.prefixlen == 0 or not n.network_address.is_global for n in networks):
                raise ValueError('empty or invalid range list')
            return networks
        except ValueError as exc:
            self.status[f'cf_v{version}'] = 'ERROR(invalid ranges)'
            self.issue(f'Cloudflare IPv{version} ranges: {exc}')
            return None

    def preflight(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get('Host'))
                self.send_response(302)
                self.send_header('Location', 'https://outside.invalid/')
                self.end_headers()

            def log_message(self, *args):
                pass

        with HTTPServer(('127.0.0.1', 0), Handler) as server:
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            target = f'http://websurface-check.invalid:{port}'
            source = self.root / 'logs/httpx_preflight.input'
            out = self.root / 'logs/httpx_preflight.jsonl'
            write_jsonl(source, [{'target': target, 'ip': '127.0.0.1'}])
            try:
                rc = self.stage('httpx_preflight', http_flags(self.config) + ['-allow', '127.0.0.1', '-l', str(source)], out, 35)
            finally:
                server.shutdown()
                thread.join()
        valid = False
        for row in self.json_rows(out, 'httpx_preflight'):
            try:
                valid |= (http_key(row) == (target, address('127.0.0.1')) and address(row['host_ip']) == address('127.0.0.1') and row['status_code'] == 302 and row['url'].rstrip('/') == target)
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
        if rc or not valid or seen != [f'websurface-check.invalid:{port}']:
            self.status['httpx_preflight'] = 'ERROR(pinning or redirect check)'
            self.issue('httpx pinned JSON preflight failed; switching to curl without sending HTTP probes through httpx')
            return False
        return True

    def summarize(self, counts, verdict):
        state = 'INCOMPLETE' if self.issues else 'COMPLETE'
        report = {'version': VERSION, 'state': state, 'stages': self.status, 'counts': counts, 'issues': self.issues, 'verdict': verdict}
        (self.root / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        text = ['================== SUMMARY ==================', f'Run dir: {self.root}', f'Status: {state}', '', 'Stages:']
        text.extend(f'  {k}: {v}' for k, v in self.status.items())
        text.extend(['', 'Counts:'])
        text.extend(f'  {k}: {v}' for k, v in counts.items())
        text.extend(['', 'Verdict: ' + verdict])
        if self.issues:
            text.extend(['', 'Issues:'] + [f'  {i}' for i in self.issues])
        write_lines(self.root / 'summary.txt', text)
        print('\n'.join(text), flush=True)
        return 3 if self.issues else 0


def nmap_job(run, item):
    ip, ports = item
    name = f'v{ip.version}_{str(ip).replace(":", "_")}'
    base = run.root / 'nmap' / name
    args = ['nmap'] + (['-6'] if ip.version == 6 else []) + ['-n', '-Pn', '-sT', '-sV', '--version-light', '-T3', '--host-timeout', '3m', '-p', ','.join(map(str, sorted(ports))), '-oA', str(base), str(ip)]
    rc = run.command('nmap_' + name, args, timeout=240)
    if rc:
        return name, f'ERROR({rc})'
    try:
        root = ET.parse(Path(str(base) + '.xml')).getroot()
        hosts = root.findall('host')
        matching = [h for h in hosts if any(address(a.get('addr')) == ip for a in h.findall('address') if a.get('addrtype') in {'ipv4', 'ipv6'})]
        finished = root.find('runstats/finished')
        if len(matching) != 1 or finished is None or finished.get('exit') != 'success' or not Path(str(base) + '.nmap').is_file():
            raise ValueError('missing host or completed output')
        host = matching[0]
        reported = {int(p.get('portid')) for p in host.findall('ports/port') if p.get('protocol') == 'tcp' and p.find('state') is not None}
        extra = sum(int(p.get('count')) for p in host.findall('ports/extraports'))
        if host.get('timedout') in {'true', '1'} or not reported.issubset(ports) or len(reported) + extra != len(ports):
            raise ValueError('host timeout or incomplete port coverage')
    except (OSError, ET.ParseError, ValueError, TypeError) as exc:
        return name, f'ERROR({exc})'
    return name, 'OK'


def pipeline(run, roots, networks, args):
    r = run.root
    counts = {'input_domains': len(roots)}
    write_lines(r / 'domains.txt', sorted(roots))
    sf = r / 'subdomains/subfinder.txt'
    run.stage('subfinder', ['subfinder', '-dL', str(r / 'domains.txt'), '-all', '-recursive', '-silent', '-duc'], sf)
    hosts = set(roots)
    rejected = []
    for line in lines(sf):
        try:
            host = domain(line)
            if in_scope(host, roots):
                hosts.add(host)
            else:
                rejected.append(line)
        except (ValueError, UnicodeError):
            rejected.append(line)
    write_lines(r / 'subdomains/rejected.txt', rejected)
    write_lines(r / 'subdomains/subdomains_all.txt', sorted(hosts))
    counts['hosts'] = len(hosts)
    raw_dns = r / 'dns/dns.json'
    run.stage('dnsx', ['dnsx', '-l', str(r / 'subdomains/subdomains_all.txt'), '-a', '-aaaa', '-cname', '-cdn', '-j', '-silent', '-duc'], raw_dns)
    pairs = set()
    dns_cdn = set()
    dns_cnames = {}
    for row in run.json_rows(raw_dns, 'dnsx'):
        try:
            host = domain(row['host'])
            if host not in hosts:
                raise ValueError('unexpected host')
            for key, version in [('a', 4), ('aaaa', 6)]:
                for value in list_field(row, key):
                    ip = address(value)
                    if ip.version != version:
                        raise ValueError('wrong address family')
                    pairs.add((host, ip))
            cnames = list_field(row, 'cname')
            dns_cnames.setdefault(host, set()).update(cnames)
            if CDN.search(' '.join(cnames)) or row.get('cdn-name') or row.get('cdn_name') or row.get('cdn') is True:
                dns_cdn.add(host)
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            run.issue(f'dnsx: invalid record: {exc}')
    if not raw_dns.stat().st_size and run.status.get('dnsx') == 'OK':
        run.issue('dnsx: no records returned; resolution coverage is unknown')
        run.status['dnsx'] = 'ERROR(no records)'
    pairs = sorted(pairs, key=lambda p: (p[0], p[1].version, int(p[1])))
    write_lines(r / 'dns/subdomains_resolved.txt', sorted({h for h, _ in pairs}))
    write_lines(r / 'dns/host_ip.csv', (f'{h},{ip}' for h, ip in pairs))
    counts['dns_pairs'] = len(pairs)
    all_ips = {ip for _, ip in pairs}
    write_lines(r / 'scan/ips_all.txt', sorted(map(str, all_ips)))
    cf = {}
    for v in (4, 6):
        ips = sorted(ip for ip in all_ips if ip.version == v)
        write_lines(r / f'scan/ips_v{v}.txt', ips)
        cf[v] = run.cf(v) if ips else None
        if not ips:
            run.status[f'cf_v{v}'] = 'SKIPPED(no addresses)'
        for prefix, selected in [('cf_ips', [ip for ip in ips if cf[v] is not None and contains(ip, cf[v])]), ('origin_ips', [ip for ip in ips if cf[v] is not None and not contains(ip, cf[v])]), ('unknown_cf_ips', ips if cf[v] is None else [])]:
            write_lines(r / f'scan/{prefix}_v{v}.txt', selected)
    dns_ok = run.status.get('dnsx') == 'OK' and not any(i.startswith('dnsx:') for i in run.issues)
    permitted = [(host, ip) for host, ip in pairs if dns_ok and allowed_http(ip, networks)]
    write_lines(r / 'scan/http_scope_skipped.csv', (f'{h},{ip}' for h, ip in pairs if not dns_ok or not allowed_http(ip, networks)))
    targets = {(f'{scheme}://{host}', ip) for host, ip in permitted for scheme in ('http', 'https')}
    input_file = r / 'httpx/targets.jsonl'
    write_jsonl(input_file, ({'target': url, 'ip': str(ip)} for url, ip in sorted(targets, key=lambda x: (x[0], x[1].version, int(x[1])))))
    counts['http_targets'] = len(targets)
    counts['http_scope_skipped_pairs'] = sum(not allowed_http(ip, networks) for _, ip in pairs)
    counts['http_dns_error_skipped_pairs'] = len(pairs) - len(permitted) - counts['http_scope_skipped_pairs']
    raw_http = r / 'httpx/httpx.json'
    raw_http.touch()
    if targets:
        before = len(run.issues)
        try:
            pinned = shutil.which('httpx') and run.preflight()
        except OSError as exc:
            print(f'[WARN] HTTP preflight unavailable: {exc}', flush=True)
            pinned = False
        if pinned:
            run.status['http_backend'] = 'httpx pinned JSON'
            allow_file = r / 'httpx/allowed_ips.txt'
            write_lines(allow_file, sorted({str(ip) for _, ip in targets}))
            run.stage('httpx', http_flags(run.config) + ['-allow', str(allow_file), '-l', str(input_file)], raw_http, 3600)
        else:
            del run.issues[before:]
            run.status['httpx_preflight'] = 'FALLBACK(pinned JSON unavailable)'
            curl_fallback(run, sorted(targets, key=lambda x: (x[0], x[1].version, int(x[1]))), raw_http)
    else:
        run.status['httpx'] = 'SKIPPED(no targets)'
    rows = []
    seen = set()
    for row in run.json_rows(raw_http, 'httpx'):
        try:
            key = http_key(row)
            if key not in targets or key in seen:
                raise ValueError('unexpected or duplicate target/address')
            url, ip = key
            if row.get('failed') is True or row.get('probe_status') == 'failed':
                seen.add(key)
                continue
            if address(row['host_ip']) != ip or row['url'].rstrip('/') != url:
                raise ValueError('HTTP peer or URL does not match pinned target')
            status = row['status_code']
            if type(status) is not int or not 100 <= status <= 599:
                raise ValueError('invalid HTTP status')
            if row.get('final_url') and row['final_url'].rstrip('/') != url:
                raise ValueError('unexpected redirect following')
            seen.add(key)
            host = urlsplit(url).hostname
            cdn = bool(host in dns_cdn or row.get('cdn') is True or row.get('cdn_name') or row.get('cdn-name') or CDN.search(str(row.get('cname', ''))))
            cf_state = 'unknown' if cf[ip.version] is None else ('cloudflare' if contains(ip, cf[ip.version]) else 'non-cloudflare')
            location = row.get('location') or ''
            if not isinstance(location, str):
                raise ValueError('invalid redirect location')
            redirect = redirect_scope(url, location, roots)
            clean = status in SHOT_CODES and not CHALLENGE.search(str(row.get('title') or ''))
            rows.append({**row, 'cname': row.get('cname') or sorted(dns_cnames.get(host, ())), 'url': url, 'host': host, 'host_ip': str(ip), 'cdnish': cdn, 'cf_state': cf_state, 'redirect_scope': redirect, 'screenshot_clean': clean})
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            run.issue(f'httpx: invalid record: {exc}')
    if targets - seen and run.status['httpx'] != 'SKIPPED(no targets)':
        run.issue(f'httpx: {len(targets - seen)} targets lack a success or failure record')
    write_jsonl(r / 'httpx/verified.jsonl', rows)
    write_jsonl(r / 'httpx/unreported.jsonl', ({'target': u, 'ip': str(ip)} for u, ip in sorted(targets - seen, key=lambda x: (x[0], x[1].version, int(x[1])))))
    fields = ['url', 'host', 'host_ip', 'port', 'status_code', 'title', 'content_length', 'webserver', 'cdn', 'cname', 'tech', 'location', 'redirect_scope', 'cf_state', 'cdnish']
    with (r / 'httpx/triage.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(fields)
        writer.writerows([csv_value(row.get(k)) for k in fields] for row in rows)
    urls = {row['url'] for row in rows}
    external_redirects = {row['url'] for row in rows if row['redirect_scope'] == 'out_of_scope'}
    clean = {row['url'] for row in rows if row['screenshot_clean']} - external_redirects
    rejected = urls - clean - external_redirects
    for filename, values in [('alive_urls_wide', urls), ('alive_urls_shots', clean), ('alive_urls_rejected', rejected), ('redirects_out_of_scope', external_redirects)]:
        write_lines(r / f'httpx/{filename}.txt', sorted(values))
    counts['http_responses'] = len(rows)
    counts['http_unreported'] = len(targets - seen)
    counts['web_urls'] = len(urls)
    counts['external_redirect_urls'] = len(external_redirects)
    cdn_ips = {address(row['host_ip']) for row in rows if row['cdnish']}
    live = {address(row['host_ip']) for row in rows}
    candidates = {address(row['host_ip']) for row in rows if row['cf_state'] == 'non-cloudflare' and address(row['host_ip']) not in cdn_ips}
    authorized = {ip for ip in candidates if contains(ip, networks)}
    scan_eligible = authorized if run.status.get('httpx') == 'OK' and not any(i.startswith(('httpx:', 'dnsx:')) for i in run.issues) and run.status.get('dnsx') == 'OK' else set()
    write_lines(r / 'scan/web_alive_ips_all.txt', sorted(map(str, live)))
    write_lines(r / 'scan/web_alive_ips_cdnish.txt', sorted(map(str, cdn_ips)))
    write_lines(r / 'scan/origin_scope_unapproved.txt', sorted(map(str, candidates - authorized)))
    counts['strict_candidates'] = len(candidates)
    counts['authorized_candidates'] = len(authorized)
    counts['scan_eligible_candidates'] = len(scan_eligible)
    counts['unapproved_candidates'] = len(candidates - authorized)
    portmap = {}
    for v in (4, 6):
        strict = sorted(ip for ip in candidates if ip.version == v)
        allowed = sorted(ip for ip in scan_eligible if ip.version == v)
        allowed_set = set(allowed)
        write_lines(r / f'scan/origin_ips_strict_v{v}.txt', strict)
        allowed_file = r / f'scan/origin_ips_authorized_v{v}.txt'
        write_lines(allowed_file, allowed)
        raw = r / f'scan/origin_ip_open_v{v}.jsonl'
        raw.touch()
        if allowed:
            run.stage(f'naabu_v{v}', ['naabu', '-config', str(run.config), '-duc', '-iv', str(v), '-l', str(allowed_file), '-tp', '100', '-ep', '80,443', '-s', 'c', '-silent', '-j', '-rate', str(args.r)], raw, 3600)
        else:
            run.status[f'naabu_v{v}'] = 'SKIPPED(no authorized candidates)'
        for row in run.json_rows(raw, f'naabu_v{v}'):
            try:
                ip = address(row['ip'])
                port = row['port']
                if ip not in allowed_set or type(port) is not int or not 1 <= port <= 65535 or port in {80, 443} or row.get('protocol', 'tcp') != 'tcp':
                    raise ValueError('unexpected address, protocol or port')
                portmap.setdefault(ip, set()).add(port)
            except (KeyError, ValueError, TypeError) as exc:
                run.issue(f'naabu_v{v}: invalid result: {exc}')
        write_lines(r / f'scan/origin_ip_open_v{v}.txt', (endpoint(ip, p) for ip in sorted(i for i in portmap if i.version == v) for p in sorted(portmap[ip])))
        write_lines(r / f'nmap/targets_v{v}.map', (f'{ip} {",".join(map(str, sorted(portmap[ip])))}' for ip in sorted(i for i in portmap if i.version == v and run.status.get(f'naabu_v{v}') == 'OK' and not any(issue.startswith(f'naabu_v{v}:') for issue in run.issues))))
    counts['additional_open_tcp_endpoints'] = sum(map(len, portmap.values()))
    nmap_results = []
    nmap_items = [(ip, ports) for ip, ports in portmap.items() if run.status.get(f'naabu_v{ip.version}') == 'OK' and not any(i.startswith(f'naabu_v{ip.version}:') for i in run.issues)]
    counts['nmap_targets'] = len(nmap_items)
    if nmap_items:
        with ThreadPoolExecutor(max_workers=min(args.n, len(nmap_items))) as pool:
            nmap_results = list(pool.map(lambda item: nmap_job(run, item), nmap_items))
    run.status['nmap'] = 'SKIPPED(no eligible additional open ports)' if not nmap_items else ('OK' if all(status == 'OK' for _, status in nmap_results) else 'ERROR(partial or failed scans)')
    summary = ['Nmap service fingerprint (TCP; 80/443 excluded)']
    for name, status in sorted(nmap_results):
        summary.extend(['', f'== {name}: {status} =='])
        if status != 'OK':
            run.issue(f'nmap {name}: {status}')
        report = r / 'nmap' / f'{name}.nmap'
        if report.is_file():
            summary.append(report.read_text(encoding='utf-8', errors='replace'))
    write_lines(r / 'nmap/summary.txt', summary)
    for name, filename, dest in [('gowitness', 'alive_urls_shots', 'gowitness'), ('gowitness_rejected', 'alive_urls_rejected', 'gowitness_rejected')]:
        file = r / 'httpx' / f'{filename}.txt'
        if not args.screenshots or run.status.get('httpx') != 'OK' or any(i.startswith(('httpx:', 'dnsx:')) for i in run.issues) or run.status.get('dnsx') != 'OK' or not file.stat().st_size:
            run.status[name] = 'SKIPPED(disabled or empty input)'
            continue
        folder = r / dest
        db = folder / f'{dest}.sqlite3'
        rc = run.stage(name, ['gowitness', 'scan', 'file', '-f', str(file), '-t', str(args.t), '-T', '60', '--screenshot-path', str(folder / 'screenshots'), '--write-db', '--write-db-uri', f'sqlite://{db}', '--write-none'], timeout=3600)
        shots = sum(1 for p in (folder / 'screenshots').iterdir() if p.is_file() and p.suffix.lower() in {'.png', '.jpg', '.jpeg'})
        counts[name + '_screenshots'] = shots
        if not rc and (not db.is_file() or shots < len(lines(file))):
            run.status[name] = 'ERROR(partial screenshots or missing database)'
            run.issue(f'{name}: screenshot output missing or incomplete')
    if run.issues:
        verdict = 'Incomplete assessment; review stage errors and available evidence. No negative exposure conclusion is justified.'
    elif not targets:
        verdict = 'No HTTP targets were eligible within the configured scope.'
    elif not candidates:
        verdict = 'No verified non-CDN candidates under current heuristics; exposure is not ruled out.'
    elif not authorized:
        verdict = 'Candidate addresses found; direct port scanning skipped because no candidate IP was explicitly authorized.'
    elif portmap:
        verdict = 'Additional open TCP ports reported on authorized candidate IPs; ownership and origin exposure require manual validation.'
    else:
        verdict = 'No additional open TCP ports reported in the selected top-100 set (80/443 excluded) on authorized candidates; exposure is not ruled out.'
    if candidates - authorized and authorized:
        verdict += ' Some candidates were outside authorized IP scope.'
    return run.summarize(counts, verdict)


def main():
    parser = argparse.ArgumentParser(description='WebSurface: web discovery and authorized exposure triage')
    parser.add_argument('-i', required=True, type=Path, help='root domains file')
    parser.add_argument('-a', '--authorized-ips', type=Path, help='explicit IP/CIDR allowlist; restricts active HTTP and enables port scanning')
    parser.add_argument('-t', type=positive, default=30, help='Gowitness threads (default 30)')
    parser.add_argument('-r', type=positive, default=2000, help='Naabu rate (default 2000)')
    parser.add_argument('-n', type=positive, default=4, help='parallel Nmap jobs (default 4)')
    parser.add_argument('-o', type=Path, help='new output directory')
    parser.add_argument('--screenshots', action='store_true', help='enable Gowitness only in an externally egress-restricted browser environment')
    parser.add_argument('--browser-egress-restricted', action='store_true', help='acknowledge an externally enforced browser egress policy')
    parser.add_argument('--version', action='version', version=f'WebSurface {VERSION}')
    args = parser.parse_args()
    if args.screenshots and (not args.authorized_ips or not args.browser_egress_restricted):
        parser.error('--screenshots requires -a and --browser-egress-restricted with an actual external egress policy')
    try:
        roots = {domain(line) for line in lines(args.i)}
        networks = [ipaddress.ip_network(line, strict=True) for line in lines(args.authorized_ips)] if args.authorized_ips else []
        if not roots or (args.authorized_ips and not networks):
            raise ValueError('domain and explicitly supplied IP scope files must not be empty')
        required = ['subfinder', 'dnsx', 'curl'] + (['naabu', 'nmap'] if networks else []) + (['gowitness'] if args.screenshots else [])
        missing = [tool for tool in required if not shutil.which(tool)]
        if missing:
            raise ValueError('missing dependencies: ' + ', '.join(missing))
        os.umask(0o077)
        output = (args.o or Path(__file__).resolve().parent / datetime.now().strftime('run_%Y%m%d_%H%M%S_%f')).absolute()
        output.mkdir(parents=False, exist_ok=False)
    except (OSError, ValueError, UnicodeError) as exc:
        parser.error(str(exc))
    print('▌ ▌   ▌  ▞▀▖      ▗▀▖\n▌▖▌▞▀▖▛▀▖▚▄ ▌ ▌▙▀▖▐  ▝▀▖▞▀▖▞▀▖\n▙▚▌▛▀ ▌ ▌▖ ▌▌ ▌▌  ▜▀ ▞▀▌▌ ▖▛▀\n▘ ▘▝▀▘▀▀ ▝▀ ▝▀▘▘  ▐  ▝▀▘▝▀ ▝▀▘', flush=True)
    print(f'WebSurface v{VERSION}\n[*] Run dir: {output}', flush=True)
    run = Run(output)
    if networks:
        write_lines(output / 'authorized_ips.txt', networks)
    try:
        return pipeline(run, roots, networks, args)
    except KeyboardInterrupt:
        run.issue('interrupted by user')
        run.summarize({}, 'Incomplete assessment; interrupted.')
        return 130
    except Exception as exc:
        run.issue(f'unhandled pipeline error: {type(exc).__name__}: {exc}')
        return run.summarize({}, 'Incomplete assessment; review logs.')


if __name__ == '__main__':
    sys.exit(main())
