#!/usr/bin/env bash
set -euo pipefail

VERSION="0.2"
TOOL_NAME="WebSurface"
BANNER_SHOWN=0

banner() {
cat << "EOF"
▌ ▌   ▌  ▞▀▖      ▗▀▖         
▌▖▌▞▀▖▛▀▖▚▄ ▌ ▌▙▀▖▐  ▝▀▖▞▀▖▞▀▖
▙▚▌▛▀ ▌ ▌▖ ▌▌ ▌▌  ▜▀ ▞▀▌▌ ▖▛▀ 
▘ ▘▝▀▘▀▀ ▝▀ ▝▀▘▘  ▐  ▝▀▘▝▀ ▝▀▘
EOF
echo "$TOOL_NAME v$VERSION"
echo ""
BANNER_SHOWN=1
}

usage() {
  [[ "${BANNER_SHOWN:-0}" -eq 1 ]] || banner
  cat << EOF
Usage:
  $0 -i domains.txt [-t GOW_THREADS] [-r NAABU_RATE] [-n NMAP_JOBS] [-o OUTDIR] [-h]

Options:
  -i  Input file with root domains (one per line)
  -t  Gowitness threads (default: 30)
  -r  Naabu rate limit (default: 2000)
  -n  Parallel Nmap jobs (default: 4)
  -o  Output directory (default: auto-generated run_YYYYMMDD_HHMMSS)
  -h  Show this help

What it does:
  1) Subdomains (passive) -> 2) DNS A/AAAA resolve -> 3) HTTP verify -> 4) Screenshots
  + Detect exposed non-Cloudflare origin IPs (strict) and scan them (naabu top100 + nmap service scan)

Legal:
  Use only against assets you own or have explicit authorization to test.
EOF
  exit 0
}

INPUT=""
GOW_THREADS=30
NAABU_RATE=2000
NMAP_JOBS=4
OUTDIR=""

banner

while getopts ":i:t:r:n:o:h" opt; do
  case "$opt" in
    i) INPUT="$OPTARG" ;;
    t) GOW_THREADS="$OPTARG" ;;
    r) NAABU_RATE="$OPTARG" ;;
    n) NMAP_JOBS="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

[[ -n "$INPUT" && -f "$INPUT" ]] || usage

need(){ command -v "$1" >/dev/null 2>&1 || { echo "[ERR] Missing: $1"; exit 2; }; }
need subfinder; need dnsx; need jq; need grepcidr; need naabu; need httpx; need curl; need gowitness; need nmap
need awk; need sed; need sort; need tr; need wc; need date; need mkdir; need cp; need printf; need sleep; need cut; need grep; need xargs; need find

ts="$(date +%Y%m%d_%H%M%S)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
run_dir="${OUTDIR:-$script_dir/run_${ts}}"
mkdir -p "$run_dir"/{subdomains,dns,cf,scan,httpx,gowitness,nmap,logs}

cp "$INPUT" "$run_dir/domains.txt"
DOMAINS="$run_dir/domains.txt"

HTTPX_MC="200,204,301,302,307,308,400,401,403,404,405,500,502,503"
CHALLENGE_RE='just a moment|attention required|access denied|request blocked|are you human|captcha|ddos|checking your browser'
SHOT_SC_RE='^(200|301|302|401|403)$'
CDN_CNAME_RE='cloudflare|cloudfront|fastly|akamai|edgesuite|edgekey|azureedge|azurefd|cdn77|stackpathdns|incapdns|impervadns|sucuri|stackpath|vercel-dns|netlify|pantheonsite|wpengine|siteground|nginxcdn|cachefly|gcore|gcdn'

line(){ printf "%s\n" "$*"; }
count_lines(){ [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

now_s(){ date +%s; }
dur(){ local s="$1" e="$2"; printf "%ds" "$((e-s))"; }

rc_status(){ [[ "${1:-1}" -eq 0 ]] && echo "OK" || echo "ERR($1)"; }

fmt_time() {
  local sec="${1:-0}"
  if (( sec < 60 )); then
    echo "${sec}s"
  elif (( sec < 3600 )); then
    local m=$(( sec / 60 ))
    local s=$(( sec % 60 ))
    echo "${m}m ${s}s"
  else
    local h=$(( sec / 3600 ))
    local m=$(( (sec % 3600) / 60 ))
    local s=$(( sec % 60 ))
    echo "${h}h ${m}m ${s}s"
  fi
}

spinner() {
  local pid="$1" msg="$2"
  local spin='-\|/'
  local i=0
  printf "%s " "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) %4 ))
    printf "\b%s" "${spin:$i:1}"
    sleep 0.2
  done
  printf "\b\u2713\n"
}

run_quiet() {
  local label="$1"; shift
  local outlog="$1"; shift
  local errlog="$1"; shift
  ( "$@" >"$outlog" 2>"$errlog" ) &
  local pid=$!
  spinner "$pid" "$label"
  wait "$pid"
  return $?
}

RUN_START="$(now_s)"
DOM_COUNT="$(grep -cv '^\s*$' "$DOMAINS" || true)"

line "[*] Run dir: $run_dir"
line "[*] Input domains (non-empty lines): $DOM_COUNT"
line ""

# ---------------- [1] subfinder + dedup (+ root domains) ----------------
S1="$(now_s)"
set +e
run_quiet "[1/7] Subdomain enum (subfinder)..." \
  "$run_dir/logs/subfinder.out" "$run_dir/logs/subfinder.err" \
  subfinder -dL "$DOMAINS" -all -recursive -silent -o "$run_dir/subdomains/subfinder.txt"
S1RC=$?
set -e

cat "$run_dir/subdomains/subfinder.txt" "$DOMAINS" 2>/dev/null \
  | tr -d '\r' \
  | sed 's/\.$//' \
  | awk '{print tolower($0)}' \
  | sed '/^\s*$/d' \
  | sort -u > "$run_dir/subdomains/subdomains_all.txt"

S1E="$(now_s)"
SUBF_COUNT="$(count_lines "$run_dir/subdomains/subfinder.txt")"
ALL_SUB_COUNT="$(count_lines "$run_dir/subdomains/subdomains_all.txt")"
SUB_DEDUP_DROP=$(( SUBF_COUNT - (ALL_SUB_COUNT - DOM_COUNT) ))
line "    subfinder rc:        $S1RC"
line "    raw subdomains:      $SUBF_COUNT"
line "    unique total (incl roots): $ALL_SUB_COUNT"
line "    time:                $(fmt_time $(( S1E - S1 )))"
line ""

# ---------------- [2] dnsx resolve + host/ip (A+AAAA) ----------------
S2="$(now_s)"
set +e
run_quiet "[2/7] DNS resolve (dnsx A+AAAA)..." \
  "$run_dir/logs/dnsx.out" "$run_dir/logs/dnsx.err" \
  dnsx -l "$run_dir/subdomains/subdomains_all.txt" -a -aaaa -j -silent -o "$run_dir/dns/dns.json"
S2RC=$?
set -e
if [[ "$S2RC" -ne 0 || ! -s "$run_dir/dns/dns.json" ]]; then
  line "[ERR] dnsx failed (rc=$S2RC) or dns.json empty. Check: $run_dir/logs/dnsx.err"
  exit 3
fi

jq -r '
  select(
    ((.a? // []) | length > 0) or
    ((.aaaa? // []) | length > 0)
  ) | .host
' "$run_dir/dns/dns.json" | sort -u > "$run_dir/dns/subdomains_resolved.txt"

jq -r '
  def emit($arr):
    if ($arr|type)=="array" and ($arr|length)>0 then
      .host as $h | $arr[] | "\($h),\(.)"
    else empty end;

  select(.host!=null)
  | emit(.a? // [])
  , emit(.aaaa? // [])
' "$run_dir/dns/dns.json" > "$run_dir/dns/host_ip.csv"

S2E="$(now_s)"
RES_COUNT="$(count_lines "$run_dir/dns/subdomains_resolved.txt")"
HOSTIP_COUNT="$(count_lines "$run_dir/dns/host_ip.csv")"
DNS_DEAD=$(( ALL_SUB_COUNT - RES_COUNT ))
line "    dnsx rc:             $S2RC"
line "    resolved hosts:      $RES_COUNT"
line "    unresolved/dropped:  $DNS_DEAD"
line "    host->ip rows:       $HOSTIP_COUNT"
line "    time:                $(fmt_time $(( S2E - S2 )))"
line ""

cut -d, -f2 "$run_dir/dns/host_ip.csv" | sed '/^\s*$/d' | sort -u > "$run_dir/scan/ips_all.txt"
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$run_dir/scan/ips_all.txt" > "$run_dir/scan/ips_v4.txt" || true
grep -E '^[0-9a-fA-F:]+$' "$run_dir/scan/ips_all.txt" > "$run_dir/scan/ips_v6.txt" || true

# ---------------- [3] cloudflare classification (v4+v6) ----------------
S3="$(now_s)"
line "[3/7] Cloudflare classification..."

: > "$run_dir/cf/cf_ipv4.txt"
: > "$run_dir/cf/cf_ipv6.txt"

curl -fsS --connect-timeout 5 --max-time 15 https://www.cloudflare.com/ips-v4 > "$run_dir/cf/cf_ipv4.txt" || true
curl -fsS --connect-timeout 5 --max-time 15 https://www.cloudflare.com/ips-v6 > "$run_dir/cf/cf_ipv6.txt" || true

: > "$run_dir/scan/cf_ips_v4.txt"
: > "$run_dir/scan/origin_ips_v4.txt"
: > "$run_dir/scan/cf_ips_v6.txt"
: > "$run_dir/scan/origin_ips_v6.txt"

if [[ -s "$run_dir/scan/ips_v4.txt" ]]; then
  if [[ -s "$run_dir/cf/cf_ipv4.txt" ]]; then
    grepcidr -f "$run_dir/cf/cf_ipv4.txt" < "$run_dir/scan/ips_v4.txt" > "$run_dir/scan/cf_ips_v4.txt" || true
    grepcidr -v -f "$run_dir/cf/cf_ipv4.txt" < "$run_dir/scan/ips_v4.txt" > "$run_dir/scan/origin_ips_v4.txt" || true
  else
    cat "$run_dir/scan/ips_v4.txt" > "$run_dir/scan/origin_ips_v4.txt"
  fi
fi

if [[ -s "$run_dir/scan/ips_v6.txt" ]]; then
  if [[ -s "$run_dir/cf/cf_ipv6.txt" ]]; then
    grepcidr -f "$run_dir/cf/cf_ipv6.txt" < "$run_dir/scan/ips_v6.txt" > "$run_dir/scan/cf_ips_v6.txt" || true
    grepcidr -v -f "$run_dir/cf/cf_ipv6.txt" < "$run_dir/scan/ips_v6.txt" > "$run_dir/scan/origin_ips_v6.txt" || true
  else
    cat "$run_dir/scan/ips_v6.txt" > "$run_dir/scan/origin_ips_v6.txt"
  fi
fi

S3E="$(now_s)"
CF_IPS_V4_COUNT="$(count_lines "$run_dir/scan/cf_ips_v4.txt")"
ORIGIN_IPS_V4_COUNT="$(count_lines "$run_dir/scan/origin_ips_v4.txt")"
CF_IPS_V6_COUNT="$(count_lines "$run_dir/scan/cf_ips_v6.txt")"
ORIGIN_IPS_V6_COUNT="$(count_lines "$run_dir/scan/origin_ips_v6.txt")"
line "    CF IPv4:             $CF_IPS_V4_COUNT"
line "    non-CF IPv4:         $ORIGIN_IPS_V4_COUNT"
line "    CF IPv6:             $CF_IPS_V6_COUNT"
line "    non-CF IPv6:         $ORIGIN_IPS_V6_COUNT"
line "    time:                $(fmt_time $(( S3E - S3 )))"
line ""

# ---------------- [4] httpx verify + wide/shots/rejected + triage.csv ----------------
S4="$(now_s)"
line "[4/7] HTTP probe (find alive web services + collect IP/CDN hints)..."
awk '{print "http://" $0 "\nhttps://" $0 }' "$run_dir/dns/subdomains_resolved.txt" > "$run_dir/scan/http_urls.txt"
HTTP_TARGETS="$(count_lines "$run_dir/scan/http_urls.txt")"
line "    url targets (http+https):   $HTTP_TARGETS"

HTTPX_FLAGS=(
  -silent -fr -mc "$HTTPX_MC" -timeout 10 -rl 200 -j
  -title -td -sc -cl -server -ip -cname -cdn
)

set +e
run_quiet "HTTPX..." \
  "$run_dir/httpx/httpx.json" "$run_dir/logs/httpx.err" \
  httpx -l "$run_dir/scan/http_urls.txt" "${HTTPX_FLAGS[@]}"
S4RC=$?
set -e
if [[ "$S4RC" -ne 0 || ! -s "$run_dir/httpx/httpx.json" ]]; then
  line "[ERR] httpx failed (rc=$S4RC) or httpx.json empty. Check: $run_dir/logs/httpx.err"
  exit 4
fi

jq -r '(.final_url // .url)' "$run_dir/httpx/httpx.json" | sed '/^null$/d' | sort -u > "$run_dir/httpx/alive_urls_wide.txt"

jq -r '
  def to_s:
    if . == null then ""
    elif type == "string" then .
    else tostring end;

  def bad_title:
    ((.title? | to_s | ascii_downcase) | test("'"$CHALLENGE_RE"'"; "i"));

  select(
    ((.status_code? // 0) | tostring | test("'"$SHOT_SC_RE"'"))
    and (bad_title | not)
  )
  | (.final_url // .url)
' "$run_dir/httpx/httpx.json" | sed '/^null$/d' | sort -u > "$run_dir/httpx/alive_urls_shots.txt"

jq -r '
  def to_s:
    if . == null then ""
    elif type == "string" then .
    else tostring end;

  def bad_title:
    ((.title? | to_s | ascii_downcase) | test("'"$CHALLENGE_RE"'"; "i"));

  select(
    (bad_title)
    or (((.status_code? // 0) | tostring | test("'"$SHOT_SC_RE"'")) | not)
  )
  | (.final_url // .url)
' "$run_dir/httpx/httpx.json" | sed '/^null$/d' | sort -u > "$run_dir/httpx/alive_urls_rejected.txt"

jq -r '
  def s:
    if . == null then ""
    elif type == "array" then (map(tostring) | join(";"))
    elif type == "boolean" then (if . then "true" else "false" end)
    else tostring end;

  [
    "url","host","ip","port","status","title","len","webserver","cdn","cname","tech"
  ],
  [
    ((.final_url // .url) | s),
    (.host | s),
    (.host_ip | s),
    ((.port // "") | s),
    ((.status_code // "") | s),
    ((.title // "") | gsub("[\r\n\t]";" ") | gsub("\"";"'"'"'") | s),
    ((.content_length // 0) | s),
    (.webserver | s),
    (.cdn | s),
    (.cname | s),
    (.tech | s)
  ] | @csv
' "$run_dir/httpx/httpx.json" > "$run_dir/httpx/triage.csv"

jq -r '
  def to_s:
    if . == null then ""
    elif type == "string" then .
    else tostring end;

  def bad_title:
    ((.title? | to_s | ascii_downcase) | test("'"$CHALLENGE_RE"'"; "i"));

  def cdnish:
    (
      (.cdn? == true)
      or ((.cname? | to_s | ascii_downcase) | test("'"$CDN_CNAME_RE"'"; "i"))
      or ((.cdn_name? | to_s | ascii_downcase) | length > 0)
    );

  def emit_ip($ip):
    if $ip == null then empty
    else ($ip|tostring) end;

  select(
    ((.status_code? // 0) | tostring | test("'"$SHOT_SC_RE"'"))
    and (bad_title | not)
  )
  | . as $o
  | (
      [ ($o.host_ip? | emit_ip(.)),
        (($o.a? // [])[] | emit_ip(.)),
        (($o.aaaa? // [])[] | emit_ip(.))
      ]
      | map(select(length>0))
      | unique
    )[] as $ip
  | {ip:$ip, cdnish:cdnish}
' "$run_dir/httpx/httpx.json" > "$run_dir/httpx/web_alive_ip_candidates.jsonl"

jq -r 'select(.cdnish==false) | .ip' "$run_dir/httpx/web_alive_ip_candidates.jsonl" \
  | sed '/^\s*$/d' | sort -u > "$run_dir/scan/web_alive_ips_all.txt"

jq -r 'select(.cdnish==true) | .ip' "$run_dir/httpx/web_alive_ip_candidates.jsonl" \
  | sed '/^\s*$/d' | sort -u > "$run_dir/scan/web_alive_ips_cdnish.txt"

grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$run_dir/scan/web_alive_ips_all.txt" > "$run_dir/scan/web_alive_ips_v4.txt" || true
grep -E '^[0-9a-fA-F:]+$' "$run_dir/scan/web_alive_ips_all.txt" > "$run_dir/scan/web_alive_ips_v6.txt" || true

: > "$run_dir/scan/origin_ips_strict_v4.txt"
: > "$run_dir/scan/origin_ips_strict_v6.txt"

if [[ -s "$run_dir/scan/web_alive_ips_v4.txt" ]]; then
  if [[ -s "$run_dir/cf/cf_ipv4.txt" ]]; then
    grepcidr -v -f "$run_dir/cf/cf_ipv4.txt" < "$run_dir/scan/web_alive_ips_v4.txt" > "$run_dir/scan/origin_ips_strict_v4.txt" || true
  else
    cat "$run_dir/scan/web_alive_ips_v4.txt" > "$run_dir/scan/origin_ips_strict_v4.txt"
  fi
fi

if [[ -s "$run_dir/scan/web_alive_ips_v6.txt" ]]; then
  if [[ -s "$run_dir/cf/cf_ipv6.txt" ]]; then
    grepcidr -v -f "$run_dir/cf/cf_ipv6.txt" < "$run_dir/scan/web_alive_ips_v6.txt" > "$run_dir/scan/origin_ips_strict_v6.txt" || true
  else
    cat "$run_dir/scan/web_alive_ips_v6.txt" > "$run_dir/scan/origin_ips_strict_v6.txt"
  fi
fi

S4E="$(now_s)"
ALIVE_WIDE="$(count_lines "$run_dir/httpx/alive_urls_wide.txt")"
ALIVE_SHOTS="$(count_lines "$run_dir/httpx/alive_urls_shots.txt")"
ALIVE_REJ="$(count_lines "$run_dir/httpx/alive_urls_rejected.txt")"
HTTP_DEAD=$(( HTTP_TARGETS - ALIVE_WIDE ))
WEBALIVE_IPS_ALL="$(count_lines "$run_dir/scan/web_alive_ips_all.txt")"
ORIGIN_STRICT_V4_COUNT="$(count_lines "$run_dir/scan/origin_ips_strict_v4.txt")"
ORIGIN_STRICT_V6_COUNT="$(count_lines "$run_dir/scan/origin_ips_strict_v6.txt")"

line "    httpx rc:            $S4RC"
line "    alive (wide):        $ALIVE_WIDE"
line "    screenshot input:    $ALIVE_SHOTS"
line "    rejected (noise):    $ALIVE_REJ"
line "    dead/unresponsive:   $HTTP_DEAD"
line "    web-alive IPs:       $WEBALIVE_IPS_ALL"
line "    strict origin IPv4:  $ORIGIN_STRICT_V4_COUNT"
line "    strict origin IPv6:  $ORIGIN_STRICT_V6_COUNT"
line "    time:                $(fmt_time $(( S4E - S4 )))"
line ""

# ---------------- [5] origin port scan (naabu top100, no 80/443) ----------------
S5="$(now_s)"
line "[5/7] Port scan on strict candidate IPs (naabu top100; excluding 80/443)..."

: > "$run_dir/scan/origin_ip_open_v4.txt"
: > "$run_dir/scan/origin_ip_open_v6.txt"

S5RC4=0
S5RC6=0

if [[ "$ORIGIN_STRICT_V4_COUNT" -gt 0 ]]; then
  set +e
  run_quiet "Naabu v4..." \
    "$run_dir/logs/naabu_v4.out" "$run_dir/logs/naabu_v4.err" \
    naabu -l "$run_dir/scan/origin_ips_strict_v4.txt" -tp 100 -silent \
      -rate "$NAABU_RATE" \
      -o "$run_dir/scan/origin_ip_open_v4.raw.txt"
  S5RC4=$?
  set -e
  grep -Ev ':(80|443)$' "$run_dir/scan/origin_ip_open_v4.raw.txt" > "$run_dir/scan/origin_ip_open_v4.txt" || true
fi

if [[ "$ORIGIN_STRICT_V6_COUNT" -gt 0 ]]; then
  set +e
  run_quiet "Naabu v6..." \
    "$run_dir/logs/naabu_v6.out" "$run_dir/logs/naabu_v6.err" \
    naabu -iv 6 -l "$run_dir/scan/origin_ips_strict_v6.txt" -tp 100 -silent \
      -rate "$NAABU_RATE" \
      -o "$run_dir/scan/origin_ip_open_v6.raw.txt"
  S5RC6=$?
  set -e

  if [[ -f "$run_dir/scan/origin_ip_open_v6.raw.txt" ]]; then
    grep -Ev ':(80|443)$' "$run_dir/scan/origin_ip_open_v6.raw.txt" > "$run_dir/scan/origin_ip_open_v6.txt" || true
  else
    : > "$run_dir/scan/origin_ip_open_v6.txt"
  fi

  if [[ "${S5RC6:-0}" -ne 0 ]]; then
    line "[WARN] naabu v6 failed rc=$S5RC6 (see $run_dir/logs/naabu_v6.err)"
  fi
fi

S5E="$(now_s)"
ORIGIN_IP_OPEN_V4="$(count_lines "$run_dir/scan/origin_ip_open_v4.txt")"
ORIGIN_IP_OPEN_V6="$(count_lines "$run_dir/scan/origin_ip_open_v6.txt")"

line "    naabu status (IPv4):             $(rc_status "$S5RC4")"
line "    naabu status (IPv6):             $(rc_status "$S5RC6")"
line "    open endpoints found (IPv4 IP:PORT): $ORIGIN_IP_OPEN_V4"
line "    open endpoints found (IPv6 IP:PORT): $ORIGIN_IP_OPEN_V6"
line "    time:                $(fmt_time $(( S5E - S5 )))"
line ""

# ---------------- [6] nmap service scan + summary ----------------
S6="$(now_s)"
line "[6/7] Nmap service scan..."
NMAP_TARGETS_V4=0
NMAP_TARGETS_V6=0
NMAP_SUMMARY=""

mkdir -p "$run_dir/logs/nmap"

if [[ "$ORIGIN_IP_OPEN_V4" -gt 0 ]]; then
  awk -F: '{ ports[$1]=(ports[$1] ? ports[$1] "," $2 : $2) }
           END { for (ip in ports) print ip " " ports[ip] }' \
    "$run_dir/scan/origin_ip_open_v4.txt" | sort -u > "$run_dir/nmap/targets_v4.map"
  NMAP_TARGETS_V4="$(count_lines "$run_dir/nmap/targets_v4.map")"

  awk '{print $1 "|" $2}' "$run_dir/nmap/targets_v4.map" \
    | xargs -P "$NMAP_JOBS" -I {} bash -lc '
        ip="${1%%|*}"
        ports="${1#*|}"
        outbase="'"$run_dir"'/nmap/v4_${ip}"
        logbase="'"$run_dir"'/logs/nmap/v4_${ip}"

        {
          echo "[*] $(date -Is) nmap v4 $ip ports=$ports"
          set +e
          nmap -n -Pn -sT -sV --version-light -T3 \
            --script "default and safe and not broadcast and not brute and not dos and not intrusive and not external,banner" \
            --script-timeout 20s \
            --host-timeout 3m \
            -p "$ports" \
            -oA "$outbase" \
            "$ip"
          rc=$?
          set -e
          echo "[*] rc=$rc"
          if [[ "$rc" -ne 0 ]]; then
            set +e
            nmap -n -Pn -sT -sV --version-light -T3 \
              --host-timeout 3m \
              -p "$ports" \
              -oN "${outbase}.fallback.nmap" \
              "$ip"
            set -e
          fi
        } > "${logbase}.stdout" 2> "${logbase}.stderr"
      ' _ {}
fi

if [[ "$ORIGIN_IP_OPEN_V6" -gt 0 ]]; then
  awk -F: '{ ports[$1]=(ports[$1] ? ports[$1] "," $2 : $2) }
           END { for (ip in ports) print ip " " ports[ip] }' \
    "$run_dir/scan/origin_ip_open_v6.txt" | sort -u > "$run_dir/nmap/targets_v6.map"
  NMAP_TARGETS_V6="$(count_lines "$run_dir/nmap/targets_v6.map")"

  awk '{print $1 "|" $2}' "$run_dir/nmap/targets_v6.map" \
    | xargs -P "$NMAP_JOBS" -I {} bash -lc '
        ip="${1%%|*}"
        ports="${1#*|}"
        outbase="'"$run_dir"'/nmap/v6_${ip//:/_}"
        logbase="'"$run_dir"'/logs/nmap/v6_${ip//:/_}"

        {
          echo "[*] $(date -Is) nmap v6 $ip ports=$ports"
          set +e
          nmap -6 -n -Pn -sT -sV --version-light -T3 \
            --script "default and safe and not broadcast and not brute and not dos and not intrusive and not external,banner" \
            --script-timeout 20s \
            --host-timeout 3m \
            -p "$ports" \
            -oA "$outbase" \
            "$ip"
          rc=$?
          set -e
          echo "[*] rc=$rc"
          if [[ "$rc" -ne 0 ]]; then
            set +e
            nmap -6 -n -Pn -sT -sV --version-light -T3 \
              --host-timeout 3m \
              -p "$ports" \
              -oN "${outbase}.fallback.nmap" \
              "$ip"
            set -e
          fi
        } > "${logbase}.stdout" 2> "${logbase}.stderr"
      ' _ {}
fi

line "[6d] Build Nmap summary report..."
NMAP_SUMMARY="$run_dir/nmap/summary.txt"
{
  echo "# Nmap Summary"
  echo "# Run: $ts"
  echo "# Format: TARGET -> PORT/PROTO STATE SERVICE VERSION (+ selected notes)"
  echo

  for f in "$run_dir"/nmap/*.nmap; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f")"
    echo "== ${base%.nmap} =="
    awk '
      /^PORT[[:space:]]+STATE[[:space:]]+SERVICE/ {in_tbl=1; next}
      in_tbl && NF==0 {in_tbl=0}
      in_tbl {print "  " $0}
    ' "$f"
    if grep -qiE 'banner:|Service Info:|Host script results:|ssh-hostkey:|ssl-cert:' "$f"; then
      echo "  -- notes --"
      grep -iE 'banner:|Service Info:|ssh-hostkey:|ssl-cert:' "$f" | sed 's/^/  /' || true
    fi
    echo
  done
} > "$NMAP_SUMMARY"

S6E="$(now_s)"
line "    nmap targets v4:     $NMAP_TARGETS_V4"
line "    nmap targets v6:     $NMAP_TARGETS_V6"
line "    nmap summary:        $NMAP_SUMMARY"
line "    time:                $(fmt_time $(( S6E - S6 )))"
line ""

# ---------------- [7] gowitness ----------------
S7="$(now_s)"
line "[7/7] Gowitness..."
mkdir -p "$run_dir/gowitness/screenshots"
GOW_DB="$run_dir/gowitness/gowitness.sqlite3"

set +e
run_quiet "Gowitness scan..." \
  "$run_dir/logs/gowitness.out" "$run_dir/logs/gowitness.err" \
  gowitness scan file -f "$run_dir/httpx/alive_urls_shots.txt" \
  -t "$GOW_THREADS" -T 60 \
  --screenshot-path "$run_dir/gowitness/screenshots" \
  --write-db --write-db-uri "sqlite://$GOW_DB" \
  --write-none
S7RC=$?
set -e

SS_COUNT="$(find "$run_dir/gowitness/screenshots" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' \) 2>/dev/null | wc -l | tr -d ' ')"
S7E="$(now_s)"
line "    gowitness rc:        $S7RC"
line "    screenshots saved:   $SS_COUNT"
line "    time:                $(fmt_time $(( S7E - S7 )))"
line ""

RUN_END="$(now_s)"
TOTAL_SEC=$(( RUN_END - RUN_START ))
TOTAL_TIME="$(fmt_time "$TOTAL_SEC")"

ORIGIN_STRICT_TOTAL=$(( ORIGIN_STRICT_V4_COUNT + ORIGIN_STRICT_V6_COUNT ))
ORIGIN_IP_OPEN_TOTAL=$(( ORIGIN_IP_OPEN_V4 + ORIGIN_IP_OPEN_V6 ))
NMAP_TARGETS_TOTAL=$(( NMAP_TARGETS_V4 + NMAP_TARGETS_V6 ))

line "================== SUMMARY =================="
line "Run dir:               $run_dir"
line "Total time:            $TOTAL_TIME"
line ""
line "Input domains:         $DOM_COUNT"
line ""

line "Pipeline (counts shrink naturally):"
line "  domains -> subdomains -> resolved hosts -> alive URLs -> strict IPs -> open endpoints -> nmap IPs"
line ""

line "Execution status:"
line "  subfinder:           $(rc_status "$S1RC")"
line "  dnsx:                $(rc_status "$S2RC")"
line "  httpx:               $(rc_status "$S4RC")"
line "  naabu IPv4:          $(rc_status "$S5RC4")"
line "  naabu IPv6:          $(rc_status "$S5RC6")"
line "  gowitness:           $(rc_status "$S7RC")"
line ""

line "Targets:"
line "  unique total (hosts): $ALL_SUB_COUNT"
line "  resolved hosts:       $RES_COUNT"
line ""

line "Cloudflare classification (by CF IP ranges; unique IPs):"
line "  CF IPv4:              $CF_IPS_V4_COUNT"
line "  non-CF IPv4:          $ORIGIN_IPS_V4_COUNT"
line "  CF IPv6:              $CF_IPS_V6_COUNT"
line "  non-CF IPv6:          $ORIGIN_IPS_V6_COUNT"
line ""

line "HTTP verification:"
line "  url targets (http+https):   $HTTP_TARGETS"
line "  alive URLs (wide):          $ALIVE_WIDE"
line "  screenshot candidates:      $ALIVE_SHOTS"
line "  rejected (challenge/noise): $ALIVE_REJ"
line "  dead/unresponsive:          $HTTP_DEAD"
line ""

line "Origin check (potential real backend IPs):"
line "  strict candidate IPs (unique):"
line "    IPv4 strict IPs:           $ORIGIN_STRICT_V4_COUNT"
line "    IPv6 strict IPs:           $ORIGIN_STRICT_V6_COUNT"
line "  open endpoints from naabu (IP:PORT pairs):"
line "    IPv4 open endpoints:       $ORIGIN_IP_OPEN_V4"
line "    IPv6 open endpoints:       $ORIGIN_IP_OPEN_V6"
line "  nmap scope (unique IPs that had any ports):"
line "    IPv4 nmap targets:         $NMAP_TARGETS_V4"
line "    IPv6 nmap targets:         $NMAP_TARGETS_V6"
line ""

line "Why numbers differ:"
line "  - 'IPs' are unique addresses."
line "  - 'endpoints' are IP:PORT pairs (one IP can create many endpoints)."
line "  - 'nmap targets' are only IPs that produced any ports after filtering (80/443 removed)."
line "  - IPv6 is scanned by nmap only if any IPv6 endpoints were found."
line ""

if [[ "$ORIGIN_STRICT_TOTAL" -eq 0 ]]; then
  line "Verdict:               No strict non-Cloudflare origin IPs detected (low confidence origin exposure)."
elif [[ "$ORIGIN_IP_OPEN_TOTAL" -eq 0 ]]; then
  line "Verdict:               Strict origin IPs detected, but no open top-100 ports (no obvious exposure)."
else
  line "Verdict:               Potential origin exposure detected (strict non-CF IPs with open ports). Review Nmap summary."
fi

line ""
line "Stage outputs (what to open when you want to understand 'why'):"
line "  1) subfinder output:        $run_dir/subdomains/subfinder.txt"
line "  1b) all unique hosts:       $run_dir/subdomains/subdomains_all.txt"
line "  2) resolved hosts:          $run_dir/dns/subdomains_resolved.txt"
line "  2b) host -> ip mapping:     $run_dir/dns/host_ip.csv"
line "  3) non-CF IPs (from DNS):   $run_dir/scan/origin_ips_v4.txt  (and origin_ips_v6.txt)"
line "  4) alive URLs:              $run_dir/httpx/alive_urls_wide.txt"
line "  4b) triage CSV:             $run_dir/httpx/triage.csv"
line "  4c) strict candidate IPs:   $run_dir/scan/origin_ips_strict_v4.txt  (and strict_v6.txt)"
line "  5) open endpoints (naabu):  $run_dir/scan/origin_ip_open_v4.txt     (and open_v6.txt)"
line "  6) nmap input (IP ports):   $run_dir/nmap/targets_v4.map            (and targets_v6.map)"
line "  6b) nmap summary:           $NMAP_SUMMARY"
line "  7) screenshots dir:         $run_dir/gowitness/screenshots"
line "  7b) gowitness DB:           $GOW_DB"
line ""

line "Run report:"
line "  gowitness report server --host 127.0.0.1 --port 7171 --db-uri sqlite://$GOW_DB --screenshot-path $run_dir/gowitness/screenshots"
