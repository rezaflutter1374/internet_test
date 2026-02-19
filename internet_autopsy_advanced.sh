#!/usr/bin/env bash
# internet_autopsy_advanced.sh
# Cross-platform (macOS + Linux) network diagnostic + evidence collection

#This is the second script, which is commented.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="2.0.0"


BASE_OUTDIR="${HOME}/network_forensics_results"
RUN_ID=""
LOG_FILE=""
SUMMARY_FILE=""
RAW_DIR=""
META_DIR=""
PCAP_DIR=""

CMD_TIMEOUT=25
PING_COUNT=10
PING_JITTER_COUNT=30
TRACEROUTE_MAX_HOPS=30
MTR_CYCLES=100
DOWNLOAD_URL="https://speed.hetzner.de/10MB.bin"
DNS_SERVERS_DEFAULT=("8.8.8.8" "1.1.1.1" "9.9.9.9")
TARGETS_DEFAULT=("8.8.8.8" "1.1.1.1" "google.com")
IPERF_SERVERS_DEFAULT=("iperf.he.net" "iperf.scottlinux.com")
PORTS_DEFAULT=(443 80 1194 51820)
PORT_PROBE_TARGET=""
PORT_SCAN_TARGET=""
CAPTURE_DURATION=30
ALLOW_SUDO=0
ENABLE_CAPTURE=0
ENABLE_IPERF=0
ENABLE_PORT_PROBE=0
ENABLE_PORT_SCAN=0
ENABLE_SPEEDTEST=1
ENABLE_DOWNLOAD=1
ICMP_OK="unknown"
TRACEROUTE_OK="unknown"
SPEEDTEST_IMPL=""
AVAILABLE_MODULES=(
  system
  network
  dns
  ping
  traceroute
  mtr
  jitter
  download
  speedtest
  iperf
  mtu
  port_probe
  port_scan
  tcpdump
  whois
)
ENABLED_MODULES=()
SKIP_MODULES=()

OS_FAMILY=""
TIMEOUT_CMD=""

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf "%s [%s] %s\n" "$ts" "$level" "$msg" | tee -a "$LOG_FILE" >/dev/null
}
log_info() { log "INFO" "$*"; }
log_warn() { log "WARN" "$*"; }
log_error() { log "ERROR" "$*"; }


on_error() {
  local exit_code=$?
  local line_no=$1
  local cmd=$2
  log_error "Command failed (exit $exit_code) at line $line_no: $cmd"
  exit "$exit_code"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

usage() {
  cat <<USAGE
$SCRIPT_NAME v$SCRIPT_VERSION

Usage:
  $SCRIPT_NAME [options]

Options:
  -o, --outdir DIR           Base output directory (default: $BASE_OUTDIR)
  -t, --targets LIST         Comma-separated targets (default: ${TARGETS_DEFAULT[*]})
  -d, --dns-servers LIST     Comma-separated DNS servers (default: ${DNS_SERVERS_DEFAULT[*]})
  -m, --modules LIST         Only run specific modules (comma-separated)
  -s, --skip LIST            Skip specific modules (comma-separated)
      --list-modules         List available modules and exit
      --timeout SECONDS      Per-command timeout (default: $CMD_TIMEOUT)
      --ping-count N         ICMP echo count per target (default: $PING_COUNT)
      --jitter-count N       Jitter test ping count (default: $PING_JITTER_COUNT)
      --download-url URL     Raw download test URL (default: $DOWNLOAD_URL)
      --no-download          Disable raw download test
      --no-speedtest         Disable speedtest (if installed)
      --iperf                Enable iperf3 tests (public servers)
      --port-probe TARGET    Enable TCP port probe to target (requires --allow-ports)
      --allow-ports          Acknowledge permission to probe ports on target
      --port-scan TARGET     Enable nmap port scan (requires --allow-ports)
      --capture              Enable tcpdump capture (requires sudo)
      --capture-seconds N    tcpdump duration seconds (default: $CAPTURE_DURATION)
      --allow-sudo           Allow use of sudo for privileged commands
  -h, --help                 Show help and exit

Notes:
  - Port probing/scanning and packet capture are disabled by default.
  - Only run port probes/scans against systems you own or have explicit permission to test.
USAGE
}

split_csv() {
  local input="$1"
  local -n _out_ref="$2"
  IFS=',' read -r -a _out_ref <<< "$input"
}

array_contains() {
  local needle="$1"; shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

module_enabled() {
  local name="$1"
  if [[ ${#ENABLED_MODULES[@]} -gt 0 ]]; then
    array_contains "$name" "${ENABLED_MODULES[@]}" || return 1
  fi
  if [[ ${#SKIP_MODULES[@]} -gt 0 ]]; then
    array_contains "$name" "${SKIP_MODULES[@]}" && return 1
  fi
  return 0
}

ensure_dir() {
  local d="$1"
  mkdir -p "$d"
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1
}

detect_speedtest() {
  if [[ -n "$SPEEDTEST_IMPL" ]]; then
    return 0
  fi


  if require_cmd speedtest; then
    if speedtest --help 2>&1 | grep -q -- '--accept-license'; then
      SPEEDTEST_IMPL="ookla"
      return 0
    fi
  fi

  if require_cmd speedtest-cli; then
    SPEEDTEST_IMPL="cli"
    return 0
  fi

  if require_cmd speedtest; then
    SPEEDTEST_IMPL="legacy"
    return 0
  fi

  SPEEDTEST_IMPL="none"
}

check_icmp_permission() {
  if [[ "$ICMP_OK" != "unknown" ]]; then
    return 0
  fi
  if ! require_cmd ping; then
    ICMP_OK="no"
    return 0
  fi

  local tmp="$META_DIR/icmp_check.txt"
  set +e
  if [[ -n "$TIMEOUT_CMD" && "$CMD_TIMEOUT" -gt 0 ]]; then
    "$TIMEOUT_CMD" 3 ping -c 1 1.1.1.1 >"$tmp" 2>&1
  else
    ping -c 1 1.1.1.1 >"$tmp" 2>&1
  fi
  set -e

  if grep -qi "operation not permitted" "$tmp"; then
    ICMP_OK="no"
  else
    ICMP_OK="yes"
  fi
  printf "%s\n" "$ICMP_OK" > "$META_DIR/icmp_allowed.txt"
}

require_icmp() {
  check_icmp_permission
  if [[ "$ICMP_OK" == "no" ]]; then
    log_warn "ICMP not permitted; skipping ping/jitter/mtu modules. Re-run with sudo if needed."
    return 1
  fi
  return 0
}

check_traceroute_permission() {
  if [[ "$TRACEROUTE_OK" != "unknown" ]]; then
    return 0
  fi
  if ! require_cmd traceroute; then
    TRACEROUTE_OK="no"
    return 0
  fi

  local tmp="$META_DIR/traceroute_check.txt"
  set +e
  if [[ -n "$TIMEOUT_CMD" && "$CMD_TIMEOUT" -gt 0 ]]; then
    "$TIMEOUT_CMD" 3 traceroute -n -m 1 1.1.1.1 >"$tmp" 2>&1
  else
    traceroute -n -m 1 1.1.1.1 >"$tmp" 2>&1
  fi
  set -e

  if grep -qiE "operation not permitted|permission denied" "$tmp"; then
    TRACEROUTE_OK="no"
  else
    TRACEROUTE_OK="yes"
  fi
  printf "%s\n" "$TRACEROUTE_OK" > "$META_DIR/traceroute_allowed.txt"
}

require_traceroute() {
  check_traceroute_permission
  if [[ "$TRACEROUTE_OK" == "no" ]]; then
    log_warn "Traceroute not permitted; skipping traceroute module. Re-run with sudo if needed."
    return 1
  fi
  return 0
}

run_cmd() {
  local label="$1"; shift
  local out="$1"; shift
  local ec
  local err_trap

  log_info "RUN: $label"
  ensure_dir "$(dirname "$out")"

  err_trap="$(trap -p ERR || true)"
  trap - ERR

  set +e
  if [[ -n "$TIMEOUT_CMD" && "$CMD_TIMEOUT" -gt 0 ]]; then
    "$TIMEOUT_CMD" "$CMD_TIMEOUT" "$@" >"$out" 2>&1
  else
    "$@" >"$out" 2>&1
  fi
  ec=$?
  set -e

  printf "%s" "$ec" > "${out}.exitcode"
  if [[ $ec -ne 0 ]]; then
    log_warn "Command failed ($ec): $label (see $out)"
  fi

  if [[ -n "$err_trap" ]]; then
    eval "$err_trap"
  fi
  return 0
}

detect_os() {
  local uname_s
  uname_s="$(uname -s)"
  case "$uname_s" in
    Darwin) OS_FAMILY="macos";;
    Linux) OS_FAMILY="linux";;
    *) OS_FAMILY="unknown";;
  esac
}

detect_timeout() {
  if require_cmd gtimeout; then
    TIMEOUT_CMD="gtimeout"
  elif require_cmd timeout; then
    TIMEOUT_CMD="timeout"
  else
    TIMEOUT_CMD=""
  fi
}

init_output() {
  local ts
  ts="$(date +"%Y%m%d_%H%M%S")"
  RUN_ID="$ts"

  local outdir="$BASE_OUTDIR/$RUN_ID"
  RAW_DIR="$outdir/raw"
  META_DIR="$outdir/meta"
  PCAP_DIR="$outdir/pcap"
  LOG_FILE="$outdir/run.log"
  SUMMARY_FILE="$outdir/summary.txt"

  ensure_dir "$RAW_DIR"
  ensure_dir "$META_DIR"
  ensure_dir "$PCAP_DIR"

  log_info "Start network forensic run: $RUN_ID"
  log_info "Output directory: $outdir"
}

write_metadata() {
  local meta="$META_DIR/metadata.txt"
  {
    echo "script: $SCRIPT_NAME"
    echo "version: $SCRIPT_VERSION"
    echo "run_id: $RUN_ID"
    echo "start_time_utc: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "user: $(id -un 2>/dev/null || echo unknown)"
    echo "host: $(hostname 2>/dev/null || echo unknown)"
    echo "os_family: $OS_FAMILY"
    echo "kernel: $(uname -a)"
  } > "$meta"
}

check_dependencies() {
  local required=(ping traceroute curl)
  local optional=(ifconfig route scutil netstat mtr jq nmap tcpdump iperf3 speedtest speedtest-cli dig drill nslookup whois)

  local missing=()
  local cmd
  for cmd in "${required[@]}"; do
    if ! require_cmd "$cmd"; then
      missing+=("$cmd")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    log_warn "Missing required commands: ${missing[*]}"
    log_warn "Some modules may not run. Install via your package manager."
  fi

  local inv="$META_DIR/commands.txt"
  {
    echo "required:"
    for cmd in "${required[@]}"; do
      echo "  $cmd: $(require_cmd "$cmd" && echo yes || echo no)"
    done
    echo "optional:"
    for cmd in "${optional[@]}"; do
      echo "  $cmd: $(require_cmd "$cmd" && echo yes || echo no)"
    done
  } > "$inv"
}


module_system() {
  module_enabled system || return 0
  log_info "Module: system"

  run_cmd "uname" "$RAW_DIR/uname.txt" uname -a
  if [[ "$OS_FAMILY" == "macos" ]]; then
    run_cmd "sw_vers" "$RAW_DIR/sw_vers.txt" sw_vers
    run_cmd "sysctl hw" "$RAW_DIR/sysctl_hw.txt" sysctl -a
  elif [[ "$OS_FAMILY" == "linux" ]]; then
    run_cmd "os-release" "$RAW_DIR/os_release.txt" bash -c 'cat /etc/os-release'
    run_cmd "lsb_release" "$RAW_DIR/lsb_release.txt" lsb_release -a
  fi
}

module_network() {
  module_enabled network || return 0
  log_info "Module: network"

  if [[ "$OS_FAMILY" == "macos" ]]; then
    run_cmd "ifconfig -a" "$RAW_DIR/ifconfig.txt" ifconfig -a
    run_cmd "netstat -rn" "$RAW_DIR/netstat_routes.txt" netstat -rn
    run_cmd "scutil --dns" "$RAW_DIR/scutil_dns.txt" scutil --dns
  elif [[ "$OS_FAMILY" == "linux" ]]; then
    run_cmd "ip addr" "$RAW_DIR/ip_addr.txt" ip addr
    run_cmd "ip route" "$RAW_DIR/ip_route.txt" ip route
    run_cmd "resolv.conf" "$RAW_DIR/resolv_conf.txt" bash -c 'cat /etc/resolv.conf'
  fi
}

module_dns() {
  module_enabled dns || return 0
  log_info "Module: dns"

  local dns_servers=("${DNS_SERVERS_DEFAULT[@]}")
  local dns
  local dig_cmd=""

  if require_cmd dig; then
    dig_cmd="dig"
  elif require_cmd drill; then
    dig_cmd="drill"
  elif require_cmd nslookup; then
    dig_cmd="nslookup"
  fi

  if [[ -z "$dig_cmd" ]]; then
    log_warn "No dig/drill/nslookup found; skipping DNS resolution tests."
    return 0
  fi

  for dns in "${dns_servers[@]}"; do
    local out="$RAW_DIR/dns_google_${dns}.txt"
    if [[ "$dig_cmd" == "nslookup" ]]; then
      run_cmd "nslookup google.com @$dns" "$out" nslookup google.com "$dns"
    else
      run_cmd "$dig_cmd google.com @$dns" "$out" "$dig_cmd" @"$dns" google.com +short
    fi
  done
}

module_ping() {
  module_enabled ping || return 0
  require_icmp || return 0
  log_info "Module: ping"

  local targets=("${TARGETS_DEFAULT[@]}")
  local t
  for t in "${targets[@]}"; do
    run_cmd "ping $t" "$RAW_DIR/ping_${t}.txt" ping -c "$PING_COUNT" "$t"
  done
}

module_traceroute() {
  module_enabled traceroute || return 0
  require_traceroute || return 0
  log_info "Module: traceroute"

  local targets=("${TARGETS_DEFAULT[@]}")
  local t
  for t in "${targets[@]}"; do
    if require_cmd traceroute; then
      run_cmd "traceroute $t" "$RAW_DIR/traceroute_${t}.txt" traceroute -n -m "$TRACEROUTE_MAX_HOPS" "$t"
    elif require_cmd tracepath; then
      run_cmd "tracepath $t" "$RAW_DIR/tracepath_${t}.txt" tracepath -n "$t"
    else
      log_warn "No traceroute/tracepath available; skipping traceroute for $t"
    fi
  done
}

module_mtr() {
  module_enabled mtr || return 0
  if ! require_cmd mtr; then
    log_warn "mtr not installed; skipping."
    return 0
  fi
  log_info "Module: mtr"

  local targets=("${TARGETS_DEFAULT[@]}")
  local t
  for t in "${targets[@]}"; do
    run_cmd "mtr $t" "$RAW_DIR/mtr_${t}.txt" mtr -r -c "$MTR_CYCLES" "$t"
  done
}

module_jitter() {
  module_enabled jitter || return 0
  require_icmp || return 0
  log_info "Module: jitter"
  run_cmd "jitter ping 8.8.8.8" "$RAW_DIR/ping_jitter_8.8.8.8.txt" ping -c "$PING_JITTER_COUNT" 8.8.8.8
}

module_download() {
  module_enabled download || return 0
  if [[ "$ENABLE_DOWNLOAD" -eq 0 ]]; then
    log_info "Download test disabled."
    return 0
  fi
  log_info "Module: download"
  run_cmd "curl download test" "$RAW_DIR/http_download.txt" curl -s -o /dev/null -w "time_total=%{time_total} time_connect=%{time_connect} speed_download=%{speed_download}\n" "$DOWNLOAD_URL"
}

module_speedtest() {
  module_enabled speedtest || return 0
  if [[ "$ENABLE_SPEEDTEST" -eq 0 ]]; then
    log_info "Speedtest disabled."
    return 0
  fi
  log_info "Module: speedtest"

  detect_speedtest
  case "$SPEEDTEST_IMPL" in
    ookla)
      run_cmd "Ookla speedtest" "$RAW_DIR/speedtest_ookla.json" speedtest --accept-license --accept-gdpr -f json
      ;;
    cli)
      run_cmd "speedtest-cli" "$RAW_DIR/speedtest_cli.json" speedtest-cli --json
      ;;
    legacy)
      run_cmd "speedtest (legacy)" "$RAW_DIR/speedtest_legacy.json" speedtest --json
      ;;
    *)
      log_warn "No speedtest CLI found; skipping."
      ;;
  esac
}

module_iperf() {
  module_enabled iperf || return 0
  if [[ "$ENABLE_IPERF" -eq 0 ]]; then
    log_info "iperf3 disabled."
    return 0
  fi
  if ! require_cmd iperf3; then
    log_warn "iperf3 not installed; skipping."
    return 0
  fi
  log_info "Module: iperf3"

  local servers=("${IPERF_SERVERS_DEFAULT[@]}")
  local s
  for s in "${servers[@]}"; do
    run_cmd "iperf3 TCP $s" "$RAW_DIR/iperf3_${s}_tcp.json" iperf3 -c "$s" -p 5201 -J -t 15
    run_cmd "iperf3 UDP $s" "$RAW_DIR/iperf3_${s}_udp.json" iperf3 -c "$s" -p 5201 -u -b 100M -J -t 15
  done
}

module_mtu() {
  module_enabled mtu || return 0
  require_icmp || return 0
  log_info "Module: mtu"

  local sizes=(1472 1400 1200 1000 900)
  local df_flag
  if [[ "$OS_FAMILY" == "linux" ]]; then
    df_flag=(-M do)
  elif [[ "$OS_FAMILY" == "macos" ]]; then
    df_flag=(-D)
  else
    df_flag=()
  fi

  local sz
  for sz in "${sizes[@]}"; do
    local out="$RAW_DIR/mtu_ping_${sz}.txt"
    run_cmd "mtu ping $sz" "$out" ping -c 3 "${df_flag[@]}" -s "$sz" 1.1.1.1
    local ec
    ec="$(cat "${out}.exitcode" 2>/dev/null || echo 1)"
    if [[ "$ec" -eq 0 ]]; then
      echo "payload $sz ok" >> "$RAW_DIR/mtu_results.txt"
      log_info "MTU OK for payload $sz"
      break
    fi
    echo "payload $sz fails" >> "$RAW_DIR/mtu_results.txt"
    log_warn "payload $sz fails"
  done
}

module_port_probe() {
  module_enabled port_probe || return 0
  if [[ "$ENABLE_PORT_PROBE" -eq 0 || -z "$PORT_PROBE_TARGET" ]]; then
    log_info "Port probe disabled or target not set."
    return 0
  fi
  log_info "Module: port_probe"

  local out="$RAW_DIR/port_probe_${PORT_PROBE_TARGET}.txt"
  ensure_dir "$(dirname "$out")"
  : > "$out"

  local port
  for port in "${PORTS_DEFAULT[@]}"; do
    if [[ -n "$TIMEOUT_CMD" ]]; then
      $TIMEOUT_CMD 5 bash -c "echo > /dev/tcp/${PORT_PROBE_TARGET}/${port}" >/dev/null 2>&1 && echo "$port: OPEN" || echo "$port: CLOSED/FILTERED"
    else
      bash -c "echo > /dev/tcp/${PORT_PROBE_TARGET}/${port}" >/dev/null 2>&1 && echo "$port: OPEN" || echo "$port: CLOSED/FILTERED"
    fi
  done >> "$out"
}

module_port_scan() {
  module_enabled port_scan || return 0
  if [[ "$ENABLE_PORT_SCAN" -eq 0 || -z "$PORT_SCAN_TARGET" ]]; then
    log_info "Port scan disabled or target not set."
    return 0
  fi
  if ! require_cmd nmap; then
    log_warn "nmap not installed; skipping port scan."
    return 0
  fi
  log_info "Module: port_scan"

  run_cmd "nmap scan $PORT_SCAN_TARGET" "$RAW_DIR/nmap_${PORT_SCAN_TARGET}.txt" nmap -Pn -p 80,443,1194,1701,500,4500,51820 "$PORT_SCAN_TARGET"
}

module_tcpdump() {
  module_enabled tcpdump || return 0
  if [[ "$ENABLE_CAPTURE" -eq 0 ]]; then
    log_info "tcpdump capture disabled."
    return 0
  fi
  if ! require_cmd tcpdump; then
    log_warn "tcpdump not installed; skipping."
    return 0
  fi

  local iface=""
  if [[ "$OS_FAMILY" == "macos" ]]; then
    iface=$(route get default 2>/dev/null | awk '/interface:/{print $2}' || true)
  elif [[ "$OS_FAMILY" == "linux" ]]; then
    iface=$(ip route show default 2>/dev/null | awk '{print $5; exit}' || true)
  fi
  [[ -z "$iface" ]] && iface="any"

  local pcap="$PCAP_DIR/capture_${iface}.pcap"
  log_info "Module: tcpdump (iface=$iface, seconds=$CAPTURE_DURATION)"

  if [[ "$ALLOW_SUDO" -eq 1 ]]; then
    run_cmd "tcpdump capture" "$RAW_DIR/tcpdump.log" sudo tcpdump -i "$iface" -s 0 -w "$pcap" -G "$CAPTURE_DURATION" -W 1 not port 22
  else
    log_warn "tcpdump requires elevated privileges. Re-run with --allow-sudo --capture"
  fi
}

module_whois() {
  module_enabled whois || return 0
  if ! require_cmd whois; then
    log_warn "whois not installed; skipping."
    return 0
  fi
  if ! require_cmd traceroute; then
    log_warn "traceroute not installed; skipping whois."
    return 0
  fi
  require_traceroute || return 0
  log_info "Module: whois"

  local trace_out="$RAW_DIR/traceroute_firsthop.txt"
  run_cmd "traceroute short" "$trace_out" traceroute -m 5 8.8.8.8
  local ec
  ec="$(cat "${trace_out}.exitcode" 2>/dev/null || echo 1)"
  if [[ "$ec" -ne 0 ]]; then
    log_warn "Unable to determine first hop."
    return 0
  fi

  local hop
  hop="$(awk 'NR==2{print $2}' "$trace_out")"
  if [[ -n "$hop" ]]; then
    run_cmd "whois $hop" "$RAW_DIR/whois_${hop}.txt" whois "$hop"
  else
    log_warn "Unable to determine first hop."
  fi
}

write_summary() {
  {
    echo "Run ID: $RUN_ID"
    echo "Start UTC: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "OS: $OS_FAMILY"
    echo "Timeout cmd: ${TIMEOUT_CMD:-none}"
    echo "Enabled modules: ${ENABLED_MODULES[*]:-all default}";
    echo "Skipped modules: ${SKIP_MODULES[*]:-none}";
    echo "Output dir: $BASE_OUTDIR/$RUN_ID";
    echo ""
    echo "Raw outputs: $RAW_DIR"
    echo "Metadata: $META_DIR"
    echo "PCAPs: $PCAP_DIR"
  } > "$SUMMARY_FILE"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--outdir)
        BASE_OUTDIR="$2"; shift 2;;
      -t|--targets)
        split_csv "$2" TARGETS_DEFAULT; shift 2;;
      -d|--dns-servers)
        split_csv "$2" DNS_SERVERS_DEFAULT; shift 2;;
      -m|--modules)
        split_csv "$2" ENABLED_MODULES; shift 2;;
      -s|--skip)
        split_csv "$2" SKIP_MODULES; shift 2;;
      --list-modules)
        printf "%s\n" "${AVAILABLE_MODULES[@]}"; exit 0;;
      --timeout)
        CMD_TIMEOUT="$2"; shift 2;;
      --ping-count)
        PING_COUNT="$2"; shift 2;;
      --jitter-count)
        PING_JITTER_COUNT="$2"; shift 2;;
      --download-url)
        DOWNLOAD_URL="$2"; shift 2;;
      --no-download)
        ENABLE_DOWNLOAD=0; shift 1;;
      --no-speedtest)
        ENABLE_SPEEDTEST=0; shift 1;;
      --iperf)
        ENABLE_IPERF=1; shift 1;;
      --port-probe)
        PORT_PROBE_TARGET="$2"; shift 2;;
      --allow-ports)
        ENABLE_PORT_PROBE=1; ENABLE_PORT_SCAN=1; shift 1;;
      --port-scan)
        PORT_SCAN_TARGET="$2"; shift 2;;
      --capture)
        ENABLE_CAPTURE=1; shift 1;;
      --capture-seconds)
        CAPTURE_DURATION="$2"; shift 2;;
      --allow-sudo)
        ALLOW_SUDO=1; shift 1;;
      -h|--help)
        usage; exit 0;;
      *)
        echo "Unknown option: $1"; usage; exit 1;;
    esac
  done
}

main() {
  parse_args "$@"
  detect_os
  detect_timeout
  init_output
  write_metadata
  check_dependencies

  module_system
  module_network
  module_dns
  module_ping
  module_traceroute
  module_mtr
  module_jitter
  module_download
  module_speedtest
  module_iperf
  module_mtu
  module_port_probe
  module_port_scan
  module_tcpdump
  module_whois

  write_summary
  log_info "All tests done. Outputs in $BASE_OUTDIR/$RUN_ID"
}

main "$@"










#!/usr/bin/env bash
#  internet_autopsy_pro.sh  v3.0.0
#  Deep network forensics, ISP analysis & censorship detection
# This is the second script, which is commented.



# set -Eeuo pipefail
# IFS=$'\n\t'
# umask 077


# SCRIPT_NAME="$(basename "$0")"
# SCRIPT_VERSION="3.0.0"


# BASE_OUTDIR="${HOME}/network_forensics_results"
# RUN_ID=""
# LOG_FILE=""
# REPORT_FILE=""
# RAW_DIR=""
# META_DIR=""
# PCAP_DIR=""
# EVIDENCE_DIR=""


# CMD_TIMEOUT=20
# LONG_TIMEOUT=60
# PING_COUNT=20
# PING_JITTER_COUNT=50
# TRACEROUTE_MAX_HOPS=30
# MTR_CYCLES=100
# CAPTURE_DURATION=30
# ALLOW_SUDO=0
# ENABLE_CAPTURE=0
# ENABLE_IPERF=0
# ENABLE_SPEEDTEST=1
# ENABLE_DOWNLOAD=1
# VERBOSE=0


# NEUTRAL_TARGETS=(
#   "8.8.8.8"       
#   "1.1.1.1"       
#   "208.67.222.222" 
#   "9.9.9.9"       
# )

# DOMAIN_TARGETS=(
#   "google.com"
#   "cloudflare.com"
#   "github.com"
#   "youtube.com"
#   "facebook.com"
#   "twitter.com"
#   "instagram.com"
#   "wikipedia.org"
#   "reddit.com"
#   "whatsapp.com"
#   "signal.org"
#   "proton.me"
#   "tor.eff.org"
# )

# CANARY_DOMAINS=(
#   "www.torproject.org"
#   "www.vpnbook.com"
#   "censys.io"
#   "ooni.org"
# )


# declare -A KNOWN_GOOD_IPS
# KNOWN_GOOD_IPS["google.com"]="142.250."
# KNOWN_GOOD_IPS["cloudflare.com"]="104.16."
# KNOWN_GOOD_IPS["github.com"]="140.82."
# KNOWN_GOOD_IPS["youtube.com"]="142.250."

# DNS_SERVERS=(
#   "8.8.8.8"       
#   "1.1.1.1"        
#   "9.9.9.9"      
#   "208.67.222.222" 
#   "77.88.8.8"    
# )

# IPERF_SERVERS=("iperf.he.net" "iperf.scottlinux.com")
# DOWNLOAD_URL="https://speed.hetzner.de/100MB.bin"
# PORTS_TO_PROBE=(80 443 8080 8443 1194 51820 4500 500 853 784)


# OS_FAMILY=""
# TIMEOUT_CMD=""
# ICMP_OK="unknown"


# declare -a FINDINGS_CRITICAL=()
# declare -a FINDINGS_WARNING=()
# declare -a FINDINGS_INFO=()

# finding_critical() { FINDINGS_CRITICAL+=("$*"); log_warn " CRITICAL: $*"; }
# finding_warning()  { FINDINGS_WARNING+=("$*");  log_warn " WARNING:  $*"; }
# finding_info()     { FINDINGS_INFO+=("$*");     log_info "INFO:     $*"; }


# log() {
#   local level="$1"; shift
#   local ts; ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
#   local line="$ts [$level] $*"
#   echo "$line" >> "$LOG_FILE"
#   if [[ "$VERBOSE" -eq 1 ]] || [[ "$level" == "WARN" ]] || [[ "$level" == "ERROR" ]]; then
#     echo "$line" >&2
#   fi
# }
# log_info()  { log "INFO"  "$*"; }
# log_warn()  { log "WARN"  "$*"; }
# log_error() { log "ERROR" "$*"; }

# on_error() {
#   local exit_code=$? line_no=$1 cmd=$2
#   log_error "Command failed (exit $exit_code) at line $line_no: $cmd"
# }
# trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR


# require_cmd() { command -v "$1" >/dev/null 2>&1; }
# ensure_dir()  { mkdir -p "$1"; }

# tcmd() {

#   if [[ -n "$TIMEOUT_CMD" && "${1:-}" =~ ^[0-9]+$ ]]; then
#     local t="$1"; shift
#     "$TIMEOUT_CMD" "$t" "$@"
#   else
#     "$@"
#   fi
# }

# run_cmd() {
#   local label="$1" out="$2"; shift 2
#   log_info "RUN: $label"
#   ensure_dir "$(dirname "$out")"
#   local ec=0
#   if [[ -n "$TIMEOUT_CMD" && "$CMD_TIMEOUT" -gt 0 ]]; then
#     "$TIMEOUT_CMD" "$CMD_TIMEOUT" "$@" >"$out" 2>&1 || ec=$?
#   else
#     "$@" >"$out" 2>&1 || ec=$?
#   fi
#   echo "$ec" > "${out}.exitcode"
#   [[ $ec -ne 0 ]] && log_warn "  ↳ exit $ec: $label"
#   return 0
# }

# run_long() {
#   local label="$1" out="$2"; shift 2
#   log_info "RUN(long): $label"
#   ensure_dir "$(dirname "$out")"
#   local ec=0
#   if [[ -n "$TIMEOUT_CMD" ]]; then
#     "$TIMEOUT_CMD" "$LONG_TIMEOUT" "$@" >"$out" 2>&1 || ec=$?
#   else
#     "$@" >"$out" 2>&1 || ec=$?
#   fi
#   echo "$ec" > "${out}.exitcode"
#   return 0
# }

# exit_code_of() { cat "${1}.exitcode" 2>/dev/null || echo 1; }

# color() {
#   local c="$1"; shift
#   case "$c" in
#     red)    printf '\033[0;31m%s\033[0m' "$*";;
#     yellow) printf '\033[0;33m%s\033[0m' "$*";;
#     green)  printf '\033[0;32m%s\033[0m' "$*";;
#     bold)   printf '\033[1m%s\033[0m'    "$*";;
#     *)      printf '%s' "$*";;
#   esac
# }

# separator() { printf '━%.0s' {1..70}; printf '\n'; }

# detect_os() {
#   case "$(uname -s)" in
#     Darwin) OS_FAMILY="macos";;
#     Linux)  OS_FAMILY="linux";;
#     *)      OS_FAMILY="unknown";;
#   esac
# }

# detect_timeout() {
#   if   require_cmd gtimeout; then TIMEOUT_CMD="gtimeout"
#   elif require_cmd timeout;  then TIMEOUT_CMD="timeout"
#   else                            TIMEOUT_CMD=""
#   fi
# }

# init_output() {
#   RUN_ID="$(date +"%Y%m%d_%H%M%S")"
#   local outdir="$BASE_OUTDIR/$RUN_ID"
#   RAW_DIR="$outdir/raw"
#   META_DIR="$outdir/meta"
#   PCAP_DIR="$outdir/pcap"
#   EVIDENCE_DIR="$outdir/evidence"
#   LOG_FILE="$outdir/run.log"
#   REPORT_FILE="$outdir/REPORT.md"

#   ensure_dir "$RAW_DIR" "$META_DIR" "$PCAP_DIR" "$EVIDENCE_DIR"
#   touch "$LOG_FILE" "$REPORT_FILE"
#   log_info "Forensic run started: $RUN_ID  →  $outdir"
# }

# print_banner() {
#   cat >&2 <<'BANNER'

#   ╔══════════════════════════════════════════════════════════════════╗
#   ║         INTERNET AUTOPSY PRO  —  Network Forensics v3           ║
#   ║   DNS hijack · DPI · throttling · censorship · ISP analysis     ║
#   ╚══════════════════════════════════════════════════════════════════╝

# BANNER
# }


# module_identity() {
#   log_info "━━━ MODULE: Identity & Environment"
#   local out="$META_DIR/identity.txt"
#   {
#     echo "=== System ==="
#     uname -a
#     echo ""
#     echo "=== Public IPv4 ==="
#     curl -s --max-time 5 https://api4.ipify.org 2>/dev/null || echo "unavailable"
#     echo ""
#     echo "=== Public IPv6 ==="
#     curl -s --max-time 5 https://api6.ipify.org 2>/dev/null || echo "unavailable"
#     echo ""
#     echo "=== IP Geolocation & ASN ==="
#     curl -s --max-time 10 "https://ipinfo.io/json" 2>/dev/null || echo "unavailable"
#     echo ""
#     echo "=== Second ASN source ==="
#     curl -s --max-time 10 "https://ip-api.com/json?fields=status,message,country,regionName,city,isp,org,as,reverse,proxy,hosting,query" 2>/dev/null || echo "unavailable"
#   } | tee "$out"


#   local asn
#   asn=$(grep -oE 'AS[0-9]+' "$out" | head -1 || true)
#   echo "$asn" > "$META_DIR/asn.txt"
#   [[ -n "$asn" ]] && finding_info "Your ASN: $asn"
# }

# module_local_network() {
#   log_info "━━━ MODULE: Local Network Configuration"

#   if [[ "$OS_FAMILY" == "macos" ]]; then
#     run_cmd "ifconfig"     "$RAW_DIR/ifconfig.txt"      ifconfig -a
#     run_cmd "netstat -rn"  "$RAW_DIR/routes.txt"        netstat -rn
#     run_cmd "scutil --dns" "$RAW_DIR/scutil_dns.txt"    scutil --dns
#     run_cmd "nettop snap"  "$RAW_DIR/nettop.txt"        nettop -n -L 1 2>/dev/null || true

#     local sys_dns
#     sys_dns=$(scutil --dns 2>/dev/null | grep "nameserver\[0\]" | awk '{print $3}' | head -3 | tr '\n' ' ')
#     [[ -n "$sys_dns" ]] && finding_info "System DNS resolver(s): $sys_dns"
#   else
#     run_cmd "ip addr"      "$RAW_DIR/ip_addr.txt"       ip addr
#     run_cmd "ip route"     "$RAW_DIR/ip_route.txt"      ip route
#     run_cmd "ip -6 route"  "$RAW_DIR/ip6_route.txt"     ip -6 route 2>/dev/null || true
#     run_cmd "ss -tuln"     "$RAW_DIR/sockets.txt"       ss -tuln 2>/dev/null || true
#     run_cmd "resolv.conf"  "$RAW_DIR/resolv_conf.txt"   cat /etc/resolv.conf

#     if [[ -f /etc/resolv.conf ]]; then
#       local sys_dns
#       sys_dns=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
#       finding_info "Configured nameservers: $sys_dns"
#       # 127.0.x = stub resolver
#       if echo "$sys_dns" | grep -qE "127\.0\.[0-9]+\.[0-9]+|::1"; then
#         finding_info "Local stub resolver detected (systemd-resolved or dnsmasq)"
#       fi
#     fi
#   fi
# }


# module_dns_forensics() {
#   log_info "━━━ MODULE: DNS Forensics"

#   local dig_cmd=""
#   if   require_cmd dig;      then dig_cmd="dig"
#   elif require_cmd drill;    then dig_cmd="drill"
#   elif require_cmd nslookup; then dig_cmd="nslookup"
#   fi

#   if [[ -z "$dig_cmd" ]]; then
#     log_warn "No DNS query tool available (dig/drill/nslookup). Skipping DNS forensics."
#     return 0
#   fi

 
#   log_info "  → DNS resolver fingerprinting"
#   {
#     echo "=== Resolver Identification ==="
    
#     if [[ "$dig_cmd" == "dig" ]]; then
#       dig +short +time=5 whoami.akamai.net 2>/dev/null || echo "failed"
#       echo "--- Resolver identifies as: ---"
#       dig +short +time=5 o-o.myaddr.l.google.com TXT 2>/dev/null || echo "failed"
#     fi
#   } | tee "$META_DIR/resolver_id.txt"


#   log_info "  → Cross-server DNS comparison (hijack detection)"
#   local ev="$EVIDENCE_DIR/dns_comparison.txt"
#   echo "# DNS Answer Comparison — $(date -u)" > "$ev"
#   echo "# Different answers = potential DNS hijacking or manipulation" >> "$ev"
#   echo "" >> "$ev"

#   local domain
#   for domain in "${DOMAIN_TARGETS[@]}"; do
#     echo "=== $domain ===" >> "$ev"
#     local prev_ans="" mismatch=0
#     local dns
#     for dns in "${DNS_SERVERS[@]}"; do
#       local ans=""
#       if [[ "$dig_cmd" == "dig" ]]; then
#         ans=$(tcmd 8 dig +short +time=4 "@$dns" "$domain" A 2>/dev/null | sort | tr '\n' ',' || echo "TIMEOUT/ERROR")
#       elif [[ "$dig_cmd" == "drill" ]]; then
#         ans=$(tcmd 8 drill -Q "@$dns" "$domain" A 2>/dev/null | sort | tr '\n' ',' || echo "TIMEOUT/ERROR")
#       else
#         ans=$(tcmd 8 nslookup "$domain" "$dns" 2>/dev/null | grep "Address:" | tail -n +2 | awk '{print $2}' | sort | tr '\n' ',' || echo "TIMEOUT/ERROR")
#       fi
#       printf "  %-20s → %s\n" "$dns" "$ans" >> "$ev"


#       if echo "$ans" | grep -qE "^(0\.0\.0\.0|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|1\.1\.1\.1,|8\.8\.8\.8,)"; then
#         finding_warning "DNS sink/block response for $domain from $dns: $ans"
#         mismatch=1
#       fi

#       if [[ -n "$prev_ans" && "$ans" != "$prev_ans" && "$ans" != "TIMEOUT/ERROR" && "$prev_ans" != "TIMEOUT/ERROR" ]]; then
#         mismatch=1
#       fi
#       [[ "$ans" != "TIMEOUT/ERROR" ]] && prev_ans="$ans"
#     done

#     if [[ "$mismatch" -eq 1 ]]; then
#       finding_critical "DNS answers DIFFER across resolvers for $domain — possible DNS hijacking or filtering"
#       echo " MISMATCH DETECTED" >> "$ev"
#     fi
#     echo "" >> "$ev"
#   done

#   log_info "  → NXDOMAIN hijacking detection"
#   local fake_domain="thisdomain-absolutely-does-not-exist-$(date +%s).com"
#   local nxcheck="$EVIDENCE_DIR/nxdomain_hijack.txt"
#   echo "# Testing: $fake_domain" > "$nxcheck"
#   local nxans=""
#   if [[ "$dig_cmd" == "dig" ]]; then
#     nxans=$(tcmd 8 dig +short +time=5 "$fake_domain" A 2>/dev/null || echo "TIMEOUT")
#     echo "Answer: $nxans" >> "$nxcheck"
#     local nxstatus
#     nxstatus=$(tcmd 8 dig +time=5 "$fake_domain" A 2>/dev/null | grep "^;; ->>HEADER<<-" | grep -o "status: [A-Z]*" || echo "unknown")
#     echo "Status: $nxstatus" >> "$nxcheck"
#   fi

#   if [[ -n "$nxans" && "$nxans" != "TIMEOUT" ]]; then
#     finding_critical "NXDOMAIN HIJACKING: Fake domain '$fake_domain' resolved to '$nxans' — ISP or resolver is redirecting NXDOMAIN responses (likely to ad/block page)"
#   else
#     finding_info "NXDOMAIN hijacking: not detected"
#   fi

#   log_info "  → DoH / DoT availability test"
#   local doh_out="$RAW_DIR/doh_test.txt"
#   {
#     echo "=== Cloudflare DoH ==="
#     curl -s --max-time 8 -H 'accept: application/dns-json' \
#       "https://1.1.1.1/dns-query?name=google.com&type=A" 2>/dev/null || echo "BLOCKED/FAILED"
#     echo ""
#     echo "=== Google DoH ==="
#     curl -s --max-time 8 -H 'accept: application/dns-json' \
#       "https://8.8.8.8/dns-query?name=google.com&type=A" 2>/dev/null || echo "BLOCKED/FAILED"
#   } | tee "$doh_out"

#   if grep -q "BLOCKED/FAILED" "$doh_out"; then
#     finding_warning "DoH (DNS-over-HTTPS) appears to be blocked or failing"
#   else
#     finding_info "DoH appears to be available"
#   fi


#   local dot_check
#   dot_check=$(tcmd 8 bash -c "echo | openssl s_client -connect 1.1.1.1:853 -quiet 2>&1" | head -5 || echo "FAILED")
#   if echo "$dot_check" | grep -qiE "connected|CONNECTED|certificate"; then
#     finding_info "DoT (DNS-over-TLS) port 853 reachable at 1.1.1.1"
#   else
#     finding_warning "DoT (DNS-over-TLS) port 853 appears blocked to 1.1.1.1"
#   fi
# }


# module_http_forensics() {
#   log_info "━━━ MODULE: HTTP/HTTPS Transparency & Proxy Detection"


#   log_info "  → HTTP header injection detection"
#   local hdr_out="$EVIDENCE_DIR/http_headers_injected.txt"
#   {
#     echo "=== What does the HTTP echo server see? ==="
#     echo "(Injected X- headers, Via, Forwarded = transparent proxy present)"
#     echo ""

#     curl -s --max-time 10 -A "NetworkForensics/3.0" \
#       -H "X-Probe-ID: forensic-baseline-$(date +%s)" \
#       "http://httpbin.org/headers" 2>/dev/null || echo "FAILED"
#     echo ""
#     echo "=== HTTPS echo ==="
#     curl -s --max-time 10 -A "NetworkForensics/3.0" \
#       "https://httpbin.org/headers" 2>/dev/null || echo "FAILED"
#   } | tee "$hdr_out"


#   if grep -qiE '"Via"|"X-Forwarded-For"|"X-Proxy|"X-Cache|"Forwarded"' "$hdr_out"; then
#     finding_critical "TRANSPARENT PROXY DETECTED: HTTP echo shows injected headers (Via/X-Forwarded-For/X-Cache) — your ISP is intercepting HTTP traffic"
#   fi


#   log_info "  → HTTP content injection test"
#   local plain_body="$EVIDENCE_DIR/http_plain_body.txt"
#   local https_body="$EVIDENCE_DIR/https_body.txt"

#   tcmd 12 curl -s --max-time 10 --compressed \
#     "http://neverssl.com" > "$plain_body" 2>/dev/null || echo "FAILED" > "$plain_body"
#   tcmd 12 curl -s --max-time 10 --compressed \
#     "https://httpbin.org/get" > "$https_body" 2>/dev/null || echo "FAILED" > "$https_body"

#   if grep -iqE "advertisement|injected|<script.*src=|isp\.example\|redirect" "$plain_body" 2>/dev/null; then
#     finding_critical "CONTENT INJECTION detected in plain HTTP response — ISP is modifying unencrypted HTTP traffic"
#   fi


#   log_info "  → TLS certificate MITM detection"
#   local cert_out="$EVIDENCE_DIR/tls_cert_check.txt"
#   {
#     echo "=== TLS Certificate Verification ==="
#     local domain
#     for domain in google.com cloudflare.com github.com; do
#       echo "--- $domain ---"

#       echo | tcmd 10 openssl s_client -connect "${domain}:443" \
#         -servername "$domain" \
#         -verify_return_error \
#         -verify_hostname "$domain" \
#         2>&1 | grep -E "subject=|issuer=|Verify return code|CONNECTED" || echo "FAILED to connect"
#       echo ""
#     done
#   } | tee "$cert_out"

#   if grep -E "issuer=" "$cert_out" | grep -qvE "Let's Encrypt|DigiCert|GlobalSign|Sectigo|Google Trust|Amazon|Cloudflare|Entrust|GeoTrust"; then
#     finding_critical "UNEXPECTED TLS ISSUER DETECTED — possible TLS MITM/interception (corp proxy or ISP SSL inspection)"
#   fi


#   log_info "  → SNI-based filtering detection"
#   local sni_out="$EVIDENCE_DIR/sni_filter.txt"
#   {
#     echo "=== SNI Filtering Test ==="
#     echo "(Connect to same IP but different SNI hostnames)"
#     echo ""
  
#     local test_sni
#     for test_sni in "google.com" "youtube.com" "facebook.com" "twitter.com" "www.torproject.org"; do
#       printf "SNI %-30s → " "$test_sni"
#       # Use Cloudflare's IP 1.1.1.1 but vary the SNI
#       local result
#       result=$(echo | tcmd 8 openssl s_client \
#         -connect "1.1.1.1:443" \
#         -servername "$test_sni" \
#         -verify_return_error 2>&1 | grep -oE "Verify return code: [0-9]+ \(.*\)" | head -1 || echo "FAILED/BLOCKED")
#       echo "$result"
#     done
#   } | tee "$sni_out"

 
#   log_info "  → Domain accessibility test (HTTP response forensics)"
#   local block_out="$EVIDENCE_DIR/domain_block_test.txt"
#   {
#     echo "=== Domain Accessibility (HTTP response codes & timing) ==="
#     local domain
#     for domain in "${DOMAIN_TARGETS[@]}"; do
#       local resp
#       resp=$(tcmd 12 curl -s --max-time 8 -o /dev/null \
#         -w "%{http_code} time=%{time_total}s redirect=%{num_redirects} final=%{url_effective}" \
#         "https://${domain}/" 2>/dev/null || echo "000 FAILED")
#       printf "%-35s %s\n" "$domain" "$resp"

    
#       if echo "$resp" | grep -qE "^000"; then
#         finding_warning "Domain $domain is UNREACHABLE (connection failed/reset)"
#       fi
#     done
#   } | tee "$block_out"
# }

# module_rst_detection() {
#   log_info "━━━ MODULE: TCP RST Injection Detection"


#   local rst_out="$EVIDENCE_DIR/rst_injection.txt"
#   {
#     echo "=== TCP RST Injection Probe ==="
#     echo "Connecting to filtered domain candidates..."
#     echo ""
#     local domain
#     for domain in "www.torproject.org" "www.bbc.com" "twitter.com" "facebook.com"; do
#       printf "TCP SYN → %-30s (port 443): " "$domain"
#       local conn_out
#       conn_out=$(tcmd 8 curl -v --max-time 6 "https://${domain}/" 2>&1 || true)
#       if echo "$conn_out" | grep -qiE "connection reset|RST|Connection refused"; then
#         echo "⚠ RST RECEIVED"
#         finding_critical "TCP RST injection possible on $domain — DPI device may be terminating connections"
#       elif echo "$conn_out" | grep -q "SSL connection using"; then
#         echo "OK (TLS established)"
#       elif echo "$conn_out" | grep -q "timed out"; then
#         echo "TIMEOUT (null-routed / blackholed)"
#         finding_warning "$domain connections are being null-routed (timeout, no RST)"
#       else
#         echo "? ($( echo "$conn_out" | grep -oE "curl: \([0-9]+\).*" | head -1 || echo 'see evidence'))"
#       fi
#     done
#   } | tee "$rst_out"
# }

# module_bgp_routing() {
#   log_info "━━━ MODULE: BGP & Routing Forensics"

#   local bgp_out="$EVIDENCE_DIR/bgp_routing.txt"
#   {
#     echo "=== BGP Route Analysis via RIPEstat ==="
#     echo ""

#     local my_ip
#     my_ip=$(curl -s --max-time 5 https://api4.ipify.org 2>/dev/null || echo "unknown")

#     if [[ "$my_ip" != "unknown" ]]; then
#       echo "--- Your IP's BGP prefix & ASN path ---"
#       curl -s --max-time 12 \
#         "https://stat.ripe.net/data/prefix-overview/data.json?resource=${my_ip}" \
#         2>/dev/null | (require_cmd jq && jq -r '.data | {prefix:.resource, asns:(.asns[]?.asn), block:.block.desc}' 2>/dev/null || cat) || echo "FAILED"

#       echo ""
#       echo "--- Routing History (BGP stability) ---"
#       curl -s --max-time 12 \
#         "https://stat.ripe.net/data/routing-history/data.json?resource=${my_ip}&min_peers_seeing=10" \
#         2>/dev/null | head -200 || echo "FAILED"
#     fi

#     echo ""
#     echo "=== Traceroute Path Analysis ==="
#     echo "(Asymmetric paths, unexpected countries, missing hops = traffic rerouting)"
#   } | tee "$bgp_out"

#   local tr_ann="$EVIDENCE_DIR/traceroute_annotated.txt"
#   {
#     echo "=== Annotated Traceroute (Google DNS) ==="
#     echo "Format: hop | IP | latency | ASN | ISP/Org"
#     echo ""

#     local trace_raw="$RAW_DIR/traceroute_google.txt"
#     if require_cmd traceroute; then
#       tcmd 45 traceroute -n -m 30 8.8.8.8 > "$trace_raw" 2>&1 || true
#     elif require_cmd tracepath; then
#       tcmd 45 tracepath -n 8.8.8.8 > "$trace_raw" 2>&1 || true
#     else
#       echo "No traceroute tool available" > "$trace_raw"
#     fi

#     cat "$trace_raw"
#     echo ""


#     if require_cmd dig && grep -qE "^\s*[0-9]" "$trace_raw"; then
#       echo "--- ASN Annotation ---"
#       while IFS= read -r line; do
#         local hop_ip
#         hop_ip=$(echo "$line" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
#         if [[ -n "$hop_ip" ]]; then
        
#           local reversed
#           reversed=$(echo "$hop_ip" | awk -F. '{print $4"."$3"."$2"."$1}')
#           local asn_info
#           asn_info=$(tcmd 5 dig +short "${reversed}.origin.asn.cymru.com" TXT 2>/dev/null | tr -d '"' || echo "unknown")
#           printf "%-16s %s\n" "$hop_ip" "$asn_info"
#         fi
#       done < "$trace_raw"
#     fi
#   } | tee "$tr_ann"


#   if grep -qiE "russia|china|iran|turkey|belarus" "$bgp_out" 2>/dev/null; then
#     finding_warning "BGP data suggests traffic may transit through restricted/unusual countries"
#   fi
# }


# module_throttle_detection() {
#   log_info "━━━ MODULE: Throttling & Traffic Shaping Detection"

#   local thr_out="$EVIDENCE_DIR/throttle_analysis.txt"
#   {
#     echo "=== Traffic Shaping / Throttling Analysis ==="
#     echo "Compares download speeds across different protocols, ports, and destinations."
#     echo "Significant variation = differential throttling by ISP."
#     echo ""

#     echo "--- Test 1: HTTPS bulk download (Hetzner 100MB) ---"
#     local speed_https
#     speed_https=$(tcmd 40 curl -s --max-time 35 -o /dev/null \
#       -w "speed=%{speed_download} bytes/s time=%{time_total}s" \
#       "$DOWNLOAD_URL" 2>/dev/null || echo "FAILED")
#     echo "HTTPS bulk: $speed_https"

#     echo ""
#     echo "--- Test 2: HTTP vs HTTPS speed differential ---"
#     local speed_http
#     speed_http=$(tcmd 30 curl -s --max-time 25 -o /dev/null \
#       -w "speed=%{speed_download} bytes/s time=%{time_total}s" \
#       "http://speedtest.tele2.net/10MB.zip" 2>/dev/null || echo "FAILED")
#     echo "HTTP bulk:  $speed_http"

#     echo ""
#     echo "--- Test 3: Multiple CDN comparison (same content, different providers) ---"
#     local url
#     for url in \
#       "https://speed.hetzner.de/1MB.bin|Hetzner-EU" \
#       "https://proof.ovh.net/files/1Mb.dat|OVH-EU" \
#       "http://speedtest.tele2.net/1MB.zip|Tele2"; do
#       local u="${url%%|*}" label="${url##*|}"
#       local sp
#       sp=$(tcmd 20 curl -s --max-time 15 -o /dev/null \
#         -w "%{speed_download}" "$u" 2>/dev/null || echo "0")
#       local sp_mb
#       sp_mb=$(awk "BEGIN {printf \"%.2f\", $sp/1048576}" 2>/dev/null || echo "?")
#       printf "  %-20s %s MB/s\n" "$label" "$sp_mb"
#     done

#     echo ""
#     echo "--- Test 4: Speedtest via popular service ---"
#     if require_cmd speedtest-cli; then
#       tcmd 60 speedtest-cli --simple 2>/dev/null || echo "speedtest-cli not available or failed"
#     elif require_cmd speedtest; then
#       tcmd 60 speedtest --accept-license -f human-readable 2>/dev/null || echo "speedtest failed"
#     else
#       echo "No speedtest binary installed (install speedtest-cli)"
#     fi

#     echo ""
#     echo "--- Test 5: YouTube / video throttling indicator ---"
#     local yt_url="https://r1---sn-uxax4vopj5qx-tt1e7.googlevideo.com/generate_204"
#     local yt_resp
#     yt_resp=$(tcmd 10 curl -s --max-time 8 -o /dev/null \
#       -w "http=%{http_code} time=%{time_connect}s" \
#       "$yt_url" 2>/dev/null || echo "FAILED")
#     echo "GoogleVideo CDN probe: $yt_resp"

#   } | tee "$thr_out"


#   local dl_speed
#   dl_speed=$(grep "HTTPS bulk:" "$thr_out" | grep -oE "speed=[0-9]+" | head -1 | cut -d= -f2 || echo "0")
#   if [[ "$dl_speed" -gt 0 ]]; then
#     local dl_mbps
#     dl_mbps=$(awk "BEGIN {printf \"%.1f\", $dl_speed/131072}" 2>/dev/null || echo "?")
#     finding_info "HTTPS bulk download: ~${dl_mbps} Mbps"
#     if [[ "$dl_speed" -lt 262144 ]]; then  # < 2 Mbps
#       finding_warning "HTTPS bulk download speed is very low (${dl_mbps} Mbps) — possible throttling or congestion"
#     fi
#   fi
# }


# module_latency_forensics() {
#   log_info "━━━ MODULE: Latency, Jitter & Packet Loss Forensics"

#   if ! tcmd 5 ping -c 1 1.1.1.1 >/dev/null 2>&1; then
#     log_warn "ICMP blocked — skipping ping-based tests. Try with sudo."
#     finding_warning "ICMP ping is blocked — limits latency diagnostics"
#     return 0
#   fi

#   local lat_out="$EVIDENCE_DIR/latency_analysis.txt"
#   {
#     echo "=== Latency Deep Analysis ==="
#     echo ""

#     local target
#     for target in 1.1.1.1 8.8.8.8 208.67.222.222; do
#       echo "--- Ping $target ($PING_COUNT packets) ---"
#       tcmd 60 ping -c "$PING_COUNT" "$target" 2>/dev/null || echo "FAILED"
#       echo ""
#     done

#     echo "--- Extended jitter test (${PING_JITTER_COUNT} packets to 8.8.8.8) ---"
#     tcmd 90 ping -c "$PING_JITTER_COUNT" 8.8.8.8 2>/dev/null | tee "$RAW_DIR/jitter_raw.txt" || echo "FAILED"
#     echo ""


#     if [[ -f "$RAW_DIR/jitter_raw.txt" ]]; then
#       echo "--- Computed jitter (stddev of RTT) ---"
#       grep -oE "[0-9]+\.[0-9]+ ms$" "$RAW_DIR/jitter_raw.txt" 2>/dev/null | \
#         awk '{sum+=$1; sumsq+=$1*$1; n++}
#              END {
#                if(n>1) {
#                  avg=sum/n; var=(sumsq/n)-(avg*avg);
#                  jitter=sqrt(var<0?0:var);
#                  printf "Avg RTT: %.2f ms | Jitter (stddev): %.2f ms | Samples: %d\n", avg, jitter, n
#                }
#              }' || echo "insufficient data"
#     fi

#     echo ""
#     echo "--- MTR (combined traceroute + ping) ---"
#     if require_cmd mtr; then
#       tcmd "$LONG_TIMEOUT" mtr -r -c 30 --no-dns 8.8.8.8 2>/dev/null || echo "mtr failed"
#     else
#       echo "mtr not installed"
#     fi

#   } | tee "$lat_out"


#   local loss
#   loss=$(grep -oE "[0-9]+(\.[0-9]+)?% packet loss" "$lat_out" 2>/dev/null | head -1 | grep -oE "[0-9]+" | head -1 || echo "0")
#   if [[ "$loss" -gt 5 ]]; then
#     finding_critical "HIGH PACKET LOSS: ${loss}% — serious network degradation detected"
#   elif [[ "$loss" -gt 1 ]]; then
#     finding_warning "Elevated packet loss: ${loss}%"
#   fi
# }


# module_ipv6() {
#   log_info "━━━ MODULE: IPv6 Forensics"

#   local v6_out="$EVIDENCE_DIR/ipv6_analysis.txt"
#   {
#     echo "=== IPv6 Connectivity Analysis ==="
#     echo ""

#     echo "--- Public IPv6 address ---"
#     tcmd 8 curl -s --max-time 6 https://api6.ipify.org 2>/dev/null || echo "NO IPv6 (no v6 connectivity)"
#     echo ""

#     echo "--- IPv6 vs IPv4 RTT comparison ---"
#     local v6_ping
#     v6_ping=$(tcmd 8 ping6 -c 5 2001:4860:4860::8888 2>/dev/null || echo "IPv6 ICMP unavailable")
#     echo "$v6_ping"
#     echo ""

#     echo "--- IPv6 DNS resolution ---"
#     if require_cmd dig; then
#       tcmd 8 dig AAAA google.com @2001:4860:4860::8888 2>/dev/null || echo "failed"
#     fi
#     echo ""

#     echo "--- IPv6 accessible sites ---"
#     local domain
#     for domain in ipv6.google.com ipv6.cloudflare.com; do
#       local resp
#       resp=$(tcmd 8 curl -s -6 --max-time 6 -o /dev/null -w "%{http_code}" "https://$domain/" 2>/dev/null || echo "000")
#       printf "%-30s %s\n" "$domain" "$resp"
#     done

#     echo ""
#     echo "--- IPv4 vs IPv6 speed differential (DPI bypass indicator) ---"
#     local speed_v4 speed_v6
#     speed_v4=$(tcmd 20 curl -s -4 --max-time 15 -o /dev/null -w "%{speed_download}" https://speed.hetzner.de/1MB.bin 2>/dev/null || echo "0")
#     speed_v6=$(tcmd 20 curl -s -6 --max-time 15 -o /dev/null -w "%{speed_download}" https://speed.hetzner.de/1MB.bin 2>/dev/null || echo "0")
#     echo "IPv4 speed: $(awk "BEGIN {printf \"%.1f\", $speed_v4/131072}" 2>/dev/null || echo "?") Mbps"
#     echo "IPv6 speed: $(awk "BEGIN {printf \"%.1f\", $speed_v6/131072}" 2>/dev/null || echo "?") Mbps"

#   } | tee "$v6_out"

#   if ! grep -q "NO IPv6" "$v6_out" 2>/dev/null; then
#     finding_info "IPv6 connectivity is available"
 
#     local sv4 sv6
#     sv4=$(grep "IPv4 speed:" "$v6_out" | grep -oE "[0-9]+\.[0-9]+" | head -1 || echo "0")
#     sv6=$(grep "IPv6 speed:" "$v6_out" | grep -oE "[0-9]+\.[0-9]+" | head -1 || echo "0")
#     if awk "BEGIN {exit !($sv6 > $sv4 * 1.5 && $sv4 > 0)}" 2>/dev/null; then
#       finding_warning "IPv6 significantly faster than IPv4 (${sv6} vs ${sv4} Mbps) — ISP may be throttling IPv4 specifically"
#     fi
#   else
#     finding_warning "No IPv6 connectivity — ISP may not offer IPv6 (or it is blocked)"
#   fi
# }


# module_vpn_tor_blocking() {
#   log_info "━━━ MODULE: VPN / Tor / Proxy Blocking Detection"

#   local vpn_out="$EVIDENCE_DIR/vpn_tor_blocking.txt"
#   {
#     echo "=== VPN / Tor / Proxy Protocol Blocking ==="
#     echo ""

#     echo "--- WireGuard indicator (UDP 51820 to public endpoints) ---"
 

#     echo "--- OpenVPN port tests ---"
#     local target
#     for target in "8.8.8.8:1194" "1.1.1.1:1194"; do
#       local host="${target%%:*}" port="${target##*:}"
#       local result
#       result=$(tcmd 6 bash -c "echo >/dev/tcp/$host/$port" 2>&1 && echo "OPEN" || echo "CLOSED/BLOCKED")
#       printf "  UDP/TCP %s port %s: %s\n" "$host" "$port" "$result"
#     done
#     echo ""

#     echo "--- Tor reachability ---"
#     echo "Tor Project website:"
#     local tor_resp
#     tor_resp=$(tcmd 10 curl -s --max-time 8 -o /dev/null -w "%{http_code}" "https://www.torproject.org/" 2>/dev/null || echo "000")
#     echo "  https://www.torproject.org → HTTP $tor_resp"
#     [[ "$tor_resp" == "000" ]] && finding_warning "Tor Project website is UNREACHABLE — possible censorship"

#     echo ""
#     echo "Tor default bridges (port 9001, 9030, 443):"
#     for bridge_port in 9001 9030 443; do
#       local result
#       result=$(tcmd 6 bash -c "echo >/dev/tcp/85.215.170.248/$bridge_port" 2>&1 && echo "OPEN" || echo "BLOCKED")
#       printf "  Known Tor relay port %s: %s\n" "$bridge_port" "$result"
#     done

#     echo ""
#     echo "--- Commercial VPN infrastructure accessibility ---"
#     local vpn_endpoint
#     for vpn_endpoint in \
#       "nl-amsterdam.nordvpn.com:443|NordVPN-NL" \
#       "sg-vpn.mullvad.net:443|Mullvad-SG" \
#       "ch-zur-wg-001.relays.mullvad.net:443|Mullvad-CH"; do
#       local host="${vpn_endpoint%%:*}"
#       local label="${vpn_endpoint##*|}"
#       local port="${vpn_endpoint##*:}"; port="${port%%|*}"
#       local result
#       result=$(tcmd 8 curl -s --max-time 6 -o /dev/null \
#         -w "%{http_code}" "https://$host:$port/" 2>/dev/null || echo "000/FAILED")
#       printf "  %-35s → %s\n" "$label ($host:$port)" "$result"
#     done

#     echo ""
#     echo "--- Encrypted SNI (ECH/ESNI) support ---"
#     local ech_result
#     ech_result=$(echo | tcmd 8 openssl s_client \
#       -connect cloudflare.com:443 \
#       -servername cloudflare.com \
#       2>&1 | grep -iE "ech|encrypted client hello" || echo "ECH not indicated")
#     echo "ECH probe: $ech_result"

#   } | tee "$vpn_out"
# }

# module_mtu_forensics() {
#   log_info "━━━ MODULE: MTU & Path MTU Black Hole Detection"

#   if ! tcmd 5 ping -c 1 1.1.1.1 >/dev/null 2>&1; then
#     log_warn "ICMP unavailable — skipping MTU tests"
#     return 0
#   fi

#   local mtu_out="$EVIDENCE_DIR/mtu_analysis.txt"
#   {
#     echo "=== MTU / Path MTU Black Hole Analysis ==="
#     echo "Standard Ethernet MTU=1500, payload=1472"
#     echo "PMTU black holes occur when ICMP 'fragmentation needed' is blocked"
#     echo ""

#     local sizes=(1472 1420 1400 1280 1200 1000 576)
#     local best_mtu=0

#     local sz
#     for sz in "${sizes[@]}"; do
#       local mtu_pkt_out="$RAW_DIR/mtu_${sz}.txt"
#       if [[ "$OS_FAMILY" == "linux" ]]; then
#         tcmd 10 ping -c 3 -M do -s "$sz" 1.1.1.1 > "$mtu_pkt_out" 2>&1 || true
#       elif [[ "$OS_FAMILY" == "macos" ]]; then
#         tcmd 10 ping -c 3 -D -s "$sz" 1.1.1.1 > "$mtu_pkt_out" 2>&1 || true
#       fi
#       local ec; ec="$(exit_code_of "$mtu_pkt_out")"
#       if [[ "$ec" -eq 0 ]]; then
#         echo "  Payload $sz bytes: OK (MTU ≥ $((sz+28)))"
#         [[ $((sz+28)) -gt $best_mtu ]] && best_mtu=$((sz+28))
#         break
#       else
#         echo "  Payload $sz bytes: FAILS (fragmentation blocked or MTU < $((sz+28)))"
#       fi
#     done

#     echo ""
#     echo "  Detected effective path MTU: $best_mtu bytes"
#     if [[ "$best_mtu" -gt 0 && "$best_mtu" -lt 1500 ]]; then
#       echo "  ⚠ Non-standard MTU detected (expected 1500 for typical Ethernet)"
#     fi
#   } | tee "$mtu_out"

#   local detected_mtu
#   detected_mtu=$(grep "Detected effective path MTU:" "$mtu_out" | grep -oE "[0-9]+" | tail -1 || echo "0")
#   if [[ "$detected_mtu" -gt 0 && "$detected_mtu" -lt 1400 ]]; then
#     finding_warning "Low path MTU ($detected_mtu) — possible tunnel, VPN interference, or ISP configuration issue"
#   fi
# }

# module_isp_infrastructure() {
#   log_info "━━━ MODULE: ISP Infrastructure Deep Analysis"

#   local isp_out="$EVIDENCE_DIR/isp_infrastructure.txt"
#   {
#     echo "=== ISP Infrastructure Fingerprinting ==="
#     echo ""

#     local my_ip
#     my_ip=$(curl -s --max-time 5 https://api4.ipify.org 2>/dev/null || echo "unknown")
#     echo "Your public IP: $my_ip"
#     echo ""

#     echo "--- Reverse DNS (PTR) of your IP ---"
#     if require_cmd dig; then
#       local rev
#       rev=$(echo "$my_ip" | awk -F. '{print $4"."$3"."$2"."$1}')
#       tcmd 8 dig +short PTR "${rev}.in-addr.arpa" 2>/dev/null || echo "no PTR record"
#     fi
#     echo ""

#     echo "--- ISP WHOIS data ---"
#     if require_cmd whois; then
#       tcmd 15 whois "$my_ip" 2>/dev/null | grep -iE "netname|org-name|orgname|country|cidr|inetnum|descr|abuse" | head -30 || echo "WHOIS failed"
#     else
#       echo "whois not installed"
#     fi
#     echo ""

#     echo "--- ASN detailed info via Cymru ---"
#     local asn; asn=$(cat "$META_DIR/asn.txt" 2>/dev/null | tr -d 'AS' || echo "")
#     if [[ -n "$asn" ]] && require_cmd dig; then
#       tcmd 8 dig +short AS"${asn}".asn.cymru.com TXT 2>/dev/null || echo "failed"
#     fi
#     echo ""

#     echo "--- BGP looking glass (route announcements) ---"
#     if [[ "$my_ip" != "unknown" ]]; then
#       curl -s --max-time 15 \
#         "https://stat.ripe.net/data/announced-prefixes/data.json?resource=$my_ip" \
#         2>/dev/null | (require_cmd jq && jq -r '.data.prefixes[].prefix' 2>/dev/null || grep -oE '"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"' | head -10) || echo "failed"
#     fi
#     echo ""

#     echo "--- RIPE IXP membership (internet exchange points) ---"
#     local asn_num; asn_num=$(cat "$META_DIR/asn.txt" 2>/dev/null | tr -d 'AS' || echo "")
#     if [[ -n "$asn_num" ]]; then
#       curl -s --max-time 12 \
#         "https://stat.ripe.net/data/ixs/data.json?resource=AS${asn_num}" \
#         2>/dev/null | (require_cmd jq && jq -r '.data.ixs[] | "\(.name) (\(.city), \(.country))"' 2>/dev/null | head -10) || echo "IXP data unavailable"
#     fi
#     echo ""

#     echo "--- Peering analysis (upstream providers) ---"
#     if [[ -n "$asn_num" ]]; then
#       curl -s --max-time 12 \
#         "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS${asn_num}" \
#         2>/dev/null | (require_cmd jq && jq -r '
#           .data.neighbours[] |
#           select(.type == "left") |
#           "Upstream: AS\(.asn) \(.details // "")"
#         ' 2>/dev/null | head -15) || echo "Peering data unavailable"
#     fi
#     echo ""

#     echo "--- First-hop gateway fingerprint ---"
#     local gateway
#     if [[ "$OS_FAMILY" == "linux" ]]; then
#       gateway=$(ip route show default 2>/dev/null | awk '{print $3; exit}' || echo "unknown")
#     else
#       gateway=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}' || echo "unknown")
#     fi
#     echo "Default gateway: $gateway"
#     if [[ "$gateway" != "unknown" ]]; then
#       tcmd 5 ping -c 3 "$gateway" 2>/dev/null | grep -E "avg|round-trip" || true
#     fi

#   } | tee "$isp_out"
# }


# module_middlebox_detection() {
#   log_info "━━━ MODULE: Middlebox & Transparent Proxy Detection"

#   local mb_out="$EVIDENCE_DIR/middlebox_detection.txt"
#   {
#     echo "=== Middlebox / Transparent Proxy Detection ==="
#     echo ""

#     echo "--- TTL anomaly check (modified TTL = middlebox present) ---"
#     echo "Expected TTL for 1.1.1.1 (Cloudflare anycast): ~57-64 depending on path"
#     tcmd 5 ping -c 1 -t 255 1.1.1.1 2>/dev/null | grep ttl || \
#     tcmd 5 ping -c 1 1.1.1.1 2>/dev/null | grep -i "ttl\|TTL" || echo "ping failed"
#     echo ""

#     echo "--- HTTP CONNECT proxy detection ---"
#     local proxy_resp
#     proxy_resp=$(tcmd 8 curl -s --max-time 6 \
#       --proxy "" \
#       -p -x "" \
#       -w "\nHTTP-code=%{http_code}" \
#       "http://detectportal.firefox.com/success.txt" 2>/dev/null || echo "FAILED")
#     echo "Captive portal check: $proxy_resp"
#     echo ""

#     echo "--- TRACE method (reveals proxy chain) ---"
#     local trace_resp
#     trace_resp=$(tcmd 8 curl -s --max-time 6 \
#       -X TRACE "http://httpbin.org/anything" \
#       -H "X-Forensic-Probe: baseline" 2>/dev/null || echo "FAILED/BLOCKED")
#     echo "TRACE response: $trace_resp"
#     echo ""

#     echo "--- Host header mismatch test (virtual host proxy detection) ---"
 
#     local host_mismatch
#     host_mismatch=$(tcmd 8 curl -s --max-time 6 \
#       -H "Host: www.google.com" \
#       "http://1.1.1.1/" 2>/dev/null | head -5 || echo "FAILED")
#     echo "Host mismatch response (sent Host: www.google.com to 1.1.1.1):"
#     echo "$host_mismatch"
#     echo ""

#     echo "--- Traceroute TCP to port 80 (reveals L7 proxies) ---"
#     if require_cmd tcptraceroute; then
#       tcmd 30 tcptraceroute -m 15 google.com 80 2>/dev/null || echo "tcptraceroute not available"
#     elif require_cmd nmap; then
#       tcmd 30 nmap --traceroute -p 80 -Pn google.com 2>/dev/null | grep -E "HOP|TRACE" || echo "nmap traceroute failed"
#     else
#       echo "tcptraceroute/nmap not available for TCP traceroute"
#     fi

#     echo ""
#     echo "--- UDP vs TCP path divergence (indicates split routing / DPI) ---"
#     echo "UDP traceroute to 8.8.8.8:"
#     if require_cmd traceroute; then
#       tcmd 30 traceroute -U -m 15 8.8.8.8 2>/dev/null || echo "UDP traceroute failed"
#     fi
#     echo "TCP traceroute to 8.8.8.8 port 443:"
#     if require_cmd traceroute; then
#       tcmd 30 traceroute -T -p 443 -m 15 8.8.8.8 2>/dev/null || echo "TCP traceroute failed"
#     fi

#   } | tee "$mb_out"


#   if grep -q "captive\|portal\|redirect" "$mb_out" 2>/dev/null; then
#     finding_warning "Possible captive portal or transparent redirect detected"
#   fi
# }


# module_packet_capture() {
#   if [[ "$ENABLE_CAPTURE" -eq 0 ]]; then
#     log_info "Packet capture disabled (use --capture --allow-sudo to enable)"
#     return 0
#   fi

#   if ! require_cmd tcpdump; then
#     log_warn "tcpdump not installed — skipping capture"
#     return 0
#   fi

#   log_info "━━━ MODULE: Packet Capture"

#   local iface=""
#   if [[ "$OS_FAMILY" == "linux" ]]; then
#     iface=$(ip route show default 2>/dev/null | awk '{print $5; exit}' || echo "any")
#   else
#     iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || echo "any")
#   fi
#   [[ -z "$iface" ]] && iface="any"

#   local pcap="$PCAP_DIR/capture_${iface}.pcap"
#   log_info "Capturing ${CAPTURE_DURATION}s on $iface → $pcap"


#   if [[ "$ALLOW_SUDO" -eq 1 ]]; then
#     sudo tcpdump -i "$iface" -s 0 -w "$pcap" \
#       -G "$CAPTURE_DURATION" -W 1 \
#       "(tcp[tcpflags] & (tcp-rst|tcp-fin) != 0) or icmp" \
#       >/dev/null 2>&1 &
#     local cap_pid=$!
#     sleep "$CAPTURE_DURATION"
#     wait "$cap_pid" 2>/dev/null || true
#     finding_info "Packet capture saved: $pcap (analyze with Wireshark — look for RST storms, unexpected ICMP unreachables)"
#   else
#     log_warn "tcpdump requires sudo. Re-run with --allow-sudo --capture"
#   fi
# }


# generate_report() {
#   log_info "━━━ Generating forensic report"
#   local outdir="$BASE_OUTDIR/$RUN_ID"
#   local ts_utc; ts_utc="$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
#   local my_ip; my_ip=$(curl -s --max-time 4 https://api4.ipify.org 2>/dev/null || echo "unknown")
#   local asn; asn=$(cat "$META_DIR/asn.txt" 2>/dev/null || echo "unknown")

#   cat > "$REPORT_FILE" <<REPORT_HEADER
# # 🔬 Internet Autopsy Forensic Report

# | Field | Value |
# |-------|-------|
# | **Generated** | $ts_utc |
# | **Run ID** | $RUN_ID |
# | **Script Version** | $SCRIPT_VERSION |
# | **Host OS** | $OS_FAMILY |
# | **Public IPv4** | $my_ip |
# | **ASN** | $asn |
# | **Output Dir** | $outdir |

# ---

# ##  Critical Findings

# REPORT_HEADER

#   if [[ ${#FINDINGS_CRITICAL[@]} -eq 0 ]]; then
#     echo "_No critical issues detected._" >> "$REPORT_FILE"
#   else
#     local f
#     for f in "${FINDINGS_CRITICAL[@]}"; do
#       echo "-  $f" >> "$REPORT_FILE"
#     done
#   fi

#   cat >> "$REPORT_FILE" <<'SECTION2'

# ---

# ## Warnings

# SECTION2

#   if [[ ${#FINDINGS_WARNING[@]} -eq 0 ]]; then
#     echo "_No warnings._" >> "$REPORT_FILE"
#   else
#     local f
#     for f in "${FINDINGS_WARNING[@]}"; do
#       echo "- $f" >> "$REPORT_FILE"
#     done
#   fi

#   cat >> "$REPORT_FILE" <<'SECTION3'

# ---

# ##  Informational

# SECTION3

#   if [[ ${#FINDINGS_INFO[@]} -eq 0 ]]; then
#     echo "_No informational notes._" >> "$REPORT_FILE"
#   else
#     local f
#     for f in "${FINDINGS_INFO[@]}"; do
#       echo "-  $f" >> "$REPORT_FILE"
#     done
#   fi

#   cat >> "$REPORT_FILE" <<SECTION4

# ---

# ## Evidence Files

# | Evidence File | Description |
# |---------------|-------------|
# | \`evidence/dns_comparison.txt\` | DNS answer comparison across 5 resolvers |
# | \`evidence/nxdomain_hijack.txt\` | NXDOMAIN hijacking test result |
# | \`evidence/http_headers_injected.txt\` | HTTP header echo (proxy/injection detection) |
# | \`evidence/tls_cert_check.txt\` | TLS certificate chain (MITM detection) |
# | \`evidence/sni_filter.txt\` | SNI-based filtering test results |
# | \`evidence/domain_block_test.txt\` | Domain accessibility matrix |
# | \`evidence/rst_injection.txt\` | TCP RST injection probe results |
# | \`evidence/bgp_routing.txt\` | BGP route & ASN analysis |
# | \`evidence/traceroute_annotated.txt\` | Annotated traceroute with ASN per hop |
# | \`evidence/throttle_analysis.txt\` | Bandwidth throttling across protocols |
# | \`evidence/latency_analysis.txt\` | Latency, jitter, packet loss analysis |
# | \`evidence/ipv6_analysis.txt\` | IPv6 vs IPv4 disparity |
# | \`evidence/vpn_tor_blocking.txt\` | VPN/Tor/proxy blocking detection |
# | \`evidence/mtu_analysis.txt\` | Path MTU & black hole detection |
# | \`evidence/isp_infrastructure.txt\` | ISP ASN, peering, IXP fingerprint |
# | \`evidence/middlebox_detection.txt\` | Transparent proxy & middlebox detection |

# ---

# ##  Interpretation Guide

# | Indicator | What it Means |
# |-----------|---------------|
# | DNS answers differ across resolvers | DNS hijacking — ISP/state redirecting specific domains |
# | NXDOMAIN resolves to an IP | ISP is redirecting failed lookups (block page / ads) |
# | Injected Via/X-Forwarded-For headers | Transparent HTTP proxy is in path |
# | Unexpected TLS certificate issuer | SSL inspection / MITM device present |
# | TCP RST with short TTL | DPI device injecting resets to block connections |
# | IPv6 significantly faster than IPv4 | ISP throttles IPv4 traffic specifically |
# | Packet loss > 5% | Network degradation, congestion, or intentional shaping |
# | Non-standard path MTU | Tunnel, misconfigured equipment, or deliberate interference |
# | Tor / VPN endpoints unreachable | Protocol/port-level blocking by ISP/state |
# | Traffic transits unexpected ASN | BGP route leak, hijack, or deliberate rerouting |

# ---

# ##  Raw Data Index
# \`\`\`
# $outdir/
# ├── REPORT.md              ← this file
# ├── run.log                ← detailed execution log
# ├── evidence/              ← key forensic findings
# ├── raw/                   ← raw command output (all modules)
# ├── meta/                  ← metadata, ASN, dependency checks
# └── pcap/                  ← packet captures (if enabled)
# \`\`\`
# SECTION4

#   echo "" >> "$REPORT_FILE"
#   echo "---" >> "$REPORT_FILE"
#   echo "_Report generated by $SCRIPT_NAME v$SCRIPT_VERSION_" >> "$REPORT_FILE"
# }

# usage() {
#   cat <<USAGE
# $SCRIPT_NAME v$SCRIPT_VERSION — Deep Internet Forensics

# Usage: $SCRIPT_NAME [options]

# Core Options:
#   -o, --outdir DIR         Base output directory (default: $BASE_OUTDIR)
#   -t, --targets LIST       Comma-separated additional ping/trace targets
#   -v, --verbose            Show all log output (not just warnings)
#       --timeout N          Per-command timeout in seconds (default: $CMD_TIMEOUT)
#       --long-timeout N     Long-command timeout (downloads, mtr) (default: $LONG_TIMEOUT)
#       --ping-count N       Ping count for latency tests (default: $PING_COUNT)
#       --jitter-count N     Extended jitter test count (default: $PING_JITTER_COUNT)

# Test Controls:
#       --no-download        Skip bulk download tests
#       --no-speedtest       Skip speedtest binary
#       --iperf              Enable iperf3 UDP/TCP throughput tests
#       --capture            Enable tcpdump RST/ICMP capture (needs --allow-sudo)
#       --capture-secs N     Capture duration (default: $CAPTURE_DURATION)
#       --allow-sudo         Permit use of sudo for privileged operations

#   -h, --help               Show this help

# What This Tool Detects:
#   • DNS hijacking, poisoning, NXDOMAIN redirection
#   • Transparent HTTP proxies and injected headers
#   • TLS/SSL MITM and certificate substitution
#   • SNI-based filtering and DPI content inspection
#   • TCP RST injection by stateful DPI firewalls
#   • Traffic throttling by protocol, port, or destination
#   • BGP route hijacking and unexpected transit ASNs
#   • Path MTU black holes
#   • VPN / Tor / proxy protocol blocking
#   • IPv4 vs IPv6 treatment disparity
#   • ISP infrastructure: ASN, IXP membership, peering

# Output: $BASE_OUTDIR/<RUN_ID>/REPORT.md
# USAGE
# }

# parse_args() {
#   while [[ $# -gt 0 ]]; do
#     case "$1" in
#       -o|--outdir)          BASE_OUTDIR="$2"; shift 2;;
#       -v|--verbose)         VERBOSE=1; shift;;
#       --timeout)            CMD_TIMEOUT="$2"; shift 2;;
#       --long-timeout)       LONG_TIMEOUT="$2"; shift 2;;
#       --ping-count)         PING_COUNT="$2"; shift 2;;
#       --jitter-count)       PING_JITTER_COUNT="$2"; shift 2;;
#       --no-download)        ENABLE_DOWNLOAD=0; shift;;
#       --no-speedtest)       ENABLE_SPEEDTEST=0; shift;;
#       --iperf)              ENABLE_IPERF=1; shift;;
#       --capture)            ENABLE_CAPTURE=1; shift;;
#       --capture-secs)       CAPTURE_DURATION="$2"; shift 2;;
#       --allow-sudo)         ALLOW_SUDO=1; shift;;
#       -h|--help)            usage; exit 0;;
#       *) echo "Unknown option: $1"; usage; exit 1;;
#     esac
#   done
# }


# main() {
#   parse_args "$@"
#   print_banner
#   detect_os
#   detect_timeout
#   init_output

#   echo "Output directory: $BASE_OUTDIR/$RUN_ID" >&2
#   echo "Report: $REPORT_FILE" >&2
#   echo "" >&2

#   module_identity
#   module_local_network
#   module_dns_forensics
#   module_http_forensics
#   module_rst_detection
#   module_bgp_routing
#   module_throttle_detection
#   module_latency_forensics
#   module_ipv6
#   module_vpn_tor_blocking
#   module_mtu_forensics
#   module_isp_infrastructure
#   module_middlebox_detection
#   module_packet_capture

#   generate_report

#   echo "" >&2
#   separator
#   printf "  %-60s\n" "FORENSIC ANALYSIS COMPLETE"
#   separator
#   echo ""

#   if [[ ${#FINDINGS_CRITICAL[@]} -gt 0 ]]; then
#     echo " CRITICAL FINDINGS (${#FINDINGS_CRITICAL[@]}):"
#     local f
#     for f in "${FINDINGS_CRITICAL[@]}"; do
#       echo "   • $f"
#     done
#     echo ""
#   fi

#   if [[ ${#FINDINGS_WARNING[@]} -gt 0 ]]; then
#     echo " WARNINGS (${#FINDINGS_WARNING[@]}):"
#     local f
#     for f in "${FINDINGS_WARNING[@]}"; do
#       echo "   • $f"
#     done
#     echo ""
#   fi

#   echo "Full report: $REPORT_FILE"
#   echo "Evidence:   $EVIDENCE_DIR/"
#   echo ""
# }

# main "$@"
