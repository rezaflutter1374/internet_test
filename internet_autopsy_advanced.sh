#!/usr/bin/env bash
# internet_autopsy_advanced.sh
# Cross-platform (macOS + Linux) network diagnostic + evidence collection
# Safe by default: advanced probes require explicit flags.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="2.0.0"

# -----------------------------
# Defaults (override via flags)
# -----------------------------
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

# Module selection
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

# Runtime detection
OS_FAMILY=""
TIMEOUT_CMD=""

# -----------------------------
# Logging helpers
# -----------------------------
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

# -----------------------------
# Error handling
# -----------------------------
on_error() {
  local exit_code=$?
  local line_no=$1
  local cmd=$2
  log_error "Command failed (exit $exit_code) at line $line_no: $cmd"
  exit "$exit_code"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

# -----------------------------
# Utility helpers
# -----------------------------
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

  # Prefer Ookla CLI if present (supports --accept-license and -f json).
  if require_cmd speedtest; then
    if speedtest --help 2>&1 | grep -q -- '--accept-license'; then
      SPEEDTEST_IMPL="ookla"
      return 0
    fi
  fi

  # Fallback to speedtest-cli if installed.
  if require_cmd speedtest-cli; then
    SPEEDTEST_IMPL="cli"
    return 0
  fi

  # Last resort: legacy speedtest (python-based) exposed as speedtest.
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

  # Temporarily disable ERR trap to allow non-zero exit codes without aborting.
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

# -----------------------------
# Platform detection
# -----------------------------
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

# -----------------------------
# Initialization
# -----------------------------
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

# -----------------------------
# Dependency check
# -----------------------------
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

  # Save inventory
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

# -----------------------------
# Modules
# -----------------------------
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

# -----------------------------
# Summary
# -----------------------------
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

# -----------------------------
# Arg parsing
# -----------------------------
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

# -----------------------------
# Main
# -----------------------------
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
