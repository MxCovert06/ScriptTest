#!/usr/bin/env bash
# =============================================================================
#  box_audit.sh  -  CCDC Linux box integrity / persistence / C2 audit
# =============================================================================
#  READ-ONLY BY DESIGN: never deletes, kills, or edits anything on the box.
#  Only exception: --beacon temporarily adds ONE auditd rule (key
#  boxaudit_conn) and removes it again when the capture ends.
#
#  Quick start (run as root):
#    bash box_audit.sh                           full audit (~2-5 min)
#    bash box_audit.sh --baseline /root/.bl      snapshot right after you harden
#    bash box_audit.sh --diff /root/.bl          what changed since the snapshot
#    bash box_audit.sh --only net,proc --beacon 600    10-minute C2/beacon hunt
#    bash box_audit.sh --online                  re-download critical packages
#                                                and compare against the box
#  Run "bash box_audit.sh -h" for every option. See README.md for the why.
# =============================================================================

VERSION="1.0"
export LC_ALL=C
umask 077
# System dirs FIRST so a trojan dropped in /usr/local/bin cannot shadow us.
PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin"
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT 2>/dev/null

# ------------------------------------------------------------------ defaults
OUTBASE=""
MODE="audit"
ONLINE=0
ONLINE_SCOPE="critical"
BASELINE_DIR=""
DIFF_DIR=""
GEN_HASHLIST=""
HASHLISTS=""
BEACON_SECS=0
QUICK=0
BB=""
RECENT_DAYS=7
NO_COLOR=0
ONLY=""
SKIP=""
MAXSHOW=20
TAB=$'\t'

ALL_MODULES="tools pkg unowned perms users pam cron systemd shell misc kernel proc net web"

usage() {
cat <<'EOF'
box_audit.sh - CCDC Linux integrity / persistence / C2 audit (read-only)

USAGE:  bash box_audit.sh [options]

Modes
  (default)              full audit, report in /root/box_audit_<host>_<time>/
  --baseline DIR         save a trusted snapshot (hashes, users, listeners, cron,
                         units, keys, SUID, modules...) to DIR and exit.
                         Copy DIR OFF the box too - red team can edit it.
  --gen-hashlist FILE    on a CLEAN reference VM: write a sha256 hashlist of all
                         system binaries/libs/PAM modules and exit.

Extra checks (add to a normal audit)
  --diff DIR             compare the box against a --baseline snapshot
  --hashlist FILE        compare against a reference hashlist (repeatable: pass
                         several lists from different patch levels)
  --online               download the exact installed versions of ~60 critical
                         packages from the distro mirror and compare hashes
                         (catches tampering of the on-box package database)
  --online-all           same, for every package that owns a binary (slow)
  --beacon SECONDS       watch outbound connections + DNS for SECONDS and flag
                         periodic (beacon-like) traffic. 600-900 recommended.

Tuning
  --only m1,m2           run only these modules
  --skip m1,m2           skip these modules
                         modules: tools pkg unowned perms users pam cron systemd
                                  shell misc kernel proc net web
  --quick                skip slow checks (webshells, conffiles, lsattr,
                         unowned libs, hidden-PID brute force)
  --days N               "recently changed" window in days (default 7)
  --bb PATH              use a STATIC busybox you brought (e.g. /root/busybox)
                         for core utilities, in case ls/find/grep are trojaned
  -o DIR                 put the report directory under DIR
  --no-color             plain output
  -h                     this help

Severity:  HIGH = act now   MED = review   INFO = context (report only)
EOF
}

need_arg() { if [ $# -lt 2 ] || [ -z "$2" ]; then echo "option $1 needs a value" >&2; exit 1; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out)        need_arg "$@"; OUTBASE="$2"; shift 2 ;;
    --online)        ONLINE=1; shift ;;
    --online-all)    ONLINE=1; ONLINE_SCOPE=all; shift ;;
    --baseline)      need_arg "$@"; MODE=baseline; BASELINE_DIR="$2"; shift 2 ;;
    --diff)          need_arg "$@"; DIFF_DIR="$2"; shift 2 ;;
    --gen-hashlist)  need_arg "$@"; MODE=genhash; GEN_HASHLIST="$2"; shift 2 ;;
    --hashlist)      need_arg "$@"; HASHLISTS="${HASHLISTS}${2}
"; shift 2 ;;
    --beacon)        need_arg "$@"; BEACON_SECS="$2"; shift 2 ;;
    --only)          need_arg "$@"; ONLY=",$2,"; shift 2 ;;
    --skip)          need_arg "$@"; SKIP=",$2,"; shift 2 ;;
    --quick)         QUICK=1; shift ;;
    --days)          need_arg "$@"; RECENT_DAYS="$2"; shift 2 ;;
    --bb|--busybox)  need_arg "$@"; BB="$2"; shift 2 ;;
    --no-color)      NO_COLOR=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

case "$BEACON_SECS" in ''|*[!0-9]*) echo "--beacon needs a number of seconds" >&2; exit 1;; esac
case "$RECENT_DAYS" in ''|*[!0-9]*) echo "--days needs a number" >&2; exit 1;; esac

# ------------------------------------------------------------------ helpers
have() { command -v "$1" >/dev/null 2>&1; }

want() {
  local m="$1"
  if [ -n "$ONLY" ]; then case "$ONLY" in *",$m,"*) ;; *) return 1 ;; esac; fi
  case "$SKIP" in *",$m,"*) return 1 ;; esac
  return 0
}

if [ -t 1 ] && [ "$NO_COLOR" = 0 ]; then
  R=$'\e[1;31m'; Y=$'\e[1;33m'; B=$'\e[1;36m'; G=$'\e[1;32m'; N=$'\e[0m'
else
  R=""; Y=""; B=""; G=""; N=""
fi

CUR="init"; SECF="/dev/null"; SEC_SHOWN=0

_emit() {
  local lvl="$1"; shift
  local msg="$*"
  msg=${msg//$'\n'/ }; msg=${msg//$'\t'/ }
  [ ${#msg} -gt 500 ] && msg="${msg:0:500}..."
  printf '%s\t%s\t%s\n' "$lvl" "$CUR" "$msg" >> "$FFILE"
  case "$lvl" in
    HIGH) printf '  %s[HIGH]%s %s\n' "$R" "$N" "$msg" ;;
    MED)  if [ "$SEC_SHOWN" -lt "$MAXSHOW" ]; then
            printf '  %s[MED]%s  %s\n' "$Y" "$N" "$msg"
          elif [ "$SEC_SHOWN" -eq "$MAXSHOW" ]; then
            printf '  %s[MED]%s  ... more MED findings in this section, see FINDINGS.txt\n' "$Y" "$N"
          fi
          SEC_SHOWN=$((SEC_SHOWN+1)) ;;
  esac
}
hi()   { _emit HIGH "$@"; }
med()  { _emit MED  "$@"; }
info() { _emit INFO "$@"; }

section() {
  CUR="$1"; SECF="$OUT/$2"; SEC_SHOWN=0
  printf '### %s\n### %s\n' "$1" "$(date)" > "$SECF"
  printf '\n%s==> %s%s\n' "$B" "$1" "$N"
}
log()    { printf '%s\n' "$*" >> "$SECF"; }
logcmd() { printf '\n--- %s ---\n' "$1" >> "$SECF"; cat >> "$SECF"; }

# file metadata for findings
fmeta() { stat -c '[%U:%G mode=%a size=%s mtime=%y ctime=%z]' "$1" 2>/dev/null | sed 's/\.[0-9]\{9\}//g; s/ [-+][0-9]\{4\}//g'; }

# first 4 bytes of a file as hex ("7f454c46" = ELF, "2321..." = #!)
magic() { head -c4 "$1" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n'; }

# print each existing dir resolved to its real path, deduplicated
uniq_dirs() { local d; for d in "$@"; do [ -d "$d" ] && readlink -f "$d"; done | awk 'NF && !s[$0]++'; }

local_mounts() {
  awk '$3 ~ /^(ext[234]|xfs|btrfs|zfs|jfs|reiserfs|f2fs|overlay|tmpfs|vfat)$/ && $2 !~ /^\/(proc|sys)/ {print $2}' /proc/mounts 2>/dev/null | sort -u
}

# severity regexes
CRIT_RE='^/(usr/)?(s?bin|lib(32|64|x32)?|libexec)/|^/usr/local/(s?bin|lib)/|/security/pam_|^/boot/'
SENS_CONF_RE='^/etc/(pam\.d/|sudoers|ssh/sshd_config|crontab|cron\.|profile|bash\.bashrc|bashrc|environment|ld\.so|security/|systemd/|init\.d/|rc\.local|hosts$|resolv\.conf|nsswitch\.conf|apt/|yum|dnf|login\.defs|modprobe|modules)'
TEMP_RE='^(/tmp/|/var/tmp/|/dev/shm/|/run/shm/|/run/user/|/var/run/user/|/memfd:|/dev/)'

# reverse-shell / C2 indicators in scripts and configs
SUSP_HIGH='/dev/(tcp|udp)/|bash -i|sh -i|(^|[^a-z])nc(\.traditional|\.openbsd)? .*-[a-z]*[ec]( |$)|ncat .*(-e|--exec|--sh-exec)|socat .*(exec|system):|mkfifo|python[0-9.]* -c|perl -e|php -r|ruby -e|base64 (-d|--decode)|curl [^|;]*\| *(ba|z|da)?sh|wget [^|;]*\| *(ba|z|da)?sh|openssl s_client|xxd -r|chmod [0-7]?[4-7][0-7][0-7][0-7] |chmod [ug]?\+s|LD_PRELOAD=|0<&[0-9]|exec [0-9]<>|telnet [^|;]*\| */bin/'
SUSP_MED='/tmp/|/var/tmp/|/dev/shm/|nohup |setsid |disown|curl |wget |(^|[^a-z])telnet |\.onion|https?://[0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{2,5}'

INTERP_RE='^(bash|sh|dash|zsh|ksh|ksh93|mksh|csh|tcsh|fish|ash|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|php-cgi.*|node|nodejs|lua[0-9.]*|tclsh[0-9.]*|nc|nc\.traditional|nc\.openbsd|ncat|netcat|socat|busybox|awk|gawk|mawk|nawk|telnet|openssl|java)$'
DAEMON_RE='^(sshd|cron|crond|systemd.*|kworker.*|kthreadd|ksoftirqd.*|migration.*|rcu_.*|rsyslogd|syslogd|dbus.*|httpd|apache2|nginx|mysqld|mariadbd|postgres|init|getty|agetty|udevd|systemd-udevd|journald|auditd|atd|polkitd|NetworkManager|irqbalance|accounts-daemon|snapd|containerd|dockerd)$'

GTFO_SUID=" bash sh dash zsh ksh csh tcsh fish ash python python2 python3 perl ruby php lua node nodejs vim vi vim.basic vim.tiny vim.nox rvim view nano pico ed less more find awk gawk mawk nawk env tar zip unzip cp mv nmap busybox socat nc ncat netcat docker strace ltrace gdb tee dd xxd base64 wget curl git make rsync scp ssh openssl tclsh expect systemctl journalctl man install chmod chown sed cut head tail sort xargs nice timeout taskset ionice stdbuf flock time watch script screen tmux rlwrap emacs gimp jjs jrunscript run-parts start-stop-daemon setarch unshare chroot capsh ld.so cat od hexdump diff file ip ash iconv logsave column cpio "

# ------------------------------------------------------------------ OS / pkg
detect_os() {
  OS_ID=unknown; OS_VER=unknown
  # parse, never source, os-release (it is a shell file the red team can edit)
  if [ -r /etc/os-release ]; then
    OS_ID=$(grep -m1 '^ID=' /etc/os-release | cut -d= -f2- | tr -d "\"' ")
    OS_VER=$(grep -m1 '^VERSION_ID=' /etc/os-release | cut -d= -f2- | tr -d "\"' ")
  elif [ -r /etc/redhat-release ]; then
    OS_ID=rhel-like; OS_VER=$(tr -d '\n' < /etc/redhat-release)
  fi
  [ -z "$OS_ID" ] && OS_ID=unknown
  [ -z "$OS_VER" ] && OS_VER=unknown
  KREL=$(uname -r 2>/dev/null); ARCH=$(uname -m 2>/dev/null)
  HOST=$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname)
  PKG=none
  if [ -d /var/lib/dpkg/info ] && ls /var/lib/dpkg/info/*.list >/dev/null 2>&1; then
    PKG=dpkg
  elif have rpm && rpm -qf /bin/sh >/dev/null 2>&1; then
    PKG=rpm
  fi
  UID_MIN=$(awk '$1=="UID_MIN"{print $2}' /etc/login.defs 2>/dev/null)
  case "$UID_MIN" in ''|*[!0-9]*) UID_MIN=1000 ;; esac
}

# usr-merge canonicalisation: /bin/ls and /usr/bin/ls are the same file
CANON_SED=""
build_canon() {
  local d t
  for d in bin sbin lib lib32 lib64 libx32; do
    if [ -L "/$d" ]; then
      t=$(readlink -f "/$d")
      [ -n "$t" ] && CANON_SED="${CANON_SED}s#^/$d/#$t/#;"
    fi
  done
}
canon() { if [ -n "$CANON_SED" ]; then sed -e "$CANON_SED"; else cat; fi; }

OWNED=""
build_owned() {
  [ -n "$OWNED" ] && return 0
  OWNED="$WORK/owned.txt"
  case "$PKG" in
    dpkg) { cat /var/lib/dpkg/info/*.list 2>/dev/null
            [ -r /var/lib/dpkg/diversions ] && grep '^/' /var/lib/dpkg/diversions; } ;;
    rpm)  rpm -qal 2>/dev/null ;;
    *)    : ;;
  esac | canon | sort -u > "$OWNED"
}
# stdin: paths  ->  stdout: those NOT owned by any package
unowned_filter() { build_owned; canon | sort -u | comm -23 - "$OWNED"; }

# home directories of all accounts (deduped, existing, not /)
homes() {
  { echo /root; awk -F: '{print $6}' /etc/passwd 2>/dev/null; ls -d /home/* 2>/dev/null; } \
    | awk 'NF && $0!="/" && $0 !~ /^\/(bin|sbin|usr|dev|proc|sys|lib[0-9x]*|run|nonexistent|var\/run)(\/|$)/ && !s[$0]++' \
    | while IFS= read -r h; do [ -d "$h" ] && echo "$h"; done
}

# scan files for reverse-shell / C2 patterns (comments ignored)
scan_susp() {
  local f l
  for f in "$@"; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    while IFS= read -r l; do hi "suspicious command in $f:$l"; done \
      < <(grep -nE "$SUSP_HIGH" "$f" 2>/dev/null | grep -E '^[0-9]+:' | grep -vE '^[0-9]+:[[:space:]]*#')
    while IFS= read -r l; do med "review line in $f:$l"; done \
      < <(grep -nE "$SUSP_MED" "$f" 2>/dev/null | grep -E '^[0-9]+:' | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vE "$SUSP_HIGH")
  done
}

# ------------------------------------------------------------------ process / socket tables (read straight from /proc)
PROCS=""
build_proc_table() {
  [ -n "$PROCS" ] && return 0
  PROCS="$WORK/procs.tsv"; : > "$PROCS"
  local p pid exe comm cmd ppid uid k v rest
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ -r "$p/status" ] || continue
    ppid=""; uid=""
    while read -r k v rest; do
      case "$k" in PPid:) ppid=$v ;; Uid:) uid=$v; break ;; esac
    done < "$p/status" 2>/dev/null
    exe=$(readlink "$p/exe" 2>/dev/null)
    comm=""; read -r comm < "$p/comm" 2>/dev/null
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    cmd=${cmd//$'\t'/ }; cmd=${cmd:0:300}
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$ppid" "$uid" "$exe" "$comm" "$cmd" >> "$PROCS"
  done
}

# inode -> pid map for every socket owned by a visible process
build_inode_map() {
  ls -l /proc/[0-9]*/fd 2>/dev/null | awk '
    /^\/proc\/[0-9]+\/fd:$/ { split($0,a,"/"); pid=a[3]; next }
    /socket:\[/ { s=$NF; gsub(/socket:\[|\]/,"",s); if (!(s in seen)) { seen[s]=1; print s "\t" pid } }' > "$1"
}

NETAWK='
function hx(s,  i,n){ n=0; s=toupper(s); for(i=1;i<=length(s);i++) n=n*16+index("0123456789ABCDEF",substr(s,i,1))-1; return n }
function ip4(h){ return hx(substr(h,7,2)) "." hx(substr(h,5,2)) "." hx(substr(h,3,2)) "." hx(substr(h,1,2)) }
function ip6(h,  w,o,g,out,p,n,i,x){
  out=""
  for(w=0;w<4;w++){ o=substr(h,w*8+1,8); g=substr(o,7,2) substr(o,5,2) substr(o,3,2) substr(o,1,2)
    out=out (out==""?"":":") tolower(substr(g,1,4)) ":" tolower(substr(g,5,4)) }
  if (out ~ /^0000:0000:0000:0000:0000:ffff:/) { n=split(out,p,":"); return hx(substr(p[7],1,2)) "." hx(substr(p[7],3,2)) "." hx(substr(p[8],1,2)) "." hx(substr(p[8],3,2)) }
  if (out=="0000:0000:0000:0000:0000:0000:0000:0000") return "::"
  n=split(out,p,":"); out=""
  for(i=1;i<=n;i++){ x=p[i]; sub(/^0+/,"",x); if(x=="")x="0"; out=out (i>1?":":"") x }
  return out }
NR>1 && NF>=10 {
  split($2,l,":"); split($3,r,":")
  if (length(l[1])==8) { lip=ip4(l[1]); rip=ip4(r[1]) } else { lip=ip6(l[1]); rip=ip6(r[1]) }
  st=$4
  if(st=="01")s="ESTAB"; else if(st=="02")s="SYN_SENT"; else if(st=="03")s="SYN_RECV"; else if(st=="04")s="FIN_WAIT1";
  else if(st=="05")s="FIN_WAIT2"; else if(st=="06")s="TIME_WAIT"; else if(st=="08")s="CLOSE_WAIT"; else if(st=="09")s="LAST_ACK";
  else if(st=="0A")s="LISTEN"; else if(st=="0B")s="CLOSING"; else if(st=="07")s="CLOSE"; else s="ST_" st
  if (proto ~ /^udp/ && st=="07") s=(hx(r[2])==0 ? "UNCONN" : "UDP_CONN")
  if (proto ~ /^udp/ && st=="01") s="UDP_CONN"
  print proto "\t" s "\t" lip "\t" hx(l[2]) "\t" rip "\t" hx(r[2]) "\t" $8 "\t" $10
}'

SOCKS=""
build_sockets() {
  [ -n "$SOCKS" ] && return 0
  build_proc_table
  SOCKS="$WORK/sockets.tsv"
  build_inode_map "$WORK/inode_pid.tsv"
  local f
  for f in tcp tcp6 udp udp6; do
    [ -r "/proc/net/$f" ] && awk -v proto="$f" "$NETAWK" "/proc/net/$f"
  done > "$WORK/sock_raw.tsv"
  # cols: proto state lip lport rip rport uid inode pid exe
  awk -F'\t' -v OFS='\t' '
    FILENAME==ARGV[1] { ip[$1]=$2; next }
    FILENAME==ARGV[2] { ex[$1]=$4; next }
    { pid=ip[$8]; e=(pid!="" ? ex[pid] : ""); print $0, pid, e }' \
    "$WORK/inode_pid.tsv" "$PROCS" "$WORK/sock_raw.tsv" > "$SOCKS"
}

# ------------------------------------------------------------------ setup
detect_os
build_canon
START=$(date)
TS=$(date +%Y%m%d_%H%M%S)
if [ -z "$OUTBASE" ]; then
  if [ "$(id -u)" = 0 ]; then OUTBASE=/root; else OUTBASE="${HOME:-/tmp}"; fi
fi
OUT="$OUTBASE/box_audit_${HOST}_${TS}"
WORK="$OUT/.work"
mkdir -p "$WORK" || { echo "cannot create $WORK" >&2; exit 1; }
FFILE="$WORK/findings.tsv"; : > "$FFILE"

setup_busybox() {
  [ -z "$BB" ] && return 0
  [ -x "$BB" ] || { echo "busybox not executable: $BB" >&2; exit 1; }
  local d="$WORK/bb" a list
  mkdir -p "$d"
  list=$("$BB" --list 2>/dev/null)
  for a in awk basename cat comm cut date dirname find grep head id ls md5sum od readlink sed sha256sum sort stat tail tr uniq wc xargs tee; do
    printf '%s\n' "$list" | grep -qx "$a" && ln -sf "$BB" "$d/$a"
  done
  PATH="$d:$PATH"; export PATH
  if grep -q 'ld-linux' "$BB" 2>/dev/null; then
    echo "${Y}WARNING:${N} $BB looks dynamically linked - an ld.so.preload rootkit can still hook it. Use a static build."
  fi
  echo "using busybox applets from $BB"
}
setup_busybox

if [ "$(id -u)" != 0 ]; then
  echo "${Y}WARNING: not root - most checks will be incomplete. Run with sudo.${N}"
fi

# cleanup hooks (beacon module registers here)
CLEANUP_CMDS=""
cleanup() { [ -n "$CLEANUP_CMDS" ] && eval "$CLEANUP_CMDS"; CLEANUP_CMDS=""; }
trap 'echo; echo "interrupted - cleaning up"; cleanup; finish; exit 130' INT TERM

# =============================================================================
#  MODULE: tool trust & PATH sanity
# =============================================================================
CORE_TOOLS="ls ps ss netstat lsof find top sha256sum md5sum stat grep awk sed cat od head tail sort bash sh sshd ssh sudo su passwd login useradd usermod crontab systemctl ip ifconfig iptables nft kill pkill who w last id chattr lsattr tcpdump auditctl getcap modinfo lsmod insmod rmmod mount dpkg rpm apt apt-get curl wget readlink tr xargs"

mod_tools() {
  section "Tool trust & PATH sanity" 00_tool_trust.txt
  log "script PATH: $PATH"
  local t p r m d hits n perm
  for t in $CORE_TOOLS; do
    p=$(command -v "$t" 2>/dev/null) || continue
    case "$p" in /*) ;; *) continue ;; esac
    r=$(readlink -f "$p")
    m=$(magic "$r")
    log "$t -> $r  magic=$m"
    if [ "$m" != "7f454c46" ]; then
      hi "core tool '$t' ($r) is NOT an ELF binary (magic=$m) - likely a wrapper/trojan script: inspect with: head -50 $r"
    fi
    hits=""
    for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /usr/games /snap/bin /root/bin /root/.local/bin; do
      [ -e "$d/$t" ] && hits="$hits
$(readlink -f "$d/$t")"
    done
    n=$(printf '%s\n' "$hits" | awk 'NF' | sort -u | wc -l)
    if [ "$n" -gt 1 ]; then
      hi "several different '$t' binaries on PATH:$(printf '%s\n' "$hits" | awk 'NF' | sort -u | tr '\n' ' ')- a shadowing trojan (often in /usr/local/bin) is likely"
    fi
  done

  for d in $(uniq_dirs /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin); do
    perm=$(stat -Lc '%a %U:%G' "$d" 2>/dev/null)
    if [ -n "$(find "$d" -maxdepth 0 -perm -0002 2>/dev/null)" ]; then
      hi "PATH dir $d is WORLD-writable ($perm)"
    fi
    case "$d" in /usr/local/*) ;; *)
      [ -n "$(find "$d" -maxdepth 0 -perm -0020 2>/dev/null)" ] && hi "PATH dir $d is group-writable ($perm)" ;;
    esac
    [ "$(stat -Lc %U "$d" 2>/dev/null)" != root ] && hi "PATH dir $d not owned by root ($perm)"
  done

  if [ -s /etc/ld.so.preload ]; then
    hi "/etc/ld.so.preload is NOT empty - every program (incl. this script's tools) loads: $(tr '\n' ' ' < /etc/ld.so.preload)  => classic userland rootkit. Results from dynamic tools are suspect; rerun with --bb static busybox"
  elif [ -e /etc/ld.so.preload ]; then
    med "/etc/ld.so.preload exists (empty). Normally it does not exist at all."
  fi
  [ -n "$BB" ] && log "busybox in use: $BB"
}

# =============================================================================
#  MODULE: package database integrity
# =============================================================================
mod_pkg() {
  section "Package integrity (on-box package DB)" 01_package_verify.txt
  : > "$WORK/pkg_mismatch.txt"
  case "$PKG" in
    dpkg) pkg_dpkg ;;
    rpm)  pkg_rpm ;;
    *)    med "no dpkg/rpm database found - package verification impossible. Use --hashlist from a clean reference VM instead."; return ;;
  esac
  sort -u -o "$WORK/pkg_mismatch.txt" "$WORK/pkg_mismatch.txt"
  local t p r
  for t in $CORE_TOOLS; do
    p=$(command -v "$t" 2>/dev/null) || continue
    r=$(readlink -f "$p" | canon)
    if grep -qxF "$r" "$WORK/pkg_mismatch.txt"; then
      hi "CORE TOOL TAMPERED: '$t' ($r) does not match its package hash. Its output cannot be trusted - rerun with --bb /path/to/static-busybox"
    fi
  done
}

pkg_dpkg() {
  local res="$WORK/dpkg_md5.txt" f pkg line path nmis=0 nbad=0 ndoc=0 recent cnt b
  # diversions first: a diverted path legitimately holds another file
  : > "$WORK/diversions.tsv"
  if [ -s /var/lib/dpkg/diversions ]; then
    awk 'NR%3==1{a=$0} NR%3==2{b=$0} NR%3==0{print a "\t" b "\t" $0}' /var/lib/dpkg/diversions > "$WORK/diversions.tsv"
  fi
  printf '  verifying md5 of every dpkg-owned file (1-3 min)...\n'
  ( cd / || exit 1
    for f in /var/lib/dpkg/info/*.md5sums; do
      [ -s "$f" ] || continue
      pkg=${f##*/}; pkg=${pkg%.md5sums}
      md5sum -c "$f" 2>/dev/null | grep -v ': OK$' | sed "s|^|${pkg}${TAB}|"
    done ) > "$res"

  while IFS="$TAB" read -r pkg line; do
    case "$line" in
      *": FAILED open or read")
        path="/${line%: FAILED open or read}"
        case "$path" in /usr/share/doc/*|/usr/share/man/*|/usr/share/locale/*|/usr/share/info/*|/usr/share/lintian/*|/usr/share/help/*) ndoc=$((ndoc+1)); continue ;; esac
        nmis=$((nmis+1))
        if [[ $path =~ $CRIT_RE ]]; then med "package file MISSING (deleted?): $path (pkg $pkg)"; else info "package file missing: $path (pkg $pkg)"; fi ;;
      *": FAILED")
        path="/${line%: FAILED}"
        if [ -s "$WORK/diversions.tsv" ] && cut -f1 "$WORK/diversions.tsv" | grep -qxF "$path"; then
          info "diverted file differs from its package (expected - see diversion list): $path"; continue
        fi
        nbad=$((nbad+1))
        printf '%s\n' "$path" | canon >> "$WORK/pkg_mismatch.txt"
        if [[ $path =~ $CRIT_RE ]]; then
          hi "MODIFIED system file (hash != package): $path (pkg $pkg) $(fmeta "$path")"
        else
          med "modified package file: $path (pkg $pkg)"
        fi ;;
    esac
  done < "$res"
  log "files with hash mismatch: $nbad   missing (non-doc): $nmis   missing docs (ignored): $ndoc"
  [ "$nbad" = 0 ] && printf '  %sno hash mismatches in dpkg-owned files%s (only meaningful if the dpkg DB itself is intact - see --online)\n' "$G" "$N"

  # conffiles (configs shipped by packages)
  if [ "$QUICK" = 0 ] && [ -r /var/lib/dpkg/status ]; then
    awk '/^Package:/{p=$2} /^Conffiles:/{c=1;next} c && /^ \//{ if ($2!="newconffile" && $NF!="obsolete" && $NF!="remove-on-upgrade") print $1 "\t" $2 "\t" p; next } {c=0}' \
      /var/lib/dpkg/status > "$WORK/conffiles.tsv"
    awk -F'\t' '{print $2 "  " $1}' "$WORK/conffiles.tsv" | md5sum -c 2>/dev/null | grep ': FAILED$' | sed 's/: FAILED$//' > "$WORK/conf_changed.txt"
    while IFS= read -r f; do
      if [[ $f =~ $SENS_CONF_RE ]]; then med "security-relevant config differs from package default (review diff): $f $(fmeta "$f")"
      else info "config changed from package default: $f"; fi
    done < "$WORK/conf_changed.txt"
    log "changed conffiles: $(wc -l < "$WORK/conf_changed.txt")"
  fi

  # was the verification database itself edited?
  recent=$( { cat /var/log/dpkg.log /var/log/dpkg.log.1 2>/dev/null; zcat /var/log/dpkg.log.*.gz 2>/dev/null; } \
            | awk '$3=="status" && $4=="installed" {split($5,a,":"); print a[1]}' | sort -u)
  find /var/lib/dpkg/info -name '*.md5sums' -ctime -"$RECENT_DAYS" 2>/dev/null > "$WORK/md5sums_recent.txt"
  cnt=$(wc -l < "$WORK/md5sums_recent.txt")
  if [ "$cnt" -gt 200 ]; then
    med "$cnt package md5sums files changed in the last $RECENT_DAYS days (fresh image or big upgrade) - DB-tamper check skipped; use --online"
  else
    while IFS= read -r f; do
      b=${f##*/}; b=${b%.md5sums}; b=${b%%:*}
      if printf '%s\n' "$recent" | grep -qxF "$b"; then
        info "md5sums for $b changed recently (matches dpkg.log install/upgrade)"
      else
        hi "package hash DB for '$b' ($f) modified in last $RECENT_DAYS days with NO dpkg.log install - attacker may have re-hashed a trojan. Run --online"
      fi
    done < "$WORK/md5sums_recent.txt"
  fi

  # local dpkg diversions can hide replaced binaries
  if [ -s "$WORK/diversions.tsv" ]; then
    logcmd "dpkg diversions (original -> diverted-to, package)" < "$WORK/diversions.tsv"
    while IFS="$TAB" read -r a b c; do
      [ "$c" = ":" ] && med "LOCAL dpkg-divert (not from a package): $a -> $b - used to swap binaries without dpkg noticing"
    done < "$WORK/diversions.tsv"
  fi
}

pkg_rpm() {
  local line flags rest attr path
  printf '  running rpm -Va (1-3 min)...\n'
  rpm -Va 2>/dev/null > "$WORK/rpmva.txt"
  logcmd "rpm -Va raw output" < "$WORK/rpmva.txt"
  while IFS= read -r line; do
    flags=${line%% *}
    rest=${line#"$flags"}; rest=${rest#"${rest%%[! ]*}"}
    attr=""
    case "$rest" in [cdglr]" "*) attr=${rest%% *}; rest=${rest#? }; rest=${rest#"${rest%%[! ]*}"} ;; esac
    path=$rest
    if [ "$flags" = missing ]; then
      if [[ $path =~ $CRIT_RE ]]; then med "package file MISSING: $path"; else info "package file missing: $path"; fi
      continue
    fi
    if [ "${flags:2:1}" = 5 ]; then
      if [ "$attr" = c ]; then
        if [[ $path =~ $SENS_CONF_RE ]]; then med "security-relevant config changed: $path"; else info "config changed: $path"; fi
      else
        printf '%s\n' "$path" | canon >> "$WORK/pkg_mismatch.txt"
        if [[ $path =~ $CRIT_RE ]]; then hi "MODIFIED system file (digest != rpm DB): $path $(fmeta "$path")"; else med "modified package file: $path"; fi
      fi
    fi
    if [ "$attr" != c ] && [ "${flags:1:1}" = M ]; then
      if [[ $path =~ $CRIT_RE ]]; then hi "permissions changed on system file (SUID added?): $path $(fmeta "$path")"; else med "mode changed: $path"; fi
    fi
    if [ "${flags:5:1}" = U ] || [ "${flags:6:1}" = G ]; then med "owner/group changed: $path $(fmeta "$path")"; fi
    if [ "${flags:8:1}" = P ]; then hi "file capabilities changed: $path"; fi
  done < "$WORK/rpmva.txt"
}

# =============================================================================
#  MODULE: online reference check (official packages re-downloaded)
# =============================================================================
DEB_CRIT="coreutils procps iproute2 net-tools util-linux util-linux-extra findutils openssh-server openssh-client openssh-sftp-server sudo passwd login bash dash libc6 libc-bin libpam-modules libpam-modules-bin libpam-runtime libpam0g libpam-systemd systemd systemd-sysv libsystemd0 cron grep sed gawk mawk tar gzip lsof psmisc iptables nftables apt dpkg curl wget kmod libkmod2 libselinux1 libaudit1 libcrypt1 libssl3 libssl3t64 libssl1.1 openssl tcpdump auditd ncurses-bin hostname debianutils diffutils bsdutils mount adduser libcap2-bin e2fsprogs attr acl busybox"
RPM_CRIT="coreutils procps-ng iproute net-tools util-linux findutils openssh-server openssh-clients openssh sudo shadow-utils passwd bash glibc glibc-common pam systemd systemd-libs cronie cronie-anacron grep sed gawk tar gzip lsof psmisc iptables iptables-nft nftables rpm yum dnf curl wget kmod kmod-libs openssl-libs libselinux audit audit-libs tcpdump which hostname e2fsprogs libcap attr acl"

online_compare() {   # $1 = dir containing ref.sha256 (absolute paths)
  local dl="$1" line path n=0
  [ -s "$dl/ref.sha256" ] || { med "no reference hashes were produced"; return; }
  # drop diverted originals (another package's file legitimately sits there)
  if [ -s "$WORK/diversions.tsv" ]; then
    cut -f1 "$WORK/diversions.tsv" > "$dl/diverted.txt"
    awk 'FILENAME==ARGV[1]{d[$0]=1;next} !(substr($0,67) in d)' "$dl/diverted.txt" "$dl/ref.sha256" > "$dl/ref2" && mv "$dl/ref2" "$dl/ref.sha256"
  fi
  sha256sum -c "$dl/ref.sha256" 2>/dev/null | grep -v ': OK$' > "$dl/bad.txt"
  while IFS= read -r line; do
    case "$line" in
      *": FAILED open or read") info "file from official package not present on box: ${line%: FAILED open or read}" ;;
      *": FAILED")
        path=${line%: FAILED}; n=$((n+1))
        if [[ $path =~ $CRIT_RE ]]; then
          if grep -qxF "$(printf '%s' "$path" | canon)" "$WORK/pkg_mismatch.txt" 2>/dev/null; then
            hi "differs from OFFICIAL package: $path $(fmeta "$path")"
          else
            hi "differs from OFFICIAL package but on-box package DB says OK => package DB was ALSO tampered: $path $(fmeta "$path")"
          fi
        else
          med "differs from official package: $path"
        fi ;;
    esac
  done < "$dl/bad.txt"
  log "files compared: $(wc -l < "$dl/ref.sha256")   mismatches: $n"
  [ "$n" = 0 ] && printf '  %sall compared files match the official packages%s\n' "$G" "$N"
}

mod_online() {
  section "Reference check vs freshly downloaded official packages" 03_online_reference.txt
  local dl="$WORK/online"
  mkdir -p "$dl/pkgs" "$dl/x"
  : > "$dl/ref.sha256"; : > "$dl/failed.txt"
  case "$PKG" in
    dpkg) online_dpkg "$dl" ;;
    rpm)  online_rpm "$dl" ;;
    *)    med "no package manager - cannot do online reference check"; return ;;
  esac
  online_compare "$dl"
}

online_dpkg() {
  local dl="$1" list p v a s spec deb name x tot fail to=""
  have apt-get || { med "apt-get not found"; return; }
  have timeout && to="timeout 90"
  { cat /etc/apt/sources.list 2>/dev/null; cat /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null; } \
    | grep -vE '^[[:space:]]*(#|$)' | logcmd "APT sources - verify every line is a real mirror (red team can add a malicious repo + key)"
  ls -la /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d /etc/apt/keyrings /usr/share/keyrings 2>/dev/null | logcmd "APT keyrings"
  while IFS= read -r f; do med "APT key/source file not owned by any package (verify): $f"; done < <(
    find /etc/apt/trusted.gpg.d /etc/apt/keyrings /etc/apt/sources.list.d -type f 2>/dev/null | unowned_filter)

  if [ "$ONLINE_SCOPE" = all ]; then
    list=$(grep -lE '^/(usr/)?(s?bin|libexec)/|/security/pam_' /var/lib/dpkg/info/*.list 2>/dev/null | sed 's#.*/##; s#\.list$##; s#:.*##' | sort -u)
  else
    list=$DEB_CRIT
  fi
  # shellcheck disable=SC2086
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' $list 2>/dev/null \
    | awk -F'\t' '$4 ~ /installed$/' > "$dl/want.tsv"
  tot=$(wc -l < "$dl/want.tsv")
  printf '  downloading %s packages from the mirror...\n' "$tot"
  ( cd "$dl/pkgs" || exit 1
    while IFS="$TAB" read -r p v a s; do
      spec="$p"; [ "$a" != all ] && spec="$p:$a"
      $to apt-get download -q "$spec=$v" >/dev/null 2>&1 || echo "$p=$v" >> "$dl/failed.txt"
    done < "$dl/want.tsv" )
  fail=$(wc -l < "$dl/failed.txt")
  logcmd "packages that could not be downloaded at the exact installed version" < "$dl/failed.txt"
  if [ "$fail" -gt 0 ]; then
    if [ "$fail" -ge "$tot" ]; then
      med "could not download ANY package (no network / no apt lists). Try: apt-get update, then rerun --online. Or use --hashlist from a reference VM."
    else
      info "$fail of $tot packages unavailable at exact version (superseded on mirror; try snapshot.debian.org / launchpad)"
    fi
  fi
  for deb in "$dl"/pkgs/*.deb; do
    [ -e "$deb" ] || continue
    name=${deb##*/}; name=${name%%_*}
    x="$dl/x/$name"; mkdir -p "$x"
    if ! dpkg-deb -x "$deb" "$x" 2>/dev/null; then
      ( cd "$x" && ar x "$deb" 2>/dev/null && tar xf data.tar.* 2>/dev/null )
    fi
    ( cd "$x" && find . -type f ! -path './etc/*' ! -name 'control.tar*' ! -name 'data.tar*' ! -name debian-binary -print0 | xargs -0 -r sha256sum ) \
      | sed 's#  \./#  /#' >> "$dl/ref.sha256"
  done
}

online_rpm() {
  local dl="$1" list r name x tot fail
  if [ "$ONLINE_SCOPE" = all ]; then
    list=$(rpm -qf --qf '%{NAME}\n' /usr/bin/* /usr/sbin/* 2>/dev/null | grep -v 'not owned' | sort -u)
  else
    list=$RPM_CRIT
  fi
  # shellcheck disable=SC2086
  rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' $list 2>/dev/null | grep -v 'not installed' | sort -u > "$dl/want.txt"
  tot=$(wc -l < "$dl/want.txt")
  printf '  downloading %s packages...\n' "$tot"
  while IFS= read -r r; do
    if have dnf; then dnf -q download --destdir "$dl/pkgs" "$r" >/dev/null 2>&1 || echo "$r" >> "$dl/failed.txt"
    elif have yumdownloader; then yumdownloader -q --destdir "$dl/pkgs" "$r" >/dev/null 2>&1 || echo "$r" >> "$dl/failed.txt"
    else med "neither dnf nor yumdownloader available"; return; fi
  done < "$dl/want.txt"
  fail=$(wc -l < "$dl/failed.txt")
  [ "$fail" -gt 0 ] && info "$fail of $tot packages could not be downloaded"
  have rpm2cpio && have cpio || { med "rpm2cpio/cpio missing - cannot extract"; return; }
  for r in "$dl"/pkgs/*.rpm; do
    [ -e "$r" ] || continue
    rpm -K "$r" 2>/dev/null | grep -qiE 'pgp|digests signatures OK|signatures ok' || med "downloaded package signature not verified: ${r##*/}"
    name=${r##*/}; x="$dl/x/$name"; mkdir -p "$x"
    ( cd "$x" && rpm2cpio "$r" | cpio -idm --quiet 2>/dev/null )
    ( cd "$x" && find . -type f ! -path './etc/*' -print0 | xargs -0 -r sha256sum ) | sed 's#  \./#  /#' >> "$dl/ref.sha256"
  done
}

# =============================================================================
#  hashing helpers (hashlist + baseline)
# =============================================================================
SEC_DIRS="/lib/security /lib64/security /usr/lib/security /usr/lib64/security /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib/aarch64-linux-gnu/security /usr/lib/aarch64-linux-gnu/security /lib/i386-linux-gnu/security /usr/lib/i386-linux-gnu/security"
BIN_DIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/libexec /usr/lib/openssh /usr/lib/systemd /usr/games"

hash_tree() {
  local d
  { # shellcheck disable=SC2046
    for d in $(uniq_dirs $BIN_DIRS $SEC_DIRS); do find "$d" -xdev -maxdepth 4 -type f -print0 2>/dev/null; done
    # shellcheck disable=SC2046
    for d in $(uniq_dirs /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib); do find "$d" -xdev -maxdepth 2 -type f -name '*.so*' -print0 2>/dev/null; done
  } | xargs -0 -r sha256sum 2>/dev/null | awk '!s[substr($0,67)]++' | sort -k2
}

hash_persist() {   # configs and persistence surfaces (for baseline/diff)
  local h
  {
    find /etc -xdev -type f ! -name 'ld.so.cache' ! -name 'adjtime' ! -name '*.swp' -print0 2>/dev/null
    for h in $(homes); do
      find "$h" -xdev -maxdepth 3 -type f -size -5M ! -path '*/.cache/*' ! -path '*/.local/share/Trash/*' \
        ! -path '*/box_audit_*' ! -path "${BASELINE_DIR:-/nonexistent-bx}/*" ! -path "${DIFF_DIR:-/nonexistent-bx}/*" -print0 2>/dev/null
    done
    find /var/spool/cron /var/spool/at /var/spool/anacron -type f -print0 2>/dev/null
    find /var/www /srv /usr/share/nginx -xdev -type f -size -5M -print0 2>/dev/null
    find /boot -xdev -maxdepth 2 -type f -print0 2>/dev/null
    find /var/lib/dpkg/info -name '*.md5sums' -print0 2>/dev/null
    find /etc/systemd /run/systemd/system /run/systemd/transient -type f -print0 2>/dev/null
  } | xargs -0 -r sha256sum 2>/dev/null | awk '!s[substr($0,67)]++' | sort -k2
}

# =============================================================================
#  MODULE: reference hashlist comparison
# =============================================================================
mode_genhash() {
  echo "Generating reference hashlist from THIS box ($OS_ID $OS_VER, $KREL). Only do this on a CLEAN VM."
  { echo "# box_audit hashlist v1"
    echo "# os=$OS_ID ver=$OS_VER kernel=$KREL arch=$ARCH host=$HOST date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    hash_tree; } > "$GEN_HASHLIST"
  echo "wrote $(grep -vc '^#' "$GEN_HASHLIST") hashes to $GEN_HASHLIST"
  echo "sha256 of the hashlist itself (write this down): $(sha256sum "$GEN_HASHLIST" | cut -c1-64)"
}

mod_hashlist() {
  section "Comparison vs reference hashlist(s)" 04_hashlist_compare.txt
  local refs="$WORK/ref_all.sha256" h hdr kind path any=0
  : > "$refs"
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    if [ ! -r "$h" ]; then med "cannot read hashlist $h"; continue; fi
    any=1
    hdr=$(grep -m1 '^# os=' "$h")
    log "reference: $h  $hdr"
    case "$hdr" in
      *"os=$OS_ID ver=$OS_VER "*) ;;
      *) med "hashlist $h was built on '$hdr' but this box is os=$OS_ID ver=$OS_VER - expect noise" ;;
    esac
    grep -v '^#' "$h" >> "$refs"
  done <<EOF
$HASHLISTS
EOF
  [ "$any" = 0 ] && return
  printf '  hashing this box...\n'
  hash_tree > "$WORK/current.sha256"
  awk 'FILENAME==ARGV[1] { p=substr($0,67); ok[p SUBSEP $1]=1; known[p]=1; next }
       { p=substr($0,67); seen[p]=1
         if (!(p in known)) print "EXTRA\t" p
         else if (!((p SUBSEP $1) in ok)) print "CHANGED\t" p }
       END { for (p in known) if (!(p in seen)) print "MISSING\t" p }' "$refs" "$WORK/current.sha256" | sort > "$WORK/hashlist_diff.tsv"
  build_owned
  while IFS="$TAB" read -r kind path; do
    case "$kind" in
      CHANGED) if [[ $path =~ $CRIT_RE ]]; then hi "hash differs from reference: $path $(fmeta "$path")"; else med "hash differs from reference: $path"; fi ;;
      EXTRA)
        if [ "$PKG" != none ] && [ -z "$(printf '%s\n' "$path" | unowned_filter)" ]; then
          info "not in reference but package-owned: $path"
        else
          case "$path" in */lib*/*.so*) med "extra unowned library not in reference: $path";;
                          *) hi "extra unowned binary not in reference: $path $(fmeta "$path")";; esac
        fi ;;
      MISSING) info "in reference but not on box: $path" ;;
    esac
  done < "$WORK/hashlist_diff.tsv"
  log "$(cut -f1 "$WORK/hashlist_diff.tsv" | sort | uniq -c)"
}

# =============================================================================
#  MODULE: unowned files in system paths
# =============================================================================
mod_unowned() {
  section "Files in system paths not owned by any package" 02_unowned.txt
  if [ "$PKG" = none ]; then med "no package DB - skipped"; return; fi
  build_owned
  local d f t
  # shellcheck disable=SC2046
  for d in $(uniq_dirs /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/lib/openssh /usr/games); do
    find "$d" -xdev -maxdepth 3 -type f 2>/dev/null
  done | grep -vE '/__pycache__/|\.pyc$' | unowned_filter > "$WORK/unowned_bins.txt"
  while IFS= read -r f; do hi "unowned file in system bin dir: $f $(fmeta "$f") magic=$(magic "$f")"; done < "$WORK/unowned_bins.txt"

  # shellcheck disable=SC2046,SC2086
  for d in $(uniq_dirs $SEC_DIRS); do find "$d" -type f 2>/dev/null; done | unowned_filter > "$WORK/unowned_pam.txt"
  while IFS= read -r f; do hi "unowned PAM module (auth backdoor candidate): $f $(fmeta "$f")"; done < "$WORK/unowned_pam.txt"

  # shellcheck disable=SC2046
  for d in $(uniq_dirs /usr/local/bin /usr/local/sbin /usr/local/libexec); do find "$d" -xdev -type f 2>/dev/null; done > "$WORK/usrlocal.txt"
  while IFS= read -r f; do med "file in /usr/local (not package managed - verify): $f $(fmeta "$f")"; done < "$WORK/usrlocal.txt"
  ls -la /opt 2>/dev/null | logcmd "/opt contents"

  if [ "$QUICK" = 0 ]; then
    # shellcheck disable=SC2046
    for d in $(uniq_dirs /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib); do
      find "$d" -xdev -maxdepth 2 -type f -name '*.so*' 2>/dev/null
    done | unowned_filter > "$WORK/unowned_libs.txt"
    while IFS= read -r f; do med "unowned shared library (preload/rootkit candidate): $f $(fmeta "$f")"; done < "$WORK/unowned_libs.txt"
  fi

  # symlinks in bin dirs / alternatives pointing somewhere nasty
  # shellcheck disable=SC2046
  for d in $(uniq_dirs /usr/bin /usr/sbin /bin /sbin /usr/local/bin /etc/alternatives); do
    find "$d" -maxdepth 1 -type l 2>/dev/null
  done | sort -u | while IFS= read -r f; do
    t=$(readlink -f "$f" 2>/dev/null)
    if [ -z "$t" ] || [ ! -e "$t" ]; then
      echo "DANGLING	$f"
    elif [[ $t =~ $TEMP_RE ]] || [[ $t =~ ^/(home|root)/ ]]; then
      echo "BAD	$f -> $t"
    fi
  done > "$WORK/badlinks.tsv"
  while IFS="$TAB" read -r t f; do
    if [ "$t" = BAD ]; then hi "symlink in system path points to temp/home: $f"; else info "dangling symlink: $f"; fi
  done < "$WORK/badlinks.tsv"
}

# =============================================================================
#  MODULE: permissions, SUID, capabilities, attributes, temp dirs
# =============================================================================
mod_perms() {
  section "SUID/SGID, capabilities, writable paths, chattr, temp dirs" 05_permissions.txt
  local m f b base caps d name mg n line

  printf '  scanning for SUID/SGID...\n'
  for m in $(local_mounts); do
    find "$m" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
  done | sort -u > "$WORK/suid.txt"
  if [ "$PKG" != none ]; then unowned_filter < "$WORK/suid.txt" > "$WORK/suid_unowned.txt"; else : > "$WORK/suid_unowned.txt"; fi
  while IFS= read -r f; do
    b=${f##*/}; base=${b%%[0-9]*}
    if grep -qxF "$(printf '%s' "$f" | canon)" "$WORK/suid_unowned.txt"; then
      hi "UNOWNED SUID/SGID binary: $f $(fmeta "$f")"
    elif [[ $f =~ $TEMP_RE ]] || [[ $f =~ ^/(home|root|var/www)/ ]]; then
      hi "SUID/SGID binary in temp/home/web dir: $f $(fmeta "$f")"
    else
      case "$GTFO_SUID" in
        *" $b "*|*" $base "*) hi "SUID/SGID set on GTFOBins-abusable binary (instant root): $f $(fmeta "$f")" ;;
        *) info "suid/sgid: $f $(stat -c '%U %a' "$f" 2>/dev/null)" ;;
      esac
    fi
  done < "$WORK/suid.txt"
  logcmd "all SUID/SGID files" < "$WORK/suid.txt"

  if have getcap; then
    for d in /usr /bin /sbin /lib /lib64 /opt /home /root /tmp /var /srv /etc /dev/shm; do
      [ -d "$d" ] && [ ! -L "$d" ] && getcap -r "$d" 2>/dev/null
    done | sort -u > "$WORK/caps.txt"
    logcmd "files with capabilities" < "$WORK/caps.txt"
    while IFS= read -r line; do
      if printf '%s' "$line" | grep -qiE 'cap_(setuid|setgid|sys_admin|sys_ptrace|sys_module|dac_override|dac_read_search|chown|fowner|bpf|sys_rawio)'; then
        hi "dangerous file capability: $line"
      else
        info "capability: $line"
      fi
    done < "$WORK/caps.txt"
  fi

  # writable system files
  # shellcheck disable=SC2046,SC2086
  for d in $(uniq_dirs $BIN_DIRS $SEC_DIRS); do
    find "$d" -maxdepth 2 ! -type l -perm -0002 2>/dev/null | while IFS= read -r f; do hi "WORLD-writable file in system path: $f $(fmeta "$f")"; done
    find "$d" -maxdepth 2 ! -type l ! -user root 2>/dev/null | head -50 | while IFS= read -r f; do med "non-root-owned file in system path: $f $(fmeta "$f")"; done
  done
  find /etc -xdev ! -type l -perm -0002 2>/dev/null | while IFS= read -r f; do hi "WORLD-writable in /etc: $f $(fmeta "$f")"; done
  find /etc/systemd /lib/systemd/system /usr/lib/systemd/system -xdev ! -type l -perm -0022 2>/dev/null | while IFS= read -r f; do hi "group/world-writable systemd unit path: $f"; done
  [ -n "$(find /etc/shadow -maxdepth 0 -perm -0004 2>/dev/null)" ] && hi "/etc/shadow is world-readable $(fmeta /etc/shadow)"
  [ -n "$(find /etc/gshadow -maxdepth 0 -perm -0004 2>/dev/null)" ] && hi "/etc/gshadow is world-readable"
  for f in /etc/passwd /etc/group /etc/sudoers /etc/crontab; do
    [ -n "$(find "$f" -maxdepth 0 -perm -0022 2>/dev/null)" ] && hi "$f is group/world-writable $(fmeta "$f")"
  done
  find /etc/sudoers.d /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/profile.d /etc/pam.d \
    -perm -0002 ! -type l 2>/dev/null | while IFS= read -r f; do hi "world-writable persistence path: $f"; done
  [ -n "$(find /root -maxdepth 0 -perm -0005 2>/dev/null)" ] && med "/root is world-readable/executable $(fmeta /root)"

  # chattr +i / +a (red team locks backdoors in place)
  if [ "$QUICK" = 0 ] && have lsattr; then
    for d in /etc /root /home /var/spool/cron /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib/systemd/system /usr/lib/systemd/system /var/www; do
      [ -d "$d" ] && [ ! -L "$d" ] && lsattr -R "$d" 2>/dev/null
    done | awk 'NF>=2 && $1 ~ /^[-a-zA-Z]+$/ && $1 ~ /[ia]/ {f=$1; $1=""; sub(/^ /,""); print f "\t" $0}' > "$WORK/chattr.tsv"
    while IFS="$TAB" read -r line f; do
      med "immutable/append-only attribute ($line) on $f - red team uses chattr +i to stop you deleting/fixing it (remove with chattr -ia)"
    done < "$WORK/chattr.tsv"
  fi

  # temp dirs: executables, ELF, hidden names
  for d in /tmp /var/tmp /dev/shm /run/shm /run/user /var/run/user /run/lock /var/crash /var/lib/php/sessions; do
    [ -d "$d" ] && [ ! -L "$d" ] && find "$d" -maxdepth 6 \( -type f -o -type d \) 2>/dev/null
  done | grep -vF "$OUT" | sort -u > "$WORK/tempfiles.txt"
  n=0
  while IFS= read -r f; do
    name=${f##*/}
    case "$name" in
      .X11-unix|.ICE-unix|.font-unix|.Test-unix|.XIM-unix|.X*-lock|.s.PGSQL*|.lock) ;;
      ...*|" "*|*" ") hi "deceptively named entry in temp dir: '$f'" ;;
      .*) med "hidden entry in temp dir: $f $(fmeta "$f")" ;;
    esac
    [ -f "$f" ] || continue
    n=$((n+1)); [ "$n" -gt 5000 ] && { med "more than 5000 temp files - stopped content checks"; break; }
    mg=$(magic "$f")
    case "$mg" in
      7f454c46) hi "ELF binary in temp dir: $f $(fmeta "$f")" ;;
      2321*)    med "script in temp dir: $f $(fmeta "$f") first line: $(head -1 "$f" 2>/dev/null | cut -c1-80)" ;;
      *) [ -x "$f" ] && med "executable file in temp dir: $f $(fmeta "$f")" ;;
    esac
  done < "$WORK/tempfiles.txt"

  # regular files / hidden dirs in /dev
  find /dev -type f ! -path '/dev/shm/*' ! -path '/dev/mqueue/*' ! -path '/dev/hugepages/*' 2>/dev/null \
    | while IFS= read -r f; do hi "regular file inside /dev (hiding spot): $f $(fmeta "$f")"; done
  find /dev -name '.*' ! -path '/dev/shm/*' 2>/dev/null | while IFS= read -r f; do med "hidden entry in /dev: $f"; done

  # recently changed system binaries / configs (ctime cannot be faked with touch)
  # shellcheck disable=SC2046,SC2086
  for d in $(uniq_dirs $BIN_DIRS $SEC_DIRS); do find "$d" -xdev -maxdepth 2 -type f -ctime -"$RECENT_DAYS" 2>/dev/null; done | sort -u > "$WORK/recent_bins.txt"
  n=$(wc -l < "$WORK/recent_bins.txt")
  logcmd "system binaries changed (ctime) in the last $RECENT_DAYS days" < "$WORK/recent_bins.txt"
  if [ "$n" -gt 0 ] && [ "$n" -le 100 ]; then
    med "$n system binaries changed in the last $RECENT_DAYS days (see 05_permissions.txt) - cross-check with package updates"
  elif [ "$n" -gt 100 ]; then
    info "$n system binaries changed in the last $RECENT_DAYS days (likely package upgrades)"
  fi
  find /etc -xdev -type f -ctime -"$RECENT_DAYS" 2>/dev/null | sort | logcmd "/etc files changed in the last $RECENT_DAYS days"
}

# =============================================================================
#  MODULE: users, sudo, SSH
# =============================================================================
mod_users() {
  section "Accounts, groups, sudo, SSH" 06_users_ssh.txt
  local u uid sh usable inter home g members f line kf nk h pat k v
  awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while IFS= read -r u; do hi "extra UID 0 account: $u"; done
  awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while IFS= read -r u; do med "duplicate UID $u: $(awk -F: -v x="$u" '$3==x{printf "%s ",$1}' /etc/passwd)"; done
  awk -F: '$4==0 && $1!="root" && $3!=0 {print $1}' /etc/passwd | while IFS= read -r u; do med "account with primary GID 0 (root group): $u"; done
  awk -F: '{print $1}' /etc/passwd | sort | uniq -d | while IFS= read -r u; do hi "duplicate username in /etc/passwd: $u"; done
  grep -vE '^[a-zA-Z0-9._-]+:[^:]*:[0-9]+:[0-9]+:[^:]*:[^:]*:[^:]*$' /etc/passwd 2>/dev/null | while IFS= read -r line; do [ -n "$line" ] && med "malformed /etc/passwd line: $line"; done

  if [ -r /etc/shadow ]; then
    awk -F: 'FILENAME==ARGV[1] { pw[$1]=$2; next }
      { h=pw[$1]; usable=(h!="" && h !~ /^[!*]/) ? 1 : 0; empty=(($1 in pw) && h=="") ? 1 : 0
        inter=($7!="" && $7 !~ /(nologin|false|sync|shutdown|halt)$/) ? 1 : 0
        print $1 "\t" $3 "\t" $7 "\t" usable "\t" inter "\t" $6 "\t" empty }' /etc/shadow /etc/passwd > "$WORK/accounts.tsv"
    while IFS="$TAB" read -r u uid sh usable inter home empty; do
      [ "$empty" = 1 ] && hi "account '$u' has an EMPTY password (login with no password)"
      if [ "$uid" != 0 ] && [ "$uid" -lt "$UID_MIN" ] && [ "$uid" != 65534 ]; then
        [ "$usable" = 1 ] && hi "system account '$u' (uid $uid) has a usable password"
        [ "$inter" = 1 ] && med "system account '$u' (uid $uid) has interactive shell $sh"
      fi
      if [ "$usable" = 1 ] || [ "$inter" = 1 ]; then
        info "login-capable account: $u uid=$uid shell=$sh home=$home password=$([ "$usable" = 1 ] && echo set || echo locked)"
      fi
    done < "$WORK/accounts.tsv"
    awk -F'\t' '{printf "%-20s uid=%-6s shell=%-20s pw=%s interactive=%s home=%s\n",$1,$2,$3,$4,$5,$6}' "$WORK/accounts.tsv" | logcmd "accounts"
  else
    med "/etc/shadow not readable - password checks skipped (not root?)"
  fi
  log "/etc/passwd changed: $(stat -c %z /etc/passwd 2>/dev/null)   /etc/shadow changed: $(stat -c %z /etc/shadow 2>/dev/null)"

  for g in sudo wheel admin root adm docker lxd libvirt disk shadow kvm; do
    members=$(awk -F: -v g="$g" '$1==g{print $4}' /etc/group 2>/dev/null)
    [ -z "$members" ] && continue
    case "$g" in
      sudo|wheel|admin) med "members of '$g' (full sudo) - verify each is authorized: $members" ;;
      docker|lxd|libvirt|disk|root|shadow|kvm) med "members of root-equivalent group '$g': $members" ;;
      *) info "members of '$g': $members" ;;
    esac
  done

  # sudoers
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    grep -vE '^[[:space:]]*$' "$f" 2>/dev/null | grep -vE '^[[:space:]]*#[^i@]' | logcmd "$f $(fmeta "$f")"
    grep -nE '^[[:space:]]*[#@]include(dir)?[[:space:]]' "$f" 2>/dev/null | while IFS= read -r line; do
      case "$line" in *"/etc/sudoers.d"*|*"@includedir /etc/sudoers.d"*) ;; *) hi "sudoers include of non-standard path: $f:$line" ;; esac
    done
    grep -nE '^[^#]*NOPASSWD' "$f" 2>/dev/null | while IFS= read -r line; do med "sudo NOPASSWD rule: $f:$line"; done
    grep -nE '^[^#]*!authenticate' "$f" 2>/dev/null | while IFS= read -r line; do hi "sudo !authenticate (no password ever): $f:$line"; done
    grep -nE '^[^#]*env_keep[^#]*(LD_|PYTHON|PERL5|RUBY|BASH_ENV|ENV)' "$f" 2>/dev/null | while IFS= read -r line; do hi "sudo env_keep of dangerous variable (LD_PRELOAD privesc): $f:$line"; done
    grep -nE '^[^#%]*ALL[[:space:]]*=[[:space:]]*\(' "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*root[[:space:]]' | while IFS= read -r line; do med "user-level sudo grant: $f:$line"; done
  done
  [ "$PKG" != none ] && find /etc/sudoers.d -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "sudoers.d file not from a package: $f"; done

  # sshd effective config
  if have sshd && sshd -T > "$WORK/sshdT.txt" 2>/dev/null && [ -s "$WORK/sshdT.txt" ]; then
    logcmd "sshd -T (effective config)" < "$WORK/sshdT.txt"
  else
    cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' \
      | awk '{ $1=tolower($1); print }' > "$WORK/sshdT.txt"
    logcmd "sshd_config (raw - sshd -T failed)" < "$WORK/sshdT.txt"
  fi
  while read -r k v; do
    case "$k" in
      permitemptypasswords) [ "$v" = yes ] && hi "sshd PermitEmptyPasswords yes" ;;
      permitrootlogin) [ "$v" = yes ] && med "sshd PermitRootLogin yes" ;;
      authorizedkeyscommand) [ "$v" != none ] && hi "sshd AuthorizedKeysCommand set: $v (keys can come from anywhere)" ;;
      authorizedprincipalsfile|authorizedprincipalscommand) [ "$v" != none ] && med "sshd $k set: $v" ;;
      trustedusercakeys) [ "$v" != none ] && med "sshd TrustedUserCAKeys set: $v (cert-based backdoor possible)" ;;
      permituserenvironment) [ "$v" != no ] && hi "sshd PermitUserEnvironment $v (~/.ssh/environment can set LD_PRELOAD)" ;;
      authorizedkeysfile) case "$v" in ".ssh/authorized_keys .ssh/authorized_keys2"|".ssh/authorized_keys") ;; *) med "non-default AuthorizedKeysFile: $v" ;; esac ;;
      subsystem) case "$v" in *internal-sftp*|*"/sftp-server"*) ;; *) hi "unusual sshd Subsystem: $v" ;; esac ;;
      forcecommand) med "sshd ForceCommand: $v" ;;
    esac
  done < "$WORK/sshdT.txt"
  grep -nE '^[[:space:]]*Match' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | while IFS= read -r line; do med "sshd Match block (per-user/host overrides - review): $line"; done
  [ "$PKG" != none ] && find /etc/ssh/sshd_config.d -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "sshd_config.d drop-in not from a package: $f"; done
  [ -e /etc/ssh/sshrc ] && hi "/etc/ssh/sshrc exists - runs on every SSH login: $(head -c 300 /etc/ssh/sshrc | tr '\n' ';')"

  pat=$(awk '$1=="authorizedkeysfile"{ $1=""; print }' "$WORK/sshdT.txt" 2>/dev/null)
  [ -z "$pat" ] && pat=".ssh/authorized_keys .ssh/authorized_keys2"
  awk -F: '{print $1 "\t" $3 "\t" $6}' /etc/passwd | while IFS="$TAB" read -r u uid h; do
    [ -d "$h" ] || continue
    for kf in $pat .ssh/authorized_keys .ssh/authorized_keys2; do
      kf=${kf//%h/$h}; kf=${kf//%u/$u}; kf=${kf//%%/%}
      case "$kf" in /*) ;; *) kf="$h/$kf" ;; esac
      echo "$u	$uid	$kf"
    done
  done | awk -F'\t' '!s[$3]++' > "$WORK/keyfiles.tsv"
  while IFS="$TAB" read -r u uid kf; do
    [ -s "$kf" ] || continue
    nk=$(grep -cvE '^[[:space:]]*(#|$)' "$kf")
    { echo "== $kf ($u) $(fmeta "$kf")"
      grep -vE '^[[:space:]]*(#|$)' "$kf" | awk '{ for(i=1;i<=NF;i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { c=""; for(j=i+2;j<=NF;j++) c=c " " $j; print "   " $i " ..." substr($(i+1),length($(i+1))-11) c; break } }'
      have ssh-keygen && ssh-keygen -lf "$kf" 2>/dev/null | sed 's/^/   fp: /'
    } >> "$SECF"
    if [ "$uid" != 0 ] && [ "$uid" -lt "$UID_MIN" ]; then
      hi "SYSTEM account '$u' has $nk SSH authorized key(s): $kf"
    else
      med "$nk SSH authorized key(s) for '$u' in $kf - verify every key (fingerprints in 06_users_ssh.txt)"
    fi
    case "$kf" in *authorized_keys2) med "authorized_keys2 in use for '$u' - commonly overlooked backdoor location" ;; esac
    grep -nE '(^|,)[[:space:]]*(command|environment)=' "$kf" | while IFS= read -r line; do hi "SSH key with forced command/environment option in $kf: ${line:0:200}"; done
    [ -n "$(find "$kf" -maxdepth 0 -perm -0022 2>/dev/null)" ] && med "$kf is group/world-writable"
  done < "$WORK/keyfiles.tsv"
  for h in $(homes); do
    [ -e "$h/.ssh/rc" ] && hi "$h/.ssh/rc exists - runs on every SSH login for that user: $(head -c 200 "$h/.ssh/rc" | tr '\n' ';')"
    [ -s "$h/.ssh/environment" ] && med "$h/.ssh/environment exists: $(head -c 200 "$h/.ssh/environment" | tr '\n' ';')"
  done

  { have last && last -n 30 -a -w 2>/dev/null || last -n 30 2>/dev/null; } | logcmd "last logins"
  have lastlog && lastlog 2>/dev/null | grep -v 'Never logged in' | logcmd "lastlog"
  { who 2>/dev/null; w 2>/dev/null; } | logcmd "who / w"
  have lastb && lastb -n 30 2>/dev/null | logcmd "failed logins (lastb)"
}

# =============================================================================
#  MODULE: PAM
# =============================================================================
mod_pam() {
  section "PAM" 07_pam.txt
  [ -d /etc/pam.d ] || { info "no /etc/pam.d"; return; }
  local line f tgt
  grep -nHE '^[[:space:]]*[^#[:space:]].*pam_' /etc/pam.d/* 2>/dev/null | logcmd "active PAM lines"
  grep -nHE '^[[:space:]]*(-?auth|account|password|session)[[:space:]]+sufficient[[:space:]]+pam_permit\.so' /etc/pam.d/* 2>/dev/null \
    | while IFS= read -r line; do hi "'sufficient pam_permit.so' = ANY password works: $line"; done
  grep -nHE '^[[:space:]]*auth[[:space:]]+(\[[^]]*success=done[^]]*\]|sufficient)[[:space:]]+pam_(permit|succeed_if)\.so' /etc/pam.d/* 2>/dev/null \
    | grep -v 'pam_permit' | while IFS= read -r line; do med "auth short-circuit rule: $line"; done
  grep -nHE '^[[:space:]]*[^#]*pam_exec\.so' /etc/pam.d/* 2>/dev/null | while IFS= read -r line; do
    tgt=$(printf '%s' "$line" | grep -oE '/[^ ]+' | grep -v 'pam_exec' | head -1)
    if [ -n "$tgt" ] && { [[ $tgt =~ $TEMP_RE ]] || { [ "$PKG" != none ] && [ -n "$(printf '%s\n' "$tgt" | unowned_filter)" ]; }; }; then
      hi "pam_exec runs unowned/temp program on auth (password logger/backdoor): $line"
    else
      med "pam_exec in use (review): $line"
    fi
  done
  grep -nHE '^[[:space:]]*[^#]*[[:space:]]/[^[:space:]]+\.so' /etc/pam.d/* 2>/dev/null | while IFS= read -r line; do
    tgt=$(printf '%s' "$line" | grep -oE '/[^[:space:]]+\.so' | head -1)
    case "$tgt" in */security/*) med "PAM module referenced by absolute path: $line" ;; *) hi "PAM module loaded from non-standard path: $line" ;; esac
  done
  grep -nHE 'pam_unix\.so.*nullok' /etc/pam.d/* 2>/dev/null | while IFS= read -r line; do info "nullok (empty passwords accepted if set): $line"; done
  [ "$PKG" != none ] && find /etc/pam.d -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do
    case "$f" in
      /etc/pam.d/common-*|/etc/pam.d/*-auth-ac|/etc/pam.d/*-auth|/etc/pam.d/*-ac) info "generated PAM file (pam-auth-update/authselect): $f" ;;
      *) med "PAM config file not from any package: $f $(fmeta "$f")" ;;
    esac
  done
  # shellcheck disable=SC2046,SC2086
  find $(uniq_dirs $SEC_DIRS) -type f -ctime -"$RECENT_DAYS" 2>/dev/null | while IFS= read -r f; do med "PAM module changed in last $RECENT_DAYS days: $f $(fmeta "$f")"; done
  grep -nHE 'LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT' /etc/security/pam_env.conf /etc/environment /etc/security/environment 2>/dev/null \
    | grep -vE ':[[:space:]]*#' | while IFS= read -r line; do hi "dynamic-linker variable injected via PAM environment: $line"; done
}

# =============================================================================
#  MODULE: cron / at
# =============================================================================
mod_cron() {
  section "cron, anacron, at" 08_cron.txt
  local f u line files=""
  for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/cron.yearly/* \
           /var/spool/cron/crontabs/* /var/spool/cron/* /var/spool/cron/tabs/* /var/spool/cron/atjobs/* /var/spool/at/* /var/spool/at/spool/*; do
    [ -f "$f" ] || continue
    files="$files
$f"
    { echo "=== $f $(fmeta "$f")"; grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | head -100; echo; } >> "$SECF"
    case "$f" in
      /var/spool/cron/atjobs/*|/var/spool/at/*)
        [ "${f##*/}" = .SEQ ] && continue
        med "pending at job: $f -> $(tail -3 "$f" 2>/dev/null | tr '\n' ' ' | cut -c1-200)" ;;
      /var/spool/cron/*)
        u=${f##*/}
        grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | grep -vE '^[A-Z_]+=' | while IFS= read -r line; do
          med "user crontab ($u): $line"
        done ;;
    esac
    [ -n "$(find "$f" -maxdepth 0 -ctime -"$RECENT_DAYS" 2>/dev/null)" ] && med "cron file changed in last $RECENT_DAYS days: $f $(fmeta "$f")"
  done
  if [ "$PKG" != none ]; then
    printf '%s\n' "$files" | awk 'NF' | grep -E '^/etc/' | unowned_filter | while IFS= read -r f; do
      case "${f##*/}" in .placeholder) continue ;; esac
      med "cron file not from any package: $f $(fmeta "$f")"
    done
  fi
  # shellcheck disable=SC2046
  scan_susp $(printf '%s\n' "$files" | awk 'NF')
  [ -r /etc/cron.allow ] && info "/etc/cron.allow: $(tr '\n' ' ' < /etc/cron.allow)"
}

# =============================================================================
#  MODULE: systemd
# =============================================================================
mod_systemd() {
  section "systemd services, timers, generators, drop-ins" 09_systemd.txt
  local f d h t line exe unitdirs gendirs
  if have systemctl; then
    systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | logcmd "running services"
    systemctl list-timers --all --no-pager 2>/dev/null | logcmd "timers"
    systemctl list-unit-files --state=enabled --no-pager --no-legend 2>/dev/null | logcmd "enabled unit files"
    systemctl list-units --state=failed --no-pager --no-legend 2>/dev/null | logcmd "failed units"
  fi
  unitdirs="/etc/systemd/system /etc/systemd/user /run/systemd/system /run/systemd/user /lib/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system /lib/systemd/user /usr/lib/systemd/user /etc/systemd/system.control /run/systemd/system.control"
  # shellcheck disable=SC2086
  find $unitdirs -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.target' -o -name '*.mount' \) 2>/dev/null | sort -u > "$WORK/units.txt"
  for h in $(homes); do
    find "$h/.config/systemd/user" "$h/.local/share/systemd/user" -type f 2>/dev/null
  done > "$WORK/user_units.txt"
  if [ "$PKG" != none ]; then unowned_filter < "$WORK/units.txt" > "$WORK/units_unowned.txt"; else cp "$WORK/units.txt" "$WORK/units_unowned.txt"; fi
  cat "$WORK/user_units.txt" >> "$WORK/units_unowned.txt"
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    line=$(grep -hE '^[[:space:]]*Exec[A-Za-z]*=' "$f" 2>/dev/null | head -3 | tr '\n' ' ' | cut -c1-250)
    case "$f" in
      /home/*|/root/*) med "per-user systemd unit (runs at user login): $f  $line" ;;
      *) med "systemd unit not from any package: $f $(fmeta "$f")  $line" ;;
    esac
    { echo "=== $f"; cat "$f" 2>/dev/null; echo; } >> "$SECF"
    grep -hoE '^[[:space:]]*Exec[A-Za-z]*=[-@+!:]*[^[:space:]]+' "$f" 2>/dev/null | sed -E 's/^[[:space:]]*Exec[A-Za-z]*=[-@+!:]*//' | while IFS= read -r exe; do
      if [[ $exe =~ $TEMP_RE ]] || [[ $exe =~ ^/(home|root|var/www)/ ]]; then hi "unit $f executes from temp/home/web: $exe"; fi
    done
  done < "$WORK/units_unowned.txt"
  # shellcheck disable=SC2046
  scan_susp $(cat "$WORK/units_unowned.txt")
  # enabled units whose target is unowned
  find /etc/systemd/system -path '*.wants/*' -type l 2>/dev/null | while IFS= read -r f; do
    t=$(readlink -f "$f" 2>/dev/null); [ -n "$t" ] && echo "$t"
  done | sort -u > "$WORK/enabled_targets.txt"
  if [ "$PKG" != none ]; then
    unowned_filter < "$WORK/enabled_targets.txt" | while IFS= read -r f; do med "ENABLED at boot, not from a package: $f"; done
  fi
  # drop-in overrides
  find /etc/systemd/system /run/systemd/system /etc/systemd/user -path '*.d/*.conf' -type f 2>/dev/null | while IFS= read -r f; do
    { echo "=== drop-in $f"; cat "$f"; echo; } >> "$SECF"
    if grep -qE '^[[:space:]]*(Exec[A-Za-z]*|Environment|EnvironmentFile)=' "$f" 2>/dev/null; then
      med "systemd drop-in overrides Exec/Environment of $(basename "$(dirname "$f")" .d): $f -> $(grep -hE '^[[:space:]]*(Exec|Environment)' "$f" | tr '\n' ' ' | cut -c1-200)"
    fi
    scan_susp "$f"
  done
  # generators run at every boot as root before units load
  gendirs="/etc/systemd/system-generators /run/systemd/system-generators /usr/local/lib/systemd/system-generators /lib/systemd/system-generators /usr/lib/systemd/system-generators /etc/systemd/user-generators /usr/local/lib/systemd/user-generators /usr/lib/systemd/user-generators /lib/systemd/user-generators"
  # shellcheck disable=SC2086
  find $gendirs -type f 2>/dev/null | sort -u > "$WORK/generators.txt"
  logcmd "systemd generators" < "$WORK/generators.txt"
  if [ "$PKG" != none ]; then
    unowned_filter < "$WORK/generators.txt" | while IFS= read -r f; do hi "systemd GENERATOR not from a package (runs as root every boot): $f $(fmeta "$f")"; done
  fi
  find /run/systemd/transient -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null | while IFS= read -r f; do
    med "transient unit (systemd-run): $f $(grep -hE '^Exec' "$f" | head -1 | cut -c1-200)"
  done
  grep -nHE '^[[:space:]]*DefaultEnvironment=.*LD_' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf 2>/dev/null | while IFS= read -r line; do hi "LD_* injected into every service: $line"; done
}

# =============================================================================
#  MODULE: shell startup files & init scripts
# =============================================================================
mod_shell() {
  section "Shell startup files, rc.local, init.d, motd" 10_shell_init.txt
  local files="" f h line k
  for f in /etc/profile/etc/profile.d/* /etc/bash.bashrc /etc/bashrc /etc/bash.bash_logout /etc/environment /etc/zsh/* /etc/zshrc /etc/zprofile /etc/zshenv /etc/csh.cshrc /etc/csh.login /etc/bash_completion.d/* /etc/inputrc; do
    [ -f "$f" ] && files="$files
$f"
  done
  for h in $(homes); do
    for f in .bashrc .bash_profile .bash_login .profile .bash_logout .zshrc .zprofile .zshenv .zlogin .zlogout .cshrc .tcshrc .config/fish/config.fish .xprofile .xinitrc .xsession .xsessionrc .vimrc .inputrc .pam_environment .config/autostart/*.desktop; do
      for line in "$h"/$f; do [ -f "$line" ] && files="$files
$line"; done
    done
  done
  files=$(printf '%s\n' "$files" | awk 'NF && !s[$0]++')
  printf '%s\n' "$files" | logcmd "startup files checked"
  # shellcheck disable=SC2086
  scan_susp $files
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    grep -nE '^[[:space:]]*alias[[:space:]]+(sudo|su|ls|ps|ss|netstat|lsof|top|htop|kill|pkill|cat|find|grep|which|passwd|ssh|scp|systemctl|crontab|iptables|nft|ufw|w|who|last|id|chattr|lsattr|history|unset|export|cd|rm|mv|cp)=' "$f" 2>/dev/null \
      | while IFS= read -r line; do
          # alias ls='ls --color=auto' is harmless: value starts with the same command
          k=$(printf '%s' "$line" | sed -E "s/^[0-9]+:[[:space:]]*alias[[:space:]]+([a-z]+)=['\"]?([^'\" ]*).*/\1 \2/")
          [ "${k% *}" = "${k#* }" ] && continue
          hi "alias overriding a security-relevant command in $f:$line"
        done
    grep -nE '^[[:space:]]*(function[[:space:]]+)?(sudo|su|ls|ps|ss|netstat|kill|cat|systemctl|passwd|ssh|crontab|chattr)[[:space:]]*\(\)' "$f" 2>/dev/null \
      | while IFS= read -r line; do hi "shell function overriding a command in $f:$line"; done
    grep -nE 'PROMPT_COMMAND|trap[[:space:]].*DEBUG' "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' \
      | while IFS= read -r line; do med "PROMPT_COMMAND/DEBUG trap (runs on every command) in $f:$line"; done
    grep -nE '(^|[[:space:];])(export[[:space:]]+)?LD_(PRELOAD|LIBRARY_PATH|AUDIT)=' "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' \
      | while IFS= read -r line; do hi "LD_* set in startup file $f:$line"; done
    grep -nE '(^|[[:space:];])(export[[:space:]]+)?PATH=[^#]*(^|:|=)(\.|/tmp[^:]*|/dev/shm[^:]*|/var/tmp[^:]*)(:|$|")' "$f" 2>/dev/null \
      | while IFS= read -r line; do hi "PATH includes . or a temp dir in $f:$line"; done
    case "$f" in */.vimrc) grep -nE 'autocmd|system\(|:!|silent!' "$f" 2>/dev/null | while IFS= read -r line; do med "vimrc command execution (persistence when root edits a file): $f:$line"; done ;; esac
    case "$f" in */.inputrc|/etc/inputrc) grep -nE '"[^"]*":[[:space:]]*"[^"]*\\(n|r)' "$f" 2>/dev/null | while IFS= read -r line; do med "readline macro that types+executes a command: $f:$line"; done ;; esac
  done <<EOF
$files
EOF
  if [ "$PKG" != none ]; then
    find /etc/profile.d /etc/bash_completion.d -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "profile.d/bash_completion.d file not from any package (runs for every login): $f $(fmeta "$f")"; done
  fi

  for f in /etc/rc.local /etc/rc.d/rc.local /etc/rc.d/rc.sysinit /etc/inittab; do
    [ -f "$f" ] || continue
    { echo "=== $f $(fmeta "$f")"; cat "$f"; } >> "$SECF"
    case "$f" in
      */inittab) grep -nE '^[^#].*:respawn:' "$f" | grep -viE 'getty' | while IFS= read -r line; do hi "non-getty respawn entry in inittab: $line"; done ;;
      *) grep -vE '^[[:space:]]*(#|$|exit 0)' "$f" | while IFS= read -r line; do med "$f runs at boot: $line"; done ;;
    esac
    scan_susp "$f"
  done
  if [ "$PKG" != none ]; then
    find /etc/init.d /etc/rc.d/init.d -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "init.d script not from any package: $f $(fmeta "$f")"; scan_susp "$f"; done
    find /etc/update-motd.d -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "motd script not from any package (runs as root at every SSH login): $f"; scan_susp "$f"; done
    find /etc/xdg/autostart -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "XDG autostart not from a package: $f"; done
  fi
}

# =============================================================================
#  MODULE: miscellaneous persistence
# =============================================================================
mod_misc() {
  section "Misc persistence: linker, apt/yum hooks, udev, modprobe, python, web modules, hosts" 11_misc_persistence.txt
  local f line t d
  cat /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | logcmd "ld.so.conf (+.d)"
  cat /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null | grep -vE '^[[:space:]]*(#|$|include)' | while IFS= read -r d; do
    if [[ $d =~ $TEMP_RE ]] || [[ $d =~ ^/(home|root|var/www)/ ]]; then hi "library search path points to temp/home: $d"; fi
  done
  [ "$PKG" != none ] && find /etc/ld.so.conf.d -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "ld.so.conf.d entry not from a package: $f -> $(tr '\n' ' ' < "$f")"; done

  # APT / YUM / DNF hooks run as root on every package operation
  if [ -d /etc/apt/apt.conf.d ]; then
    grep -nHE '(Pre|Post)-Invoke|Pre-Install-Pkgs|Post-Invoke-Success|Update::' /etc/apt/apt.conf.d/* 2>/dev/null | logcmd "APT hooks"
    for f in /etc/apt/apt.conf.d/*; do
      [ -f "$f" ] || continue
      grep -qE '(Pre|Post)-Invoke|Pre-Install-Pkgs' "$f" 2>/dev/null || continue
      if [ "${f##*/}" = docker-clean ] && ! grep -vE '^[[:space:]]*(#|$|//)' "$f" | grep -E 'Invoke' | grep -qvE 'rm -f /var/cache/apt/'; then
        info "standard docker-clean APT hook: $f"
      elif [ "$PKG" != none ] && [ -n "$(printf '%s\n' "$f" | unowned_filter)" ]; then
        hi "APT hook in file not from any package (runs as root on apt use): $f -> $(grep -hE 'Invoke|Install-Pkgs' "$f" | tr '\n' ' ' | cut -c1-250)"
      fi
      scan_susp "$f"
    done
  fi
  for d in /etc/yum/pluginconf.d /etc/dnf/plugins /usr/lib/yum-plugins; do
    [ -d "$d" ] && [ "$PKG" != none ] && find "$d" -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "yum/dnf plugin not from a package: $f"; done
  done

  # udev RUN+= rules
  for f in /etc/udev/rules.d/* /run/udev/rules.d/* /lib/udev/rules.d/* /usr/lib/udev/rules.d/*; do
    [ -f "$f" ] || continue
    grep -qE 'RUN\+?=' "$f" 2>/dev/null || continue
    if [ "$PKG" = none ] || [ -n "$(printf '%s\n' "$f" | unowned_filter)" ]; then
      med "udev rule with RUN not from a package: $f -> $(grep -hoE 'RUN\+?="[^"]*"' "$f" | head -3 | tr '\n' ' ')"
      scan_susp "$f"
    fi
  done

  # modprobe install hooks + module autoload
  grep -nHE '^[[:space:]]*install[[:space:]]' /etc/modprobe.d/* /lib/modprobe.d/* /usr/lib/modprobe.d/* /run/modprobe.d/* 2>/dev/null | while IFS= read -r line; do
    case "$line" in
      *"/bin/true"*|*"/bin/false"*|*"/usr/bin/true"*|*"/usr/bin/false"*|*"modprobe --ignore-install"*|*"/sbin/modprobe"*|*"/usr/sbin/modprobe"*|*"/bin/modprobe"*) info "modprobe install: $line" ;;
      *) hi "modprobe 'install' runs a custom command when a module loads: $line" ;;
    esac
  done
  cat /etc/modules /etc/modules-load.d/* /usr/lib/modules-load.d/* /lib/modules-load.d/* 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | logcmd "modules loaded at boot"
  [ "$PKG" != none ] && find /etc/modules-load.d -type f 2>/dev/null | unowned_filter | while IFS= read -r f; do med "modules-load.d file not from a package: $f -> $(grep -vE '^#' "$f" | tr '\n' ' ')"; done

  # NetworkManager / ifupdown hooks
  for d in /etc/NetworkManager/dispatcher.d /etc/network/if-up.d /etc/network/if-pre-up.d /etc/network/if-down.d /etc/network/if-post-down.d /etc/ppp/ip-up.d /etc/dhcp/dhclient-exit-hooks.d /etc/dhcp/dhclient-enter-hooks.d; do
    [ -d "$d" ] || continue
    find "$d" -type f 2>/dev/null | while IFS= read -r f; do
      if [ "$PKG" = none ] || [ -n "$(printf '%s\n' "$f" | unowned_filter)" ]; then med "network hook script not from a package: $f"; fi
      scan_susp "$f"
    done
  done

  # python startup hooks (.pth with import, sitecustomize)
  find /usr/lib/python3* /usr/local/lib/python3* /usr/lib64/python3* /usr/lib/python2* -maxdepth 3 \( -name '*.pth' -o -name 'sitecustomize.py' -o -name 'usercustomize.py' \) -type f 2>/dev/null > "$WORK/pyhooks.txt"
  while IFS= read -r f; do
    if [ "$PKG" != none ] && [ -z "$(printf '%s\n' "$f" | unowned_filter)" ]; then continue; fi
    case "$f" in
      *.pth) grep -q '_distutils_hack' "$f" 2>/dev/null && continue
             grep -qE '^[[:space:]]*import ' "$f" 2>/dev/null && hi "python .pth with import (runs on every python start, not from a package): $f -> $(grep -m1 -E '^[[:space:]]*import' "$f" | cut -c1-200)" ;;
      *) med "python site/usercustomize not from a package (runs on every python start): $f" ;;
    esac
  done < "$WORK/pyhooks.txt"

  # web server modules (mod_rootme style backdoors)
  for d in /usr/lib/apache2/modules /usr/lib64/httpd/modules /etc/httpd/modules /usr/lib/nginx/modules /usr/share/nginx/modules /usr/lib64/nginx/modules; do
    [ -d "$d" ] || continue
    if [ "$PKG" != none ]; then
      find "$d" -name '*.so' 2>/dev/null | unowned_filter | while IFS= read -r f; do hi "web server module not from any package: $f $(fmeta "$f")"; done
    fi
  done
  grep -rnhE '^[[:space:]]*LoadModule' /etc/apache2 /etc/httpd 2>/dev/null | logcmd "apache LoadModule"
  grep -rnhE '^[[:space:]]*load_module' /etc/nginx 2>/dev/null | logcmd "nginx load_module"

  # logrotate postrotate commands
  # shellcheck disable=SC2046
  scan_susp $(find /etc/logrotate.d -type f 2>/dev/null) /etc/logrotate.conf

  # hosts / resolver hijack
  grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | logcmd "/etc/hosts"
  grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | grep -vE '^(127\.|::1|fe00::|ff0[0-9]::|0\.0\.0\.0[[:space:]]+localhost)' | while IFS= read -r line; do
    if printf '%s' "$line" | grep -qiE '(debian|ubuntu|centos|fedora|redhat|rockylinux|almalinux|launchpad|kernel\.org|security|mirror|archive|update|github|pypi|clamav|splunk|wazuh|elastic)'; then
      hi "/etc/hosts overrides an update/security domain: $line"
    else
      info "/etc/hosts entry: $line"
    fi
  done
  grep -vE '^[[:space:]]*(#|$)' /etc/resolv.conf 2>/dev/null | logcmd "/etc/resolv.conf"
  grep -E '^[[:space:]]*(hosts|passwd|shadow|group):' /etc/nsswitch.conf 2>/dev/null | logcmd "nsswitch"
  grep -E '^[[:space:]]*(passwd|shadow|group):' /etc/nsswitch.conf 2>/dev/null | grep -vE ':[[:space:]]*(files|compat|systemd|sss|ldap|winbind|nis|db|altfiles|extrausers|cache|[[:space:]]|\[|\]|=|[A-Za-z]+)*$' \
    | while IFS= read -r line; do med "unusual nsswitch source: $line"; done
  if have docker; then docker ps --format '{{.ID}} {{.Image}} {{.Names}} {{.Status}}' 2>/dev/null | logcmd "docker containers"; fi
}

# =============================================================================
#  MODULE: kernel
# =============================================================================
mod_kernel() {
  section "Kernel: taint, hidden modules, module origins, eBPF" 12_kernel.txt
  local t m f line
  t=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)
  log "kernel: $KREL   tainted=$t"
  if [ "$t" != 0 ]; then
    local why=""
    [ $((t & 1)) -ne 0 ] && why="$why proprietary-module"
    [ $((t & 2)) -ne 0 ] && why="$why forced-load"
    [ $((t & 128)) -ne 0 ] && why="$why kernel-oops"
    [ $((t & 4096)) -ne 0 ] && why="$why OUT-OF-TREE-module"
    [ $((t & 8192)) -ne 0 ] && why="$why UNSIGNED-module"
    [ $((t & 32768)) -ne 0 ] && why="$why kernel-live-patched"
    med "kernel is tainted ($t:$why) - check the module list below for something you don't recognize (rootkits taint as out-of-tree/unsigned)"
  fi
  awk '{print $1}' /proc/modules 2>/dev/null | sort > "$WORK/mods_proc.txt"
  for m in /sys/module/*; do [ -f "$m/initstate" ] && echo "${m##*/}"; done | sort > "$WORK/mods_sys.txt"
  comm -13 "$WORK/mods_proc.txt" "$WORK/mods_sys.txt" | while IFS= read -r m; do
    hi "kernel module '$m' is live in /sys/module but HIDDEN from /proc/modules (lsmod) - LKM rootkit indicator"
  done
  logcmd "loaded modules" < "$WORK/mods_proc.txt"
  if have modinfo; then
    : > "$WORK/mod_files.txt"
    while IFS= read -r m; do
      f=$(modinfo -F filename "$m" 2>/dev/null | head -1)
      case "$f" in
        ""|"(builtin)") ;;
        /lib/modules/"$KREL"/*|/usr/lib/modules/"$KREL"/*) echo "$f" >> "$WORK/mod_files.txt" ;;
        *) hi "loaded module '$m' comes from outside /lib/modules/$KREL: $f" ;;
      esac
      [ -z "$f" ] && med "loaded module '$m' has no module file on disk (loaded from memory/deleted file?)"
    done < "$WORK/mods_proc.txt"
    if [ "$PKG" != none ]; then
      unowned_filter < "$WORK/mod_files.txt" | while IFS= read -r f; do
        case "$f" in */updates/dkms/*|*/extra/*) info "DKMS/extra module (verify you know it): $f" ;; *) med "loaded kernel module file not from any package: $f $(fmeta "$f")" ;; esac
      done
    fi
  fi
  if have dmesg; then
    dmesg 2>/dev/null | grep -iE 'taints kernel|module verification failed|loading out-of-tree|unsigned module|hidden|rootkit' | tail -20 | while IFS= read -r line; do med "dmesg: $line"; done
  fi
  log "kernel.modules_disabled=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)  kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)  unprivileged_bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"
  # eBPF (used by modern rootkits / BPFdoor variants)
  if have bpftool; then
    bpftool prog show 2>/dev/null | logcmd "bpftool prog show"
    bpftool prog show 2>/dev/null | grep -E '^[0-9]+:' | grep -vE 'cgroup_(skb|device|sock)|tracing.*name (hid_|s_)|name sd_' | while IFS= read -r line; do med "eBPF program loaded (verify owner): $line"; done
  fi
  find /sys/fs/bpf -mindepth 1 2>/dev/null | head -50 | while IFS= read -r f; do med "pinned BPF object: $f"; done
  grep -l 'prog_type' /proc/[0-9]*/fdinfo/* 2>/dev/null | awk -F/ '{print $3}' | sort -u | while IFS= read -r m; do
    line=$(readlink /proc/"$m"/exe 2>/dev/null)
    case "${line##*/}" in systemd|systemd-*|bpftool|bpftrace|falco*|tracee*|cilium*|snapd) info "pid $m ($line) holds eBPF programs" ;; *) med "pid $m ($line) holds eBPF programs - unusual unless it's a monitoring tool" ;; esac
  done
}

# =============================================================================
#  MODULE: processes
# =============================================================================
is_interp() { [[ $1 =~ $INTERP_RE ]]; }

mod_proc() {
  section "Processes (read directly from /proc)" 13_processes.txt
  build_proc_table
  local pid ppid uid exe comm cmd e eb a0 f line
  awk -F'\t' '{ printf "%-7s %-7s %-6s %-45s %s\n", $1, $2, $3, $4, $6 }' "$PROCS" | logcmd "process table: pid ppid uid exe cmdline"
  while IFS="$TAB" read -r pid ppid uid exe comm cmd; do
    [ "$pid" = "$$" ] && continue
    [ -z "$exe" ] && [ -z "$cmd" ] && continue
    case "$exe" in
      /memfd:*) hi "pid $pid runs from memfd (fileless execution - verify it is a known agent): $exe :: $cmd" ;;
      *" (deleted)")
        e=${exe% (deleted)}
        if [[ $e =~ $TEMP_RE ]]; then hi "pid $pid running from a DELETED temp file: $exe :: $cmd"
        else med "pid $pid binary deleted/replaced on disk since start (upgrade or tampering): $exe :: $cmd"; fi ;;
      /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/run/shm/*|/dev/*) hi "pid $pid executable lives in temp dir: $exe :: $cmd" ;;
      /home/*|/root/*|/var/www/*) med "pid $pid executable in home/web dir: $exe :: $cmd" ;;
    esac
    case "$cmd" in "["*"]"*) [ -n "$exe" ] && hi "pid $pid pretends to be kernel thread '$cmd' but runs userland binary $exe" ;; esac
    eb=${exe##*/}; eb=${eb% (deleted)}
    a0=${cmd%% *}; a0=${a0##*/}; a0=${a0#-}; a0=${a0%:}
    if [ -n "$eb" ] && is_interp "$eb" && [ -n "$a0" ] && ! is_interp "$a0" && [ "$a0" != "$eb" ]; then
      case "$a0" in "$eb"*|python*|perl*|ruby*|php*|node*|java*) ;; *)
        if [[ $a0 =~ $DAEMON_RE ]]; then hi "pid $pid: $exe disguised as '$a0' (argv[0] spoofing): $cmd"
        else med "pid $pid: interpreter $exe running under name '$a0': $cmd"; fi ;;
      esac
    fi
    case "$eb" in nc|nc.traditional|nc.openbsd|ncat|netcat|socat|telnet) hi "pid $pid netcat/socat/telnet running: $cmd" ;; esac
  done < "$PROCS"

  # LD_PRELOAD in any process environment
  grep -alE 'LD_(PRELOAD|AUDIT)=' /proc/[0-9]*/environ 2>/dev/null | while IFS= read -r f; do
    pid=$(printf '%s' "$f" | cut -d/ -f3)
    line=$(tr '\0' '\n' < "$f" 2>/dev/null | grep -E '^LD_(PRELOAD|AUDIT)=' | tr '\n' ' ')
    hi "pid $pid ($(readlink /proc/"$pid"/exe 2>/dev/null)) runs with $line"
  done

  # working directory in temp
  ls -l /proc/[0-9]*/cwd 2>/dev/null | awk '{print $(NF-2) "\t" $NF}' | while IFS="$TAB" read -r f e; do
    case "$e" in /tmp|/tmp/*|/var/tmp*|/dev/shm*) pid=$(printf '%s' "$f" | cut -d/ -f3); med "pid $pid working dir is $e ($(readlink /proc/"$pid"/exe 2>/dev/null))" ;; esac
  done

  # binaries of running processes: unowned or tampered
  cut -f4 "$PROCS" | grep '^/' | grep -v ' (deleted)$' | sort -u > "$WORK/proc_exes.txt"
  if [ "$PKG" != none ]; then
    grep -vE '^/(usr/local|opt|snap|home|root|tmp|var/tmp|dev/shm|memfd)' "$WORK/proc_exes.txt" | unowned_filter | while IFS= read -r e; do
      hi "process running binary not owned by any package: $e (pids: $(awk -F'\t' -v x="$e" '$4==x{printf "%s ",$1}' "$PROCS"))"
    done
    if [ -s "$WORK/pkg_mismatch.txt" ]; then
      canon < "$WORK/proc_exes.txt" | sort -u | comm -12 - "$WORK/pkg_mismatch.txt" | while IFS= read -r e; do
        hi "process running a TAMPERED binary: $e"
      done
    fi
  fi

  # shells spawned by network services = webshell / RCE
  awk -F'\t' 'FNR==NR { ex[$1]=$4; next }
    { c=$4; sub(/.*\//,"",c); sub(/ \(deleted\)$/,"",c); p=ex[$2]; pb=p; sub(/.*\//,"",pb)
      if (pb ~ /^(apache2|httpd|nginx|php-fpm.*|php-cgi.*|java|tomcat.*|mysqld|mariadbd|postgres|node|lighttpd|vsftpd|proftpd|pure-ftpd|named|dovecot|exim4|master|smbd|uwsgi|gunicorn|python[0-9.]*|perl|ruby|redis-server|mongod)$/ &&
          c ~ /^(bash|sh|dash|zsh|ksh|python[0-9.]*|perl|ruby|nc|ncat|netcat|socat|busybox|telnet|curl|wget|whoami|id|uname)$/)
        print $1 "\t" pb "\t" $4 "\t" $6 }' "$PROCS" "$PROCS" | while IFS="$TAB" read -r pid e f cmd; do
    case "$e" in python*|perl|ruby) med "pid $pid: $f spawned by $e: $cmd" ;; *) hi "pid $pid: shell/tool '$f' spawned by network service '$e' (webshell/RCE): $cmd" ;; esac
  done

  # hidden processes
  if have ps; then
    ps -e -o pid= 2>/dev/null | tr -d ' ' | sort > "$WORK/ps_pids.txt"
    ls -d /proc/[0-9]* 2>/dev/null | sed 's#/proc/##' | sort > "$WORK/proc_pids.txt"
    comm -13 "$WORK/ps_pids.txt" "$WORK/proc_pids.txt" | while IFS= read -r pid; do
      [ -d "/proc/$pid" ] || continue
      [ "$pid" = "$$" ] && continue
      ps -p "$pid" >/dev/null 2>&1 && continue
      hi "pid $pid exists in /proc but 'ps' does not show it (trojaned ps / userland rootkit): $(readlink /proc/"$pid"/exe 2>/dev/null) $(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | cut -c1-150)"
    done
  fi
  if [ "$QUICK" = 0 ] && [ "${BASH_VERSINFO[0]}" -ge 4 ]; then
    printf '  brute-forcing PID space for hidden processes...\n'
    local max lim tg k v rest
    declare -A listed=()
    for f in /proc/[0-9]*; do listed[${f#/proc/}]=1; done
    max=$(sort -n "$WORK/proc_pids.txt" 2>/dev/null | tail -1); [ -z "$max" ] && max=40000
    lim=$((max + 5000)); [ "$lim" -gt 400000 ] && lim=400000
    pid=1
    while [ "$pid" -le "$lim" ]; do
      if [ -z "${listed[$pid]}" ] && [ -e "/proc/$pid/status" ]; then
        tg=""
        while read -r k v rest; do [ "$k" = "Tgid:" ] && { tg=$v; break; }; done < "/proc/$pid/status" 2>/dev/null
        if [ "$tg" = "$pid" ]; then
          hi "pid $pid is reachable but HIDDEN from the /proc listing (kernel rootkit hooking getdents): $(readlink /proc/"$pid"/exe 2>/dev/null) $(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | cut -c1-150)"
        fi
      fi
      pid=$((pid+1))
    done
  fi
  cp "$PROCS" "$OUT/processes.tsv" 2>/dev/null
}

# =============================================================================
#  MODULE: network
# =============================================================================
fmt_sock() { awk -F'\t' '{ printf "%-5s %-10s %-40s %-40s pid=%-7s %s\n", $1, $2, $3 ":" $4, $5 ":" $6, $9, $10 }'; }

mod_net() {
  section "Network: listeners, connections, raw/packet sniffers, firewall" 14_network.txt
  build_sockets
  local proto st lip lport rip rport uid inode pid exe eb ports f line i flags
  awk -F'\t' '$2=="LISTEN" || $2=="UNCONN"' "$SOCKS" | sort -t"$TAB" -k1,1 -k4,4n | fmt_sock | logcmd "LISTENING sockets (parsed from /proc/net, not from ss/netstat)"
  awk -F'\t' '$2!="LISTEN" && $2!="UNCONN"' "$SOCKS" | fmt_sock | logcmd "connected sockets"

  awk -F'\t' '$10 ~ /^\// {print $10}' "$SOCKS" | sed 's/ (deleted)$//' | sort -u > "$WORK/sock_exes.txt"
  if [ "$PKG" != none ]; then
    grep -vE '^/(usr/local|opt|snap)/' "$WORK/sock_exes.txt" | unowned_filter > "$WORK/sock_exes_unowned.txt"
  else : > "$WORK/sock_exes_unowned.txt"; fi

  while IFS="$TAB" read -r proto st lip lport rip rport uid inode pid exe; do
    eb=${exe##*/}; eb=${eb% (deleted)}
    case "$st" in
      LISTEN|UNCONN)
        if [ -z "$pid" ] && [ "$inode" != 0 ] && [ "$st" = LISTEN ]; then
          hi "$proto port $lport ($lip) is LISTENING but no visible process owns it (hidden process / rootkit?) inode=$inode"
        elif [ -n "$exe" ] && is_interp "$eb"; then
          hi "$proto port $lport listener owned by shell/interpreter $exe (pid $pid) - bind shell? $(awk -F'\t' -v p="$pid" '$1==p{print $6}' "$PROCS")"
        elif [[ $exe =~ $TEMP_RE ]] || [[ $exe == *"(deleted)" ]]; then
          hi "$proto port $lport listener runs from temp/deleted binary $exe (pid $pid)"
        elif [ -n "$exe" ] && grep -qxF "$(printf '%s' "$exe" | canon)" "$WORK/sock_exes_unowned.txt"; then
          hi "$proto port $lport listener binary not from any package: $exe (pid $pid)"
        else
          [ "$st" = LISTEN ] && info "listening $proto $lip:$lport  $exe (pid $pid)"
        fi ;;
      ESTAB|SYN_SENT|UDP_CONN|CLOSE_WAIT)
        case "$rip" in 127.*|::1) continue ;; esac
        if [ -n "$exe" ] && is_interp "$eb"; then
          hi "$st $proto connection $lip:$lport -> $rip:$rport by shell/interpreter $exe (pid $pid) - reverse shell? $(awk -F'\t' -v p="$pid" '$1==p{print $6}' "$PROCS")"
        elif [[ $exe =~ $TEMP_RE ]] || [[ $exe == *"(deleted)" ]]; then
          hi "$st connection -> $rip:$rport from temp/deleted binary $exe (pid $pid)"
        elif [ -n "$exe" ] && grep -qxF "$(printf '%s' "$exe" | canon)" "$WORK/sock_exes_unowned.txt"; then
          hi "$st connection -> $rip:$rport by binary not from any package: $exe (pid $pid)"
        elif [ "$st" = SYN_SENT ]; then
          med "outbound connection attempt (SYN_SENT) -> $rip:$rport by $exe (pid $pid)"
        else
          info "$st $lip:$lport -> $rip:$rport $exe (pid $pid)"
        fi ;;
    esac
  done < "$SOCKS"

  # cross-check against ss / netstat (trojaned tool hides ports)
  awk -F'\t' '$1 ~ /^tcp/ && $2=="LISTEN" {print $4}' "$SOCKS" | sort -u > "$WORK/proc_lports.txt"
  if have ss; then
    ss -ltn 2>/dev/null | awk 'NR>1 {n=split($4,a,":"); print a[n]}' | sort -u > "$WORK/ss_lports.txt"
    comm -23 "$WORK/proc_lports.txt" "$WORK/ss_lports.txt" | while IFS= read -r ports; do
      hi "TCP port $ports is listening per /proc/net but HIDDEN from 'ss' - ss is trojaned or hooked"
    done
  fi
  if have netstat; then
    netstat -ltn 2>/dev/null | awk '$1 ~ /^tcp/ {n=split($4,a,":"); print a[n]}' | sort -u > "$WORK/ns_lports.txt"
    comm -23 "$WORK/proc_lports.txt" "$WORK/ns_lports.txt" | while IFS= read -r ports; do
      hi "TCP port $ports is listening per /proc/net but HIDDEN from 'netstat' - netstat is trojaned or hooked"
    done
  fi

  # packet sockets = passive sniffers (BPFdoor-style magic-packet backdoors)
  if [ -r /proc/net/packet ]; then
    awk 'NR>1 {print $NF}' /proc/net/packet | while IFS= read -r inode; do
      pid=$(awk -F'\t' -v i="$inode" '$1==i{print $2; exit}' "$WORK/inode_pid.tsv")
      exe=""; [ -n "$pid" ] && exe=$(readlink /proc/"$pid"/exe 2>/dev/null)
      eb=${exe##*/}
      case "$eb" in
        dhclient*|dhcpcd|NetworkManager|systemd-networkd|wpa_supplicant|tcpdump|tshark|dumpcap|lldpd|keepalived|dhcpd|dnsmasq|zeek|bro|suricata|snort|arpwatch|ladvd|cdpr|isc-dhcp*|udhcpc|nm-dhcp*) info "packet socket: $exe (pid $pid)" ;;
        "") hi "raw PACKET socket (inode $inode) with no visible owner - hidden sniffer/backdoor" ;;
        *) hi "raw PACKET socket held by $exe (pid $pid) - passive magic-packet backdoor (BPFdoor-style) unless you know this tool: $(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | cut -c1-150)" ;;
      esac
    done
  fi
  for f in /proc/net/raw /proc/net/raw6; do
    [ -r "$f" ] || continue
    awk 'NR>1 && NF>=10 {print $10}' "$f" | while IFS= read -r inode; do
      [ "$inode" = 0 ] && continue
      pid=$(awk -F'\t' -v i="$inode" '$1==i{print $2; exit}' "$WORK/inode_pid.tsv")
      exe=""; [ -n "$pid" ] && exe=$(readlink /proc/"$pid"/exe 2>/dev/null)
      case "${exe##*/}" in
        ping|ping6|fping|traceroute*|mtr*|NetworkManager|arping|keepalived|zabbix*|nagios*|smokeping) info "raw socket: $exe" ;;
        "") med "raw IP socket (inode $inode) with no visible owner" ;;
        *) med "raw IP socket held by $exe (pid $pid) - ICMP backdoors (prism etc.) use these" ;;
      esac
    done
  done

  for i in /sys/class/net/*; do
    flags=$(cat "$i/flags" 2>/dev/null) || continue
    [ $((flags & 0x100)) -ne 0 ] && med "interface ${i##*/} is in PROMISCUOUS mode (sniffing)"
  done

  { have iptables-save && iptables-save 2>/dev/null; } | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' > "$WORK/iptables.txt"
  { have ip6tables-save && ip6tables-save 2>/dev/null; } | grep -v '^#' >> "$WORK/iptables.txt"
  logcmd "iptables-save" < "$WORK/iptables.txt"
  grep -E -- '-j (DNAT|REDIRECT)|-m string|--string|-m recent|-m u32|--hex-string' "$WORK/iptables.txt" 2>/dev/null | while IFS= read -r line; do
    med "iptables rule with redirect/knock/string-match (port-knocking or traffic hijack backdoor?): $line"
  done
  have nft && nft list ruleset 2>/dev/null | logcmd "nft ruleset"
  { ip route 2>/dev/null || route -n 2>/dev/null; } | logcmd "routes"
  { ip neigh 2>/dev/null || arp -an 2>/dev/null; } | logcmd "neighbours"
  { ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null; } | logcmd "addresses"
  cp "$SOCKS" "$OUT/sockets.tsv" 2>/dev/null
}

# =============================================================================
#  MODULE: webshells
# =============================================================================
mod_web() {
  section "Web roots: webshells & recently dropped files" 15_web.txt
  if [ "$QUICK" = 1 ]; then log "skipped (--quick)"; return; fi
  local roots="" d f re
  for d in /var/www /srv /usr/share/nginx /usr/local/apache2/htdocs /usr/local/nginx/html /opt/lampp/htdocs /var/lib/tomcat* /opt/tomcat* /usr/share/tomcat* /var/lib/jetty* /usr/share/wordpress /usr/share/phpmyadmin /var/lib/mediawiki /usr/share/roundcube; do
    [ -d "$d" ] && roots="$roots $d"
  done
  for d in $(grep -rhoiE '^[[:space:]]*(DocumentRoot|root)[[:space:]]+"?[^";[:space:]]+' /etc/apache2 /etc/httpd /etc/nginx 2>/dev/null | awk '{print $2}' | tr -d '"' | sort -u); do
    [ -d "$d" ] && roots="$roots $d"
  done
  roots=$(printf '%s\n' $roots | awk 'NF && !s[$0]++' | tr '\n' ' ')
  [ -z "$roots" ] && { log "no web roots found"; return; }
  log "web roots: $roots"
  re='(eval|assert|create_function)[[:space:]]*\([[:space:]]*(@?(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)|\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES))|(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*@?\$_(GET|POST|REQUEST|COOKIE|SERVER)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder[[:space:]]*\(|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(|base64_decode[[:space:]]*\([[:space:]]*\$_|move_uploaded_file.*\$_(GET|POST|REQUEST)|<\?php[[:space:]]+@?\$_(GET|POST|REQUEST)|cmd\.exe|/bin/sh|fsockopen\([^)]*\$|weevely|c99shell|r57shell|b374k|wso[[:space:]]*shell|FilesMan'
  # shellcheck disable=SC2086
  find $roots -xdev -type f -size -3M \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.inc' -o -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.asp' -o -iname '*.aspx' -o -iname '*.cgi' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.sh' -o -iname '.htaccess' -o -iname '*.war' \) 2>/dev/null > "$WORK/webfiles.txt"
  log "script files scanned: $(wc -l < "$WORK/webfiles.txt")"
  while IFS= read -r f; do
    if grep -qE "$re" "$f" 2>/dev/null; then
      hi "WEBSHELL pattern in $f $(fmeta "$f") :: $(grep -m1 -oE "$re" "$f" 2>/dev/null | cut -c1-120)"
    fi
    case "$f" in
      */uploads/*.php*|*/upload/*.php*|*/images/*.php*|*/img/*.php*|*/files/*.php*|*/media/*.php*|*/cache/*.php*|*/tmp/*.php*)
        med "PHP file inside an upload/media/cache dir: $f $(fmeta "$f")" ;;
      */.htaccess)
        grep -qiE 'AddType.*(php|x-httpd)|AddHandler|SetHandler|php_value[[:space:]]+auto_prepend_file|auto_append_file' "$f" 2>/dev/null && \
          hi ".htaccess makes extra extensions executable or auto-prepends code: $f :: $(grep -iE 'AddType|AddHandler|SetHandler|auto_' "$f" | head -2 | tr '\n' ' ')" ;;
    esac
  done < "$WORK/webfiles.txt"
  # shellcheck disable=SC2086
  find $roots -xdev -type f -ctime -"$RECENT_DAYS" 2>/dev/null | head -300 | while IFS= read -r f; do
    med "web file created/changed in last $RECENT_DAYS days: $f $(fmeta "$f")"
  done
  grep -rhE '^[[:space:]]*(auto_prepend_file|auto_append_file|disable_functions)[[:space:]]*=' /etc/php* 2>/dev/null | logcmd "php.ini auto_prepend / disable_functions"
  grep -rhE '^[[:space:]]*(auto_prepend_file|auto_append_file)[[:space:]]*=[[:space:]]*[^[:space:];]' /etc/php* 2>/dev/null | while IFS= read -r f; do hi "php.ini auto_prepend/append set (code injected into every PHP page): $f"; done
}

# =============================================================================
#  MODULE: beacon / C2 hunt
# =============================================================================
analyze_events() {   # $1 events file (epoch\tkey) $2 label
  awk -F'\t' -v label="$2" '
    { k=$2; t=int($1); if (t==last[k]) next; last[k]=t; n[k]++; times[k]=times[k] " " t }
    END {
      for (k in n) {
        if (n[k] < 3) { printf "%s\t%d\t-\t-\t-\t%s\n", label, n[k], k; continue }
        m=split(times[k], a, " "); cnt=0; s=0; ss=0
        for (i=2; i<=m; i++) { d=a[i]-a[i-1]; if (d<=0) continue; iv[++cnt]=d; s+=d; ss+=d*d }
        if (cnt < 2) { printf "%s\t%d\t-\t-\t-\t%s\n", label, n[k], k; continue }
        mean=s/cnt; var=ss/cnt-mean*mean; if (var<0) var=0; sd=sqrt(var); cv=(mean>0)? sd/mean : 9
        printf "%s\t%d\t%.1f\t%.1f\t%.2f\t%s\n", label, n[k], mean, sd, cv, k
      }
    }' "$1"
}

mod_beacon() {
  local S="$BEACON_SECS"
  section "C2 / beacon hunt (${S}s capture)" 20_beacon.txt
  local ev_proc="$WORK/bev_proc.tsv" ev_tcp="$WORK/bev_tcpdump.tsv" ev_dns="$WORK/bev_dns.tsv" ev_aud="$WORK/bev_audit.tsv"
  local alog="/var/log/audit/audit.log" aoff=0 audit_on=0 tdpid="" end now localips line lvl
  : > "$ev_proc"; : > "$ev_tcp"; : > "$ev_dns"; : > "$ev_aud"; : > "$WORK/bev_attr.txt"; : > "$WORK/bev_attr.txt.tmp"
  localips=$( { ip -o addr 2>/dev/null | awk '{split($4,a,"/"); print a[1]}'; hostname -I 2>/dev/null | tr ' ' '\n'; } | awk 'NF' | sort -u | tr '\n' ' ')
  log "local IPs: $localips"

  # 1) auditd connect() logging - gives exact binary for every connection
  if have auditctl && [ -w "$alog" ] && auditctl -s 2>/dev/null | grep -qE 'enabled[ =]1'; then
    aoff=$(stat -c %s "$alog" 2>/dev/null || echo 0)
    if auditctl -a always,exit -F arch=b64 -S connect -k boxaudit_conn >/dev/null 2>&1; then
      audit_on=1
      auditctl -a always,exit -F arch=b32 -S connect -k boxaudit_conn >/dev/null 2>&1
      CLEANUP_CMDS="$CLEANUP_CMDS auditctl -d always,exit -F arch=b64 -S connect -k boxaudit_conn >/dev/null 2>&1; auditctl -d always,exit -F arch=b32 -S connect -k boxaudit_conn >/dev/null 2>&1;"
      printf '  auditd: logging connect() syscalls (rule removed afterwards)\n'
    fi
  else
    log "auditd not usable (not installed, disabled, or locked) - using tcpdump and /proc polling"
  fi

  # 2) tcpdump: outbound SYNs and DNS queries
  if have tcpdump; then
    if have timeout; then
      timeout "$S" tcpdump -nn -tt -l -i any '(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or (udp dst port 53)' > "$WORK/tcpdump.txt" 2>/dev/null &
    else
      tcpdump -nn -tt -l -i any '(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or (udp dst port 53)' > "$WORK/tcpdump.txt" 2>/dev/null &
    fi
    tdpid=$!
    CLEANUP_CMDS="$CLEANUP_CMDS kill $tdpid >/dev/null 2>&1;"
    printf '  tcpdump: capturing SYNs + DNS queries\n'
  fi

  # 3) /proc polling every second. Closed connections linger ~60s in TIME_WAIT,
  #    so even sub-second HTTP beacons are caught (binary is only known if seen live).
  printf '  polling /proc/net every second for %ss (Ctrl-C to stop early)...\n' "$S"
  for f in tcp tcp6; do [ -r "/proc/net/$f" ] && awk -v proto="$f" "$NETAWK" "/proc/net/$f"; done \
    | awk -F'\t' '$2=="LISTEN"{print $4}' | sort -u > "$WORK/bev_lports.txt"
  echo 0 >> "$WORK/bev_lports.txt"
  end=$(( $(date +%s) + S ))
  local seen="$WORK/bev_seen.txt"; echo "#" > "$seen"
  while :; do
    now=$(date +%s); [ "$now" -ge "$end" ] && break
    for f in tcp tcp6; do [ -r "/proc/net/$f" ] && awk -v proto="$f" "$NETAWK" "/proc/net/$f"; done \
      | awk -F'\t' -v t="$now" '
          FILENAME==ARGV[1] { lp[$1]=1; next }
          ($2!="LISTEN") && !($4 in lp) && $5!~/^127\./ && $5!="::1" && $5!="0.0.0.0" && $5!="::" {
            print t "\t" $3 ":" $4 ">" $5 ":" $6 "\t" $8 "\t" $5 ":" $6 }' "$WORK/bev_lports.txt" - > "$WORK/bev_now.tsv"
    # one event per connection (keyed by local+remote endpoint)
    awk -F'\t' 'FILENAME==ARGV[1]{s[$1]=1;next} !($2 in s)' "$seen" "$WORK/bev_now.tsv" > "$WORK/bev_new.tsv"
    if [ -s "$WORK/bev_new.tsv" ]; then
      cut -f2 "$WORK/bev_new.tsv" >> "$seen"
      build_inode_map "$WORK/bev_map.tsv"; echo "0	" >> "$WORK/bev_map.tsv"
      awk -F'\t' -v attr="$WORK/bev_attr.txt.tmp" 'FILENAME==ARGV[1]{m[$1]=$2;next} { pid=($3=="0"?"":m[$3]); e=""; if (pid!="") { cmd="readlink /proc/" pid "/exe 2>/dev/null"; cmd | getline e; close(cmd) }
                  print $1 "\t" $4; if (e!="") print $4 " " e > attr }' "$WORK/bev_map.tsv" "$WORK/bev_new.tsv" >> "$ev_proc"
      cat "$WORK/bev_attr.txt.tmp" >> "$WORK/bev_attr.txt" 2>/dev/null; : > "$WORK/bev_attr.txt.tmp"
    fi
    sleep 1
  done
  [ -n "$tdpid" ] && { kill "$tdpid" >/dev/null 2>&1; wait "$tdpid" 2>/dev/null; }
  if [ "$audit_on" = 1 ]; then
    auditctl -d always,exit -F arch=b64 -S connect -k boxaudit_conn >/dev/null 2>&1
    auditctl -d always,exit -F arch=b32 -S connect -k boxaudit_conn >/dev/null 2>&1
    printf '  auditd rule removed\n'
  fi
  CLEANUP_CMDS=""

  # parse auditd: join SYSCALL(exe) + SOCKADDR(saddr) by event serial
  if [ "$audit_on" = 1 ] && [ -r "$alog" ]; then
    tail -c +"$((aoff+1))" "$alog" 2>/dev/null | awk '
      function hx(s,  i,n){ n=0; s=toupper(s); for(i=1;i<=length(s);i++) n=n*16+index("0123456789ABCDEF",substr(s,i,1))-1; return n }
      { if (match($0, /msg=audit\([0-9.]+:[0-9]+\)/)) { id=substr($0, RSTART+10, RLENGTH-11); split(id, a, ":"); ts[a[2]]=int(a[1]); ser=a[2] } else next }
      /type=SYSCALL/ && /key="boxaudit_conn"/ { if (match($0, / exe=[^ ]+/)) { e=substr($0, RSTART+5, RLENGTH-5); gsub(/"/,"",e); exe[ser]=e } ok[ser]=1 }
      /type=SOCKADDR/ { if (match($0, /saddr=[0-9A-Fa-f]+/)) sa[ser]=substr($0, RSTART+6, RLENGTH-6) }
      END { for (s in ok) { h=sa[s]; if (h=="") continue; fam=toupper(substr(h,1,4))
              if (fam=="0200") { port=hx(substr(h,5,4)); ip=hx(substr(h,9,2)) "." hx(substr(h,11,2)) "." hx(substr(h,13,2)) "." hx(substr(h,15,2)) }
              else if (fam=="0A00") { port=hx(substr(h,5,4)); ip=tolower(substr(h,17,32)) }
              else continue
              if (ip ~ /^127\./ || ip=="00000000000000000000000000000001" || port==0) continue
              print ts[s] "\t" ip ":" port " " exe[s] } }' > "$ev_aud"
  fi

  # parse tcpdump
  if [ -s "$WORK/tcpdump.txt" ]; then
    awk -v lips=" $localips " '
      { for (i=2;i<=NF;i++) if ($i=="IP" || $i=="IP6") break; if (i>NF) next
        src=$(i+1); dst=$(i+3); sub(/:$/,"",dst)
        ns=split(src,s,"."); sport=s[ns]; sip=substr(src,1,length(src)-length(sport)-1)
        nd=split(dst,d,"."); dport=d[nd]; dip=substr(dst,1,length(dst)-length(dport)-1)
        if (index(lips, " " sip " ")==0) next
        t=int($1)
        if (dport=="53") { for (j=i+4;j<=NF;j++) if ($j ~ /\?$/) { q=$(j+1); sub(/\.$/,"",q); print "DNS\t" t "\t" tolower(q); break } }
        else print "TCP\t" t "\t" dip ":" dport }' "$WORK/tcpdump.txt" > "$WORK/td_parsed.tsv"
    awk -F'\t' '$1=="TCP"{print $2 "\t" $3}' "$WORK/td_parsed.tsv" > "$ev_tcp"
    awk -F'\t' '$1=="DNS"{print $2 "\t" $3}' "$WORK/td_parsed.tsv" > "$ev_dns"
  fi

  {
    [ -s "$ev_aud" ]  && analyze_events "$ev_aud" auditd
    [ -s "$ev_tcp" ]  && analyze_events "$ev_tcp" tcpdump
    [ -s "$ev_proc" ] && analyze_events "$ev_proc" proc-poll
    [ -s "$ev_dns" ]  && analyze_events "$ev_dns" dns
  } | sort -t"$TAB" -k2,2nr > "$WORK/beacon_stats.tsv"
  { printf 'source\tcount\tmean_interval_s\tstddev_s\tcv\tdestination [binary]\n'; cat "$WORK/beacon_stats.tsv"; } \
    | awk -F'\t' '{ printf "%-10s %-6s %-16s %-9s %-6s %s\n", $1, $2, $3, $4, $5, $6 }' \
    | logcmd "destinations seen (cv = stddev/mean: near 0 = clockwork-regular = beacon)"

  while IFS="$TAB" read -r src cnt mean sd cv key; do
    [ "$cv" = "-" ] && continue
    lvl=""
    if [ "$cnt" -ge 4 ] && awk -v c="$cv" -v m="$mean" 'BEGIN{exit !(c<0.25 && m>=2)}'; then lvl=HIGH
    elif [ "$cnt" -ge 3 ] && awk -v c="$cv" -v m="$mean" 'BEGIN{exit !(c<0.5 && m>=2)}'; then lvl=MED; fi
    [ -z "$lvl" ] && continue
    line="$src: PERIODIC traffic to $key - $cnt times, every ~${mean}s (stddev ${sd}s, cv $cv)"
    case "$src" in dns) line="$line - DNS beacon / tunnel candidate" ;; *) line="$line - C2 beacon candidate (block it at pfSense, find the process)" ;; esac
    if [ "$lvl" = HIGH ]; then hi "$line"; else med "$line"; fi
  done < "$WORK/beacon_stats.tsv"

  # binaries that made outbound connections at all
  { cut -f2 "$ev_aud"; cat "$WORK/bev_attr.txt"; } 2>/dev/null | sort -u | logcmd "destination -> binary attribution"
  { cut -f2 "$ev_aud"; cat "$WORK/bev_attr.txt"; } 2>/dev/null | awk '{ $1=""; sub(/^ /,""); print }' | sort | uniq -c | sort -rn | logcmd "binaries that connected out (count)"
  { cut -f2 "$ev_aud"; cat "$WORK/bev_attr.txt"; } 2>/dev/null | awk '{ $1=""; sub(/^ /,""); print }' | sort -u | while IFS= read -r e; do
    [ "$e" = "?" ] && continue
    eb=${e##*/}
    if is_interp "$eb"; then hi "shell/interpreter $e made outbound connections during capture"
    elif [[ $e =~ $TEMP_RE ]] || [[ $e =~ ^/(home|root|var/www)/ ]]; then hi "binary in temp/home/web dir made outbound connections: $e"
    elif [ "$PKG" != none ] && [ -n "$(printf '%s\n' "$e" | unowned_filter)" ]; then
      case "$e" in /opt/*|/usr/local/*|/snap/*) med "non-package binary made outbound connections (verify): $e" ;;
                   *) hi "binary not from any package made outbound connections: $e" ;; esac
    fi
  done
  # DNS tunnelling heuristics
  if [ -s "$ev_dns" ]; then
    cut -f2 "$ev_dns" | sort | uniq -c | sort -rn | head -40 | logcmd "top DNS queries"
    cut -f2 "$ev_dns" | sort -u | awk -F. '{ m=0; for(i=1;i<=NF;i++) if (length($i)>m) m=length($i); if (m>=40 || length($0)>=100) print }' | head -50 | while IFS= read -r line; do
      med "very long DNS label (DNS tunnelling / exfil?): $line"
    done
    cut -f2 "$ev_dns" | awk -F. 'NF>=2 {print $(NF-1) "." $NF}' | sort | uniq -c | awk '$1>=50 {print}' | while read -r cnt line; do
      med "heavy DNS volume to one domain during capture: $line ($cnt queries)"
    done
  fi
  [ "$audit_on" = 0 ] && [ -z "$tdpid" ] && med "only /proc polling was available: beacons are still caught via TIME_WAIT sockets, but the responsible binary is often unknown for sub-second connections. With auditd or tcpdump installed you get exact attribution; also check pfSense logs for the flagged destinations."
  cp "$WORK/beacon_stats.tsv" "$OUT/beacon_stats.tsv" 2>/dev/null
}

# =============================================================================
#  BASELINE / DIFF
# =============================================================================
snapshot() {   # $1 = dir
  local d="$1" f h
  mkdir -p "$d" || { echo "cannot create $d" >&2; return 1; }
  printf '  hashing binaries and libraries...\n'
  hash_tree > "$d/bin_lib.sha256"
  printf '  hashing configs and persistence locations...\n'
  hash_persist > "$d/persist.sha256"
  build_proc_table; build_sockets
  awk -F'\t' '$2=="LISTEN" || $2=="UNCONN" { e=$10; sub(/ \(deleted\)$/,"",e); print $1 " " $3 ":" $4 " " e }' "$SOCKS" | sort -u > "$d/listeners.txt"
  awk -F'\t' '$2=="ESTAB" && $5!~/^127\./ && $5!="::1" { e=$10; print $5 ":" $6 " " e }' "$SOCKS" | sort -u > "$d/remotes.txt"
  # (drop short-lived utilities - they are mostly this script's own pipelines)
  cut -f4 "$PROCS" | grep '^/' | sed 's/ (deleted)$//' \
    | grep -vE '/(head|tail|sed|awk|mawk|gawk|sort|tr|cat|cut|grep|readlink|ls|find|xargs|sha256sum|md5sum|stat|od|wc|comm|uniq|tee|date|sleep|ps|getcap|lsattr|tar|gzip|sync|timeout)$' \
    | sort -u > "$d/proc_exes.txt"
  cp /etc/passwd "$d/passwd.txt" 2>/dev/null
  cp /etc/group "$d/group.txt" 2>/dev/null
  if [ -r /etc/shadow ]; then
    awk -F: '{print $1 ":" $2}' /etc/shadow | while IFS=: read -r u h; do printf '%s %s\n' "$u" "$(printf '%s' "$h" | sha256sum | cut -c1-16)"; done | sort > "$d/shadow_fingerprints.txt"
  fi
  for f in $(local_mounts); do find "$f" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null; done | sort -u > "$d/suid.txt"
  have getcap && for f in /usr /bin /sbin /opt /home /root /tmp; do [ -d "$f" ] && [ ! -L "$f" ] && getcap -r "$f" 2>/dev/null; done | sort -u > "$d/caps.txt"
  awk '{print $1}' /proc/modules 2>/dev/null | sort > "$d/modules.txt"
  have systemctl && systemctl list-unit-files --state=enabled --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sort > "$d/enabled_units.txt"
  have systemctl && systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /\.timer$/) print $i}' | sort -u > "$d/timers.txt"
  for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | sed "s|^|$f: |"
  done | sort -u > "$d/cron_lines.txt"
  for h in $(homes); do
    for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
      [ -f "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" | awk -v f="$f" '{ for(i=1;i<=NF;i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { print f ": " $i " " $(i+1); break } }'
    done
  done | sort -u > "$d/ssh_keys.txt"
  { have iptables-save && iptables-save 2>/dev/null; } | grep -vE '^(#|:)' | sed 's/\[[0-9]*:[0-9]*\]//' | sort -u > "$d/iptables.txt"
  { echo "box_audit baseline v$VERSION"; echo "host=$HOST os=$OS_ID $OS_VER kernel=$KREL"; echo "taken=$(date)"; } > "$d/meta.txt"
  ( cd "$d" && sha256sum ./*.txt ./*.sha256 2>/dev/null | grep -v MANIFEST > MANIFEST.sha256 )
}

mode_baseline() {
  echo "Taking baseline snapshot into $BASELINE_DIR ..."
  snapshot "$BASELINE_DIR" || exit 1
  echo
  echo "${G}baseline saved:${N} $BASELINE_DIR"
  echo "manifest sha256 (write it down / keep a copy OFF the box): $(sha256sum "$BASELINE_DIR/MANIFEST.sha256" | cut -c1-64)"
  echo "later run:  bash $0 --diff $BASELINE_DIR"
}

set_diff() {   # $1 name  $2 old  $3 new  $4 level-for-added  $5 level-for-removed
  [ -f "$2" ] || return
  [ -f "$3" ] || return
  sort -u "$2" > "$WORK/sd_old"; sort -u "$3" > "$WORK/sd_new"
  comm -13 "$WORK/sd_old" "$WORK/sd_new" | while IFS= read -r l; do _emit "$4" "$1 ADDED since baseline: $l"; done
  comm -23 "$WORK/sd_old" "$WORK/sd_new" | while IFS= read -r l; do _emit "$5" "$1 REMOVED since baseline: $l"; done
}

mod_diff() {
  section "Changes since baseline $DIFF_DIR" 16_baseline_diff.txt
  local d="$DIFF_DIR" n="$WORK/snap_now" kind path lvl
  if [ ! -d "$d" ] || [ ! -f "$d/MANIFEST.sha256" ]; then med "baseline dir $d missing or incomplete"; return; fi
  if ! ( cd "$d" && sha256sum -c MANIFEST.sha256 >/dev/null 2>&1 ); then
    hi "BASELINE ITSELF WAS MODIFIED ($d) - its manifest no longer verifies. Use your off-box copy."
  fi
  log "baseline: $(tr '\n' ' ' < "$d/meta.txt")"
  printf '  taking current snapshot for comparison...\n'
  snapshot "$n" >/dev/null 2>&1
  for f in bin_lib.sha256 persist.sha256; do
    awk 'FILENAME==ARGV[1] { h[substr($0,67)]=$1; next }
         { p=substr($0,67); seen[p]=1; if (!(p in h)) print "NEW\t" p; else if (h[p]!=$1) print "CHANGED\t" p }
         END { for (p in h) if (!(p in seen)) print "DELETED\t" p }' "$d/$f" "$n/$f"
  done | sort > "$WORK/diff_files.tsv"
  while IFS="$TAB" read -r kind path; do
    lvl=MED
    if [[ $path =~ $CRIT_RE ]]; then lvl=HIGH; fi
    case "$path" in
      /etc/pam.d/*|/etc/sudoers*|/etc/passwd|/etc/shadow|/etc/group|/etc/ld.so.preload|/etc/ssh/*|*/.ssh/*|/etc/cron*|/var/spool/cron/*|/etc/systemd/*|/etc/profile*|/etc/bash.bashrc|/etc/rc.local|/etc/update-motd.d/*|/var/www/*|/srv/*) lvl=HIGH ;;
      /etc/mtab|/etc/resolv.conf|*/.bash_history|*/.viminfo|*/.lesshst|*/.zsh_history|*/.python_history|*/.wget-hsts|/var/lib/dpkg/info/*) lvl=INFO ;;
    esac
    [ "$kind" = DELETED ] && [ "$lvl" = HIGH ] && lvl=MED
    _emit "$lvl" "file $kind since baseline: $path $(fmeta "$path")"
  done < "$WORK/diff_files.tsv"
  set_diff "listener"           "$d/listeners.txt"      "$n/listeners.txt"      HIGH INFO
  set_diff "established remote" "$d/remotes.txt"        "$n/remotes.txt"        MED  INFO
  set_diff "running binary"     "$d/proc_exes.txt"      "$n/proc_exes.txt"      MED  INFO
  set_diff "passwd entry"       "$d/passwd.txt"         "$n/passwd.txt"         HIGH MED
  set_diff "group entry"        "$d/group.txt"          "$n/group.txt"          HIGH MED
  set_diff "password hash"      "$d/shadow_fingerprints.txt" "$n/shadow_fingerprints.txt" MED INFO
  set_diff "SUID/SGID file"     "$d/suid.txt"           "$n/suid.txt"           HIGH INFO
  set_diff "file capability"    "$d/caps.txt"           "$n/caps.txt"           HIGH INFO
  set_diff "kernel module"      "$d/modules.txt"        "$n/modules.txt"        HIGH INFO
  set_diff "enabled unit"       "$d/enabled_units.txt"  "$n/enabled_units.txt"  HIGH MED
  set_diff "timer"              "$d/timers.txt"         "$n/timers.txt"         HIGH INFO
  set_diff "cron line"          "$d/cron_lines.txt"     "$n/cron_lines.txt"     HIGH MED
  set_diff "SSH key"            "$d/ssh_keys.txt"       "$n/ssh_keys.txt"       HIGH MED
  set_diff "iptables rule"      "$d/iptables.txt"       "$n/iptables.txt"       MED  MED
}

# =============================================================================
#  REPORT
# =============================================================================
FINISHED=0
finish() {
  [ "$FINISHED" = 1 ] && return
  FINISHED=1
  local nh nm ni
  nh=$(awk -F'\t' '$1=="HIGH"' "$FFILE" | wc -l)
  nm=$(awk -F'\t' '$1=="MED"' "$FFILE" | wc -l)
  ni=$(awk -F'\t' '$1=="INFO"' "$FFILE" | wc -l)
  {
    echo "box_audit.sh v$VERSION   host=$HOST   os=$OS_ID $OS_VER   kernel=$KREL   pkg=$PKG"
    echo "started:  $START"
    echo "finished: $(date)"
    echo "HIGH=$nh  MED=$nm  INFO=$ni"
    echo
    for l in HIGH MED INFO; do
      echo "==================================== $l ===================================="
      awk -F'\t' -v l="$l" '$1==l { printf "[%s] %s\n", $2, $3 }' "$FFILE"
      echo
    done
  } > "$OUT/FINDINGS.txt"
  echo
  echo "=============================================================="
  printf ' %sHIGH: %s%s   %sMED: %s%s   INFO: %s\n' "$R" "$nh" "$N" "$Y" "$nm" "$N" "$ni"
  echo " full report : $OUT/FINDINGS.txt"
  echo " raw details : $OUT/*.txt"
  if tar czf "$OUT.tar.gz" -C "$(dirname "$OUT")" --exclude='.work' "$(basename "$OUT")" 2>/dev/null; then
    echo " archive     : $OUT.tar.gz   (scp it off the box)"
  fi
  echo "=============================================================="
}

# =============================================================================
#  MAIN
# =============================================================================
echo "${B}box_audit.sh v$VERSION${N}  host=$HOST  os=$OS_ID $OS_VER  kernel=$KREL  pkg-db=$PKG"

case "$MODE" in
  genhash)  mode_genhash; rm -rf "$OUT" 2>/dev/null; exit 0 ;;
  baseline) mode_baseline; rm -rf "$OUT" 2>/dev/null; exit 0 ;;
esac

echo "report dir: $OUT"
want tools   && mod_tools
want pkg     && mod_pkg
[ "$ONLINE" = 1 ] && mod_online
[ -n "$HASHLISTS" ] && mod_hashlist
want unowned && mod_unowned
want perms   && mod_perms
want users   && mod_users
want pam     && mod_pam
want cron    && mod_cron
want systemd && mod_systemd
want shell   && mod_shell
want misc    && mod_misc
want kernel  && mod_kernel
want proc    && mod_proc
want net     && mod_net
want web     && mod_web
[ -n "$DIFF_DIR" ] && mod_diff
[ "$BEACON_SECS" -gt 0 ] && mod_beacon
cleanup
finish
