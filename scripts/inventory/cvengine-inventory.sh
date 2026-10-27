#!/bin/sh
# cvengine-inventory.sh: tell cvENGINE what this machine is (Linux and macOS).
#
# Collects the operating system and version, the kernel, installed packages and their versions, listening sockets, running services,
# containers and a few security settings, and POSTs them as "inventory v1" JSON over HTTPS to cvENGINE. cvENGINE scans from outside and
# cannot see any of this: with it, kernel and local-only CVEs become decidable and package versions stop being guesses.
#
# Read-only: it runs only commands that list things, never installs, changes or deletes anything, and writes only a temporary file
# (removed on exit). No dependencies beyond a POSIX sh and, to send, curl. It never reads or sends passwords, keys, tokens, shell
# history, environment variables or the contents of files other than the OS metadata named below.
#
# Files read:  /etc/os-release, /proc/stat (boot time), /etc/machine-id (only as a hash, see below), modification times of the package
#              database, /etc/apt/apt.conf.d/20auto-upgrades (one setting), /Applications/*/Contents/Info.plist (macOS versions).
# The machine id is sent only as sha256("cvengine-inventory-v1:" + id): systemd's machine-id(5) says the raw id is confidential.
#
# Usage:   cvengine-inventory.sh --server https://cvengine.example.test --project my-project [options]
#          CVENGINE_TOKEN or --token-file supplies the bearer token. It is never a command-line argument: arguments are visible to every
#          user in `ps` and are saved in shell history, an environment variable or a root-only file are not.
# Options:
#   --server URL        cvENGINE address, https only (or CVENGINE_URL)
#   --project SLUG      project to report to (or CVENGINE_PROJECT)
#   --token-file PATH   file holding the token (or CVENGINE_TOKEN_FILE); otherwise the CVENGINE_TOKEN environment variable
#   --ca-file PATH      PEM file of the certificate authority that signed the server (the installer's secrets/certs/ca.crt)
#   --insecure          DO NOT VERIFY THE SERVER'S CERTIFICATE. Anyone on the path can read the token and the report. Testing only.
#   --dry-run           print the report that would be sent (to stdout) and send nothing; needs no token
#   --macs              include network interface MAC addresses (off by default)
#   --timeout SECONDS   per request, default 30
#   --retries N         attempts after the first when the network or server fails, default 3, with growing delays
#   --install-cron      print (do not apply) a cron line and a systemd timer for running this daily, then exit
#   --version, --help
# Exit codes: 0 sent (or dry run), 1 bad usage or configuration, 2 nothing could be collected, 3 could not reach the server or its
#             certificate is not trusted, 4 the server refused the report (read its message), 5 the server kept failing.

SCRIPT_NAME=cvengine-inventory.sh
SCRIPT_VERSION=1.0.0
ROOT=${CVENGINE_ROOT:-}   # a test hook: a directory standing in for / when reading files
T=$(printf '\t')

say() { printf '%s\n' "$*" >&2; }
die() { code=$1; shift; say "cvengine-inventory: $*"; exit "$code"; }
have() { command -v "$1" >/dev/null 2>&1; }

SERVER=${CVENGINE_URL:-}
PROJECT=${CVENGINE_PROJECT:-}
TOKEN_FILE=${CVENGINE_TOKEN_FILE:-}
CA_FILE=
INSECURE=0
DRY_RUN=0
WITH_MACS=0
TIMEOUT=30
RETRIES=3
INSTALL_CRON=0

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; }

while [ $# -gt 0 ]; do
	case $1 in
		--server) [ $# -ge 2 ] || die 1 "$1 needs a value"; SERVER=$2; shift 2 ;;
		--project) [ $# -ge 2 ] || die 1 "$1 needs a value"; PROJECT=$2; shift 2 ;;
		--token-file) [ $# -ge 2 ] || die 1 "$1 needs a value"; TOKEN_FILE=$2; shift 2 ;;
		--ca-file) [ $# -ge 2 ] || die 1 "$1 needs a value"; CA_FILE=$2; shift 2 ;;
		--timeout) [ $# -ge 2 ] || die 1 "$1 needs a value"; TIMEOUT=$2; shift 2 ;;
		--retries) [ $# -ge 2 ] || die 1 "$1 needs a value"; RETRIES=$2; shift 2 ;;
		--insecure) INSECURE=1; shift ;;
		--dry-run) DRY_RUN=1; shift ;;
		--macs) WITH_MACS=1; shift ;;
		--install-cron) INSTALL_CRON=1; shift ;;
		--version) printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
		-h|--help) usage; exit 0 ;;
		--token|--token=*) die 1 "the token is never a command-line argument (it would show in ps and shell history): use CVENGINE_TOKEN or --token-file" ;;
		*) die 1 "unknown option: $1 (try --help)" ;;
	esac
done

case $TIMEOUT in ''|*[!0-9]*) die 1 "--timeout must be a number of seconds" ;; esac
case $RETRIES in ''|*[!0-9]*) die 1 "--retries must be a number" ;; esac
if [ "$TIMEOUT" -lt 1 ] || [ "$TIMEOUT" -gt 300 ]; then die 1 "--timeout must be 1 to 300"; fi
[ "$RETRIES" -le 10 ] || die 1 "--retries must be 0 to 10"

# --- printing the scheduling snippets (nothing is installed) ---------------------------------------------------------------

print_schedule() {
	url=${SERVER:-https://cvengine.example.test}
	proj=${PROJECT:-my-project}
	# a minute derived from the host name, so a fleet does not report in the same second
	minute=$(( $(uname -n 2>/dev/null | cksum | cut -d' ' -f1) % 60 ))
	cat <<EOF
# Nothing has been installed. Copy what you want.
# 1. Store the token where only root can read it:
#      install -m 600 /dev/null /etc/cvengine-inventory.token   # then put the token in it
#      install -m 755 $SCRIPT_NAME /usr/local/bin/$SCRIPT_NAME
#
# 2a. cron, daily (/etc/cron.d/cvengine-inventory):
$minute 3 * * * root /usr/local/bin/$SCRIPT_NAME --server $url --project $proj --token-file /etc/cvengine-inventory.token

# 2b. or a systemd timer. /etc/systemd/system/cvengine-inventory.service:
[Unit]
Description=Report this host's inventory to cvENGINE
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/$SCRIPT_NAME --server $url --project $proj --token-file /etc/cvengine-inventory.token
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true

# /etc/systemd/system/cvengine-inventory.timer, then: systemctl enable --now cvengine-inventory.timer
[Unit]
Description=Daily cvENGINE inventory report
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF
}

# the address and project go into the text this prints (a cron line a person pastes into a root crontab), so they are checked first
check_server() {
	case $SERVER in https://*) ;; '') die 1 "--server is required (or set CVENGINE_URL)" ;; *) die 1 "--server must be an https:// address: the token never travels in the clear" ;; esac
	# case first: grep looks at one line at a time, so a value with a second line would pass it
	case $SERVER in *[!]A-Za-z0-9._:/~[-]*) die 1 "--server is not a plain https address" ;; esac
	printf '%s' "$SERVER" | grep -Eq '^https://[]A-Za-z0-9._:[-]+(/[A-Za-z0-9._~/-]*)?$' || die 1 "--server is not a plain https address"
}
check_project() {
	case $PROJECT in ''|*[!A-Za-z0-9_-]*) die 1 "--project (the project slug) is required and is letters, digits, - and _" ;; esac
}

if [ "$INSTALL_CRON" = 1 ]; then
	[ -z "$SERVER" ] || check_server
	[ -z "$PROJECT" ] || check_project
	print_schedule
	exit 0
fi

# --- checks that need no collecting ----------------------------------------------------------------------------------------

if [ "$DRY_RUN" = 0 ]; then
	check_server
	check_project
	have curl || die 1 "curl is needed to send the report (use --dry-run to see it without)"
	if [ -n "$CA_FILE" ]; then [ -r "$CA_FILE" ] || die 1 "cannot read --ca-file $CA_FILE"; fi
	TOKEN=${CVENGINE_TOKEN:-}
	if [ -n "$TOKEN_FILE" ]; then
		[ -r "$TOKEN_FILE" ] || die 1 "cannot read the token file $TOKEN_FILE"
		mode=$(stat -c %a "$TOKEN_FILE" 2>/dev/null || stat -f %Lp "$TOKEN_FILE" 2>/dev/null)
		case $mode in *[1-7][0-7]|*[1-7]) say "cvengine-inventory: warning: $TOKEN_FILE is readable by other users (mode $mode): chmod 600 it" ;; esac
		TOKEN=$(head -n 1 "$TOKEN_FILE" | tr -d ' \r\n')
	fi
	# only these characters: the token goes into curl's configuration, where a newline would add a setting of its own
	case $TOKEN in *[!A-Za-z0-9_-]*) die 1 "no usable token: it holds characters a cvENGINE token never has" ;; esac
	printf '%s' "$TOKEN" | grep -Eq '^cve_[A-Za-z0-9_-]{20,200}$' || die 1 "no usable token: set CVENGINE_TOKEN or --token-file (a cvENGINE inventory token, cve_...)"
	if [ "$INSECURE" = 1 ]; then
		say "cvengine-inventory: *** --insecure: the server's certificate is NOT being checked. Anyone on the network path can read the token and this report. ***"
	fi
fi

# --- helpers ---------------------------------------------------------------------------------------------------------------

WORK=$(mktemp -d 2>/dev/null) || { WORK=${TMPDIR:-/tmp}/cvengine-inventory.$$; (umask 077; mkdir "$WORK") || die 1 "cannot create a temporary directory"; }
trap 'rm -rf "$WORK"' EXIT INT TERM HUP

# one line of text made safe for JSON: no control characters, no invalid UTF-8 where iconv can tell, backslash and quote escaped
clean() { tr -d '\000-\010\013-\037\177' | { if have iconv; then iconv -f UTF-8 -t UTF-8 -c 2>/dev/null; else tr -cd '\11\12\40-\176'; fi; }; }
esc() { clean | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
jstr() { printf '"%s"' "$(printf '%s' "$1" | tr -d '\t\n\r' | esc)"; }
# "key":"value" when the value is not empty, else nothing (and the caller adds the comma)
kv() { [ -n "$2" ] && printf '"%s":%s' "$1" "$(jstr "$2")"; }
# a timeout for commands that might hang (a stuck docker daemon), when the system has one
run_t() { secs=$1; shift; if have timeout; then timeout "$secs" "$@"; else "$@"; fi; }
epoch_iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; }
mtime_of() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null; }
hash_stdin() {
	if have sha256sum; then sha256sum | cut -d' ' -f1
	elif have shasum; then shasum -a 256 | cut -d' ' -f1
	elif have openssl; then openssl dgst -sha256 | sed 's/^.*= //'
	fi
}
# a list of lines on stdin as a JSON array of strings
json_strings() { esc | awk 'NF { printf "%s\"%s\"", sep, $0; sep = "," }'; }

os_get() { [ -r "$OSR" ] && sed -n "s/^$1=//p" "$OSR" | head -n 1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//"; }

# --- collecting ------------------------------------------------------------------------------------------------------------

UNAME_S=$(uname -s 2>/dev/null)
case $UNAME_S in
	Linux) FAMILY=linux ;;
	Darwin) FAMILY=macos ;;
	*) die 2 "this script handles Linux and macOS (this is $UNAME_S); use cvengine-inventory.ps1 on Windows" ;;
esac
KERNEL=$(uname -r 2>/dev/null)
ARCH=$(uname -m 2>/dev/null)
HOSTNAME_SHORT=$( { hostname 2>/dev/null || uname -n 2>/dev/null; } | cut -d. -f1)
FQDN=$(run_t 5 hostname -f 2>/dev/null)  # asks the resolver, which can be slow on a machine with no DNS: not for more than a few seconds
case $FQDN in *.*) ;; *) FQDN= ;; esac
[ -n "$HOSTNAME_SHORT" ] || [ -n "$FQDN" ] || die 2 "cannot tell this machine's host name"

collect_addresses() {
	addrs=
	have ip && addrs=$(ip -o addr show 2>/dev/null | awk '$3 ~ /^inet/ { split($4, a, "/"); print a[1] }')
	[ -n "$addrs" ] || addrs=$(hostname -I 2>/dev/null | tr ' ' '\n')
	[ -n "$addrs" ] || { have ifconfig && addrs=$(ifconfig -a 2>/dev/null | awk '$1 == "inet" || $1 == "inet6" { print $2 }'); }
	printf '%s\n' "$addrs" | sed 's/%.*//' | grep -Ev '^(127\.|::1$|fe80:|$)' | sort -u | json_strings
}

collect_macs() {
	if have ip; then ip -o link show 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "link/ether") print $(i + 1) }'
	elif have ifconfig; then ifconfig -a 2>/dev/null | awk '$1 == "ether" { print $2 }'
	fi | sort -u | json_strings
}

machine_id_hash() {
	mid=
	if [ "$FAMILY" = macos ]; then
		mid=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | sed -n 's/.*"IOPlatformUUID" = "\(.*\)".*/\1/p')
	else
		for f in "$ROOT/etc/machine-id" "$ROOT/var/lib/dbus/machine-id"; do
			[ -r "$f" ] && mid=$(head -n 1 "$f" | tr -d ' \r\n') && [ -n "$mid" ] && break
		done
	fi
	[ -n "$mid" ] && printf 'cvengine-inventory-v1:%s' "$mid" | hash_stdin
}

# TSV on stdin (name, version, ecosystem, arch, source) to the JSON objects of the compact package list
packages_json() {
	clean | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | awk -F"$T" '
		$1 != "" && $2 != "" {
			printf "%s{\"n\":\"%s\",\"v\":\"%s\",\"e\":\"%s\"", sep, $1, $2, $3
			if ($4 != "") printf ",\"a\":\"%s\"", $4
			if ($5 != "" && $5 != $1) printf ",\"s\":\"%s\"", $5
			printf "}"; sep = ","
		}'
}

collect_packages() {
	{
		if have dpkg-query; then
			dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${db:Status-Abbrev}\n' 2>/dev/null |
				awk -F"$T" '$5 ~ /^.i/ { print $1 "\t" $2 "\tdpkg\t" $3 "\t" $4 }'
		fi
		if have rpm; then
			rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{INSTALLTIME}\n' 2>/dev/null |
				awk -F"$T" -v last="$WORK/rpm-last" '
					$1 == "gpg-pubkey" { next }
					{
						ver = ($2 == "(none)" || $2 == "" || $2 == "0") ? $3 : $2 ":" $3
						src = $5; if (src == "(none)") src = ""; else sub(/-[^-]*-[^-]*\.src\.rpm$/, "", src)
						print $1 "\t" ver "\trpm\t" $4 "\t" src
						if ($6 + 0 > m) m = $6 + 0
					}
					END { if (m) print m > last }'
		fi
		if have apk; then
			apk list -I 2>/dev/null | sed -n "s/^\\(.*\\)-\\([0-9][^-]*-r[0-9][0-9]*\\) \\([^ ]*\\) {\\([^}]*\\)}.*\$/\\1${T}\\2${T}apk${T}\\3${T}\\4/p"
		fi
		if have pacman; then pacman -Q 2>/dev/null | awk -v t="$T" 'NF >= 2 { print $1 t $2 t "pacman" }'; fi
		if have snap; then snap list 2>/dev/null | awk -v t="$T" 'NR > 1 && NF >= 2 { print $1 t $2 t "snap" }'; fi
		if have flatpak; then flatpak list --columns=application,version,arch 2>/dev/null | awk -F"$T" '$1 ~ /\./ && $2 != "" { print $1 "\t" $2 "\tflatpak\t" $3 }'; fi
		if have brew && [ "$(id -u)" != 0 ]; then brew list --versions 2>/dev/null | awk -v t="$T" 'NF >= 2 { print $1 t $NF t "brew" }'; fi
		if [ "$FAMILY" = macos ]; then
			for app in /Applications/*.app /Applications/*/*.app /System/Applications/*.app; do
				plist=$app/Contents/Info.plist
				[ -r "$plist" ] || continue
				ver=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist" 2>/dev/null)
				[ -n "$ver" ] && printf '%s\t%s\tmacapp\n' "$(basename "$app" .app)" "$ver"
			done
			if have pkgutil; then
				pkgutil --pkgs 2>/dev/null | grep -v '^com\.apple\.' | while read -r id; do
					ver=$(pkgutil --pkg-info "$id" 2>/dev/null | sed -n 's/^version: //p')
					[ -n "$ver" ] && printf '%s\t%s\tmacpkg\n' "$id" "$ver"
				done
			fi
		fi
	} | packages_json
}

# the time the newest package was installed or the package database last changed: when this machine last took an update
last_update() {
	stamp=
	if [ -r "$WORK/rpm-last" ]; then stamp=$(cat "$WORK/rpm-last")
	elif [ -r "$ROOT/var/lib/dpkg/status" ]; then stamp=$(mtime_of "$ROOT/var/lib/dpkg/status")
	elif [ -r "$ROOT/lib/apk/db/installed" ]; then stamp=$(mtime_of "$ROOT/lib/apk/db/installed")
	elif [ -r "$ROOT/var/lib/pacman/local" ]; then stamp=$(mtime_of "$ROOT/var/lib/pacman/local")
	fi
	[ -n "$stamp" ] && epoch_iso "$stamp"
}

collect_os() {
	OSR=$ROOT/etc/os-release
	[ -r "$OSR" ] || OSR=$ROOT/usr/lib/os-release
	if [ "$FAMILY" = macos ]; then
		name=$(sw_vers -productName 2>/dev/null)
		version=$(sw_vers -productVersion 2>/dev/null)
		build=$(sw_vers -buildVersion 2>/dev/null)
		pretty="$name $version"
		ident=macos; codename=; like=; cpe=
		boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p')
	else
		name=$(os_get NAME); version=$(os_get VERSION_ID); build=; pretty=$(os_get PRETTY_NAME)
		ident=$(os_get ID | tr '[:upper:]' '[:lower:]'); codename=$(os_get VERSION_CODENAME); like=$(os_get ID_LIKE); cpe=$(os_get CPE_NAME)
		[ -n "$name" ] || name=Linux
		boot=$(sed -n 's/^btime //p' "$ROOT/proc/stat" 2>/dev/null | head -n 1)
	fi
	printf '{"family":"%s"' "$FAMILY"
	for pair in "id=$ident" "name=$name" "version=$version" "build=$build" "codename=$codename" "pretty=$pretty" "kernel=$KERNEL" "arch=$ARCH" "cpe=$cpe"; do
		value=${pair#*=}
		[ -n "$value" ] && printf ',%s' "$(kv "${pair%%=*}" "$value")"
	done
	# shellcheck disable=SC2086  # ID_LIKE is a space separated list: splitting it is the point
	[ -n "$like" ] && printf ',"id_like":[%s]' "$( ( set -f; printf '%s\n' $like ) | tr '[:upper:]' '[:lower:]' | json_strings)"
	[ -n "$boot" ] && printf ',"last_boot":"%s"' "$(epoch_iso "$boot")"
	upd=$(last_update); [ -n "$upd" ] && printf ',"last_update":"%s"' "$upd"
	printf '}'
}

# listening sockets as {"p":"tcp","a":"*","n":22,"x":"sshd"}
collect_services() {
	if [ "$FAMILY" = macos ]; then
		have lsof && lsof -nP -iTCP -sTCP:LISTEN -iUDP -F cPn 2>/dev/null | awk '
			/^c/ { cmd = substr($0, 2) }
			/^P/ { proto = tolower(substr($0, 2)) }
			/^n/ { name = substr($0, 2); sub(/ .*/, "", name); print proto "\t" name "\t" cmd }'
	elif have ss; then
		ss -tulnp 2>/dev/null | awk -v t="$T" '
			($2 == "LISTEN" || $2 == "UNCONN") && ($1 == "tcp" || $1 == "udp") {
				proc = ""
				if (match($0, /\(\("[^"]*"/)) proc = substr($0, RSTART + 3, RLENGTH - 4)
				print $1 t $5 t proc
			}'
	elif have netstat; then
		netstat -tuln 2>/dev/null | awk -v t="$T" '$1 ~ /^(tcp|udp)/ && ($1 ~ /^udp/ || $NF == "LISTEN") { print $1 t $4 t "" }'
	fi | clean | awk -F"$T" '
		{
			proto = substr($1, 1, 3); local = $2
			i = length(local); while (i > 0 && substr(local, i, 1) != ":" && substr(local, i, 1) != ".") i--
			if (i == 0) next
			port = substr(local, i + 1); addr = substr(local, 1, i - 1)
			if (port !~ /^[0-9]+$/) next
			gsub(/^\[|\]$/, "", addr); sub(/%.*/, "", addr)
			if (addr == "" || addr == "0.0.0.0" || addr == "::" || addr == "*") addr = "*"
			gsub(/\\/, "", $3); gsub(/"/, "", $3)
			printf "%s{\"p\":\"%s\",\"a\":\"%s\",\"n\":%d", sep, proto, addr, port
			if ($3 != "") printf ",\"x\":\"%s\"", $3
			printf "}"; sep = ","
		}'
}

collect_runtime() {
	reboot=null
	if [ -e "$ROOT/var/run/reboot-required" ] || [ -e "$ROOT/run/reboot-required" ]; then reboot=true
	elif have dpkg-query; then reboot=false
	elif have needs-restarting; then needs-restarting -r >/dev/null 2>&1; case $? in 0) reboot=false ;; 1) reboot=true ;; esac
	fi
	kernels=
	if have dpkg-query; then
		kernels=$(dpkg-query -W -f='${Package}\t${db:Status-Abbrev}\n' 'linux-image-[0-9]*' 2>/dev/null | awk -F"$T" '$2 ~ /^.i/ { sub(/^linux-image-/, "", $1); print $1 }')
	elif have rpm; then
		kernels=$(rpm -q kernel-core kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | grep -v 'not installed')
	fi
	containers=$(for rt in docker podman; do
		have "$rt" && run_t 10 "$rt" ps --format '{{.Image}}' 2>/dev/null | sort -u | sed "s/^/$rt$T/"
	done | esc | awk -F"$T" 'NF >= 2 { printf "%s{\"rt\":\"%s\",\"image\":\"%s\"}", sep, $1, $2; sep = "," }')
	units=
	if [ -d "$ROOT/run/systemd/system" ] && have systemctl; then
		units=$(systemctl list-units --type=service --state=running --no-legend --plain --no-pager 2>/dev/null | awk '{ print $1 }')
	fi
	printf '{"reboot_required":%s,"kernels_installed":[%s],"containers":[%s],"units":[%s]}' "$reboot" \
		"$(printf '%s\n' "$kernels" | json_strings)" "$containers" "$(printf '%s\n' "$units" | json_strings)"
}

collect_security() {
	out=
	add() { [ -n "$2" ] && out="$out${out:+,}$(kv "$1" "$2")"; }
	if [ "$FAMILY" = macos ]; then
		add firewall "$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | sed -En 's/^.*is (enabled|disabled).*$/\1/p')"
		add sip "$(csrutil status 2>/dev/null | sed -En 's/^.*status: (enabled|disabled).*$/\1/p')"
		add gatekeeper "$(spctl --status 2>/dev/null | sed -En 's/^assessments (enabled|disabled)$/\1/p')"
		add disk_encryption "$(fdesetup status 2>/dev/null | sed -En 's/^FileVault is (On|Off).*$/FileVault \1/p')"
	else
		if have systemctl; then
			for unit in firewalld ufw nftables; do
				[ "$(systemctl is-active "$unit" 2>/dev/null)" = active ] && { add firewall "$unit active"; break; }
			done
		fi
		if have getenforce; then add selinux "$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')"
		elif [ -r "$ROOT/sys/fs/selinux/enforce" ]; then add selinux "$([ "$(cat "$ROOT/sys/fs/selinux/enforce")" = 1 ] && echo enforcing || echo permissive)"
		fi
		if [ -r "$ROOT/sys/module/apparmor/parameters/enabled" ]; then add apparmor "$([ "$(cat "$ROOT/sys/module/apparmor/parameters/enabled")" = Y ] && echo enabled || echo disabled)"; fi
		if [ -r "$ROOT/etc/apt/apt.conf.d/20auto-upgrades" ]; then
			add auto_updates "$(grep -Eq '^APT::Periodic::Unattended-Upgrade "1"' "$ROOT/etc/apt/apt.conf.d/20auto-upgrades" && echo unattended-upgrades enabled || echo unattended-upgrades off)"
		elif have systemctl && systemctl is-enabled dnf-automatic.timer dnf-automatic-install.timer >/dev/null 2>&1; then add auto_updates "dnf-automatic enabled"
		fi
		if have lsblk && lsblk -rno TYPE 2>/dev/null | grep -qx crypt; then add disk_encryption "LUKS volume present"; fi
		if have mokutil; then add secure_boot "$(mokutil --sb-state 2>/dev/null | sed -En 's/^SecureBoot (enabled|disabled).*$/\1/p')"; fi
	fi
	printf '{%s}' "$out"
}

# --- the report -------------------------------------------------------------------------------------------------------------

REPORT=$WORK/report.json
build_report() {
	mid=$(machine_id_hash)
	pkgs=$(collect_packages)  # first: the newest rpm install time it notes is the operating system's last update
	{
		printf '{"schema":"cvengine-inventory/1","script":{"name":"%s","version":"%s"},"collected_at":"%s",' "$SCRIPT_NAME" "$SCRIPT_VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		printf '"host":{'
		first=1
		for pair in "hostname=$HOSTNAME_SHORT" "fqdn=$FQDN" "machine_id=$mid"; do
			value=${pair#*=}
			[ -n "$value" ] || continue
			[ "$first" = 1 ] || printf ','
			first=0
			kv "${pair%%=*}" "$value"
		done
		[ "$first" = 1 ] || printf ','
		printf '"ips":[%s]' "$(collect_addresses)"
		[ "$WITH_MACS" = 1 ] && printf ',"macs":[%s]' "$(collect_macs)"
		printf '},"os":'
		collect_os
		printf ',"packages":[%s]' "$pkgs"
		printf ',"patches":[],"services":[%s]' "$(collect_services)"
		printf ',"runtime":'
		collect_runtime
		printf ',"security":'
		collect_security
		printf '}\n'
	} > "$REPORT"
}

build_report
[ -s "$REPORT" ] || die 2 "nothing could be collected"
SIZE=$(wc -c < "$REPORT" | tr -d ' ')
COUNT=$(grep -o '"n":"' "$REPORT" | wc -l | tr -d ' ')
say "cvengine-inventory: collected $COUNT package entries ($SIZE bytes) on $HOSTNAME_SHORT"

if [ "$DRY_RUN" = 1 ]; then
	cat "$REPORT"
	say "cvengine-inventory: dry run: nothing was sent. It would POST to ${SERVER:-<--server>}/api/v1/projects/${PROJECT:-<--project>}/inventory"
	exit 0
fi

# --- sending ---------------------------------------------------------------------------------------------------------------

URL=${SERVER%/}/api/v1/projects/$PROJECT/inventory
RESPONSE=$WORK/response.txt
attempt=0
while :; do
	# curl reads its configuration from stdin (-K -), so the token is never an argument: printf is a shell builtin, and nothing else
	# can see a pipe's contents. Redirects are not followed, so the token is only ever sent to the address given.
	if [ "$INSECURE" = 1 ]; then set -- --insecure; elif [ -n "$CA_FILE" ]; then set -- --cacert "$CA_FILE"; else set --; fi
	code=$(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl -sS -K - --proto '=https' --tlsv1.2 \
		--connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" "$@" -X POST -H 'Content-Type: application/json' \
		-A "$SCRIPT_NAME/$SCRIPT_VERSION" --data-binary "@$REPORT" -o "$RESPONSE" -w '%{http_code}' "$URL" 2>"$WORK/curl-error")
	rc=$?
	if [ "$rc" = 0 ]; then
		case $code in
			2??) say "cvengine-inventory: sent: $(tr -d '\n' < "$RESPONSE" | cut -c1-300)"; exit 0 ;;
			408|429|5??) why="the server answered $code" ;;
			*) say "cvengine-inventory: the server refused the report ($code): $(tr -d '\n' < "$RESPONSE" | cut -c1-300)"; exit 4 ;;
		esac
	else
		case $rc in
			60|51|58|59|77|83)
				say "cvengine-inventory: the server's certificate is not trusted ($(head -n 1 "$WORK/curl-error")). For a private certificate authority pass --ca-file (the installer's secrets/certs/ca.crt)."
				exit 3 ;;
		esac
		why="could not reach the server: $(head -n 1 "$WORK/curl-error")"
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -gt "$RETRIES" ]; then
		say "cvengine-inventory: giving up after $attempt attempts: $why"
		case $why in "the server answered"*) exit 5 ;; *) exit 3 ;; esac
	fi
	# 2, 4, 8, ... seconds plus up to three more, so a fleet that failed together does not retry together
	delay=$(( (1 << attempt) + $(date +%s) % 4 ))
	say "cvengine-inventory: $why; retrying in ${delay}s ($attempt of $RETRIES)"
	sleep "$delay"
done
