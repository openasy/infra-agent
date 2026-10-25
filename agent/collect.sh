# Read-only collection, run on the host as `sh -s` over SSH (ADR 0031). It writes nothing, starts nothing that
# keeps running, and reads no password hashes or private keys. Every tool is optional: what a host lacks is skipped.
# Commands that need root go through `p`, which uses the sudo rule from the agent's sudoers file when the host
# has it and runs the command unprivileged otherwise. Each of those commands has fixed arguments, so the sudoers
# file can list them exactly (agent/setup.ts); a test checks that both list the same commands.
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
s() { printf '\n@@%s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
# A line "@ok" after the output says the command ran: an empty answer is then "none", not "not readable".
p() { { sudo -n "$@" 2>/dev/null || "$@" 2>/dev/null; } && echo '@ok'; }

s meta
printf 'format 1\nuid %s\nuser %s\ntime %s\n' "$(id -u)" "$(id -un)" "$(date -u +%s)"
sudo -n true 2>/dev/null && echo 'sudo all' || echo 'sudo rules'

s hostname
hostname 2>/dev/null || cat /proc/sys/kernel/hostname
s machine-id
cat /etc/machine-id 2>/dev/null
s os-release
cat /etc/os-release 2>/dev/null
s uname
uname -srm
s uptime
cat /proc/uptime
s loadavg
cat /proc/loadavg
s cpuinfo
grep -E '^(processor|model name|physical id|core id|Model|Hardware)[[:space:]]*:' /proc/cpuinfo
s meminfo
grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
s virt
have systemd-detect-virt && systemd-detect-virt 2>/dev/null
s dmi
for f in sys_vendor product_name product_version bios_vendor bios_version bios_date board_vendor board_name; do
  [ -r "/sys/class/dmi/id/$f" ] && printf '%s=%s\n' "$f" "$(cat "/sys/class/dmi/id/$f")"
done
s dmi-serial
p cat /sys/class/dmi/id/product_serial

s lsblk
have lsblk && lsblk -J -b -o NAME,TYPE,SIZE,MODEL,ROTA,FSTYPE,MOUNTPOINT 2>/dev/null
s df
df -Pk 2>/dev/null
s mounts
cat /proc/mounts

s ip-addr
have ip && ip -j addr 2>/dev/null
s ip-route
have ip && ip -j route 2>/dev/null
s resolv
grep -E '^(nameserver|search)' /etc/resolv.conf 2>/dev/null

s listen
if have ss; then p ss -H -tulnp; elif have netstat; then p netstat -tulnp; fi

s ps
ps -eo pid=,ppid=,user:32=,pcpu=,rss=,etimes=,comm=,args= 2>/dev/null || ps -o pid,ppid,user,args

s services
have systemctl && systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null
s unit-files
have systemctl && systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null
s timers
have systemctl && systemctl list-timers --all --no-legend --no-pager 2>/dev/null
s cron
for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] && [ -r "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" | sed "s|^|$f\t|"; done
s cron-users
p ls -1 /var/spool/cron/crontabs

s passwd
cat /etc/passwd
s group
cat /etc/group
s password-status
p passwd -S -a
# No wildcards and nothing to escape in these arguments: a sudoers rule with `*` would also match extra arguments.
s sudoers
p cat /etc/sudoers
s sudoers.d
p find /etc/sudoers.d -maxdepth 1 -type f -print -exec cat {} \;
s authorized-keys
p find /root /home -maxdepth 3 -name authorized_keys -type f -print -exec ssh-keygen -lf {} \;
s sshd
p sshd -T

s modules
cut -d' ' -f1 /proc/modules 2>/dev/null
s sysctl
have sysctl && sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies \
  kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled fs.protected_symlinks \
  fs.protected_hardlinks fs.suid_dumpable 2>/dev/null
s nft
have nft && p nft list ruleset
s iptables
have iptables-save && p iptables-save

# Each package with the source package it was built from: Vulnerabilities matches advisories by source (ADR 0031).
s dpkg
have dpkg-query && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' 2>/dev/null
s rpm
have rpm && rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{EPOCH}\t%{SOURCERPM}\n' 2>/dev/null
s apk
[ -r /lib/apk/db/installed ] && grep -E '^[PVAo]:' /lib/apk/db/installed

# Containers only when switched on for this host: reading the Docker socket is equivalent to root (ADR 0031).
if [ "${OPENASY_CONTAINERS:-0}" = 1 ]; then
  for e in docker podman; do
    have "$e" || continue
    s "$e-version"
    "$e" version --format '{{.Server.Version}}' 2>/dev/null || "$e" --version
    s "$e-inspect"
    ids=$("$e" ps -aq 2>/dev/null)
    [ -n "$ids" ] && "$e" inspect $ids 2>/dev/null
  done
fi
s end
