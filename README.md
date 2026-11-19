# AUDITING SCRIPTS — box_audit.sh

A read-only Linux audit script for CCDC. It finds tampered binaries, persistence, backdoors and C2 beacons, then writes a report with findings ranked HIGH / MED / INFO.

## Why not one big hashlist of every default binary?

The original idea was a hashlist of every default Linux binary in every version. It can't work as stated, for three reasons:

- **Too many combinations.** Every distro, release, point update and architecture produces different hashes. Ubuntu 22.04.1 and 22.04.4 differ, and so do Debian and Ubuntu builds of the same version. The list would be huge, out of date within weeks, and you'd still be missing the exact build your competition image uses.
- **The box already has that list.** Every package installs per-file hashes (`/var/lib/dpkg/info/*.md5sums` on Debian/Ubuntu, the rpm database on RHEL/CentOS/Rocky). Checking against those covers every version automatically.
- **Hashes only cover binaries.** Most red-team persistence isn't a modified binary. It's a new cron line, a systemd unit, an SSH key, a PAM line, `ld.so.preload`, a webshell or a new user, none of which a binary hashlist would catch.

So the script checks in layers, from fastest to most paranoid:

| Layer | What it trusts | What it catches |
|---|---|---|
| 1. On-box package DB (default) | dpkg md5sums / `rpm -Va` | modified binaries and libraries, changed configs |
| 2. `--online` | the official mirror (GPG-signed) | the above, **plus** an attacker who re-hashed the package DB to hide a trojan |
| 3. `--hashlist` (your original idea, made workable) | a clean VM of the **same image** | everything, even with no package DB. Pass several lists to cover several patch levels |
| 4. `--baseline` / `--diff` | your own snapshot taken right after hardening | **anything** that changes during the competition |
| + persistence / process / network / kernel checks | reads `/proc` directly | cron, systemd, PAM, SSH keys, SUID, rootkits, bind/reverse shells, sniffers, beacons |

## Quick start (on the competition box, as root)

```bash
# 1. First minutes: full audit
sudo bash box_audit.sh

# 2. After you've cleaned and hardened: take a baseline, copy it OFF the box
sudo bash box_audit.sh --baseline /root/.bl
scp -r root@BOX:/root/.bl ./bl_BOXNAME

# 3. Every 15-30 min: what changed?
sudo bash box_audit.sh --quick --diff /root/.bl

# 4. Hunting C2 (the part you missed in the simulation): watch for 10-15 min
sudo bash box_audit.sh --only net,proc --beacon 900

# 5. If you suspect the package DB itself was tampered with (needs internet/mirror)
sudo bash box_audit.sh --online
```

The report goes to `/root/box_audit_<host>_<time>/`:
- `FINDINGS.txt` is the ranked list. Start with HIGH.
- `00_…` to `20_…` hold the raw evidence for each module (key fingerprints, unit file contents, socket tables, etc.).
- `processes.tsv`, `sockets.tsv` and `beacon_stats.tsv` are the raw tables.
- `…tar.gz` is everything, ready to `scp` off the box.

## Building reference hashlists (your idea, done right)

On a **clean** VM built from the same image as the competition box (same OS and version, ideally the same updates):

```bash
sudo bash box_audit.sh --gen-hashlist ubuntu2204_clean.hashlist
```

Then on the competition box:

```bash
sudo bash box_audit.sh --hashlist ubuntu2204_clean.hashlist
# several patch levels at once - a file passes if it matches ANY of them
sudo bash box_audit.sh --hashlist u2204_jan.hashlist --hashlist u2204_jun.hashlist
```

If the hashlist was made on a different OS/version, the script warns you. Build a few before the competition for the distros CCDC usually uses (Ubuntu, Debian, CentOS/Rocky, Fedora), and keep them on a USB drive or your laptop.

## How the beacon hunt works

Run `--beacon SECONDS`. Use 600-900, because beacons that sleep 60 seconds or more need many check-ins before a pattern shows.

1. **auditd** (if present and not locked): temporarily logs every `connect()` call with the exact binary. The rule is removed when the capture ends.
2. **tcpdump** (if present): records outbound SYNs and every DNS query.
3. **`/proc/net` polling** (always available): samples once a second. Closed connections stay in TIME_WAIT for about 60 seconds, so sub-second HTTP beacons are still seen.

For every destination, the script works out how often it was contacted and how regular the timing is (cv = stddev / mean). Traffic that repeats like clockwork is flagged as a beacon. With 30% jitter, cv stays around 0.2-0.3, which still gets flagged. The script also flags:
- shells or interpreters (bash, python, perl, nc, socat…) making outbound connections
- binaries in temp dirs or not owned by any package making outbound connections
- very long DNS labels, which can mean DNS tunnelling

Take each flagged destination to pfSense, block it and log it. Then find the process.

## What each module checks

- **tools**: core tools (`ls`, `ps`, `ss`…) that are scripts instead of ELF binaries; duplicate/shadowing copies in `/usr/local/bin`; writable PATH dirs; `/etc/ld.so.preload`
- **pkg**: hash-verifies every package file, changed security configs, recently re-hashed package DB entries with no install log, local `dpkg-divert` tricks, mode/owner/capability changes (rpm)
- **unowned**: files in bin dirs, PAM modules and libraries that no package owns; `/usr/local`; symlinks pointing into `/tmp` or home dirs
- **perms**: SUID/SGID (unowned or on GTFOBins binaries), dangerous file capabilities, world-writable system files, `chattr +i`/`+a` locks, ELF/scripts/hidden files in temp dirs, regular files in `/dev`, recently changed binaries
- **users**: UID 0 duplicates, empty passwords, system accounts with passwords or shells, sudo/docker/lxd group members, sudoers NOPASSWD / `!authenticate` / `env_keep LD_PRELOAD`, `sshd -T` red flags, every `authorized_keys`/`authorized_keys2` (including keys for system accounts like www-data and forced `command=` keys), `sshrc`, `~/.ssh/rc`
- **pam**: `sufficient pam_permit`, `pam_exec`, modules loaded from odd paths, unowned modules, LD_* injected through pam_env
- **cron**: all cron/anacron/at locations, user crontabs, unowned cron files, reverse-shell patterns
- **systemd**: unowned units (system and per-user), units running from temp dirs, enabled unowned units, drop-in overrides, **generators**, transient units, DefaultEnvironment LD_*
- **shell**: profile/bashrc/zshrc/etc. for every user; aliases or functions that hijack `sudo`/`ls`/`ps`; `PROMPT_COMMAND`/DEBUG traps; PATH containing `.` or `/tmp`; vimrc and inputrc tricks; rc.local, init.d, motd, XDG autostart
- **misc**: ld.so.conf paths, APT/yum hooks, udev `RUN+=`, modprobe `install` hooks, NetworkManager/ifupdown hooks, python `.pth`/sitecustomize, unowned Apache/nginx modules, `/etc/hosts` hijack of update domains, nsswitch
- **kernel**: taint flags, modules hidden from `lsmod` but present in `/sys/module`, modules loaded from outside `/lib/modules`, eBPF programs and pinned maps
- **proc**: binaries running from deleted files, memfd or temp dirs; fake kernel threads; argv[0] spoofing (`exec -a sshd python…`); `LD_PRELOAD` in process environments; unowned/tampered running binaries; shells spawned by web/DB services (webshells); PIDs hidden from `ps`; PIDs hidden from `/proc` listing (brute force)
- **net**: listeners and connections parsed straight from `/proc/net` (not from `ss`), bind/reverse shells, listeners with no visible owner, ports hidden from `ss`/`netstat` (trojan check), **AF_PACKET sniffers (BPFdoor-style magic-packet backdoors)**, raw ICMP sockets, promiscuous NICs, iptables port-knock/redirect rules
- **web**: webshell signatures, PHP in upload dirs, `.htaccess` handler tricks, php.ini `auto_prepend_file`, recently dropped web files

## Notes and limits

- **Read-only.** Nothing is deleted, killed or changed. Remediation is up to you. The one exception is `--beacon`, which adds a single auditd rule and removes it when done.
- **If a core tool is trojaned**, the tools/pkg modules will tell you. Re-run with a **static** busybox you brought yourself: `--bb /root/busybox`. A kernel rootkit can lie even to that. The hidden-module, hidden-PID and hidden-port cross-checks are there to catch that case.
- **Expect some MED noise on a fresh box.** Vendor software in `/usr/local` or `/opt` and changed configs will show up. That's why the baseline/diff workflow matters: once you've reviewed the box, `--diff` shows only what's new.
- **Keep the baseline off-box.** The script detects a tampered baseline (its manifest no longer verifies), but you'll still need a clean copy to compare against.
- Tested on Ubuntu 24.04. Written for bash 3.2+ and plain coreutils/awk, so it should run on old CentOS and Debian images too. `--online` needs a reachable mirror (run `apt-get update` first if the lists are empty).

| Option | Meaning |
|---|---|
| `--quick` | skip webshell scan, conffile check, lsattr, unowned libs, hidden-PID brute force |
| `--only a,b` / `--skip a,b` | choose modules: tools pkg unowned perms users pam cron systemd shell misc kernel proc net web |
| `--days N` | "recently changed" window (default 7) |
| `-o DIR` | where to write the report |
| `--no-color` | plain output (for piping to a file) |
