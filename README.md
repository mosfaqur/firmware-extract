# fw-extract.sh

Automated static-analysis pipeline that extracts and classifies security-relevant
artifacts from embedded Linux firmware images: **credentials, cryptographic key
material, password hashes, unsafe binary functions and debug interfaces**.

`fw-extract.sh` was developed as the operational tooling for a study of detection
coverage across these five sensitive-material categories in production firmware.
The pipeline was validated on production embedded-Linux images, with the
accompanying research extending the design across ARM64 production firmware
images.

## Features

- **Multi-partition & nested extraction** — binwalk (recursive, depth 5) + `unsquashfs` /
  `sasquatch`, `cpio`, plus multi-pass recursive extraction of nested `.tgz`, `.tar`,
  and `.zip` filesystem archives.
- **Privilege & permissions audit** — SUID (`4000`) and SGID (`2000`) binary census
  correlated with ELF hardening (canary/PIE/NX), identification of high-risk binaries
  (e.g. SUID root `busybox`/`su`), and detection of world-writable system files.
- **Kernel module (.ko) & driver census** — comprehensive driver inventory via
  `modinfo`, extracting module parameters (hardware/debug overrides), license
  attribution (GPL vs proprietary), vermagic, authors, and dependencies.
- **Super-server & network services** — parses `xinetd` and `inetd` configurations,
  reporting daemons running as root and flagging scripts with dynamic command execution (`eval`/`exec`).
- **Scheduled tasks & background jobs** — discovers scheduled crontabs and systemd
  timers running under root.
- **Plaintext secret stores** — detects dedicated secret files (`/etc/*.secret*`,
  `pap-secrets`, `chap-secrets`, `.netrc`, `.htpasswd`), shadow backups, and
  wireless credentials (`wpa_supplicant.conf`, `hostapd.conf`, OpenWrt wireless).
- **Cryptographic hygiene & key classification** — validates keys with `openssl`
  (private/encrypted/public), checks x509 certificate expiry/validity, flags weak
  signature algorithms (MD5/SHA1), weak RSA key lengths (< 2048-bit), and weak
  Diffie-Hellman parameters (`dhpars.pem`).
- **Credential scanning** — root-equivalent and blank-password accounts,
  `shadow` hash enumeration, hardcoded-secret regex pass over a cross-partition
  `strings` index (including Google API keys, JWT tokens, WireGuard keys, GitHub tokens).
- **Password-hash cracking** (optional) — hash format auto-detection
  (`$1$`, `$5$`, `$6$`, `$2a/b/y$`, unsalted MD5/SHA1) and a time-bounded
  `hashcat` dictionary run with a per-account recovery report.
- **Binary analysis** — hardening census over every ELF binary
  (canary / PIE / NX / RELRO depth full·partial·none) plus an unsafe-function
  import census from the dynamic symbol table, alongside per-binary `strings`
  counts of `system, popen, execve, strcpy, strcat, sprintf, gets`.
  Extended binary metrics: static vs dynamic linkage, stripped vs unstripped,
  FORTIFY_SOURCE (`_chk` imports), and a per-architecture breakdown.
- **Embedded-secret attribution** — scans the largest ELF binaries for embedded
  private-key headers, certificates, credential assignments, URLs and
  host:port strings, and reports which specific binary contains them.
- **Component version fingerprinting** — detects OpenSSL, glibc, BusyBox,
  libcurl, uhttpd, dropbear, strongSwan, OpenSSH and tcpdump version strings
  inside binaries to flag outdated builds.
- **System hardening & bootloader layout** — parses `/etc/sysctl.conf` (flagging
  test/lab mode remnants) and U-Boot `fw_env.config` MTD flash partition layouts.
- **Debug-interface enumeration** — startup scripts, `.profile` and `scripts`
  material checked for `telnet(d)`, `gdbserver`, `dropbear`, `socat`/`nc -l`,
  serial-console and JTAG references, classified as *loopback* or
  *network-exposed*.
- **Deterministic + machine-readable** — content-based dedup across duplicated
  rootfs variants, provenance-preserving findings copies, and a
  `findings.json` taxonomy emitted alongside the human-readable `REPORT.md`.

## Requirements

| Tool | Purpose | Required |
|------|---------|----------|
| `binwalk`, `unsquashfs`/`sasquatch` | filesystem extraction | yes (skip in scan-only mode) |
| `strings`, `openssl`, `file`, `find`, `grep`, `readelf` | analysis | yes |
| `modinfo` | kernel module parameter extraction | optional (falls back to strings) |
| `hashcat` | stage 4 cracking | optional |
| `python3` | `findings.json` output | optional |

## Usage

```sh
# full pipeline on a firmware archive
./fw-extract.sh firmware.bin out/

# scan an already-extracted filesystem tree (skips stage 1)
./fw-extract.sh /path/to/extracted/ out/
```

Optional environment:

```sh
# enable stage 4 dictionary cracking (skipped unless set)
HASH_WORDLIST=./rockyou.txt \
HASH_TIMEOUT=86400 \
./fw-extract.sh firmware.bin out/

NO_HASHCAT=1            # force-disable cracking
BIN_SCAN_LIMIT=300      # top-N largest ELF binaries for the embedded-secret
                        # and version scans (default 200)
```

## Outputs

```
out/
├── REPORT.md           human-readable report (all categories + summary table)
├── findings.json       machine-readable taxonomy (summary + typed findings)
├── items.tsv           raw findings log
├── census.tsv          per-ELF metric rows (relro/size/arch/linkage/stripped/fortify)
├── kernel_modules.tsv  kernel module catalog (module/license/vermagic/author/params)
├── all_strings.txt     cross-partition strings index
├── hashcat.log/.pot    stage 4 artefacts (when cracking is enabled)
└── findings/           copied artefacts
    ├── keys/  certs/  configs/  credentials/  hashes/  modules/
```

## Ethical note

The tool is intended for **authorised security research on firmware the user is
entitled to analyse**. Findings are reported in aggregate; do not use recovered
credentials or keys against live systems.

## Files

- `fw-extract.sh` — current version (v2).
- `fw-extract.v1.sh` — original single-module version retained for reference
  and diffing (the §4.2 key-classification defect is fixed in v2).
