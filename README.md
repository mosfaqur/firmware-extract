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

- **Multi-partition extraction** — binwalk (recursive, depth 5) + `unsquashfs` /
  `sasquatch`; also unpacks `cpio` images found inside the archive.
- **Credential scanning** — root-equivalent and blank-password accounts,
  `shadow` hash enumeration, hardcoded-secret regex pass over a cross-partition
  `strings` index, `sshd_config` and IPsec review.
- **Key-material classification** — each candidate key is validated with
  `openssl` and classified as *private (plaintext)*, *private (encrypted)* or
  *public*, so public keys are no longer miscounted as private keys (the v1
  defect documented as the §4.2 fix in the accompanying paper).
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
  host:port strings, and reports which specific binary contains them (e.g.
  management credentials compiled into an application partition binary).
- **Component version fingerprinting** — detects OpenSSL, glibc, BusyBox,
  libcurl, uhttpd, dropbear, strongSwan, OpenSSH and tcpdump version strings
  inside binaries to flag outdated builds (e.g. OpenSSL 0.9.8y, glibc 2.5).
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
├── all_strings.txt     cross-partition strings index
├── hashcat.log/.pot    stage 4 artefacts (when cracking is enabled)
└── findings/           copied artefacts
    ├── keys/  certs/  configs/  credentials/  hashes/
```

## Ethical note

The tool is intended for **authorised security research on firmware the user is
entitled to analyse**. Findings are reported in aggregate; do not use recovered
credentials or keys against live systems.

## Files

- `fw-extract.sh` — current version (v2).
- `fw-extract.v1.sh` — original single-module version retained for reference
  and diffing (the §4.2 key-classification defect is fixed in v2).
