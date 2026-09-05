#!/usr/bin/env bash
#
# fw-extract.sh - extract and classify security-relevant artifacts from
#                 embedded Linux firmware images.
#
# v2.2 (enhanced)
#   - SUID/SGID & permission audit: enumerates setuid/setgid binaries,
#     cross-references with ELF hardening (canary/PIE/NX), flags high-risk
#     binaries (busybox/su/sh) and identifies world-writable system files
#   - Kernel modules (.ko) & driver census: catalogs all loadable drivers,
#     inspects module parameters (debug/hardware test overrides), licenses
#     (GPL vs proprietary), vermagic, authors, and module dependencies
#   - Super-server & network services: audits xinetd and inetd configs,
#     detecting daemons running as root and dynamic command runners (eval/exec)
#   - Scheduled tasks & background automation: comprehensive crontab and
#     systemd timer discovery, reporting command targets running under root
#   - Plaintext secret stores: audits dedicated secret files (/etc/*.secret,
#     pap-secrets, chap-secrets, .netrc, .htpasswd, shadow backups) and
#     wireless credentials (wpa_supplicant, hostapd, OpenWrt wireless)
#   - Cryptographic hygiene & certificate depth: checks x509 validity/expiry,
#     flags deprecated signature algorithms (MD5/SHA1), weak RSA key lengths
#     (< 2048-bit), and weak Diffie-Hellman parameters (dhpars.pem)
#   - Kernel & system hardening (sysctl): audits /etc/sysctl.conf and lab/test
#     configurations (flags test-mode remnants left in production builds)
#   - Bootloader & hardware assets: parses U-Boot MTD environment layouts
#     (fw_env.config) and identifies FPGA bitstreams (.rbf/.bit) and blobs
#   - Recursive archive unpacking: handles nested rootfs archives (.tgz, .tar,
#     .zip, .xz, .squashfs) across multi-stage firmware packages
#   - Extended regex patterns: Google API keys, JWT tokens, WireGuard keys,
#     and GitHub tokens added to strings credential index
#   - Provenance-preserving copies, deterministic output, findings.json taxonomy
#
# usage: ./fw-extract.sh <firmware_file|extracted_dir> [output_dir]
#
#   passing a directory enables scan-only mode (no extraction step)
#
# optional environment:
#   HASH_WORDLIST=<path>   wordlist for stage 4 hash cracking
#                          (stage 4 is skipped unless this is set)
#   HASH_TIMEOUT=<seconds> per-hashcat-run time budget (default 3600)
#   NO_HASHCAT=1           disable stage 4 cracking even if wordlist set
#   BIN_SCAN_LIMIT=<n>     top-N (largest) ELF binaries to scan for
#                          embedded secrets/versions (default 200)
#
# deps: binwalk, unsquashfs/sasquatch, strings, openssl, file, find,
#       grep, readelf, numfmt (optional: modinfo, hashcat, python3)
#
# outputs:
#   $OUTDIR/REPORT.md      human-readable per-category report
#   $OUTDIR/findings.json  machine-readable taxonomy (category counts +
#                          typed findings)
#   $OUTDIR/findings/      copied artefacts under keys/certs/configs/
#                          credentials/hashes/modules
#   $OUTDIR/all_strings.txt
#   $OUTDIR/items.tsv
#   $OUTDIR/census.tsv
#   $OUTDIR/kernel_modules.tsv
#
# All outputs are deterministic for a given input tree.

set -uo pipefail
shopt -s nullglob

declare -r SCRIPT_NAME="fw-extract.sh"
declare -r VERSION="2.2.0"

HASH_WORDLIST="${HASH_WORDLIST:-}"
HASH_TIMEOUT="${HASH_TIMEOUT:-3600}"
NO_HASHCAT="${NO_HASHCAT:-0}"
BIN_SCAN_LIMIT="${BIN_SCAN_LIMIT:-200}"

export LC_ALL=C

trap 'die "interrupted"' INT TERM

# ---------------------------------------------------------------------------
# logging / report helpers
# ---------------------------------------------------------------------------

log()  { printf '%s\n' "[*] $*"; }
warn() { printf '%s\n' "[!] $*" >&2; }
die()  { printf '%s\n' "error: $*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

rpt() { printf '%s\n' "$@" >> "$REPORT"; }

section() {
    local title="$1"
    rpt "" "## $title" ""
}

# note <category> <severity> <path> <detail>   (appends a TSV row)
note() {
    local cat="$1" sev="$2" path="$3" detail="$4"
    printf '%s\t%s\t%s\t%s\n' \
        "$cat" "$sev" "${path//$'\t'/ }" "${detail//$'\t'/ }" >> "$ITEMS"
}

# copy findings into a findings subdir, preserving relative provenance
copy_finding() {
    local sub="$1" src="$2"
    local rel dest
    rel="${src#"$ROOTFS/"}"
    dest="$FINDINGS/$sub/${rel%/*}"
    [[ -d "$dest" ]] || mkdir -p "$dest"
    cp -f "$src" "$dest/" 2>/dev/null
}

# ---------------------------------------------------------------------------
# small predicates / helpers
# ---------------------------------------------------------------------------

count_matches() { grep -Ei "$1" "$2" 2>/dev/null | wc -l | tr -d ' '; }

is_text()   { file "$1" 2>/dev/null | grep -qiE 'text|empty|script|ASCII'; }
is_binary() { file "$1" 2>/dev/null | grep -qiE 'ELF|executable|shared object'; }

# content-based dedup across rootfs variants
# db files are initialised in main() / individual stages
seen_db() {
    local db="$1" tgt="$2" h
    h=$(sha256sum "$tgt" 2>/dev/null | cut -d' ' -f1) || return 1
    grep -qF "$h" "$db" 2>/dev/null && return 0
    echo "$h" >> "$db"
    return 1
}
seen() { seen_db "$SEEN" "$1"; }

human_time() {
    local s=$1
    if [[ "$s" -ge 60 ]]; then
        printf '%dm %02ds' "$((s / 60))" "$((s % 60))"
    else
        printf '%ds' "$s"
    fi
}

# ---------------------------------------------------------------------------
# key material classification  (paper 4.2 correction)
#
# class:  private | encrypted | public | unknown
# ---------------------------------------------------------------------------

key_class() {
    local f="$1" marker
    [[ -r "$f" && -s "$f" ]] || { echo "unknown"; return; }

    marker=$(grep -am1 -E \
        'ENCRYPTED PRIVATE KEY|BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY|PuTTY-User-Key-File|^ssh-(rsa|dss|ed25519|ecdsa)|^ecdsa-|^sk-' \
        "$f" 2>/dev/null | tr -d '\0')

    case "$marker" in
        *"PuTTY-User-Key-File"*)
            if head -6 "$f" 2>/dev/null | grep -qiE 'Encryption: (aes|arcfour)'; then
                echo "encrypted"
            else
                echo "private"
            fi
            return ;;
        *"OPENSSH PRIVATE KEY"*)
            if grep -aqE 'bcrypt|aes(128|192|256)-cbc|chacha20-poly1305' "$f" 2>/dev/null; then
                echo "encrypted"
            else
                echo "private"
            fi
            return ;;
        *"ENCRYPTED PRIVATE KEY"*)
            echo "encrypted"; return ;;
        *"PRIVATE KEY"*)
            if head -6 "$f" 2>/dev/null | grep -qiE 'Proc-Type: 4,ENCRYPTED|DEK-Info:'; then
                echo "encrypted"; return
            fi
            # authoritative check: parse without passphrase, non-interactively
            if openssl pkey -in "$f" -passin pass: -noout </dev/null 2>/dev/null; then
                echo "private"; return
            fi
            echo "encrypted"; return ;;
        "ssh-"*|"ecdsa-"*|"sk-"*)
            echo "public"; return ;;
        *)
            # no header matched: some keys carry a comment line before the
            # PEM body (e.g. /etc/init.d/dummy.key starts with "### Dummy key ###")
            if openssl pkey -in "$f" -passin pass: -noout </dev/null 2>/dev/null; then
                echo "private"; return
            fi
            if openssl pkey -pubin -in "$f" -noout </dev/null 2>/dev/null; then
                echo "public"; return
            fi
            echo "unknown"; return ;;
    esac
}

# first-line openssl human detail for a key (best effort)
key_detail() {
    local f="$1"
    openssl pkey -in "$f" -passin pass: -text -noout </dev/null 2>/dev/null | head -1
}

# ---------------------------------------------------------------------------
# stage 1 : firmware acquisition and filesystem extraction
# ---------------------------------------------------------------------------

stage1_extract() {
    local f
    if [[ -d "$FIRMWARE" ]]; then
        ROOTFS="$FIRMWARE"
        EXTRACT="$FIRMWARE"
        log "scan-only mode: analysing existing tree $ROOTFS"
        FILE_COUNT=$(find "$ROOTFS" -type f 2>/dev/null | wc -l | tr -d ' ')
        log "$FILE_COUNT files under analysis"
        {
            echo "## Extraction"
            echo ""
            echo "- files: $FILE_COUNT"
            echo "- mode: scan-only (existing tree)"
            echo ""
        } >> "$REPORT"
        return
    fi

    log "extracting firmware..."
    if have binwalk; then
        binwalk -e -M -d 5 -C "$EXTRACT" "$FIRMWARE" 2>/dev/null || true
        binwalk "$FIRMWARE" > "$OUTDIR/binwalk_scan.txt" 2>/dev/null || true
    fi

    MIME=$(file -b --mime-type "$FIRMWARE" 2>/dev/null || echo "unknown")
    case "$MIME" in
        application/gzip|application/x-gzip)
            mkdir -p "$EXTRACT/tar_contents"
            tar xzf "$FIRMWARE" -C "$EXTRACT/tar_contents" 2>/dev/null || \
                (gunzip -c "$FIRMWARE" 2>/dev/null | tar xf - -C "$EXTRACT/tar_contents" 2>/dev/null) || \
                gunzip -c "$FIRMWARE" > "$EXTRACT/decompressed" 2>/dev/null || true ;;
        application/x-tar)
            mkdir -p "$EXTRACT/tar_contents"
            tar xf "$FIRMWARE" -C "$EXTRACT/tar_contents" 2>/dev/null || true ;;
        application/zip)
            unzip -o "$FIRMWARE" -d "$EXTRACT/zip_contents" 2>/dev/null || true ;;
        application/x-xz)
            xz -dc "$FIRMWARE" > "$EXTRACT/decompressed" 2>/dev/null || true ;;
    esac

    # unpack nested archives (squashfs, cpio, tar/tgz, zip) recursively (up to 3 passes)
    local pass new_archives ftype bname dest
    local unpack_db="$OUTDIR/.unpacked"
    : > "$unpack_db"
    for pass in 1 2 3; do
        new_archives=0
        while IFS= read -r -d '' f; do
            seen_db "$unpack_db" "$f" && continue
            ftype=$(file -b "$f" 2>/dev/null || true)
            bname="${f##*/}"
            case "$ftype" in
                *[Ss]quashfs*)
                    dest="$EXTRACT/squashfs_${bname}"
                    [[ -d "$dest" ]] && dest="${dest}_p${pass}"
                    log "squashfs (pass $pass): $bname"
                    unsquashfs -d "$dest" -f "$f" 2>/dev/null || \
                        sasquatch -d "$dest" -f "$f" 2>/dev/null || true
                    new_archives=1
                    ;;
                *cpio*)
                    dest="$EXTRACT/cpio_${bname}"
                    [[ -d "$dest" ]] && dest="${dest}_p${pass}"
                    log "cpio (pass $pass): $bname"
                    mkdir -p "$dest"
                    (cd "$dest" && cpio -idm < "$f" 2>/dev/null) || true
                    new_archives=1
                    ;;
                *gzip*|*POSIX\ tar*|*tar\ archive*|*XZ\ compressed*)
                    if [[ "$f" == *.tgz || "$f" == *.tar.gz || "$f" == *.tar || "$f" == *.tar.xz || "$f" == *.txz ]]; then
                        dest="$EXTRACT/tar_${bname}"
                        [[ -d "$dest" ]] && dest="${dest}_p${pass}"
                        log "tar archive (pass $pass): $bname"
                        mkdir -p "$dest"
                        tar xf "$f" -C "$dest" 2>/dev/null || \
                            (gunzip -c "$f" 2>/dev/null | tar xf - -C "$dest" 2>/dev/null) || true
                        new_archives=1
                    fi
                    ;;
                *Zip\ archive*)
                    if [[ "$f" == *.zip ]]; then
                        dest="$EXTRACT/zip_${bname}"
                        [[ -d "$dest" ]] && dest="${dest}_p${pass}"
                        log "zip archive (pass $pass): $bname"
                        mkdir -p "$dest"
                        unzip -q -o "$f" -d "$dest" 2>/dev/null || true
                        new_archives=1
                    fi
                    ;;
            esac
        done < <(find "$EXTRACT" -type f -print0 2>/dev/null)
        [[ "$new_archives" -eq 0 ]] && break
    done

    ROOTFS="$EXTRACT"
    FILE_COUNT=$(find "$ROOTFS" -type f 2>/dev/null | wc -l | tr -d ' ')
    log "$FILE_COUNT files extracted"
    {
        echo "## Extraction"
        echo ""
        echo "- files: $FILE_COUNT"
        echo "- type: $MIME"
        echo ""
    } >> "$REPORT"
}

# ---------------------------------------------------------------------------
# stage 2 : ssh keys, sshd config, accounts, shadow
# ---------------------------------------------------------------------------

stage2_ssh_keys() {
    local kf kclass label open_detail f
    section "SSH Keys"

    while IFS= read -r -d '' kf; do
        grep -aqE "PRIVATE KEY|PuTTY-User-Key-File" "$kf" 2>/dev/null || continue
        seen "$kf" && continue
        kclass=$(key_class "$kf")
        case "$kclass" in
            private)    label="PRIVATE KEY (plaintext)" ;;
            encrypted)  label="PRIVATE KEY (encrypted)" ;;
            *)          label="PRIVATE KEY ($kclass)" ;;
        esac
        open_detail=$(key_detail "$kf")
        copy_finding "keys" "$kf"
        log "  $kclass key: $kf"
        rpt "- **$label:** \`$kf\`"
        [[ -n "$open_detail" ]] && rpt "  $open_detail"
        case "$kclass" in
            private)   note "key" high "$kf" "plaintext private key" ;;
            encrypted) note "key" medium "$kf" "passphrase-protected private key" ;;
        esac
    done < <(find "$ROOTFS" -type f \( -name "*.key" -o -name "*.pem" -o \
        -name "id_*" -o -name "ssh_host_*" -o -name "*.ppk" \) -print0 2>/dev/null)

    # private-key material embedded in non-key files (headers anywhere)
    while IFS= read -r -d '' f; do
        case "$f" in *.key|*.pem) continue ;; esac
        seen "$f" && continue
        copy_finding "keys" "$f"
        kclass=$(key_class "$f")
        log "  embedded key: $f"
        rpt "- embedded private key: \`$f\`"
        note "key" high "$f" "embedded $kclass"
    done < <(grep -rlZ -E -- "BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY" \
        "$ROOTFS" 2>/dev/null | head -z -n 50)

    # public keys
    while IFS= read -r -d '' kf; do
        seen "$kf" && continue
        copy_finding "keys" "$kf"
        log "  public key: $kf"
        rpt "- public key: \`$kf\`"
        note "key" info "$kf" "public"
    done < <(find "$ROOTFS" -type f \( -name "*.pub" -o -name "authorized_keys" \
        -o -name "authorized_keys2" \) -print0 2>/dev/null)

    # sshd_config and secondary ssh configurations
    while IFS= read -r -d '' kf; do
        seen "$kf" && continue
        local rel="${kf#"$ROOTFS/"}"
        rpt "" "### SSH server config: \`$rel\`" '```'
        grep -vE '^\s*#|^\s*$' "$kf" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""

        local p_root p_pass p_empty p_port p_authkey p_pub
        p_root=$(grep -iE '^\s*PermitRootLogin\s+' "$kf" 2>/dev/null | head -1)
        p_pass=$(grep -iE '^\s*PasswordAuthentication\s+' "$kf" 2>/dev/null | head -1)
        p_empty=$(grep -iE '^\s*PermitEmptyPasswords\s+' "$kf" 2>/dev/null | head -1)
        p_port=$(grep -iE '^\s*Port\s+' "$kf" 2>/dev/null | head -1)
        p_authkey=$(grep -iE '^\s*AuthorizedKeysFile\s+' "$kf" 2>/dev/null | head -1)
        p_pub=$(grep -iE '^\s*PubkeyAuthentication\s+' "$kf" 2>/dev/null | head -1)

        [[ -n "$p_port" ]] && rpt "- $p_port"
        [[ -n "$p_root" ]] && rpt "- $p_root"
        [[ -n "$p_pass" ]] && rpt "- $p_pass"
        [[ -n "$p_empty" ]] && rpt "- $p_empty"
        [[ -n "$p_pub" ]] && rpt "- $p_pub"
        [[ -n "$p_authkey" ]] && rpt "- $p_authkey"

        if [[ "$p_authkey" =~ /tmp/|/var/tmp/ ]]; then
            rpt "  - **HIGH RISK**: AuthorizedKeysFile points to writable temp path: $p_authkey"
            note "ssh_config" high "$kf" "insecure AuthorizedKeysFile in temp path: $p_authkey"
        fi
        if grep -qiE 'PermitRootLogin\s+yes' "$kf" 2>/dev/null; then
            note "ssh_config" high "$kf" "PermitRootLogin yes"
        fi
        if grep -qiE 'PermitEmptyPasswords\s+yes' "$kf" 2>/dev/null; then
            note "ssh_config" high "$kf" "PermitEmptyPasswords yes"
        fi
        if grep -qi "StrictHostKeyChecking.*no" "$kf" 2>/dev/null; then
            rpt "- StrictHostKeyChecking no"
            note "ssh_config" medium "$kf" "StrictHostKeyChecking no"
        fi
        copy_finding "configs" "$kf"
    done < <(find "$ROOTFS" -type f \( -name "sshd_config*" -o -name "ssh_config*" \) -print0 2>/dev/null)
}

# ---------------------------------------------------------------------------
# stage 2 : certificates
# ---------------------------------------------------------------------------

stage2_certs() {
    local cert info subj issuer is_ca f
    local not_after sig_alg key_size
    section "Certificates"

    while IFS= read -r -d '' cert; do
        seen "$cert" && continue
        copy_finding "certs" "$cert"
        info=$(openssl x509 -in "$cert" -text -noout 2>/dev/null) || \
        info=$(openssl x509 -in "$cert" -inform DER -text -noout 2>/dev/null) || \
        info=""
        if [[ -n "$info" ]]; then
            subj=$(printf '%s\n' "$info" | grep "Subject:" | head -1 | sed 's/.*Subject:\s*//')
            issuer=$(printf '%s\n' "$info" | grep "Issuer:" | head -1 | sed 's/.*Issuer:\s*//')
            is_ca=$(printf '%s\n' "$info" | grep -c "CA:TRUE" 2>/dev/null || true)
            is_ca=${is_ca:-0}
            not_after=$(printf '%s\n' "$info" | grep "Not After" | head -1 | sed 's/.*Not After\s*:\s*//')
            sig_alg=$(printf '%s\n' "$info" | grep -m1 "Signature Algorithm" | sed 's/.*Signature Algorithm:\s*//')
            key_size=$(printf '%s\n' "$info" | grep -oE 'Public-Key: \([0-9]+ bit\)' | head -1 | grep -oE '[0-9]+')

            rpt "- \`${cert##*/}\`: $subj"
            [[ "$is_ca" -gt 0 ]] && rpt "  - CA certificate"
            rpt "  - issuer: $issuer"
            [[ -n "$not_after" ]] && rpt "  - expires: $not_after"
            [[ -n "$sig_alg" ]] && rpt "  - algorithm: $sig_alg"
            [[ -n "$key_size" ]] && rpt "  - public key: $key_size-bit"

            if ! openssl x509 -in "$cert" -checkend 0 -noout 2>/dev/null; then
                rpt "  - **EXPIRED**: certificate expired ($not_after)"
                note "cert" medium "$cert" "certificate expired on $not_after"
                N_EXPIRED_CERTS=$((N_EXPIRED_CERTS + 1))
            fi
            if [[ "$sig_alg" =~ (md5|sha1|MD5|SHA1) ]]; then
                rpt "  - **WEAK ALGORITHM**: uses deprecated hash algorithm ($sig_alg)"
                note "weak_crypto" high "$cert" "deprecated cert signature algorithm: $sig_alg"
                N_WEAK_CERTS=$((N_WEAK_CERTS + 1))
            fi
            if [[ -n "$key_size" && "$key_size" -lt 2048 ]]; then
                rpt "  - **WEAK KEY**: RSA key size < 2048 ($key_size-bit)"
                note "weak_crypto" high "$cert" "weak certificate public key size ($key_size-bit < 2048)"
                N_WEAK_CERTS=$((N_WEAK_CERTS + 1))
            fi
            if [[ "$subj" == "$issuer" ]]; then
                rpt "  - self-signed certificate"
            fi
            note "cert" info "$cert" "subject=$subj; expires=$not_after"
        else
            rpt "- \`${cert##*/}\` (unparseable)"
            note "cert" low "$cert" "unparseable"
        fi
    done < <(find "$ROOTFS" -type f \( -name "*.pem" -o -name "*.crt" -o \
        -name "*.cer" -o -name "*.der" -o -name "*.p12" -o -name "*.pfx" -o \
        -name "*.jks" -o -name "*.keystore" -o -name "ca-bundle*" -o -name "*.ca" \
        \) -print0 2>/dev/null)

    # Diffie-Hellman parameters check
    while IFS= read -r -d '' f; do
        seen "$f" && continue
        copy_finding "keys" "$f"
        local dh_info dh_bits
        dh_info=$(openssl dhparam -in "$f" -text -noout 2>/dev/null || true)
        dh_bits=$(printf '%s\n' "$dh_info" | grep -oE 'DH Parameters: \([0-9]+ bit\)' | grep -oE '[0-9]+' | head -1)
        if [[ -n "$dh_bits" ]]; then
            rpt "- DH parameter file: \`${f##*/}\` ($dh_bits-bit prime)"
            if [[ "$dh_bits" -lt 2048 ]]; then
                rpt "  - **WEAK DH PARAMETERS**: DH prime < 2048 ($dh_bits-bit, vulnerable to Logjam)"
                note "weak_crypto" high "$f" "weak Diffie-Hellman prime length: $dh_bits bit (< 2048)"
                N_WEAK_CERTS=$((N_WEAK_CERTS + 1))
            else
                note "crypto" info "$f" "Diffie-Hellman parameters: $dh_bits bit"
            fi
        fi
    done < <(find "$ROOTFS" -type f \( -name "*dhpar*.pem" -o -name "*dhparam*.pem" -o -name "*.dh" \) -print0 2>/dev/null)

    while IFS= read -r -d '' f; do
        seen "$f" && continue
        copy_finding "configs" "$f"
        log "  ipsec: $f"
        rpt "- IPsec: \`$f\`"
        note "key" low "$f" "ipsec secrets/config"
    done < <(find "$ROOTFS" -type f \( -name "ipsec.secrets" -o -name "ipsec.conf" \
        -o -name "*.secrets" -o -path "*/ipsec.d/*" \) -print0 2>/dev/null)
}

# ---------------------------------------------------------------------------
# stage 2 : dedicated secret files and credential stores
# ---------------------------------------------------------------------------

stage2_secret_files() {
    local sf rel bname sz firstline
    section "Dedicated Secret and Credential Files"

    log "scanning for dedicated secret files..."
    N_SECRET_FILES=0

    # 1. Plaintext secret files in /etc or /var or across rootfs
    while IFS= read -r -d '' sf; do
        seen "$sf" && continue
        is_text "$sf" || continue
        sz=$(stat -c%s "$sf" 2>/dev/null || stat -f%z "$sf" 2>/dev/null || echo 0)
        [[ "$sz" -eq 0 ]] && continue
        bname="${sf##*/}"
        rel="${sf#"$ROOTFS/"}"
        copy_finding "credentials" "$sf"
        N_SECRET_FILES=$((N_SECRET_FILES + 1))
        firstline=$(grep -vE '^\s*#|^\s*$' "$sf" 2>/dev/null | head -1)
        rpt "- **Secret file:** \`$rel\` ($sz bytes)"
        [[ -n "$firstline" ]] && rpt "  - sample: \`${firstline:0:80}\`"
        note "secret_file" high "$sf" "plaintext secret store: $bname"
    done < <(find "$ROOTFS" -type f \( -name "*.secret" -o -name "*.secrets" -o \
        -name "*eap.secret*" -o -name "*pap-secrets*" -o -name "*chap-secrets*" -o \
        -name ".netrc" -o -name ".htpasswd" -o -name ".pgpass" -o \
        -name "shadow.dir" -o -name "shadow.field" \) -print0 2>/dev/null)

    # 2. Wireless / Wi-Fi credentials
    while IFS= read -r -d '' sf; do
        seen "$sf" && continue
        is_text "$sf" || continue
        rel="${sf#"$ROOTFS/"}"
        copy_finding "configs" "$sf"
        local psk ssid
        psk=$(grep -iE 'psk\s*=' "$sf" 2>/dev/null | head -1)
        ssid=$(grep -iE 'ssid\s*=' "$sf" 2>/dev/null | head -1)
        rpt "- **Wireless config:** \`$rel\`"
        [[ -n "$ssid" ]] && rpt "  - $ssid"
        if [[ -n "$psk" ]]; then
            rpt "  - $psk"
            note "wireless_credential" high "$sf" "Wi-Fi PSK configured: ${psk:0:60}"
            N_SECRET_FILES=$((N_SECRET_FILES + 1))
        fi
    done < <(find "$ROOTFS" -type f \( -name "wpa_supplicant*.conf" -o \
        -name "hostapd*.conf" -o -name "wireless" -path "*/config/wireless" \) -print0 2>/dev/null)

    # 3. Radius server / secret configs
    while IFS= read -r -d '' sf; do
        seen "$sf" && continue
        is_text "$sf" || continue
        rel="${sf#"$ROOTFS/"}"
        copy_finding "configs" "$sf"
        rpt "- **RADIUS config:** \`$rel\`"
        local rline
        rline=$(grep -vE '^\s*#|^\s*$' "$sf" 2>/dev/null | head -2)
        [[ -n "$rline" ]] && rpt '```' "$rline" '```'
        if grep -qiE 'secret|shared_secret' "$sf" 2>/dev/null; then
            note "radius_config" medium "$sf" "RADIUS client/server configuration"
            N_SECRET_FILES=$((N_SECRET_FILES + 1))
        fi
    done < <(find "$ROOTFS" -type f \( -path "*/raddb/*" -o -name "pam_radius*.conf" \) -print0 2>/dev/null)

    rpt ""
    rpt "- dedicated secret and credential files found: $N_SECRET_FILES"
    rpt ""
}

# ---------------------------------------------------------------------------
# stage 2 : user accounts and password hashes
# ---------------------------------------------------------------------------

stage2_accounts() {
    local pf sf user hash uid shell pass
    section "User Accounts"

    while IFS= read -r -d '' pf; do
        is_text "$pf" || continue
        seen "$pf" && continue
        copy_finding "credentials" "$pf"
        rpt "### passwd" '```'
        cat "$pf" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""
        while IFS=: read -r user pass uid _ _ _ shell; do
            [[ -n "$user" ]] || continue
            if [[ "$uid" == "0" && "$user" != "root" ]]; then
                log "  root-equivalent: $user (uid 0)"
                rpt "- root-equivalent: \`$user\` (uid 0, $shell)"
                note "credential" high "$pf" "root-equivalent account $user"
            fi
            if [[ -z "$pass" ]]; then
                log "  blank password: $user"
                rpt "- blank password: \`$user\`"
                note "credential" high "$pf" "blank password account $user"
            fi
        done < "$pf"
    done < <(find "$ROOTFS" -type f -name "passwd" -path "*/etc/*" -print0 2>/dev/null)

    while IFS= read -r -d '' sf; do
        is_text "$sf" || continue
        seen "$sf" && continue
        copy_finding "hashes" "$sf"
        rpt "### shadow ($sf)" ""
        while IFS=: read -r user hash _; do
            [[ -z "$hash" || "$hash" == "*" || "$hash" == "!" || "$hash" == "!!" \
                || "$hash" == "x" ]] && continue
            log "  hash: $user"
            rpt "- \`$user\`: \`${hash:0:20}...\`"
            echo "$user:$hash" >> "$FINDINGS/hashes/crackable.txt"
            note "credential" medium "$sf" "password hash account $user prefix ${hash:0:3}"
        done < "$sf"
    done < <(find "$ROOTFS" -type f \( -name "shadow" -o -name "shadow.*" -o \
        -name "shadow_*" \) -print0 2>/dev/null)
}

# ---------------------------------------------------------------------------
# stage 4 : password hash cracking feasibility (hashcat)
# ---------------------------------------------------------------------------

# return $1=hashcat mode $2=label for a shadow hash
hash_meta() {
    local hash="$1"
    case "$hash" in
        '$1$'*)   out_mode=500  out_label="MD5-crypt (\$1\$)" ;;
        '$2y$'*)  out_mode=3200 out_label="bcrypt (\$2y\$)" ;;
        '$2b$'*)  out_mode=3200 out_label="bcrypt (\$2b\$)" ;;
        '$2a$'*)  out_mode=3200 out_label="bcrypt (\$2a\$)" ;;
        '$5$'*)   out_mode=7400 out_label="SHA256-crypt (\$5\$)" ;;
        '$6$'*)   out_mode=1800 out_label="SHA512-crypt (\$6\$)" ;;
        '$sha1$'*) out_mode=110 out_label="SHA1-crypt" ;;
        *)
            case "$hash" in
                *[0-9a-f]*)
                    if [[ "$hash" =~ ^[0-9a-f]{32}$ ]]; then
                        out_mode=0; out_label="MD5 (unsalted)"
                    elif [[ "$hash" =~ ^[0-9a-f]{40}$ ]]; then
                        out_mode=100; out_label="SHA1 (unsalted)"
                    else
                        out_mode=""; out_label=""
                    fi ;;
                *) out_mode=""; out_label="" ;;
            esac ;;
    esac
}

stage4_hashcat() {
    local line user hash mode label
    local mf umap total t0 t1 dur plain pline pot
    local n_cracked algo_count
    declare -A MDONE=()
    section "Password Hash Cracking"

    [[ -s "$FINDINGS/hashes/crackable.txt" ]] || { rpt "- no crackable hashes found"; return; }

    if [[ "$NO_HASHCAT" != "0" ]]; then
        rpt "- cracking disabled (NO_HASHCAT=1)"; return
    fi
    if [[ -z "$HASH_WORDLIST" ]]; then
        rpt "- skipped: set HASH_WORDLIST=<path> to run a dictionary attack"; return
    fi
    if ! have hashcat; then
        rpt "- skipped: hashcat not installed"; return
    fi
    if [[ ! -r "$HASH_WORDLIST" ]]; then
        rpt "- skipped: wordlist not readable: $HASH_WORDLIST"; return
    fi

    log "grouping hashes by algorithm..."
    POT="$OUTDIR/hashcat.pot"
    : > "$POT"
    : > "$OUTDIR/hashcat.log"

    # split crackable.txt (user:hash) into per-mode bare-hash files plus a
    # hash<TAB>user map; a shadow hash already contains ':' separators, so
    # the first field must be split off with parameter expansion, not IFS=:
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        user=${line%%:*}
        hash=${line#*:}
        [[ -n "$hash" ]] || continue
        out_mode=""; out_label=""
        hash_meta "$hash"
        if [[ -z "$out_mode" ]]; then
            rpt "- \`$user\`: unsupported hash format \`${hash:0:12}...\`"
            continue
        fi
        mf="$FINDINGS/hashes/mode_${out_mode}.hashes"
        echo "$hash" >> "$mf"
        printf '%s\t%s\n' "$hash" "$user" >> "${mf%.hashes}.users"
        MDONE[$out_mode]="$out_label"
    done < "$FINDINGS/hashes/crackable.txt"

    for mode in $(printf '%s\n' "${!MDONE[@]}" | sort -n); do
        mf="$FINDINGS/hashes/mode_${mode}.hashes"
        umap="${mf%.hashes}.users"
        label="${MDONE[$mode]}"
        total=$(wc -l < "$mf" 2>/dev/null | tr -d ' ')
        [[ "$total" -gt 0 ]] || continue

        log "cracking $total ${label} hash(es) with hashcat -m $mode (${HASH_TIMEOUT}s budget)..."
        t0=$(date +%s)
        hashcat --quiet -a 0 -m "$mode" -O --potfile-path "$POT" \
            --runtime "$HASH_TIMEOUT" "$mf" "$HASH_WORDLIST" </dev/null \
            >> "$OUTDIR/hashcat.log" 2>&1
        rc=$?
        t1=$(date +%s)
        dur=$(human_time $((t1 - t0)))
        # hashcat exit codes: 0 = finished (>=1 cracked / clean stop), 1 = exhausted
        if [[ "$rc" -ne 0 && "$rc" -ne 1 ]]; then
            rpt "- hashcat error (exit $rc) for mode $mode; see $OUTDIR/hashcat.log"
            rpt ""
            continue
        fi

        rpt "" "### $label (mode $mode, $total hashes)" ""
        n_cracked=0
        while IFS=$'\t' read -r hash user; do
            pline=""
            [[ -s "$POT" ]] && pline=$(grep -aF -- "$hash:" "$POT" 2>/dev/null | head -1)
            if [[ -n "$pline" ]]; then
                plain=${pline#"$hash:"}
                n_cracked=$((n_cracked + 1))
                log "  recovered: $user"
                rpt "- \`$user\`: RECOVERED (\`$plain\`), ${dur}"
                note "hash" high "$FINDINGS/hashes/crackable.txt" \
                    "$user password recovered from $label"
            else
                rpt "- \`$user\`: not recovered (${dur})"
            fi
        done < "$umap"
        HASH_CRACKED=$((HASH_CRACKED + n_cracked))
        rpt ""
    done
}

# ---------------------------------------------------------------------------
# stage 2 : strings index + hardcoded credential patterns
# ---------------------------------------------------------------------------

stage2_creds() {
    local n name hit
    log "building strings index..."
    find "$ROOTFS" -type f -size +0c -size -100M -print0 2>/dev/null | \
        xargs -0 -r strings -a -n 6 > "$STRINGS_DUMP" 2>/dev/null || true
    STR_COUNT=$(wc -l < "$STRINGS_DUMP" 2>/dev/null | tr -d ' ')
    log "$STR_COUNT strings indexed"

    section "Hardcoded Credentials"

    # NOTE: the 'passwords' pattern is intentionally unchanged; its 30-match
    # / low-precision behaviour is a documented pilot result (paper 5.2).
    declare -A PATTERNS=(
        ["passwords"]='[Pp]assword\s*[:=]\s*["\x27]?[^\s"'\'']{3,}'
        ["api_keys"]='[Aa][Pp][Ii][-_]?[Kk]ey\s*[:=]\s*["\x27]?[A-Za-z0-9_\-]{16,}'
        ["tokens"]='[Tt]oken\s*[:=]\s*["\x27]?[A-Za-z0-9_\-\.]{16,}'
        ["aws_keys"]='AKIA[0-9A-Z]{16}'
        ["secrets"]='[Ss]ecret\s*[:=]\s*["\x27]?[^\s"'\'']{6,}'
        ["connection_strings"]='(mysql|postgres|mongodb|redis)://[^\s"'\''<>]{10,}'
        ["psk"]='PSK\s*["\x27][^\s"'\'']{4,}'
        ["basic_auth"]='[Bb]asic\s+[A-Za-z0-9+/=]{20,}'
        ["bearer"]='[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}'
        ["url_creds"]='https?://[^/\s]*:([\w]+)@'
        ["snmp_community"]='[Ss][Nn][Mm][Pp](\s+|_|-)[Cc]ommunity\s*[:=]\s*["\x27]?[^\s"'\'']{4,}'
        ["mgmt_server_password"]='MANAGEMENT_SERVER_PASSWORD\s*[:=]'
        ["google_api_keys"]='AIza[0-9A-Za-z_\-]{35}'
        ["jwt_tokens"]='eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
        ["wireguard_keys"]='PrivateKey\s*=\s*[A-Za-z0-9+/]{43}='
        ["github_tokens"]='gh[pousr]_[A-Za-z0-9_]{36,}'
        ["private_key_headers"]='BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY'
    )

    for name in $(printf '%s\n' "${!PATTERNS[@]}" | sort); do
        n=$(count_matches "${PATTERNS[$name]}" "$STRINGS_DUMP")
        if [[ "$n" -gt 0 ]]; then
            log "  $name: $n matches"
            rpt "### $name ($n)" '```'
            grep -Ei "${PATTERNS[$name]}" "$STRINGS_DUMP" 2>/dev/null | \
                sort -u | head -n 50 >> "$REPORT"
            rpt '```' ""
            grep -Ei "${PATTERNS[$name]}" "$STRINGS_DUMP" 2>/dev/null | sort -u > \
                "$FINDINGS/credentials/${name}.txt" 2>/dev/null || true
            while IFS= read -r hit; do
                note "credential" low "$STRINGS_DUMP" "pattern $name: $hit"
            done < <(grep -Ei "${PATTERNS[$name]}" "$STRINGS_DUMP" 2>/dev/null \
                | sort -u | head -n 10)
        fi
    done

    # password salts (kept identical to v1)
    grep -Ei 'salt\s*[:=]' "$STRINGS_DUMP" 2>/dev/null | sort -u | head -n 20 > \
        "$FINDINGS/credentials/salts.txt" 2>/dev/null || true
    n=$(wc -l < "$FINDINGS/credentials/salts.txt" 2>/dev/null || echo 0)
    if [[ "$n" -gt 0 ]]; then
        log "  salts: $n"
        rpt "### password salts" '```'
        cat "$FINDINGS/credentials/salts.txt" >> "$REPORT"
        rpt '```' ""
    fi
}

# ---------------------------------------------------------------------------
# network configuration artefacts
# ---------------------------------------------------------------------------

stage2_network() {
    local nc fw ipc uc
    section "Network"

    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$STRINGS_DUMP" 2>/dev/null | \
        sort -u | grep -vE '^(0\.0\.0\.0|127\.0\.0\.[01]|255\.|224\.|0\.0\.)' | \
        head -n 100 > "$FINDINGS/configs/ip_addresses.txt"
    ipc=$(wc -l < "$FINDINGS/configs/ip_addresses.txt" 2>/dev/null || echo 0)
    log "$ipc unique IPs"
    rpt "### IP addresses ($ipc)" '```'
    cat "$FINDINGS/configs/ip_addresses.txt" >> "$REPORT" 2>/dev/null || true
    rpt '```' ""

    grep -oEi 'https?://[^\s"'\''<>]+' "$STRINGS_DUMP" 2>/dev/null | sort -u | \
        head -n 100 > "$FINDINGS/configs/urls.txt"
    uc=$(wc -l < "$FINDINGS/configs/urls.txt" 2>/dev/null || echo 0)
    if [[ "$uc" -gt 0 ]]; then
        log "$uc URLs"
        rpt "### URLs ($uc)" '```'
        cat "$FINDINGS/configs/urls.txt" >> "$REPORT"
        rpt '```' ""
    fi

    while IFS= read -r -d '' nc; do
        is_binary "$nc" && continue
        is_text "$nc" || continue
        seen "$nc" && continue
        copy_finding "configs" "$nc"
        rpt "### ${nc##*/}" '```'
        head -n 200 "$nc" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""
    done < <(find "$ROOTFS" -type f \( -name "resolv.conf" -o -name "hosts" -o \
        -name "hostname" -o -name "*.conf" -path "*/netplan/*" -o -name "interfaces" \) \
        -path "*/etc/*" -print0 2>/dev/null)

    while IFS= read -r -d '' fw; do
        is_binary "$fw" && continue
        is_text "$fw" || continue
        seen "$fw" && continue
        copy_finding "configs" "$fw"
        rpt "### firewall: ${fw##*/}" '```'
        head -n 500 "$fw" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""
    done < <(find "$ROOTFS" -type f \( -name "iptables*" -o -name "nftables*" -o \
        -name "firewall*" -o -name "*.rules" -path "*/iptables/*" \) -print0 2>/dev/null)
}

# ---------------------------------------------------------------------------
# stage 2 : super-server and network services (xinetd / inetd)
# ---------------------------------------------------------------------------

stage2_services() {
    local sc rel svc srv sargs usr grp iface port stype
    section "Super-Server and Network Services"

    log "enumerating super-server configurations (xinetd/inetd)..."
    N_SERVICES=0

    # xinetd services
    while IFS= read -r -d '' sc; do
        seen "$sc" && continue
        is_text "$sc" || continue
        rel="${sc#"$ROOTFS/"}"
        copy_finding "configs" "$sc"

        svc=$(grep -oE 'service\s+[A-Za-z0-9_-]+' "$sc" 2>/dev/null | awk '{print $2}' | head -1)
        [[ -z "$svc" ]] && svc="${sc##*/}"
        srv=$(grep -E 'server\s*=' "$sc" 2>/dev/null | sed 's/.*server\s*=\s*//' | tr -d ' \t' | head -1)
        sargs=$(grep -E 'server_args\s*=' "$sc" 2>/dev/null | sed 's/.*server_args\s*=\s*//' | head -1)
        usr=$(grep -E 'user\s*=' "$sc" 2>/dev/null | sed 's/.*user\s*=\s*//' | tr -d ' \t' | head -1)
        grp=$(grep -E 'group\s*=' "$sc" 2>/dev/null | sed 's/.*group\s*=\s*//' | tr -d ' \t' | head -1)
        iface=$(grep -E 'interface\s*=' "$sc" 2>/dev/null | sed 's/.*interface\s*=\s*//' | tr -d ' \t' | head -1)
        port=$(grep -E 'port\s*=' "$sc" 2>/dev/null | sed 's/.*port\s*=\s*//' | tr -d ' \t' | head -1)
        stype=$(grep -E 'socket_type\s*=' "$sc" 2>/dev/null | sed 's/.*socket_type\s*=\s*//' | tr -d ' \t' | head -1)

        N_SERVICES=$((N_SERVICES + 1))
        rpt "### Service: \`$svc\` (xinetd)"
        rpt "- config: \`$rel\`"
        [[ -n "$srv" ]] && rpt "- server: \`$srv\` ${sargs:+($sargs)}"
        [[ -n "$usr" ]] && rpt "- user/group: \`$usr\` / \`${grp:-unknown}\`"
        [[ -n "$iface" ]] && rpt "- interface: \`$iface\`"
        [[ -n "$port" ]] && rpt "- port: \`$port\` ($stype)"

        # Check for dangerous patterns in the target server script/binary
        local sev="medium"
        local srv_full="$ROOTFS/$srv"
        if [[ -f "$srv_full" ]] && grep -qE 'eval\b|exec\b|/bin/sh|/bin/bash' "$srv_full" 2>/dev/null; then
            sev="high"
            rpt "  - **WARNING**: server script utilizes dynamic command execution (eval/exec)"
        fi
        if [[ "$usr" == "root" ]]; then
            note "network_service" "$sev" "$sc" "xinetd service '$svc' runs as root: $srv"
        else
            note "network_service" "low" "$sc" "xinetd service '$svc' ($usr): $srv"
        fi
        rpt ""
    done < <(find "$ROOTFS" -type f \( -path "*/xinetd.d/*" -o -name "xinetd.conf" \) -print0 2>/dev/null)

    # inetd services
    while IFS= read -r -d '' sc; do
        seen "$sc" && continue
        is_text "$sc" || continue
        rel="${sc#"$ROOTFS/"}"
        copy_finding "configs" "$sc"
        rpt "### inetd config: \`$rel\`" '```'
        grep -vE '^\s*#|^\s*$' "$sc" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""
        note "network_service" medium "$sc" "inetd configuration active"
        N_SERVICES=$((N_SERVICES + 1))
    done < <(find "$ROOTFS" -type f -name "inetd.conf" -print0 2>/dev/null)

    rpt "- total network/super-server services enumerated: $N_SERVICES"
    rpt ""
}

# ---------------------------------------------------------------------------
# stage 2 : scheduled tasks and background automation
# ---------------------------------------------------------------------------

stage2_scheduled() {
    local cr rel line
    section "Scheduled Tasks and Background Jobs"

    log "auditing scheduled cron jobs and timers..."
    N_CRON=0

    while IFS= read -r -d '' cr; do
        seen "$cr" && continue
        is_text "$cr" || continue
        rel="${cr#"$ROOTFS/"}"
        local active_lines
        active_lines=$(grep -vE '^\s*#|^\s*$' "$cr" 2>/dev/null || true)
        [[ -z "$active_lines" ]] && continue

        copy_finding "configs" "$cr"
        rpt "### crontab: \`$rel\`" '```'
        printf '%s\n' "$active_lines" >> "$REPORT"
        rpt '```' ""

        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            N_CRON=$((N_CRON + 1))
            note "scheduled_task" medium "$cr" "cron job: ${line:0:100}"
        done <<< "$active_lines"
    done < <(find "$ROOTFS" -type f \( -name "crontab" -o -path "*/cron.*/*" -o \
        -path "*/crontabs/*" -o -name "*.timer" \) -print0 2>/dev/null)

    rpt "- scheduled task definitions found: $N_CRON"
    rpt ""
}

# ---------------------------------------------------------------------------
# stage 5 : binary static analysis
# ---------------------------------------------------------------------------

UNSAFE_FUNCS=(system popen execve strcpy strcat sprintf gets)

# normalise the readelf "Machine:" field to a short arch label
arch_short() {
    local m="$1"
    case "$m" in
        *MIPS*)         echo "MIPS" ;;
        *AArch64*)      echo "aarch64" ;;
        *ARM*)          echo "ARM" ;;
        *X86-64*|*x86-64*) echo "x86-64" ;;
        *80386*)        echo "x86" ;;
        *RISC-V*)       echo "RISC-V" ;;
        *PowerPC64*)    echo "PowerPC64" ;;
        *PowerPC*)      echo "PowerPC" ;;
        *)              echo "other" ;;
    esac
}

# relro classification: none | partial | full   ($1 = readelf -l, $2 = readelf -d)
relro_state() {
    case "$1" in *GNU_RELRO*)
        case "$2" in *BIND_NOW*) echo "full" ;; *) echo "partial" ;; esac ;;
    *) echo "none" ;; esac
}

stage5_binaries() {
    local bin arch f c missing line imp tok flag
    local rp mline relro hdr size linkage stripped symimports fort ph dy
    section "Binaries"

    # --- hardening + import census over every (unique) ELF binary ---
    log "hardening census over all ELF binaries..."
    N_ELF=0; N_WEAK=0; N_UNSAFE=0
    N_STATIC=0; N_UNSTRIP=0; N_FORT=0
    N_RELFULL=0; N_RELPART=0; N_RELNONE=0
    declare -A UFN_IMPORTS=()
    declare -A ARCH_TOT ARCH_WEAK ARCH_UNSAFE ARCH_FORT \
              ARCH_STATIC ARCH_UNSTRIP ARCH_NORELRO
    local census_db="$OUTDIR/.seen_census"
    : > "$census_db"
    : > "$CENSUS_TSV"
    while IFS= read -r -d '' bin; do
        file -b "$bin" 2>/dev/null | grep -q "ELF" || continue
        seen_db "$census_db" "$bin" && continue
        rp="${bin#"$ROOTFS/"}"
        N_ELF=$((N_ELF + 1))

        hdr=$(readelf -h "$bin" 2>/dev/null)
        mline=$(printf '%s\n' "$hdr" | grep -i "Machine:" | head -1)
        arch=$(arch_short "$mline")
        ph=$(readelf -l "$bin" 2>/dev/null)
        dy=$(readelf -d "$bin" 2>/dev/null)

        # linkage: has a dynamic section -> dynamic, else static
        [[ -n "$dy" ]] && linkage="dynamic" || linkage="static"

        # stripped? rely on section/symbol presence rather than file(1) wording
        if readelf -S "$bin" 2>/dev/null | grep -qE '\.symtab'; then
            stripped="no"
            N_UNSTRIP=$((N_UNSTRIP + 1))
        else
            stripped="yes"
        fi

        missing=""
        readelf -s "$bin" 2>/dev/null | grep -q "__stack_chk_fail" || missing+="NO_CANARY "
        printf '%s\n' "$hdr" | grep -q "DYN" || missing+="NO_PIE "
        printf '%s\n' "$ph" | grep -qE "GNU_STACK.* RW " || missing+="NO_NX "
        relro=$(relro_state "$ph" "$dy")
        case "$relro" in
            full)    N_RELFULL=$((N_RELFULL + 1)) ;;
            partial) N_RELPART=$((N_RELPART + 1)) ;;
            none)    N_RELNONE=$((N_RELNONE + 1)); missing+="NO_RELRO " ;;
        esac
        [[ -n "$missing" ]] && N_WEAK=$((N_WEAK + 1))
        [[ "$linkage" == "static" ]] && N_STATIC=$((N_STATIC + 1))

        symimports=$(readelf -Ws "$bin" 2>/dev/null | grep -a "UND")
        # FORTIFY_SOURCE: any *_chk import
        fort="no"
        if printf '%s\n' "$symimports" | grep -aqE '_chk(@|$)'; then
            fort="yes"; N_FORT=$((N_FORT + 1))
        fi
        # unsafe-function imports via the dynamic symbol table
        imp=$(printf '%s\n' "$symimports" | grep -aE "FUNC|OBJECT" | \
            grep -aoE '(system|popen|execve|strcpy|strcat|sprintf|gets)(@[A-Za-z0-9_.]+)?' \
            | sort -u)
        flag=0
        for tok in $imp; do
            case "$tok" in
                system|popen|execve|strcpy|strcat|sprintf|gets) ;;
                *) continue ;;
            esac
            UFN_IMPORTS[$tok]=$(( ${UFN_IMPORTS[$tok]:-0} + 1 ))
            flag=1
        done
        [[ "$flag" -eq 1 ]] && N_UNSAFE=$((N_UNSAFE + 1))

        # per-arch aggregates
        ARCH_TOT[$arch]=$(( ${ARCH_TOT[$arch]:-0} + 1 ))
        [[ -n "$missing" ]] && ARCH_WEAK[$arch]=$(( ${ARCH_WEAK[$arch]:-0} + 1 ))
        [[ "$flag" -eq 1 ]] && ARCH_UNSAFE[$arch]=$(( ${ARCH_UNSAFE[$arch]:-0} + 1 ))
        [[ "$fort" == "yes" ]] && ARCH_FORT[$arch]=$(( ${ARCH_FORT[$arch]:-0} + 1 ))
        [[ "$linkage" == "static" ]] && ARCH_STATIC[$arch]=$(( ${ARCH_STATIC[$arch]:-0} + 1 ))
        [[ "$stripped" == "no" ]] && ARCH_UNSTRIP[$arch]=$(( ${ARCH_UNSTRIP[$arch]:-0} + 1 ))
        [[ "$relro" == "none" ]] && ARCH_NORELRO[$arch]=$(( ${ARCH_NORELRO[$arch]:-0} + 1 ))

        size=$(stat -c%s "$bin" 2>/dev/null || stat -f%z "$bin" 2>/dev/null)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$relro" "$size" "$arch" "$linkage" "$stripped" "$fort" \
            "$([[ -n "$missing" ]] && echo 1 || echo 0)" \
            "$([[ "$flag" -eq 1 ]] && echo 1 || echo 0)" \
            "$([[ "$stripped" == "no" ]] && echo 1 || echo 0)" \
            "$([[ "$linkage" == "static" ]] && echo 1 || echo 0)" \
            "$bin" >> "$CENSUS_TSV"
    done < <(find "$ROOTFS" -type f -executable -print0 2>/dev/null)

    log "census: $N_ELF ELF; $N_WEAK weak; $N_UNSAFE unsafe-import; $N_FORT fortify"
    rpt "" "- analysed ELF binaries: $N_ELF"
    rpt "- ELF binaries missing >=1 hardening control: $N_WEAK"
    rpt "- ELF binaries importing an unsafe function: $N_UNSAFE"
    for f in $(printf '%s\n' "${!UFN_IMPORTS[@]}" | sort); do
        rpt "  - $f(): ${UFN_IMPORTS[$f]} binaries"
    done
    rpt ""
    rpt "- statically linked ELF binaries: $N_STATIC"
    rpt "- unstripped ELF binaries (debug syms): $N_UNSTRIP"
    rpt "- ELF binaries using FORTIFY_SOURCE (_chk): $N_FORT"
    rpt "- RELRO full: $N_RELFULL | partial: $N_RELPART | none: $N_RELNONE"
    rpt ""
    rpt "### Architecture breakdown"
    for arch in $(printf '%s\n' "${!ARCH_TOT[@]}" | sort); do
        local aline
        aline="- $arch: ${ARCH_TOT[$arch]} binaries (weak ${ARCH_WEAK[$arch]:-0}, "
        aline+="unsafe-import ${ARCH_UNSAFE[$arch]:-0}, fortify ${ARCH_FORT[$arch]:-0}, "
        aline+="static ${ARCH_STATIC[$arch]:-0}, unstripped ${ARCH_UNSTRIP[$arch]:-0}, "
        aline+="no-RELRO ${ARCH_NORELRO[$arch]:-0})"
        rpt "$aline"
    done

    # --- per-binary strings counts (methodology unchanged from v1) ---
    log "analysing executables with strings/readelf..."
    while IFS= read -r -d '' bin; do
        file -b "$bin" 2>/dev/null | grep -q "ELF" || continue
        seen "$bin" && continue
        arch=$(file -b "$bin" 2>/dev/null | grep -oE \
            '(ARM|MIPS|x86-64|x86|PowerPC|RISC-V|aarch64|i[3-6]86)' | head -1)
        dangerous=""
        stro=$(strings -a "$bin" 2>/dev/null)
        for f in "${UNSAFE_FUNCS[@]}"; do
            c=$(printf '%s\n' "$stro" | grep -cw "$f" 2>/dev/null || true)
            [[ "$c" -gt 0 ]] && dangerous+="$f($c) "
        done
        [[ -z "$dangerous" ]] && continue
        log "  ${bin##*/} [$arch]: $dangerous"
        ph=$(readelf -l "$bin" 2>/dev/null)
        dy=$(readelf -d "$bin" 2>/dev/null)
        relro=$(relro_state "$ph" "$dy")
        if readelf -Ws "$bin" 2>/dev/null | grep -aqE '_chk(@|$)'; then
            fort="yes"
        else
            fort="no"
        fi
        missing=""
        readelf -s "$bin" 2>/dev/null | grep -q "__stack_chk_fail" || missing+="NO_CANARY "
        readelf -h "$bin" 2>/dev/null | grep -q "DYN" || missing+="NO_PIE "
        printf '%s\n' "$ph" | grep -qE "GNU_STACK.* RW " || missing+="NO_NX "
        [[ "$relro" == "none" ]] && missing+="NO_RELRO "
        line="- \`${bin##*/}\` [$arch]: $dangerous"
        [[ -n "$missing" ]] && line+=" | missing: $missing"
        line+=" | RELRO: $relro | FORTIFY: $fort"
        rpt "$line"
        note "unsafe_binary" medium "$bin" "$dangerous${missing:+ missing: $missing} RELRO:$relro FORTIFY:$fort"
    done < <(find "$ROOTFS" -type f -executable -print0 2>/dev/null | head -z -n 200)
    rpt ""
}

# ---------------------------------------------------------------------------
# stage 5 (continued): embedded-secret scan + component version fingerprint
# on the largest unique ELF binaries (attribution to specific binaries).
# ---------------------------------------------------------------------------

stage5_binary_insight() {
    local limit rows tmp size path stro
    local n_pk n_cert n_cred n_url n_hp total rel line detail
    local ver_list v
    rpt "" "### Embedded secrets and component versions in binaries"

    [[ -s "$CENSUS_TSV" ]] || { rpt "- no ELF binaries to scan"; return; }
    log "scanning top-$BIN_SCAN_LIMIT ELF binaries for embedded secrets/versions..."
    limit="$BIN_SCAN_LIMIT"
    tmp="$OUTDIR/.secret_rows"
    : > "$tmp"
    : > "$OUTDIR/component_rows"

    # census rows: relro TAB size TAB arch TAB ... TAB path ; largest first
    mapfile -t rows < <(sort -s -t $'\t' -k2,2 -nr "$CENSUS_TSV" | head -n "$limit")
    for line in "${rows[@]:-}"; do
        [[ -n "$line" ]] || continue
        size=${line#*$'\t'}; size=${size%%$'\t'*}
        path=${line##*$'\t'}
        [[ -r "$path" ]] || continue
        # skip pathological sizes
        if [[ "${size:-0}" -gt 300000000 ]]; then continue; fi

        stro=$(strings -a -n 6 "$path" 2>/dev/null)

        n_pk=$(printf '%s\n' "$stro" | grep -acE 'BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY' 2>/dev/null || true); n_pk=${n_pk:-0}
        n_cert=$(printf '%s\n' "$stro" | grep -acE 'BEGIN CERTIFICATE' 2>/dev/null || true); n_cert=${n_cert:-0}
        n_cred=$(printf '%s\n' "$stro" | grep -acEi '(password|passwd|secret|token|api[_-]?key|psk)[[:space:]]*[:=][[:space:]]*["'\''A-Za-z0-9]' 2>/dev/null || true); n_cred=${n_cred:-0}
        n_url=$(printf '%s\n' "$stro" | grep -acE 'https?://' 2>/dev/null || true); n_url=${n_url:-0}
        n_hp=$(printf '%s\n' "$stro" | grep -acE '\b([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}\b' 2>/dev/null || true); n_hp=${n_hp:-0}

        total=$((n_pk + n_cert + n_cred + n_url + n_hp))
        if [[ "$total" -gt 0 ]]; then
            N_BIN_SECRET=$((N_BIN_SECRET + 1))
            example=$(printf '%s\n' "$stro" | grep -aE 'BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|BEGIN CERTIFICATE' | head -1)
            [[ -z "$example" ]] && example=$(printf '%s\n' "$stro" | grep -aEi '(password|secret|token|api[_-]?key|psk)[[:space:]]*[:=]' | head -1)
            [[ -z "$example" ]] && example=$(printf '%s\n' "$stro" | grep -aE 'https?://' | head -1)
            rel="${path#"$ROOTFS/"}"
            printf '%s\t%s\tpk=%s cert=%s cred=%s url=%s hostport=%s\t%s\n' \
                "$total" "$rel" "$n_pk" "$n_cert" "$n_cred" "$n_url" "$n_hp" \
                "${example:0:90}" >> "$tmp"
            if [[ "$n_pk" -gt 0 || "$n_cert" -gt 0 ]]; then
                note "embedded_secret" high "$path" \
                    "embedded key/cert headers (pk=$n_pk cert=$n_cert)"
            elif [[ "$n_cred" -ge 5 ]]; then
                note "embedded_secret" medium "$path" "embedded credential strings"
            fi
        fi

        # component version fingerprint (match the version token itself)
        ver_list=""
        v=$(printf '%s\n' "$stro" | grep -aoE 'OpenSSL[ /][0-9]+(\.[0-9]+){1,3}[a-z]?' 2>/dev/null | head -1);        [[ -n "$v" ]] && ver_list+="$v; "
        v=$(printf '%s\n' "$stro" | grep -aoE 'GNU C Library[^\n]{0,80}version [0-9]+(\.[0-9]+)+' 2>/dev/null | head -1); [[ -n "$v" ]] && ver_list+="glibc ${v##*version }; "
        v=$(printf '%s\n' "$stro" | grep -aoE 'BusyBox v[0-9]+\.[0-9]+(\.[0-9]+)?' 2>/dev/null | head -1);         [[ -n "$v" ]] && ver_list+="$v; "
        v=$(printf '%s\n' "$stro" | grep -aoE 'libcurl/[0-9]+\.[0-9]+(\.[0-9]+)?' 2>/dev/null | head -1);         [[ -n "$v" ]] && ver_list+="$v; "
        v=$(printf '%s\n' "$stro" | grep -aoE 'uhttpd[ /][0-9]+(\.[0-9]+)?' 2>/dev/null | head -1);               [[ -n "$v" ]] && ver_list+="$v; "
        v=$(printf '%s\n' "$stro" | grep -aoE 'Dropbear SSH server v[0-9]+\.[0-9]+' 2>/dev/null | head -1);        [[ -n "$v" ]] && ver_list+="$v; "
        v=$(printf '%s\n' "$stro" | grep -aoE '[Ss]trong[Ss]wan [0-9]+\.[0-9]+' 2>/dev/null | head -1);            [[ -n "$v" ]] && ver_list+="$v; "
        v=$(printf '%s\n' "$stro" | grep -aoE 'OpenSSH[ _][0-9]+\.[0-9]+(p[0-9]+)?' 2>/dev/null | head -1);        [[ -n "$v" ]] && ver_list+="$v; "
        v=$(printf '%s\n' "$stro" | grep -aoE 'tcpdump version [0-9]+\.[0-9]+' 2>/dev/null | head -1);             [[ -n "$v" ]] && ver_list+="$v; "
        if [[ -n "$ver_list" ]]; then
            rel="${path#"$ROOTFS/"}"
            printf '%s\t%s\n' "$rel" "${ver_list%; }" >> "$OUTDIR/component_rows"
            N_BIN_VER=$((N_BIN_VER + 1))
        fi
    done

    rpt ""
    rpt "#### Binaries containing embedded secret patterns"
    rpt ""
    if [[ -s "$tmp" ]]; then
        # sort by hit count desc, then path
        sort -s -t $'\t' -k1,1 -nr -k2,2 "$tmp" | head -n 60 | \
        while IFS=$'\t' read -r total rel detail; do
            rpt "- \`$rel\`: $detail"
        done
        rpt ""
        rpt "- ELF binaries with embedded secrets (top ${BIN_SCAN_LIMIT} scanned): $N_BIN_SECRET"
    else
        rpt "- no embedded secret strings found in the analysed binaries"
    fi

    rpt ""
    rpt "#### Component version fingerprint"
    rpt ""
    if [[ -s "$OUTDIR/component_rows" ]]; then
        sort -s -t $'\t' -k1,1 "$OUTDIR/component_rows" | head -n 40 | \
        while IFS=$'\t' read -r rel detail; do
            rpt "- \`$rel\`: $detail"
        done
        rpt ""
        rpt "- ELF binaries with identifiable component versions: $N_BIN_VER"
    else
        rpt "- no identifiable component versions found"
    fi
    rpt ""
}

# ---------------------------------------------------------------------------
# stage 5 : privilege and permissions audit (SUID / SGID / world-writable)
# ---------------------------------------------------------------------------

stage_permissions() {
    local sf rel mode sz user group perm_str bname
    local is_suid is_sgid
    section "Privilege and Permissions Audit"

    log "auditing SUID/SGID binaries and world-writable files..."
    N_SUID=0; N_SGID=0; N_WW=0; N_SUID_WEAK=0

    local perm_db="$OUTDIR/.seen_perms"
    : > "$perm_db"

    rpt "### SUID and SGID Binaries"
    rpt ""
    rpt "| permissions | user:group | size | binary | risk flags |"
    rpt "|-------------|------------|------|--------|------------|"

    while IFS= read -r -d '' sf; do
        seen_db "$perm_db" "$sf" && continue
        mode=$(stat -c%a "$sf" 2>/dev/null || stat -f%Lp "$sf" 2>/dev/null || echo 0)
        perm_str=$(stat -c%A "$sf" 2>/dev/null || stat -f%Sp "$sf" 2>/dev/null || echo "")
        user=$(stat -c%U "$sf" 2>/dev/null || stat -f%Su "$sf" 2>/dev/null || echo "unknown")
        group=$(stat -c%G "$sf" 2>/dev/null || stat -f%Sg "$sf" 2>/dev/null || echo "unknown")
        sz=$(stat -c%s "$sf" 2>/dev/null || stat -f%z "$sf" 2>/dev/null || echo 0)
        rel="${sf#"$ROOTFS/"}"
        bname="${sf##*/}"

        is_suid=0; is_sgid=0
        [[ "$mode" =~ ^[4-7]...$ ]] && is_suid=1
        [[ "$mode" =~ ^[2367]...$ ]] && is_sgid=1

        [[ "$is_suid" -eq 1 ]] && N_SUID=$((N_SUID + 1))
        [[ "$is_sgid" -eq 1 ]] && N_SGID=$((N_SGID + 1))

        # Check ELF hardening on SUID binary
        local risk=""
        if file -b "$sf" 2>/dev/null | grep -q "ELF"; then
            local hdr ph
            hdr=$(readelf -h "$sf" 2>/dev/null)
            ph=$(readelf -l "$sf" 2>/dev/null)
            readelf -s "$sf" 2>/dev/null | grep -q "__stack_chk_fail" || risk+="NO_CANARY "
            printf '%s\n' "$hdr" | grep -q "DYN" || risk+="NO_PIE "
            printf '%s\n' "$ph" | grep -qE "GNU_STACK.* RW " || risk+="EXEC_STACK "
            if [[ -n "$risk" ]]; then
                N_SUID_WEAK=$((N_SUID_WEAK + 1))
            fi
        fi

        case "$bname" in
            busybox|su|sh|bash|dash|python*|perl|awk|find|tar|chmod|chown)
                risk+="CRITICAL_BIN "
                note "suid_root" high "$sf" "high-risk SUID binary: $bname ($perm_str) [${risk:-HARDENED}]"
                ;;
            *)
                if [[ -n "$risk" ]]; then
                    note "suid_root" high "$sf" "SUID binary lacking hardening: $bname ($risk)"
                else
                    note "suid_root" medium "$sf" "SUID binary: $bname ($perm_str)"
                fi
                ;;
        esac

        rpt "| \`$perm_str\` | \`$user:$group\` | $sz | \`$rel\` | **${risk:-clean}** |"
    done < <(find "$ROOTFS" -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)

    rpt ""
    rpt "- SUID binaries: $N_SUID"
    rpt "- SGID binaries: $N_SGID"
    rpt "- SUID binaries missing hardening: $N_SUID_WEAK"
    rpt ""

    # World-writable files in system paths
    rpt "### World-Writable Files in System Paths"
    rpt ""
    while IFS= read -r -d '' sf; do
        [[ -L "$sf" ]] && continue
        seen "$sf" && continue
        rel="${sf#"$ROOTFS/"}"
        perm_str=$(stat -c%A "$sf" 2>/dev/null || stat -f%Sp "$sf" 2>/dev/null || echo "")
        user=$(stat -c%U "$sf" 2>/dev/null || stat -f%Su "$sf" 2>/dev/null || echo "unknown")
        N_WW=$((N_WW + 1))
        rpt "- \`$rel\` ($perm_str, owner: $user)"
        note "world_writable" high "$sf" "world-writable file: $perm_str"
    done < <(find "$ROOTFS" -type f -perm -0002 \( -path "*/etc/*" -o -path "*/usr/*" \
        -o -path "*/bin/*" -o -path "*/sbin/*" -o -path "*/lib/*" -o -path "*/opt/*" \) \
        -print0 2>/dev/null | head -z -n 50)

    rpt ""
    rpt "- world-writable files in system paths: $N_WW"
    rpt ""
}

# ---------------------------------------------------------------------------
# stage 5 : kernel modules and driver security census
# ---------------------------------------------------------------------------

stage_kernel_modules() {
    local ko rel bname info author desc lic vmagic parms deps
    local kmod_tsv="$OUTDIR/kernel_modules.tsv"
    section "Kernel Modules and Drivers"

    log "cataloging kernel modules (.ko)..."
    N_KMOD=0; N_KMOD_PROP=0
    : > "$kmod_tsv"

    local kmod_db="$OUTDIR/.seen_kmod"
    : > "$kmod_db"

    rpt "| module | license | vermagic | author / description | parameters |"
    rpt "|--------|---------|----------|----------------------|------------|"

    while IFS= read -r -d '' ko; do
        seen_db "$kmod_db" "$ko" && continue
        bname="${ko##*/}"
        rel="${ko#"$ROOTFS/"}"
        N_KMOD=$((N_KMOD + 1))

        author=""; desc=""; lic=""; vmagic=""; parms=""; deps=""
        if have modinfo; then
            info=$(modinfo "$ko" 2>/dev/null || true)
            author=$(printf '%s\n' "$info" | grep -m1 '^author:' | sed 's/^author:\s*//' | tr -d '\t\r\n')
            desc=$(printf '%s\n' "$info" | grep -m1 '^description:' | sed 's/^description:\s*//' | tr -d '\t\r\n')
            lic=$(printf '%s\n' "$info" | grep -m1 '^license:' | sed 's/^license:\s*//' | tr -d '\t\r\n')
            vmagic=$(printf '%s\n' "$info" | grep -m1 '^vermagic:' | sed 's/^vermagic:\s*//' | tr -d '\t\r\n')
            deps=$(printf '%s\n' "$info" | grep -m1 '^depends:' | sed 's/^depends:\s*//' | tr -d '\t\r\n')
            parms=$(printf '%s\n' "$info" | grep '^parm:' | sed 's/^parm:\s*//' | tr '\n' '; ' | sed 's/; $//')
        fi
        if [[ -z "$lic" ]]; then
            local mstrs
            mstrs=$(strings -a "$ko" 2>/dev/null | grep -E '^(license|author|description|vermagic|parm)=' || true)
            lic=$(printf '%s\n' "$mstrs" | grep -m1 '^license=' | cut -d= -f2-)
            author=$(printf '%s\n' "$mstrs" | grep -m1 '^author=' | cut -d= -f2-)
            desc=$(printf '%s\n' "$mstrs" | grep -m1 '^description=' | cut -d= -f2-)
            vmagic=$(printf '%s\n' "$mstrs" | grep -m1 '^vermagic=' | cut -d= -f2-)
            parms=$(printf '%s\n' "$mstrs" | grep '^parm=' | cut -d= -f2- | tr '\n' '; ' | sed 's/; $//')
        fi

        lic="${lic:-unspecified}"
        case "$lic" in
            *GPL*|*BSD*|*MIT*|*Dual*) ;;
            *)
                N_KMOD_PROP=$((N_KMOD_PROP + 1))
                lic="**PROPRIETARY** ($lic)"
                ;;
        esac

        local auth_desc=""
        [[ -n "$author" ]] && auth_desc+="$author"
        if [[ -n "$desc" ]]; then
            [[ -n "$auth_desc" ]] && auth_desc+=" - $desc" || auth_desc="$desc"
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$bname" "$lic" "${vmagic:0:50}" "${auth_desc:0:60}" "${parms:0:80}" "$rel" >> "$kmod_tsv"

        rpt "| \`$bname\` | $lic | \`${vmagic:0:35}\` | ${auth_desc:0:45} | ${parms:0:50} |"
        note "kernel_module" low "$ko" "driver $bname ($lic): $auth_desc"
    done < <(find "$ROOTFS" -type f -name "*.ko" -print0 2>/dev/null | sort -z)

    rpt ""
    rpt "- total kernel modules (.ko) cataloged: $N_KMOD"
    rpt "- proprietary / out-of-tree modules: $N_KMOD_PROP"
    rpt ""
}

# ---------------------------------------------------------------------------
# startup scripts
# ---------------------------------------------------------------------------

stage2_startup() {
    local s
    section "Startup Scripts"

    while IFS= read -r -d '' s; do
        is_text "$s" || continue
        seen "$s" && continue
        rpt "- \`$s\`"
        if grep -lEi '(password|passwd|secret|key|token)\s*[:=]' "$s" &>/dev/null; then
            rpt "  - contains credential references"
        fi
        if grep -lEi '(telnet|nc -l|socat|ncat).*listen' "$s" &>/dev/null; then
            rpt "  - network listener (possible backdoor)"
        fi
    done < <(find "$ROOTFS" -type f \( -path "*/init.d/*" -o -path "*/rc.d/*" -o \
        -path "*/systemd/system/*.service" -o -name "rc.local" -o -name "inittab" \
        -path "*/etc/*" \) -print0 2>/dev/null)
    rpt ""
}

# ---------------------------------------------------------------------------
# stage 6 : debug interface enumeration
# ---------------------------------------------------------------------------

stage6_debug() {
    local tref pat h file line bind exp sev
    section "Debug and Backdoor Indicators"

    tref=$(grep -ciE 'telnet.*(127\.0\.0\.1|localhost|0\.0\.0\.0)' "$STRINGS_DUMP" 2>/dev/null || true)
    tref=${tref:-0}
    if [[ "$tref" -gt 0 ]]; then
        rpt "### debug consoles" '```'
        grep -Ei 'telnet.*(127\.0\.0\.1|localhost|0\.0\.0\.0)' "$STRINGS_DUMP" 2>/dev/null | \
            sort -u | head -n 20 >> "$REPORT"
        rpt '```' ""
    fi

    for pat in "backdoor" "master.key" "master_password" "super.admin" "superadmin" \
        "debug_shell" "reverse.shell" "bind.shell" "god.mode" "test_mode" \
        "factory_reset" "hidden_user" "maintenance_mode"; do
        h=$(grep -ci "$pat" "$STRINGS_DUMP" 2>/dev/null || true)
        h=${h:-0}
        [[ "$h" -gt 0 ]] && rpt "- \`$pat\`: $h references"
    done

    # --- stage 6: debug service enumeration in startup/config material ---
    rpt "" "### Debug interface enumeration"
    local re='(telnet|gdbserver|dropbear|ser2net|socat|ncat|\bnc -l\b|/dev/ttyS[0-9]|console=|jtag|debugd)'
    N_CONSOLE=0; N_LISTENER=0
    # stage-local content dedup (the global seen() db is already populated by
    # earlier scan passes over the same startup files)
    local debug_db="$OUTDIR/.seen_debug"
    : > "$debug_db"
    while IFS= read -r -d '' file; do
        is_text "$file" || continue
        seen_db "$debug_db" "$file" && continue
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            # skip pure-comment context (mentions of a telnet session are
            # not evidence of a debug service being started)
            case "${line#"${line%%[![:space:]]*}"}" in \#*) continue ;; esac
            bind="bind-unknown"
            case "$line" in
                *127.0.0.1*|*localhost*)   bind="loopback" ;;
                *0.0.0.0*) bind="network-exposed" ;;
            esac
            case "$bind" in loopback) sev="low" ;; network-exposed) sev="high" ;;
                *) sev="medium" ;; esac
            case "$line" in
                *telnetd*|*telnet*) N_CONSOLE=$((N_CONSOLE + 1)) ;;
                *gdbserver*|*debugd*|*ser2net*) N_CONSOLE=$((N_CONSOLE + 1)) ;;
                *"nc -l"*|*socat*|*ncat*) N_LISTENER=$((N_LISTENER + 1)) ;;
            esac
            rpt "- [${bind}] \`${file#"$ROOTFS/"}\`: ${line:0:160}"
            note "debug_service" "$sev" "$file" \
                "$bind debug service: ${line:0:160}"
        done < <(grep -aE "$re" "$file" 2>/dev/null | head -n 15)
    done < <(find "$ROOTFS" -type f \( -path "*/init.d/*" -o -path "*/rc.d/*" -o \
        -path "*/rcS.d/*" -o -name "inittab" -o -name "*.service" -o \
        -path "*/systemd/*" -o -name "*.sh" -o -path "*/scripts/*" -o \
        -name ".profile" -o -name "profile" -o -name ".bashrc" \) \
        -print0 2>/dev/null | head -z -n 400)
    rpt "" "- debug consoles/services referenced: $N_CONSOLE"
    rpt "- raw listeners referenced: $N_LISTENER"

    # vpn material (unchanged from v1)
    while IFS= read -r -d '' file; do
        seen "$file" && continue
        copy_finding "configs" "$file"
        rpt "- VPN config: \`$file\`"
    done < <(find "$ROOTFS" -type f \( -name "*.ovpn" -o -name "openvpn*" -o \
        -name "vpn*" -o -path "*/openvpn/*" -o -name "wg*.conf" \) -print0 2>/dev/null)
    rpt ""
}

# ---------------------------------------------------------------------------
# web interfaces
# ---------------------------------------------------------------------------

stage5_web() {
    local w func d
    section "Web Interfaces"

    while IFS= read -r -d '' w; do
        seen "$w" && continue
        rpt "- \`$w\`"
        if [[ "$w" == *.php || "$w" == *.cgi ]]; then
            for func in eval exec system passthru shell_exec popen proc_open; do
                if grep -q "$func" "$w" 2>/dev/null; then
                    rpt "  - uses $func()"
                    note "unsafe_web" medium "$w" "uses $func()"
                fi
            done
        fi
    done < <(find "$ROOTFS" -type f \( -name "httpd.conf" -o -name "nginx.conf" -o \
        -name "lighttpd.conf" -o -name "apache2.conf" -o -name "uhttpd*" -o \
        -name "*.php" -path "*/www/*" -o -name "*.cgi" \) -print0 2>/dev/null | \
        head -z -n 50)

    while IFS= read -r -d '' d; do
        seen "$d" && continue
        rpt "- debug file: \`$d\`"
    done < <(find "$ROOTFS" -type f \( -name "phpinfo*" -o -name "adminer*" -o \
        -name "phpmyadmin*" -o -name "info.php" -o -name "test.php" -o \
        -name "debug.php" \) -print0 2>/dev/null)
    rpt ""
}

# ---------------------------------------------------------------------------
# stage 5 : kernel and system security configuration (sysctl)
# ---------------------------------------------------------------------------

stage_sysctl() {
    local sc rel
    section "Kernel and Network Security Configuration (sysctl)"

    log "auditing sysctl configurations..."
    while IFS= read -r -d '' sc; do
        seen "$sc" && continue
        is_text "$sc" || continue
        rel="${sc#"$ROOTFS/"}"
        copy_finding "configs" "$sc"

        rpt "### sysctl: \`$rel\`"
        if grep -qi "LAB MODE" "$sc" 2>/dev/null; then
            rpt "> [!WARNING]"
            rpt "> Test / Lab mode configuration active in production image!"
            note "test_artifact" medium "$sc" "sysctl file indicates LAB MODE ONLY"
        fi
        rpt '```'
        grep -vE '^\s*#|^\s*$' "$sc" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""

        if grep -qE 'net\.ipv4\.ip_forward\s*=\s*1' "$sc" 2>/dev/null; then
            note "hardening" low "$sc" "IPv4 forwarding enabled (routing appliance)"
        fi
        if grep -qE 'kernel\.randomize_va_space\s*=\s*0' "$sc" 2>/dev/null; then
            rpt "- **WARNING**: ASLR explicitly disabled (kernel.randomize_va_space = 0)"
            note "hardening" high "$sc" "ASLR explicitly disabled (randomize_va_space = 0)"
        fi
    done < <(find "$ROOTFS" -type f \( -name "sysctl.conf" -o -name "sysctl_*.conf" \
        -o -path "*/sysctl.d/*" \) -print0 2>/dev/null)
    rpt ""
}

# ---------------------------------------------------------------------------
# bootloader, flash storage partitions and hardware assets
# ---------------------------------------------------------------------------

stage_boot_hardware() {
    local be rel fpg sz ftype
    section "Bootloader, Storage Partitions and Hardware Assets"

    log "inspecting bootloader environments and hardware blobs..."
    N_FPGA=0

    # U-Boot fw_env.config
    while IFS= read -r -d '' be; do
        seen "$be" && continue
        is_text "$be" || continue
        rel="${be#"$ROOTFS/"}"
        copy_finding "configs" "$be"
        rpt "### U-Boot Environment Layout (\`${be##*/}\`)" '```'
        grep -vE '^\s*#|^\s*$' "$be" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""
        note "boot_config" low "$be" "U-Boot flash environment configuration"
    done < <(find "$ROOTFS" -type f \( -name "fw_env.config" -o -name "uEnv.txt" -o -name "boot.scr" \) -print0 2>/dev/null)

    # Hardware blobs / FPGA bitstreams
    while IFS= read -r -d '' fpg; do
        seen "$fpg" && continue
        rel="${fpg#"$ROOTFS/"}"
        sz=$(stat -c%s "$fpg" 2>/dev/null || stat -f%z "$fpg" 2>/dev/null || echo 0)
        ftype=$(file -b "$fpg" 2>/dev/null || echo "unknown")
        N_FPGA=$((N_FPGA + 1))
        copy_finding "configs" "$fpg"
        rpt "- **Hardware blob / FPGA:** \`$rel\` ($sz bytes, $ftype)"
        note "hardware_asset" info "$fpg" "FPGA/coprocessor image: ${fpg##*/}"
    done < <(find "$ROOTFS" -type f \( -name "*.rbf" -o -name "*.bit" -o -name "*fpga*" \) -print0 2>/dev/null)

    rpt ""
    rpt "- hardware bitstreams/coprocessor blobs identified: $N_FPGA"
    rpt ""
}

# ---------------------------------------------------------------------------
# firmware metadata
# ---------------------------------------------------------------------------

stage_metadata() {
    local osf kc dc arch_info b
    section "Firmware Metadata"

    while IFS= read -r -d '' osf; do
        is_text "$osf" || continue
        seen "$osf" && continue
        rpt "### ${osf##*/}" '```'
        cat "$osf" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""
    done < <(find "$ROOTFS" -type f \( -name "os-release" -o -name "lsb-release" -o \
        -name "issue" -o -name "version" -o -name "buildinfo" -o -name "BUILD_INFO" \) \
        -path "*/etc/*" -print0 2>/dev/null)

    while IFS= read -r -d '' kc; do
        is_text "$kc" || continue
        seen "$kc" && continue
        rpt "### kernel config" '```'
        grep -E '^CONFIG_(SECURITY|SECCOMP|DEBUG|CRYPTO|KEYS|SELINUX|APPARMOR)' \
            "$kc" 2>/dev/null | sort >> "$REPORT" || true
        rpt '```' ""
        dc=$(grep -c '^CONFIG_DEBUG' "$kc" 2>/dev/null || true)
        dc=${dc:-0}
        [[ "$dc" -gt 5 ]] && rpt "- $dc kernel debug options enabled"
    done < <(find "$ROOTFS" -type f \( -name "config-*" -path "*/boot/*" -o \
        -name ".config" \) -print0 2>/dev/null)

    arch_info=$(find "$ROOTFS" -type f -executable -print0 2>/dev/null | \
        head -z -n 5 | while IFS= read -r -d '' b; do
            file -b "$b" 2>/dev/null | grep -oE \
                '(ARM|MIPS|x86-64|aarch64|PowerPC|RISC-V|i[3-6]86)' | head -1
        done | sort -u | head -1)
    [[ -n "${arch_info:-}" ]] && rpt "- architecture: $arch_info"
}

# ---------------------------------------------------------------------------
# crypto material references + key classification table (stage 3 output)
# ---------------------------------------------------------------------------

stage3_crypto() {
    local ks cc d kfile kclass ftype
    section "Crypto Material"

    grep -Ei '(AES|DES|RSA|ECDSA|HMAC|SHA256|MD5)' "$STRINGS_DUMP" 2>/dev/null | \
        grep -Ei '(key|secret|password|salt|iv|nonce)' | sort -u | head -n 30 > \
        "$FINDINGS/credentials/crypto_refs.txt"
    cc=$(wc -l < "$FINDINGS/credentials/crypto_refs.txt" 2>/dev/null || echo 0)
    if [[ "$cc" -gt 0 ]]; then
        rpt "### crypto references ($cc)" '```'
        cat "$FINDINGS/credentials/crypto_refs.txt" >> "$REPORT"
        rpt '```' ""
    fi

    while IFS= read -r -d '' ks; do
        seen "$ks" && continue
        copy_finding "keys" "$ks"
        rpt "- keystore: \`$ks\`"
    done < <(find "$ROOTFS" -type f \( -name "*.p12" -o -name "*.pfx" -o -name "*.jks" \
        -o -name "*.bks" \) -print0 2>/dev/null)

    # --- key classification table (paper 4.2 fix) ---
    PRIV_PLAIN=0; PRIV_ENC=0; PUB_KEYS=0
    rpt "" "### Key classification"
    rpt ""
    rpt "| file | class | type |"
    rpt "|------|-------|------|"
    while IFS= read -r -d '' kfile; do
        kclass=$(key_class "$kfile")
        ftype=$(file -b "$kfile" 2>/dev/null)
        case "$kclass" in
            private)   PRIV_PLAIN=$((PRIV_PLAIN + 1)) ;;
            encrypted) PRIV_ENC=$((PRIV_ENC + 1)) ;;
            public)    PUB_KEYS=$((PUB_KEYS + 1)) ;;
        esac
        rpt "| \`${kfile#"$FINDINGS/keys/"}\` | $kclass | ${ftype:0:60} |"
    done < <(find "$FINDINGS/keys" -type f -print0 2>/dev/null | sort -z)
    rpt ""
}

# ---------------------------------------------------------------------------
# interesting files (databases, config files carrying secrets)
# ---------------------------------------------------------------------------

stage_interesting() {
    local db sz cfg
    section "Interesting Files"

    while IFS= read -r -d '' db; do
        seen "$db" && continue
        sz=$(stat -c%s "$db" 2>/dev/null || stat -f%z "$db" 2>/dev/null)
        rpt "- \`${db##*/}\` ($sz bytes)"
    done < <(find "$ROOTFS" -type f \( -name "*.db" -o -name "*.sqlite" -o \
        -name "*.sqlite3" -o -name "*.sql" -o -name "*.mdb" \) -print0 2>/dev/null)

    while IFS= read -r -d '' cfg; do
        is_text "$cfg" || continue
        grep -lEi '(password|passwd|secret|key|token|credential)\s*[:=]' "$cfg" \
            &>/dev/null || continue
        seen "$cfg" && continue
        copy_finding "configs" "$cfg"
        rpt "- secrets in: \`$cfg\`"
        note "config_secret" medium "$cfg" "config file contains secret-pattern matches"
    done < <(find "$ROOTFS" -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" \
        -o -name "*.yaml" -o -name "*.yml" -o -name "*.json" -o -name "*.xml" -o \
        -name "*.properties" -o -name "*.env" -o -name ".env*" \) -size +0c \
        -print0 2>/dev/null)
}

# ---------------------------------------------------------------------------
# synthesis / report summary
# ---------------------------------------------------------------------------

synthesize() {
    local certs_n conf_n cred_n hash_n
    section "Summary"

    certs_n=$(find "$FINDINGS/certs" -type f 2>/dev/null | wc -l | tr -d ' ')
    conf_n=$(find "$FINDINGS/configs" -type f 2>/dev/null | wc -l | tr -d ' ')
    cred_n=$(find "$FINDINGS/credentials" -type f -size +0c 2>/dev/null | wc -l | tr -d ' ')
    hash_n=$(wc -l < "$FINDINGS/hashes/crackable.txt" 2>/dev/null || echo 0)

    cat >> "$REPORT" <<EOF

| category | count |
|----------|-------|
| private keys (plaintext) | ${PRIV_PLAIN:-0} |
| private keys (encrypted) | ${PRIV_ENC:-0} |
| public keys | ${PUB_KEYS:-0} |
| certificates | $certs_n |
| config files | $conf_n |
| credential files | $cred_n |
| crackable hashes | $hash_n |
| hashes cracked | ${HASH_CRACKED:-0} |
| ELF binaries analysed | ${N_ELF:-0} |
| ELF binaries missing hardening | ${N_WEAK:-0} |
| ELF binaries importing unsafe fn | ${N_UNSAFE:-0} |
| statically linked ELF binaries | ${N_STATIC:-0} |
| unstripped ELF binaries | ${N_UNSTRIP:-0} |
| ELF binaries with FORTIFY | ${N_FORT:-0} |
| ELF binaries with no RELRO | ${N_RELNONE:-0} |
| ELF binaries with embedded secrets | ${N_BIN_SECRET:-0} |
| ELF binaries with known component ver | ${N_BIN_VER:-0} |
| debug consoles/services referenced | ${N_CONSOLE:-0} |
| SUID binaries | ${N_SUID:-0} |
| SGID binaries | ${N_SGID:-0} |
| SUID binaries missing hardening | ${N_SUID_WEAK:-0} |
| world-writable files (system paths) | ${N_WW:-0} |
| kernel modules (.ko) cataloged | ${N_KMOD:-0} |
| proprietary kernel modules | ${N_KMOD_PROP:-0} |
| super-server/network services | ${N_SERVICES:-0} |
| scheduled tasks (cron) | ${N_CRON:-0} |
| dedicated secret files | ${N_SECRET_FILES:-0} |
| weak/expired certificates | ${N_WEAK_CERTS:-0} |
| hardware/FPGA blobs | ${N_FPGA:-0} |
| extracted files | ${FILE_COUNT:-0} |
| strings indexed | ${STR_COUNT:-0} |
EOF
}

# ---------------------------------------------------------------------------
# machine-readable findings (findings.json)
# ---------------------------------------------------------------------------

emit_json() {
    if have python3; then
        ITEMS="$ITEMS" REPORT="$REPORT" \
        FW_NAME="$FW_NAME" FW_SIZE="${FW_SIZE:-0}" OUTDIR="$OUTDIR" \
        FW_VER="$VERSION" \
        python3 - "$OUTDIR/findings.json" <<'PY'
import json, os, sys

out = sys.argv[1]
items = []
with open(os.environ["ITEMS"], encoding="utf-8", errors="replace") as fh:
    for ln in fh:
        p = ln.rstrip("\n").split("\t")
        if len(p) == 4:
            items.append({"category": p[0], "severity": p[1],
                          "path": p[2], "detail": p[3]})

summary = {}
with open(os.environ["REPORT"], encoding="utf-8", errors="replace") as fh:
    text = fh.read()
head = text.rfind("## Summary")
if head != -1:
    table = text[head:]
    for ln in table.splitlines():
        if ln.startswith("|") and "category" not in ln \
                and not ln.replace(" ", "").startswith("|---"):
            cells = [c.strip() for c in ln.strip("|").split("|")]
            if len(cells) == 2 and cells[1].lstrip("-").isdigit():
                summary[cells[0]] = int(cells[1])

doc = {
    "tool": {"name": "fw-extract.sh", "version": os.environ.get("FW_VER", "2.2.0")},
    "firmware": {"file": os.environ.get("FW_NAME", ""),
                 "size_bytes": int(os.environ.get("FW_SIZE", "0") or 0)},
    "output_dir": os.environ.get("OUTDIR", ""),
    "summary": summary,
    "counts_by_category": {},
    "findings": items,
}
for it in items:
    doc["counts_by_category"][it["category"]] = \
        doc["counts_by_category"].get(it["category"], 0) + 1

with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
print(f"[*] wrote {out}")
PY
    else
        warn "python3 unavailable - skipping findings.json"
    fi
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

main() {
    FIRMWARE="${1:?usage: $0 <firmware_file|extracted_dir> [output_dir]}"
    out_arg="${2:-fw_analysis_$(date +%Y%m%d_%H%M%S)}"

    [[ -e "$FIRMWARE" ]] || die "$FIRMWARE not found"

    OUTDIR="$out_arg"
    REPORT="$OUTDIR/REPORT.md"
    EXTRACT="$OUTDIR/extracted"
    FINDINGS="$OUTDIR/findings"
    STRINGS_DUMP="$OUTDIR/all_strings.txt"
    ITEMS="$OUTDIR/items.tsv"
    SEEN="$OUTDIR/.seen"
    CENSUS_TSV="$OUTDIR/census.tsv"

    mkdir -p "$OUTDIR" "$EXTRACT" "$FINDINGS"/{keys,certs,configs,credentials,hashes,modules}
    : > "$SEEN"
    : > "$ITEMS"
    : > "$FINDINGS/hashes/crackable.txt"

    FW_SIZE=0
    if [[ -f "$FIRMWARE" ]]; then
        FW_SIZE=$(stat -c%s "$FIRMWARE" 2>/dev/null || stat -f%z "$FIRMWARE")
        FW_NAME=$(basename "$FIRMWARE")
        cat > "$REPORT" <<EOF
# Firmware Security Analysis

**File:** $FW_NAME
**Size:** $FW_SIZE bytes ($(numfmt --to=iec "$FW_SIZE" 2>/dev/null || echo "$FW_SIZE"))
**Date:** $(date -u +"%Y-%m-%d %H:%M UTC")
**SHA256:** $(sha256sum "$FIRMWARE" | cut -d' ' -f1)
**Tool:** $SCRIPT_NAME v$VERSION

---
EOF
    else
        FW_NAME="$FIRMWARE"
        cat > "$REPORT" <<EOF
# Firmware Security Analysis

**Tree:** $FW_NAME
**Date:** $(date -u +"%Y-%m-%d %H:%M UTC")
**Tool:** $SCRIPT_NAME v$VERSION
**Mode:** scan-only

---
EOF
    fi

    log "$SCRIPT_NAME v$VERSION: $FW_NAME -> $OUTDIR/"

    # counters referenced across stages / summary
    HASH_CRACKED=0; PRIV_PLAIN=0; PRIV_ENC=0; PUB_KEYS=0
    N_ELF=0; N_WEAK=0; N_UNSAFE=0; N_CONSOLE=0; N_LISTENER=0
    N_STATIC=0; N_UNSTRIP=0; N_FORT=0
    N_RELFULL=0; N_RELPART=0; N_RELNONE=0
    N_BIN_SECRET=0; N_BIN_VER=0
    FILE_COUNT=0; STR_COUNT=0
    MIME="directory/scan-only"

    # extended security counters
    N_SUID=0; N_SGID=0; N_WW=0; N_SUID_WEAK=0
    N_KMOD=0; N_KMOD_PROP=0
    N_SERVICES=0; N_CRON=0; N_SECRET_FILES=0
    N_WEAK_CERTS=0; N_EXPIRED_CERTS=0
    N_FPGA=0

    t_start=$(date +%s)

    stage1_extract
    stage2_ssh_keys
    stage2_certs
    stage2_secret_files
    stage2_accounts
    stage4_hashcat
    stage2_creds
    stage2_network
    stage2_services
    stage2_scheduled
    stage5_binaries
    stage5_binary_insight
    stage_permissions
    stage_kernel_modules
    stage2_startup
    stage6_debug
    stage5_web
    stage_sysctl
    stage_boot_hardware
    stage_metadata
    stage3_crypto
    stage_interesting
    synthesize
    emit_json

    t_end=$(date +%s)
    {
        echo "------------------------------------------"
        echo " private keys (plaintext) : ${PRIV_PLAIN}"
        echo " private keys (encrypted) : ${PRIV_ENC}"
        echo " public keys              : ${PUB_KEYS}"
        echo " crackable hashes         : $(wc -l < "$FINDINGS/hashes/crackable.txt" 2>/dev/null | tr -d ' ')"
        echo " hashes cracked           : ${HASH_CRACKED}"
        echo " ELF binaries analysed    : ${N_ELF}"
        echo " ELF binaries missing hw  : ${N_WEAK}"
        echo " SUID / SGID binaries     : ${N_SUID} / ${N_SGID}"
        echo " SUID binaries missing hw : ${N_SUID_WEAK}"
        echo " world-writable files     : ${N_WW}"
        echo " kernel modules (.ko)     : ${N_KMOD} (${N_KMOD_PROP} proprietary)"
        echo " network services (xinetd): ${N_SERVICES}"
        echo " scheduled tasks (cron)   : ${N_CRON}"
        echo " dedicated secret files   : ${N_SECRET_FILES}"
        echo " weak/expired certs       : ${N_WEAK_CERTS}"
        echo " hardware/FPGA blobs      : ${N_FPGA}"
        echo "------------------------------------------"
    } >> "$REPORT"
    log "analysis complete in $(human_time $((t_end - t_start))). see $REPORT"
}

main "$@"
