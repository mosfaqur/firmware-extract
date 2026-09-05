#!/usr/bin/env bash
#
# fw-extract.sh - extract and classify security-relevant artifacts from
#                 embedded Linux firmware images.
#
# v2 (enhanced)
#   - refactored into stage functions; deterministic output ordering
#   - FIX (paper 4.2): private/public/encrypted key classification using
#     openssl, reported separately in the Summary (no longer counting
#     public keys as private keys)
#   - scan-only mode: pass an already-extracted directory instead of a
#     firmware archive to skip stage 1
#   - provenance-preserving copies: findings retain their relative path
#     instead of being flattened to basename (no silent clobbering when a
#     firmware contains several rootfs variants sharing file names)
#   - stage 4 automation: hash format auto-detection + optional
#     time-bounded hashcat run producing a Table 5.3 style report
#   - stage 6 debug-interface enumeration: startup scripts and binary
#     strings checked for telnetd/gdbserver/serial/jtag consoles with
#     loopback vs 0.0.0.0 exposure classification
#   - hardening census over all ELF binaries (canary/PIE/NX/RELRO) plus
#     an unsafe-function import census from the dynamic symbol table as
#     a lightweight complement to per-binary strings counts
#   - machine-readable output: $OUTDIR/findings.json + items.tsv
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
#
# deps: binwalk, unsquashfs/sasquatch, strings, openssl, file, find,
#       grep, readelf, numfmt (optional: hashcat, python3)
#
# outputs:
#   $OUTDIR/REPORT.md      human-readable per-category report
#   $OUTDIR/findings.json  machine-readable taxonomy (category counts +
#                          typed findings)
#   $OUTDIR/findings/      copied artefacts under keys/certs/configs/
#                          credentials/hashes
#   $OUTDIR/all_strings.txt
#   $OUTDIR/items.tsv
#
# All outputs are deterministic for a given input tree.

set -uo pipefail
shopt -s nullglob

declare -r SCRIPT_NAME="fw-extract.sh"
declare -r VERSION="2.0.0"

HASH_WORDLIST="${HASH_WORDLIST:-}"
HASH_TIMEOUT="${HASH_TIMEOUT:-3600}"
NO_HASHCAT="${NO_HASHCAT:-0}"

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
        "$f" 2>/dev/null)

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
                gunzip -c "$FIRMWARE" > "$EXTRACT/decompressed" 2>/dev/null || true ;;
        application/x-tar)
            mkdir -p "$EXTRACT/tar_contents"
            tar xf "$FIRMWARE" -C "$EXTRACT/tar_contents" 2>/dev/null || true ;;
        application/zip)
            unzip -o "$FIRMWARE" -d "$EXTRACT/zip_contents" 2>/dev/null || true ;;
        application/x-xz)
            xz -dc "$FIRMWARE" > "$EXTRACT/decompressed" 2>/dev/null || true ;;
    esac

    # unpack any squashfs/cpio images found inside
    while IFS= read -r -d '' f; do
        case "$(file -b "$f" 2>/dev/null)" in
            *[Ss]quashfs*)
                log "squashfs: ${f##*/}"
                unsquashfs -d "$EXTRACT/squashfs_${f##*/}" -f "$f" 2>/dev/null || \
                    sasquatch -d "$EXTRACT/squashfs_${f##*/}" -f "$f" 2>/dev/null || true
                ;;
            *cpio*)
                log "cpio: ${f##*/}"
                mkdir -p "$EXTRACT/cpio_${f##*/}"
                (cd "$EXTRACT/cpio_${f##*/}" && cpio -idm < "$f" 2>/dev/null) || true
                ;;
        esac
    done < <(find "$EXTRACT" -type f -print0 2>/dev/null)

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

    # sshd_config
    while IFS= read -r -d '' kf; do
        seen "$kf" && continue
        rpt "" "### sshd_config" '```'
        grep -vE '^\s*#|^\s*$' "$kf" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""
        grep -qi "PermitRootLogin.*yes" "$kf" 2>/dev/null && rpt "- PermitRootLogin yes"
        grep -qi "StrictHostKeyChecking.*no" "$kf" 2>/dev/null && \
            rpt "- StrictHostKeyChecking no"
        copy_finding "configs" "$kf"
    done < <(find "$ROOTFS" -type f -name "sshd_config" -print0 2>/dev/null)
}

# ---------------------------------------------------------------------------
# stage 2 : certificates
# ---------------------------------------------------------------------------

stage2_certs() {
    local cert info subj issuer is_ca f
    section "Certificates"

    while IFS= read -r -d '' cert; do
        seen "$cert" && continue
        copy_finding "certs" "$cert"
        info=$(openssl x509 -in "$cert" -text -noout 2>/dev/null | head -20) || \
        info=$(openssl x509 -in "$cert" -inform DER -text -noout 2>/dev/null | head -20) || \
        info=""
        if [[ -n "$info" ]]; then
            subj=$(printf '%s\n' "$info" | grep "Subject:" | sed 's/.*Subject: //')
            issuer=$(printf '%s\n' "$info" | grep "Issuer:" | sed 's/.*Issuer: //')
            is_ca=$(printf '%s\n' "$info" | grep -c "CA:TRUE" 2>/dev/null || true)
            is_ca=${is_ca:-0}
            rpt "- \`${cert##*/}\`: $subj"
            [[ "$is_ca" -gt 0 ]] && rpt "  - CA certificate"
            rpt "  - issuer: $issuer"
            note "cert" info "$cert" "subject=$subj"
        else
            rpt "- \`${cert##*/}\` (unparseable)"
            note "cert" low "$cert" "unparseable"
        fi
    done < <(find "$ROOTFS" -type f \( -name "*.pem" -o -name "*.crt" -o \
        -name "*.cer" -o -name "*.der" -o -name "*.p12" -o -name "*.pfx" -o \
        -name "*.jks" -o -name "*.keystore" -o -name "ca-bundle*" -o -name "*.ca" \
        \) -print0 2>/dev/null)

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
# stage 5 : binary static analysis
# ---------------------------------------------------------------------------

UNSAFE_FUNCS=(system popen execve strcpy strcat sprintf gets)

stage5_binaries() {
    local bin arch f c missing line imp tok flag
    section "Binaries"

    # --- hardening + import census over every (unique) ELF binary ---
    log "hardening census over all ELF binaries..."
    N_ELF=0; N_WEAK=0; N_UNSAFE=0
    declare -A UFN_IMPORTS=()
    local census_db="$OUTDIR/.seen_census"
    : > "$census_db"
    while IFS= read -r -d '' bin; do
        file -b "$bin" 2>/dev/null | grep -q "ELF" || continue
        seen_db "$census_db" "$bin" && continue
        N_ELF=$((N_ELF + 1))
        missing=""
        readelf -s "$bin" 2>/dev/null | grep -q "__stack_chk_fail" || missing+="NO_CANARY "
        readelf -h "$bin" 2>/dev/null | grep -q "DYN" || missing+="NO_PIE "
        readelf -l "$bin" 2>/dev/null | grep -qE "GNU_STACK.* RW " || missing+="NO_NX "
        readelf -l "$bin" 2>/dev/null | grep -q "GNU_RELRO" || missing+="NO_RELRO "
        [[ -n "$missing" ]] && N_WEAK=$((N_WEAK + 1))
        # unsafe-function imports via the dynamic symbol table
        imp=$(readelf -Ws "$bin" 2>/dev/null | grep -aE "FUNC|OBJECT" | \
            grep -a "UND" | \
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
    done < <(find "$ROOTFS" -type f -executable -print0 2>/dev/null)

    log "census: $N_ELF ELF binaries; $N_WEAK missing >=1 hardening control; $N_UNSAFE import unsafe fns"
    rpt "" "- analysed ELF binaries: $N_ELF"
    rpt "- ELF binaries missing >=1 hardening control: $N_WEAK"
    rpt "- ELF binaries importing an unsafe function: $N_UNSAFE"
    for f in $(printf '%s\n' "${!UFN_IMPORTS[@]}" | sort); do
        rpt "  - $f(): ${UFN_IMPORTS[$f]} binaries"
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
        missing=""
        readelf -s "$bin" 2>/dev/null | grep -q "__stack_chk_fail" || missing+="NO_CANARY "
        readelf -h "$bin" 2>/dev/null | grep -q "DYN" || missing+="NO_PIE "
        readelf -l "$bin" 2>/dev/null | grep -qE "GNU_STACK.* RW " || missing+="NO_NX "
        line="- \`${bin##*/}\` [$arch]: $dangerous"
        [[ -n "$missing" ]] && line+=" | missing: $missing"
        rpt "$line"
        note "unsafe_binary" medium "$bin" "$dangerous${missing:+ missing: $missing}"
    done < <(find "$ROOTFS" -type f -executable -print0 2>/dev/null | head -z -n 200)
    rpt ""
}

# ---------------------------------------------------------------------------
# startup scripts
# ---------------------------------------------------------------------------

stage2_startup() {
    local s cr
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
        -o -name "crontab" -path "*/etc/*" \) -print0 2>/dev/null)

    while IFS= read -r -d '' cr; do
        is_text "$cr" || continue
        seen "$cr" && continue
        rpt "" "### crontab: ${cr##*/}" '```'
        grep -vE '^\s*#|^\s*$' "$cr" >> "$REPORT" 2>/dev/null || true
        rpt '```' ""
    done < <(find "$ROOTFS" -type f \( -name "crontab" -o -path "*/cron.d/*" -o \
        -path "*/cron.daily/*" -o -path "*/cron.hourly/*" \) -print0 2>/dev/null)
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
| debug consoles/services referenced | ${N_CONSOLE:-0} |
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
    "tool": {"name": "fw-extract.sh", "version": "2.0.0"},
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

    mkdir -p "$OUTDIR" "$EXTRACT" "$FINDINGS"/{keys,certs,configs,credentials,hashes}
    : > "$SEEN"
    : > "$ITEMS"

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
    FILE_COUNT=0; STR_COUNT=0
    MIME="directory/scan-only"

    t_start=$(date +%s)

    stage1_extract
    stage2_ssh_keys
    stage2_certs
    stage2_accounts
    stage4_hashcat
    stage2_creds
    stage2_network
    stage5_binaries
    stage2_startup
    stage6_debug
    stage5_web
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
        echo "------------------------------------------"
    } >> "$REPORT"
    log "analysis complete in $(human_time $((t_end - t_start))). see $REPORT"
}

main "$@"
