#!/usr/bin/env bash
#
# fw-extract.sh - extract security-relevant artifacts from firmware images
#
# usage: ./fw-extract.sh <firmware_file> [output_dir]
#
# deps: binwalk, unsquashfs, strings, openssl, file, find, grep, readelf

set -uo pipefail

die() { echo "error: $1" >&2; exit 1; }

FIRMWARE="${1:?usage: $0 <firmware_file> [output_dir]}"
OUTDIR="${2:-fw_analysis_$(date +%Y%m%d_%H%M%S)}"
[[ -f "$FIRMWARE" ]] || die "$FIRMWARE not found"

REPORT="$OUTDIR/REPORT.md"
EXTRACT="$OUTDIR/extracted"
FINDINGS="$OUTDIR/findings"
mkdir -p "$OUTDIR" "$EXTRACT" "$FINDINGS"/{keys,certs,configs,credentials,hashes}

FW_SIZE=$(stat -c%s "$FIRMWARE" 2>/dev/null || stat -f%z "$FIRMWARE")
FW_NAME=$(basename "$FIRMWARE")

# dedup: skip files with identical content across rootfs variants
SEEN="$OUTDIR/.seen"
> "$SEEN"
seen() {
    local h
    h=$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1) || return 1
    grep -qF "$h" "$SEEN" 2>/dev/null && return 0
    echo "$h" >> "$SEEN"
    return 1
}

# safe integer from grep output (avoids multiline issues with grep -c)
count_matches() { grep -Ei "$1" "$2" 2>/dev/null | wc -l | tr -d ' '; }

# check if file is plaintext
is_text() { file "$1" 2>/dev/null | grep -qiE 'text|empty|script|ASCII'; }

# check if file is binary/ELF
is_binary() { file "$1" 2>/dev/null | grep -qiE 'ELF|executable|shared object'; }

cat > "$REPORT" <<EOF
# Firmware Security Analysis

**File:** $FW_NAME
**Size:** $FW_SIZE bytes ($(numfmt --to=iec "$FW_SIZE" 2>/dev/null || echo "$FW_SIZE"))
**Date:** $(date -u +"%Y-%m-%d %H:%M UTC")
**SHA256:** $(sha256sum "$FIRMWARE" | cut -d' ' -f1)

---

EOF

echo "fw-extract: $FW_NAME ($FW_SIZE bytes) -> $OUTDIR/"

# --- extraction ---

echo "[*] extracting firmware..."

if command -v binwalk &>/dev/null; then
    binwalk -e -M -d 5 -C "$EXTRACT" "$FIRMWARE" 2>/dev/null || true
    binwalk "$FIRMWARE" > "$OUTDIR/binwalk_scan.txt" 2>/dev/null || true
fi

MIME=$(file -b --mime-type "$FIRMWARE")
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

# unpack squashfs/cpio found inside
find "$EXTRACT" -type f 2>/dev/null | while read -r f; do
    if file "$f" | grep -qi squashfs; then
        echo "  squashfs: $(basename "$f")"
        unsquashfs -d "$EXTRACT/squashfs_$(basename "$f")" -f "$f" 2>/dev/null || \
            sasquatch -d "$EXTRACT/squashfs_$(basename "$f")" -f "$f" 2>/dev/null || true
    fi
    if file "$f" | grep -qi cpio; then
        echo "  cpio: $(basename "$f")"
        mkdir -p "$EXTRACT/cpio_$(basename "$f")"
        (cd "$EXTRACT/cpio_$(basename "$f")" && cpio -idm < "$f" 2>/dev/null) || true
    fi
done

FILE_COUNT=$(find "$EXTRACT" -type f 2>/dev/null | wc -l)
echo "  $FILE_COUNT files extracted"

{
    echo "## Extraction"
    echo ""
    echo "- files: $FILE_COUNT"
    echo "- type: $MIME"
    echo ""
} >> "$REPORT"

ROOTFS="$EXTRACT"

# --- ssh keys ---

echo "[*] scanning for ssh keys..."

{
    echo "## SSH Keys"
    echo ""
} >> "$REPORT"

find "$ROOTFS" -type f \( -name "*.key" -o -name "*.pem" -o -name "id_*" \
    -o -name "ssh_host_*" -o -name "*.ppk" \) 2>/dev/null | while read -r kf; do
    head -5 "$kf" 2>/dev/null | grep -qiE "PRIVATE KEY|PuTTY-User-Key-File" || continue
    seen "$kf" && continue
    echo "  PRIVATE KEY: $kf"
    cp "$kf" "$FINDINGS/keys/" 2>/dev/null || true
    echo "- **PRIVATE KEY:** \`$kf\`" >> "$REPORT"
    openssl pkey -in "$kf" -text -noout 2>/dev/null | head -3 >> "$REPORT" || true
done

grep -rlE "BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY" "$ROOTFS" 2>/dev/null | \
    head -50 | while read -r f; do
    echo "$f" | grep -qE "\.(key|pem)$" && continue
    seen "$f" && continue
    echo "  embedded key: $f"
    echo "- embedded private key: \`$f\`" >> "$REPORT"
    cp "$f" "$FINDINGS/keys/embedded_$(basename "$f")" 2>/dev/null || true
done

find "$ROOTFS" -type f \( -name "*.pub" -o -name "authorized_keys" -o -name "authorized_keys2" \) \
    2>/dev/null | while read -r pf; do
    seen "$pf" && continue
    echo "- public key: \`$pf\`" >> "$REPORT"
    cp "$pf" "$FINDINGS/keys/" 2>/dev/null || true
done

find "$ROOTFS" -type f -name "sshd_config" 2>/dev/null | while read -r cfg; do
    seen "$cfg" && continue
    echo "" >> "$REPORT"
    echo "### sshd_config" >> "$REPORT"
    echo '```' >> "$REPORT"
    grep -vE '^\s*#|^\s*$' "$cfg" >> "$REPORT" 2>/dev/null || true
    echo '```' >> "$REPORT"

    grep -qi "PermitRootLogin.*yes" "$cfg" 2>/dev/null && \
        echo "- PermitRootLogin yes" >> "$REPORT"
    grep -qi "StrictHostKeyChecking.*no" "$cfg" 2>/dev/null && \
        echo "- StrictHostKeyChecking no" >> "$REPORT"
    cp "$cfg" "$FINDINGS/configs/" 2>/dev/null || true
done

# --- certificates ---

echo "[*] scanning certificates..."

{
    echo ""
    echo "## Certificates"
    echo ""
} >> "$REPORT"

find "$ROOTFS" -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.der" \
    -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks" -o -name "*.keystore" \
    -o -name "ca-bundle*" -o -name "*.ca" \) 2>/dev/null | while read -r cert; do
    seen "$cert" && continue
    cp "$cert" "$FINDINGS/certs/" 2>/dev/null || true

    INFO=$(openssl x509 -in "$cert" -text -noout 2>/dev/null | head -20) || \
    INFO=$(openssl x509 -in "$cert" -inform DER -text -noout 2>/dev/null | head -20) || \
    INFO=""

    if [[ -n "$INFO" ]]; then
        SUBJ=$(echo "$INFO" | grep "Subject:" | sed 's/.*Subject: //')
        ISSUER=$(echo "$INFO" | grep "Issuer:" | sed 's/.*Issuer: //')
        IS_CA=$(echo "$INFO" | grep -c "CA:TRUE" || true)
        echo "- \`$(basename "$cert")\`: $SUBJ" >> "$REPORT"
        [[ "$IS_CA" -gt 0 ]] && echo "  - CA certificate" >> "$REPORT"
        echo "  - issuer: $ISSUER" >> "$REPORT"
    else
        echo "- \`$(basename "$cert")\` (unparseable)" >> "$REPORT"
    fi
done

find "$ROOTFS" -type f \( -name "ipsec.secrets" -o -name "ipsec.conf" -o -name "*.secrets" \
    -o -path "*/ipsec.d/*" \) 2>/dev/null | while read -r f; do
    seen "$f" && continue
    echo "  ipsec: $f"
    echo "- IPsec: \`$f\`" >> "$REPORT"
    cp "$f" "$FINDINGS/configs/" 2>/dev/null || true
done

# --- user accounts ---

echo "[*] scanning user accounts..."

{
    echo ""
    echo "## User Accounts"
    echo ""
} >> "$REPORT"

find "$ROOTFS" -type f -name "passwd" -path "*/etc/*" 2>/dev/null | while read -r pf; do
    is_text "$pf" || continue
    seen "$pf" && continue
    echo "### passwd" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$pf" >> "$REPORT"
    echo '```' >> "$REPORT"
    cp "$pf" "$FINDINGS/credentials/" 2>/dev/null || true

    while IFS=: read -r user _ uid _ _ _ shell; do
        if [[ "$uid" == "0" && "$user" != "root" ]]; then
            echo "  root-equivalent: $user (uid 0)"
            echo "- root-equivalent: \`$user\` (uid 0, $shell)" >> "$REPORT"
        fi
    done < "$pf"
    echo "" >> "$REPORT"
done

find "$ROOTFS" -type f \( -name "shadow" -o -name "shadow.*" -o -name "shadow_*" \) \
    2>/dev/null | while read -r sf; do
    is_text "$sf" || continue
    seen "$sf" && continue
    echo "### shadow ($sf)" >> "$REPORT"
    echo "" >> "$REPORT"
    cp "$sf" "$FINDINGS/hashes/" 2>/dev/null || true

    while IFS=: read -r user hash _; do
        [[ -z "$hash" || "$hash" == "*" || "$hash" == "!" || "$hash" == "!!" || "$hash" == "x" ]] && continue
        echo "  hash: $user"
        echo "- \`$user\`: \`${hash:0:20}...\`" >> "$REPORT"
        echo "$user:$hash" >> "$FINDINGS/hashes/crackable.txt"
    done < "$sf" 2>/dev/null || true
    echo "" >> "$REPORT"
done

# --- hardcoded credentials ---

echo "[*] building strings index..."

STRINGS_DUMP="$OUTDIR/all_strings.txt"
find "$ROOTFS" -type f -size +0c -size -100M -exec strings -a -n 6 {} + > "$STRINGS_DUMP" 2>/dev/null || true

STR_COUNT=$(wc -l < "$STRINGS_DUMP")
echo "  $STR_COUNT strings indexed"

{
    echo "## Hardcoded Credentials"
    echo ""
} >> "$REPORT"

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
)

for label in "${!PATTERNS[@]}"; do
    n=$(count_matches "${PATTERNS[$label]}" "$STRINGS_DUMP")
    n=$(( n + 0 )) 2>/dev/null || n=0
    if [[ "$n" -gt 0 ]]; then
        echo "  $label: $n matches"
        echo "### $label ($n)" >> "$REPORT"
        echo '```' >> "$REPORT"
        grep -Ei "${PATTERNS[$label]}" "$STRINGS_DUMP" 2>/dev/null | sort -u | head -50 >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "" >> "$REPORT"
        grep -Ei "${PATTERNS[$label]}" "$STRINGS_DUMP" 2>/dev/null | sort -u > \
            "$FINDINGS/credentials/${label}.txt" 2>/dev/null || true
    fi
done

grep -Ei 'salt\s*[:=]' "$STRINGS_DUMP" 2>/dev/null | sort -u | head -20 > \
    "$FINDINGS/credentials/salts.txt" 2>/dev/null || true
SC=$(wc -l < "$FINDINGS/credentials/salts.txt" 2>/dev/null || echo 0)
if [[ "$SC" -gt 0 ]]; then
    echo "  salts: $SC"
    echo "### password salts" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$FINDINGS/credentials/salts.txt" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
fi

# --- network ---

echo "[*] scanning network config..."

{
    echo "## Network"
    echo ""
} >> "$REPORT"

grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$STRINGS_DUMP" 2>/dev/null | \
    sort -u | grep -vE '^(0\.0\.0\.0|127\.0\.0\.[01]|255\.|224\.|0\.0\.)' | \
    head -100 > "$FINDINGS/configs/ip_addresses.txt"
IPC=$(wc -l < "$FINDINGS/configs/ip_addresses.txt")
echo "  $IPC unique IPs"
echo "### IP addresses ($IPC)" >> "$REPORT"
echo '```' >> "$REPORT"
cat "$FINDINGS/configs/ip_addresses.txt" >> "$REPORT"
echo '```' >> "$REPORT"
echo "" >> "$REPORT"

grep -oEi 'https?://[^\s"'\''<>]+' "$STRINGS_DUMP" 2>/dev/null | sort -u | head -100 > \
    "$FINDINGS/configs/urls.txt"
UC=$(wc -l < "$FINDINGS/configs/urls.txt")
if [[ "$UC" -gt 0 ]]; then
    echo "  $UC URLs"
    echo "### URLs ($UC)" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$FINDINGS/configs/urls.txt" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
fi

find "$ROOTFS" -type f \( -name "resolv.conf" -o -name "hosts" -o -name "hostname" \
    -o -name "*.conf" -path "*/netplan/*" -o -name "interfaces" \) -path "*/etc/*" \
    2>/dev/null | while read -r nc; do
    is_binary "$nc" && continue
    is_text "$nc" || continue
    seen "$nc" && continue
    echo "### $(basename "$nc")" >> "$REPORT"
    echo '```' >> "$REPORT"
    head -200 "$nc" >> "$REPORT" 2>/dev/null || true
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
    cp "$nc" "$FINDINGS/configs/" 2>/dev/null || true
done

find "$ROOTFS" -type f \( -name "iptables*" -o -name "nftables*" -o -name "firewall*" \
    -o -name "*.rules" -path "*/iptables/*" \) 2>/dev/null | while read -r fw; do
    is_binary "$fw" && continue
    is_text "$fw" || continue
    seen "$fw" && continue
    echo "### firewall: $(basename "$fw")" >> "$REPORT"
    echo '```' >> "$REPORT"
    head -500 "$fw" >> "$REPORT" 2>/dev/null || true
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
    cp "$fw" "$FINDINGS/configs/" 2>/dev/null || true
done

# --- binaries ---

echo "[*] analyzing binaries..."

{
    echo "## Binaries"
    echo ""
} >> "$REPORT"

find "$ROOTFS" -type f -executable 2>/dev/null | head -200 | while read -r bin; do
    file "$bin" 2>/dev/null | grep -q "ELF" || continue
    seen "$bin" && continue
    ARCH=$(file "$bin" | grep -oE '(ARM|MIPS|x86-64|x86|PowerPC|RISC-V|aarch64|i[3-6]86)' | head -1)

    DANGEROUS=""
    STROUT=$(strings -a "$bin" 2>/dev/null)
    for func in system popen execve strcpy strcat sprintf gets; do
        c=$(echo "$STROUT" | grep -cw "$func" 2>/dev/null || true)
        c=$(( c + 0 )) 2>/dev/null || c=0
        [[ "$c" -gt 0 ]] && DANGEROUS+="$func($c) "
    done

    [[ -z "$DANGEROUS" ]] && continue

    LINE="- \`$(basename "$bin")\` [$ARCH]: $DANGEROUS"
    echo "  $(basename "$bin") [$ARCH]: $DANGEROUS"

    if command -v readelf &>/dev/null; then
        canary=$(readelf -s "$bin" 2>/dev/null | grep -c "__stack_chk_fail" 2>/dev/null || true)
        canary=$(( canary + 0 )) 2>/dev/null || canary=0
        pie=$(readelf -h "$bin" 2>/dev/null | grep -c "DYN" 2>/dev/null || true)
        pie=$(( pie + 0 )) 2>/dev/null || pie=0
        nx=$(readelf -l "$bin" 2>/dev/null | grep -c "GNU_STACK.*RW " 2>/dev/null || true)
        nx=$(( nx + 0 )) 2>/dev/null || nx=0

        missing=""
        [[ "$canary" -eq 0 ]] && missing+="NO_CANARY "
        [[ "$pie" -eq 0 ]] && missing+="NO_PIE "
        [[ "$nx" -eq 0 ]] && missing+="NO_NX "
        [[ -n "$missing" ]] && LINE+=" | missing: $missing"
    fi

    echo "$LINE" >> "$REPORT"
done
echo "" >> "$REPORT"

# --- startup scripts ---

echo "[*] scanning startup scripts..."

{
    echo "## Startup Scripts"
    echo ""
} >> "$REPORT"

find "$ROOTFS" -type f \( -path "*/init.d/*" -o -path "*/rc.d/*" \
    -o -path "*/systemd/system/*.service" -o -name "rc.local" -o -name "inittab" \
    -o -name "crontab" -path "*/etc/*" \) 2>/dev/null | while read -r s; do
    is_text "$s" || continue
    seen "$s" && continue
    echo "- \`$s\`" >> "$REPORT"

    if grep -lEi '(password|passwd|secret|key|token)\s*[:=]' "$s" &>/dev/null; then
        echo "  - contains credential references" >> "$REPORT"
    fi
    if grep -lEi '(telnet|nc -l|socat|ncat).*listen' "$s" &>/dev/null; then
        echo "  - network listener (possible backdoor)" >> "$REPORT"
    fi
done

find "$ROOTFS" -type f \( -name "crontab" -o -path "*/cron.d/*" -o -path "*/cron.daily/*" \
    -o -path "*/cron.hourly/*" \) 2>/dev/null | while read -r cr; do
    is_text "$cr" || continue
    seen "$cr" && continue
    echo "" >> "$REPORT"
    echo "### crontab: $(basename "$cr")" >> "$REPORT"
    echo '```' >> "$REPORT"
    grep -vE '^\s*#|^\s*$' "$cr" >> "$REPORT" 2>/dev/null || true
    echo '```' >> "$REPORT"
done
echo "" >> "$REPORT"

# --- debug/backdoor ---

echo "[*] checking debug/backdoor indicators..."

{
    echo "## Debug and Backdoor Indicators"
    echo ""
} >> "$REPORT"

TREF=$(grep -ciE 'telnet.*(127\.0\.0\.1|localhost|0\.0\.0\.0)' "$STRINGS_DUMP" 2>/dev/null || echo 0)
if [[ "$TREF" -gt 0 ]]; then
    echo "### debug consoles" >> "$REPORT"
    echo '```' >> "$REPORT"
    grep -Ei 'telnet.*(127\.0\.0\.1|localhost|0\.0\.0\.0)' "$STRINGS_DUMP" 2>/dev/null | sort -u | head -20 >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
fi

for pat in "backdoor" "master.key" "master_password" "super.admin" "superadmin" \
    "debug_shell" "reverse.shell" "bind.shell" "god.mode" "test_mode" "factory_reset" \
    "hidden_user" "maintenance_mode"; do
    h=$(grep -ci "$pat" "$STRINGS_DUMP" 2>/dev/null || echo 0)
    [[ "$h" -gt 0 ]] && echo "- \`$pat\`: $h references" >> "$REPORT"
done

find "$ROOTFS" -type f \( -name "*.ovpn" -o -name "openvpn*" -o -name "vpn*" \
    -o -path "*/openvpn/*" -o -name "wg*.conf" \) 2>/dev/null | while read -r vpn; do
    seen "$vpn" && continue
    echo "- VPN config: \`$vpn\`" >> "$REPORT"
    cp "$vpn" "$FINDINGS/configs/" 2>/dev/null || true
done
echo "" >> "$REPORT"

# --- web ---

echo "[*] scanning web interfaces..."

{
    echo "## Web Interfaces"
    echo ""
} >> "$REPORT"

find "$ROOTFS" -type f \( -name "httpd.conf" -o -name "nginx.conf" -o -name "lighttpd.conf" \
    -o -name "apache2.conf" -o -name "uhttpd*" -o -name "*.php" -path "*/www/*" \
    -o -name "*.cgi" \) 2>/dev/null | head -50 | while read -r w; do
    seen "$w" && continue
    echo "- \`$w\`" >> "$REPORT"
    if echo "$w" | grep -qE '\.(php|cgi)$'; then
        for func in eval exec system passthru shell_exec popen proc_open; do
            grep -q "$func" "$w" 2>/dev/null && echo "  - uses $func()" >> "$REPORT"
        done
    fi
done

find "$ROOTFS" -type f \( -name "phpinfo*" -o -name "adminer*" -o -name "phpmyadmin*" \
    -o -name "info.php" -o -name "test.php" -o -name "debug.php" \) 2>/dev/null | while read -r d; do
    seen "$d" && continue
    echo "- debug file: \`$d\`" >> "$REPORT"
done
echo "" >> "$REPORT"

# --- metadata ---

echo "[*] firmware metadata..."

{
    echo "## Firmware Metadata"
    echo ""
} >> "$REPORT"

find "$ROOTFS" -type f \( -name "os-release" -o -name "lsb-release" -o -name "issue" \
    -o -name "version" -o -name "buildinfo" -o -name "BUILD_INFO" \) -path "*/etc/*" \
    2>/dev/null | while read -r osf; do
    is_text "$osf" || continue
    seen "$osf" && continue
    echo "### $(basename "$osf")" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$osf" >> "$REPORT" 2>/dev/null || true
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
done

find "$ROOTFS" -type f \( -name "config-*" -path "*/boot/*" -o -name ".config" \) \
    2>/dev/null | while read -r kc; do
    is_text "$kc" || continue
    seen "$kc" && continue
    echo "### kernel config" >> "$REPORT"
    echo '```' >> "$REPORT"
    grep -E '^CONFIG_(SECURITY|SECCOMP|DEBUG|CRYPTO|KEYS|SELINUX|APPARMOR)' "$kc" 2>/dev/null | \
        sort >> "$REPORT" || true
    echo '```' >> "$REPORT"
    dc=$(grep -c '^CONFIG_DEBUG' "$kc" 2>/dev/null || echo 0)
    [[ "$dc" -gt 5 ]] && echo "- $dc kernel debug options enabled" >> "$REPORT"
    echo "" >> "$REPORT"
done

ARCH_INFO=$(find "$ROOTFS" -type f -executable 2>/dev/null | head -5 | while read -r b; do
    file "$b" 2>/dev/null | grep -oE '(ARM|MIPS|x86-64|aarch64|PowerPC|RISC-V|i[3-6]86)' | head -1
done | sort -u | head -1)
[[ -n "${ARCH_INFO:-}" ]] && echo "- architecture: $ARCH_INFO" >> "$REPORT"

# --- crypto ---

echo "[*] scanning crypto material..."

{
    echo ""
    echo "## Crypto Material"
    echo ""
} >> "$REPORT"

grep -Ei '(AES|DES|RSA|ECDSA|HMAC|SHA256|MD5)' "$STRINGS_DUMP" 2>/dev/null | \
    grep -Ei '(key|secret|password|salt|iv|nonce)' | sort -u | head -30 > \
    "$FINDINGS/credentials/crypto_refs.txt"

CC=$(wc -l < "$FINDINGS/credentials/crypto_refs.txt")
if [[ "$CC" -gt 0 ]]; then
    echo "### crypto references ($CC)" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$FINDINGS/credentials/crypto_refs.txt" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
fi

find "$ROOTFS" -type f \( -name "*.p12" -o -name "*.pfx" -o -name "*.jks" -o -name "*.bks" \) \
    2>/dev/null | while read -r ks; do
    seen "$ks" && continue
    echo "- keystore: \`$ks\`" >> "$REPORT"
    cp "$ks" "$FINDINGS/keys/" 2>/dev/null || true
done

# --- interesting files ---

{
    echo ""
    echo "## Interesting Files"
    echo ""
} >> "$REPORT"

find "$ROOTFS" -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \
    -o -name "*.sql" -o -name "*.mdb" \) 2>/dev/null | while read -r db; do
    seen "$db" && continue
    sz=$(stat -c%s "$db" 2>/dev/null || stat -f%z "$db" 2>/dev/null)
    echo "- \`$(basename "$db")\` ($sz bytes)" >> "$REPORT"
done

find "$ROOTFS" -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.yaml" \
    -o -name "*.yml" -o -name "*.json" -o -name "*.xml" -o -name "*.properties" \
    -o -name "*.env" -o -name ".env*" \) -size +0c 2>/dev/null | while read -r cfg; do
    is_text "$cfg" || continue
    grep -lEi '(password|passwd|secret|key|token|credential)\s*[:=]' "$cfg" &>/dev/null || continue
    seen "$cfg" && continue
    echo "- secrets in: \`$cfg\`" >> "$REPORT"
    cp "$cfg" "$FINDINGS/configs/" 2>/dev/null || true
done

# --- summary ---

KEYS_N=$(find "$FINDINGS/keys" -type f 2>/dev/null | wc -l)
CERTS_N=$(find "$FINDINGS/certs" -type f 2>/dev/null | wc -l)
CONF_N=$(find "$FINDINGS/configs" -type f 2>/dev/null | wc -l)
CRED_N=$(find "$FINDINGS/credentials" -type f -size +0c 2>/dev/null | wc -l)
HASH_N=$(wc -l < "$FINDINGS/hashes/crackable.txt" 2>/dev/null || echo 0)

cat >> "$REPORT" <<EOF

---

## Summary

| category | count |
|----------|-------|
| private keys | $KEYS_N |
| certificates | $CERTS_N |
| config files | $CONF_N |
| credential files | $CRED_N |
| crackable hashes | $HASH_N |
| extracted files | $FILE_COUNT |
| strings indexed | $STR_COUNT |
EOF

echo ""
echo "done. report: $REPORT"
echo "  keys=$KEYS_N certs=$CERTS_N configs=$CONF_N hashes=$HASH_N"
