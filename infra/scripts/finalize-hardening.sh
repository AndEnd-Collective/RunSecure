#!/bin/bash
# ============================================================================
# RunSecure — Finalize Image Hardening
# ============================================================================
# Called as the LAST step in every default language image and in project images
# produced by compose-image.sh.
# Removes package-manager functionality, retains only inert scanner inventory,
# re-strips setuid binaries, and locks /etc.
#
# This is separated from base.Dockerfile because language layers and tool
# recipes need apt during image build. Only the final image strips it.
# ============================================================================

set -euo pipefail

echo "[RunSecure] Finalizing image hardening..."

# M10: every operation below was previously suffixed with `2>/dev/null
# || true`, which converted any failure (read-only filesystem, missing
# binary path, immutable bit set) into a silent success — the script
# would then claim "Hardening finalized" without having actually done
# anything. With set -euo pipefail and the masks removed, an unexpected
# failure now aborts the image build instead of producing a degraded
# image that the operator believes is hardened.

# Preserve the installed-package inventory Syft/Grype needs before deleting
# dpkg's mutable database. The inventory is data only: no maintainer scripts,
# locks, update queues, executable helpers, or writable state survives.
_dpkg_inventory_tmp=""
if [[ -e /var/lib/dpkg/status ]]; then
    if [[ ! -f /var/lib/dpkg/status || -L /var/lib/dpkg/status ]]; then
        echo "[RunSecure] ERROR: dpkg status inventory is not a regular file" >&2
        exit 1
    fi
    _dpkg_inventory_tmp=$(mktemp -d /tmp/runsecure-dpkg-inventory.XXXXXX)
    install -m 0444 /var/lib/dpkg/status "${_dpkg_inventory_tmp}/status"

    if [[ -e /var/lib/dpkg/status.d ]]; then
        if [[ ! -d /var/lib/dpkg/status.d || -L /var/lib/dpkg/status.d ]]; then
            echo "[RunSecure] ERROR: dpkg status.d inventory is not a regular directory" >&2
            exit 1
        fi
        _invalid_status_entry=$(find /var/lib/dpkg/status.d \
            -mindepth 1 -maxdepth 1 ! -type f -print -quit)
        if [[ -n "$_invalid_status_entry" ]]; then
            echo "[RunSecure] ERROR: unsupported dpkg status.d entry: $_invalid_status_entry" >&2
            exit 1
        fi
        install -d -m 0755 "${_dpkg_inventory_tmp}/status.d"
        while IFS= read -r -d '' _status_file; do
            install -m 0444 "$_status_file" \
                "${_dpkg_inventory_tmp}/status.d/${_status_file##*/}"
        done < <(find /var/lib/dpkg/status.d \
            -mindepth 1 -maxdepth 1 -type f -print0)
    fi
fi

# Remove package manager so nothing can be installed at runtime. rm -rf with
# -f returns 0 for non-existent paths, so this remains idempotent.
rm -rf \
    /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config \
    /usr/bin/apt-key /usr/bin/apt-mark /usr/bin/aptitude \
    /usr/bin/dpkg /usr/bin/dpkg-deb /usr/bin/dpkg-divert /usr/bin/dpkg-query \
    /usr/bin/dpkg-split /usr/bin/dpkg-statoverride /usr/bin/dpkg-trigger \
    /usr/lib/apt \
    /usr/lib/dpkg \
    /var/lib/apt \
    /var/lib/dpkg \
    /var/cache/apt \
    /etc/apt

if [[ -n "$_dpkg_inventory_tmp" ]]; then
    install -d -m 0755 /var/lib/dpkg
    install -m 0444 "${_dpkg_inventory_tmp}/status" /var/lib/dpkg/status
    if [[ -d "${_dpkg_inventory_tmp}/status.d" ]]; then
        install -d -m 0755 /var/lib/dpkg/status.d
        while IFS= read -r -d '' _status_file; do
            install -m 0444 "$_status_file" \
                "/var/lib/dpkg/status.d/${_status_file##*/}"
        done < <(find "${_dpkg_inventory_tmp}/status.d" \
            -mindepth 1 -maxdepth 1 -type f -print0)
        chmod 0555 /var/lib/dpkg/status.d
    fi
    chmod 0555 /var/lib/dpkg
    rm -rf "$_dpkg_inventory_tmp"
fi

# Debian package maintainer scripts legitimately need these helpers while the
# build-only *-build stages are composing project packages (for example, dbus
# creates its service account through adduser). Remove them only now, after all
# installation is complete, so they are never present in terminal images.
rm -f \
    /usr/sbin/adduser \
    /usr/sbin/useradd \
    /usr/sbin/userdel \
    /usr/sbin/usermod \
    /usr/sbin/groupadd \
    /usr/sbin/groupdel \
    /usr/sbin/groupmod \
    /usr/bin/passwd

# Re-strip setuid/setgid bits added by any tool install. Use -print0 |
# xargs -0 -r so an unreadable filesystem entry on `find`'s walk does
# NOT mask a chmod failure on a real binary (which is what we care
# about). xargs propagates chmod's exit code.
find / -xdev -perm /6000 -type f -print0 2>/dev/null | xargs -0 -r chmod a-s

# Lock system paths. These MUST succeed on a normal Debian/Alpine base
# — any failure here means the image is not properly hardened and the
# build should abort.
chmod 444 /etc/passwd /etc/group
chmod 555 /etc

# Belt-and-suspenders: verify the binaries we tried to remove are
# really gone, in case a future apt+/dpkg+ glob expansion regresses.
for bin in \
    apt apt-get dpkg dpkg-query \
    adduser useradd userdel usermod groupadd groupdel groupmod passwd; do
    if command -v "$bin" >/dev/null 2>&1; then
        echo "[RunSecure] ERROR: $bin still on PATH after finalize-hardening — refusing to produce a degraded image" >&2
        exit 1
    fi
done

# Scanner inventory is the only permitted dpkg state. It must be regular,
# non-executable, read-only data; mutable package-manager state fails closed.
if [[ -d /var/lib/dpkg ]]; then
    if [[ ! -f /var/lib/dpkg/status || -L /var/lib/dpkg/status ]]; then
        echo "[RunSecure] ERROR: preserved dpkg inventory is missing or unsafe" >&2
        exit 1
    fi
    _unexpected_dpkg_entry=$(find /var/lib/dpkg -mindepth 1 \
        ! -path /var/lib/dpkg/status \
        ! -path /var/lib/dpkg/status.d \
        ! -path '/var/lib/dpkg/status.d/*' -print -quit)
    if [[ -n "$_unexpected_dpkg_entry" ]]; then
        echo "[RunSecure] ERROR: mutable dpkg state survived: $_unexpected_dpkg_entry" >&2
        exit 1
    fi
    _writable_dpkg_entry=$(find /var/lib/dpkg -perm /222 -print -quit)
    if [[ -n "$_writable_dpkg_entry" ]]; then
        echo "[RunSecure] ERROR: writable dpkg inventory survived: $_writable_dpkg_entry" >&2
        exit 1
    fi
fi

# ============================================================================
# H2: optional user-requested tool removal / stubbing
# ============================================================================
# RUNSECURE_HARDENING_REMOVE — comma-separated list of binary names to rm.
# RUNSECURE_HARDENING_STUB   — comma-separated list of binary names to
#                              replace with a friendly stub that explains
#                              why the tool is intentionally unavailable.
#
# Both lists were validated upstream by validate-schema.sh + a sink-side
# guard in compose-image.sh (no shell metachars; alphanumerics and
# hyphens/underscores only). We re-validate here as defense-in-depth —
# any future code path that reaches this script via a different sink
# must still pass the same character-class check.
_h2_validate_name() {
    local name="$1"
    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "[RunSecure] ERROR: H2 invalid name '$name' — refusing finalize" >&2
        exit 1
    fi
}

# Resolve a name to its absolute path on PATH. Empty if not found.
_h2_locate() {
    command -v "$1" 2>/dev/null || true
}

# H2 stubs: install a tiny POSIX shell script in place of the binary
# that prints why it was removed and exits 127. This is gentler than
# `command not found` for users who deliberately invoked a tool — the
# stub tells them which runner.yml setting hid it.
_h2_install_stub() {
    local name="$1"
    local target
    target=$(_h2_locate "$name")
    if [[ -z "$target" ]]; then
        echo "[RunSecure] H2: '$name' not present on PATH (nothing to stub)" >&2
        return 0
    fi
    rm -f "$target"
    cat > "$target" <<STUB
#!/bin/sh
# RunSecure stub — generated by hardening.stub at image build time.
echo "[runsecure] '$name' was intentionally replaced by hardening.stub in your runner.yml." >&2
echo "[runsecure] If your job needs $name, remove it from hardening.stub or move to hardening.remove + hardening.allow." >&2
exit 127
STUB
    chmod 555 "$target"
    echo "[RunSecure] H2: stubbed $target"
}

_h2_remove_binary() {
    local name="$1"
    local target
    target=$(_h2_locate "$name")
    if [[ -z "$target" ]]; then
        echo "[RunSecure] H2: '$name' not present on PATH (nothing to remove)" >&2
        return 0
    fi
    # Walk every PATH entry once. We track previously seen targets to
    # bound the loop — without this, an rm failure on a system path
    # (e.g. read-only mount) would cause an infinite loop because
    # command -v keeps finding the same file.
    local seen=" "
    while true; do
        local next
        next=$(_h2_locate "$name")
        [[ -z "$next" ]] && break
        case "$seen" in
            *" $next "*)
                echo "[RunSecure] ERROR: H2 cannot remove '$name' at $next (rm failed) — refusing to produce a degraded image" >&2
                exit 1
                ;;
        esac
        seen="${seen}${next} "
        rm -f "$next"
        echo "[RunSecure] H2: removed $next"
    done
}

if [[ -n "${RUNSECURE_HARDENING_REMOVE:-}" ]]; then
    IFS=',' read -ra _h2_rm_list <<<"$RUNSECURE_HARDENING_REMOVE"
    for _name in "${_h2_rm_list[@]}"; do
        [[ -z "$_name" ]] && continue
        _h2_validate_name "$_name"
        _h2_remove_binary "$_name"
    done
fi

if [[ -n "${RUNSECURE_HARDENING_STUB:-}" ]]; then
    IFS=',' read -ra _h2_stub_list <<<"$RUNSECURE_HARDENING_STUB"
    for _name in "${_h2_stub_list[@]}"; do
        [[ -z "$_name" ]] && continue
        _h2_validate_name "$_name"
        _h2_install_stub "$_name"
    done
fi

echo "[RunSecure] Hardening finalized."
