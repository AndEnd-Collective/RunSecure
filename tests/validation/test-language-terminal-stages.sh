#!/bin/bash
# Published language packages must be terminal hardened images. Project
# composition is the only consumer of the build-only *-build stages.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNSECURE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1 — $2"; FAIL=$((FAIL + 1)); }

for lang in node python rust; do
    dockerfile="${RUNSECURE_ROOT}/images/${lang}.Dockerfile"
    last_stage=$(awk 'toupper($1) == "FROM" { stage=$0 } END { print stage }' "$dockerfile")

    if grep -Fq "AS ${lang}-build" "$dockerfile"; then
        pass "${lang}: build-only composition stage exists"
    else
        fail "${lang}-build-stage" "missing build-only ${lang}-build stage"
    fi

    if [[ "$last_stage" == "FROM ${lang}-build AS ${lang}" ]]; then
        pass "${lang}: default target is the terminal stage"
    else
        fail "${lang}-terminal-stage" "last stage is '$last_stage'"
    fi

    build_body=$(awk -v marker="FROM ${lang}-build AS ${lang}" '
        $0 == marker { exit }
        { print }
    ' "$dockerfile")
    if grep -Fq 'COPY tools/ /opt/runsecure/composition/tools/' <<<"$build_body" \
        && grep -Fq 'COPY infra/scripts/finalize-hardening.sh /opt/runsecure/composition/finalize-hardening.sh' <<<"$build_body"; then
        pass "${lang}: build stage embeds release composition assets"
    else
        fail "${lang}-embedded-assets" "build stage does not embed recipes and finalizer"
    fi
    if grep -Fq 'LABEL security.hardening="build-only"' <<<"$build_body" \
        && grep -Fq 'LABEL io.runsecure.image-role="composition"' <<<"$build_body"; then
        pass "${lang}: composition stage is labelled build-only"
    else
        fail "${lang}-build-metadata" "composition stage claims runnable hardening"
    fi

    terminal_body=$(awk -v marker="FROM ${lang}-build AS ${lang}" '
        $0 == marker { terminal=1 }
        terminal { print }
    ' "$dockerfile")
    if grep -Fq 'RUN /opt/runsecure/composition/finalize-hardening.sh' <<<"$terminal_body" \
        && grep -Fq '&& rm -rf /opt/runsecure/composition' <<<"$terminal_body" \
        && ! grep -qE '^[[:space:]]*COPY ' <<<"$terminal_body"; then
        pass "${lang}: terminal stage uses and removes embedded finalizer assets"
    else
        fail "${lang}-finalizer" "terminal stage copies mutable assets or does not remove embedded assets"
    fi
    if grep -Fq 'LABEL security.hardening="full"' <<<"$terminal_body" \
        && grep -Fq 'LABEL io.runsecure.image-role="runtime"' <<<"$terminal_body"; then
        pass "${lang}: terminal stage is labelled as the hardened runtime"
    else
        fail "${lang}-terminal-metadata" "terminal stage lacks truthful runtime metadata"
    fi
done

compose_script="${RUNSECURE_ROOT}/infra/scripts/compose-image.sh"
private_target="BUILD_TARGET_ARGS=(--target \"\${LANG}-build\")"
private_from="FROM \${LANG_BUILD_IMAGE}"
if grep -Fq "$private_target" "$compose_script" \
    && grep -Fq "$private_from" "$compose_script"; then
    pass "compose-image: project additions use the build-only stage"
else
    fail "compose-image-build-stage" "project composition can layer onto a terminal image"
fi

if grep -Fq 'io.runsecure.composition-base' "$compose_script" \
    && grep -Fq 'Required composition stage unavailable' "$compose_script" \
    && ! grep -qE '^COPY (tools|infra/scripts)' "$compose_script"; then
    pass "compose-image: versioned composition is digest-bound and fail-closed"
else
    fail "compose-image-release-pin" "versioned composition can consume mutable checkout inputs"
fi

finalize_dockerfile="${RUNSECURE_ROOT}/images/finalize-language.Dockerfile"
base_dockerfile="${RUNSECURE_ROOT}/images/base.Dockerfile"
if grep -Fq 'FROM ${BUILD_IMAGE}@${BUILD_DIGEST}' "$finalize_dockerfile" \
    && grep -Fq 'io.runsecure.composition-base="${COMPOSITION_BASE}"' "$finalize_dockerfile" \
    && grep -Fq 'security.hardening="full"' "$finalize_dockerfile" \
    && grep -Fq 'io.runsecure.image-role="runtime"' "$finalize_dockerfile"; then
    pass "publish: terminal runtime is derived from and labelled with one builder digest"
else
    fail "publish-builder-binding" "terminal runtime is not bound to its immutable builder digest"
fi

if grep -Fq 'LABEL security.hardening="build-only"' "$base_dockerfile" \
    && grep -Fq 'LABEL io.runsecure.image-role="composition-base"' "$base_dockerfile"; then
    pass "base: published composition input is not presented as a terminal runtime"
else
    fail "base-build-metadata" "composition base falsely claims full runtime hardening"
fi

h2_cache_fields="\${HARDENING_REMOVE}|\${HARDENING_STUB}"
if grep -Fq "$h2_cache_fields" "$compose_script"; then
    pass "compose-image: H2 overrides participate in the image cache key"
else
    fail "compose-image-h2-cache" "H2 overrides missing from image cache key"
fi

# Package maintainer scripts need account-management helpers while composing,
# but terminal images must not retain them.
finalizer="${RUNSECURE_ROOT}/infra/scripts/finalize-hardening.sh"
if grep -Fq '/usr/sbin/adduser' "$finalizer" \
    && grep -Fq '/usr/sbin/useradd' "$finalizer" \
    && grep -Fq '/usr/sbin/groupadd' "$finalizer"; then
    pass "finalizer: account-management helpers are removed after composition"
else
    fail "finalizer-account-tools" "account-management helpers are not removed terminally"
fi

base_runtime_removal=$(awk '
    /Security hardening: remove dangerous runtime utilities/ { block=1 }
    block { print }
    block && /2>\/dev\/null \|\| true/ { exit }
' "$base_dockerfile")
if grep -Fq '/usr/sbin/adduser' <<<"$base_runtime_removal"; then
    fail "base-build-account-tools" "adduser is removed before package composition"
else
    pass "base build: package account helpers survive until terminal finalization"
fi

echo "PASSED: $PASS; FAILED: $FAIL"
[[ "$FAIL" -eq 0 ]]
