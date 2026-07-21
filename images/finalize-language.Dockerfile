# Finalize one immutable language composition stage into its terminal runtime.
# BUILD_DIGEST is a multi-architecture manifest digest emitted by the preceding
# publish job. The terminal image and every future project composition therefore
# share the exact same language/runtime bytes.
ARG BUILD_IMAGE
ARG BUILD_DIGEST
FROM ${BUILD_IMAGE}@${BUILD_DIGEST}

ARG COMPOSITION_BASE
LABEL org.opencontainers.image.title="RunSecure Terminal Runtime"
LABEL org.opencontainers.image.description="Hardened terminal GitHub Actions runner. One job per container, then destroyed."
LABEL io.runsecure.composition-base="${COMPOSITION_BASE}"
LABEL io.runsecure.image-role="runtime"
LABEL security.hardening="full"

USER root
RUN /opt/runsecure/composition/finalize-hardening.sh \
    && rm -rf /opt/runsecure/composition

USER runner
WORKDIR /home/runner
