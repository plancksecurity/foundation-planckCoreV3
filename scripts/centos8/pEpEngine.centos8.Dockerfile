ARG DOCKER_REGISTRY_HOST
ARG CURRENT_DISTRO
ARG PEPENGINE_VERSION
ARG SEQUOIA_VERSION
ARG YML2_VERSION
FROM ${DOCKER_REGISTRY_HOST}/pep-${CURRENT_DISTRO}-engine-deps:${SEQUOIA_VERSION}-${YML2_VERSION}

ENV BUILDROOT /build
ENV INSTPREFIX /install
ENV OUTDIR /out
ARG PEP_MACHINE_DIR

### Setup working directory
USER root
RUN mkdir -p ${BUILDROOT}/pEpEngine
COPY . ${BUILDROOT}/pEpEngine

RUN chown -R pep-builder:pep-builder ${BUILDROOT}/pEpEngine
WORKDIR ${BUILDROOT}/pEpEngine
USER pep-builder

ARG YML2_VERSION
ARG ENGINE_VERSION
ARG CURRENT_DISTRO

### Build pEpEngine
RUN sh ./scripts/common/build_pEpEngine.sh

### Install Systemdb
USER root

RUN sh ./scripts/common/install_pEpEngine_systemdb.sh && \
    rm -rf ${BUILDROOT}/*
