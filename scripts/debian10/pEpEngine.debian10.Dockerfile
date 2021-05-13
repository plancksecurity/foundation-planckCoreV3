ARG DOCKER_REGISTRY_HOST
ARG CURRENT_DISTRO
ARG PEPENGINE_VERSION
ARG SEQUOIA_VERSION
FROM ${DOCKER_REGISTRY_HOST}/pep-${CURRENT_DISTRO}-sequoia:${SEQUOIA_VERSION}

ENV BUILDROOT /build
ENV INSTPREFIX /install
ENV OUTDIR /out
ARG PEP_MACHINE_DIR

### Setup working directory
RUN mkdir ${BUILDROOT}/pEpEngine
COPY . ${BUILDROOT}/pEpEngine

USER root

RUN chown -R pep-builder:pep-builder ${BUILDROOT}/pEpEngine
WORKDIR ${BUILDROOT}/pEpEngine

ARG YML2_VERSION
ARG ENGINE_VERSION
ARG CURRENT_DISTRO

RUN  apt-get update && apt-get install -y bzip2 && \
     rm -rf /var/lib/apt/lists/*

### Build pEpEngine dependencies
USER pep-builder

RUN sh ./scripts/${CURRENT_DISTRO}/build_pEpEngine_deps.sh

### Build pEpEngine
RUN sh ./scripts/${CURRENT_DISTRO}/build_pEpEngine.sh

### Install Systemdb
USER root

RUN sh ./scripts/${CURRENT_DISTRO}/install_pEpEngine_systemdb.sh && \
    rm -rf ${BUILDROOT}/*
