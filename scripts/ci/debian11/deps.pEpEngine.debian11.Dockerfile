FROM registry.gitlab.com/sequoia-pgp/build-docker-image/bookworm-prebuild:latest

ARG DOCKER_REGISTRY_HOST
ARG CURRENT_DISTRO
ARG PEPENGINE_VERSION
ARG PEPTRANSPORT_VERSION
ARG SEQUOIA_VERSION
ARG CARGO_HOME
ARG BUILD
ARG CARGO_TARGET_DIR

ENV BUILDROOT /build
ENV INSTPREFIX /install
ENV PREFIX /install
ENV OUTDIR /out
ARG PEP_MACHINE_DIR

RUN echo DOCKER_REGISTRY_HOST=$DOCKER_REGISTRY_HOST
RUN echo CURRENT_DISTRO=$CURRENT_DISTRO
RUN echo PEPENGINE_VERSION=$PEPENGINE_VERSION
RUN echo PEPTRANSPORT_VERSION=$PEPTRANSPORT_VERSION
RUN echo SEQUOIA_VERSION=$SEQUOIA_VERSION
  
### Create basic dirs
RUN mkdir -p ${BUILDROOT}
RUN mkdir -p ${INSTPREFIX}
RUN mkdir -p ${OUTDIR}
RUN mkdir -p ${BUILD}
RUN mkdir -p ${CARGO_HOME}

RUN adduser --shell /bin/sh --disabled-password --gecos "" pep-builder

RUN chown -R pep-builder:pep-builder ${BUILDROOT} && \
    chown -R pep-builder:pep-builder ${INSTPREFIX} && \
    chown -R pep-builder:pep-builder ${OUTDIR} && \
    chown -R pep-builder:pep-builder ${BUILD} && \
    chown -R pep-builder:pep-builder ${CARGO_HOME} && \
    chown -R pep-builder:pep-builder /home/pep-builder

WORKDIR /build

### Setup working directory
RUN mkdir -p ${BUILDROOT}/pEpEngine
COPY ./scripts/ci/common/build_pEpEngine_deps.sh ${BUILDROOT}/pEpEngine

# Install the common system dependencies for building the pEp Software Stack.

RUN apt-get update -y -qq && \
    apt-get upgrade -y -qq && \
    apt-get install -y -qq curl openssl libssl-dev pkg-config git \
	mercurial capnproto clang sqlite3 libsqlite3-0 libgtest-dev \
	libsqlite3-dev python3 python3-lxml build-essential automake \
	libtool autoconf make nettle-dev capnproto uuid-dev bzip2 \
	cmake faketime opendoas && \
	rm -rf /var/lib/apt/lists/*

## gtest source installed by operating system package libgtest-dev
RUN cd /usr/src/gtest && \
    cmake CMakeLists.txt && \
    cd -

### Setup PEP_MACHINE_DIR
RUN mkdir -p ${PEP_MACHINE_DIR}

RUN echo 'permit nopass pep-builder as root' > /etc/doas.conf
RUN chown -R pep-builder:pep-builder ${BUILDROOT}/pEpEngine
WORKDIR ${BUILDROOT}/pEpEngine

ARG YML2_VERSION
ARG ENGINE_VERSION
ARG PEPTRANSPORT_VERSION
ARG CURRENT_DISTRO

### Build pEpEngine dependencies
USER pep-builder

RUN sh ./build_pEpEngine_deps.sh
