ARG DOCKER_REGISTRY_HOST
ARG CURRENT_DISTRO
ARG PEP_MACHINE_DIR
ARG PEPENGINE_VERSION
FROM ${DOCKER_REGISTRY_HOST}/pep-${CURRENT_DISTRO}-engine:${PEPENGINE_VERSION} AS pEpBuild

FROM ${DOCKER_REGISTRY_HOST}/fpm-${CURRENT_DISTRO}:latest
# whatever is required for building should be installed in this image; just like BuildRequires: for RPM specs
RUN yum -y install readline-devel epel-release && \
    yum -y install patchelf chrpath

ARG PEP_MACHINE_DIR
COPY --from=pEpBuild /install /source
COPY --from=pEpBuild ${PEP_MACHINE_DIR}/system.db ${PEP_MACHINE_DIR}/system.db

COPY install.sh /usr/local/bin/install.sh

ENV INSTPREFIX /source

RUN /usr/local/bin/install.sh
