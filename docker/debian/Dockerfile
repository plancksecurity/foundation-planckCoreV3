
# building SequoiaBackend
FROM rust:1.70-bullseye as sequoiaBuilder
RUN apt-get update && apt-get install -yqq --no-install-recommends libclang-dev nettle-dev pkg-config libssl-dev
WORKDIR /root/
RUN git clone --depth=1 --branch=v1.0.0 https://git.planck.security/foundation/planckCoreSequoiaBackend.git
WORKDIR /root/planckCoreSequoiaBackend
COPY docker/debian/planckCoreSequoiaBackend.conf local.conf
RUN make install

# building yml2
FROM python:3.9-bullseye as yml2Builder
WORKDIR /root/
RUN git clone --depth=1 --branch=v2.7.5 https://git.planck.security/foundation/yml2.git
WORKDIR /root/yml2
RUN make dist

# building libetpan
FROM gcc:11-bullseye as libetpanBuilder 
WORKDIR /root/
RUN git clone --depth=1 --branch=1.9.4 https://github.com/dinhvh/libetpan.git
WORKDIR /root/libetpan
RUN ./autogen.sh --prefix=/opt/planck
RUN make -j4 install
WORKDIR /root/
#
#building ASN1C
FROM gcc:11-bullseye as asn1cBuilder 
WORKDIR /root/
RUN git clone --depth=1 --branch=v0.9.28 https://github.com/vlm/asn1c.git
WORKDIR /root/asn1c
RUN autoreconf -iv
RUN ./configure --prefix=/opt/planck
RUN make install
#
#building libPlanckTransport
FROM gcc:11-bullseye as libPlanckTransportBuilder
RUN apt-get update && apt-get install -yqq --no-install-recommends python3 python3-pip python-is-python3 virtualenv
WORKDIR /root/
COPY --from=yml2Builder /root/yml2/dist/yml2-2.7.4.tar.gz /root/
RUN virtualenv /root/virtualenv
RUN . /root/virtualenv/bin/activate && pip install /root/yml2-2.7.4.tar.gz
RUN git clone --depth=1 --branch=v1.0.0 https://git.planck.security/foundation/libPlanckTransport.git
WORKDIR /root/libPlanckTransport
COPY docker/debian/libPlanckTransport.conf local.conf
RUN . /root/virtualenv/bin/activate && make && make install


# building final runner
FROM gcc:11-bullseye as runner
RUN apt-get update && apt-get install -yqq --no-install-recommends sqlite3
WORKDIR /opt/tools
RUN git clone --dept=1 https://github.com/google/gtest-parallel.git

COPY --from=sequoiaBuilder /opt/planck /opt/planck

# WARNING: even if version v2.7.5 is checked out, the version is still 2.7.4
COPY --from=yml2Builder /root/yml2/dist/yml2-2.7.4.tar.gz /root/
RUN apt-get update && apt-get install -yqq --no-install-recommends python3 python3-pip virtualenv cmake libgtest-dev faketime
RUN virtualenv /opt/tools/virtualenv
RUN . /opt/tools/virtualenv/bin/activate && pip install /root/yml2-2.7.4.tar.gz

COPY --from=libetpanBuilder /opt/planck /opt/planck

COPY --from=asn1cBuilder /opt/planck /opt/planck

COPY --from=libPlanckTransportBuilder /opt/planck /opt/planck


ENV LD_LIBRARY_PATH=/opt/planck/lib
WORKDIR /root/planckCoreV3
