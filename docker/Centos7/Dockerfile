FROM centos:7

RUN yum install -y python3 \
    && yum install -y python3-devel \
    && yum install -y python3-pip \
    && yum install -y gcc \
    && yum install -y zlib-devel \
    && yum install -y python3-setuptools \
    && yum install -y python3-libs \
    && yum install -y gcc

ENV CFLAGS "-std=gnu99"

RUN pip3 install wheel \
    && pip3 install pyinstaller \
    && pip3 install jeepney

RUN mkdir -p /github/workspace
RUN mkdir -p /github/home
RUN mkdir -p /github/workflow
COPY entrypoint.sh /entrypoint.sh
WORKDIR /github/workspace
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
