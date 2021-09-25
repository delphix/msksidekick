FROM centos:7

RUN yum install -y python3 \
    && yum install -y python3-devel \
    && yum install -y git

RUN mkdir -p /github/workspace
RUN mkdir -p /github/home
RUN mkdir -p /github/workflow
COPY entrypoint.sh /entrypoint.sh
WORKDIR /github/workspace
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

