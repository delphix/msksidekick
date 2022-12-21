FROM centos:7

RUN yum install -y epel-release \
    && yum -y update

RUN yum -y groupinstall "Development Tools" \
    && yum install -y openssl \
    && yum install -y openssl-devel \
    && yum install -y bzip2-devel \
    && yum install -y libffi-devel \
    && yum install -y xz-devel \
    && yum install -y wget \
    && yum install -y which \
    && yum install -y zlib-devel \
    && yum install -y gcc

RUN wget https://www.python.org/ftp/python/3.8.12/Python-3.8.12.tgz
RUN tar xvf Python-3.8.12.tgz
RUN cd Python-3.8*/
ENV LD_LIBRARY_PATH "${LD_LIBRARY_PATH}:/Python-3.8.12"
ENV CFLAGS "-std=gnu99"
RUN cd /Python-3.8.12 \
    && ./configure --prefix=/usr/local --enable-shared LDFLAGS="-Wl,-rpath /Python-3.8.12"
RUN cd /Python-3.8.12 \
    && make altinstall
RUN /usr/local/bin/python3.8 -m pip install --upgrade pip

RUN pip3.8 install urllib3==1.26 \
    && pip3.8 install charset-normalizer==2

RUN pip3.8 install pyinstaller

RUN mkdir -p /github/workspace \
    && mkdir -p /github/home \
    && mkdir -p /github/workflow

COPY entrypoint.sh /entrypoint.sh
WORKDIR /github/workspace
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
