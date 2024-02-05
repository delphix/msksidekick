FROM ubuntu:18.04

RUN apt-get update \
    && apt-get install -y libpar-packer-perl \
    && apt-get install -y libjson-pp-perl \
    && apt-get install -y libdate-manip-perl \
    && apt-get install -y libdatetime-format-dateparse-perl \
    && apt-get install -y libcrypt-cbc-perl \
    && apt-get install -y libcrypt-blowfish-perl \
    && apt-get install -y libtext-csv-perl \
    && apt-get install -y libtry-tiny-perl \
    && apt-get install -y libparse-http-useragent-perl \
    && apt-get install -y libnet-ssleay-perl \
    && apt-get install -y libio-socket-ssl-perl \
    && apt-get install -y libfilter-perl \
    && apt-get install -y libterm-readkey-perl \
    && apt-get install -y cpanminus \
    && apt-get install -y make \
    && apt-get install -y gcc \
    && apt-get install -y libssl-dev \
    && apt-get install -y libwww-perl \
    && cpanm DateTime::Event::Cron::Quartz \
    && cpanm Log::Syslog::Fast@0.65 \
    && cpanm Filter::Crypto::Decrypt

RUN apt-get update -y \
    && apt-get install -y software-properties-common binutils

RUN apt-get install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev

RUN apt-get install -y wget tree

RUN wget https://www.python.org/ftp/python/3.9.5/Python-3.9.5.tgz
RUN tar -xf Python-3.9.5.tgz
RUN cd Python-3.9.5 && ./configure --enable-optimizations   && make -j 4   && make altinstall   
RUN python3.9 -m pip install --upgrade pip
RUN python3.9 -m venv /venv --upgrade-deps
RUN export PATH=/venv/bin:$PATH; python -m pip install pyinstaller
#ENTRYPOINT ["/bin/sh echo 'Hello World'"]