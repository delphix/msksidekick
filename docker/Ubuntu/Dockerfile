# Use Ubuntu 18.04 as base image
FROM ubuntu:18.04

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    zlib1g-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libssl-dev \
    libreadline-dev \
    libffi-dev \
    libsqlite3-dev \
    libbz2-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download and install Python 3.9
#RUN wget https://www.python.org/ftp/python/3.9.5/Python-3.9.5.tgz \
#    && tar -xf Python-3.9.5.tgz \
#    && cd Python-3.9.5 \
#    && ./configure --enable-optimizations \
#    && make -j$(nproc) \
#    && make altinstall \
#    && cd .. \
#    && rm -rf Python-3.9.5*

RUN wget https://www.python.org/ftp/python/3.9.5/Python-3.9.5.tgz \
    && tar -xf Python-3.9.5.tgz \
    && cd Python-3.9.5 \
    && ./configure --enable-optimizations \
    && make -j$(nproc) \
    && make altinstall \
    && cd ..

# Set environment variables
ENV PATH="/usr/local/bin:$PATH"

# Install PyInstaller
RUN python3.9 -m pip install pyinstaller
RUN python3.9 -m pip install staticx

# Set the working directory
WORKDIR /

