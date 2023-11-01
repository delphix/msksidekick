
# Use the official CentOS 8 base image
FROM centos:8

# Set the maintainer label
LABEL maintainer="at.oracledba@gmail.com"

RUN cd /etc/yum.repos.d/
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# Update the system and install necessary packages
RUN yum -y update && \
    yum -y install epel-release && \
    yum -y install python3.9 python3-pip && \
    yum clean all

# Symlink python3 and pip3 to default python and pip
RUN ln -s /usr/bin/python3 /usr/bin/python && \
    ln -s /usr/bin/pip3 /usr/bin/pip

# Set the working directory inside the container
# WORKDIR /app

# Optional: Copy your application files to the container
# COPY . /app

# Optional: Install any Python packages your application requires
# RUN pip install -r requirements.txt

ENV CFLAGS "-std=gnu99"

RUN pip install --upgrade pip
RUN pip install --upgrade setuptools
RUN pip install --upgrade wheel
RUN pip install --upgrade pyinstaller
RUN pip install --upgrade jeepney

#RUN pip3 install wheel \
#    && pip3 install pyinstaller \
#    && pip3 install jeepney

RUN mkdir -p /github/workspace
RUN mkdir -p /github/home
RUN mkdir -p /github/workflow
COPY entrypoint.sh /entrypoint.sh
WORKDIR /github/workspace
RUN chmod +x /entrypoint.sh

# Specify the default command to run when the container starts
ENTRYPOINT ["/entrypoint.sh"]


