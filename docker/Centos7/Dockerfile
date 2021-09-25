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


FROM oraclelinux:7-slim

ADD . /msksidekick
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv ${VIRTUAL_ENV}
ENV PATH="${VIRTUAL_ENV}/bin:$PATH"
ENV WORKING_DIR=/msksidekick
RUN cd ${WORKING_DIR}; pip3 install -r requirements.txt
RUN pip install --upgrade pip

#CMD ["/bin/python3","--version"]
#CMD exec ./docker_dummy_tail.sh
RUN mkdir -p ~/.ssh; cp /msksidekick/id_rsa ~/.ssh; cp /msksidekick/github.config ~/.ssh/config
RUN echo "export LC_ALL=C.UTF-8" > .bashrc
RUN echo "export LANG=C.UTF-8" >> .bashrc
RUN git config --global user.email "at.oracledba@gmail.com"
RUN git config --global user.name "Ajay Thotangare"
RUN chmod 755 ${WORKING_DIR}/docker_dummy_tail.sh
RUN export LC_ALL=en_US.utf-8
RUN export LANG=en_US.utf-8
RUN if [ -d "${WORKING_DIR}/dist" ]; then rm -Rf ${WORKING_DIR}/dist; fi
RUN cd ${WORKING_DIR}; pyinstaller -F ${WORKING_DIR}/msksidekick.py --onefile
CMD exec ${WORKING_DIR}/docker_dummy_tail.sh
