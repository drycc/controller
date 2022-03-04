FROM docker.io/drycc/base:bullseye

ARG DRYCC_UID=1001
ARG DRYCC_GID=1001
ARG DRYCC_HOME_DIR=/workspace

RUN groupadd drycc --gid ${DRYCC_GID} \
  && useradd drycc -u ${DRYCC_UID} -g ${DRYCC_GID} -s /bin/bash -m -d ${DRYCC_HOME_DIR}

ENV PYTHON_VERSION="3.10.2"
COPY requirements.txt ${DRYCC_HOME_DIR}/requirements.txt

RUN buildDeps='gcc libffi-dev libpq-dev rustc cargo'; \
    install-packages $buildDeps \
  && install-stack python $PYTHON_VERSION && . init-stack \
  && python3 -m venv ${DRYCC_HOME_DIR}/.venv \
  && source ${DRYCC_HOME_DIR}/.venv/bin/activate \
  && pip3 install --disable-pip-version-check --no-cache-dir -r ${DRYCC_HOME_DIR}/requirements.txt \
  && chown -R drycc:drycc ${DRYCC_HOME_DIR} \
  # set env
  && echo "source ${DRYCC_HOME_DIR}/.venv/bin/activate" >> /opt/drycc/python/profile.d/python.sh \
  # cleanup
  && scanelp ${DRYCC_HOME_DIR}/.venv/lib > runtime.txt \
  && apt-get purge -y --auto-remove $buildDeps \
  && install-packages $(< runtime.txt) \
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf \
        /usr/share/doc \
        /usr/share/man \
        /usr/share/info \
        /usr/share/locale \
        /var/lib/apt/lists/* \
        /var/log/* \
        /var/cache/debconf/* \
        /etc/systemd \
        /lib/lsb \
        /lib/udev \
        /usr/lib/`echo $(uname -m)`-linux-gnu/gconv/IBM* \
        /usr/lib/`echo $(uname -m)`-linux-gnu/gconv/EBC* \
  && mkdir -p /usr/share/man/man{1..8}

USER drycc

COPY --chown=drycc:drycc . ${DRYCC_HOME_DIR}
WORKDIR ${DRYCC_HOME_DIR}
CMD ["bin/boot"]
EXPOSE 8000
