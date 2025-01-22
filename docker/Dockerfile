FROM library/python:3.12-slim

ARG PYNUOADMIN_VERSION=2.5.0

# Install runtime dependencies
RUN set -ex; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
    libnss-wrapper \
    ; \
    rm -rf /var/lib/apt/lists/*

# Setup nuodb user and copy files as nuodb user
ENV NUODB_DEFAULT_UID 1000
COPY docker/user_setup /usr/local/bin
RUN user_setup

# Create directory for each tool
RUN mkdir /opt/config_watcher \
    && chown 1000:0 /opt/config_watcher
RUN mkdir /opt/nuodb-operations \
    && chown 1000:0 /opt/nuodb-operations

# Copy tools code as nuodb user
USER 1000:0

# Copy sidecar scripts
COPY --chown=1000:0 config_watcher/requirements.txt /opt/config_watcher/requirements.txt
COPY --chown=1000:0 config_watcher/watcher.py /opt/config_watcher/watcher.py
COPY --chown=1000:0 nuodb-operations /opt/nuodb-operations
COPY --chown=1000:0 docker/entrypoint.sh /usr/local/bin/

# Install tools requirements
RUN pip3 install -r /opt/config_watcher/requirements.txt

# Install pynuoadmin
RUN pip3 install pynuoadmin==${PYNUOADMIN_VERSION}
RUN echo "export NUOCMD_PYTHONPATH=$(pip show pynuoadmin | sed -ne 's|Location: \(.*\)|\1|p')" >> /home/nuodb/.profile

ENV NUOCMD_CLIENT_KEY /etc/nuodb/keys/nuocmd.pem
ENV NUOCMD_VERIFY_SERVER /etc/nuodb/keys/ca.cert

ENV LANG en_US.UTF-8
ENV HOME /home/nuodb

ENTRYPOINT ["entrypoint.sh"]

CMD [ "config_watcher" ]
