FROM library/python:3.12-slim

ARG NUODBCLIENT_VERSION="2024.1"

# Install runtime dependencies
RUN set -ex; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
    vim \
    curl \
    libnss-wrapper \
    ; \
    rm -rf /var/lib/apt/lists/*

# Setup nuodb user and copy files as nuodb user
ENV NUODB_DEFAULT_UID 1000
COPY docker/user_setup /usr/local/bin
RUN user_setup

ENV NUOCLIENT_HOME /opt/nuodb-client
ENV NUOCMD_CLIENT_KEY /etc/nuodb/keys/nuocmd.pem
ENV NUOCMD_VERIFY_SERVER /etc/nuodb/keys/ca.cert

# Create directory for each tool
RUN mkdir $NUOCLIENT_HOME \
    && chown 1000:0 $NUOCLIENT_HOME
RUN mkdir /opt/config_watcher \
    && chown 1000:0 /opt/config_watcher
RUN mkdir /opt/nuodb-operations \
    && chown 1000:0 /opt/nuodb-operations

# Copy tools code as nuodb user
USER 1000:1000

# Download NuoDB client package
RUN curl -sSL "https://github.com/nuodb/nuodb-client/releases/download/v${NUODBCLIENT_VERSION}/nuodb-client-${NUODBCLIENT_VERSION}.lin-x64.tar.gz" | tar -xz --strip-components=1 -C $NUOCLIENT_HOME

# Copy sidecar scripts
COPY --chown=1000:0 config_watcher/requirements.txt /opt/config_watcher/requirements.txt
COPY --chown=1000:0 config_watcher/watcher.py /opt/config_watcher/watcher.py
COPY --chown=1000:0 nuodb-operations /opt/nuodb-operations
COPY --chown=1000:0 docker/entrypoint.sh /usr/local/bin/

# Install tools requirements
RUN pip3 install -r /opt/config_watcher/requirements.txt

ENTRYPOINT ["entrypoint.sh"]

CMD [ "config_watcher" ]
