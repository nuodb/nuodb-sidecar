FROM library/python:3.12-slim

# Create nuodb user/group entries and home directory
RUN echo "nuodb:x:1000:1000:nuodb user:/home/nuodb:/bin/bash" >> /etc/passwd \
    && echo "nuodb:x:1000:" >> /etc/group \
    && mkdir -p /home/nuodb \
    && chown 1000:1000 /home/nuodb

# Create directory for each tool
RUN mkdir /opt/config_watcher \
    && chown 1000:1000 /opt/config_watcher
RUN mkdir /opt/nuodb-operations \
    && chown 1000:1000 /opt/nuodb-operations

# Copy tools code as nuodb user
USER 1000:1000

# Copy sidecar scripts
COPY --chown=1000:1000 config_watcher/requirements.txt /opt/config_watcher/requirements.txt
COPY --chown=1000:1000 config_watcher/watcher.py /opt/config_watcher/watcher.py
COPY --chown=1000:1000 nuodb-operations /opt/nuodb-operations
COPY --chown=1000:1000 docker/entrypoint.sh /usr/local/bin/

# Install tools requirements
RUN pip3 install -r /opt/config_watcher/requirements.txt

ENTRYPOINT ["entrypoint.sh"]

CMD [ "config_watcher" ]
