FROM ubuntu:22.04

# Prevent apt and tzdata from blocking on interactive prompts
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# Version of the prebuilt payload-dumper-go binary to download.
# Check https://github.com/ssut/payload-dumper-go/releases for newer versions.
ARG DUMPER_VERSION=1.2.2

# Install runtime dependencies + curl (used only during build, removed after)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 \
        binutils \
        unzip \
        p7zip-full \
        curl \
        ca-certificates \
 && curl --fail --location --show-error \
        "https://github.com/ssut/payload-dumper-go/releases/download/${DUMPER_VERSION}/payload-dumper-go_${DUMPER_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/payload-dumper-go.tar.gz \
 && mkdir -p /opt/tools \
 && tar -xzf /tmp/payload-dumper-go.tar.gz -C /opt/tools \
 && chmod +x /opt/tools/payload-dumper-go \
 && rm /tmp/payload-dumper-go.tar.gz \
 && apt-get remove -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# Entrypoint script: installs the dumper binary into /workspace/tools/ if
# it is not already there, then execs whatever command was requested.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command — override on the docker run line if needed
CMD ["python3", "src/pipeline.py"]
