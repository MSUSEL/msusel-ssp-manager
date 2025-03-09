# Adapted from blossom-archive Dockerfile created by AJ.
# Current maven:3.8.6-openjdk-11-slim
ARG MAVEN_VERSION=sha256:bed43e35f3e5f013670d4d7d247612de5ac82355b0c58c244005c532dfe6a1d7

FROM maven@${MAVEN_VERSION} AS builder

RUN apt-get update && \
    apt-get install unzip

RUN mkdir -p /tmp/oscal-cli
COPY ./cli-core-v2.4.0-oscal-cli /tmp/oscal-cli
RUN chmod +x /tmp/oscal-cli/bin/oscal-cli

FROM maven@${MAVEN_VERSION} 

WORKDIR /opt/oscal-cli

# Create a non-root user
RUN useradd -ms /bin/bash appuser

# Add appuser to the group with GID 1001 (host docker group)
RUN groupadd -g 1001 dockergroup && usermod -aG dockergroup appuser

COPY --from=builder /tmp/oscal-cli /opt/oscal-cli

COPY . .

RUN chown -R appuser:appuser /opt/oscal-cli

# Switch to the non-root user
USER appuser


RUN chmod +x /opt/oscal-cli/script.sh
ENTRYPOINT ["sh", "script.sh"]
