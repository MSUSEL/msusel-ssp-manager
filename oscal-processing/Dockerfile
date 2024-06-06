# Adapted from blossom-archive Dockerfile created by AJ.
# Current maven:3.8.6-openjdk-11-slim
ARG MAVEN_VERSION=sha256:bed43e35f3e5f013670d4d7d247612de5ac82355b0c58c244005c532dfe6a1d7

FROM maven@${MAVEN_VERSION} as builder

RUN apt-get update && \
    apt-get install unzip

RUN mkdir -p /tmp/oscal-cli
COPY ./cli-core-0.3.1-oscal-cli /tmp/oscal-cli
RUN chmod +x /tmp/oscal-cli/bin/oscal-cli

FROM maven@${MAVEN_VERSION} 

WORKDIR /opt/oscal-cli

COPY --from=builder /tmp/oscal-cli /opt/oscal-cli

COPY . .

RUN chmod +x /opt/oscal-cli/script.sh
ENTRYPOINT ["sh", "script.sh"]
