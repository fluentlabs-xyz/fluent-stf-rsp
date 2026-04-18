# nitro-builder.Dockerfile — pinned build environment for AWS Nitro EIF.
#
# All host-version dependencies that affect PCR0 (nitro-cli, its kernel/init
# blobs, docker CLI, buildx) live inside this image. Host only needs any
# Docker daemon to run the builder; PCR0 is determined by this image's digest.
#
# Build once:
#   docker build -f docker/nitro-builder.Dockerfile -t fluent-nitro-builder:1.4.2 .
# Consume digest output:
#   docker inspect --format '{{index .RepoDigests 0}}' fluent-nitro-builder:1.4.2

FROM amazonlinux:2023@sha256:cfa6c2d0270c6517c0e46cb87aed7edcae8d9eb96af5f51814b6ee8680faaa2c

ARG NITRO_CLI_VERSION=1.4.2-0.amzn2023
ARG DOCKER_VERSION=25.0.13-1.amzn2023.0.3
ARG BUILDX_VERSION=0.21.2
ARG BUILDX_SHA256=b13bee81c3db12a4be7d0b9d042b64d0dd9ed116f7674dfac0ffdf2a71acfe3d

RUN dnf install -y \
        aws-nitro-enclaves-cli-${NITRO_CLI_VERSION} \
        aws-nitro-enclaves-cli-devel-${NITRO_CLI_VERSION} \
        docker-${DOCKER_VERSION} \
        curl-minimal \
        jq \
        python3 \
        make \
        git \
    && dnf clean all \
    && rm -rf /var/cache/dnf

RUN mkdir -p /usr/libexec/docker/cli-plugins \
    && curl -fsSL -o /usr/libexec/docker/cli-plugins/docker-buildx \
        "https://github.com/docker/buildx/releases/download/v${BUILDX_VERSION}/buildx-v${BUILDX_VERSION}.linux-amd64" \
    && echo "${BUILDX_SHA256}  /usr/libexec/docker/cli-plugins/docker-buildx" | sha256sum -c - \
    && chmod +x /usr/libexec/docker/cli-plugins/docker-buildx

RUN nitro-cli --version \
    && docker --version \
    && docker buildx version

WORKDIR /src
ENTRYPOINT ["/bin/bash"]
