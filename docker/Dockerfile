# Dev/test image: real firewalld + Rust toolchain for interactive TUI testing on macOS.
# firewalld needs a system D-Bus and netfilter access, so run this container privileged
# (see docker-compose.yml). No systemd: dbus-daemon + firewalld are started by the
# entrypoint script.
#
# BASE_IMAGE selects the distro: fedora:44 (default, firewalld 2.x), almalinux:9
# (EL9, firewalld 1.x), or debian:13 (trixie, firewalld 2.3.x). Package names
# differ between families, so the RUN below branches on the package manager.
ARG BASE_IMAGE=fedora:44
FROM ${BASE_IMAGE} AS base

RUN if command -v dnf >/dev/null; then \
        dnf install -y \
            firewalld \
            nftables \
            dbus-daemon \
            dbus-tools \
            iproute \
            iputils \
            procps-ng \
            gcc \
        && dnf clean all; \
    else \
        apt-get update \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y \
            firewalld \
            nftables \
            dbus \
            iproute2 \
            iputils-ping \
            procps \
            curl \
            ca-certificates \
            build-essential \
            pkg-config \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# Rust via rustup (distro rustc may lag behind our MSRV)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /workspace

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]

FROM base AS coverage

ARG CARGO_LLVM_COV_VERSION=0.8.7
RUN rustup component add llvm-tools-preview \
    && cargo install cargo-llvm-cov --version "${CARGO_LLVM_COV_VERSION}" --locked

FROM base AS dev
