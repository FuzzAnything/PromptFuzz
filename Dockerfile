FROM ubuntu:22.04

ENV PATH=/lib/llvm-18/bin:/usr/local/cargo/bin:/root/.cargo/bin:$PATH \ 
    LD_LIBRARY_PATH=/lib/llvm-18/lib \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    DEBIAN_FRONTEND=noninteractive \
    DOCKER_CONTAINER=1

RUN apt-get update \
    && apt-get -y install build-essential wget curl cmake git unzip patchelf graphviz python3 python3-pip lsb-release bison flex software-properties-common gnupg file libtool binutils autoconf libssl-dev openssl pkg-config libfontconfig libfontconfig1-dev zip libpsl-dev libbrotli-dev libcurl4 tcl \
    && apt-get clean \
    && pip3 install wllvm

# build llvm and clang dependency
RUN wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh 18 all \
    && ln -s /usr/bin/clang-18 /usr/bin/clang \
    && ln -s /usr/bin/clang++-18 /usr/bin/clang++

# Install Rust via proxy
ENV RUSTUP_DIST_SERVER=https://rsproxy.cn
ENV RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN mkdir -p $HOME/.cargo && \
    echo '[source.crates-io]\n\
replace-with = "rsproxy-sparse"\n\
[source.rsproxy]\n\
registry = "https://rsproxy.cn/crates.io-index"\n\
[source.rsproxy-sparse]\n\
registry = "sparse+https://rsproxy.cn/index/"\n\
[net]\n\
git-fetch-with-cli = true' > $HOME/.cargo/config.toml

# Install Dependency for easier development

RUN apt-get install -y tmux vim bubblewrap bubblewrap rsync yasm

RUN cd /root && git clone --single-branch https://github.com/gpakosz/.tmux.git && \
    ln -s -f .tmux/.tmux.conf && \
    cp .tmux/.tmux.conf.local . && \
    git clone https://github.com/pwndbg/pwndbg.git /tmp/pwndbg && \
    cd /tmp/pwndbg && \
    git submodule update --init --recursive && \
    ./setup.sh

git clone https://github.com/AFLplusplus/AFLplusplus.git /tmp/AFLplusplus && \
     cd /tmp/AFLplusplus && \
     sed -i 's|^#define USE_COLOR|/* #define USE_COLOR */|g' include/config.h && \
     export LLVM_CONFIG=llvm-config && \
     make all -j$(nproc) && \
     make install && \
     rm -rf /tmp/AFLplusplus

WORKDIR /root/promptfuzz
