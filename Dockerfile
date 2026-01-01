FROM ubuntu:22.04

ENV PATH=/lib/llvm-18/bin:/usr/local/cargo/bin:/root/.cargo/bin:$PATH \ 
    LD_LIBRARY_PATH=/lib/llvm-18/lib \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    DEBIAN_FRONTEND=noninteractive \
    DOCKER_CONTAINER=1

RUN apt-get update \
    && apt-get -y install build-essential wget curl cmake git unzip patchelf graphviz python3 python3-pip lsb-release bison flex software-properties-common gnupg file libtool binutils autoconf libssl-dev openssl pkg-config libfontconfig libfontconfig1-dev zip libpsl-dev libbrotli-dev \
    && apt-get clean \
    && pip3 install wllvm

# build llvm and clang dependency
RUN wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh 18 \
    && ln -s /usr/bin/clang-18 /usr/bin/clang \
    && ln -s /usr/bin/clang++-18 /usr/bin/clang++

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && rustup default stable

# Install Dependency for easier development
RUN apt-get install -y tmux vim 

RUN cd /root && git clone --single-branch https://github.com/gpakosz/.tmux.git && \
    ln -s -f .tmux/.tmux.conf && \
    cp .tmux/.tmux.conf.local . && \
    git clone https://github.com/pwndbg/pwndbg.git /tmp/pwndbg && \
    cd /tmp/pwndbg && \
    git submodule update --init --recursive && \
    ./setup.sh

WORKDIR /root/promptfuzz
