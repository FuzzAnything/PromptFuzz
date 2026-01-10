#!/bin/bash

source ../common.sh

PROJECT_NAME=opencv
STALIB_NAME=libopencv_world.a
DYNLIB_NAME=libopencv_world.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y cmake yasm wget
    fi
    cd $SRC

    git clone --depth 1 https://github.com/opencv/opencv.git
}

function build_lib() {
    # Build aom
    LIB_STORE_DIR=$WORK/lib
    cd $SRC/${PROJECT_NAME}
    rm -rf build_fuzz
    mkdir -p build_fuzz
    cd build_fuzz
    echo "Configuring static build..."
cmake \
    -DCMAKE_INSTALL_PREFIX="$WORK" \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DOPENCV_GENERATE_PKGCONFIG=ON \
  -DOPENCV_GENERATE_PKGCONFIG=ON -wDOPENCV_FORCE_3RDPARTY_BUILD=ON \
  -DBUILD_TESTS=OFF -DBUILD_PERF_TESTS=OFF -DBUILD_opencv_apps=OFF \
  -DWITH_IMGCODEC_GIF=ON -DWITH_IPP=OFF "$SRC/${PROJECT_NAME}"

echo "Building static libraries..."
make -j$(nproc)

make install

# Post-process static libraries
cd "$WORK/lib"
if [ -d "opencv4/3rdparty" ]; then
    mkdir -p dependencies
    mv opencv4/3rdparty/*.a dependencies/ 2>/dev/null || true
    rm -rf opencv4
fi

# Merge static libraries if there are multiple
opencv_libs=( $(ls libopencv_*.a 2>/dev/null) )
if [ ${#opencv_libs[@]} -gt 1 ]; then
    echo "Merging ${#opencv_libs[@]} static libraries into libopencv_world.a"
    cat > merge.mri <<'MRI_EOF'
create libopencv_world.a
MRI_EOF
    for lib in "${opencv_libs[@]}"; do
        echo "addlib $lib" >> merge.mri
    done
    echo "save" >> merge.mri
    echo "end" >> merge.mri
    ar -M < merge.mri
    # Remove the individual libraries
    for lib in "${opencv_libs[@]}"; do
        rm "$lib"
    done
    rm merge.mri
elif [ ${#opencv_libs[@]} -eq 1 ]; then
    # If only one library, rename it to libopencv_world.a if not already
    if [ "${opencv_libs[0]}" != "libopencv_world.a" ]; then
        mv "${opencv_libs[0]}" libopencv_world.a
    fi
fi


    clang++ -shared -fPIC -o libopencv_world.so \
        -fuse-ld=lld \
        -Wl,--whole-archive libopencv_world.a -Wl,--no-whole-archive \
        -Wl,--allow-multiple-definition \
        -ldl -lpthread -lz -lm
}

function copy_include() {
    cd ${LIB_BUILD}
    mkdir -p include
    cp ${WORK}/include/openssl include/openssl -r
}

function build_corpus() {
    cd ${LIB_BUILD}
    mkdir corpus
}

function build_dict() {
    ls
}

build_all
