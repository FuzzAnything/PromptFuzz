# Developer Guide
This is the document for who want to develop upon PromptFuzz.


## 1. Locally Build
If you prefer to set up the environment locally instead of using Docker, you can follow the instructions below:

**Requirements:**
- Rust stable
- LLVM and Clang (built with compiler-rt)
- wllvm (installed by `pip3 install wllvm`)

You can download llvm and clang from this [link](https://github.com/llvm/llvm-project/releases/tag/llvmorg-18.0.0) or install by [llvm.sh](https://apt.llvm.org/).

Explicit dependency see [Dockerfile](Dockerfile).

If you prefer build llvm manually, you can build clang with compiler-rt and libcxx from source code following the config:
```
cmake -S llvm -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="clang;lld" \
 -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;compiler-rt;" \
 -DCMAKE_BUILD_TYPE=Release -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
 -DLIBCXXABI_ENABLE_SHARED=OFF  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ 
 ```


### 2. Add Library Support
Before you apply this fuzzer for a new project, you **must** have a automatic build script to build your project to prepare the required data (e.g., headers, link libraries, fuzzing corpus and etc.), like [OSS-Fuzz](https://github.com/google/oss-fuzz). 

The instructions for adding new libraries see [Preparation](data/README.md).


We have prepared the build scripts for some popular open source libraries, you can refer to the [libraries](libraries/README.md) directory.


