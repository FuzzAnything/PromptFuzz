#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>

// declare the external fuzzing entry function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <seed file name>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];

    // 1. open the file in binary mode, and move the file pointer to the end
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    
    if (!file.is_open()) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return 1;
    }

    // 2. get the file size and allocate memory
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);

    // 3. read the file content into the buffer
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cout << "Read file successfully (" << size << " bytes). Start calling Harness..." << std::endl;

        // 4. call the fuzzing entry
        // note: even if size is 0, buffer.data() is safe in std::vector (although it may return nullptr)
        LLVMFuzzerTestOneInput(buffer.data(), static_cast<size_t>(size));

        std::cout << "Execution completed." << std::endl;
    } else {
        std::cerr << "Error: cannot read file content." << std::endl;
        return 1;
    }

    return 0;
}