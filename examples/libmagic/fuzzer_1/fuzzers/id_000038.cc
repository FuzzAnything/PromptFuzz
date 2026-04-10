#include "FDSan.h"
#include "FuzzedDataProvider.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
extern "C" {
#include <magic.h>
}
//<ID> 836
//<Prompt> []
/*<Combination>: [
*/
//<score> 27, nr_unique_branch: 2
//<Quality> {"density":9,"unique_branches":{"file_printable":[[851,7,851,35,0,0,4,0]],"magic_getparam":[[691,2,691,9,0,0,4,0]]},"library_calls":["magic_open","magic_getpath","magic_load_buffers","magic_check","magic_compile","magic_getflags","magic_buffer","magic_descriptor","magic_error","magic_getparam","magic_close"],"critical_calls":["magic_open","magic_getpath","magic_load_buffers","magic_check","magic_compile","magic_getflags","magic_buffer","magic_descriptor","magic_error","magic_getparam","magic_close"],"visited":0}
/**/


// Function to safely copy data to avoid out-of-bounds access
template<typename T>
bool safe_copy(const uint8_t* data, size_t size, size_t offset, T* dest, size_t count = 1) {
    if (offset + sizeof(T) * count > size) return false;
    memcpy(dest, data + offset, sizeof(T) * count);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}
	FILE *input_file_ptr = fopen("input_file", "wb");
	if (input_file_ptr == NULL) {return 0;}
	fwrite(data, sizeof(uint8_t), size, input_file_ptr);
	fclose(input_file_ptr);





    // Early return if we don't have enough data for basic operations
    if (size < 32) {
	return 0;
	}
	
    
    // Variables needed for our fuzzing scenario
    int flags = 0;
    const char* error_msg = nullptr;
    void* param_value = nullptr;
    size_t param_size = 0;
    int param_type = 0;
    int descriptor_fd = -1;
    const char* result = nullptr;
    
    // Split the input data into different parts for different operations
    // Part 1: Flags and parameters
    size_t offset = 0;
    
    // Extract flags
    if (!safe_copy(data, size, offset, &flags)) {
	return 0;
	}
	
    offset += sizeof(int);
    
    // Extract parameter type
    if (!safe_copy(data, size, offset, &param_type)) {
	return 0;
	}
	
    offset += sizeof(int);
    
    // Extract parameter size (for getparam)
    if (!safe_copy(data, size, offset, &param_size)) {
	return 0;
	}
	
    offset += sizeof(size_t);
    
    // Allocate memory for parameter value if needed
    if (param_size > 0 && param_size <= 1024) { // Limit to reasonable size
        param_value = malloc(param_size);
        if (!param_value) return 0;
    }
    
    // Part 2: Magic database buffer data
    size_t magic_data_size = size / 4; // Use 25% of input for magic database
    if (magic_data_size > size - offset) magic_data_size = size - offset;
    
    // Prepare buffers for magic_load_buffers
    std::vector<void*> magic_buffers;
    std::vector<size_t> buffer_sizes;
    
    // Split the magic data into 2 buffers
    if (magic_data_size > 0) {
        size_t buf1_size = magic_data_size / 2;
        size_t buf2_size = magic_data_size - buf1_size;
        
        void* buf1 = malloc(buf1_size);
        void* buf2 = malloc(buf2_size);
        
        if (!buf1 || !buf2) {
            free(buf1); free(buf2);
            free(param_value);
            return 0;
        }
        
        if (offset + buf1_size > size) {
            free(buf1); free(buf2);
            free(param_value);
            return 0;
        }
        
        memcpy(buf1, data + offset, buf1_size);
        offset += buf1_size;
        
        if (offset + buf2_size > size) {
            free(buf1); free(buf2);
            free(param_value);
            return 0;
        }
        
        memcpy(buf2, data + offset, buf2_size);
        offset += buf2_size;
        
        magic_buffers.push_back(buf1);
        magic_buffers.push_back(buf2);
        buffer_sizes.push_back(buf1_size);
        buffer_sizes.push_back(buf2_size);
    }
    
    // Part 3: Remaining data for magic_buffer and file operations
    size_t remaining_size = size - offset;
    const void* buffer_data = data + offset;
    
    // Create a magic cookie
    magic_t cookie = magic_open(flags);
    if (!cookie) {
        // Cleanup
        for (void* buf : magic_buffers) free(buf);
        free(param_value);
        return 0;
    }
    
    // Use magic_getpath to get default magic database path
    const char* magic_path = magic_getpath("/usr/share/misc/magic", 0);
    (void)magic_path; // Suppress unused warning
    
    // Load magic database from buffers
    if (!magic_buffers.empty()) {
        magic_load_buffers(cookie, magic_buffers.data(), buffer_sizes.data(), magic_buffers.size());
    }
    
    // Check the magic database (we'll use a dummy file name since we loaded from buffers)
    magic_check(cookie, "input_file");
    
    // Try to compile the magic database to a file
    magic_compile(cookie, "output_file");
    
    // Get current flags
    int current_flags = magic_getflags(cookie);
    (void)current_flags; // Suppress unused warning
    
    // Analyze a buffer with the loaded magic database
    if (remaining_size > 0) {
        result = magic_buffer(cookie, buffer_data, remaining_size);
        (void)result; // Suppress unused warning
    }
    
    // Create a FILE* from memory for descriptor operations
    FILE* in_file = fmemopen((void*)buffer_data, remaining_size, "rb");
    if (in_file) {
        descriptor_fd = fuzz_fileno(in_file);
        
        // Use magic_descriptor
        if (descriptor_fd >= 0) {
            result = magic_descriptor(cookie, descriptor_fd);
            (void)result; // Suppress unused warning
        }
        
        assert_file_closed(&in_file);;
    }
    
    // Get any error messages
    error_msg = magic_error(cookie);
    (void)error_msg; // Suppress unused warning
    
    // Get a parameter if we have allocated space
    if (param_value && param_size > 0) {
        magic_getparam(cookie, param_type, param_value);
    }
    
    // Cleanup
    magic_close(cookie);
    
    for (void* buf : magic_buffers) {
        free(buf);
    }
    
    free(param_value);
    
    assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	return 0;
}