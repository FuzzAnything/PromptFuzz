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
//<ID> 491
//<Prompt> []
/*<Combination>: [
*/
//<score> 72, nr_unique_branch: 49
//<Quality> {"density":12,"unique_branches":{"do_ops":[[1505,3,1505,18,0,0,4,0]],"handle_annotation":[[2544,7,2544,57,0,0,4,0],[2548,7,2548,37,0,0,4,0]],"magic_buffer":[[561,6,561,52,0,0,4,0]],"cvt_32":[[1070,3,1070,17,3,0,4,0],[1085,3,1085,21,3,0,4,0],[1087,8,1087,36,3,0,4,0],[1087,8,1087,36,3,0,4,1]],"file_strncmp":[[2091,14,2091,22,0,0,4,1]],"magiccheck":[[2298,7,2298,15,0,0,4,1],[2320,17,2320,34,0,0,4,0],[2328,8,2328,14,0,0,4,0]],"file_push_buffer":[[801,6,801,37,0,0,4,0]],"cvt_64":[[1076,3,1076,18,4,0,4,0]],"cvt_8":[[1073,3,1073,18,3,0,4,0],[1085,3,1085,21,3,0,4,0],[1087,8,1087,36,3,0,4,0],[1087,8,1087,36,3,0,4,1],[1085,3,1085,21,4,0,4,0],[1087,8,1087,36,4,0,4,0],[1087,8,1087,36,4,0,4,1]],"buffer_fill":[[80,6,80,18,0,0,4,0]],"mget":[[1709,4,1709,20,0,0,4,0],[1764,8,1764,54,0,0,4,1],[1918,7,1918,22,0,0,4,1],[1921,7,1921,42,0,0,4,0],[1921,7,1921,42,0,0,4,1],[1931,34,1931,53,0,0,4,0],[1931,34,1931,53,0,0,4,1],[1934,8,1937,36,0,0,4,1],[1942,7,1942,37,0,0,4,1],[1946,7,1946,19,0,0,4,0],[1946,23,1946,54,0,0,4,1],[1949,7,1949,14,0,0,4,1],[2005,7,2005,31,0,0,4,0],[72,59,72,76,12,0,4,1],[109,22,109,25,13,0,4,0],[72,30,72,40,21,0,4,1],[72,59,72,76,21,0,4,0],[72,59,72,76,21,0,4,1],[109,22,109,25,22,0,4,0],[72,30,72,40,32,0,4,0],[72,30,72,40,32,0,4,1],[72,59,72,76,32,0,4,0],[109,22,109,25,50,0,4,0],[109,22,109,25,56,0,4,0],[72,59,72,76,58,0,4,1],[109,22,109,25,59,0,4,1],[72,59,72,76,69,0,4,0]]},"library_calls":["magic_open","magic_load_buffers","magic_close","magic_setflags","magic_close","magic_file","magic_file","magic_buffer","magic_list","magic_compile","magic_errno","magic_close"],"critical_calls":["magic_open","magic_load_buffers","magic_setflags","magic_file","magic_file","magic_buffer","magic_list","magic_compile","magic_errno","magic_close"],"visited":1}
/**/


extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}




    // Early return if input is too small for meaningful processing
    if (size < 2) {
        return 0;
    }

    // Create magic cookie with flags
    magic_t cookie = magic_open(MAGIC_NONE | MAGIC_ERROR);
    if (cookie == nullptr) {
        return 0;
    }

    // Split input data into two parts for different purposes
    // First part: buffer data for magic database compilation
    // Second part: file data for magic analysis
    size_t split_point = size / 2;
    
    // Prepare buffers for magic database loading
    void* buffer_array[1];
    size_t sizes_array[1];
    
    buffer_array[0] = (void*)data;
    sizes_array[0] = split_point;

    // Load magic database from buffer
    if (magic_load_buffers(cookie, buffer_array, sizes_array, 1) != 0) {
        magic_close(cookie);
        return 0;
    }

    // Set additional flags for magic analysis
    magic_setflags(cookie, MAGIC_MIME);

    // Create a temporary file for magic_file testing
    FILE* in_file = fmemopen((void*)(data + split_point), size - split_point, "rb");
    if (in_file == nullptr) {
        magic_close(cookie);
        assert_file_closed(&in_file);
	return 0;
    }

    // Get file descriptor for magic_descriptor if needed (though not in our API list)
    // We'll just keep it for potential use
    int fd = fuzz_fileno(in_file);

    // Use magic_file to analyze the temporary file
    const char* file_result = magic_file(cookie, "dummy_path");
    // Note: magic_file needs actual file path, so we'll create one
    FILE* temp_file = fopen("temp_input_file", "wb");
    if (temp_file != nullptr) {
        fwrite(data + split_point, 1, size - split_point, temp_file);
        assert_file_closed(&temp_file);;
        
        file_result = magic_file(cookie, "temp_input_file");
        remove("temp_input_file");
    }

    // Use magic_buffer to analyze the data buffer directly
    const char* buffer_result = magic_buffer(cookie, data + split_point, size - split_point);

    // List magic entries to an output file
    FILE* out_file = fopen("output_file", "wb");
    if (out_file != nullptr) {
        // We can't directly capture magic_list output since it writes to file
        // So we'll specify our output file
        magic_list(cookie, "magic_list_output.txt");
        assert_file_closed(&out_file);;
    }

    // Compile magic database to a file
    magic_compile(cookie, "compiled.mgc");

    // Check for errors using magic_errno
    int error_code = magic_errno(cookie);

    // Clean up resources
    assert_file_closed(&in_file);;
    remove("magic_list_output.txt");
    remove("compiled.mgc");
    remove("output_file");
    
    magic_close(cookie);

    assert_file_closed(&out_file);
	assert_file_closed(&temp_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_fd_closed(fd);
	return 0;
}