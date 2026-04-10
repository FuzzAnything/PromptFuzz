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
//<ID> 121
//<Prompt> []
/*<Combination>: [
*/
//<score> 30, nr_unique_branch: 20
//<Quality> {"density":9,"unique_branches":{"mconvert":[[1320,2,1320,19,0,0,4,0]],"file_buffer":[[474,8,474,26,0,0,4,1]],"mcopy":[[1436,10,1439,29,0,0,4,0],[1439,10,1439,28,0,0,4,0]],"file_softmagic":[[146,8,146,41,0,0,4,1]],"handle_annotation":[[2537,6,2537,35,0,0,4,0],[2537,39,2537,53,0,0,4,0],[2537,39,2537,53,0,0,4,1],[2540,7,2540,17,0,0,4,1],[2542,7,2542,37,0,0,4,1],[2544,7,2544,57,0,0,4,1],[2548,7,2548,37,0,0,4,1]],"magiccheck":[[2256,2,2256,19,0,0,4,0]],"mget":[[2011,2,2011,19,0,0,4,0]],"file_strncmp":[[2082,12,2082,18,0,0,4,0],[2086,9,2086,34,0,0,4,1]],"match":[[295,7,295,54,0,0,4,0],[311,8,311,13,0,0,4,1],[411,9,412,13,0,0,4,0],[423,9,423,14,0,0,4,1]]},"library_calls":["magic_open","magic_open","magic_close","magic_close","magic_close","magic_close","magic_close","magic_check","magic_compile","magic_load_buffers","magic_check","magic_compile","magic_file","magic_buffer","magic_descriptor","magic_close","magic_close"],"critical_calls":["magic_open","magic_open","magic_check","magic_compile","magic_load_buffers","magic_check","magic_compile","magic_file","magic_buffer","magic_descriptor","magic_close","magic_close"],"visited":2}
/**/


// Include libmagic headers

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}
	FILE *input_file_ptr = fopen("input_file", "wb");
	if (input_file_ptr == NULL) {return 0;}
	fwrite(data, sizeof(uint8_t), size, input_file_ptr);
	fclose(input_file_ptr);





    // Early return if no data
    if (size == 0 || data == nullptr) {
        return 0;
    }

    // Create FILE* for reading input data
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) {
        assert_file_closed(&in_file);
	return 0;
    }

    // Get file descriptor for reading
    int in_fd = fuzz_fileno(in_file);
    if (in_fd < 0) {
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(in_fd);
	return 0;
    }

    // Create two magic instances
    magic_t magic_cookie1 = magic_open(MAGIC_CHECK | MAGIC_COMPRESS);
    if (!magic_cookie1) {
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(in_fd);
	return 0;
    }

    magic_t magic_cookie2 = magic_open(MAGIC_MIME_TYPE | MAGIC_CONTINUE);
    if (!magic_cookie2) {
        magic_close(magic_cookie1);
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(in_fd);
	return 0;
    }

    // Create output file for magic_compile
    FILE *out_file = fopen("output_file", "wb");
    if (!out_file) {
        magic_close(magic_cookie2);
        magic_close(magic_cookie1);
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_fd_closed(in_fd);
	return 0;
    }
    assert_file_closed(&out_file);;  // We'll use the filename for magic_compile

    // Prepare buffer for magic_load_buffers
    void *data_buffer = malloc(size);
    if (!data_buffer) {
        magic_close(magic_cookie2);
        magic_close(magic_cookie1);
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_fd_closed(in_fd);
	return 0;
    }
    memcpy(data_buffer, data, size);
    
    void *buffers[] = {data_buffer};
    size_t sizes[] = {size};
    
    // First instance operations
    int check_result1 = magic_check(magic_cookie1, "input_file");
    int compile_result1 = magic_compile(magic_cookie1, "output_file");
    
    // Second instance operations with magic_load_buffers
    int load_result = magic_load_buffers(magic_cookie2, buffers, sizes, 1);
    
    // More operations on first instance
    int check_result2 = magic_check(magic_cookie1, "input_file");
    int compile_result2 = magic_compile(magic_cookie1, "output_file");
    
    // Use magic_file with the input file
    const char *file_result = magic_file(magic_cookie2, "input_file");
    
    // Use magic_buffer with the input data
    const char *buffer_result = magic_buffer(magic_cookie2, data, size);
    
    // Get file descriptor for output (though not used directly)
    out_file = fopen("output_file", "wb");
    if (out_file) {
        int out_fd = fuzz_fileno(out_file);
        // Could use out_fd if needed
        assert_file_closed(&out_file);;
    }
    
    // Also use the file descriptor with magic_descriptor (though not in required list)
    rewind(in_file);
    const char *desc_result = magic_descriptor(magic_cookie2, in_fd);
    
    // Clean up
    free(data_buffer);
    magic_close(magic_cookie2);
    magic_close(magic_cookie1);
    assert_file_closed(&in_file);;
    
    // Remove temporary output file
    remove("output_file");
    
    assert_file_closed(&out_file);
	assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_fd_closed(in_fd);
	return 0;
}