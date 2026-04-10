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
//<ID> 601
//<Prompt> []
/*<Combination>: [
*/
//<score> 12, nr_unique_branch: 0
//<Quality> {"density":12,"unique_branches":{},"library_calls":["magic_getpath","magic_open","magic_getflags","magic_load_buffers","magic_check","magic_compile","magic_setflags","magic_list","magic_file","magic_buffer","magic_descriptor","magic_close","magic_open","magic_load","magic_file","magic_close"],"critical_calls":["magic_getpath","magic_open","magic_getflags","magic_load_buffers","magic_check","magic_compile","magic_setflags","magic_list","magic_file","magic_buffer","magic_descriptor","magic_close","magic_open","magic_load","magic_file","magic_close"],"visited":0}
/**/


extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}
	FILE *input_file_ptr = fopen("input_file", "wb");
	if (input_file_ptr == NULL) {return 0;}
	fwrite(data, sizeof(uint8_t), size, input_file_ptr);
	fclose(input_file_ptr);





    // Early return if input is too small
    if (size < 2) {
	return 0;
	}
	

    // Create FILE* for input data
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) {
	assert_file_closed(&in_file);
	return 0;
	}
	

    // Create FILE* for output
    FILE *out_file = fopen("output_file", "wb");
    if (!out_file) {
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	return 0;
    }

    // 1. First get the magic database path
    const char *magic_path = magic_getpath(nullptr, 0);
    
    // 2. Open magic database
    magic_t cookie = magic_open(MAGIC_NONE);
    if (!cookie) {
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	return 0;
    }

    // 3. Get current flags
    int flags = magic_getflags(cookie);

    // 4. Load magic database from buffers (using input data as magic database)
    // We'll split the input data into two parts for demonstration
    if (size > 4) {
        size_t part1_size = size / 2;
        size_t part2_size = size - part1_size;
        
        void *buffers[2];
        size_t lengths[2];
        
        // First part - allocate and copy
        buffers[0] = malloc(part1_size);
        if (buffers[0]) {
            memcpy(buffers[0], data, part1_size);
            lengths[0] = part1_size;
            
            // Second part - allocate and copy
            buffers[1] = malloc(part2_size);
            if (buffers[1]) {
                memcpy(buffers[1], data + part1_size, part2_size);
                lengths[1] = part2_size;
                
                // Try to load from buffers (this may fail if data isn't valid magic format)
                magic_load_buffers(cookie, buffers, lengths, 2);
                
                free(buffers[1]);
            }
            free(buffers[0]);
        }
    }

    // 5. Check if magic database is valid
    int check_result = magic_check(cookie, magic_path);
    
    // 6. Try to compile magic database (even if check failed)
    int compile_result = magic_compile(cookie, "output_file");

    // 7. Set flags back (demo of using setflags)
    magic_setflags(cookie, flags);

    // 8. List magic entries to output file
    magic_list(cookie, "output_file");

    // 9. Get file descriptor for input file
    int fd = fuzz_fileno(in_file);
    
    // 10. Try to identify the input file using different methods
    const char *result_file = magic_file(cookie, "input_file");
    
    // 11. Try to identify from buffer (using first 256 bytes of input)
    size_t buffer_size = size > 256 ? 256 : size;
    const char *result_buffer = magic_buffer(cookie, data, buffer_size);
    
    // 12. Try to identify from file descriptor
    const char *result_descriptor = magic_descriptor(cookie, fd);

    // Clean up resources
    magic_close(cookie);
    assert_file_closed(&in_file);;
    assert_file_closed(&out_file);;
    
    // Create test file for magic_file() to work with
    FILE *test_input = fopen("input_file", "wb");
    if (test_input) {
        fwrite(data, 1, size, test_input);
        assert_file_closed(&test_input);;
        
        // Try magic operations again with the created file
        cookie = magic_open(MAGIC_NONE);
        if (cookie) {
            magic_load(cookie, nullptr); // Load default database
            magic_file(cookie, "input_file");
            magic_close(cookie);
        }
        
        // Remove temporary file
        remove("input_file");
    }
    
    // Remove output file
    remove("output_file");
    
    assert_file_closed(&test_input);
	assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	assert_fd_closed(fd);
	return 0;
}