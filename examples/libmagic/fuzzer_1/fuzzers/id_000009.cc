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
//<ID> 170
//<Prompt> []
/*<Combination>: [
*/
//<score> 15, nr_unique_branch: 0
//<Quality> {"density":15,"unique_branches":{},"library_calls":["magic_open","magic_getflags","magic_setflags","magic_close","magic_setparam","magic_close","magic_getpath","magic_load_buffers","magic_load","magic_close","magic_getparam","magic_compile","magic_file","magic_descriptor","magic_buffer","magic_close"],"critical_calls":["magic_open","magic_getflags","magic_setflags","magic_setparam","magic_getpath","magic_load_buffers","magic_load","magic_getparam","magic_compile","magic_file","magic_descriptor","magic_buffer","magic_close"],"visited":0}
/*Here's a C++ fuzz driver that uses the specified libmagic APIs to process the input data:

*/


extern "C" {
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}
	FILE *input_file_ptr = fopen("input_file", "wb");
	if (input_file_ptr == NULL) {return 0;}
	fwrite(data, sizeof(uint8_t), size, input_file_ptr);
	fclose(input_file_ptr);





    if (size == 0) {
        return 0;
    }

    // Create a FILE* from input data
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) {
        assert_file_closed(&in_file);
	return 0;
    }

    // Create output file
    FILE *out_file = fopen("output_file", "wb");
    if (!out_file) {
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	return 0;
    }

    // Get file descriptors
    int in_fd = fuzz_fileno(in_file);
    int out_fd = fuzz_fileno(out_file);

    magic_t cookie = NULL;
    const char *result = NULL;
    char *buffer = NULL;
    int param_value = 0;
    int flags = 0;
    
    // 1. Open magic database
    cookie = magic_open(MAGIC_CONTINUE | MAGIC_ERROR | MAGIC_MIME);
    if (!cookie) {
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_fd_closed(out_fd);
	assert_fd_closed(in_fd);
	return 0;
    }

    // 2. Set flags
    flags = magic_getflags(cookie);
    if (magic_setflags(cookie, flags | MAGIC_COMPRESS) != 0) {
        magic_close(cookie);
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_fd_closed(out_fd);
	assert_fd_closed(in_fd);
	return 0;
    }

    // 3. Set parameter (buffer size limit)
    size_t max_buffer_size = 1024 * 1024; // 1MB
    if (magic_setparam(cookie, MAGIC_PARAM_INDIR_MAX, &max_buffer_size) != 0) {
        magic_close(cookie);
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_fd_closed(out_fd);
	assert_fd_closed(in_fd);
	return 0;
    }

    // 4. Get magic database path
    const char *magic_path = magic_getpath(NULL, 0);
    
    // 5. Load magic database from buffers
    // Prepare buffer array from input data
    void *buffers[1] = {(void *)data};
    size_t buffer_sizes[1] = {size};
    
    if (magic_load_buffers(cookie, buffers, buffer_sizes, 1) != 0) {
        // If loading from buffers fails, try loading from default database
        if (magic_load(cookie, NULL) != 0) {
            magic_close(cookie);
            assert_file_closed(&in_file);;
            assert_file_closed(&out_file);;
            assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_fd_closed(out_fd);
	assert_fd_closed(in_fd);
	return 0;
        }
    }

    // 6. Get parameter value back
    size_t retrieved_size = 0;
    if (magic_getparam(cookie, MAGIC_PARAM_INDIR_MAX, &retrieved_size) == 0) {
        param_value = (int)retrieved_size;
    }

    // 7. Try to compile magic database (using input file)
    if (magic_compile(cookie, "input_file") != 0) {
        // Compilation failed, but continue anyway
    }

    // 8. Use magic_file on the input file
    result = magic_file(cookie, "input_file");
    if (result) {
        // Write result to output file
        fwrite(result, strlen(result), 1, out_file);
        fputc('\n', out_file);
    }

    // 9. Use magic_descriptor on input file descriptor
    result = magic_descriptor(cookie, in_fd);
    if (result) {
        fwrite(result, strlen(result), 1, out_file);
        fputc('\n', out_file);
    }

    // 10. Also try magic_buffer with input data
    result = magic_buffer(cookie, data, size);
    if (result) {
        fwrite(result, strlen(result), 1, out_file);
        fputc('\n', out_file);
    }

    // Cleanup
    fflush(out_file);
    assert_file_closed(&out_file);;
    assert_file_closed(&in_file);;
    
    // Remove the output file
    remove("output_file");
    
    if (cookie) {
        magic_close(cookie);
    }
    
    assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_fd_closed(out_fd);
	assert_fd_closed(in_fd);
	return 0;
}