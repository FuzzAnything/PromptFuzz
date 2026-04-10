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
//<ID> 123
//<Prompt> []
/*<Combination>: [
*/
//<score> 4, nr_unique_branch: 0
//<Quality> {"density":8,"unique_branches":{},"library_calls":["magic_open","magic_load_buffers","magic_close","magic_compile","magic_check","magic_open","magic_close","magic_load","magic_close","magic_close","magic_compile","magic_check","magic_file","magic_buffer","magic_close","magic_close"],"critical_calls":["magic_open","magic_load_buffers","magic_compile","magic_check","magic_open","magic_load","magic_compile","magic_check","magic_file","magic_buffer","magic_close","magic_close"],"visited":1}
/**/



extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}
	FILE *input_file_ptr = fopen("input_file", "wb");
	if (input_file_ptr == NULL) {return 0;}
	fwrite(data, sizeof(uint8_t), size, input_file_ptr);
	fclose(input_file_ptr);





    // Early return if there's no data to process
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Create a temporary file with the input data to use for various operations
    FILE *temp_file = fopen("input_file", "wb");
    if (temp_file == nullptr) {
        assert_file_closed(&temp_file);
	return 0;
    }
    fwrite(data, 1, size, temp_file);
    assert_file_closed(&temp_file);;

    magic_t magic_cookie1 = nullptr;
    magic_t magic_cookie2 = nullptr;
    
    // First sequence: open, load from buffer, compile, check
    magic_cookie1 = magic_open(MAGIC_NONE);
    if (magic_cookie1 == nullptr) {
        remove("input_file");
        assert_file_closed(&temp_file);
	assert_file_name_closed("input_file");
	return 0;
    }

    // Prepare buffer for magic_load_buffers
    void *buffer_array[] = { (void *)data };
    size_t sizes[] = { size };
    
    // Load magic database from input buffer
    if (magic_load_buffers(magic_cookie1, buffer_array, sizes, 1) != 0) {
        magic_close(magic_cookie1);
        remove("input_file");
        assert_file_closed(&temp_file);
	assert_file_name_closed("input_file");
	return 0;
    }

    // Try to compile the loaded database to a file
    if (magic_compile(magic_cookie1, "output_file") != 0) {
        // Compilation failed, but we continue anyway
    }

    // Check the database
    if (magic_check(magic_cookie1, "input_file") != 0) {
        // Check failed, but we continue anyway
    }

    // Second sequence: open new handle, compile, check, then use file and buffer APIs
    magic_cookie2 = magic_open(MAGIC_CONTINUE | MAGIC_ERROR);
    if (magic_cookie2 == nullptr) {
        magic_close(magic_cookie1);
        remove("input_file");
        assert_file_closed(&temp_file);
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("output_file");
	return 0;
    }

    // Load a simple built-in database for the second handle
    if (magic_load(magic_cookie2, nullptr) != 0) {
        magic_close(magic_cookie1);
        magic_close(magic_cookie2);
        remove("input_file");
        assert_file_closed(&temp_file);
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("output_file");
	return 0;
    }

    // Try to compile (will likely fail but we call it anyway)
    magic_compile(magic_cookie2, "input_file");

    // Check the database
    magic_check(magic_cookie2, "input_file");

    // Use magic_file to identify the temporary file
    const char *file_result = magic_file(magic_cookie2, "input_file");
    if (file_result != nullptr) {
        // Do something with the result to ensure it's not optimized away
        volatile const char *unused = file_result;
        (void)unused;
    }

    // Use magic_buffer to identify the input data directly
    const char *buffer_result = magic_buffer(magic_cookie2, data, size);
    if (buffer_result != nullptr) {
        volatile const char *unused = buffer_result;
        (void)unused;
    }

    // Clean up resources
    magic_close(magic_cookie1);
    magic_close(magic_cookie2);
    
    // Remove temporary file
    remove("input_file");
    
    assert_file_closed(&temp_file);
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("output_file");
	return 0;
}