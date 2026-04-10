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
//<ID> 120
//<Prompt> []
/*<Combination>: [
*/
//<score> 3.5, nr_unique_branch: 0
//<Quality> {"density":7,"unique_branches":{},"library_calls":["magic_open","magic_load_buffers","magic_compile","magic_check","magic_open","magic_close","magic_load_buffers","magic_compile","magic_check","magic_file","magic_buffer","magic_close","magic_close"],"critical_calls":["magic_open","magic_load_buffers","magic_compile","magic_check","magic_open","magic_load_buffers","magic_compile","magic_check","magic_file","magic_buffer","magic_close","magic_close"],"visited":1}
/**/


extern "C" {
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}
	FILE *input_file_ptr = fopen("input_file", "wb");
	if (input_file_ptr == NULL) {return 0;}
	fwrite(data, sizeof(uint8_t), size, input_file_ptr);
	fclose(input_file_ptr);





    // Early exit if input is too small for meaningful processing
    if (size < 10) {
        return 0;
    }

    // Create a temporary input file with the fuzzer data
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) {
        assert_file_closed(&in_file);
	return 0;
    }
    
    // Create a temporary output file
    FILE *out_file = fopen("output_file", "wb");
    if (!out_file) {
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	return 0;
    }

    // Create first magic cookie for loading/compiling database
    magic_t magic_cookie1 = magic_open(MAGIC_NONE);
    if (!magic_cookie1) {
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	return 0;
    }

    // Prepare buffer for magic_load_buffers
    // We'll use the entire input data as a single buffer
    void *buffer = (void *)data;
    size_t buffer_size = size;
    
    // Load magic database from buffer
    int load_result = magic_load_buffers(magic_cookie1, &buffer, &buffer_size, 1);
    
    // Try to compile the loaded database
    int compile_result1 = magic_compile(magic_cookie1, "output_file");
    
    // Check the compiled database
    int check_result1 = magic_check(magic_cookie1, "output_file");

    // Create second magic cookie for file/buffer identification
    magic_t magic_cookie2 = magic_open(MAGIC_NONE);
    if (!magic_cookie2) {
        magic_close(magic_cookie1);
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	return 0;
    }

    // Load the compiled database into second cookie
    // First, read the compiled database from output file
    fseek(out_file, 0, SEEK_END);
    long out_size = ftell(out_file);
    fseek(out_file, 0, SEEK_SET);
    
    if (out_size > 0) {
        std::vector<uint8_t> compiled_db(out_size);
        fread(compiled_db.data(), 1, out_size, out_file);
        
        void *compiled_buffer = compiled_db.data();
        size_t compiled_size = out_size;
        
        magic_load_buffers(magic_cookie2, &compiled_buffer, &compiled_size, 1);
    }

    // Try to compile again (even if loading failed)
    int compile_result2 = magic_compile(magic_cookie2, "output_file");
    
    // Check the database again
    int check_result2 = magic_check(magic_cookie2, "output_file");

    // Use magic_file to identify the input file
    const char *file_type = magic_file(magic_cookie2, "input_file");
    (void)file_type; // Use result to avoid unused variable warning

    // Use magic_buffer to identify the input data directly
    const char *buffer_type = magic_buffer(magic_cookie2, data, size);
    (void)buffer_type; // Use result to avoid unused variable warning

    // Clean up
    magic_close(magic_cookie2);
    magic_close(magic_cookie1);
    
    assert_file_closed(&in_file);;
    assert_file_closed(&out_file);;
    
    // Remove temporary files
    remove("input_file");
    remove("output_file");

    assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	return 0;
}