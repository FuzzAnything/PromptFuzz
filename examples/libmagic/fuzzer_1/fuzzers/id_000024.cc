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
//<ID> 492
//<Prompt> []
/*<Combination>: [
*/
//<score> 30, nr_unique_branch: 8
//<Quality> {"density":10,"unique_branches":{"file_or_fd":[[475,8,475,14,0,0,4,0],[476,8,476,53,0,0,4,1]],"unreadable_info":[[275,6,275,10,0,0,4,0],[277,7,277,30,0,0,4,0],[278,8,278,43,0,0,4,1],[281,7,281,30,0,0,4,1],[298,7,298,46,0,0,4,1],[300,6,300,49,0,0,4,1]]},"library_calls":["magic_open","magic_setflags","magic_close","magic_load_buffers","magic_errno","magic_compile","magic_list","magic_buffer","magic_file","magic_close"],"critical_calls":["magic_open","magic_setflags","magic_load_buffers","magic_errno","magic_compile","magic_list","magic_buffer","magic_file","magic_close"],"visited":0}
/**/


extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}
	FILE *input_file_ptr = fopen("input_file", "wb");
	if (input_file_ptr == NULL) {return 0;}
	fwrite(data, sizeof(uint8_t), size, input_file_ptr);
	fclose(input_file_ptr);





    if (size < 1) {
        return 0;
    }

    // Create output buffer for magic_load_buffers
    void *buffer = malloc(size);
    if (!buffer) {
        return 0;
    }
    memcpy(buffer, data, size);
    
    size_t buffer_size = size;
    void *buffers[] = {buffer};
    size_t sizes[] = {buffer_size};
    
    // Create a magic handle
    magic_t magic = magic_open(MAGIC_NONE);
    if (!magic) {
        free(buffer);
        return 0;
    }
    
    // Set flags
    int flags = MAGIC_CONTINUE | MAGIC_CHECK;
    if (magic_setflags(magic, flags) == -1) {
        magic_close(magic);
        free(buffer);
        return 0;
    }
    
    // Try to load from buffer
    int load_result = magic_load_buffers(magic, buffers, sizes, 1);
    
    // Check errno after load
    int err = magic_errno(magic);
    (void)err; // Use err to avoid unused variable warning
    
    // If buffer load failed, try to compile from file
    if (load_result == -1) {
        // Write input to a file for compilation
        FILE *out_file = fopen("output_file", "wb");
        if (out_file) {
            fwrite(data, 1, size, out_file);
            assert_file_closed(&out_file);;
            
            // Try to compile magic rules
            magic_compile(magic, "output_file");
            
            // Remove temp file
            remove("output_file");
        }
    }
    
    // List magic rules to file
    FILE *list_file = fopen("list_output", "wb");
    if (list_file) {
        magic_list(magic, "list_output");
        assert_file_closed(&list_file);;
        remove("list_output");
    }
    
    // Use magic_buffer on the input data
    const char *buffer_result = magic_buffer(magic, data, size);
    (void)buffer_result; // Use result to avoid unused warning
    
    // Use magic_file on a temporary file
    FILE *temp_file = fopen("input_file", "wb");
    if (temp_file) {
        fwrite(data, 1, size, temp_file);
        assert_file_closed(&temp_file);;
        
        const char *file_result = magic_file(magic, "input_file");
        (void)file_result; // Use result to avoid unused warning
        
        remove("input_file");
    }
    
    // Clean up
    magic_close(magic);
    free(buffer);
    
    assert_file_closed(&temp_file);
	assert_file_closed(&list_file);
	return 0;
}