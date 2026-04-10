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
//<ID> 309
//<Prompt> []
/*<Combination>: [
*/
//<score> 26, nr_unique_branch: 1
//<Quality> {"density":13,"unique_branches":{"parse":[[2179,4,2179,12,0,0,4,0]]},"library_calls":["magic_open","magic_getpath","magic_close","magic_compile","magic_errno","magic_setparam","magic_getparam","magic_load","magic_load","magic_close","magic_descriptor","magic_list","magic_errno","magic_close"],"critical_calls":["magic_open","magic_getpath","magic_compile","magic_errno","magic_setparam","magic_getparam","magic_load","magic_descriptor","magic_list","magic_errno","magic_close"],"visited":0}
/*Here's a C++ fuzz driver that uses all the specified libmagic APIs to achieve an event where the input data is treated as a magic file (pattern database), compiled into a binary format, and then used to identify a file descriptor:

*/


extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}




    // Create a magic cookie
    magic_t cookie = magic_open(MAGIC_NONE);
    if (!cookie) {
        return 0;
    }

    // Get the default magic database path
    const char *magic_path = magic_getpath(nullptr, 0);
    
    // Write input data to a temporary magic file
    FILE *magic_file = fopen("input_magic", "wb");
    if (!magic_file) {
        magic_close(cookie);
        assert_file_closed(&magic_file);
	return 0;
    }
    fwrite(data, 1, size, magic_file);
    assert_file_closed(&magic_file);;

    // Try to compile the input as a magic database
    int compile_result = magic_compile(cookie, "input_magic");
    
    // Get error number if compilation failed
    int err = magic_errno(cookie);
    
    // Set a parameter (buffer size limit)
    size_t param_value = 1024 * 1024; // 1MB limit
    magic_setparam(cookie, MAGIC_PARAM_BYTES_MAX, &param_value);
    
    // Get the parameter back to verify
    size_t get_param_value = 0;
    magic_getparam(cookie, MAGIC_PARAM_BYTES_MAX, &get_param_value);
    
    // Load a magic database (try compiled version first, fallback to default)
    if (compile_result == 0) {
        // Load the compiled magic file
        magic_load(cookie, "input_magic.mgc");
    } else {
        // Load default database
        magic_load(cookie, nullptr);
    }
    
    // Create input file from data using fmemopen
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) {
        remove("input_magic");
        magic_close(cookie);
        assert_file_closed(&in_file);
	assert_file_closed(&magic_file);
	return 0;
    }
    
    // Get file descriptor
    int fd = fuzz_fileno(in_file);
    
    // Use the loaded magic database to identify the file descriptor
    const char *description = magic_descriptor(cookie, fd);
    
    // List magic entries to an output file
    FILE *out_file = fopen("output_list", "w");
    if (out_file) {
        magic_list(cookie, "output_list");
        assert_file_closed(&out_file);;
    }
    
    // Check for errors again
    err = magic_errno(cookie);
    
    // Cleanup
    assert_file_closed(&in_file);;
    magic_close(cookie);
    
    // Remove temporary files
    remove("input_magic");
    remove("input_magic.mgc");
    remove("output_list");
    
    assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_closed(&magic_file);
	assert_fd_closed(fd);
	return 0;
}