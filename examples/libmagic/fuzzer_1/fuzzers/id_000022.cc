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
//<ID> 486
//<Prompt> []
/*<Combination>: [
*/
//<score> 20, nr_unique_branch: 1
//<Quality> {"density":10,"unique_branches":{"magic_setparam":[[643,2,643,31,0,0,4,0]]},"library_calls":["magic_getpath","magic_open","magic_getflags","magic_setflags","magic_setparam","magic_load","magic_load","magic_buffer","magic_list","magic_close"],"critical_calls":["magic_getpath","magic_open","magic_getflags","magic_setflags","magic_setparam","magic_load","magic_load","magic_buffer","magic_list","magic_close"],"visited":0}
/*Here's a fuzz driver for libmagic that uses all the specified APIs to achieve the event of analyzing input data and listing magic database entries:

*/


extern "C" {
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}




    // Limit size to avoid excessive memory usage
    if (size < 1) {
        return 0;
    }
    size_t use_size = std::min(size, static_cast<size_t>(4096));
    
    // 1. Get the default magic database path
    const char *default_magic_path = magic_getpath(NULL, 0);
    
    // 2. Open magic database with default flags
    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (magic_cookie == NULL) {
        // If we can't open magic, there's nothing more we can do
        return 0;
    }
    
    // 3. Get current flags
    int current_flags = magic_getflags(magic_cookie);
    
    // 4. Set some additional flags for better parsing
    // MAGIC_MIME type flag is 128 (0x80) in libmagic
    // Let's try to set some reasonable flags based on input
    int flags_to_set = current_flags;
    
    // Set flags based on input characteristics
    if (use_size > 100) {
        flags_to_set |= MAGIC_CONTINUE;  // Continue after first match
    }
    if (use_size % 2 == 0) {
        flags_to_set |= MAGIC_MIME;  // MIME type output
    }
    
    // Try to set the flags
    magic_setflags(magic_cookie, flags_to_set);
    
    // 5. Set a parameter (max bytes to check)
    // MAGIC_PARAM_BYTES_MAX is typically 7
    size_t bytes_to_check = std::min(use_size, static_cast<size_t>(1024));
    magic_setparam(magic_cookie, 7 /* MAGIC_PARAM_BYTES_MAX */, &bytes_to_check);
    
    // 6. Load magic database from default location
    // First try to load from default path, then fallback to system default
    if (magic_load(magic_cookie, default_magic_path) != 0) {
        // If loading from specific path fails, try NULL for default
        magic_load(magic_cookie, NULL);
    }
    
    // 7. Analyze the input buffer using magic_buffer
    const char *result = magic_buffer(magic_cookie, data, use_size);
    
    // 8. Create output file for magic_list
    FILE *out_file = fopen("output_file", "wb");
    if (out_file != NULL) {
        // 9. List magic entries to output file
        magic_list(magic_cookie, "output_file");
        assert_file_closed(&out_file);;
    }
    
    // 10. Clean up
    magic_close(magic_cookie);
    
    // Remove output file if created
    remove("output_file");
    
    assert_file_closed(&out_file);
	assert_file_name_closed("output_file");
	return 0;
}