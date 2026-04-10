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
//<ID> 669
//<Prompt> []
/*<Combination>: [
*/
//<score> 15, nr_unique_branch: 1
//<Quality> {"density":15,"unique_branches":{"do_os_note":[[673,6,673,32,0,0,4,1]]},"library_calls":["magic_open","magic_getflags","magic_setparam","magic_close","magic_load","magic_error","magic_check","magic_error","magic_file","magic_error","magic_list","magic_error","magic_file","magic_error","magic_close"],"critical_calls":["magic_open","magic_getflags","magic_setparam","magic_load","magic_error","magic_check","magic_error","magic_file","magic_error","magic_list","magic_error","magic_file","magic_error","magic_close"],"visited":1}
/**/


// Constants for magic parameters
#define MAGIC_PARAM_INDIR_MAX 0
#define MAGIC_PARAM_NAME_MAX 1
#define MAGIC_PARAM_ELF_PHNUM_MAX 2
#define MAGIC_PARAM_ELF_SHNUM_MAX 3
#define MAGIC_PARAM_ELF_NOTES_MAX 4
#define MAGIC_PARAM_REGEX_MAX 5

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}
	FILE *input_file_ptr = fopen("input_file", "wb");
	if (input_file_ptr == NULL) {return 0;}
	fwrite(data, sizeof(uint8_t), size, input_file_ptr);
	fclose(input_file_ptr);





    // Early exit if no data
    if (size == 0) {
	return 0;
	}
	
    
    // 1. Create magic cookie with MAGIC_NONE flags
    magic_t cookie = magic_open(0);
    if (cookie == nullptr) {
	return 0;
	}
	
    
    // 2. Get current flags (just for demonstration)
    int current_flags = magic_getflags(cookie);
    
    // 3. Set a magic parameter
    size_t param_value = 100;
    if (size > sizeof(size_t)) {
        memcpy(&param_value, data, sizeof(size_t));
    }
    magic_setparam(cookie, MAGIC_PARAM_INDIR_MAX, &param_value);
    
    // 4. Create a temporary file with input data
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (in_file == nullptr) {
        magic_close(cookie);
        assert_file_closed(&in_file);
	return 0;
    }
    
    // 5. Write input data to "input_file" for magic_file API
    FILE *input_file = fopen("input_file", "wb");
    if (input_file != nullptr) {
        fwrite(data, 1, size, input_file);
        assert_file_closed(&input_file);;
    }
    
    // 6. Load default magic database
    if (magic_load(cookie, nullptr) != 0) {
        const char *error1 = magic_error(cookie);
        if (error1 != nullptr) {
            // Error handling (just consume it for fuzzing)
        }
    }
    
    // 7. Check the magic database
    if (magic_check(cookie, nullptr) != 0) {
        const char *error2 = magic_error(cookie);
        if (error2 != nullptr) {
            // Error handling
        }
    }
    
    // 8. First call to magic_file
    const char *result1 = magic_file(cookie, "input_file");
    if (result1 == nullptr) {
        const char *error3 = magic_error(cookie);
        if (error3 != nullptr) {
            // Error handling
        }
    }
    
    // 9. List magic entries to "output_file"
    FILE *out_file = fopen("output_file", "wb");
    if (out_file != nullptr) {
        // We need to close the file as magic_list will open it again
        assert_file_closed(&out_file);;
        
        if (magic_list(cookie, "output_file") != 0) {
            const char *error4 = magic_error(cookie);
            if (error4 != nullptr) {
                // Error handling
            }
        }
    }
    
    // 10. Second call to magic_file (on the same input file)
    const char *result2 = magic_file(cookie, "input_file");
    if (result2 == nullptr) {
        const char *error5 = magic_error(cookie);
        if (error5 != nullptr) {
            // Error handling
        }
    }
    
    // 11. Cleanup
    if (in_file != nullptr) assert_file_closed(&in_file);;
    
    // Remove temporary files
    remove("input_file");
    remove("output_file");
    
    magic_close(cookie);
    
    assert_file_closed(&out_file);
	assert_file_closed(&input_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("input_file");
	return 0;
}