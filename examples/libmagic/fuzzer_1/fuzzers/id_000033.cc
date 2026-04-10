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
//<ID> 811
//<Prompt> []
/*<Combination>: [
*/
//<score> 102, nr_unique_branch: 9
//<Quality> {"density":17,"unique_branches":{"doshn":[[1442,6,1442,28,0,0,4,0]],"elf_printf":[[76,6,76,28,0,0,4,0]],"dophn_exec":[[1838,8,1838,30,0,0,4,0],[1848,8,1848,30,0,0,4,0],[1866,8,1866,30,0,0,4,0],[1871,6,1871,28,0,0,4,0]],"handle_mime":[[96,7,96,35,0,0,4,1],[100,6,100,34,0,0,4,1]],"dophn_core":[[376,6,376,28,0,0,4,0]]},"library_calls":["magic_getpath","magic_open","magic_getflags","magic_setflags","magic_setparam","magic_load","magic_error","magic_load_buffers","magic_check","magic_getparam","magic_list","magic_buffer","magic_file","magic_descriptor","magic_error","magic_errno","magic_close"],"critical_calls":["magic_getpath","magic_open","magic_getflags","magic_setflags","magic_setparam","magic_load","magic_error","magic_load_buffers","magic_check","magic_getparam","magic_list","magic_buffer","magic_file","magic_descriptor","magic_error","magic_errno","magic_close"],"visited":0}
/*We are going to create a fuzzing driver that tests the libmagic library by simulating a realistic usage scenario. The event we'll implement is: "Using libmagic to identify the MIME type of input data, while also loading and checking a custom magic database buffer".

The step-by-step approach:
1. First, we'll get the default magic database path.
2. Create a magic cookie with `magic_open`.
3. Set and get flags to configure the cookie.
4. Load the default magic database and also load the input data as a custom magic buffer.
5. Use `magic_check` to verify the loaded databases.
6. Use `magic_list` to output the magic entries to a file.
7. Identify the MIME type of the input data using both `magic_buffer` and `magic_file`.
8. Handle errors and cleanup.

Here's the complete fuzz driver:

*/



extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t* f_data, size_t f_size) {
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
    if (size == 0) {
        return 0;
    }

    // 1. Get the default magic database path
    const char *default_db = magic_getpath(nullptr, 0);
    if (!default_db) {
        // If we can't get path, still continue with other operations
    }

    // 2. Open magic cookie with MIME type flag
    magic_t cookie = magic_open(MAGIC_MIME_TYPE);
    if (!cookie) {
        return 0;  // Can't proceed without cookie
    }

    // 3. Get current flags
    int flags = magic_getflags(cookie);

    // 4. Set additional flags (preserve existing ones)
    // We'll add MAGIC_CONTINUE to get multiple matches
    int new_flags = flags | MAGIC_CONTINUE;
    magic_setflags(cookie, new_flags);

    // 5. Set a parameter - using MAGIC_PARAM_INDIR_MAX
    size_t indirect_max = 50;
    magic_setparam(cookie, MAGIC_PARAM_INDIR_MAX, &indirect_max);

    // 6. Load the default magic database
    if (magic_load(cookie, default_db) != 0) {
        // Even if default load fails, continue with buffer load
        const char *error = magic_error(cookie);
        (void)error; // Use error to avoid unused warning
    }

    // 7. Load the input data as a magic buffer
    // We'll treat the input as a magic database buffer
    void *buffer = const_cast<void*>(static_cast<const void*>(data));
    void *buffers[] = {buffer};
    size_t sizes[] = {size};
    
    // This might fail if input isn't valid magic data, but we try anyway
    magic_load_buffers(cookie, buffers, sizes, 1);

    // 8. Check the loaded magic databases
    // Check default database first
    if (default_db) {
        magic_check(cookie, default_db);
        // Don't check the buffer as it's already loaded via load_buffers
    }

    // 9. Get the parameter we set to verify it
    size_t retrieved_max = 0;
    magic_getparam(cookie, MAGIC_PARAM_INDIR_MAX, &retrieved_max);

    // 10. Write the magic list to an output file
    FILE *out_file = fopen("output_file", "wb");
    if (out_file) {
        // We need to flush and close to ensure list is written
        assert_file_closed(&out_file);;
        magic_list(cookie, "output_file");
    }

    // 11. Create an input file with the data for magic_file
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (in_file) {
        // Write the file to disk for magic_file
        FILE *temp_in = fopen("input_file", "wb");
        if (temp_in) {
            rewind(in_file);
            char buf[1024];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), in_file)) > 0) {
                fwrite(buf, 1, n, temp_in);
            }
            assert_file_closed(&temp_in);;
        }
        
        // 12. Use magic_buffer on the original data
        const char *buffer_result = magic_buffer(cookie, data, size);
        if (buffer_result) {
            // Use the result to avoid unused variable warning
            volatile const char *vol_result = buffer_result;
            (void)vol_result;
        }
        
        // 13. Use magic_file on the saved file
        const char *file_result = magic_file(cookie, "input_file");
        if (file_result) {
            volatile const char *vol_result = file_result;
            (void)vol_result;
        }
        
        // 14. Try magic_descriptor (though not in the list, but mentioned in header)
        rewind(in_file);
        int fd = fuzz_fileno(in_file);
        if (fd != -1) {
            const char *desc_result = magic_descriptor(cookie, fd);
            if (desc_result) {
                volatile const char *vol_result = desc_result;
                (void)vol_result;
            }
        }
        
        assert_file_closed(&in_file);;
    }

    // 15. Check for any errors
    const char *error_msg = magic_error(cookie);
    if (error_msg) {
        volatile const char *vol_error = error_msg;
        (void)vol_error;
    }
    
    // 16. Get errno from magic
    int magic_err = magic_errno(cookie);
    (void)magic_err; // Use to avoid unused warning

    // 17. Cleanup
    magic_close(cookie);
    
    // Remove temporary files
    remove("input_file");
    remove("output_file");

    assert_file_closed(&in_file);
	assert_file_closed(&out_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	return 0;
}