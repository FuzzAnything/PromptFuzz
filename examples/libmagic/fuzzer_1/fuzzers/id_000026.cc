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
//<ID> 510
//<Prompt> []
/*<Combination>: [
*/
//<score> 13, nr_unique_branch: 2
//<Quality> {"density":13,"unique_branches":{"parse":[[2180,4,2180,12,0,0,4,0],[2211,4,2211,12,0,0,4,0]]},"library_calls":["magic_getpath","magic_open","magic_getflags","magic_setflags","magic_error","magic_descriptor","magic_error","magic_buffer","magic_error","magic_check","magic_error","magic_compile","magic_error","magic_close"],"critical_calls":["magic_getpath","magic_open","magic_getflags","magic_setflags","magic_descriptor","magic_error","magic_buffer","magic_error","magic_check","magic_error","magic_compile","magic_error","magic_close"],"visited":1}
/**/


// Include libmagic headers

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}




    if (size == 0) {
        return 0;
    }

    // Variables for libmagic operations
    magic_t magic_cookie = NULL;
    const char *result = NULL;
    const char *error_msg = NULL;
    int flags = 0;
    int ret = 0;
    FILE *in_file = NULL;
    FILE *out_file = NULL;
    int fd = -1;
    const char *magic_path = NULL;
    
    // 1. Get the default magic database path
    magic_path = magic_getpath(NULL, 0);
    if (!magic_path) {
        // Continue anyway, magic_open will use default
    }
    
    // 2. Open magic cookie
    magic_cookie = magic_open(MAGIC_NONE);
    if (!magic_cookie) {
        goto cleanup;
    }
    
    // 3. Set some flags
    flags = magic_getflags(magic_cookie);
    ret = magic_setflags(magic_cookie, flags | MAGIC_CONTINUE);
    if (ret != 0) {
        error_msg = magic_error(magic_cookie);
        goto cleanup;
    }
    
    // 4. Create input file from the fuzzer data
    in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) {
        goto cleanup;
    }
    
    // 5. Get file descriptor for the input
    fd = fuzz_fileno(in_file);
    if (fd < 0) {
        goto cleanup;
    }
    
    // 6. Use magic_descriptor to identify the file type
    result = magic_descriptor(magic_cookie, fd);
    if (!result) {
        error_msg = magic_error(magic_cookie);
    }
    
    // 7. Rewind the file for next operations
    rewind(in_file);
    
    // 8. Also try magic_buffer with the same data
    result = magic_buffer(magic_cookie, data, size);
    if (!result) {
        error_msg = magic_error(magic_cookie);
    }
    
    // 9. Create a temporary file to check/compile magic rules
    out_file = fopen("output_file", "wb");
    if (!out_file) {
        goto cleanup;
    }
    
    // 10. Write some data to the output file
    fwrite(data, 1, size > 1024 ? 1024 : size, out_file);
    assert_file_closed(&out_file);;
    out_file = NULL;
    
    // 11. Check if the magic database is valid
    ret = magic_check(magic_cookie, magic_path ? magic_path : "/etc/magic");
    if (ret != 0) {
        error_msg = magic_error(magic_cookie);
    }
    
    // 12. Try to compile magic rules (this would normally fail with default db)
    ret = magic_compile(magic_cookie, "output_file");
    if (ret != 0) {
        error_msg = magic_error(magic_cookie);
    }

cleanup:
    // 13. Clean up resources
    if (magic_cookie) {
        magic_close(magic_cookie);
    }
    if (in_file) {
        assert_file_closed(&in_file);;
    }
    if (out_file) {
        assert_file_closed(&out_file);;
    }
    // Remove temporary output file
    remove("output_file");
    
    assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	assert_fd_closed(fd);
	return 0;
}