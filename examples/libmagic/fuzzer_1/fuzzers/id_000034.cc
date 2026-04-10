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
//<ID> 815
//<Prompt> []
/*<Combination>: [
*/
//<score> 13, nr_unique_branch: 0
//<Quality> {"density":13,"unique_branches":{},"library_calls":["magic_open","magic_getpath","magic_check","magic_getflags","magic_close","magic_close","magic_load_buffers","magic_compile","magic_descriptor","magic_setflags","magic_error","magic_errno","magic_check","magic_close"],"critical_calls":["magic_open","magic_getpath","magic_check","magic_getflags","magic_load_buffers","magic_compile","magic_descriptor","magic_setflags","magic_error","magic_errno","magic_check","magic_close"],"visited":0}
/**/


// Include libmagic headers

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t* f_data, size_t f_size) {
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

    // 1. Create magic database using magic_open
    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (magic_cookie == nullptr) {
        return 0;
    }

    // 2. Get the default magic database path
    const char *magic_path = magic_getpath(nullptr, 0);
    
    // 3. First call to magic_check - check if database is valid
    // We'll use a dummy file name since we're loading from buffer later
    int check_result1 = magic_check(magic_cookie, "input_file");
    
    // 4. Get current flags
    int current_flags = magic_getflags(magic_cookie);
    
    // 5. Second call to magic_check - check with actual data file
    // Create a temporary FILE* to read input data
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (in_file == nullptr) {
        magic_close(magic_cookie);
        assert_file_closed(&in_file);
	assert_file_name_closed("input_file");
	return 0;
    }
    
    int fd = fuzz_fileno(in_file);
    if (fd < 0) {
        assert_file_closed(&in_file);;
        magic_close(magic_cookie);
        assert_file_closed(&in_file);
	assert_file_name_closed("input_file");
	assert_fd_closed(fd);
	return 0;
    }
    
    // 6. Load magic database from input buffer
    // Prepare buffer pointers for magic_load_buffers
    void *buffer_ptr = (void *)data;
    size_t buffer_size = size;
    int load_result = magic_load_buffers(magic_cookie, &buffer_ptr, &buffer_size, 1);
    
    // 7. Compile magic database to a file
    int compile_result = magic_compile(magic_cookie, "output_file");
    
    // 8. Get description of file descriptor
    const char *description = magic_descriptor(magic_cookie, fd);
    
    // 9. Set different flags (toggle some common flags)
    int new_flags = current_flags | MAGIC_MIME;
    int setflags_result = magic_setflags(magic_cookie, new_flags);
    
    // 10. Get error message if any
    const char *error_msg = magic_error(magic_cookie);
    
    // 11. Get error number
    int err_num = magic_errno(magic_cookie);
    
    // 12. Second call to magic_check after operations
    int check_result2 = magic_check(magic_cookie, "output_file");
    
    // Clean up resources
    assert_file_closed(&in_file);;
    magic_close(magic_cookie);
    
    assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_fd_closed(fd);
	return 0;
}