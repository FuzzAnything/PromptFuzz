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
//<ID> 819
//<Prompt> []
/*<Combination>: [
*/
//<score> 13, nr_unique_branch: 2
//<Quality> {"density":13,"unique_branches":{"parse_indirect_modifier":[[1904,3,1904,30,0,0,4,0],[1907,3,1907,10,0,0,4,1]]},"library_calls":["magic_open","magic_getpath","magic_getflags","magic_setflags","magic_close","magic_check","magic_compile","magic_close","magic_load_buffers","magic_check","magic_descriptor","magic_error","magic_errno","magic_close"],"critical_calls":["magic_open","magic_getpath","magic_getflags","magic_setflags","magic_check","magic_compile","magic_load_buffers","magic_check","magic_descriptor","magic_error","magic_errno","magic_close"],"visited":1}
/**/


// Include libmagic headers

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t* f_data, size_t f_size) {
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

    // Create FILE* for input data
    FILE* in_file = fmemopen((void*)data, size, "rb");
    if (!in_file) {
        assert_file_closed(&in_file);
	return 0;
    }

    // Get file descriptor for input
    int in_fd = fuzz_fileno(in_file);
    if (in_fd < 0) {
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(in_fd);
	return 0;
    }

    // 1. Open magic handle
    magic_t magic = magic_open(MAGIC_NONE);
    if (!magic) {
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(in_fd);
	return 0;
    }

    // 2. Get default magic database path
    const char* default_path = magic_getpath(nullptr, 0);
    (void)default_path; // May be unused

    // 3. Set some flags (combine with existing)
    int current_flags = magic_getflags(magic);
    magic_setflags(magic, current_flags | MAGIC_MIME_TYPE | MAGIC_CONTINUE);

    // 4. Create output file for compilation
    FILE* out_file = fopen("output_file", "wb");
    if (!out_file) {
        magic_close(magic);
        assert_file_closed(&in_file);;
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_fd_closed(in_fd);
	return 0;
    }

    // 5. Write data to output file for magic_check/magic_compile
    fwrite(data, 1, size, out_file);
    fflush(out_file);
    assert_file_closed(&out_file);;

    // 6. First magic_check (on output file)
    int check_result1 = magic_check(magic, "output_file");
    (void)check_result1;

    // 7. Compile magic database from output file
    int compile_result = magic_compile(magic, "output_file");
    (void)compile_result;

    // 8. Prepare buffer for magic_load_buffers
    void* buffer = malloc(size);
    if (!buffer) {
        magic_close(magic);
        assert_file_closed(&in_file);;
        remove("output_file");
        assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	assert_fd_closed(in_fd);
	return 0;
    }
    memcpy(buffer, data, size);
    
    void* buffers[] = {buffer};
    size_t sizes[] = {size};
    
    // 9. Load magic from buffer
    int load_result = magic_load_buffers(magic, buffers, sizes, 1);
    (void)load_result;

    // 10. Second magic_check (on input file)
    int check_result2 = magic_check(magic, "input_file");
    (void)check_result2;

    // 11. Get file type using descriptor
    const char* type = magic_descriptor(magic, in_fd);
    (void)type;

    // 12. Check for errors
    const char* error = magic_error(magic);
    (void)error;
    
    int err = magic_errno(magic);
    (void)err;

    // 13. Clean up
    free(buffer);
    magic_close(magic);
    assert_file_closed(&in_file);;
    
    // Remove temporary output file
    remove("output_file");

    assert_file_closed(&out_file);
	assert_file_closed(&in_file);
	assert_file_name_closed("output_file");
	assert_file_name_closed("input_file");
	assert_file_name_closed("output_file");
	assert_file_name_closed("output_file");
	assert_fd_closed(in_fd);
	return 0;
}