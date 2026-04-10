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
//<ID> 505
//<Prompt> []
/*<Combination>: [
*/
//<score> 104.5, nr_unique_branch: 86
//<Quality> {"density":11,"unique_branches":{"handle_annotation":[[2540,7,2540,17,0,0,4,0],[2540,21,2540,50,0,0,4,1]],"print_sep":[[2558,6,2558,15,0,0,4,1]],"magiccheck":[[2196,3,2196,11,0,0,4,0],[2208,3,2208,11,0,0,4,0],[2356,7,2356,16,0,0,4,1],[2392,2,2392,15,0,0,4,0],[2493,2,2493,10,0,0,4,0],[2495,7,2495,37,0,0,4,1]],"moffset":[[867,4,867,20,0,0,4,0],[934,10,934,50,0,0,4,1],[944,2,944,17,0,0,4,0],[945,2,945,19,0,0,4,0],[948,2,948,15,0,0,4,0],[952,2,952,15,0,0,4,0],[954,7,954,14,0,0,4,1],[954,18,954,42,0,0,4,1],[965,2,965,16,0,0,4,0]],"do_ops":[[1511,3,1511,20,0,0,4,0],[1514,3,1514,23,0,0,4,0]],"mcopy":[[1397,10,1398,52,0,0,4,1],[1399,12,1400,48,0,0,4,0],[1399,12,1400,48,0,0,4,1],[1402,9,1402,20,0,0,4,0],[1402,24,1402,36,0,0,4,0],[1402,24,1402,36,0,0,4,1],[1402,40,1402,52,0,0,4,1],[1404,9,1404,20,0,0,4,0],[1404,24,1404,36,0,0,4,0],[1404,24,1404,36,0,0,4,1],[1438,11,1438,27,0,0,4,1]],"file_strncmp":[[2062,9,2062,43,0,0,4,1],[2071,14,2071,20,0,0,4,1]],"der_offs":[[267,25,267,41,0,0,4,0],[269,6,269,38,0,0,4,1],[277,6,277,21,0,0,4,1],[292,6,292,24,0,0,4,0],[292,6,292,24,0,0,4,1],[293,7,293,27,0,0,4,1]],"der_cmp":[[343,2,343,11,0,0,4,0],[349,2,349,9,0,0,4,1],[350,7,350,15,0,0,4,1],[359,7,359,37,0,0,4,1],[362,7,362,19,0,0,4,0]],"save_cont":[[1601,6,1601,22,0,0,4,1]],"match":[[226,6,226,23,0,0,4,1],[228,6,228,25,0,0,4,1],[343,8,343,34,0,0,4,0],[350,8,350,59,0,0,4,0],[378,9,378,23,0,0,4,1],[391,12,391,17,0,0,4,0],[403,9,403,30,0,0,4,0],[405,14,405,44,0,0,4,0],[406,10,406,33,0,0,4,0],[406,10,406,33,0,0,4,1],[455,5,455,12,0,0,4,0],[459,5,459,12,0,0,4,1]],"cvt_id3":[[992,6,992,36,0,0,4,1]],"file_ascmagic_with_encoding":[[224,9,224,23,0,0,4,0],[224,27,224,51,0,0,4,1]],"getlength":[[188,6,188,13,0,0,4,0]],"mget":[[1752,8,1752,61,0,0,4,1],[1772,8,1772,29,0,0,4,0],[1774,8,1774,53,0,0,4,0],[1784,8,1784,53,0,0,4,0],[1825,8,1825,23,0,0,4,1],[1832,8,1832,19,0,0,4,1],[1838,8,1838,38,0,0,4,1],[1972,7,1972,42,0,0,4,1],[1976,7,1976,30,0,0,4,1],[1982,7,1982,24,0,0,4,1],[1998,7,1998,14,0,0,4,0],[1998,7,1998,14,0,0,4,1],[2002,10,2002,12,0,0,4,0],[2002,10,2002,12,0,0,4,1],[72,59,72,76,52,0,4,1],[109,22,109,25,53,0,4,1]],"file_magicfind":[[3764,8,3764,31,0,0,4,1],[3766,8,3766,40,0,0,4,0],[3766,8,3766,40,0,0,4,1],[3769,21,3769,35,0,0,4,0],[3770,13,3770,34,0,0,4,0],[3770,13,3770,34,0,0,4,1]],"msetoffset":[[1545,8,1545,38,0,0,4,1],[1555,7,1555,13,0,0,4,0]],"gettag":[[166,7,166,14,0,0,4,0]]},"library_calls":["magic_getpath","magic_open","magic_setflags","magic_close","magic_load","magic_close","magic_load_buffers","magic_close","magic_descriptor","magic_buffer","magic_close"],"critical_calls":["magic_getpath","magic_open","magic_setflags","magic_load","magic_load_buffers","magic_descriptor","magic_buffer","magic_close"],"visited":1}
/**/


// Include libmagic headers

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t* f_data, size_t f_size) {
	if(f_size<0) return 0;

	
	//fuzzer vars shim {
		FuzzedDataProvider fdp(f_data, f_size);
		FDPConsumeRawBytes(const uint8_t *, data, size, fdp)
	//fuzzer shim end}




    // Create a temporary file with the input data
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) {
        assert_file_closed(&in_file);
	return 0;
    }
    
    int fd = fuzz_fileno(in_file);
    if (fd < 0) {
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(fd);
	return 0;
    }
    
    // Get magic database path
    const char *magic_db_path = magic_getpath("magic.mgc", 0);
    if (!magic_db_path) {
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(fd);
	return 0;
    }
    
    // Create magic cookie
    magic_t magic_cookie = magic_open(MAGIC_NONE);
    if (!magic_cookie) {
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(fd);
	return 0;
    }
    
    // Set flags - using multiple flags for testing
    int flags = MAGIC_MIME | MAGIC_CONTINUE;
    if (magic_setflags(magic_cookie, flags) != 0) {
        magic_close(magic_cookie);
        assert_file_closed(&in_file);;
        assert_file_closed(&in_file);
	assert_fd_closed(fd);
	return 0;
    }
    
    // Load magic database from file
    if (magic_load(magic_cookie, magic_db_path) != 0) {
        // Try to load from buffers instead
        void *buffer = malloc(size);
        if (!buffer) {
            magic_close(magic_cookie);
            assert_file_closed(&in_file);;
            assert_file_closed(&in_file);
	assert_fd_closed(fd);
	return 0;
        }
        
        // Copy data to buffer
        memcpy(buffer, data, size);
        
        // Prepare buffer array for magic_load_buffers
        void *buffers[] = {buffer};
        size_t sizes[] = {size};
        
        // Try loading from buffer
        if (magic_load_buffers(magic_cookie, buffers, sizes, 1) != 0) {
            free(buffer);
            magic_close(magic_cookie);
            assert_file_closed(&in_file);;
            assert_file_closed(&in_file);
	assert_fd_closed(fd);
	return 0;
        }
        
        free(buffer);
    }
    
    // Now test the magic cookie with the input data
    // Try to identify the file type using the descriptor
    const char *result = magic_descriptor(magic_cookie, fd);
    if (result) {
        // Optional: Do something with the result
        // For fuzzing, we just want to exercise the APIs
    }
    
    // Test with buffer as well
    const char *buffer_result = magic_buffer(magic_cookie, data, size);
    if (buffer_result) {
        // Optional: Process buffer result
    }
    
    // Cleanup
    magic_close(magic_cookie);
    assert_file_closed(&in_file);;
    
    assert_file_closed(&in_file);
	assert_fd_closed(fd);
	return 0;
}