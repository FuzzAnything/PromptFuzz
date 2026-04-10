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
#include <FuzzedDataProvider.h>


extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t* data, size_t size);
extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t* data, size_t size);


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	FuzzedDataProvider fdp(data, size);
	FDPConsumeIntegral(uint16_t, switch_id, fdp);
	const uint8_t *input = data + sizeof(uint16_t);
	size_t i_size = size - sizeof(uint16_t);
	switch (switch_id) {
		case 0:
			return LLVMFuzzerTestOneInput_3(input, i_size);
			break;
		case 1:
			return LLVMFuzzerTestOneInput_4(input, i_size);
			break;
		case 2:
			return LLVMFuzzerTestOneInput_5(input, i_size);
			break;
		case 3:
			return LLVMFuzzerTestOneInput_6(input, i_size);
			break;
		case 4:
			return LLVMFuzzerTestOneInput_7(input, i_size);
			break;
		case 5:
			return LLVMFuzzerTestOneInput_8(input, i_size);
			break;
		case 6:
			return LLVMFuzzerTestOneInput_9(input, i_size);
			break;
		case 7:
			return LLVMFuzzerTestOneInput_10(input, i_size);
			break;
		case 8:
			return LLVMFuzzerTestOneInput_11(input, i_size);
			break;
		case 9:
			return LLVMFuzzerTestOneInput_12(input, i_size);
			break;
		case 10:
			return LLVMFuzzerTestOneInput_13(input, i_size);
			break;
		case 11:
			return LLVMFuzzerTestOneInput_14(input, i_size);
			break;
		case 12:
			return LLVMFuzzerTestOneInput_15(input, i_size);
			break;
		case 13:
			return LLVMFuzzerTestOneInput_16(input, i_size);
			break;
		case 14:
			return LLVMFuzzerTestOneInput_17(input, i_size);
			break;
		case 15:
			return LLVMFuzzerTestOneInput_18(input, i_size);
			break;
		case 16:
			return LLVMFuzzerTestOneInput_19(input, i_size);
			break;
		case 17:
			return LLVMFuzzerTestOneInput_20(input, i_size);
			break;
		case 18:
			return LLVMFuzzerTestOneInput_21(input, i_size);
			break;
		case 19:
			return LLVMFuzzerTestOneInput_22(input, i_size);
			break;
		case 20:
			return LLVMFuzzerTestOneInput_23(input, i_size);
			break;
		case 21:
			return LLVMFuzzerTestOneInput_24(input, i_size);
			break;
		case 22:
			return LLVMFuzzerTestOneInput_25(input, i_size);
			break;
		case 23:
			return LLVMFuzzerTestOneInput_26(input, i_size);
			break;
		case 24:
			return LLVMFuzzerTestOneInput_27(input, i_size);
			break;
		case 25:
			return LLVMFuzzerTestOneInput_28(input, i_size);
			break;
		case 26:
			return LLVMFuzzerTestOneInput_29(input, i_size);
			break;
		case 27:
			return LLVMFuzzerTestOneInput_30(input, i_size);
			break;
		case 28:
			return LLVMFuzzerTestOneInput_31(input, i_size);
			break;
		case 29:
			return LLVMFuzzerTestOneInput_32(input, i_size);
			break;
		case 30:
			return LLVMFuzzerTestOneInput_33(input, i_size);
			break;
		case 31:
			return LLVMFuzzerTestOneInput_34(input, i_size);
			break;
		case 32:
			return LLVMFuzzerTestOneInput_35(input, i_size);
			break;
		case 33:
			return LLVMFuzzerTestOneInput_36(input, i_size);
			break;
		case 34:
			return LLVMFuzzerTestOneInput_37(input, i_size);
			break;
		case 35:
			return LLVMFuzzerTestOneInput_38(input, i_size);
			break;
		case 36:
			return LLVMFuzzerTestOneInput_39(input, i_size);
			break;
		default:
			break;
	}
return 0;
}
