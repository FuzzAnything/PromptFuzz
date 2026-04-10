//===- FuzzedDataProvider.h - Utility header for fuzz targets ---*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// A single header library providing an utility class to break up an array of
// bytes. Whenever run on the same input, provides the same output, as long as
// its methods are called in the same order, with the same arguments.
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_
#define LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <iomanip>


#include <cstring>
#include <cmath>
union FloatByte {
    float value;
    unsigned char bytes[4];
};

inline float deserializeFloat(unsigned char bytes[4]) {
    FloatByte fb;
    for(int i=0; i<4; i++) {
        fb.bytes[i] = bytes[i];
    }
    return fb.value;
}

union DoubleByte {
    double value;
    unsigned char bytes[sizeof(double)];
};

inline double deserializeDouble(unsigned char bytes[sizeof(double)]) {
    DoubleByte db;
    for (int i = 0; i < sizeof(double); i++) {
        db.bytes[i] = bytes[i];
    }
    return db.value;
}


// In addition to the comments below, the API is also briefly documented at
// https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#fuzzed-data-provider
class FuzzedDataProvider {
 public:
  // |data| is an array of length |size| that the FuzzedDataProvider wraps to
  // provide more granular access. |data| must outlive the FuzzedDataProvider.
  FuzzedDataProvider(const uint8_t *data, size_t size)
      : data_ptr_(data), remaining_bytes_(size), magic_bytes{0xCA, 0xFE, 0xBA} {
      }
  ~FuzzedDataProvider() = default;

  // See the implementation below (after the class definition) for more verbose
  // comments for each of the methods.

  // Methods returning std::vector of bytes. These are the most popular choice
  // when splitting fuzzing input into pieces, as every piece is put into a
  // separate buffer (i.e. ASan would catch any under-/overflow) and the memory
  // will be released automatically.
  template <typename T> std::vector<T> ConsumeBytes(size_t num_bytes);
  template <typename T> T ConsumeByte();
  template <typename T>
  std::vector<T> ConsumeBytesWithTerminator(size_t num_bytes, T terminator = 0);
  template <typename T> std::vector<T> ConsumeRemainingBytes();


  // Methods returning strings. Use only when you need a std::string or a null
  // terminated C-string. Otherwise, prefer the methods returning std::vector.
  std::string ConsumeBytesAsString(size_t num_bytes);
  std::string ConsumeRandomLengthString(size_t max_length);
  std::string ConsumeRandomLengthString();
  std::string ConsumeRemainingBytesAsString();

  // Methods returning integer values.
  template <typename T> T ConsumeIntegral();
  template <typename T> T ConsumeIntegralInRange(T min, T max);

  // Methods returning floating point values.
  template <typename T> T ConsumeFloatingPoint();
  template <typename T> T ConsumeFloatingPointInRange(T min, T max);

  // 0 <= return value <= 1.
  template <typename T> T ConsumeProbability();

  bool ConsumeBool();

  // Returns a value chosen from the given enum.
  template <typename T> T ConsumeEnum();

  // Returns a value from the given array.
  template <typename T, size_t size> T PickValueInArray(const T (&array)[size]);
  template <typename T, size_t size>
  T PickValueInArray(const std::array<T, size> &array);
  template <typename T> T PickValueInArray(std::initializer_list<const T> list);

  // Writes data to the given destination and returns number of bytes written.
  size_t ConsumeData(void *destination, size_t num_bytes);

  // Reports the remaining bytes available for fuzzed input.
  size_t remaining_bytes() { return remaining_bytes_; }

//-----------------------------------------------------
//-----bellow are declared custom provider----------
//-----------------------------------------------------
  template <typename T> std::vector<T> ConsumeMagicBytes();
  template <typename T> std::vector<T> ConsumeMagicString();
  template <typename T> T ConsumeCoustomIntegral();
  template <typename T> T GetAnIntegeral();
  template <typename T> std::vector<T> ConsumeIntegralArray();
  std::vector<float> ConsumeFloatArray();
  std::vector<double> ConsumeDoubleArray();

  float ConsumeFloat();
  double ConsumeDouble();

 private:
  FuzzedDataProvider(const FuzzedDataProvider &) = delete;
  FuzzedDataProvider &operator=(const FuzzedDataProvider &) = delete;

  void CopyAndAdvance(void *destination, size_t num_bytes);

  void Advance(size_t num_bytes);
  void Retreat(size_t num_bytes);
  bool is_magic_bytes();

  template <typename T>
  std::vector<T> ConsumeBytes(size_t size, size_t num_bytes);

  template <typename TS, typename TU> TS ConvertUnsignedToSigned(TU value);

  const uint8_t *data_ptr_;
  size_t remaining_bytes_;
  const uint8_t magic_bytes[3];
};

// Returns a std::vector containing |num_bytes| of input data. If fewer than
// |num_bytes| of data remain, returns a shorter std::vector containing all
// of the data that's left. Can be used with any byte sized type, such as
// char, unsigned char, uint8_t, etc.
template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytes(size_t num_bytes) {
  num_bytes = std::min(num_bytes, remaining_bytes_);
  return ConsumeBytes<T>(num_bytes, num_bytes);
}

template <typename T>
T FuzzedDataProvider::ConsumeByte() {
  size_t num_bytes = std::min((size_t) 1, remaining_bytes_);
  std::vector<T> bytes = ConsumeBytes<T>(num_bytes, num_bytes);
  return bytes[0];
}

// Similar to |ConsumeBytes|, but also appends the terminator value at the end
// of the resulting vector. Useful, when a mutable null-terminated C-string is
// needed, for example. But that is a rare case. Better avoid it, if possible,
// and prefer using |ConsumeBytes| or |ConsumeBytesAsString| methods.
template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytesWithTerminator(size_t num_bytes,
                                                              T terminator) {
  num_bytes = std::min(num_bytes, remaining_bytes_);
  std::vector<T> result = ConsumeBytes<T>(num_bytes + 1, num_bytes);
  result.back() = terminator;
  return result;
}

// Returns a std::vector containing all remaining bytes of the input data.
template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeRemainingBytes() {
  return ConsumeBytes<T>(remaining_bytes_);
}

// Returns a std::string containing |num_bytes| of input data. Using this and
// |.c_str()| on the resulting string is the best way to get an immutable
// null-terminated C string. If fewer than |num_bytes| of data remain, returns
// a shorter std::string containing all of the data that's left.
inline std::string FuzzedDataProvider::ConsumeBytesAsString(size_t num_bytes) {
  static_assert(sizeof(std::string::value_type) == sizeof(uint8_t),
                "ConsumeBytesAsString cannot convert the data to a string.");

  num_bytes = std::min(num_bytes, remaining_bytes_);
  std::string result(
      reinterpret_cast<const std::string::value_type *>(data_ptr_), num_bytes);
  Advance(num_bytes);
  return result;
}

// Returns a std::string of length from 0 to |max_length|. When it runs out of
// input data, returns what remains of the input. Designed to be more stable
// with respect to a fuzzer inserting characters than just picking a random
// length and then consuming that many bytes with |ConsumeBytes|.
inline std::string
FuzzedDataProvider::ConsumeRandomLengthString(size_t max_length) {
  // Reads bytes from the start of |data_ptr_|. Maps "\\" to "\", and maps "\"
  // followed by anything else to the end of the string. As a result of this
  // logic, a fuzzer can insert characters into the string, and the string
  // will be lengthened to include those new characters, resulting in a more
  // stable fuzzer than picking the length of a string independently from
  // picking its contents.
  std::string result;

  // Reserve the anticipated capaticity to prevent several reallocations.
  result.reserve(std::min(max_length, remaining_bytes_));
  for (size_t i = 0; i < max_length && remaining_bytes_ != 0; ++i) {
    char next = ConvertUnsignedToSigned<char>(data_ptr_[0]);
    Advance(1);
    if (next == '\\' && remaining_bytes_ != 0) {
      next = ConvertUnsignedToSigned<char>(data_ptr_[0]);
      Advance(1);
      if (next != '\\')
        break;
    }
    result += next;
  }

  result.shrink_to_fit();
  return result;
}

// Returns a std::string of length from 0 to |remaining_bytes_|.
inline std::string FuzzedDataProvider::ConsumeRandomLengthString() {
  return ConsumeRandomLengthString(remaining_bytes_);
}

// Returns a std::string containing all remaining bytes of the input data.
// Prefer using |ConsumeRemainingBytes| unless you actually need a std::string
// object.
inline std::string FuzzedDataProvider::ConsumeRemainingBytesAsString() {
  return ConsumeBytesAsString(remaining_bytes_);
}

// Returns a number in the range [Type's min, Type's max]. The value might
// not be uniformly distributed in the given range. If there's no input data
// left, always returns |min|.
template <typename T> T FuzzedDataProvider::ConsumeIntegral() {
  return ConsumeIntegralInRange(std::numeric_limits<T>::min(),
                                std::numeric_limits<T>::max());
}

// Returns a number in the range [min, max] by consuming bytes from the
// input data. The value might not be uniformly distributed in the given
// range. If there's no input data left, always returns |min|. |min| must
// be less than or equal to |max|.
template <typename T>
T FuzzedDataProvider::ConsumeIntegralInRange(T min, T max) {
  static_assert(std::is_integral<T>::value, "An integral type is required.");
  static_assert(sizeof(T) <= sizeof(uint64_t), "Unsupported integral type.");

  if (min > max)
    abort();

  // Use the biggest type possible to hold the range and the result.
  uint64_t range = static_cast<uint64_t>(max) - min;
  uint64_t result = 0;
  size_t offset = 0;

  while (offset < sizeof(T) * CHAR_BIT && (range >> offset) > 0 &&
         remaining_bytes_ != 0) {
    // Pull bytes off the end of the seed data. Experimentally, this seems to
    // allow the fuzzer to more easily explore the input space. This makes
    // sense, since it works by modifying inputs that caused new code to run,
    // and this data is often used to encode length of data read by
    // |ConsumeBytes|. Separating out read lengths makes it easier modify the
    // contents of the data that is actually read.
    --remaining_bytes_;
    result = (result << CHAR_BIT) | data_ptr_[remaining_bytes_];
    offset += CHAR_BIT;
  }

  // Avoid division by 0, in case |range + 1| results in overflow.
  if (range != std::numeric_limits<decltype(range)>::max())
    result = result % (range + 1);

  return static_cast<T>(min + result);
}

// Returns a floating point value in the range [Type's lowest, Type's max] by
// consuming bytes from the input data. If there's no input data left, always
// returns approximately 0.
template <typename T> T FuzzedDataProvider::ConsumeFloatingPoint() {
  return ConsumeFloatingPointInRange<T>(std::numeric_limits<T>::lowest(),
                                        std::numeric_limits<T>::max());
}

// Returns a floating point value in the given range by consuming bytes from
// the input data. If there's no input data left, returns |min|. Note that
// |min| must be less than or equal to |max|.
template <typename T>
T FuzzedDataProvider::ConsumeFloatingPointInRange(T min, T max) {
  if (min > max)
    abort();

  T range = .0;
  T result = min;
  constexpr T zero(.0);
  if (max > zero && min < zero && max > min + std::numeric_limits<T>::max()) {
    // The diff |max - min| would overflow the given floating point type. Use
    // the half of the diff as the range and consume a bool to decide whether
    // the result is in the first of the second part of the diff.
    range = (max / 2.0) - (min / 2.0);
    //if (ConsumeBool()) {
      result += range;
    //}
  } else {
    range = max - min;
  }

  return result + range * ConsumeProbability<T>();
}

// Returns a floating point number in the range [0.0, 1.0]. If there's no
// input data left, always returns 0.
template <typename T> T FuzzedDataProvider::ConsumeProbability() {
  static_assert(std::is_floating_point<T>::value,
                "A floating point type is required.");

  // Use different integral types for different floating point types in order
  // to provide better density of the resulting values.
  using IntegralType =
      typename std::conditional<(sizeof(T) <= sizeof(uint32_t)), uint32_t,
                                uint64_t>::type;

  T result = static_cast<T>(ConsumeIntegral<IntegralType>());
  result /= static_cast<T>(std::numeric_limits<IntegralType>::max());
  return result;
}

// Reads one byte and returns a bool, or false when no data remains.
inline bool FuzzedDataProvider::ConsumeBool() {
  return 1 & ConsumeIntegral<uint8_t>();
}

// Returns an enum value. The enum must start at 0 and be contiguous. It must
// also contain |kMaxValue| aliased to its largest (inclusive) value. Such as:
// enum class Foo { SomeValue, OtherValue, kMaxValue = OtherValue };
template <typename T> T FuzzedDataProvider::ConsumeEnum() {
  static_assert(std::is_enum<T>::value, "|T| must be an enum type.");
  return static_cast<T>(
      ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(T::kMaxValue)));
}

// Returns a copy of the value selected from the given fixed-size |array|.
template <typename T, size_t size>
T FuzzedDataProvider::PickValueInArray(const T (&array)[size]) {
  static_assert(size > 0, "The array must be non empty.");
  return array[ConsumeIntegralInRange<size_t>(0, size - 1)];
}

template <typename T, size_t size>
T FuzzedDataProvider::PickValueInArray(const std::array<T, size> &array) {
  static_assert(size > 0, "The array must be non empty.");
  return array[ConsumeIntegralInRange<size_t>(0, size - 1)];
}

template <typename T>
T FuzzedDataProvider::PickValueInArray(std::initializer_list<const T> list) {
  // TODO(Dor1s): switch to static_assert once C++14 is allowed.
  if (!list.size())
    abort();

  return *(list.begin() + ConsumeIntegralInRange<size_t>(0, list.size() - 1));
}

// Writes |num_bytes| of input data to the given destination pointer. If there
// is not enough data left, writes all remaining bytes. Return value is the
// number of bytes written.
// In general, it's better to avoid using this function, but it may be useful
// in cases when it's necessary to fill a certain buffer or object with
// fuzzing data.
inline size_t FuzzedDataProvider::ConsumeData(void *destination,
                                              size_t num_bytes) {
  num_bytes = std::min(num_bytes, remaining_bytes_);
  CopyAndAdvance(destination, num_bytes);
  return num_bytes;
}

// Private methods.
inline void FuzzedDataProvider::CopyAndAdvance(void *destination,
                                               size_t num_bytes) {
  std::memcpy(destination, data_ptr_, num_bytes);
  Advance(num_bytes);
}

inline void FuzzedDataProvider::Advance(size_t num_bytes) {
  if (num_bytes > remaining_bytes_)
    abort();

  data_ptr_ += num_bytes;
  remaining_bytes_ -= num_bytes;
}

template <typename T>
std::vector<T> FuzzedDataProvider::ConsumeBytes(size_t size, size_t num_bytes) {
  static_assert(sizeof(T) == sizeof(uint8_t), "Incompatible data type.");

  // The point of using the size-based constructor below is to increase the
  // odds of having a vector object with capacity being equal to the length.
  // That part is always implementation specific, but at least both libc++ and
  // libstdc++ allocate the requested number of bytes in that constructor,
  // which seems to be a natural choice for other implementations as well.
  // To increase the odds even more, we also call |shrink_to_fit| below.
  std::vector<T> result(size);
  if (size == 0) {
    if (num_bytes != 0)
      abort();
    return result;
  }

  CopyAndAdvance(result.data(), num_bytes);

  // Even though |shrink_to_fit| is also implementation specific, we expect it
  // to provide an additional assurance in case vector's constructor allocated
  // a buffer which is larger than the actual amount of data we put inside it.
  result.shrink_to_fit();
  return result;
}

template <typename TS, typename TU>
TS FuzzedDataProvider::ConvertUnsignedToSigned(TU value) {
  static_assert(sizeof(TS) == sizeof(TU), "Incompatible data types.");
  static_assert(!std::numeric_limits<TU>::is_signed,
                "Source type must be unsigned.");

  // TODO(Dor1s): change to `if constexpr` once C++17 becomes mainstream.
  if (std::numeric_limits<TS>::is_modulo)
    return static_cast<TS>(value);

  // Avoid using implementation-defined unsigned to signed conversions.
  // To learn more, see https://stackoverflow.com/questions/13150449.
  if (value <= std::numeric_limits<TS>::max()) {
    return static_cast<TS>(value);
  } else {
    constexpr auto TS_min = std::numeric_limits<TS>::min();
    return TS_min + static_cast<TS>(value - TS_min);
  }
}

//-----------------------------------------------------
//-----bellow are implemented custom provider----------
//-----------------------------------------------------

inline void FuzzedDataProvider::Retreat(size_t num_bytes) {
  data_ptr_ -= num_bytes;
  remaining_bytes_ += num_bytes;
}

// Wether the head of the data is the magic bytes.
inline bool FuzzedDataProvider::is_magic_bytes() {
  uint8_t next = data_ptr_[0];
  Advance(1);
  if (next == magic_bytes[0] && remaining_bytes_ != 0) {
    uint8_t next_byte = data_ptr_[0];
    Advance(1);
    if (next_byte == magic_bytes[1] && remaining_bytes_ != 0) {
      next_byte = data_ptr_[0];
      Advance(1);
      if (next_byte == magic_bytes[2]) {
        return true;
      }
      Retreat(1);
    }
    Retreat(1);
  }
  Retreat(1);
  return false;
}

// Consume raw bytes until meet a magic string.
template <typename T> 
std::vector<T> FuzzedDataProvider::ConsumeMagicBytes() {
  std::vector<T> result;
  size_t default_size = 512;
  size_t ty_size = sizeof(T);
  static_assert(sizeof(T) == 1, "ConsumeMagicBytes only can consume with type size == 1");

  // Reserve the anticipated capaticity to prevent several reallocations.
  result.reserve(std::min(default_size, remaining_bytes_));
  for (size_t i = 0; remaining_bytes_ != 0; i += ty_size) {
    if (is_magic_bytes()) {
      break;
    }
    uint8_t next = (T) data_ptr_[0];
    Advance(1);
    result.push_back(next);
  }

  result.shrink_to_fit();
  return result;
}


inline std::vector<float> FuzzedDataProvider::ConsumeFloatArray() {
  std::vector<float> result;
  size_t default_size = 512;
  size_t ty_size = sizeof(float);

  // Reserve the anticipated capaticity to prevent several reallocations.
  result.reserve(std::min(default_size, remaining_bytes_));
  while (remaining_bytes_ >= ty_size) {
    if (is_magic_bytes()) {
      break;
    }
    float next = ConsumeFloat();
    result.push_back(next);
  }

  result.shrink_to_fit();
  return result;
}

inline std::vector<double> FuzzedDataProvider::ConsumeDoubleArray() {
  std::vector<double> result;
  size_t default_size = 512;
  size_t ty_size = sizeof(double);

  // Reserve the anticipated capaticity to prevent several reallocations.
  result.reserve(std::min(default_size, remaining_bytes_));
  while (remaining_bytes_ >= ty_size) {
    if (is_magic_bytes()) {
      break;
    }
    double next = ConsumeDouble();
    result.push_back(next);
  }

  result.shrink_to_fit();
  return result;
}

template <typename T> std::vector<T> FuzzedDataProvider::ConsumeIntegralArray() {
  std::vector<T> result;
  size_t default_size = 512;
  size_t ty_size = sizeof(T);

  // Reserve the anticipated capaticity to prevent several reallocations.
  result.reserve(std::min(default_size, remaining_bytes_));
  while (remaining_bytes_ >= ty_size) {
    if (is_magic_bytes()) {
      break;
    }
    T next = ConsumeCoustomIntegral<T>();
    result.push_back(next);
  }

  result.shrink_to_fit();
  return result;
}

template <typename T> T FuzzedDataProvider::GetAnIntegeral() {
  static_assert(std::is_integral<T>::value, "An integral type is required.");
  static_assert(sizeof(T) <= sizeof(uint64_t), "Unsupported integral type.");
  if (remaining_bytes_ == 0 || remaining_bytes_ < sizeof(T)) {
    return static_cast<T>(0);
  }
  size_t offset = 0;
  uint64_t result = 0;

  while (offset < sizeof(T) * CHAR_BIT && remaining_bytes_ != 0) {
      u_int8_t byte = data_ptr_[offset];
      result = (result << CHAR_BIT) | byte;
      offset += CHAR_BIT;
  }
  return static_cast<T>(result);
}

template <typename T>
T FuzzedDataProvider::ConsumeCoustomIntegral() {
  static_assert(std::is_integral<T>::value, "An integral type is required.");
  static_assert(sizeof(T) <= sizeof(uint64_t), "Unsupported integral type.");

  // Use the biggest type possible to hold the range and the result.
  
  uint64_t result = 0;
  size_t offset = 0;

  while (offset < sizeof(T) * CHAR_BIT && remaining_bytes_ != 0) {
    u_int8_t byte = ConsumeByte<u_int8_t>();
    result = (result << CHAR_BIT) | byte;
    offset += CHAR_BIT;
  }
  return static_cast<T>(result);
}

inline float FuzzedDataProvider::ConsumeFloat() {
  size_t size = sizeof(float);
  std::vector<unsigned char> byte_vec = ConsumeBytes<unsigned char>(size);
  unsigned char bytes[size];
  for (int i=0; i<size; i++) {
    bytes[i] = byte_vec[i];
  }
  float value = deserializeFloat(bytes);
  return value;
}


inline double FuzzedDataProvider::ConsumeDouble() {
  size_t size = sizeof(double);
  std::vector<unsigned char> byte_vec = ConsumeBytes<unsigned char>(size);
  unsigned char bytes[size];
  for (int i=0; i<size; i++) {
    bytes[i] = byte_vec[i];
  }
  double value = deserializeDouble(bytes);
  return value;
}

template <typename T> std::vector<T> FuzzedDataProvider::ConsumeMagicString() {
  static_assert(sizeof(T) == 1, "An char type is required.");
  std::vector<T> result;
  size_t default_size = 128;

  // Reserve the anticipated capaticity to prevent several reallocations.
  result.reserve(std::min(default_size, remaining_bytes_));
  for (size_t i = 0; remaining_bytes_ != 0; ++i) {
    if (is_magic_bytes()){
      break;
    }
    uint8_t next = data_ptr_[0];
    Advance(1);
    if (std::numeric_limits<T>::is_signed) {
      T next_char = ConvertUnsignedToSigned<char>(next);
      result.push_back(next_char);
    } else {
      T next_char = static_cast<T>(next);
      result.push_back(next_char);
    }
  }
  result.shrink_to_fit();
  return result;
}

template <typename T>
inline const T* FDPCheckSizeReturnNull(std::vector<T> &var) {
  if (var.size() == 0) {
    return NULL;
  } else {
    return var.data();
  }
}

#include<iostream>

#ifdef __cplusplus
extern "C" {
#endif

#define FDPConsumeRawBytes(ty, data, data_sz, fdp) \
  if (fdp.remaining_bytes() == 0) { return 0;} \
  std::vector<uint8_t> temp_bytes = fdp.ConsumeMagicBytes<uint8_t>(); \
  const uint8_t* data = temp_bytes.data(); \
  size_t data_sz = temp_bytes.size(); \
  if (data_sz == 0) return 0; 

#define FDPConsumeRawBytesWithNullTerm(ty, data, data_sz, fdp) \
  if (fdp.remaining_bytes() == 0) { return 0;} \
  std::vector<uint8_t> temp_bytes = fdp.ConsumeMagicBytes<uint8_t>(); \
  const uint8_t* data; \
  size_t data_sz; \
  if (temp_bytes.size() ==0) { \
    data = NULL; \
    data_sz = 0; \
    return 0; \
  } else { \
    temp_bytes.push_back('\x00'); \
    data = (ty)temp_bytes.data(); \
    data_sz = temp_bytes.size(); \
  }

#define FDPReadRawBytes(ty, data, data_sz, fdp) \
  const char *fuzz_filename = "highest_cov_corpora"; \
  std::ifstream fuzz_file(fuzz_filename, std::ios::binary); \
  if (!fuzz_file) { \
      std::cerr << "Error opening file: " << fuzz_filename << std::endl; \
      abort(); \
  } \
  std::vector<uint8_t> promptfuzz_fuzz_data((std::istreambuf_iterator<char>(fuzz_file)), std::istreambuf_iterator<char>()); \
  const uint8_t* data = promptfuzz_fuzz_data.data(); \
  size_t data_sz = promptfuzz_fuzz_data.size(); 

#define FDPReadRawBytesWithNullTerm(ty, data, data_sz, fdp) \
  const char *fuzz_filename = "highest_cov_corpora"; \
  std::ifstream fuzz_file(fuzz_filename, std::ios::binary); \
  if (!fuzz_file) { \
      std::cerr << "Error opening file: " << fuzz_filename << std::endl; \
      return 1; \
  } \
  std::vector<uint8_t> promptfuzz_fuzz_data((std::istreambuf_iterator<char>(fuzz_file)), std::istreambuf_iterator<char>()); \
  promptfuzz_fuzz_data.push_back('\x00'); \
  const uint8_t* data = promptfuzz_fuzz_data.data(); \
  size_t data_sz = promptfuzz_fuzz_data.size(); 

#define FDPConsumeChar(var, fdp) \
  if (fdp.remaining_bytes() < sizeof(char)) { return 0;} \
  char var = fdp.ConsumeByte<char>();

#define FDPConsumeUChar(var, fdp) \
  if (fdp.remaining_bytes() < sizeof(unsigned char)) { return 0;} \
  char var = fdp.ConsumeByte<unsigned char>();

#define FDPConsumeCharArray(ty, var, array_sz, fdp) \
  std::vector<ty> temp_##var = fdp.ConsumeMagicString<ty>(); \
  size_t array_sz = temp_##var.size(); \
  const ty *var; \
  if (array_sz == 0) { \
    var = NULL; \
    return 0; \
  } else { \
    var = temp_##var.data(); \
  }

#define FDPConsumeFloatingPoint(var, fdp) \
  if (fdp.remaining_bytes() < sizeof(float)) { return 0;} \
  float var = fdp.ConsumeFloat(); 

#define FDPConsumeFloatingArray(var, array_sz, fdp) \
  std::vector<float> temp_##var = fdp.ConsumeFloatArray(); \
  const float *var = FDPCheckSizeReturnNull(temp_##var); \
  size_t array_sz = temp_##var.size(); \
  if (array_sz == 0) return 0;
  

#define FDPConsumeDoublingPoint(var, fdp) \
  if (fdp.remaining_bytes() < sizeof(double)) { return 0;} \
  double var = fdp.ConsumeDouble();

#define FDPConsumeDoublingArray(var, array_sz, fdp) \
  std::vector<double> temp_##var = fdp.ConsumeDoubleArray(); \
  const double *var = FDPCheckSizeReturnNull(temp_##var); \
  size_t array_sz = temp_##var.size(); \
  if (array_sz ==0 ) return 0;
  
#define FDPConsumeRandomLengthString(ty, var, var_sz, fdp) \
  std::vector<ty> temp_##var = fdp.ConsumeMagicString<ty>(); \
  const ty *var; \
  size_t var_sz = temp_##var.size(); \
  if (temp_##var.size() == 0) { \
    var = NULL; \
    return 0; \
  } else { \
    temp_##var.push_back(static_cast<ty>('\x00')); \
    var = temp_##var.data(); \
  }

#define FDPConsumeIntegral(ty, var, fdp) \
  if (fdp.remaining_bytes() < sizeof(ty)) { return 0;} \
  ty var = fdp.ConsumeCoustomIntegral<ty>();
  
#define FDPConsumeIntegralArray(ty, var, array_sz, fdp) \
  std::vector<ty> temp_##var = fdp.ConsumeIntegralArray<ty>(); \
  const ty *var = FDPCheckSizeReturnNull(temp_##var); \
  size_t array_sz = temp_##var.size(); \
  if (array_sz == 0) return 0;


#define FDPGetRandomInteger(ty, var, size_limit) \
ty var = fdp.GetAnIntegeral<ty>() % static_cast<ty>(size_limit);
  


// Bellow only used for debugging.

#define FDPConsumeCharDebug(var, fdp) \
  if (fdp.remaining_bytes() < sizeof(char)) { return 0;} \
  char var = fdp.ConsumeByte<char>();\
  std::cout<<"FDPConsumeChar: "<< var<< std::endl;

#define FDPConsumeFloatingPointDebug(var, fdp) \
  if (fdp.remaining_bytes() < sizeof(float)) { return 0;} \
  float var = fdp.ConsumeFloat(); \
  std::cout<<"FDPConsumeFloat: "<< std::fixed << std::setprecision(18) << var<< std::endl;

#define FDPConsumeDoublingPointDebug(var, fdp) \
  if (fdp.remaining_bytes() < sizeof(double)) { return 0;} \
  double var = fdp.ConsumeDouble();\
  std::cout<<"FDPConsumeDouble: "<< std::fixed << std::setprecision(18) << var<< std::endl;


#define FDPConsumeIntegralDebug(ty, var, fdp) \
  if (fdp.remaining_bytes() < sizeof(ty)) { return 0;} \
  ty var = fdp.ConsumeCousomIntegral<ty>();\
  std::cout<<"FDPConsumeIntegeral: "<< var<< std::endl;


#ifdef __cplusplus
} // extern "C"
#endif

#endif // LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_
