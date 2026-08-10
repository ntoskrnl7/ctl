/**
 * @file vectors.h
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief Helpers for working with test vectors
 *
 * Specifications print their test values as hexadecimal strings, so comparing
 * in the same form makes it immediately clear which byte differs on a failure.
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace test {

/**
 * @brief Converts a hexadecimal string into a byte string
 *
 * @param text hexadecimal string, without any whitespace
 * @return the bytes
 */
inline std::vector<uint8_t> hex(const std::string &text) {
  std::vector<uint8_t> result;
  result.reserve(text.size() / 2);
  for (size_t i = 0; i + 1 < text.size(); i += 2) {
    const char digits[3] = {text[i], text[i + 1], '\0'};
    result.push_back(static_cast<uint8_t>(strtoul(digits, nullptr, 16)));
  }
  return result;
}

/**
 * @brief Converts a byte string into a hexadecimal string
 *
 * @param data the bytes
 * @param size number of bytes
 * @return hexadecimal string
 */
inline std::string to_hex(const uint8_t *data, size_t size) {
  static const char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    result.push_back(digits[data[i] >> 4]);
    result.push_back(digits[data[i] & 0x0f]);
  }
  return result;
}

/**
 * @brief Converts a byte string into a hexadecimal string
 */
inline std::string to_hex(const std::vector<uint8_t> &data) {
  return to_hex(data.data(), data.size());
}

} // namespace test
