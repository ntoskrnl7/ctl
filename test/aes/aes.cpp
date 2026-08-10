/**
 * @file aes.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief AES block cipher verification (FIPS 197, NIST SP 800-38A)
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <ctl/symmetric/cipher/aes>

#include "../vectors.h"

namespace {

// The three examples in appendix C of FIPS 197 share one plaintext and use
// sequential keys that differ only in length.
const char *kSequentialKey =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const char *kPlaintext = "00112233445566778899aabbccddeeff";

/**
 * @brief Verifies a block cipher against a known answer vector
 */
template <class Cipher>
void check(const char *key_hex, const char *plain_hex,
           const char *cipher_hex) {
  const std::vector<uint8_t> key = test::hex(key_hex);
  const std::vector<uint8_t> plain = test::hex(plain_hex);

  ASSERT_GE(key.size(), Cipher::key_size);
  ASSERT_EQ(plain.size(), Cipher::block_size);

  Cipher cipher(key.data(), Cipher::key_size);

  std::vector<uint8_t> encrypted(Cipher::block_size);
  cipher.encrypt_block(plain.data(), encrypted.data());
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(Cipher::block_size);
  cipher.decrypt_block(encrypted.data(), decrypted.data());
  EXPECT_EQ(std::string(plain_hex), test::to_hex(decrypted));

  // The result has to be the same when the input and output buffers coincide.
  std::vector<uint8_t> inplace = plain;
  cipher.encrypt_block(inplace.data(), inplace.data());
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(inplace));
}

} // namespace

using ctl::symmetric::cipher::aes;

TEST(aes, fips197_appendix_c1_128bit) {
  check<aes<128>>(kSequentialKey, kPlaintext,
                  "69c4e0d86a7b0430d8cdb78070b4c55a");
}

TEST(aes, fips197_appendix_c2_192bit) {
  check<aes<192>>(kSequentialKey, kPlaintext,
                  "dda97ca4864cdfe06eaf70a0ec0d7191");
}

TEST(aes, fips197_appendix_c3_256bit) {
  check<aes<256>>(kSequentialKey, kPlaintext,
                  "8ea2b7ca516745bfeafc49904b496089");
}

// Since all three cases in appendix C share a plaintext, one more vector with a
// different key and a different plaintext is checked as well.
TEST(aes, sp800_38a_f11_first_block) {
  check<aes<128>>("2b7e151628aed2a6abf7158809cf4f3c",
                  "6bc1bee22e409f96e93d7e117393172a",
                  "3ad77bb40d7a3660a89ecaf32466ef97");
}

TEST(aes, key_size_constants) {
  EXPECT_EQ(16u, aes<128>::key_size);
  EXPECT_EQ(24u, aes<192>::key_size);
  EXPECT_EQ(32u, aes<256>::key_size);
  EXPECT_EQ(16u, aes<128>::block_size);
  // Table 2 of FIPS 197: Nr = Nk + 6
  EXPECT_EQ(10u, aes<128>::rounds);
  EXPECT_EQ(12u, aes<192>::rounds);
  EXPECT_EQ(14u, aes<256>::rounds);
}

namespace {

// The hardware path and the software path have to agree on every input. When
// the hardware path is not compiled in, or the CPU does not support it, both
// calls go through the same code, so this test still passes meaningfully.
template <class Cipher> void check_paths_agree() {
  std::vector<uint8_t> key(Cipher::key_size);
  for (size_t i = 0; i < key.size(); ++i)
    key[i] = static_cast<uint8_t>(0x5a + i * 7);

  Cipher cipher(key.data(), key.size());

  std::vector<uint8_t> block(Cipher::block_size);
  std::vector<uint8_t> by_dispatch(Cipher::block_size);
  std::vector<uint8_t> by_software(Cipher::block_size);

  uint32_t state = 0x12345678u;
  for (size_t round = 0; round < 512; ++round) {
    for (size_t i = 0; i < block.size(); ++i) {
      // Reproducible values are needed, so a simple linear congruential
      // generator is used.
      state = state * 1664525u + 1013904223u;
      block[i] = static_cast<uint8_t>(state >> 24);
    }

    cipher.encrypt_block(block.data(), by_dispatch.data());
    cipher.encrypt_block_software(block.data(), by_software.data());
    ASSERT_EQ(test::to_hex(by_software), test::to_hex(by_dispatch))
        << "encrypt mismatch at round " << round;

    cipher.decrypt_block(by_dispatch.data(), by_dispatch.data());
    cipher.decrypt_block_software(by_software.data(), by_software.data());
    ASSERT_EQ(test::to_hex(by_software), test::to_hex(by_dispatch))
        << "decrypt mismatch at round " << round;
    ASSERT_EQ(test::to_hex(block), test::to_hex(by_dispatch))
        << "roundtrip mismatch at round " << round;
  }
}

} // namespace

TEST(aes, hardware_path_agrees_with_software_128) {
  check_paths_agree<aes<128>>();
}

TEST(aes, hardware_path_agrees_with_software_192) {
  check_paths_agree<aes<192>>();
}

TEST(aes, hardware_path_agrees_with_software_256) {
  check_paths_agree<aes<256>>();
}

TEST(aes, rejects_short_key_buffer) {
  const std::vector<uint8_t> key = test::hex("00112233445566778899aabbccdd");
  ASSERT_LT(key.size(), aes<128>::key_size);
  EXPECT_THROW(aes<128>(key.data(), key.size()), std::invalid_argument);
}
