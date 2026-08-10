/**
 * @file aria.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief ARIA block cipher verification (RFC 5794)
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <ctl/symmetric/cipher/aria>

#include "../vectors.h"

namespace {

// The three examples in appendix A of RFC 5794 share one plaintext and use
// sequential keys that differ only in length.
const char *kSequentialKey =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const char *kPlaintext = "00112233445566778899aabbccddeeff";

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

  std::vector<uint8_t> inplace = plain;
  cipher.encrypt_block(inplace.data(), inplace.data());
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(inplace));
}

} // namespace

using ctl::symmetric::cipher::aria;

TEST(aria, rfc5794_appendix_a1_128bit) {
  check<aria<128>>(kSequentialKey, kPlaintext,
                   "d718fbd6ab644c739da95f3be6451778");
}

TEST(aria, rfc5794_appendix_a2_192bit) {
  check<aria<192>>(kSequentialKey, kPlaintext,
                   "26449c1805dbe7aa25a468ce263a9e79");
}

TEST(aria, rfc5794_appendix_a3_256bit) {
  check<aria<256>>(kSequentialKey, kPlaintext,
                   "f92bd7c79fb72e2f2b8f80c1972d24fc");
}

TEST(aria, key_size_constants) {
  EXPECT_EQ(16u, aria<128>::key_size);
  EXPECT_EQ(24u, aria<192>::key_size);
  EXPECT_EQ(32u, aria<256>::key_size);
  EXPECT_EQ(16u, aria<128>::block_size);
  // Section 2.2 of RFC 5794
  EXPECT_EQ(12u, aria<128>::rounds);
  EXPECT_EQ(14u, aria<192>::rounds);
  EXPECT_EQ(16u, aria<256>::rounds);
  // One extra round key is needed for the additional key addition layer of the
  // last round.
  EXPECT_EQ(13u, aria<128>::round_key_count);
  EXPECT_EQ(15u, aria<192>::round_key_count);
  EXPECT_EQ(17u, aria<256>::round_key_count);
}

TEST(aria, rejects_short_key_buffer) {
  const std::vector<uint8_t> key = test::hex("00112233445566778899aabbccdd");
  ASSERT_LT(key.size(), aria<128>::key_size);
  EXPECT_THROW(aria<128>(key.data(), key.size()), std::invalid_argument);
}
