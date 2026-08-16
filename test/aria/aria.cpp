/**
 * @file aria.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief ARIA block cipher verification (RFC 5794)
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <ctl/bytes>
#include <ctl/detail/cpu>
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

  // The vectors share one key that is long enough for every size, so the part
  // this cipher uses is named rather than being left to a length argument that
  // happens to be smaller than the buffer.
  Cipher cipher(ctl::bytes(key).first(Cipher::key_size));

  std::vector<uint8_t> encrypted(Cipher::block_size);
  cipher.encrypt_block(plain, encrypted);
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(Cipher::block_size);
  cipher.decrypt_block(encrypted, decrypted);
  EXPECT_EQ(std::string(plain_hex), test::to_hex(decrypted));

  std::vector<uint8_t> inplace = plain;
  cipher.encrypt_block(inplace, inplace);
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

namespace {

// The vector path and the table driven path have to agree on every input. Where
// the vector path is not compiled in, or the processor does not support it, both
// calls go through the same code and the test still passes meaningfully.
template <class Cipher> void check_paths_agree() {
  std::vector<uint8_t> key(Cipher::key_size);
  for (size_t i = 0; i < key.size(); ++i)
    key[i] = static_cast<uint8_t>(0x3c + i * 5);

  Cipher cipher(key);

  std::vector<uint8_t> block(Cipher::block_size);
  std::vector<uint8_t> by_dispatch(Cipher::block_size);
  std::vector<uint8_t> by_software(Cipher::block_size);

  uint32_t state = 0x9e3779b9u;
  for (size_t round = 0; round < 512; ++round) {
    for (size_t i = 0; i < block.size(); ++i) {
      state = state * 1664525u + 1013904223u;
      block[i] = static_cast<uint8_t>(state >> 24);
    }

    cipher.encrypt_block(block, by_dispatch);
    cipher.encrypt_block_reference(block, by_software);
    ASSERT_EQ(test::to_hex(by_software), test::to_hex(by_dispatch))
        << "encrypt mismatch at round " << round;

    cipher.decrypt_block(by_dispatch, by_dispatch);
    cipher.decrypt_block_reference(by_software, by_software);
    ASSERT_EQ(test::to_hex(by_software), test::to_hex(by_dispatch))
        << "decrypt mismatch at round " << round;
    ASSERT_EQ(test::to_hex(block), test::to_hex(by_dispatch))
        << "roundtrip mismatch at round " << round;
  }
}

} // namespace

// The three tests below pass whether or not the vector path is reached, because
// where it is not the table driven path answers for it and answers correctly.
// This is the one that notices.
TEST(aria, the_vector_path_is_actually_reached) {
  const std::vector<uint8_t> key(aria<128>::key_size);
  aria<128> cipher(key);

#if defined(CTL_HAS_X86_HW_ACCEL)
  EXPECT_EQ(ctl::detail::cpu::has_aes() && ctl::detail::cpu::has_byte_shuffle(),
            cipher.accelerated());
#elif defined(CTL_HAS_ARM_HW_ACCEL)
  EXPECT_EQ(ctl::detail::cpu::has_arm_aes(), cipher.accelerated());
#else
  EXPECT_FALSE(cipher.accelerated());
#endif

  // Unlike AES, the vector path holds one block per register with nothing to
  // interleave, so it asks for no batches whether or not it is reached.
  EXPECT_FALSE(cipher.prefers_batching());
}

TEST(aria, vector_path_agrees_with_software_128) {
  check_paths_agree<aria<128>>();
}

TEST(aria, vector_path_agrees_with_software_192) {
  check_paths_agree<aria<192>>();
}

TEST(aria, vector_path_agrees_with_software_256) {
  check_paths_agree<aria<256>>();
}

TEST(aria, rejects_key_of_the_wrong_length) {
  const std::vector<uint8_t> too_short =
      test::hex("00112233445566778899aabbccdd");
  ASSERT_LT(too_short.size(), aria<128>::key_size);
  EXPECT_THROW(aria<128>{ctl::bytes(too_short)}, std::invalid_argument);

  const std::vector<uint8_t> too_long(aria<256>::key_size);
  EXPECT_THROW(aria<128>{ctl::bytes(too_long)}, std::invalid_argument);
}
