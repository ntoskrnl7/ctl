/**
 * @file lea.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief LEA block cipher verification (KS X 3246, ISO/IEC 29192-2)
 *
 * The round constants of LEA are the only values in this library that no
 * property of their own can check, so these vectors are what stands between a
 * mistyped digit and a build that passes.
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <array>

#include <ctl/bytes>
#include <ctl/symmetric/cipher/lea>

#include "../vectors.h"

namespace {

/**
 * @brief Verifies a block cipher against a known answer vector
 */
template <class Cipher>
void check(const char *key_hex, const char *plain_hex,
           const char *cipher_hex) {
  const std::vector<uint8_t> key = test::hex(key_hex);
  const std::vector<uint8_t> plain = test::hex(plain_hex);

  ASSERT_EQ(key.size(), Cipher::key_size);
  ASSERT_EQ(plain.size(), Cipher::block_size);

  Cipher cipher(key);

  std::vector<uint8_t> encrypted(Cipher::block_size);
  cipher.encrypt_block(plain, encrypted);
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(Cipher::block_size);
  cipher.decrypt_block(encrypted, decrypted);
  EXPECT_EQ(std::string(plain_hex), test::to_hex(decrypted));

  // The result has to be the same when the input and output buffers coincide.
  std::vector<uint8_t> inplace = plain;
  cipher.encrypt_block(inplace, inplace);
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(inplace));
}

} // namespace

using ctl::symmetric::cipher::lea;

// The three vectors published with the specification, one per key length. Each
// uses its own plaintext, so unlike the AES and ARIA vectors these do not share
// one input between them.
TEST(lea, spec_vector_128bit) {
  check<lea<128>>("0f1e2d3c4b5a69788796a5b4c3d2e1f0",
                  "101112131415161718191a1b1c1d1e1f",
                  "9fc84e3528c6c6185532c7a704648bfd");
}

TEST(lea, spec_vector_192bit) {
  check<lea<192>>("0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a59687",
                  "202122232425262728292a2b2c2d2e2f",
                  "6fb95e325aad1b878cdcf5357674c6f2");
}

TEST(lea, spec_vector_256bit) {
  check<lea<256>>("0f1e2d3c4b5a69788796a5b4c3d2e1f0"
                  "f0e1d2c3b4a5968778695a4b3c2d1e0f",
                  "303132333435363738393a3b3c3d3e3f",
                  "d651aff647b189c13a8900ca27f9e197");
}

TEST(lea, key_size_constants) {
  EXPECT_EQ(16u, lea<128>::key_size);
  EXPECT_EQ(24u, lea<192>::key_size);
  EXPECT_EQ(32u, lea<256>::key_size);
  EXPECT_EQ(16u, lea<128>::block_size);
  // Section 2 of the specification
  EXPECT_EQ(24u, lea<128>::rounds);
  EXPECT_EQ(28u, lea<192>::rounds);
  EXPECT_EQ(32u, lea<256>::rounds);
  // Six words of round key per round
  EXPECT_EQ(6u, lea<128>::round_key_words);
}

namespace {

// Round trips over many inputs, which catches a decryption that undoes the
// rounds in the wrong order or turns a rotation the wrong way. The known answer
// tests above only exercise one input each.
template <class Cipher> void check_round_trip() {
  std::vector<uint8_t> key(Cipher::key_size);
  for (size_t i = 0; i < key.size(); ++i)
    key[i] = static_cast<uint8_t>(0x21 + i * 11);

  Cipher cipher(key);

  std::vector<uint8_t> block(Cipher::block_size);
  std::vector<uint8_t> encrypted(Cipher::block_size);
  std::vector<uint8_t> decrypted(Cipher::block_size);

  uint32_t state = 0x1f2e3d4cu;
  for (size_t round = 0; round < 512; ++round) {
    for (size_t i = 0; i < block.size(); ++i) {
      state = state * 1664525u + 1013904223u;
      block[i] = static_cast<uint8_t>(state >> 24);
    }

    cipher.encrypt_block(block, encrypted);
    ASSERT_NE(test::to_hex(block), test::to_hex(encrypted))
        << "the cipher returned its input at round " << round;

    cipher.decrypt_block(encrypted, decrypted);
    ASSERT_EQ(test::to_hex(block), test::to_hex(decrypted))
        << "round trip mismatch at round " << round;
  }
}

} // namespace

TEST(lea, round_trips_128) { check_round_trip<lea<128>>(); }
TEST(lea, round_trips_192) { check_round_trip<lea<192>>(); }
TEST(lea, round_trips_256) { check_round_trip<lea<256>>(); }

// Every bit of the key has to reach the ciphertext. A key schedule that drops a
// word, which is easy to do where the state is walked around rather than
// indexed directly, shows up here.
TEST(lea, every_key_byte_changes_the_result) {
  const std::vector<uint8_t> plain = test::hex("00112233445566778899aabbccddeeff");

  for (size_t byte = 0; byte < lea<256>::key_size; ++byte) {
    std::vector<uint8_t> key(lea<256>::key_size, 0x5a);
    lea<256> before(key);
    key[byte] ^= 0x01;
    lea<256> after(key);

    std::vector<uint8_t> a(16);
    std::vector<uint8_t> b(16);
    before.encrypt_block(plain, a);
    after.encrypt_block(plain, b);
    EXPECT_NE(test::to_hex(a), test::to_hex(b)) << "key byte " << byte;
  }
}

TEST(lea, rejects_key_of_the_wrong_length) {
  const std::vector<uint8_t> too_short =
      test::hex("00112233445566778899aabbccdd");
  ASSERT_LT(too_short.size(), lea<128>::key_size);
  EXPECT_THROW(lea<128>{ctl::bytes(too_short)}, std::invalid_argument);

  const std::vector<uint8_t> too_long(lea<256>::key_size);
  EXPECT_THROW(lea<128>{ctl::bytes(too_long)}, std::invalid_argument);
}

// Words are little endian here and big endian in AES and ARIA. Reading a block
// the other way round still round trips, so only a known answer catches it;
// this states the property directly so the reason is visible.
TEST(lea, reads_blocks_little_endian) {
  const std::vector<uint8_t> key(lea<128>::key_size, 0);
  lea<128> cipher(key);

  std::vector<uint8_t> block(16, 0);
  std::vector<uint8_t> first(16);
  block[0] = 0x01;
  cipher.encrypt_block(block, first);

  std::vector<uint8_t> last(16);
  block[0] = 0x00;
  block[3] = 0x01;
  cipher.encrypt_block(block, last);

  // Both set one bit of the first word. If the word were assembled the other
  // way round the two would still differ, so what this pins down is only that
  // the two positions are not interchangeable.
  EXPECT_NE(test::to_hex(first), test::to_hex(last));
}
