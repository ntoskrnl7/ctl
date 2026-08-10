/**
 * @file gcm.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief GCM mode verification
 *
 * The known answer vectors are the canonical GCM test cases published with the
 * mode by McGrew and Viega, which NIST SP 800-38D refers to.
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/mode/gcm>

#include "../vectors.h"

namespace {

using aes128 = ctl::symmetric::cipher::aes<128>;
using aes256 = ctl::symmetric::cipher::aes<256>;

namespace mode = ctl::symmetric::mode;

/**
 * @brief Verifies one known answer vector in both directions
 */
template <class Mode>
void check(const char *key_hex, const char *iv_hex, const char *aad_hex,
           const char *plain_hex, const char *cipher_hex,
           const char *tag_hex) {
  const std::vector<uint8_t> key = test::hex(key_hex);
  const std::vector<uint8_t> iv = test::hex(iv_hex);
  const std::vector<uint8_t> aad = test::hex(aad_hex);
  const std::vector<uint8_t> plain = test::hex(plain_hex);

  ASSERT_EQ(key.size(), Mode::key_size);

  Mode gcm(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  std::vector<uint8_t> tag(Mode::tag_size);
  ASSERT_TRUE(gcm.encrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                          {{plain.data(), plain.size()}}, encrypted.data(),
                          tag.data()));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));
  EXPECT_EQ(std::string(tag_hex), test::to_hex(tag));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(gcm.decrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                          {{encrypted.data(), encrypted.size()}},
                          decrypted.data(), tag.data()));
  EXPECT_EQ(std::string(plain_hex), test::to_hex(decrypted));
}

// The key, plaintext and AAD shared by test cases 3 through 6
const char *kKey128 = "feffe9928665731c6d6a8f9467308308";
const char *kKey256 = "feffe9928665731c6d6a8f9467308308"
                      "feffe9928665731c6d6a8f9467308308";
const char *kPlain64 = "d9313225f88406e5a55909c5aff5269a"
                       "86a7a9531534f7da2e4c303d8a318a72"
                       "1c3c0c95956809532fcf0e2449a6b525"
                       "b16aedf5aa0de657ba637b391aafd255";
const char *kPlain60 = "d9313225f88406e5a55909c5aff5269a"
                       "86a7a9531534f7da2e4c303d8a318a72"
                       "1c3c0c95956809532fcf0e2449a6b525"
                       "b16aedf5aa0de657ba637b39";
const char *kAad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const char *kIv96 = "cafebabefacedbaddecaf888";

} // namespace

TEST(gcm, case1_empty_plaintext_and_empty_aad) {
  check<mode::gcm<aes128>>("00000000000000000000000000000000",
                           "000000000000000000000000", "", "", "",
                           "58e2fccefa7e3061367f1d57a4e7455a");
}

TEST(gcm, case2_single_block_no_aad) {
  check<mode::gcm<aes128>>("00000000000000000000000000000000",
                           "000000000000000000000000", "",
                           "00000000000000000000000000000000",
                           "0388dace60b6a392f328c2b971b2fe78",
                           "ab6e47d42cec13bdf53a67b21257bddf");
}

TEST(gcm, case3_four_blocks_no_aad) {
  check<mode::gcm<aes128>>(kKey128, kIv96, "", kPlain64,
                           "42831ec2217774244b7221b784d0d49c"
                           "e3aa212f2c02a4e035c17e2329aca12e"
                           "21d514b25466931c7d8f6a5aac84aa05"
                           "1ba30b396a0aac973d58e091473f5985",
                           "4d5c2af327cd64a62cf35abd2ba6fab4");
}

TEST(gcm, case4_with_aad_and_partial_final_block) {
  check<mode::gcm<aes128>>(kKey128, kIv96, kAad, kPlain60,
                           "42831ec2217774244b7221b784d0d49c"
                           "e3aa212f2c02a4e035c17e2329aca12e"
                           "21d514b25466931c7d8f6a5aac84aa05"
                           "1ba30b396a0aac973d58e091",
                           "5bc94fbc3221a5db94fae95ae7121a47");
}

// A 64 bit initialization vector, which forces the initial counter to be
// derived through GHASH rather than taken from the vector directly.
TEST(gcm, case5_non_96_bit_iv) {
  check<mode::gcm<aes128>>(kKey128, "cafebabefacedbad", kAad, kPlain60,
                           "61353b4c2806934a777ff51fa22a4755"
                           "699b2a714fcdc6f83766e5f97b6c7423"
                           "73806900e49f24b22b097544d4896b42"
                           "4989b5e1ebac0f07c23f4598",
                           "3612d2e79e3b0785561be14aaca2fccb");
}

TEST(gcm, case15_aes256_no_aad) {
  check<mode::gcm<aes256>>(kKey256, kIv96, "", kPlain64,
                           "522dc1f099567d07f47f37a32a84427d"
                           "643a8cdcbfe5c0c97598a2bd2555d1aa"
                           "8cb08e48590dbb3da7b08b1056828838"
                           "c5f61e6393ba7a0abcc9f662898015ad",
                           "b094dac5d93471bdec1a502270e3cc6c");
}

TEST(gcm, case16_aes256_with_aad) {
  check<mode::gcm<aes256>>(kKey256, kIv96, kAad, kPlain60,
                           "522dc1f099567d07f47f37a32a84427d"
                           "643a8cdcbfe5c0c97598a2bd2555d1aa"
                           "8cb08e48590dbb3da7b08b1056828838"
                           "c5f61e6393ba7a0abcc9f662",
                           "76fc6ece0f4e1768cddf8853bb2d551b");
}

TEST(gcm, constants) {
  using gcm_t = mode::gcm<aes128>;
  EXPECT_EQ(16u, gcm_t::tag_size);
  EXPECT_EQ(16u, gcm_t::key_size);
  EXPECT_EQ(12u, gcm_t::recommended_iv_size);
  EXPECT_EQ(12u, mode::gcm<aes256>::recommended_iv_size);
  EXPECT_EQ(32u, mode::gcm<aes256>::key_size);
  // A truncated tag, which the specification permits
  EXPECT_EQ(12u, (mode::gcm<aes128, 96>::tag_size));
}

// The published vectors always hand over the whole plaintext at once, so they
// never exercise a piece boundary that is not a multiple of the block size.
// Splitting there has to leave both the ciphertext and the tag unchanged: the
// key stream has to carry on mid block, and GHASH has to buffer the remainder.
TEST(gcm, pieces_split_off_block_boundary_match_a_single_piece) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key.data(), key.size());

  std::vector<uint8_t> whole(plain.size());
  std::vector<uint8_t> whole_tag(16);
  ASSERT_TRUE(gcm.encrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                          {{plain.data(), plain.size()}}, whole.data(),
                          whole_tag.data()));

  // Boundaries deliberately chosen to fall inside blocks.
  for (size_t cut : {size_t(1), size_t(5), size_t(15), size_t(16), size_t(17),
                     size_t(31), size_t(59)}) {
    std::vector<uint8_t> split(plain.size());
    std::vector<uint8_t> split_tag(16);
    ASSERT_TRUE(gcm.encrypt(
        iv.data(), iv.size(),
        {{aad.data(), 3}, {aad.data() + 3, aad.size() - 3}},
        {{plain.data(), cut}, {plain.data() + cut, plain.size() - cut}},
        split.data(), split_tag.data()))
        << "cut = " << cut;
    EXPECT_EQ(test::to_hex(whole), test::to_hex(split)) << "cut = " << cut;
    EXPECT_EQ(test::to_hex(whole_tag), test::to_hex(split_tag))
        << "cut = " << cut;
  }
}

// GHASH consumes the concatenation of the AAD list, so where the list is split
// makes no difference but the order of the list does. This pins that down so
// nobody later "optimizes" the AAD handling into something order independent.
TEST(gcm, aad_order_changes_the_tag) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> first = test::hex("0011223344556677");
  const std::vector<uint8_t> second = test::hex("8899aabb");
  const std::vector<uint8_t> plain = test::hex("00112233445566778899aabbccddeeff");

  mode::gcm<aes128> gcm(key.data(), key.size());

  std::vector<uint8_t> out(plain.size());
  std::vector<uint8_t> forward(16);
  std::vector<uint8_t> reversed(16);

  ASSERT_TRUE(gcm.encrypt(iv.data(), iv.size(),
                          {{first.data(), first.size()},
                           {second.data(), second.size()}},
                          {{plain.data(), plain.size()}}, out.data(),
                          forward.data()));
  ASSERT_TRUE(gcm.encrypt(iv.data(), iv.size(),
                          {{second.data(), second.size()},
                           {first.data(), first.size()}},
                          {{plain.data(), plain.size()}}, out.data(),
                          reversed.data()));

  EXPECT_NE(test::to_hex(forward), test::to_hex(reversed));
}

TEST(gcm, tampered_tag_fails_and_erases_the_output) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                          {{plain.data(), plain.size()}}, encrypted.data(),
                          tag.data()));

  tag[0] ^= 0x01;

  std::vector<uint8_t> decrypted(plain.size(), 0xcc);
  const auto result =
      gcm.decrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                  {{encrypted.data(), encrypted.size()}}, decrypted.data(),
                  tag.data());
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::gcm<aes128>::authentication_failed, result.error().value);

  // Nothing usable may be left behind for a caller that ignores the error.
  EXPECT_EQ(std::string(plain.size() * 2, '0'), test::to_hex(decrypted));
}

TEST(gcm, tampered_aad_fails) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                          {{plain.data(), plain.size()}}, encrypted.data(),
                          tag.data()));

  aad[0] ^= 0x01;

  std::vector<uint8_t> decrypted(plain.size());
  const auto result =
      gcm.decrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                  {{encrypted.data(), encrypted.size()}}, decrypted.data(),
                  tag.data());
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::gcm<aes128>::authentication_failed, result.error().value);
}

TEST(gcm, works_in_place) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key.data(), key.size());

  std::vector<uint8_t> buffer = plain;
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                          {{buffer.data(), buffer.size()}}, buffer.data(),
                          tag.data()));
  EXPECT_EQ(std::string("42831ec2217774244b7221b784d0d49c"
                        "e3aa212f2c02a4e035c17e2329aca12e"
                        "21d514b25466931c7d8f6a5aac84aa05"
                        "1ba30b396a0aac973d58e091"),
            test::to_hex(buffer));

  ASSERT_TRUE(gcm.decrypt(iv.data(), iv.size(), {{aad.data(), aad.size()}},
                          {{buffer.data(), buffer.size()}}, buffer.data(),
                          tag.data()));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(buffer));
}

// Passing the tag pointer just past the ciphertext appends it, which is the
// layout a wire format usually wants. This is the property that made a separate
// tag argument the better choice.
TEST(gcm, tag_can_be_appended_to_the_output) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key.data(), key.size());

  std::vector<uint8_t> packet(plain.size() + mode::gcm<aes128>::tag_size);
  ASSERT_TRUE(gcm.encrypt(iv.data(), iv.size(), {},
                          {{plain.data(), plain.size()}}, packet.data(),
                          packet.data() + plain.size()));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(gcm.decrypt(iv.data(), iv.size(), {},
                          {{packet.data(), plain.size()}}, decrypted.data(),
                          packet.data() + plain.size()));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(decrypted));
}

TEST(gcm, rejects_empty_iv) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  mode::gcm<aes128> gcm(key.data(), key.size());

  uint8_t output[16] = {0};
  uint8_t tag[16] = {0};
  const uint8_t plain[16] = {0};
  const auto result =
      gcm.encrypt(nullptr, 0, {}, {{plain, sizeof(plain)}}, output, tag);
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::gcm<aes128>::invalid_iv_length, result.error().value);
}
