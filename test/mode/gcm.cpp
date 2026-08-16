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

#include <algorithm>
#include <type_traits>
#include <utility>

#include <ctl/bytes>
#include <ctl/detail/cpu>
#include <ctl/detail/ghash>
#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/cipher/lea>
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

  Mode gcm(key);

  std::vector<uint8_t> encrypted(plain.size());
  std::vector<uint8_t> tag(Mode::tag_size);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, encrypted, tag));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));
  EXPECT_EQ(std::string(tag_hex), test::to_hex(tag));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(gcm.decrypt(iv, {aad}, {encrypted}, decrypted, tag));
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

// The polynomial multiply, PCLMULQDQ on x86 and PMULL on ARM, is what makes
// GHASH quick. A path that is compiled in and never dispatched to passes every
// vector above, because the bit at a time path answers for it correctly, so
// this is the only test that would notice. It exists because exactly that
// happened once already, to the vector path of LEA.
TEST(gcm, the_polynomial_multiply_is_actually_reached) {
  const std::vector<uint8_t> subkey(16, 0x42);
  ctl::detail::ghash hash;
  hash.set_key(subkey.data());

#if defined(CTL_HAS_X86_HW_ACCEL)
  EXPECT_EQ(ctl::detail::cpu::has_carryless_multiply() &&
                ctl::detail::cpu::has_byte_shuffle(),
            hash.accelerated());
#elif defined(CTL_HAS_ARM_HW_ACCEL)
  EXPECT_EQ(ctl::detail::cpu::has_arm_polynomial_multiply(),
            hash.accelerated());
#else
  EXPECT_FALSE(hash.accelerated());
#endif
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

  mode::gcm<aes128> gcm(key);

  std::vector<uint8_t> whole(plain.size());
  std::vector<uint8_t> whole_tag(16);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, whole, whole_tag));

  // Boundaries deliberately chosen to fall inside blocks.
  for (size_t cut : {size_t(1), size_t(5), size_t(15), size_t(16), size_t(17),
                     size_t(31), size_t(59)}) {
    std::vector<uint8_t> split(plain.size());
    std::vector<uint8_t> split_tag(16);
    ASSERT_TRUE(gcm.encrypt(
        iv,
        {ctl::bytes(aad).first(3), ctl::bytes(aad).last(aad.size() - 3)},
        {ctl::bytes(plain).first(cut),
         ctl::bytes(plain).last(plain.size() - cut)},
        split, split_tag))
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
  const std::vector<uint8_t> plain =
      test::hex("00112233445566778899aabbccddeeff");

  mode::gcm<aes128> gcm(key);

  std::vector<uint8_t> out(plain.size());
  std::vector<uint8_t> forward(16);
  std::vector<uint8_t> reversed(16);

  ASSERT_TRUE(gcm.encrypt(iv, {first, second}, {plain}, out, forward));
  ASSERT_TRUE(gcm.encrypt(iv, {second, first}, {plain}, out, reversed));

  EXPECT_NE(test::to_hex(forward), test::to_hex(reversed));
}

TEST(gcm, tampered_tag_fails_and_erases_the_output) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key);

  std::vector<uint8_t> encrypted(plain.size());
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, encrypted, tag));

  tag[0] ^= 0x01;

  std::vector<uint8_t> decrypted(plain.size(), 0xcc);
  const auto result = gcm.decrypt(iv, {aad}, {encrypted}, decrypted, tag);
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

  mode::gcm<aes128> gcm(key);

  std::vector<uint8_t> encrypted(plain.size());
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, encrypted, tag));

  aad[0] ^= 0x01;

  std::vector<uint8_t> decrypted(plain.size());
  const auto result = gcm.decrypt(iv, {aad}, {encrypted}, decrypted, tag);
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::gcm<aes128>::authentication_failed, result.error().value);
}

TEST(gcm, works_in_place) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key);

  std::vector<uint8_t> buffer = plain;
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {buffer}, buffer, tag));
  EXPECT_EQ(std::string("42831ec2217774244b7221b784d0d49c"
                        "e3aa212f2c02a4e035c17e2329aca12e"
                        "21d514b25466931c7d8f6a5aac84aa05"
                        "1ba30b396a0aac973d58e091"),
            test::to_hex(buffer));

  ASSERT_TRUE(gcm.decrypt(iv, {aad}, {buffer}, buffer, tag));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(buffer));
}

// In-place operation still has to work when the input is described by several
// pieces. Each piece begins exactly where its own result is written.
TEST(gcm, works_in_place_across_piece_boundaries) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key);
  std::vector<uint8_t> buffer = plain;
  std::vector<uint8_t> tag(16);

  const ctl::bytes plain_view(buffer);
  ASSERT_TRUE(gcm.encrypt(
      iv, {aad},
      {plain_view.first(7), plain_view.subview(7, 20),
       plain_view.last(plain.size() - 27)},
      buffer, tag));

  const ctl::bytes cipher_view(buffer);
  ASSERT_TRUE(gcm.decrypt(
      iv, {aad},
      {cipher_view.first(7), cipher_view.subview(7, 20),
       cipher_view.last(buffer.size() - 27)},
      buffer, tag));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(buffer));
}

// A forward loop cannot implement memmove semantics: when output begins one
// byte into input it overwrites a byte that has not been read yet. The opposite
// direction happens to work for that loop, but accepting only one direction
// would be a fragile contract, so every partial overlap is refused.
TEST(gcm, refuses_partially_overlapping_single_call_buffers) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);
  mode::gcm<aes128> gcm(key);
  std::vector<uint8_t> tag(16);

  std::vector<uint8_t> shifted(plain.size() + 1);
  std::copy(plain.begin(), plain.end(), shifted.begin());
  const std::vector<uint8_t> before = shifted;
  EXPECT_THROW(
      (void)gcm.encrypt(
          iv, {aad}, {ctl::bytes(shifted).first(plain.size())},
          ctl::writable_bytes(shifted).subview(1, plain.size()), tag),
      std::invalid_argument);
  EXPECT_EQ(before, shifted);

  std::fill(shifted.begin(), shifted.end(), 0);
  std::copy(plain.begin(), plain.end(), shifted.begin() + 1);
  EXPECT_THROW(
      (void)gcm.encrypt(
          iv, {aad}, {ctl::bytes(shifted).subview(1, plain.size())},
          ctl::writable_bytes(shifted).first(plain.size()), tag),
      std::invalid_argument);

  std::vector<uint8_t> cipher(plain.size());
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, cipher, tag));
  std::copy(cipher.begin(), cipher.end(), shifted.begin());
  EXPECT_THROW(
      (void)gcm.decrypt(
          iv, {aad}, {ctl::bytes(shifted).first(cipher.size())},
          ctl::writable_bytes(shifted).subview(1, cipher.size()), tag),
      std::invalid_argument);
}

// Naming the last tag_size bytes of one buffer as the tag appends it to the
// ciphertext, which is the layout a wire format usually wants. This is the
// property that made a separate tag argument the better choice.
TEST(gcm, tag_can_be_appended_to_the_output) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key);

  const size_t tag_size = mode::gcm<aes128>::tag_size;
  std::vector<uint8_t> packet(plain.size() + tag_size);
  ASSERT_TRUE(gcm.encrypt(iv, {}, {plain},
                          ctl::writable_bytes(packet).first(plain.size()),
                          ctl::writable_bytes(packet).last(tag_size)));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(gcm.decrypt(iv, {}, {ctl::bytes(packet).first(plain.size())},
                          decrypted, ctl::bytes(packet).last(tag_size)));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(decrypted));
}

namespace {

using gcm128 = mode::gcm<aes128>;

// Detects whether a phase type accepts additional authenticated data. Used to
// check by compilation that the data phase does not, which is the whole point of
// giving the two phases different types.
template <class T, class = void> struct accepts_aad : std::false_type {};

template <class T>
struct accepts_aad<T, decltype(void(std::declval<T &>().aad(
                          std::declval<gcm128::piece>())))>
    : std::true_type {};

} // namespace

static_assert(accepts_aad<gcm128::encrypt_aad>::value,
              "the AAD phase has to accept AAD");
static_assert(!accepts_aad<gcm128::encrypt_data>::value,
              "the data phase must not accept AAD, since the specification "
              "requires all of it to be hashed before any ciphertext");
static_assert(accepts_aad<gcm128::decrypt_aad>::value,
              "the AAD phase has to accept AAD");
static_assert(!accepts_aad<gcm128::decrypt_data>::value,
              "the data phase must not accept AAD");

// Feeding the same input through the incremental interface in several pieces has
// to give exactly what the single call gives.
TEST(gcm, builder_matches_the_single_call) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  gcm128 gcm(key);

  std::vector<uint8_t> once(plain.size());
  std::vector<uint8_t> once_tag(16);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, once, once_tag));

  std::vector<uint8_t> streamed(plain.size());
  std::vector<uint8_t> streamed_tag(16);
  {
    const ctl::bytes aad_view(aad);
    const ctl::bytes plain_view(plain);
    const ctl::writable_bytes out(streamed);

    auto writer = gcm.encryptor(iv)
                      .aad(aad_view.first(4))
                      .aad(aad_view.last(aad.size() - 4))
                      .data();
    // Deliberately uneven runs so the key stream has to carry on mid block.
    writer.write(plain_view.subview(0, 7), out.subview(0, 7))
        .write(plain_view.subview(7, 20), out.subview(7, 20))
        .write(plain_view.subview(27, plain.size() - 27),
               out.subview(27, plain.size() - 27));
    writer.finish(streamed_tag);
  }

  EXPECT_EQ(test::to_hex(once), test::to_hex(streamed));
  EXPECT_EQ(test::to_hex(once_tag), test::to_hex(streamed_tag));
}

// The writer can hold the output buffer and keep its own place in it, which is
// what removes the running offset the caller would otherwise have to advance by
// hand next to every write. It has to agree with doing that by hand.
TEST(gcm, a_writer_that_holds_its_buffer_matches_one_that_does_not) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  gcm128 gcm(key);

  std::vector<uint8_t> by_hand(plain.size());
  std::vector<uint8_t> by_hand_tag(16);
  {
    const ctl::bytes source(plain);
    const ctl::writable_bytes out(by_hand);
    auto writer = gcm.encryptor(iv).aad(aad).data();
    size_t written = 0;
    for (size_t run : {size_t(7), size_t(20), size_t(33)}) {
      writer.write(source.subview(written, run), out.subview(written, run));
      written += run;
    }
    writer.finish(by_hand_tag);
  }

  std::vector<uint8_t> held(plain.size());
  std::vector<uint8_t> held_tag(16);
  {
    auto writer = gcm.encryptor(iv).aad(aad).data(held);
    size_t at = 0;
    for (size_t run : {size_t(7), size_t(20), size_t(33)}) {
      writer.write(ctl::bytes(plain).subview(at, run));
      at += run;
    }
    EXPECT_EQ(plain.size(), writer.written());
    writer.finish(held_tag);
  }

  EXPECT_EQ(test::to_hex(by_hand), test::to_hex(held));
  EXPECT_EQ(test::to_hex(by_hand_tag), test::to_hex(held_tag));
}

TEST(gcm, a_writer_that_holds_its_buffer_refuses_to_overrun_it) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  gcm128 gcm(key);

  std::vector<uint8_t> small(20);
  auto writer = gcm.encryptor(iv).data(small);
  writer.write(ctl::bytes(plain).first(16));
  EXPECT_THROW(writer.write(ctl::bytes(plain).subview(16, 16)),
               std::invalid_argument);
}

// A rejected run must not advance either the key stream or the output cursor,
// so the caller can correct the buffer selection and retry.
TEST(gcm, incremental_writers_refuse_partial_overlap_before_advancing) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> plain = test::hex(kPlain60);
  gcm128 gcm(key);

  std::vector<uint8_t> shifted(plain.size() + 1);
  std::copy(plain.begin(), plain.end(), shifted.begin());
  std::vector<uint8_t> cipher(plain.size());
  std::vector<uint8_t> tag(16);
  auto writer = gcm.encryptor(iv).data();
  EXPECT_THROW(
      writer.write(ctl::bytes(shifted).first(plain.size()),
                   ctl::writable_bytes(shifted).subview(1, plain.size())),
      std::invalid_argument);
  writer.write(plain, cipher).finish(tag);

  std::copy(cipher.begin(), cipher.end(), shifted.begin());
  std::vector<uint8_t> recovered(plain.size());
  auto reader = gcm.decryptor(iv).data();
  EXPECT_THROW(
      reader.write(ctl::bytes(shifted).first(cipher.size()),
                   ctl::writable_bytes(shifted).subview(1, cipher.size())),
      std::invalid_argument);
  reader.write(cipher, recovered);
  ASSERT_TRUE(reader.finish(tag));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(recovered));
}

// A holding writer may read from its output only at the exact position it is
// about to write. That permits chunked in-place operation without accepting a
// shifted range elsewhere in the buffer.
TEST(gcm, holding_writers_allow_only_the_current_in_place_position) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> plain = test::hex(kPlain60);
  gcm128 gcm(key);

  std::vector<uint8_t> buffer = plain;
  std::vector<uint8_t> tag(16);
  auto writer = gcm.encryptor(iv).data(buffer);
  EXPECT_THROW(writer.write(ctl::bytes(buffer).subview(1, 7)),
               std::invalid_argument);
  EXPECT_EQ(0u, writer.written());
  writer.write(ctl::bytes(buffer).first(7));
  writer.write(ctl::bytes(buffer).last(buffer.size() - 7));
  writer.finish(tag);

  auto reader = gcm.decryptor(iv).data(buffer);
  EXPECT_THROW(reader.write(ctl::bytes(buffer).subview(1, 7)),
               std::invalid_argument);
  EXPECT_EQ(0u, reader.written());
  reader.write(ctl::bytes(buffer).first(7));
  reader.write(ctl::bytes(buffer).last(buffer.size() - 7));
  ASSERT_TRUE(reader.finish(tag));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(buffer));
}

TEST(gcm, a_holding_writer_decrypts_and_verifies) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  gcm128 gcm(key);

  std::vector<uint8_t> cipher(plain.size());
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, cipher, tag));

  std::vector<uint8_t> recovered(plain.size());
  auto reader = gcm.decryptor(iv).aad(aad).data(recovered);
  reader.write(ctl::bytes(cipher).first(13));
  reader.write(ctl::bytes(cipher).last(cipher.size() - 13));
  ASSERT_TRUE(reader.finish(tag));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(recovered));
}

TEST(gcm, builder_reproduces_the_official_vector) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  gcm128 gcm(key);

  std::vector<uint8_t> out(plain.size());
  std::vector<uint8_t> tag(16);
  auto writer = gcm.encryptor(iv).aad(aad).data();
  for (size_t offset = 0; offset < plain.size(); offset += 9) {
    const size_t run =
        (plain.size() - offset) < 9 ? (plain.size() - offset) : 9;
    writer.write(ctl::bytes(plain).subview(offset, run),
                 ctl::writable_bytes(out).subview(offset, run));
  }
  writer.finish(tag);

  EXPECT_EQ(std::string("42831ec2217774244b7221b784d0d49c"
                        "e3aa212f2c02a4e035c17e2329aca12e"
                        "21d514b25466931c7d8f6a5aac84aa05"
                        "1ba30b396a0aac973d58e091"),
            test::to_hex(out));
  EXPECT_EQ(std::string("5bc94fbc3221a5db94fae95ae7121a47"), test::to_hex(tag));
}

// Finishing straight from the AAD phase authenticates without encrypting, which
// is GMAC.
TEST(gcm, builder_authenticates_aad_only_as_gmac) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> message = test::hex(kPlain60);

  gcm128 gcm(key);

  std::vector<uint8_t> tag(16);
  gcm.encryptor(iv).aad(message).finish(tag);

  // The single call interface has to agree, with the message as AAD and no data.
  std::vector<uint8_t> expected(16);
  ASSERT_TRUE(
      gcm.encrypt(iv, {message}, {}, ctl::writable_bytes(), expected));
  EXPECT_EQ(test::to_hex(expected), test::to_hex(tag));

  EXPECT_TRUE(gcm.decryptor(iv).aad(message).finish(tag));
}

TEST(gcm, builder_decrypts_and_verifies) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  gcm128 gcm(key);

  std::vector<uint8_t> cipher(plain.size());
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, cipher, tag));

  std::vector<uint8_t> recovered(plain.size());
  const ctl::bytes cipher_view(cipher);
  const ctl::writable_bytes out(recovered);

  auto reader = gcm.decryptor(iv).aad(aad).data();
  reader.write(cipher_view.first(13), out.first(13))
      .write(cipher_view.last(cipher.size() - 13),
             out.last(cipher.size() - 13));
  ASSERT_TRUE(reader.finish(tag));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(recovered));
}

TEST(gcm, builder_decrypt_reports_a_bad_tag) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  gcm128 gcm(key);

  std::vector<uint8_t> cipher(plain.size());
  std::vector<uint8_t> tag(16);
  ASSERT_TRUE(gcm.encrypt(iv, {}, {plain}, cipher, tag));
  tag[15] ^= 0x80;

  std::vector<uint8_t> recovered(plain.size());
  auto reader = gcm.decryptor(iv).data();
  reader.write(cipher, recovered);
  const auto result = reader.finish(tag);
  ASSERT_FALSE(result);
  EXPECT_EQ(gcm128::authentication_failed, result.error().value);
  // Note that recovered still holds plaintext here. The incremental interface
  // cannot reach the caller's buffers, which is why its documentation puts the
  // obligation to discard on the caller.
}

TEST(gcm, builder_rejects_empty_iv) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  gcm128 gcm(key);
  EXPECT_THROW(gcm.encryptor(ctl::bytes()), std::invalid_argument);
  EXPECT_THROW(gcm.decryptor(ctl::bytes()), std::invalid_argument);
}

TEST(gcm, rejects_empty_iv) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  mode::gcm<aes128> gcm(key);

  uint8_t output[16] = {0};
  uint8_t tag[16] = {0};
  const uint8_t plain[16] = {0};
  const auto result =
      gcm.encrypt(ctl::bytes(), {}, {plain}, output, tag);
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::gcm<aes128>::invalid_iv_length, result.error().value);
}

// GCM needs a 128 bit block and nothing else from its cipher, so LEA composes
// with it the same way AES does. There are no published vectors for that pair,
// so what is checked is that it round trips and that a tampered tag is caught.
TEST(gcm, composes_with_lea) {
  using lea128 = ctl::symmetric::cipher::lea<128>;

  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> aad = test::hex(kAad);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<lea128> gcm(key);

  std::vector<uint8_t> encrypted(plain.size());
  std::vector<uint8_t> tag(mode::gcm<lea128>::tag_size);
  ASSERT_TRUE(gcm.encrypt(iv, {aad}, {plain}, encrypted, tag));
  EXPECT_NE(test::to_hex(plain), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(gcm.decrypt(iv, {aad}, {encrypted}, decrypted, tag));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(decrypted));

  tag[0] ^= 0x01;
  std::vector<uint8_t> rejected(plain.size());
  const auto result = gcm.decrypt(iv, {aad}, {encrypted}, rejected, tag);
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::gcm<lea128>::authentication_failed, result.error().value);
}

// A tag is fixed length, so a buffer of the wrong length is refused instead of
// being written past its end or compared over the wrong range.
TEST(gcm, rejects_a_tag_buffer_of_the_wrong_length) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> plain = test::hex(kPlain60);
  std::vector<uint8_t> out(plain.size());

  mode::gcm<aes128> gcm(key);

  std::vector<uint8_t> short_tag(mode::gcm<aes128>::tag_size - 1);
  EXPECT_THROW((void)gcm.encrypt(iv, {}, {plain}, out, short_tag),
               std::invalid_argument);

  // A tag sized for the full 128 bits handed to a mode configured for 96 is
  // the mistake a separate length argument could never catch.
  mode::gcm<aes128, 96> truncated(key);
  std::vector<uint8_t> wide_tag(16);
  EXPECT_THROW((void)truncated.encrypt(iv, {}, {plain}, out, wide_tag),
               std::invalid_argument);
}

// The output buffer carries its own length, so a ciphertext that does not fit
// is reported rather than written past the end of the buffer.
TEST(gcm, rejects_an_output_buffer_that_is_too_small) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);
  const std::vector<uint8_t> plain = test::hex(kPlain60);

  mode::gcm<aes128> gcm(key);

  std::vector<uint8_t> too_small(plain.size() - 1);
  std::vector<uint8_t> tag(16);
  EXPECT_THROW((void)gcm.encrypt(iv, {}, {plain}, too_small, tag),
               std::invalid_argument);

  // The same holds for the incremental interface, where the output of each run
  // is a separate buffer.
  std::vector<uint8_t> run(4);
  auto writer = gcm.encryptor(iv).data();
  EXPECT_THROW(writer.write(ctl::bytes(plain).first(8), run),
               std::invalid_argument);
}

// The counter of GCM is only the last four bytes of the block, so an invocation
// that runs past the limit in the specification repeats its key stream. The
// single call interface sees the whole length up front and reports this through
// its result; the incremental interface only learns the length as the data
// arrives, and used to accumulate without a limit at all.
//
// The limit is about 64 GiB, so this describes a run of that length rather than
// allocating one. The guard runs before anything is read, which is what makes
// that possible.
TEST(gcm, refuses_to_run_past_what_one_key_stream_covers) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> iv = test::hex(kIv96);

  mode::gcm<aes128> gcm(key);

  if constexpr (sizeof(size_t) >= 8) {
    const size_t past =
        static_cast<size_t>(mode::gcm<aes128>::max_data_size) + 1;
    const ctl::bytes nothing(nullptr, past);
    const ctl::writable_bytes nowhere(nullptr, past);

    auto writer = gcm.encryptor(iv).data();
    EXPECT_THROW(writer.write(nothing, nowhere), std::length_error);

    auto reader = gcm.decryptor(iv).data();
    EXPECT_THROW(reader.write(nothing, nowhere), std::length_error);

    // The single call interface reports the same thing through its result.
    std::vector<uint8_t> tag(16);
    const auto result = gcm.encrypt(iv, {}, {nothing}, nowhere, tag);
    ASSERT_FALSE(result);
    EXPECT_EQ(mode::gcm<aes128>::invalid_input_length, result.error().value);
  }
}

// A writer holds the cipher and the prepared hash of the gcm it came from, so
// making one from a temporary would leave it pointing at a destroyed object.
// That is refused at compile time rather than documented.
namespace {

template <class T, class = void>
struct encryptor_on_temporary : std::false_type {};

template <class T>
struct encryptor_on_temporary<
    T, decltype(void(std::declval<T>().encryptor(std::declval<ctl::bytes>())))>
    : std::true_type {};

} // namespace

static_assert(encryptor_on_temporary<mode::gcm<aes128> &>::value,
              "a named gcm has to hand out a writer");
static_assert(!encryptor_on_temporary<mode::gcm<aes128>>::value,
              "a temporary gcm must not, since the writer outlives it");
