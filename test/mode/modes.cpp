/**
 * @file modes.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief Mode of operation verification (NIST SP 800-38A, NIST CAVP XTS)
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <ctl/bytes>
#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/cipher/aria>
#include <ctl/symmetric/mode/cbc>
#include <ctl/symmetric/mode/ctr>
#include <ctl/symmetric/mode/ecb>
#include <ctl/symmetric/mode/xts>

#include "../vectors.h"

namespace {

using aes128 = ctl::symmetric::cipher::aes<128>;
using aes192 = ctl::symmetric::cipher::aes<192>;
using aes256 = ctl::symmetric::cipher::aes<256>;
using aria128 = ctl::symmetric::cipher::aria<128>;

namespace mode = ctl::symmetric::mode;

// Appendix F of SP 800-38A uses one plaintext and one key per size throughout,
// and the same IV for CBC and the same initial counter for CTR.
const char *kKey128 = "2b7e151628aed2a6abf7158809cf4f3c";
const char *kKey192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const char *kKey256 = "603deb1015ca71be2b73aef0857d7781"
                      "1f352c073b6108d72d9810a30914dff4";

const char *kPlaintext = "6bc1bee22e409f96e93d7e117393172a"
                         "ae2d8a571e03ac9c9eb76fac45af8e51"
                         "30c81c46a35ce411e5fbc1191a0a52ef"
                         "f69f2445df4f9b17ad2b417be66c3710";

const char *kIv = "000102030405060708090a0b0c0d0e0f";
const char *kInitialCounter = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/**
 * @brief Verifies ECB in both directions, and that it works in place
 */
template <class Cipher>
void check_ecb(const char *key_hex, const char *cipher_hex) {
  const std::vector<uint8_t> key = test::hex(key_hex);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  ASSERT_EQ(key.size(), Cipher::key_size);

  mode::ecb<Cipher> ecb(key);

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(ecb.encrypt(plain, encrypted));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(ecb.decrypt(encrypted, decrypted));
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(decrypted));

  std::vector<uint8_t> buffer = plain;
  ASSERT_TRUE(ecb.encrypt(buffer, buffer));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(buffer));
  ASSERT_TRUE(ecb.decrypt(buffer, buffer));
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(buffer));
}

/**
 * @brief Verifies CBC in both directions, and that it works in place
 *
 * In place matters more here than elsewhere: encryption feeds each ciphertext
 * block into the next, and decryption has to keep the input block before
 * overwriting it.
 */
template <class Cipher>
void check_cbc(const char *key_hex, const char *cipher_hex) {
  const std::vector<uint8_t> key = test::hex(key_hex);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  const std::vector<uint8_t> iv = test::hex(kIv);
  ASSERT_EQ(key.size(), Cipher::key_size);
  ASSERT_EQ(iv.size(), mode::cbc<Cipher>::iv_size);

  mode::cbc<Cipher> cbc(key);

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(cbc.encrypt(iv, plain, encrypted));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(cbc.decrypt(iv, encrypted, decrypted));
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(decrypted));

  std::vector<uint8_t> buffer = plain;
  ASSERT_TRUE(cbc.encrypt(iv, buffer, buffer));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(buffer));
  ASSERT_TRUE(cbc.decrypt(iv, buffer, buffer));
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(buffer));
}

/**
 * @brief Verifies CTR, which runs the same operation in both directions
 */
template <class Cipher>
void check_ctr(const char *key_hex, const char *cipher_hex) {
  const std::vector<uint8_t> key = test::hex(key_hex);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  const std::vector<uint8_t> nonce = test::hex(kInitialCounter);
  ASSERT_EQ(key.size(), Cipher::key_size);
  ASSERT_EQ(nonce.size(), mode::ctr<Cipher>::nonce_size);

  mode::ctr<Cipher> ctr(key);

  std::vector<uint8_t> encrypted(plain.size());
  ctr.crypt(nonce, 0, plain, encrypted);
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ctr.crypt(nonce, 0, encrypted, decrypted);
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(decrypted));

  std::vector<uint8_t> buffer = plain;
  ctr.crypt(nonce, 0, buffer, buffer);
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(buffer));
}

/**
 * @brief Verifies one XTS vector given in the form that supplies the tweak
 * directly
 */
template <class Mode>
void check_xts(const char *key_hex, const char *tweak_hex,
               const char *plain_hex, const char *cipher_hex) {
  const std::vector<uint8_t> key = test::hex(key_hex);
  const std::vector<uint8_t> tweak = test::hex(tweak_hex);
  const std::vector<uint8_t> plain = test::hex(plain_hex);

  ASSERT_EQ(key.size(), Mode::key_size);
  ASSERT_EQ(tweak.size(), Mode::tweak_size);

  Mode mode(key);

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(mode.encrypt(tweak, plain, encrypted));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(mode.decrypt(tweak, encrypted, decrypted));
  EXPECT_EQ(std::string(plain_hex), test::to_hex(decrypted));

  // Operating in place. Ciphertext stealing crosses over the last two blocks,
  // so getting the order of the reads and writes wrong shows up here.
  std::vector<uint8_t> inplace = plain;
  ASSERT_TRUE(mode.encrypt(tweak, inplace, inplace));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(inplace));
}

} // namespace

// ---------------------------------------------------------------- ECB

TEST(ecb, sp800_38a_f11_aes128) {
  check_ecb<aes128>(kKey128, "3ad77bb40d7a3660a89ecaf32466ef97"
                             "f5d3d58503b9699de785895a96fdbaaf"
                             "43b1cd7f598ece23881b00e3ed030688"
                             "7b0c785e27e8ad3f8223207104725dd4");
}

TEST(ecb, sp800_38a_f13_aes192) {
  check_ecb<aes192>(kKey192, "bd334f1d6e45f25ff712a214571fa5cc"
                             "974104846d0ad3ad7734ecb3ecee4eef"
                             "ef7afd2270e2e60adce0ba2face6444e"
                             "9a4b41ba738d6c72fb16691603c18e0e");
}

TEST(ecb, sp800_38a_f15_aes256) {
  check_ecb<aes256>(kKey256, "f3eed1bdb5d2a03c064b5a7e3db181f8"
                             "591ccb10d410ed26dc5ba74a31362870"
                             "b6ed21b99ca6f4f9f153e7b1beafed1d"
                             "23304b7a39f9f3ff067d8d8f9e24ecc7");
}

TEST(ecb, rejects_non_block_multiple_length) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  mode::ecb<aes128> ecb(key);

  std::vector<uint8_t> output(plain.size());
  const auto result = ecb.encrypt(ctl::bytes(plain).first(plain.size() - 1),
                                  output);
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::ecb<aes128>::invalid_input_length, result.error().value);

  const auto decrypted = ecb.decrypt(ctl::bytes(plain).first(plain.size() - 1),
                                     output);
  ASSERT_FALSE(decrypted);
  EXPECT_EQ(mode::ecb<aes128>::invalid_input_length, decrypted.error().value);
}

TEST(ecb, accepts_empty_input) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  mode::ecb<aes128> ecb(key);
  EXPECT_TRUE(ecb.encrypt(ctl::bytes(), ctl::writable_bytes()));
  EXPECT_TRUE(ecb.decrypt(ctl::bytes(), ctl::writable_bytes()));
}

// ---------------------------------------------------------------- CBC

TEST(cbc, sp800_38a_f21_aes128) {
  check_cbc<aes128>(kKey128, "7649abac8119b246cee98e9b12e9197d"
                             "5086cb9b507219ee95db113a917678b2"
                             "73bed6b8e3c1743b7116e69e22229516"
                             "3ff1caa1681fac09120eca307586e1a7");
}

TEST(cbc, sp800_38a_f23_aes192) {
  check_cbc<aes192>(kKey192, "4f021db243bc633d7178183a9fa071e8"
                             "b4d9ada9ad7dedf4e5e738763f69145a"
                             "571b242012fb7ae07fa9baac3df102e0"
                             "08b0e27988598881d920a9e64f5615cd");
}

TEST(cbc, sp800_38a_f25_aes256) {
  check_cbc<aes256>(kKey256, "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                             "9cfc4e967edb808d679f777bc6702c7d"
                             "39f23369a9d9bacfa530e26304231461"
                             "b2eb05e2c39be9fcda6c19078c6a9d1b");
}

TEST(cbc, rejects_non_block_multiple_length) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  mode::cbc<aes128>::iv_t iv = {0};
  mode::cbc<aes128> cbc(key);

  std::vector<uint8_t> output(plain.size());
  const auto result =
      cbc.encrypt(iv, ctl::bytes(plain).first(plain.size() - 1), output);
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::cbc<aes128>::invalid_input_length, result.error().value);

  const auto decrypted =
      cbc.decrypt(iv, ctl::bytes(plain).first(plain.size() - 1), output);
  ASSERT_FALSE(decrypted);
  EXPECT_EQ(mode::cbc<aes128>::invalid_input_length, decrypted.error().value);
}

// A different IV has to give different ciphertext, otherwise the IV is not
// reaching the first block at all.
TEST(cbc, the_iv_reaches_the_first_block) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  mode::cbc<aes128> cbc(key);

  mode::cbc<aes128>::iv_t first = {0};
  mode::cbc<aes128>::iv_t second = {0};
  second[0] = 0x01;

  std::vector<uint8_t> a(plain.size());
  std::vector<uint8_t> b(plain.size());
  ASSERT_TRUE(cbc.encrypt(first, plain, a));
  ASSERT_TRUE(cbc.encrypt(second, plain, b));
  EXPECT_NE(test::to_hex(a), test::to_hex(b));
}

// ---------------------------------------------------------------- CTR

TEST(ctr, sp800_38a_f51_aes128) {
  check_ctr<aes128>(kKey128, "874d6191b620e3261bef6864990db6ce"
                             "9806f66b7970fdff8617187bb9fffdff"
                             "5ae4df3edbd5d35e5b4f09020db03eab"
                             "1e031dda2fbe03d1792170a0f3009cee");
}

TEST(ctr, sp800_38a_f53_aes192) {
  check_ctr<aes192>(kKey192, "1abc932417521ca24f2b0459fe7e6e0b"
                             "090339ec0aa6faefd5ccc2c6f4ce8e94"
                             "1e36b26bd1ebc670d1bd1d665620abf7"
                             "4f78a7f6d29809585a97daec58c6b050");
}

TEST(ctr, sp800_38a_f55_aes256) {
  check_ctr<aes256>(kKey256, "601ec313775789a5b7a7f504bbf3d228"
                             "f443e3ca4d62b59aca84e990cacaf5c5"
                             "2b0930daa23de94ce87017ba2d84988d"
                             "dfc9c58db67aada613c2dd08457941a6");
}

// The initial counter of these vectors is ...fcfdfeff, so on the second block
// the carry crosses a byte boundary into ...fcfdff00. Starting partway through
// with an offset has to give the same result as processing the whole buffer,
// which is only the case when the carry propagates correctly.
TEST(ctr, random_access_matches_sequential) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  const std::vector<uint8_t> nonce = test::hex(kInitialCounter);

  mode::ctr<aes128> ctr(key);

  std::vector<uint8_t> whole(plain.size());
  ctr.crypt(nonce, 0, plain, whole);

  // Checked at offsets that do not line up with a block boundary.
  for (size_t offset : {size_t(1), size_t(15), size_t(16), size_t(17),
                        size_t(31), size_t(48), size_t(63)}) {
    std::vector<uint8_t> partial(plain.size() - offset);
    ctr.crypt(nonce, offset, ctl::bytes(plain).last(partial.size()), partial);
    EXPECT_EQ(test::to_hex(whole.data() + offset, partial.size()),
              test::to_hex(partial))
        << "offset = " << offset;
  }
}

// CTR puts no constraint on the length, so a run that stops inside a block has
// to give the same bytes the full run gives.
TEST(ctr, partial_lengths_match_a_truncated_run) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  const std::vector<uint8_t> nonce = test::hex(kInitialCounter);

  mode::ctr<aes128> ctr(key);

  std::vector<uint8_t> whole(plain.size());
  ctr.crypt(nonce, 0, plain, whole);

  for (size_t length : {size_t(0), size_t(1), size_t(15), size_t(16),
                        size_t(17), size_t(33), size_t(63)}) {
    std::vector<uint8_t> partial(length);
    ctr.crypt(nonce, 0, ctl::bytes(plain).first(length), partial);
    EXPECT_EQ(test::to_hex(whole.data(), length), test::to_hex(partial))
        << "length = " << length;
  }
}

// ---------------------------------------------------------------- XTS

TEST(xts, cavp_aes128_one_block) {
  check_xts<mode::xts<aes128>>("a1b90cba3f06ac353b2c343876081762"
                               "090923026e91771815f29dab01932f2f",
                               "4faef7117cda59c66e4b92013e768ad5",
                               "ebabce95b14d3c8d6fb350390790311c",
                               "778ae8b43cb98d5a825081d5be471c63");
}

TEST(xts, cavp_aes128_two_blocks) {
  check_xts<mode::xts<aes128>>(
      "b7b93f516aef295eff3a29d837cf1f13"
      "5347e8a21dae616ff5062b2e8d78ce5e",
      "873edea653b643bd8bcf51403197ed14",
      "236f8a5b58dd55f6194ed70c4ac1a17f1fe60ec9a6c454d087ccb77d6b638c47",
      "22e6a3c6379dcf7599b052b5a749c7f78ad8a11b9f1aa9430cf3aef445682e19");
}

// 25 bytes is one block plus nine bytes, which goes through the ciphertext
// stealing path.
TEST(xts, cavp_aes128_ciphertext_stealing) {
  check_xts<mode::xts<aes128>>(
      "394c97881abd989d29c703e48a72b397"
      "a7acf51b59649eeea9b33274d8541df4",
      "4b15c684a152d485fe9937d39b168c29",
      "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0",
      "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e");
}

TEST(xts, cavp_aes256_two_blocks) {
  check_xts<mode::xts<aes256>>(
      "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7c"
      "d6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08",
      "adf8d92627464ad2f0428e84a9f87564",
      "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e",
      "cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db");
}

// The data unit number is defined as an integer and converted to a little
// endian byte string. Writing the number out as big endian instead does not
// match this vector.
TEST(xts, cavp_aes128_sequence_number_form) {
  const std::vector<uint8_t> key = test::hex("fb46fb3cab7f67ad5207bc232c50dcbb"
                                            "24dbd1564590855d4cb777b3ba6431c3");
  const std::vector<uint8_t> plain =
      test::hex("46409f7426eb4e3d33480534b80fe6e09fed6583907eb83c84");

  mode::xts<aes128> xts(key);

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(xts.encrypt(static_cast<uint64_t>(117), plain, encrypted));
  EXPECT_EQ(std::string("a19d9b3209d388740a581975091fe26deecbb0f117c22b0ae4"),
            test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(xts.decrypt(static_cast<uint64_t>(117), encrypted, decrypted));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(decrypted));
}

TEST(xts, sequence_number_becomes_little_endian_tweak) {
  mode::xts<aes128>::tweak_t tweak;
  mode::xts<aes128>::make_tweak(117, tweak);
  EXPECT_EQ(std::string("75000000000000000000000000000000"),
            test::to_hex(&tweak[0], sizeof(tweak)));
}

TEST(xts, rejects_data_unit_shorter_than_one_block) {
  const std::vector<uint8_t> key = test::hex("fb46fb3cab7f67ad5207bc232c50dcbb"
                                            "24dbd1564590855d4cb777b3ba6431c3");
  std::vector<uint8_t> buffer(15);
  mode::xts<aes128> xts(key);

  const auto result = xts.encrypt(static_cast<uint64_t>(0), buffer, buffer);
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::xts<aes128>::data_unit_too_short, result.error().value);
}

TEST(xts, rejects_key_of_the_wrong_length) {
  const std::vector<uint8_t> short_key =
      test::hex("00112233445566778899aabbccddeeff");
  ASSERT_LT(short_key.size(), mode::xts<aes128>::key_size);
  EXPECT_THROW(mode::xts<aes128>{ctl::bytes(short_key)},
               std::invalid_argument);

  // A key that is too long used to be accepted and silently truncated, which
  // is how a key meant for a different cipher ends up in use unnoticed.
  const std::vector<uint8_t> long_key(mode::xts<aes128>::key_size + 1);
  EXPECT_THROW(mode::xts<aes128>{ctl::bytes(long_key)}, std::invalid_argument);
}

// Data units of many lengths, including several that are not a multiple of the
// block size and so take the ciphertext stealing path, have to come back
// unchanged. The published vectors only cover a few lengths.
TEST(xts, round_trips_at_every_length) {
  const std::vector<uint8_t> key = test::hex("fb46fb3cab7f67ad5207bc232c50dcbb"
                                            "24dbd1564590855d4cb777b3ba6431c3");
  mode::xts<aes128> xts(key);

  std::vector<uint8_t> plain(200);
  for (size_t i = 0; i < plain.size(); ++i)
    plain[i] = static_cast<uint8_t>(i * 7 + 1);

  for (size_t length = 16; length <= plain.size(); ++length) {
    std::vector<uint8_t> encrypted(length);
    std::vector<uint8_t> decrypted(length);
    ASSERT_TRUE(xts.encrypt(static_cast<uint64_t>(length),
                            ctl::bytes(plain).first(length), encrypted))
        << "length = " << length;
    ASSERT_TRUE(xts.decrypt(static_cast<uint64_t>(length), encrypted,
                            decrypted))
        << "length = " << length;
    EXPECT_EQ(test::to_hex(plain.data(), length), test::to_hex(decrypted))
        << "length = " << length;
  }
}

// ------------------------------------------------------- lengths that no
// ------------------------------------------------------- longer have to be
// ------------------------------------------------------- kept in step

// The length of a key is part of the type of the argument, so the only way to
// get it wrong is with a container whose length is decided at run time, and
// that is checked where it is handed over rather than read past its end.
TEST(lengths, a_key_of_the_wrong_length_is_refused) {
  const std::vector<uint8_t> correct(aes128::key_size);
  const std::vector<uint8_t> too_short(aes128::key_size - 1);
  const std::vector<uint8_t> too_long(aes128::key_size + 1);

  EXPECT_NO_THROW(mode::ecb<aes128>{ctl::bytes(correct)});
  EXPECT_THROW(mode::ecb<aes128>{ctl::bytes(too_short)},
               std::invalid_argument);
  EXPECT_THROW(mode::ecb<aes128>{ctl::bytes(too_long)}, std::invalid_argument);
}

// An initialization vector, a nonce and a tweak are fixed length in the same
// way as a key.
TEST(lengths, a_nonce_of_the_wrong_length_is_refused) {
  const std::vector<uint8_t> key(aes128::key_size);
  const std::vector<uint8_t> plain(32);
  std::vector<uint8_t> output(32);

  mode::cbc<aes128> cbc(key);
  const std::vector<uint8_t> short_iv(mode::cbc<aes128>::iv_size - 1);
  EXPECT_THROW(cbc.encrypt(short_iv, plain, output), std::invalid_argument);

  mode::ctr<aes128> ctr(key);
  const std::vector<uint8_t> long_nonce(mode::ctr<aes128>::nonce_size + 1);
  EXPECT_THROW(ctr.crypt(long_nonce, 0, plain, output), std::invalid_argument);
}

// An output buffer now carries its own length, so writing past its end is
// reported instead of corrupting whatever follows it.
TEST(lengths, an_output_buffer_that_is_too_small_is_refused) {
  const std::vector<uint8_t> key(aes128::key_size);
  const std::vector<uint8_t> plain(64);
  std::vector<uint8_t> too_small(48);

  mode::ecb<aes128> ecb(key);
  EXPECT_THROW(ecb.encrypt(plain, too_small), std::invalid_argument);

  mode::cbc<aes128>::iv_t iv = {0};
  mode::cbc<aes128> cbc(key);
  EXPECT_THROW(cbc.encrypt(iv, plain, too_small), std::invalid_argument);

  mode::ctr<aes128>::nonce_t nonce = {0};
  mode::ctr<aes128> ctr(key);
  EXPECT_THROW(ctr.crypt(nonce, 0, plain, too_small), std::invalid_argument);

  const std::vector<uint8_t> xts_key(mode::xts<aes128>::key_size);
  mode::xts<aes128> xts(xts_key);
  EXPECT_THROW(xts.encrypt(static_cast<uint64_t>(0), plain, too_small),
               std::invalid_argument);
}

// An output buffer larger than the input is fine, and only the part that was
// asked for is written.
TEST(lengths, a_larger_output_buffer_is_left_alone_past_the_result) {
  const std::vector<uint8_t> key(aes128::key_size);
  const std::vector<uint8_t> plain(32);
  std::vector<uint8_t> output(48, 0xcd);

  mode::ecb<aes128> ecb(key);
  ASSERT_TRUE(ecb.encrypt(plain, output));
  for (size_t i = plain.size(); i < output.size(); ++i)
    EXPECT_EQ(0xcd, output[i]) << "index = " << i;
}

// ---------------------------------------------------------------- composition

// Because a mode takes the block cipher as a template argument, every mode
// composes with ARIA through the same code. There are no published vectors for
// ARIA in these modes, so only the round trip is checked.
TEST(modes, compose_with_aria_roundtrip_only) {
  const std::vector<uint8_t> key = test::hex(kKey128);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);

  {
    mode::ecb<aria128> ecb(key);
    std::vector<uint8_t> out(plain.size());
    std::vector<uint8_t> back(plain.size());
    ASSERT_TRUE(ecb.encrypt(plain, out));
    EXPECT_NE(test::to_hex(plain), test::to_hex(out));
    ASSERT_TRUE(ecb.decrypt(out, back));
    EXPECT_EQ(test::to_hex(plain), test::to_hex(back));
  }

  {
    mode::cbc<aria128> cbc(key);
    mode::cbc<aria128>::iv_t iv = {0};
    std::vector<uint8_t> out(plain.size());
    std::vector<uint8_t> back(plain.size());
    ASSERT_TRUE(cbc.encrypt(iv, plain, out));
    EXPECT_NE(test::to_hex(plain), test::to_hex(out));
    ASSERT_TRUE(cbc.decrypt(iv, out, back));
    EXPECT_EQ(test::to_hex(plain), test::to_hex(back));
  }

  {
    mode::ctr<aria128> ctr(key);
    mode::ctr<aria128>::nonce_t nonce = {0};
    std::vector<uint8_t> out(plain.size());
    std::vector<uint8_t> back(plain.size());
    ctr.crypt(nonce, 0, plain, out);
    EXPECT_NE(test::to_hex(plain), test::to_hex(out));
    ctr.crypt(nonce, 0, out, back);
    EXPECT_EQ(test::to_hex(plain), test::to_hex(back));
  }
}

TEST(xts, composes_with_aria_roundtrip_only) {
  const std::vector<uint8_t> key = test::hex("fb46fb3cab7f67ad5207bc232c50dcbb"
                                            "24dbd1564590855d4cb777b3ba6431c3");
  const std::vector<uint8_t> plain =
      test::hex("46409f7426eb4e3d33480534b80fe6e09fed6583907eb83c84");

  mode::xts<aria128> xts(key);

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(xts.encrypt(static_cast<uint64_t>(7), plain, encrypted));
  EXPECT_NE(test::to_hex(plain), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(xts.decrypt(static_cast<uint64_t>(7), encrypted, decrypted));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(decrypted));
}
