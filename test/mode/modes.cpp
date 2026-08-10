/**
 * @file modes.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief Mode of operation verification (NIST SP 800-38A, NIST CAVP XTS)
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/cipher/aria>
#include <ctl/symmetric/mode/cbc>
#include <ctl/symmetric/mode/ctr>
#include <ctl/symmetric/mode/ecb>
#include <ctl/symmetric/mode/xts>

#include "../vectors.h"

namespace {

using aes128 = ctl::symmetric::cipher::aes<128>;
using aes256 = ctl::symmetric::cipher::aes<256>;

// The ECB, CBC and CTR examples of SP 800-38A share one key and the same four
// block plaintext.
const char *kKey = "2b7e151628aed2a6abf7158809cf4f3c";
const char *kPlaintext = "6bc1bee22e409f96e93d7e117393172a"
                         "ae2d8a571e03ac9c9eb76fac45af8e51"
                         "30c81c46a35ce411e5fbc1191a0a52ef"
                         "f69f2445df4f9b17ad2b417be66c3710";

/**
 * @brief Verifies one XTS vector given in the form that supplies the tweak
 * directly
 */
template <class Mode>
void check_xts(const char *key_hex, const char *tweak_hex,
               const char *plain_hex, const char *cipher_hex) {
  const std::vector<uint8_t> key = test::hex(key_hex);
  const std::vector<uint8_t> tweak_bytes = test::hex(tweak_hex);
  const std::vector<uint8_t> plain = test::hex(plain_hex);

  ASSERT_EQ(key.size(), Mode::key_size);
  ASSERT_EQ(tweak_bytes.size(), Mode::tweak_size);

  typename Mode::tweak_t tweak;
  memcpy(&tweak[0], tweak_bytes.data(), Mode::tweak_size);

  Mode mode(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(mode.encrypt(tweak, plain.data(), plain.size(),
                           encrypted.data()));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(mode.decrypt(tweak, encrypted.data(), encrypted.size(),
                           decrypted.data()));
  EXPECT_EQ(std::string(plain_hex), test::to_hex(decrypted));

  // Operating in place. Ciphertext stealing crosses over the last two blocks,
  // so getting the order of the reads and writes wrong shows up here.
  std::vector<uint8_t> inplace = plain;
  ASSERT_TRUE(mode.encrypt(tweak, inplace.data(), inplace.size(),
                           inplace.data()));
  EXPECT_EQ(std::string(cipher_hex), test::to_hex(inplace));
}

} // namespace

namespace mode = ctl::symmetric::mode;

TEST(ecb, sp800_38a_f11_aes128) {
  const std::vector<uint8_t> key = test::hex(kKey);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  mode::ecb<aes128> ecb(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(ecb.encrypt(plain.data(), plain.size(), encrypted.data()));
  EXPECT_EQ(std::string("3ad77bb40d7a3660a89ecaf32466ef97"
                        "f5d3d58503b9699de785895a96fdbaaf"
                        "43b1cd7f598ece23881b00e3ed030688"
                        "7b0c785e27e8ad3f8223207104725dd4"),
            test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(ecb.decrypt(encrypted.data(), encrypted.size(),
                          decrypted.data()));
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(decrypted));
}

TEST(ecb, rejects_non_block_multiple_length) {
  const std::vector<uint8_t> key = test::hex(kKey);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  mode::ecb<aes128> ecb(key.data(), key.size());

  std::vector<uint8_t> output(plain.size());
  const auto result = ecb.encrypt(plain.data(), plain.size() - 1,
                                  output.data());
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::ecb<aes128>::invalid_input_length, result.error().value);
}

TEST(cbc, sp800_38a_f21_aes128) {
  const std::vector<uint8_t> key = test::hex(kKey);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  const std::vector<uint8_t> iv_bytes =
      test::hex("000102030405060708090a0b0c0d0e0f");

  mode::cbc<aes128>::iv_t iv;
  memcpy(&iv[0], iv_bytes.data(), sizeof(iv));

  mode::cbc<aes128> cbc(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(cbc.encrypt(iv, plain.data(), plain.size(), encrypted.data()));
  EXPECT_EQ(std::string("7649abac8119b246cee98e9b12e9197d"
                        "5086cb9b507219ee95db113a917678b2"
                        "73bed6b8e3c1743b7116e69e22229516"
                        "3ff1caa1681fac09120eca307586e1a7"),
            test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(cbc.decrypt(iv, encrypted.data(), encrypted.size(),
                          decrypted.data()));
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(decrypted));

  // In place decryption has to keep the chaining value before the input block
  // is overwritten.
  std::vector<uint8_t> inplace = encrypted;
  ASSERT_TRUE(cbc.decrypt(iv, inplace.data(), inplace.size(),
                          inplace.data()));
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(inplace));
}

TEST(ctr, sp800_38a_f51_aes128) {
  const std::vector<uint8_t> key = test::hex(kKey);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  const std::vector<uint8_t> nonce_bytes =
      test::hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

  mode::ctr<aes128>::nonce_t nonce;
  memcpy(&nonce[0], nonce_bytes.data(), sizeof(nonce));

  mode::ctr<aes128> ctr(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  ctr.crypt(nonce, 0, plain.data(), plain.size(), encrypted.data());
  EXPECT_EQ(std::string("874d6191b620e3261bef6864990db6ce"
                        "9806f66b7970fdff8617187bb9fffdff"
                        "5ae4df3edbd5d35e5b4f09020db03eab"
                        "1e031dda2fbe03d1792170a0f3009cee"),
            test::to_hex(encrypted));

  // Encryption and decryption are the same operation.
  std::vector<uint8_t> decrypted(plain.size());
  ctr.crypt(nonce, 0, encrypted.data(), encrypted.size(), decrypted.data());
  EXPECT_EQ(std::string(kPlaintext), test::to_hex(decrypted));
}

// The initial counter of this vector is ...fcfdfeff, so on the second block the
// carry crosses a byte boundary into ...fcfdff00. Starting partway through with
// an offset has to give the same result as processing the whole buffer, which
// is only the case when the carry propagates correctly.
TEST(ctr, random_access_matches_sequential) {
  const std::vector<uint8_t> key = test::hex(kKey);
  const std::vector<uint8_t> plain = test::hex(kPlaintext);
  const std::vector<uint8_t> nonce_bytes =
      test::hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

  mode::ctr<aes128>::nonce_t nonce;
  memcpy(&nonce[0], nonce_bytes.data(), sizeof(nonce));

  mode::ctr<aes128> ctr(key.data(), key.size());

  std::vector<uint8_t> whole(plain.size());
  ctr.crypt(nonce, 0, plain.data(), plain.size(), whole.data());

  // Checked at offsets that do not line up with a block boundary.
  for (size_t offset : {size_t(1), size_t(15), size_t(16), size_t(17),
                        size_t(31), size_t(48)}) {
    std::vector<uint8_t> partial(plain.size() - offset);
    ctr.crypt(nonce, offset, plain.data() + offset, partial.size(),
              partial.data());
    EXPECT_EQ(test::to_hex(whole.data() + offset, partial.size()),
              test::to_hex(partial))
        << "offset = " << offset;
  }
}

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

  mode::xts<aes128> xts(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(xts.encrypt(static_cast<uint64_t>(117), plain.data(),
                          plain.size(), encrypted.data()));
  EXPECT_EQ(std::string("a19d9b3209d388740a581975091fe26deecbb0f117c22b0ae4"),
            test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(xts.decrypt(static_cast<uint64_t>(117), encrypted.data(),
                          encrypted.size(), decrypted.data()));
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
  mode::xts<aes128> xts(key.data(), key.size());

  const auto result = xts.encrypt(static_cast<uint64_t>(0), buffer.data(),
                                  buffer.size(), buffer.data());
  ASSERT_FALSE(result);
  EXPECT_EQ(mode::xts<aes128>::data_unit_too_short, result.error().value);
}

TEST(xts, rejects_short_key_buffer) {
  const std::vector<uint8_t> key = test::hex("00112233445566778899aabbccddeeff");
  ASSERT_LT(key.size(), mode::xts<aes128>::key_size);
  EXPECT_THROW(mode::xts<aes128>(key.data(), key.size()),
               std::invalid_argument);
}

// Because a mode takes the block cipher as a template argument, it composes
// with ARIA through the same code. There is no published vector for ARIA-XTS,
// so only the round trip is checked.
TEST(xts, composes_with_aria_roundtrip_only) {
  using aria128 = ctl::symmetric::cipher::aria<128>;

  const std::vector<uint8_t> key = test::hex("fb46fb3cab7f67ad5207bc232c50dcbb"
                                            "24dbd1564590855d4cb777b3ba6431c3");
  const std::vector<uint8_t> plain =
      test::hex("46409f7426eb4e3d33480534b80fe6e09fed6583907eb83c84");

  mode::xts<aria128> xts(key.data(), key.size());

  std::vector<uint8_t> encrypted(plain.size());
  ASSERT_TRUE(xts.encrypt(static_cast<uint64_t>(7), plain.data(), plain.size(),
                          encrypted.data()));
  EXPECT_NE(test::to_hex(plain), test::to_hex(encrypted));

  std::vector<uint8_t> decrypted(plain.size());
  ASSERT_TRUE(xts.decrypt(static_cast<uint64_t>(7), encrypted.data(),
                          encrypted.size(), decrypted.data()));
  EXPECT_EQ(test::to_hex(plain), test::to_hex(decrypted));
}
