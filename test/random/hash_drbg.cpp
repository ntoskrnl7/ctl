/**
 * @file hash_drbg.cpp
 * @brief NIST CAVP and lifecycle tests for Hash_DRBG
 */
#include <gtest/gtest.h>

#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/hash/sha2>
#include <ctl/random/hash_drbg>

#include "../vectors.h"

namespace {

using drbg = ctl::hash_drbg<ctl::hash::sha256>;

static_assert(!std::is_copy_constructible<drbg>::value,
              "a DRBG stream must have one owner");
static_assert(std::is_move_constructible<drbg>::value,
              "a DRBG state may be transferred");
static_assert(drbg::seed_size == 55, "SHA-256 Hash_DRBG seedlen is 440 bits");
static_assert(ctl::hash_drbg<ctl::hash::sha512>::seed_size == 111,
              "SHA-512 Hash_DRBG seedlen is 888 bits");
static_assert(ctl::hash_drbg<ctl::hash::sha512_224>::seed_size == 55,
              "SHA-512/224 Hash_DRBG seedlen is 440 bits");
static_assert(ctl::hash_drbg<ctl::hash::sha512_256>::seed_size == 55,
              "SHA-512/256 Hash_DRBG seedlen is 440 bits");

} // namespace

TEST(hash_drbg, cavp_sha256_without_optional_inputs) {
  const auto entropy = test::hex(
      "a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb");
  const auto nonce = test::hex("8581f9317517276e06e9607ddbcbcc2e");
  drbg generator(entropy, nonce);
  std::vector<uint8_t> discarded(128), output(128);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80d"
            "aaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febd"
            "c343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51c"
            "cde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df",
            test::to_hex(output));
}

TEST(hash_drbg, cavp_personalization_and_additional_input) {
  const auto entropy = test::hex(
      "68c43a008fe46a823d260a9d7fa388fb9e401f0197e7e758a744b4babb3f4651");
  const auto nonce = test::hex("eb6825777856331884aaf3751b3e4006");
  const auto personalization = test::hex(
      "23ce0d32cbf2d26467f0d62acff1a3acbaa6d2746dc3ee7aa9d32c880788afc8");
  const auto first = test::hex(
      "a31b9f13b58d4fa2f8d8ac42b62a207ff647339a146bd8b268b33d4aff57adbd");
  const auto second = test::hex(
      "d34fc6504eca4b568193c75357b0d3821a48c77ff80d6dbd21c6cf045ff489cf");
  drbg generator(entropy, nonce, personalization);
  std::vector<uint8_t> discarded(128), output(128);
  generator.generate(discarded, first);
  generator.generate(output, second);
  EXPECT_EQ("abb4ecbacd4e8fa943c7221aed433861c3b203232657ec4c417d021f905d911d"
            "b1058ff1e11e272232482ec96bae7cb4efc135502dbe41724077077f6de79b71"
            "3670c385d04644e1281c3e582e0016255abbe5f8c06d0de57160559f0c08f7fb"
            "5be3563c649966190f8d3261364447537de2c7371c6e8c308933d27145bf90ab",
            test::to_hex(output));
}

TEST(hash_drbg, cavp_reseed) {
  const auto entropy = test::hex(
      "63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569");
  const auto nonce = test::hex("808aa38f2a72a62359915a9f8a04ca68");
  const auto reseed = test::hex(
      "e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3");
  drbg generator(entropy, nonce);
  generator.reseed(reseed);
  std::vector<uint8_t> discarded(128), output(128);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("04eec63bb231df2c630a1afbe724949d005a587851e1aa795e477347c8b05662"
            "1c18bddcdd8d99fc5fc2b92053d8cfacfb0bb8831205fad1ddd6c071318a6018"
            "f03b73f5ede4d4d071f9de03fd7aea105d9299b8af99aa075bdb4db9aa28c18"
            "d174b56ee2a014d098896ff2282c955a81969e069fa8ce007a180183a07dfae17",
            test::to_hex(output));
}

TEST(hash_drbg, cavp_sha512_exercises_the_888_bit_seed) {
  const auto entropy = test::hex(
      "6b50a7d8f8a55d7a3df8bb40bcc3b722d8708de67fda010b03c4c84d72096f8c");
  const auto nonce = test::hex("3ec649cc6256d9fa31db7a2904aaf025");
  ctl::hash_drbg<ctl::hash::sha512> generator(entropy, nonce);
  std::vector<uint8_t> discarded(256), output(256);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("95b7f17e9802d3577392c6a9c08083b67dd1292265b5f42d237f1c55bb9b10bf"
            "cfd82c77a378b8266a0099143b3c2d64611eeeb69acdc055957c139e8b190c7a"
            "06955f2c797c2778de940396a501f40e91396acf8d7e45ebdbb53bbf8c975230"
            "d2f0ff9106c76119ae498e7fbc03d90f8e4c51627aed5c8d4263d5d2b978873"
            "a0de596ee6dc7f7c29e37eee8b34c90dd1cf6a9ddb22b4cbd086b14b35de93d"
            "a2d5cb1806698cbd7bbb67bfe3d31fd2d1dbd2a1e058a3eb99d7e51f1a938ee"
            "d5e1c1de23a6b4345d3191409f92f39b3670d8dbfb635d8e6a36932d81033d1"
            "448d63b403ddf88e121b6e819ac381226c1321e4b08644f6727c368c5a9f7a4"
            "b3ee2",
            test::to_hex(output));
}

TEST(hash_drbg, cavp_sha512_224_uses_the_440_bit_seed) {
  const auto entropy =
      test::hex("65568162700f22ac868a504110fa466c70cfe0e7c32f1451");
  const auto nonce = test::hex("69545e871b89c7b3f95885eb");
  ctl::hash_drbg<ctl::hash::sha512_224> generator(entropy, nonce);
  std::vector<uint8_t> discarded(112), output(112);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("588572c2e4f0d6c7077d2b9eb593687ca92c86e5a9729505fcff52adfcf8a5eb"
            "850b910b985df10299bfe7434f3b6b7af92a3edaed732751cdb421c38431e276"
            "3afc6799eb61e176f9f20945870680ff8b62484378d3a7fd7d29202e5d371785"
            "d68fe399d5f600f34517fcccadf58937",
            test::to_hex(output));
}

TEST(hash_drbg, validates_inputs_limits_and_move) {
  std::vector<uint8_t> entropy(drbg::entropy_size, 0x31);
  std::vector<uint8_t> nonce(drbg::nonce_size, 0x13);
  EXPECT_THROW(drbg(ctl::bytes(entropy.data(), entropy.size() - 1), nonce),
               std::invalid_argument);
  EXPECT_THROW(drbg(entropy, ctl::bytes(nonce.data(), nonce.size() - 1)),
               std::invalid_argument);

  drbg source(entropy, nonce);
  drbg moved(std::move(source));
  std::vector<uint8_t> output(32);
  EXPECT_THROW(source.generate(output), std::logic_error);
  EXPECT_NO_THROW(moved.generate(output));

  std::vector<uint8_t> too_large(drbg::max_per_request + 1);
  EXPECT_THROW(moved.generate(too_large), std::length_error);
}
