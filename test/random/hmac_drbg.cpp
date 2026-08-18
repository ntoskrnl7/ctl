/**
 * @file hmac_drbg.cpp
 * @brief NIST CAVP and lifecycle tests for HMAC_DRBG
 */
#include <gtest/gtest.h>

#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/hash/sha2>
#include <ctl/random/hmac_drbg>

#include "../vectors.h"

namespace {

using drbg = ctl::hmac_drbg<ctl::hash::sha256>;

static_assert(!std::is_copy_constructible<drbg>::value,
              "a DRBG stream must have one owner");
static_assert(std::is_move_constructible<drbg>::value,
              "a DRBG state may be transferred");
static_assert(drbg::security_strength == 256, "SHA-256 profile strength");
static_assert(drbg::entropy_size == 32, "minimum entropy length");
static_assert(drbg::nonce_size == 16, "minimum nonce length");

} // namespace

TEST(hmac_drbg, cavp_sha256_without_optional_inputs) {
  const auto entropy = test::hex(
      "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488");
  const auto nonce = test::hex("659ba96c601dc69fc902940805ec0ca8");
  drbg generator(entropy, nonce);
  std::vector<uint8_t> discarded(128), output(128);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
            "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
            "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
            "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
            test::to_hex(output));
}

TEST(hmac_drbg, cavp_sha512) {
  const auto entropy = test::hex(
      "35049f389a33c0ecb1293238fd951f8ffd517dfde06041d32945b3e26914ba15");
  const auto nonce = test::hex("f7328760be6168e6aa9fb54784989a11");
  ctl::hmac_drbg<ctl::hash::sha512> generator(entropy, nonce);
  std::vector<uint8_t> discarded(256), output(256);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("e76491b0260aacfded01ad39fbf1a66a88284caa5123368a2ad9330ee48335e3"
            "c9c9ba90e6cbc9429962d60c1a6661edcfaa31d972b8264b9d4562cf18494128"
            "a092c17a8da6f3113e8a7edfcd4427082bd390675e9662408144971717303d8dc"
            "352c9e8b95e7f35fa2ac9f549b292bc7c4bc7f01ee0a577859ef6e82d79ef238"
            "92d167c140d22aac32b64ccdfeee2730528a38763b24227f91ac3ffe47fb11538"
            "e435307e77481802b0f613f370ffb0dbeab774fe1efbb1a80d01154a9459e73a"
            "d361108bbc86b0914f095136cbe634555ce0bb263618dc5c367291ce082551898"
            "7154fe9ecb052b3f0a256fcc30cc14572531c9628973639beda456f2bddf6",
            test::to_hex(output));
}

TEST(hmac_drbg, cavp_personalization_and_additional_input) {
  const auto entropy = test::hex(
      "5d3286bc53a258a53ba781e2c4dcd79a790e43bbe0e89fb3eed39086be34174b");
  const auto nonce = test::hex("c5422294b7318952ace7055ab7570abf");
  const auto personalization = test::hex(
      "2dba094d008e150d51c4135bb2f03dcde9cbf3468a12908a1b025c120c985b9d");
  const auto first = test::hex(
      "793a7ef8f6f0482beac542bb785c10f8b7b406a4de92667ab168ecc2cf7573c6");
  const auto second = test::hex(
      "2238cdb4e23d629fe0c2a83dd8d5144ce1a6229ef41dabe2a99ff722e510b530");
  drbg generator(entropy, nonce, personalization);
  std::vector<uint8_t> discarded(128), output(128);
  generator.generate(discarded, first);
  generator.generate(output, second);
  EXPECT_EQ("d04678198ae7e1aeb435b45291458ffde0891560748b43330eaf866b5a6385e7"
            "4c6fa5a5a44bdb284d436e98d244018d6acedcdfa2e9f499d8089e4db86ae89a"
            "6ab2d19cb705e2f048f97fb597f04106a1fa6a1416ad3d859118e079a0c319eb"
            "95686f4cbcce3b5101c7a0b010ef029c4ef6d06cdfac97efb9773891688c37cf",
            test::to_hex(output));
}

TEST(hmac_drbg, cavp_reseed) {
  const auto entropy = test::hex(
      "06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d");
  const auto nonce = test::hex("0e66f71edc43e42a45ad3c6fc6cdc4df");
  const auto reseed = test::hex(
      "01920a4e669ed3a85ae8a33b35a74ad7fb2a6bb4cf395ce00334a9c9a5a5d552");
  drbg generator(entropy, nonce);
  generator.reseed(reseed);
  std::vector<uint8_t> discarded(128), output(128);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("76fc79fe9b50beccc991a11b5635783a83536add03c157fb30645e611c2898bb"
            "2b1bc215000209208cd506cb28da2a51bdb03826aaf2bd2335d576d519160842"
            "e7158ad0949d1a9ec3e66ea1b1a064b005de914eac2e9d4f2d72a8616a80225"
            "422918250ff66a41bd2f864a6a38cc5b6499dc43f7f2bd09e1e0f8f5885935124",
            test::to_hex(output));
}

TEST(hmac_drbg, validates_inputs_limits_and_move) {
  std::vector<uint8_t> entropy(drbg::entropy_size, 0x11);
  std::vector<uint8_t> nonce(drbg::nonce_size, 0x22);
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

TEST(hmac_drbg, rejects_additional_input_that_overlaps_output) {
  std::vector<uint8_t> entropy(drbg::entropy_size, 0x51);
  std::vector<uint8_t> nonce(drbg::nonce_size, 0x15);
  drbg generator(entropy, nonce);
  std::vector<uint8_t> buffer(32, 0x7a);
  EXPECT_THROW(generator.generate(buffer, buffer), std::invalid_argument);
  EXPECT_EQ(0u, generator.requests_served());
}
