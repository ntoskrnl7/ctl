/**
 * @file ctr_drbg.cpp
 * @brief NIST CAVP and lifecycle tests for CTR_DRBG with Block_Cipher_df
 */
#include <gtest/gtest.h>

#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/random/ctr_drbg>
#include <ctl/symmetric/cipher/aes>

#include "../vectors.h"

namespace {

using ctl::symmetric::cipher::aes;
using drbg = ctl::ctr_drbg<aes<256>>;

static_assert(!std::is_copy_constructible<drbg>::value,
              "a DRBG stream must have one owner");
static_assert(std::is_move_constructible<drbg>::value,
              "a DRBG state may be transferred");
static_assert(drbg::entropy_size == 32, "AES-256 requires 256 entropy bits");
static_assert(drbg::nonce_size == 16, "the nonce minimum is half strength");

} // namespace

TEST(ctr_drbg, cavp_aes128_without_optional_inputs) {
  const auto entropy =
      test::hex("890eb067acf7382eff80b0c73bc872c6");
  const auto nonce = test::hex("aad471ef3ef1d203");
  ctl::ctr_drbg<aes<128>> generator(entropy, nonce);
  std::vector<uint8_t> discarded(64), output(64);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("a5514ed7095f64f3d0d3a5760394ab42062f373a25072a6ea6bcfd8489e94af6"
            "cf18659fea22ed1ca0a9e33f718b115ee536b12809c31b72b08ddd8be1910fa3",
            test::to_hex(output));
}

TEST(ctr_drbg, cavp_aes192_exercises_the_partial_seed_block) {
  const auto entropy =
      test::hex("c35c2fa2a89d52a11fa32aa96c95b8f1c9a8f9cb245a8b40");
  const auto nonce = test::hex("f3a6e5a7fbd9d3c68e277ba9ac9bbb00");
  ctl::ctr_drbg<aes<192>> generator(entropy, nonce);
  std::vector<uint8_t> discarded(64), output(64);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("8c2e72abfd9bb8284db79e17a43a3146cd7694e35249fc3383914a7117f41368"
            "e6d4f148ff49bf29076b5015c59f457945662e3d3503843f4aa5a3df9a9df10d",
            test::to_hex(output));
}

TEST(ctr_drbg, cavp_aes256_personalization_and_additional_input) {
  const auto entropy = test::hex(
      "87b56e964eba227154724bb9484b812d3e2c0c43b3d17f6098d9526e16e6d0ef");
  const auto nonce = test::hex("9bea6a7ff2358df142e6c23e2157fb83");
  const auto personalization = test::hex(
      "9860b432edd58d1ccbfeecbce99ffaee7d935a614860d4e965bd67041403096b");
  const auto first = test::hex(
      "99a5cc87924e8ea65a596f81fd17d63f5b4542fe6e8e1511b5d35c835dfadb0b");
  const auto second = test::hex(
      "9a8dec54734a34582a2332f3452e82313524c3e0dfb485faeac6ca5fc0ff504d");
  drbg generator(entropy, nonce, personalization);
  std::vector<uint8_t> discarded(64), output(64);
  generator.generate(discarded, first);
  generator.generate(output, second);
  EXPECT_EQ("dbc6a2330b19b5cddd8cd6392ec1fb508678c805e87d1aca07ac265007632503"
            "044a00610c79d98375afa7ab4cca1a90989cbfe7c674af5d823ced11c47e9af6",
            test::to_hex(output));
}

TEST(ctr_drbg, cavp_reseed) {
  const auto entropy = test::hex(
      "2d4c9f46b981c6a0b2b5d8c69391e569ff13851437ebc0fc00d616340252fed5");
  const auto nonce = test::hex("0bf814b411f65ec4866be1abb59d3c32");
  const auto reseed = test::hex(
      "93500fae4fa32b86033b7a7bac9d37e710dcc67ca266bc8607d665937766d207");
  drbg generator(entropy, nonce);
  generator.reseed(reseed);
  std::vector<uint8_t> discarded(64), output(64);
  generator.generate(discarded);
  generator.generate(output);
  EXPECT_EQ("322dd28670e75c0ea638f3cb68d6a9d6e50ddfd052b772a7b1d78263a7b8978b"
            "6740c2b65a9550c3a76325866fa97e16d74006bc96f26249b9f0a90d076f08e5",
            test::to_hex(output));
}

TEST(ctr_drbg, validates_entropy_nonce_request_and_moved_state) {
  std::vector<uint8_t> entropy(drbg::entropy_size, 0x42);
  std::vector<uint8_t> nonce(drbg::nonce_size, 0x24);
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
