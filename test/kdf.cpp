/**
 * @file kdf.cpp
 * @brief RFC 5869 HKDF and RFC 7914 PBKDF2-HMAC-SHA-256 tests
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <ctl/hash/blake2>
#include <ctl/hash/sha2>
#include <ctl/hash/sha3>
#include <ctl/kdf/hkdf>
#include <ctl/kdf/pbkdf2>

#include "vectors.h"

TEST(hkdf, rfc5869_sha256_test_case_1) {
  typedef ctl::kdf::hkdf<ctl::hash::sha256> hkdf_type;
  const std::vector<uint8_t> ikm(22, 0x0b);
  const std::vector<uint8_t> salt =
      test::hex("000102030405060708090a0b0c");
  const std::vector<uint8_t> info = test::hex("f0f1f2f3f4f5f6f7f8f9");

  hkdf_type::prk_t prk = {0};
  hkdf_type::extract(salt, ikm, prk);
  EXPECT_EQ("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844a"
            "d7c2b3e5",
            test::to_hex(prk, sizeof(prk)));

  std::vector<uint8_t> expanded(42);
  hkdf_type::expand(prk, info, expanded);
  EXPECT_EQ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
            "ecc4c5bf34007208d5b887185865",
            test::to_hex(expanded));

  std::vector<uint8_t> derived(42);
  hkdf_type::derive(salt, ikm, info, derived);
  EXPECT_EQ(expanded, derived);
}

TEST(hkdf, rfc5869_sha256_test_case_3_uses_an_empty_salt_and_info) {
  typedef ctl::kdf::hkdf<ctl::hash::sha256> hkdf_type;
  const std::vector<uint8_t> ikm(22, 0x0b);
  const ctl::bytes empty;

  hkdf_type::prk_t prk = {0};
  hkdf_type::extract(empty, ikm, prk);
  EXPECT_EQ("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c2"
            "93ccb04",
            test::to_hex(prk, sizeof(prk)));

  std::vector<uint8_t> output(42);
  hkdf_type::derive(empty, ikm, empty, output);
  EXPECT_EQ("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f"
            "3c738d2d9d201395faa4b61a96c8",
            test::to_hex(output));
}

TEST(hkdf, the_255_block_boundary_is_supported_but_not_exceeded) {
  typedef ctl::kdf::hkdf<ctl::hash::sha256> hkdf_type;
  const std::string salt = "salt";
  const std::string ikm = "input key material";
  const std::string info = "context";

  std::vector<uint8_t> maximum(hkdf_type::max_output_size);
  std::vector<uint8_t> two_stage(maximum.size());
  hkdf_type::derive(salt, ikm, info, maximum);
  hkdf_type::prk_t prk = {0};
  hkdf_type::extract(salt, ikm, prk);
  hkdf_type::expand(prk, info, two_stage);
  EXPECT_EQ(maximum, two_stage);

  std::vector<uint8_t> too_long(hkdf_type::max_output_size + 1, 0xa5);
  EXPECT_THROW(hkdf_type::derive(salt, ikm, info, too_long),
               std::length_error);
  EXPECT_TRUE(std::all_of(too_long.begin(), too_long.end(),
                          [](uint8_t value) { return value == 0xa5; }));
}

TEST(hkdf, output_must_not_overlap_any_input) {
  typedef ctl::kdf::hkdf<ctl::hash::sha256> hkdf_type;
  std::vector<uint8_t> shared(80, 0x3c);
  const std::vector<uint8_t> before = shared;

  EXPECT_THROW(
      hkdf_type::expand(ctl::bytes(shared).first(hkdf_type::prk_size),
                        ctl::bytes(),
                        ctl::writable_bytes(shared).subview(16, 42)),
      std::invalid_argument);
  EXPECT_EQ(before, shared);

  EXPECT_THROW(
      hkdf_type::derive(std::string("salt"), std::string("ikm"),
                        ctl::bytes(shared).first(24),
                        ctl::writable_bytes(shared).subview(12, 42)),
      std::invalid_argument);
  EXPECT_EQ(before, shared);
}

TEST(pbkdf2, rfc7914_hmac_sha256_test_vectors) {
  typedef ctl::kdf::pbkdf2<ctl::hash::sha256> pbkdf2_type;

  std::vector<uint8_t> first(64);
  pbkdf2_type::derive(std::string("passwd"), std::string("salt"), 1,
                      first);
  EXPECT_EQ("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c2"
            "0dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd50911"
            "2041d3a19783",
            test::to_hex(first));

  std::vector<uint8_t> intensive(64);
  pbkdf2_type::derive(std::string("Password"), std::string("NaCl"), 80000,
                      intensive);
  EXPECT_EQ("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b"
            "34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f6"
            "2b397f33c8d",
            test::to_hex(intensive));
}

TEST(pbkdf2, hmac_sha256_iterations_and_partial_last_block) {
  typedef ctl::kdf::pbkdf2<ctl::hash::sha256> pbkdf2_type;
  std::vector<uint8_t> full(32);
  pbkdf2_type::derive(std::string("password"), std::string("salt"), 2,
                      full);
  EXPECT_EQ("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a9"
            "5474c43",
            test::to_hex(full));

  std::vector<uint8_t> partial(17);
  pbkdf2_type::derive(std::string("password"), std::string("salt"), 2,
                      partial);
  EXPECT_TRUE(std::equal(partial.begin(), partial.end(), full.begin()));
}

TEST(pbkdf2, hmac_sha512_uses_the_same_generic_construction) {
  typedef ctl::kdf::pbkdf2<ctl::hash::sha512> pbkdf2_type;
  std::vector<uint8_t> output(64);
  pbkdf2_type::derive(std::string("password"), std::string("salt"), 1,
                      output);
  EXPECT_EQ("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c"
            "8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63"
            "f73b60a57fce",
            test::to_hex(output));
}

TEST(kdf, fixed_sha3_and_blake2_hashes_compose_without_adapters) {
  std::vector<uint8_t> sha3_output(32);
  ctl::kdf::pbkdf2<ctl::hash::sha3_256>::derive(
      std::string("password"), std::string("salt"), 2, sha3_output);
  EXPECT_EQ("4c915baedd1773383e77fcfe38114ca7514010adec24b47290ec17020"
            "8423f76",
            test::to_hex(sha3_output));

  std::vector<uint8_t> blake2_output(32);
  ctl::kdf::pbkdf2<ctl::hash::blake2s_256>::derive(
      std::string("password"), std::string("salt"), 2, blake2_output);
  EXPECT_EQ("7b88e65e6e95a118bc995f681a391cbd7b46e0cf9750a81100f613ad"
            "d62d84be",
            test::to_hex(blake2_output));

  typedef ctl::kdf::hkdf<ctl::hash::sha3_256> hkdf_type;
  hkdf_type::prk_t prk = {0};
  hkdf_type::extract(std::string("salt"), std::string("input"), prk);
  std::vector<uint8_t> staged(48);
  std::vector<uint8_t> combined(48);
  hkdf_type::expand(prk, std::string("context"), staged);
  hkdf_type::derive(std::string("salt"), std::string("input"),
                    std::string("context"), combined);
  EXPECT_EQ(staged, combined);
}

TEST(pbkdf2, invalid_parameters_are_rejected_before_output_changes) {
  typedef ctl::kdf::pbkdf2<ctl::hash::sha256> pbkdf2_type;
  std::vector<uint8_t> output(32, 0xa5);
  EXPECT_THROW(pbkdf2_type::derive(std::string("password"),
                                   std::string("salt"), 0, output),
               std::invalid_argument);
  EXPECT_TRUE(std::all_of(output.begin(), output.end(),
                          [](uint8_t value) { return value == 0xa5; }));

  std::vector<uint8_t> empty;
  EXPECT_THROW(pbkdf2_type::derive(std::string("password"),
                                   std::string("salt"), 1, empty),
               std::invalid_argument);

  std::vector<uint8_t> shared(64, 0x7d);
  const std::vector<uint8_t> before = shared;
  EXPECT_THROW(pbkdf2_type::derive(
                   ctl::bytes(shared).first(20), std::string("salt"), 1,
                   ctl::writable_bytes(shared).subview(10, 32)),
               std::invalid_argument);
  EXPECT_EQ(before, shared);

  if (pbkdf2_type::max_output_size <
      static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
    uint8_t dummy = 0;
    const size_t impossible =
        static_cast<size_t>(pbkdf2_type::max_output_size + 1);
    EXPECT_THROW(pbkdf2_type::derive(
                     std::string("password"), std::string("salt"), 1,
                     ctl::writable_bytes(&dummy, impossible)),
                 std::length_error);
  }
}
