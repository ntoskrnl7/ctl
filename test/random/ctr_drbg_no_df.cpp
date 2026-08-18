/**
 * @file ctr_drbg_no_df.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief CTR_DRBG verification (NIST SP 800-90A)
 *
 * The vectors are the CAVP response files for CTR_DRBG with no derivation
 * function, prediction resistance disabled and no reseed. Those files give the
 * key and counter after each step as well as the returned bits, so where a
 * mismatch happens is visible rather than only that one happened.
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/random/ctr_drbg_no_df>
#include <ctl/random/system>
#include <ctl/symmetric/cipher/aes>

#include "../vectors.h"

namespace {

using ctl::symmetric::cipher::aes;

using drbg128 = ctl::ctr_drbg_no_df<aes<128>>;

static_assert(!std::is_copy_constructible<drbg128>::value,
              "copying a DRBG would clone its output stream");
static_assert(!std::is_copy_assignable<drbg128>::value,
              "copy assignment would clone its output stream");
static_assert(std::is_move_constructible<drbg128>::value,
              "a DRBG state may be transferred without being cloned");
static_assert(std::is_move_assignable<drbg128>::value,
              "a DRBG state may be transferred without being cloned");

/**
 * @brief Runs one CAVP case: instantiate, generate, generate, and compare
 *
 * The bits the file records are the ones the second call returns. The first
 * call is made and thrown away, which is what the file describes.
 */
template <class Cipher>
void check(const char *entropy_hex, const char *expected_hex) {
  const std::vector<uint8_t> entropy = test::hex(entropy_hex);
  ASSERT_EQ(entropy.size(), ctl::ctr_drbg_no_df<Cipher>::seed_size);

  ctl::ctr_drbg_no_df<Cipher> drbg(entropy);

  std::vector<uint8_t> thrown_away(64);
  drbg.generate(thrown_away);

  std::vector<uint8_t> produced(64);
  drbg.generate(produced);

  EXPECT_EQ(std::string(expected_hex), test::to_hex(produced));
}

} // namespace

TEST(ctr_drbg_no_df, cavp_aes128) {
  check<aes<128>>(
      "ce50f33da5d4c1d3d4004eb35244b7f2cd7f2e5076fbf6780a7ff634b249a5fc",
      "6545c0529d372443b392ceb3ae3a99a30f963eaf313280f1d1a1e87f9db373d3"
      "61e75d18018266499cccd64d9bbb8de0185f213383080faddec46bae1f784e5a");
}

TEST(ctr_drbg_no_df, cavp_aes192) {
  check<aes<192>>(
      "f1ef7eb311c850e189be229df7e6d68f1795aa8e21d93504e75abe78f0413958"
      "73540386812a9a2a",
      "6bb0aa5b4b97ee83765736ad0e9068dfef0ccfc93b71c1d3425302ef7ba4635f"
      "fc09981d262177e208a7ec90a557b6d76112d56c40893892c3034835036d7a69");
}

TEST(ctr_drbg_no_df, cavp_aes256) {
  check<aes<256>>(
      "df5d73faa468649edda33b5cca79b0b05600419ccb7a879ddfec9db32ee494e5"
      "531b51de16a30f769262474c73bec010",
      "d1c07cd95af8a7f11012c84ce48bb8cb87189e99d40fccb1771c619bdf82ab22"
      "80b1dc2f2581f39164f7ac0c510494b3a43c41b7db17514c87b107ae793e01c5");
}

TEST(ctr_drbg_no_df, cavp_aes256_with_optional_inputs) {
  const auto entropy = test::hex(
      "0dd4d80062ecc0f359efbe7723020be9b88b550fe74088094069e74428395856"
      "f63eed4f5b0e7d1e006f0eaff74f638c");
  const auto personalization = test::hex(
      "d2aa2ccd4bc6537e51f6550ab6d6294547bef3e971a7f128e4436f957de9982c"
      "93ee22110b0e40ab33a7d3dfa22f599d");
  const auto first = test::hex(
      "0b081bab6c74d86b4a010e2ded99d14e0c9838f7c3d69afd64f1b66377d95cdc"
      "b7f6ec5358e3516034c3339ced7e1638");
  const auto second = test::hex(
      "ca818f938ae0c7f4f507e4cfec10e7baf51fe34b89a502f754d2d2be7395120f"
      "e1fb013c67ac2500b3d17b735da09a6e");
  ctl::ctr_drbg_no_df<aes<256>> generator(entropy, personalization);
  std::vector<uint8_t> discarded(64), output(64);
  generator.generate(discarded, first);
  generator.generate(output, second);
  EXPECT_EQ("6808268b13e236f642c06deba2494496e7003c937ebf6f7cb7c92104ea090f18"
            "484aa075560d7844a06eb559948c93b26ae40f2db98ecb53ad593eb4c78f82b1",
            test::to_hex(output));
}

TEST(ctr_drbg_no_df, seed_size_follows_the_cipher) {
  // Key and counter together, which is what a seed has to set.
  EXPECT_EQ(32u, ctl::ctr_drbg_no_df<aes<128>>::seed_size);
  EXPECT_EQ(40u, ctl::ctr_drbg_no_df<aes<192>>::seed_size);
  EXPECT_EQ(48u, ctl::ctr_drbg_no_df<aes<256>>::seed_size);
}

// The same seed has to give the same stream, which is what makes this a
// deterministic generator and what the vectors above rely on.
TEST(ctr_drbg_no_df, the_same_seed_gives_the_same_stream) {
  const std::vector<uint8_t> seed(
      ctl::ctr_drbg_no_df<aes<256>>::seed_size, 0x5c);

  ctl::ctr_drbg_no_df<aes<256>> first(seed);
  ctl::ctr_drbg_no_df<aes<256>> second(seed);

  std::vector<uint8_t> a(200);
  std::vector<uint8_t> b(200);
  first.generate(a);
  second.generate(b);
  EXPECT_EQ(test::to_hex(a), test::to_hex(b));
}

// A personalization string has to change the stream, otherwise it is not doing
// the one thing it is for: separating two generators seeded from the same pool
// at the same moment.
TEST(ctr_drbg_no_df, the_personalization_string_changes_the_stream) {
  const std::vector<uint8_t> seed(
      ctl::ctr_drbg_no_df<aes<256>>::seed_size, 0x11);
  const std::vector<uint8_t> label = test::hex("0102030405");

  ctl::ctr_drbg_no_df<aes<256>> plain(seed);
  ctl::ctr_drbg_no_df<aes<256>> labelled(seed, label);

  std::vector<uint8_t> a(64);
  std::vector<uint8_t> b(64);
  plain.generate(a);
  labelled.generate(b);
  EXPECT_NE(test::to_hex(a), test::to_hex(b));
}

// Successive requests must not repeat, and the state has to move even when
// nothing is mixed in.
TEST(ctr_drbg_no_df, successive_requests_differ) {
  const std::vector<uint8_t> seed(
      ctl::ctr_drbg_no_df<aes<128>>::seed_size, 0x77);
  ctl::ctr_drbg_no_df<aes<128>> drbg(seed);

  std::string previous;
  for (int i = 0; i < 32; ++i) {
    std::vector<uint8_t> out(48);
    drbg.generate(out);
    const std::string now = test::to_hex(out);
    EXPECT_NE(previous, now);
    previous = now;
  }
}

// Requests of every length, including ones that end partway through a block,
// have to be a prefix of the same stream taken in one go.
TEST(ctr_drbg_no_df, a_request_is_a_prefix_of_the_longer_one) {
  const std::vector<uint8_t> seed(
      ctl::ctr_drbg_no_df<aes<128>>::seed_size, 0x2a);

  for (size_t size : {size_t(1), size_t(15), size_t(16), size_t(17),
                      size_t(31), size_t(64), size_t(100)}) {
    ctl::ctr_drbg_no_df<aes<128>> whole(seed);
    ctl::ctr_drbg_no_df<aes<128>> part(seed);

    std::vector<uint8_t> long_run(128);
    whole.generate(long_run);

    std::vector<uint8_t> short_run(size);
    part.generate(short_run);

    EXPECT_EQ(test::to_hex(long_run.data(), size), test::to_hex(short_run))
        << "size = " << size;
  }
}

TEST(ctr_drbg_no_df, reseeding_moves_the_stream) {
  const std::vector<uint8_t> seed(
      ctl::ctr_drbg_no_df<aes<128>>::seed_size, 0x33);
  const std::vector<uint8_t> other(
      ctl::ctr_drbg_no_df<aes<128>>::seed_size, 0x44);

  ctl::ctr_drbg_no_df<aes<128>> drbg(seed);
  std::vector<uint8_t> before(32);
  drbg.generate(before);

  drbg.reseed(other);
  std::vector<uint8_t> after(32);
  drbg.generate(after);

  EXPECT_NE(test::to_hex(before), test::to_hex(after));
  EXPECT_EQ(1u, drbg.requests_served());
}

// A move transfers the one state rather than leaving two generators at the
// same key and counter. The destination continues exactly where the source
// would have, while the erased source refuses to generate predictable output.
TEST(ctr_drbg_no_df, moving_transfers_the_state_and_disables_the_source) {
  const std::vector<uint8_t> seed(drbg128::seed_size, 0x6d);
  drbg128 source(seed);
  drbg128 reference(seed);

  std::vector<uint8_t> skipped(19);
  source.generate(skipped);
  reference.generate(skipped);

  drbg128 moved(std::move(source));
  std::vector<uint8_t> expected(48);
  std::vector<uint8_t> actual(48);
  reference.generate(expected);
  moved.generate(actual);
  EXPECT_EQ(expected, actual);

  EXPECT_THROW(source.generate(actual), std::logic_error);
  EXPECT_THROW(source.reseed(seed), std::logic_error);
  EXPECT_THROW((void)source.requests_served(), std::logic_error);

  // Explicit instantiation with fresh seed material is the only way a
  // moved-from object becomes usable again.
  source.instantiate(seed);
  EXPECT_NO_THROW(source.generate(actual));
}

TEST(ctr_drbg_no_df, refuses_more_than_one_request_may_produce) {
  const std::vector<uint8_t> seed(
      ctl::ctr_drbg_no_df<aes<128>>::seed_size, 0x01);
  ctl::ctr_drbg_no_df<aes<128>> drbg(seed);

  std::vector<uint8_t> too_much(
      ctl::ctr_drbg_no_df<aes<128>>::max_per_request + 1);
  EXPECT_THROW(drbg.generate(too_much), std::length_error);

  std::vector<uint8_t> allowed(
      ctl::ctr_drbg_no_df<aes<128>>::max_per_request);
  EXPECT_NO_THROW(drbg.generate(allowed));
}

TEST(ctr_drbg_no_df, refuses_a_seed_of_the_wrong_length) {
  const std::vector<uint8_t> too_short(
      ctl::ctr_drbg_no_df<aes<128>>::seed_size - 1);
  EXPECT_THROW(ctl::ctr_drbg_no_df<aes<128>>{ctl::bytes(too_short)},
               std::invalid_argument);

  const std::vector<uint8_t> too_long(
      ctl::ctr_drbg_no_df<aes<128>>::seed_size + 1);
  EXPECT_THROW(ctl::ctr_drbg_no_df<aes<128>>{ctl::bytes(too_long)},
               std::invalid_argument);
}

// The way the two halves are meant to be put together: entropy from the
// operating system, the stream from the algorithm.
TEST(ctr_drbg_no_df, seeds_from_the_operating_system) {
  uint8_t seed[ctl::ctr_drbg_no_df<aes<256>>::seed_size];
  ctl::random_bytes(seed);

  ctl::ctr_drbg_no_df<aes<256>> drbg(seed);
  std::vector<uint8_t> a(64);
  std::vector<uint8_t> b(64);
  drbg.generate(a);
  drbg.generate(b);

  EXPECT_NE(test::to_hex(a), test::to_hex(b));
  EXPECT_NE(std::string(128, '0'), test::to_hex(a));
}
