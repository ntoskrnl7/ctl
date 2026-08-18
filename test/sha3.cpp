/**
 * @file sha3.cpp
 * @brief FIPS 202 SHA-3 answers, sponge boundaries and state lifetime
 */

#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/hash/sha3>

#include "vectors.h"

namespace {

template <class Hash>
void check_hash(ctl::bytes message, const char *expected) {
  typename Hash::digest_t direct = {0};
  Hash::hash(message, direct);
  ASSERT_EQ(std::string(expected), test::to_hex(direct, Hash::digest_size));

  typename Hash::digest_t generic = {0};
  ctl::hash::compute<Hash>(message, generic);
  ASSERT_EQ(std::string(expected), test::to_hex(generic, Hash::digest_size));

  for (size_t cut = 0; cut <= message.size(); ++cut) {
    Hash streamed;
    streamed.update(ctl::bytes(message).first(cut));
    streamed.update(ctl::bytes(message).subview(cut, message.size() - cut));
    typename Hash::digest_t result = {0};
    streamed.finish(result);
    ASSERT_EQ(std::string(expected), test::to_hex(result, Hash::digest_size))
        << "cut = " << cut;
  }
}

static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha3_224>,
              "SHA3-224 must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha3_256>,
              "SHA3-256 must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha3_384>,
              "SHA3-384 must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha3_512>,
              "SHA3-512 must satisfy the fixed hash interface");

} // namespace

TEST(sha3, fips202_empty_message_answers) {
  const std::string message;
  check_hash<ctl::hash::sha3_224>(
      message, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
  check_hash<ctl::hash::sha3_256>(
      message, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b"
               "80f8434a");
  check_hash<ctl::hash::sha3_384>(
      message, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bb"
               "ee983a2ac3713831264adb47fb6bd1e058d5f004");
  check_hash<ctl::hash::sha3_512>(
      message, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1"
               "475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e3"
               "01758586281dcd26");
}

TEST(sha3, fips202_abc_answers) {
  const std::string message("abc");
  check_hash<ctl::hash::sha3_224>(
      message, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
  check_hash<ctl::hash::sha3_256>(
      message, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe245"
               "11431532");
  check_hash<ctl::hash::sha3_384>(
      message, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0"
               "e49be4b298d88cea927ac7f539f1edf228376d25");
  check_hash<ctl::hash::sha3_512>(
      message, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d02"
               "40d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a5"
               "6592f8274eec53f0");
}

TEST(sha3, multi_block_answers_cross_every_rate) {
  std::vector<uint8_t> message(300);
  for (size_t i = 0; i < message.size(); ++i)
    message[i] = static_cast<uint8_t>(i * 73u + 19u);

  check_hash<ctl::hash::sha3_224>(
      message, "dda1bf26b24783829236fc73a464f57fecd8241b04e07b2860ea70b0");
  check_hash<ctl::hash::sha3_256>(
      message, "2c0adc946ec76aab80baecf24ba06bb1d03ac674238144e9eaec5863"
               "fdb74466");
  check_hash<ctl::hash::sha3_384>(
      message, "353ed34607706ca2a3944a97ae6fbe25eefff518015b1f2b97c39f0c"
               "77a04f44bcfe9e7443e34bbe858329afbedc45d2");
  check_hash<ctl::hash::sha3_512>(
      message, "63de5543a22cdd4e619a89748230e694e60e2a1f1438e4e65e575603"
               "8b59fcccbe470964a92fec6d9e46d27c924a5ed661c2778ba71e7ebc"
               "373a5518dd80405f");
}

TEST(sha3, nist_1600_bit_message_crosses_every_rate_boundary) {
  // NIST's byte-aligned 1600-bit sample is 200 repetitions of A3. It spans
  // one or more complete rate blocks for every fixed-output SHA-3 variant.
  const std::vector<uint8_t> message(200, 0xa3);
  check_hash<ctl::hash::sha3_224>(
      message, "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0");
  check_hash<ctl::hash::sha3_256>(
      message, "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd"
               "9de31787");
  check_hash<ctl::hash::sha3_384>(
      message, "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649"
               "ce1dbcdd76197a31fd55ee989f2d7050dd473e8f");
  check_hash<ctl::hash::sha3_512>(
      message, "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc4"
               "8caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a841"
               "6df6545a1ce8ba00");
}

TEST(sha3, contexts_are_transferred_consumed_and_reset) {
  typedef ctl::hash::sha3_256 hash_type;
  static_assert(!std::is_copy_constructible<hash_type>::value,
                "a streaming context has one owner");
  static_assert(std::is_move_constructible<hash_type>::value,
                "a streaming context can be transferred");

  hash_type original;
  original.update(std::string("ab"));
  hash_type moved(std::move(original));
  EXPECT_THROW(original.update(std::string("c")), std::logic_error);

  moved.update(std::string("c"));
  hash_type::digest_t digest = {0};
  moved.finish(digest);
  EXPECT_EQ("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe245"
            "11431532",
            test::to_hex(digest, sizeof(digest)));
  EXPECT_THROW(moved.update(std::string("again")), std::logic_error);

  moved.reset();
  moved.update(std::string("abc"));
  EXPECT_NO_THROW(moved.finish(digest));
}

TEST(sha3, digest_length_is_part_of_the_output_type) {
  std::vector<uint8_t> wrong(ctl::hash::sha3_256::digest_size - 1);
  EXPECT_THROW(ctl::hash::sha3_256::hash(std::string("abc"), wrong),
               std::invalid_argument);
}
