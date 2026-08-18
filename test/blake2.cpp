/**
 * @file blake2.cpp
 * @brief RFC 7693 BLAKE2 answers, digest sizes and streaming boundaries
 */

#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/hash/blake2>

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
    streamed.update(message.first(cut));
    streamed.update(message.subview(cut, message.size() - cut));
    typename Hash::digest_t result = {0};
    streamed.finish(result);
    ASSERT_EQ(std::string(expected), test::to_hex(result, Hash::digest_size))
        << "cut = " << cut;
  }
}

std::vector<uint8_t> patterned(size_t size) {
  std::vector<uint8_t> result(size);
  for (size_t i = 0; i < result.size(); ++i)
    result[i] = static_cast<uint8_t>(i * 73u + 19u);
  return result;
}

static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::blake2s_256>,
              "BLAKE2s must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::blake2b_512>,
              "BLAKE2b must satisfy the fixed hash interface");
static_assert(ctl::hash::blake2s_128::digest_size == 16,
              "BLAKE2s digest bits must determine its output type");
static_assert(ctl::hash::blake2b_256::digest_size == 32,
              "BLAKE2b digest bits must determine its output type");

} // namespace

TEST(blake2, rfc7693_abc_answers) {
  check_hash<ctl::hash::blake2s_256>(
      std::string("abc"),
      "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c"
      "86675982");
  check_hash<ctl::hash::blake2b_512>(
      std::string("abc"),
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6f"
      "dbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925a"
      "b92386edd4009923");
}

TEST(blake2, empty_message_and_compile_time_digest_sizes) {
  check_hash<ctl::hash::blake2s_128>(ctl::bytes(),
                                     "64550d6ffe2c0a01a14aba1eade0200c");
  check_hash<ctl::hash::blake2s_160>(
      ctl::bytes(), "354c9c33f735962418bdacb9479873429c34916f");
  check_hash<ctl::hash::blake2s_224>(
      ctl::bytes(), "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4");
  check_hash<ctl::hash::blake2s_256>(
      ctl::bytes(), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd"
                    "1ed0eef9");

  check_hash<ctl::hash::blake2b_160>(
      ctl::bytes(), "3345524abf6bbe1809449224b5972c41790b6cf2");
  check_hash<ctl::hash::blake2b_256>(
      ctl::bytes(), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cd"
                    "f12fe3a8");
  check_hash<ctl::hash::blake2b_384>(
      ctl::bytes(), "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d797"
                    "8c6fd3244a6caf0498812673c5e05ef583825100");
  check_hash<ctl::hash::blake2b_512>(
      ctl::bytes(), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217"
                    "f71f5419d25e1031afee585313896444934eb04b903a685b1448b755"
                    "d56f701afe9be2ce");
}

TEST(blake2, minimum_and_nonstandard_byte_aligned_digest_sizes) {
  // The digest length is part of BLAKE2's parameter block, not a truncation
  // of the maximum-size digest. Odd byte lengths therefore need independent
  // answers as well as compile-time range checks.
  check_hash<ctl::hash::blake2s<8>>(std::string("abc"), "0d");
  check_hash<ctl::hash::blake2s<136>>(
      std::string("abc"), "e8e884d3c0651b3dfbd4e212d16df1f512");
  check_hash<ctl::hash::blake2b<8>>(std::string("abc"), "6b");
  check_hash<ctl::hash::blake2b<264>>(
      std::string("abc"),
      "f7bb660ec10c1b537a53ff432791f8a34c09e9ecfca84288bba1ee39afec290d"
      "63");
}

TEST(blake2, exact_final_blocks_keep_the_final_flag) {
  const std::vector<uint8_t> s_block = patterned(64);
  const std::vector<uint8_t> b_block = patterned(128);
  check_hash<ctl::hash::blake2s_256>(
      s_block, "b63ab6cf5145ad158fcc90ff0c86a1eeda47ce0cc804cc59bb5a3603"
               "12929fec");
  check_hash<ctl::hash::blake2b_512>(
      b_block, "59767f85e3da8b7927ae5253dd1318a655491343af4dcaa6616399989"
               "17f349e7e736d5e17b231e3f55f89c7ec0d5013da29d649dad8760d"
               "911cb8e0cb30ad89");
}

TEST(blake2, multi_block_answers_cross_both_block_sizes) {
  const std::vector<uint8_t> message = patterned(300);
  check_hash<ctl::hash::blake2s_256>(
      message, "c593674ecf7c933d9763d2e2331257673c86d6d39aca1ef4a9b21df6"
               "07b5ef27");
  check_hash<ctl::hash::blake2b_512>(
      message, "1e5ab3fee9a3973069bc745030a7d75a3057e0e121f47d2cc9a9f3ce"
               "367279f7b27deaa3988edcb982bba61f1443c90abfd30358b2866b5f"
               "6827010edeeddbb2");
}

TEST(blake2, contexts_are_transferred_consumed_and_reset) {
  typedef ctl::hash::blake2s_256 hash_type;
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
  EXPECT_EQ("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c"
            "86675982",
            test::to_hex(digest, sizeof(digest)));
  EXPECT_THROW(moved.finish(digest), std::logic_error);

  moved.reset();
  moved.update(std::string("abc"));
  EXPECT_NO_THROW(moved.finish(digest));
}

TEST(blake2, digest_length_is_part_of_the_output_type) {
  std::vector<uint8_t> wrong(ctl::hash::blake2b_256::digest_size - 1);
  EXPECT_THROW(ctl::hash::blake2b_256::hash(std::string("abc"), wrong),
               std::invalid_argument);
}
