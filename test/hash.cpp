/**
 * @file hash.cpp
 * @brief SHA-2 known answers, streaming boundaries and state lifetime
 */

#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/hash/sha2>

#include "vectors.h"

namespace {

template <class Hash>
void check_hash(const std::string &message, const char *expected) {
  typename Hash::digest_t one = {0};
  Hash::hash(message, one);
  ASSERT_EQ(std::string(expected), test::to_hex(one, Hash::digest_size));

  typename Hash::digest_t generic = {0};
  ctl::hash::compute<Hash>(message, generic);
  ASSERT_EQ(std::string(expected),
            test::to_hex(generic, Hash::digest_size));

  for (size_t cut = 0; cut <= message.size(); ++cut) {
    Hash streamed;
    streamed.update(ctl::bytes(message).first(cut));
    streamed.update(
        ctl::bytes(message).subview(cut, message.size() - cut));
    typename Hash::digest_t result = {0};
    streamed.finish(result);
    ASSERT_EQ(std::string(expected), test::to_hex(result, Hash::digest_size))
        << "cut = " << cut;
  }
}

const char *const kShort = "abc";
const char *const kLong32 =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const char *const kLong64 =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

struct undersized_digest_storage {
  static constexpr size_t block_size = 64;
  static constexpr size_t digest_size = 32;
  typedef uint8_t digest_t[1];
  typedef ctl::fixed_bytes<digest_size> digest_view;
  typedef ctl::writable_fixed_bytes<digest_size> writable_digest_view;
  void reset();
  void update(ctl::bytes);
  void finish(writable_digest_view);
};

struct mismatched_digest_view {
  static constexpr size_t block_size = 64;
  static constexpr size_t digest_size = 32;
  typedef uint8_t digest_t[digest_size];
  typedef ctl::fixed_bytes<16> digest_view;
  typedef ctl::writable_fixed_bytes<digest_size> writable_digest_view;
  void reset();
  void update(ctl::bytes);
  void finish(writable_digest_view);
};

struct wrongly_typed_sizes {
  static constexpr bool block_size = true;
  static constexpr bool digest_size = true;
  typedef uint8_t digest_t[1];
  typedef ctl::fixed_bytes<1> digest_view;
  typedef ctl::writable_fixed_bytes<1> writable_digest_view;
  void reset();
  void update(ctl::bytes);
  void finish(writable_digest_view);
};

static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha224>,
              "SHA-224 must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha256>,
              "SHA-256 must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha384>,
              "SHA-384 must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha512>,
              "SHA-512 must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha512_224>,
              "SHA-512/224 must satisfy the fixed hash interface");
static_assert(ctl::hash::is_fixed_hash_v<ctl::hash::sha512_256>,
              "SHA-512/256 must satisfy the fixed hash interface");
static_assert(!ctl::hash::is_fixed_hash_v<std::string>,
              "unrelated types must not satisfy the fixed hash interface");
static_assert(!ctl::hash::is_fixed_hash_v<undersized_digest_storage>,
              "digest storage must agree with digest_size");
static_assert(!ctl::hash::is_fixed_hash_v<mismatched_digest_view>,
              "digest views must agree with digest_size");
static_assert(!ctl::hash::is_fixed_hash_v<wrongly_typed_sizes>,
              "hash sizes must use the size_t contract");

} // namespace

TEST(sha2, nist_one_block_samples) {
  check_hash<ctl::hash::sha224>(
      kShort, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
  check_hash<ctl::hash::sha256>(
      kShort, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
              "f20015ad");
  check_hash<ctl::hash::sha384>(
      kShort, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a"
              "43ff5bed8086072ba1e7cc2358baeca134c825a7");
  check_hash<ctl::hash::sha512>(
      kShort, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee6"
              "4b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e"
              "2a9ac94fa54ca49f");
  check_hash<ctl::hash::sha512_224>(
      kShort, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
  check_hash<ctl::hash::sha512_256>(
      kShort, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f131"
              "07e7af23");
}

TEST(sha2, nist_two_block_samples) {
  check_hash<ctl::hash::sha224>(
      kLong32, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
  check_hash<ctl::hash::sha256>(
      kLong32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd4"
               "19db06c1");
  check_hash<ctl::hash::sha384>(
      kLong64, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086"
               "e3b0f712fcc7c71a557e2db966c3e9fa91746039");
  check_hash<ctl::hash::sha512>(
      kLong64, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aead"
               "b6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd2654"
               "5e96e55b874be909");
  check_hash<ctl::hash::sha512_224>(
      kLong64, "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");
  check_hash<ctl::hash::sha512_256>(
      kLong64, "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861"
               "e19b563a");
}

TEST(sha2, empty_message_answers) {
  check_hash<ctl::hash::sha224>(
      "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
  check_hash<ctl::hash::sha256>(
      "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
          "7852b855");
  check_hash<ctl::hash::sha384>(
      "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf"
          "63f6e1da274edebfe76f65fbd51ad2f14898b95b");
  check_hash<ctl::hash::sha512>(
      "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921"
          "d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81"
          "a538327af927da3e");
  check_hash<ctl::hash::sha512_224>(
      "", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
  check_hash<ctl::hash::sha512_256>(
      "", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01e"
          "cef0967a");
}

TEST(sha2, every_padding_and_streaming_boundary_agrees) {
  std::vector<uint8_t> message(257);
  for (size_t i = 0; i < message.size(); ++i)
    message[i] = static_cast<uint8_t>(i * 73u + 19u);

  for (size_t length = 0; length <= message.size(); ++length) {
    ctl::hash::sha256 whole256;
    ctl::hash::sha512 whole512;
    for (size_t i = 0; i < length; ++i) {
      whole256.update(ctl::bytes(message).subview(i, 1));
      whole512.update(ctl::bytes(message).subview(i, 1));
    }
    ctl::hash::sha256::digest_t split256 = {0};
    ctl::hash::sha512::digest_t split512 = {0};
    whole256.finish(split256);
    whole512.finish(split512);

    ctl::hash::sha256::digest_t direct256 = {0};
    ctl::hash::sha512::digest_t direct512 = {0};
    ctl::hash::sha256::hash(ctl::bytes(message).first(length), direct256);
    ctl::hash::sha512::hash(ctl::bytes(message).first(length), direct512);
    EXPECT_EQ(test::to_hex(direct256, sizeof(direct256)),
              test::to_hex(split256, sizeof(split256)))
        << "length = " << length;
    EXPECT_EQ(test::to_hex(direct512, sizeof(direct512)),
              test::to_hex(split512, sizeof(split512)))
        << "length = " << length;
  }
}

TEST(sha2, contexts_are_transferred_and_consumed) {
  using hash_type = ctl::hash::sha256;
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
  EXPECT_EQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
            "f20015ad",
            test::to_hex(digest, sizeof(digest)));
  EXPECT_THROW(moved.update(std::string("again")), std::logic_error);
  EXPECT_THROW(moved.finish(digest), std::logic_error);

  moved.reset();
  EXPECT_NO_THROW(moved.update(std::string("abc")));

  // A default empty view has a null data pointer. Updating a partially filled
  // block with it must be a no-op without performing pointer arithmetic on
  // that null pointer.
  hash_type with_empty_view;
  with_empty_view.update(std::string("a"));
  with_empty_view.update(ctl::bytes());
  with_empty_view.update(std::string("bc"));
  with_empty_view.finish(digest);
  EXPECT_EQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
            "f20015ad",
            test::to_hex(digest, sizeof(digest)));
}

TEST(sha2, digest_length_is_part_of_the_output_type) {
  std::vector<uint8_t> wrong(ctl::hash::sha256::digest_size - 1);
  EXPECT_THROW(ctl::hash::sha256::hash(std::string("abc"), wrong),
               std::invalid_argument);
}
