/**
 * @file hmac.cpp
 * @brief RFC 4231 HMAC-SHA-2 answers and keyed-context lifetime tests
 */

#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/hash/blake2>
#include <ctl/hash/sha2>
#include <ctl/hash/sha3>
#include <ctl/mac/hmac>

#include "vectors.h"

namespace {

// A structurally compatible hash does not have to derive from fixed_hash or
// provide SHA-2's static hash convenience function. This is the shape an
// independently implemented fixed-output hash presents to HMAC and the KDFs.
class external_sha256 {
public:
  static constexpr size_t block_size = ctl::hash::sha256::block_size;
  static constexpr size_t digest_size = ctl::hash::sha256::digest_size;

  typedef uint8_t digest_t[digest_size];
  typedef ctl::fixed_bytes<digest_size> digest_view;
  typedef ctl::writable_fixed_bytes<digest_size> writable_digest_view;

  void reset() { context_.reset(); }
  void update(ctl::bytes input) { context_.update(input); }
  void finish(writable_digest_view output) { context_.finish(output); }

private:
  ctl::hash::sha256 context_;
};

static_assert(ctl::hash::is_fixed_hash_v<external_sha256>,
              "a structural hash must not have to inherit from fixed_hash");

template <class Hash>
void check_hmac(const std::vector<uint8_t> &key, const std::string &message,
                const char *expected) {
  typedef ctl::mac::hmac<Hash> hmac_type;
  typename hmac_type::tag_t direct = {0};
  hmac_type::authenticate(key, message, direct);
  ASSERT_EQ(std::string(expected),
            test::to_hex(direct, hmac_type::tag_size));

  for (size_t cut = 0; cut <= message.size(); ++cut) {
    hmac_type streamed(key);
    streamed.update(ctl::bytes(message).first(cut));
    streamed.update(
        ctl::bytes(message).subview(cut, message.size() - cut));
    typename hmac_type::tag_t result = {0};
    streamed.finish(result);
    ASSERT_EQ(std::string(expected),
              test::to_hex(result, hmac_type::tag_size))
        << "cut = " << cut;
  }

  const std::vector<uint8_t> expected_bytes = test::hex(expected);
  EXPECT_TRUE(hmac_type::verify(key, message, expected_bytes));
  std::vector<uint8_t> altered = expected_bytes;
  altered[altered.size() / 2] ^= 0x80;
  EXPECT_FALSE(hmac_type::verify(key, message, altered));
}

} // namespace

TEST(hmac_sha2, rfc4231_test_case_1) {
  const std::vector<uint8_t> key(20, 0x0b);
  const std::string message = "Hi There";

  check_hmac<ctl::hash::sha224>(
      key, message,
      "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
  check_hmac<ctl::hash::sha256>(
      key, message,
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c"
      "2e32cff7");
  check_hmac<ctl::hash::sha384>(
      key, message,
      "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c"
      "7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
  check_hmac<ctl::hash::sha512>(
      key, message,
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b305"
      "45e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f170"
      "2e696c203a126854");
}

TEST(hmac_sha2, rfc4231_test_case_6_hashes_a_long_key_first) {
  const std::vector<uint8_t> key(131, 0xaa);
  const std::string message =
      "Test Using Larger Than Block-Size Key - Hash Key First";

  check_hmac<ctl::hash::sha224>(
      key, message,
      "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e");
  check_hmac<ctl::hash::sha256>(
      key, message,
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f"
      "0ee37f54");
  check_hmac<ctl::hash::sha384>(
      key, message,
      "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05"
      "033ac4c60c2ef6ab4030fe8296248df163f44952");
  check_hmac<ctl::hash::sha512>(
      key, message,
      "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b0137"
      "83f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0ae"
      "c8b915a985d786598");
}

TEST(hmac_sha2, all_sha2_variants_share_the_generic_interface) {
  const std::vector<uint8_t> key = test::hex("00010203040506070809");
  const std::string message = "generic HMAC interface";

  ctl::mac::hmac<ctl::hash::sha512_224>::tag_t tag224 = {0};
  ctl::mac::hmac<ctl::hash::sha512_256>::tag_t tag256 = {0};
  ctl::mac::hmac<ctl::hash::sha512_224>::authenticate(key, message, tag224);
  ctl::mac::hmac<ctl::hash::sha512_256>::authenticate(key, message, tag256);

  EXPECT_TRUE(ctl::mac::hmac<ctl::hash::sha512_224>::verify(key, message,
                                                            tag224));
  EXPECT_TRUE(ctl::mac::hmac<ctl::hash::sha512_256>::verify(key, message,
                                                            tag256));
  EXPECT_NE(test::to_hex(tag224, sizeof(tag224)),
            test::to_hex(tag256, sizeof(tag256)));
}

TEST(hmac, accepts_a_structural_fixed_hash_without_a_static_hash_function) {
  // Longer than SHA-256's block so HMAC has to shorten the key through the
  // generic compute<Hash> path.
  const std::vector<uint8_t> key(80, 0xa5);
  const std::string message = "an independently implemented fixed hash";

  ctl::mac::hmac<ctl::hash::sha256>::tag_t expected = {0};
  ctl::mac::hmac<external_sha256>::tag_t actual = {0};
  ctl::mac::hmac<ctl::hash::sha256>::authenticate(key, message, expected);
  ctl::mac::hmac<external_sha256>::authenticate(key, message, actual);

  EXPECT_EQ(test::to_hex(expected, sizeof(expected)),
            test::to_hex(actual, sizeof(actual)));
}

TEST(hmac, fixed_sha3_and_blake2_hashes_use_the_same_construction) {
  std::vector<uint8_t> key(32);
  for (size_t i = 0; i < key.size(); ++i)
    key[i] = static_cast<uint8_t>(i);
  const std::string message = "fixed hash interface";

  ctl::mac::hmac<ctl::hash::sha3_256>::tag_t sha3_tag = {0};
  ctl::mac::hmac<ctl::hash::sha3_256>::authenticate(key, message, sha3_tag);
  EXPECT_EQ("2b8c460810fc3dd7c7b60e901602a0862717ca1605590276f6906bada"
            "a9b29c3",
            test::to_hex(sha3_tag, sizeof(sha3_tag)));

  ctl::mac::hmac<ctl::hash::blake2s_256>::tag_t blake2_tag = {0};
  ctl::mac::hmac<ctl::hash::blake2s_256>::authenticate(key, message,
                                                        blake2_tag);
  EXPECT_EQ("7da0572a67e37cb5b1297df1692234adcbd2516fa8c22b428e3ae2064e"
            "1f5363",
            test::to_hex(blake2_tag, sizeof(blake2_tag)));
}

TEST(hmac_sha2, keyed_contexts_are_transferred_consumed_and_rekeyed) {
  typedef ctl::mac::hmac<ctl::hash::sha256> hmac_type;
  static_assert(!std::is_copy_constructible<hmac_type>::value,
                "a keyed context has one owner");
  static_assert(std::is_move_constructible<hmac_type>::value,
                "a keyed context can be transferred");

  const std::vector<uint8_t> first_key(20, 0x0b);
  hmac_type original(first_key);
  original.update(std::string("Hi "));
  hmac_type moved(std::move(original));
  EXPECT_THROW(original.update(std::string("There")), std::logic_error);

  moved.update(std::string("There"));
  hmac_type::tag_t tag = {0};
  moved.finish(tag);
  EXPECT_EQ("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c"
            "2e32cff7",
            test::to_hex(tag, sizeof(tag)));
  EXPECT_THROW(moved.update(std::string("again")), std::logic_error);

  moved.reset();
  moved.update(std::string("Hi There"));
  moved.finish(tag);
  EXPECT_EQ("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c"
            "2e32cff7",
            test::to_hex(tag, sizeof(tag)));

  const std::vector<uint8_t> second_key = test::hex("4a656665");
  moved.set_key(second_key);
  moved.update(std::string("what do ya want for nothing?"));
  moved.finish(tag);
  EXPECT_EQ("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964e"
            "c3843",
            test::to_hex(tag, sizeof(tag)));
}

TEST(hmac_sha2, tag_length_is_part_of_the_interface) {
  const std::vector<uint8_t> key(16, 0x11);
  std::vector<uint8_t> short_tag(ctl::hash::sha256::digest_size - 1);
  EXPECT_THROW((ctl::mac::hmac<ctl::hash::sha256>::authenticate(
                   key, std::string("message"), short_tag)),
               std::invalid_argument);
}
