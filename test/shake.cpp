/**
 * @file shake.cpp
 * @brief FIPS 202 SHAKE answers and absorb/squeeze lifecycle tests
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <ctl/hash/fixed>
#include <ctl/hash/sha3>
#include <ctl/hash/shake>
#include <ctl/hash/xof>

#include "vectors.h"

namespace {

template <class Xof>
void check_vector(ctl::bytes message, const char *expected) {
  const size_t output_size = std::char_traits<char>::length(expected) / 2;

  std::vector<uint8_t> direct(output_size);
  Xof::expand(message, direct);
  ASSERT_EQ(std::string(expected), test::to_hex(direct));

  std::vector<uint8_t> generic(output_size);
  ctl::hash::expand<Xof>(message, generic);
  ASSERT_EQ(std::string(expected), test::to_hex(generic));

  for (size_t cut = 0; cut <= message.size(); ++cut) {
    Xof streamed;
    streamed.update(message.first(cut));
    streamed.update(message.subview(cut, message.size() - cut));
    streamed.finish();
    std::vector<uint8_t> result(output_size);
    streamed.squeeze(result);
    ASSERT_EQ(std::string(expected), test::to_hex(result))
        << "input cut = " << cut;
  }

  for (size_t cut = 0; cut <= output_size; ++cut) {
    Xof streamed;
    streamed.update(message);
    streamed.finish();
    std::vector<uint8_t> result(output_size);
    streamed.squeeze(ctl::writable_bytes(result).first(cut));
    streamed.squeeze(
        ctl::writable_bytes(result).subview(cut, output_size - cut));
    ASSERT_EQ(std::string(expected), test::to_hex(result))
        << "output cut = " << cut;
  }
}

static_assert(ctl::hash::is_xof_v<ctl::hash::shake128>,
              "SHAKE128 must satisfy the XOF interface");
static_assert(ctl::hash::is_xof_v<ctl::hash::shake256>,
              "SHAKE256 must satisfy the XOF interface");
static_assert(!ctl::hash::is_fixed_hash_v<ctl::hash::shake128>,
              "an XOF must not silently satisfy the fixed-hash interface");
static_assert(!ctl::hash::is_xof_v<ctl::hash::sha3_256>,
              "a fixed hash must not silently satisfy the XOF interface");
static_assert(ctl::hash::shake128::rate == 168,
              "SHAKE128 has a 1344-bit rate");
static_assert(ctl::hash::shake256::rate == 136,
              "SHAKE256 has a 1088-bit rate");

} // namespace

TEST(shake, fips202_empty_message_2048_bit_outputs) {
  const std::string message;
  check_vector<ctl::hash::shake128>(
      message,
      "7f9c2ba4e88f827d616045507605853e"
      "d73b8093f6efbc88eb1a6eacfa66ef26"
      "3cb1eea988004b93103cfb0aeefd2a68"
      "6e01fa4a58e8a3639ca8a1e3f9ae57e2"
      "35b8cc873c23dc62b8d260169afa2f75"
      "ab916a58d974918835d25e6a435085b2"
      "badfd6dfaac359a5efbb7bcc4b59d538"
      "df9a04302e10c8bc1cbf1a0b3a5120ea"
      "17cda7cfad765f5623474d368ccca8af"
      "0007cd9f5e4c849f167a580b14aabdef"
      "aee7eef47cb0fca9767be1fda69419df"
      "b927e9df07348b196691abaeb580b32d"
      "ef58538b8d23f87732ea63b02b4fa0f4"
      "873360e2841928cd60dd4cee8cc0d4c9"
      "22a96188d032675c8ac850933c7aff15"
      "33b94c834adbb69c6115bad4692d8619");

  check_vector<ctl::hash::shake256>(
      message,
      "46b9dd2b0ba88d13233b3feb743eeb24"
      "3fcd52ea62b81b82b50c27646ed5762f"
      "d75dc4ddd8c0f200cb05019d67b592f6"
      "fc821c49479ab48640292eacb3b7c4be"
      "141e96616fb13957692cc7edd0b45ae3"
      "dc07223c8e92937bef84bc0eab862853"
      "349ec75546f58fb7c2775c38462c5010"
      "d846c185c15111e595522a6bcd16cf86"
      "f3d122109e3b1fdd943b6aec468a2d62"
      "1a7c06c6a957c62b54dafc3be87567d6"
      "77231395f6147293b68ceab7a9e0c58d"
      "864e8efde4e1b9a46cbe854713672f5c"
      "aaae314ed9083dab4b099f8e300f01b8"
      "650f1f4b1d8fcf3f3cb53fb8e9eb2ea2"
      "03bdc970f50ae55428a91f7f53ac266b"
      "28419c3778a15fd248d339ede785fb7f");
}

TEST(shake, fips202_1600_bit_message_2048_bit_outputs) {
  const std::vector<uint8_t> message(200, 0xa3);
  check_vector<ctl::hash::shake128>(
      message,
      "131ab8d2b594946b9c81333f9bb6e0ce"
      "75c3b93104fa3469d3917457385da037"
      "cf232ef7164a6d1eb448c8908186ad85"
      "2d3f85a5cf28da1ab6fe343817197846"
      "7f1c05d58c7ef38c284c41f6c2221a76"
      "f12ab1c04082660250802294fb871802"
      "13fdef5b0ecb7df50ca1f8555be14d32"
      "e10f6edcde892c09424b29f597afc270"
      "c904556bfcb47a7d40778d390923642b"
      "3cbd0579e60908d5a000c1d08b98ef93"
      "3f806445bf87f8b009ba9e94f7266122"
      "ed7ac24e5e266c42a82fa1bbefb7b8db"
      "0066e16a85e0493f07df4809aec084a5"
      "93748ac3dde5a6d7aae1e8b6e5352b2d"
      "71efbb47d4caeed5e6d633805d2d323e"
      "6fd81b4684b93a2677d45e7421c2c6ae");

  check_vector<ctl::hash::shake256>(
      message,
      "cd8a920ed141aa0407a22d59288652e9"
      "d9f1a7ee0c1e7c1ca699424da84a904d"
      "2d700caae7396ece96604440577da4f3"
      "aa22aeb8857f961c4cd8e06f0ae6610b"
      "1048a7f64e1074cd629e85ad7566048e"
      "fc4fb500b486a3309a8f26724c0ed628"
      "001a1099422468de726f1061d99eb9e9"
      "3604d5aa7467d4b1bd6484582a384317"
      "d7f47d750b8f5499512bb85a226c4243"
      "556e696f6bd072c5aa2d9b69730244b5"
      "6853d16970ad817e213e470618178001"
      "c9fb56c54fefa5fee67d2da524bb3b0b"
      "61ef0e9114a92cdbb6cccb98615cfe76"
      "e3510dd88d1cc28ff99287512f24bfaf"
      "a1a76877b6f37198e3a641c68a7c42d4"
      "5fa7acc10dae5f3cefb7b735f12d4e58");
}

TEST(shake, successive_squeezes_are_one_continuous_stream) {
  typedef ctl::hash::shake128 xof_type;
  const std::string message("abc");
  std::vector<uint8_t> whole(2 * xof_type::rate + 29);
  xof_type::expand(message, whole);

  xof_type streamed;
  streamed.update(message);
  streamed.finish();
  std::vector<uint8_t> pieces(whole.size());
  streamed.squeeze(ctl::writable_bytes(pieces).first(1));
  streamed.squeeze(ctl::writable_bytes(pieces).subview(1, xof_type::rate - 1));
  streamed.squeeze(ctl::writable_bytes(pieces).subview(xof_type::rate, 0));
  streamed.squeeze(ctl::writable_bytes(pieces).subview(xof_type::rate, 7));
  streamed.squeeze(ctl::writable_bytes(pieces).subview(
      xof_type::rate + 7, pieces.size() - xof_type::rate - 7));
  EXPECT_EQ(whole, pieces);
}

TEST(shake, contexts_are_transferred_phased_and_reset) {
  typedef ctl::hash::shake256 xof_type;
  static_assert(!std::is_copy_constructible<xof_type>::value,
                "an XOF state has one owner");
  static_assert(std::is_move_constructible<xof_type>::value,
                "an XOF state can be transferred");

  xof_type original;
  std::vector<uint8_t> one(1);
  EXPECT_THROW(original.squeeze(one), std::logic_error);
  original.update(std::string("ab"));
  xof_type absorbing(std::move(original));
  EXPECT_THROW(original.update(std::string("c")), std::logic_error);
  EXPECT_THROW(original.finish(), std::logic_error);

  absorbing.update(std::string("c"));
  absorbing.finish();
  EXPECT_THROW(absorbing.update(std::string("again")), std::logic_error);
  EXPECT_THROW(absorbing.finish(), std::logic_error);

  std::vector<uint8_t> prefix(17);
  absorbing.squeeze(prefix);
  xof_type squeezing(std::move(absorbing));
  EXPECT_THROW(absorbing.squeeze(prefix), std::logic_error);

  std::vector<uint8_t> suffix(47);
  squeezing.squeeze(suffix);
  std::vector<uint8_t> expected(64);
  xof_type::expand(std::string("abc"), expected);
  EXPECT_TRUE(std::equal(prefix.begin(), prefix.end(), expected.begin()));
  EXPECT_TRUE(std::equal(suffix.begin(), suffix.end(), expected.begin() + 17));

  squeezing.reset();
  squeezing.update(std::string("abc"));
  squeezing.finish();
  std::vector<uint8_t> repeated(64);
  squeezing.squeeze(repeated);
  EXPECT_EQ(expected, repeated);
}
