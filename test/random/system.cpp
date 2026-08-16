/**
 * @file system.cpp
 * @author jung-kwang lee (ntoskrnl7@gmail.com)
 * @brief Random bytes from the operating system
 *
 * A generator cannot be tested for being random. What can be tested is that it
 * writes what it was asked to write, that it does not repeat, and that it does
 * not leave part of the buffer alone, which are the ways this goes wrong in
 * practice.
 *
 * @copyright Copyright (c) 2022 C++ Cryptographics template library Authors
 *
 */
#include <gtest/gtest.h>

#include <array>
#include <set>
#include <string>
#include <vector>

#include <ctl/random/system>
#include <ctl/symmetric/cipher/aes>
#include <ctl/symmetric/mode/ctr>

#include "../vectors.h"

TEST(rng, fills_the_whole_buffer) {
  // A byte the generator never touches would stay at the fill value. Over
  // enough runs, every position has to change at least once.
  const size_t size = 64;
  std::vector<bool> ever_changed(size, false);

  for (int attempt = 0; attempt < 32; ++attempt) {
    std::vector<uint8_t> buffer(size, 0xa5);
    ctl::random_bytes(buffer);
    for (size_t i = 0; i < size; ++i)
      if (buffer[i] != 0xa5)
        ever_changed[i] = true;
  }

  for (size_t i = 0; i < size; ++i)
    EXPECT_TRUE(ever_changed[i]) << "byte " << i << " was never written";
}

TEST(rng, does_not_repeat) {
  std::set<std::string> seen;
  for (int i = 0; i < 64; ++i) {
    std::vector<uint8_t> buffer(32);
    ctl::random_bytes(buffer);
    EXPECT_TRUE(seen.insert(test::to_hex(buffer)).second)
        << "the same 32 bytes came back twice";
  }
}

// Sixteen zero bytes is what an uninitialised buffer looks like and what a
// generator that quietly did nothing would leave behind.
TEST(rng, does_not_return_all_zeroes) {
  for (int i = 0; i < 32; ++i) {
    std::vector<uint8_t> buffer(16, 0);
    ctl::random_bytes(buffer);
    EXPECT_NE(std::string(32, '0'), test::to_hex(buffer));
  }
}

TEST(rng, handles_every_length) {
  // Lengths around the sizes the platform sources have limits at.
  for (size_t size : {size_t(0), size_t(1), size_t(15), size_t(16), size_t(255),
                      size_t(256), size_t(257), size_t(1024)}) {
    std::vector<uint8_t> buffer(size, 0x5a);
    EXPECT_NO_THROW(ctl::random_bytes(buffer)) << "size = " << size;
    if (size >= 16) {
      // The tail is what a source with a per call limit gets wrong.
      const std::string tail = test::to_hex(buffer.data() + size - 16, 16);
      EXPECT_NE(std::string(32, '5'), tail) << "size = " << size;
    }
  }
}

// BCryptGenRandom accepts a ULONG length. A 64 bit view therefore has to be
// divided rather than narrowed, or a successful call would leave its tail
// untouched. This exercises the boundary without allocating four gigabytes.
TEST(rng, windows_sized_requests_are_split_before_narrowing) {
  const size_t limit = static_cast<size_t>(UINT32_MAX);
  EXPECT_EQ(size_t(17), ctl::detail::bcrypt_request_size(17));
  EXPECT_EQ(limit, ctl::detail::bcrypt_request_size(limit));
  if constexpr (sizeof(size_t) > sizeof(uint32_t)) {
    EXPECT_EQ(limit, ctl::detail::bcrypt_request_size(limit + size_t(1)));
  }
}

// The whole reason this exists: a nonce that must not repeat, filled by
// something whose length the type states.
TEST(rng, fills_a_nonce_of_the_length_the_mode_wants) {
  using aes128 = ctl::symmetric::cipher::aes<128>;
  namespace mode = ctl::symmetric::mode;

  ctl::rng random;
  mode::ctr<aes128>::nonce_t first = {0};
  mode::ctr<aes128>::nonce_t second = {0};
  random.fill(first);
  random.fill(second);

  EXPECT_NE(test::to_hex(&first[0], sizeof(first)),
            test::to_hex(&second[0], sizeof(second)));

  // And it is usable where it was meant to go.
  const std::vector<uint8_t> key(aes128::key_size);
  const std::vector<uint8_t> plain(64);
  std::vector<uint8_t> a(64);
  std::vector<uint8_t> b(64);
  mode::ctr<aes128> ctr(key);
  ctr.crypt(first, 0, plain, a);
  ctr.crypt(second, 0, plain, b);
  EXPECT_NE(test::to_hex(a), test::to_hex(b));
}

// Roughly even bits. This will not catch a subtly biased source and is not
// meant to; it catches one that is stuck or that returns a counter.
TEST(rng, the_bits_are_not_obviously_lopsided) {
  std::vector<uint8_t> buffer(8192);
  ctl::random_bytes(buffer);

  size_t ones = 0;
  for (uint8_t byte : buffer)
    for (int bit = 0; bit < 8; ++bit)
      ones += (byte >> bit) & 1u;

  const size_t total = buffer.size() * 8;
  EXPECT_GT(ones, total * 45 / 100);
  EXPECT_LT(ones, total * 55 / 100);
}
