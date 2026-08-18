/**
 * @file rbg.cpp
 * @brief Entropy, reseed, ownership and fork tests for the RBG policy
 */
#include <gtest/gtest.h>

#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <ctl/hash/sha2>
#include <ctl/random/ctr_drbg>
#include <ctl/random/hash_drbg>
#include <ctl/random/hmac_drbg>
#include <ctl/random/rbg>
#include <ctl/symmetric/cipher/aes>

namespace {

struct entropy_state {
  size_t fills = 0;
  bool fail = false;
};

struct deterministic_entropy {
  entropy_state *state;

  void fill(ctl::writable_bytes output) {
    if (state->fail)
      throw std::runtime_error("injected entropy failure");
    ++state->fills;
    for (size_t i = 0; i < output.size(); ++i)
      output.data()[i] =
          static_cast<uint8_t>((state->fills * 37u + i) & 0xffu);
  }
};

using drbg = ctl::hmac_drbg<ctl::hash::sha256>;
using test_rbg = ctl::rbg<drbg, deterministic_entropy>;

static_assert(!std::is_copy_constructible<test_rbg>::value,
              "an RBG stream must have one owner");
static_assert(std::is_move_constructible<test_rbg>::value,
              "an RBG may transfer its one state");

} // namespace

TEST(rbg, seeds_and_automatically_reseeds_at_the_selected_interval) {
  entropy_state state;
  test_rbg random(deterministic_entropy{&state}, {}, 1);
  EXPECT_EQ(2u, state.fills); // entropy and nonce at instantiation

  std::vector<uint8_t> first(32), second(32);
  random.generate(first);
  EXPECT_EQ(2u, state.fills);
  EXPECT_EQ(1u, random.requests_since_reseed());

  random.generate(second);
  EXPECT_EQ(3u, state.fills); // one entropy input for reseed
  EXPECT_EQ(1u, random.requests_since_reseed());
  EXPECT_NE(first, second);
}

TEST(rbg, fresh_generation_and_explicit_reseed_get_new_entropy) {
  entropy_state state;
  test_rbg random(deterministic_entropy{&state}, {}, 100);
  std::vector<uint8_t> output(32);

  random.generate_fresh(output);
  EXPECT_EQ(3u, state.fills);
  EXPECT_EQ(1u, random.requests_since_reseed());

  random.reseed();
  EXPECT_EQ(4u, state.fills);
  EXPECT_EQ(0u, random.requests_since_reseed());
}

TEST(rbg, entropy_failure_does_not_advance_the_drbg) {
  entropy_state state;
  test_rbg random(deterministic_entropy{&state}, {}, 1);
  std::vector<uint8_t> output(32);
  random.generate(output);
  EXPECT_EQ(1u, random.requests_since_reseed());

  state.fail = true;
  EXPECT_THROW(random.generate(output), std::runtime_error);
  EXPECT_EQ(1u, random.requests_since_reseed());

  state.fail = false;
  EXPECT_NO_THROW(random.generate(output));
  EXPECT_EQ(1u, random.requests_since_reseed());
}

TEST(rbg, move_disables_the_source_object) {
  entropy_state state;
  test_rbg source(deterministic_entropy{&state});
  test_rbg moved(std::move(source));
  std::vector<uint8_t> output(16);
  EXPECT_THROW(source.generate(output), std::logic_error);
  EXPECT_NO_THROW(moved.generate(output));
}

TEST(rbg, validates_the_automatic_reseed_interval) {
  entropy_state state;
  EXPECT_THROW(test_rbg(deterministic_entropy{&state}, {}, 0),
               std::invalid_argument);
  EXPECT_THROW(test_rbg(deterministic_entropy{&state}, {},
                        drbg::reseed_interval + 1),
               std::invalid_argument);
  EXPECT_EQ(0u, state.fills);
}

TEST(rbg, rejects_bad_requests_before_obtaining_reseed_entropy) {
  entropy_state state;
  test_rbg random(deterministic_entropy{&state}, {}, 1);
  std::vector<uint8_t> ordinary(32);
  random.generate(ordinary);
  ASSERT_EQ(2u, state.fills);

  std::vector<uint8_t> too_large(drbg::max_per_request + 1);
  EXPECT_THROW(random.generate_fresh(too_large), std::length_error);
  EXPECT_EQ(2u, state.fills);
  EXPECT_EQ(1u, random.requests_since_reseed());

  EXPECT_THROW(random.generate(ordinary, ordinary), std::invalid_argument);
  EXPECT_EQ(2u, state.fills);
  EXPECT_EQ(1u, random.requests_since_reseed());
}

TEST(rbg, default_system_source_produces_distinct_requests) {
  ctl::rbg<drbg> random;
  std::vector<uint8_t> first(32), second(32);
  random.generate(first);
  random.generate(second);
  EXPECT_NE(first, second);
}

TEST(rbg, composes_with_every_conditioned_drbg_family) {
  entropy_state ctr_state;
  using ctr_type =
      ctl::ctr_drbg<ctl::symmetric::cipher::aes<256>>;
  ctl::rbg<ctr_type, deterministic_entropy> ctr(
      deterministic_entropy{&ctr_state});
  std::vector<uint8_t> ctr_output(32);
  EXPECT_NO_THROW(ctr.generate(ctr_output));

  entropy_state hash_state;
  using hash_type = ctl::hash_drbg<ctl::hash::sha256>;
  ctl::rbg<hash_type, deterministic_entropy> hash(
      deterministic_entropy{&hash_state});
  std::vector<uint8_t> hash_output(32);
  EXPECT_NO_THROW(hash.generate(hash_output));
  EXPECT_NE(ctr_output, hash_output);
}

#if defined(__unix__) || defined(__APPLE__)
TEST(rbg, a_forked_child_reseeds_before_generating) {
  entropy_state state;
  test_rbg random(deterministic_entropy{&state}, {}, 100);
  ASSERT_EQ(2u, state.fills);

  int channel[2];
  ASSERT_EQ(0, ::pipe(channel));
  const pid_t child = ::fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    ::close(channel[0]);
    int result = 0;
    try {
      std::vector<uint8_t> output(16);
      random.generate(output);
      result = static_cast<int>(state.fills);
    } catch (...) {
      result = -1;
    }
    const ssize_t written = ::write(channel[1], &result, sizeof(result));
    ::close(channel[1]);
    ::_exit(written == static_cast<ssize_t>(sizeof(result)) ? 0 : 2);
  }

  ::close(channel[1]);
  int child_fills = 0;
  const ssize_t read_size =
      ::read(channel[0], &child_fills, sizeof(child_fills));
  ::close(channel[0]);
  int status = 0;
  ASSERT_EQ(child, ::waitpid(child, &status, 0));
  ASSERT_EQ(static_cast<ssize_t>(sizeof(child_fills)), read_size);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
  EXPECT_EQ(3, child_fills); // one reseed entropy fill after the PID changed
  EXPECT_EQ(2u, state.fills); // the parent's source was not touched
}
#endif
