/**
 * @file sha2_kdf.cpp
 * @brief Structural libFuzzer target for hashes, XOFs, HMAC and KDFs
 *
 * Build from the repository root with Clang:
 *
 *   clang++ -std=c++17 -Iinclude -fsanitize=fuzzer,address,undefined \
 *       test/fuzz/sha2_kdf.cpp -o sha2_kdf_fuzz
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include <ctl/hash/blake2>
#include <ctl/hash/sha2>
#include <ctl/hash/sha3>
#include <ctl/hash/shake>
#include <ctl/kdf/hkdf>
#include <ctl/kdf/pbkdf2>
#include <ctl/mac/hmac>

namespace {

void require(bool condition) {
  if (!condition)
    std::abort();
}

template <class Hash> void exercise(const uint8_t *data, size_t size) {
  const ctl::bytes input(data, size);
  const size_t first_size = size / 3;
  const size_t second_size = (size - first_size) / 2;
  const ctl::bytes key = input.first(first_size);
  const ctl::bytes salt = input.subview(first_size, second_size);
  const ctl::bytes info = input.last(size - first_size - second_size);

  typename Hash::digest_t direct = {0};
  typename Hash::digest_t streamed = {0};
  Hash::hash(input, direct);
  Hash context;
  const size_t cut = size == 0 ? 0 : data[0] % (size + 1);
  context.update(input.first(cut));
  context.update(input.subview(cut, size - cut));
  context.finish(streamed);
  require(ctl::detail::equal_constant_time(direct, streamed,
                                            Hash::digest_size));

  typedef ctl::mac::hmac<Hash> hmac_type;
  typename hmac_type::tag_t tag = {0};
  hmac_type::authenticate(key, input, tag);
  require(hmac_type::verify(key, input, tag));

  typedef ctl::kdf::hkdf<Hash> hkdf_type;
  const size_t hkdf_size =
      size == 0 ? 0 : data[size - 1] % (2 * Hash::digest_size + 1);
  std::vector<uint8_t> hkdf_output(hkdf_size);
  std::vector<uint8_t> expanded(hkdf_size);
  typename hkdf_type::prk_t prk = {0};
  hkdf_type::derive(salt, key, info, hkdf_output);
  hkdf_type::extract(salt, key, prk);
  hkdf_type::expand(prk, info, expanded);
  require(hkdf_output == expanded);

  typedef ctl::kdf::pbkdf2<Hash> pbkdf2_type;
  const size_t derived_size =
      1 + (size == 0 ? 0 : data[0] % (2 * Hash::digest_size));
  const uint32_t iterations =
      1 + (size < 2 ? 0 : static_cast<uint32_t>(data[1] % 8));
  std::vector<uint8_t> derived(derived_size);
  std::vector<uint8_t> prefix((derived_size + 1) / 2);
  pbkdf2_type::derive(key, salt, iterations, derived);
  pbkdf2_type::derive(key, salt, iterations, prefix);
  require(std::equal(prefix.begin(), prefix.end(), derived.begin()));
}

template <class Xof> void exercise_xof(const uint8_t *data, size_t size) {
  const ctl::bytes input(data, size);
  const size_t output_size =
      size == 0 ? 0 : data[size - 1] % (2 * Xof::rate + 1);
  std::vector<uint8_t> direct(output_size);
  std::vector<uint8_t> streamed(output_size);
  Xof::expand(input, direct);

  Xof context;
  const size_t input_cut = size == 0 ? 0 : data[0] % (size + 1);
  context.update(input.first(input_cut));
  context.update(input.subview(input_cut, size - input_cut));
  context.finish();
  const size_t output_cut =
      output_size == 0 || size < 2 ? 0 : data[1] % (output_size + 1);
  context.squeeze(ctl::writable_bytes(streamed).first(output_cut));
  context.squeeze(ctl::writable_bytes(streamed).subview(
      output_cut, output_size - output_cut));
  require(direct == streamed);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t selector = size == 0 ? 0 : data[0];
  switch (selector % 14) {
  case 0:
    exercise<ctl::hash::sha224>(data, size);
    break;
  case 1:
    exercise<ctl::hash::sha256>(data, size);
    break;
  case 2:
    exercise<ctl::hash::sha384>(data, size);
    break;
  case 3:
    exercise<ctl::hash::sha512>(data, size);
    break;
  case 4:
    exercise<ctl::hash::sha512_224>(data, size);
    break;
  case 5:
    exercise<ctl::hash::sha512_256>(data, size);
    break;
  case 6:
    exercise<ctl::hash::sha3_224>(data, size);
    break;
  case 7:
    exercise<ctl::hash::sha3_256>(data, size);
    break;
  case 8:
    exercise<ctl::hash::sha3_384>(data, size);
    break;
  case 9:
    exercise<ctl::hash::sha3_512>(data, size);
    break;
  case 10:
    exercise<ctl::hash::blake2s_256>(data, size);
    break;
  case 11:
    exercise<ctl::hash::blake2b_512>(data, size);
    break;
  case 12:
    exercise_xof<ctl::hash::shake128>(data, size);
    break;
  default:
    exercise_xof<ctl::hash::shake256>(data, size);
    break;
  }
  return 0;
}
