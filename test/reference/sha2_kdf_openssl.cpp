/**
 * @file sha2_kdf_openssl.cpp
 * @brief Differential check of fixed hashes, HMAC, HKDF and PBKDF2
 *
 * This is intentionally outside test/CMakeLists.txt's source globs because
 * OpenSSL is a reference implementation used by the review, not a ctl
 * dependency. Run from the repository root on a system with OpenSSL headers:
 *
 *   c++ -std=c++17 -Iinclude test/reference/sha2_kdf_openssl.cpp \
 *       -lcrypto -o fixed_hash_openssl && ./fixed_hash_openssl
 */

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include <ctl/hash/blake2>
#include <ctl/hash/sha2>
#include <ctl/hash/sha3>
#include <ctl/kdf/hkdf>
#include <ctl/kdf/pbkdf2>
#include <ctl/mac/hmac>

namespace {

const unsigned char *pointer(const std::vector<uint8_t> &value) {
  static const unsigned char empty = 0;
  return value.empty() ? &empty : value.data();
}

std::vector<uint8_t> random_bytes(std::mt19937_64 &random, size_t size) {
  std::vector<uint8_t> result(size);
  for (uint8_t &byte : result)
    byte = static_cast<uint8_t>(random());
  return result;
}

bool same(const char *operation, const char *hash_name, size_t test_case,
          const uint8_t *actual, const uint8_t *reference, size_t size) {
  if (std::equal(actual, actual + size, reference))
    return true;
  std::cerr << operation << '/' << hash_name << " differs in case "
            << test_case << '\n';
  return false;
}

template <class Hash>
bool check_case(const EVP_MD *md, const char *hash_name,
                std::mt19937_64 &random, size_t test_case) {
  static const size_t boundaries[] = {
      0,   1,   2,   27,  28,  31,  32,  55,  56,  63,  64,
      65,  71,  72,  73,  103, 104, 105, 111, 112, 127, 128,
      129, 135, 136, 137, 143, 144, 145, 255, 256, 511, 512};
  const size_t message_size =
      test_case < sizeof(boundaries) / sizeof(boundaries[0])
          ? boundaries[test_case]
          : static_cast<size_t>(random() % 700);
  const size_t key_size =
      test_case < sizeof(boundaries) / sizeof(boundaries[0])
          ? boundaries[sizeof(boundaries) / sizeof(boundaries[0]) - 1 -
                       test_case]
          : static_cast<size_t>(random() % 260);
  const std::vector<uint8_t> message = random_bytes(random, message_size);
  const std::vector<uint8_t> key = random_bytes(random, key_size);

  typename Hash::digest_t digest = {0};
  typename Hash::digest_t reference_digest = {0};
  unsigned int reference_size = 0;
  Hash::hash(message, digest);
  if (EVP_Digest(pointer(message), message.size(), reference_digest,
                 &reference_size, md, nullptr) != 1 ||
      reference_size != Hash::digest_size ||
      !same("HASH", hash_name, test_case, digest, reference_digest,
            Hash::digest_size))
    return false;

  typedef ctl::mac::hmac<Hash> hmac_type;
  typename hmac_type::tag_t tag = {0};
  typename hmac_type::tag_t reference_tag = {0};
  hmac_type::authenticate(key, message, tag);
  if (HMAC(md, pointer(key), static_cast<int>(key.size()), pointer(message),
           message.size(), reference_tag, &reference_size) == nullptr ||
      reference_size != hmac_type::tag_size ||
      !same("HMAC", hash_name, test_case, tag, reference_tag,
            hmac_type::tag_size))
    return false;

  const std::vector<uint8_t> salt =
      random_bytes(random, static_cast<size_t>(random() % 80));
  const std::vector<uint8_t> info =
      random_bytes(random, static_cast<size_t>(random() % 100));
  const size_t derived_size =
      1 + static_cast<size_t>(random() % (2 * Hash::digest_size + 19));
  std::vector<uint8_t> derived(derived_size);
  std::vector<uint8_t> reference_derived(derived_size);
  ctl::kdf::hkdf<Hash>::derive(salt, key, info, derived);

  EVP_PKEY_CTX *hkdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  size_t reference_derived_size = reference_derived.size();
  const bool hkdf_ok =
      hkdf != nullptr && EVP_PKEY_derive_init(hkdf) > 0 &&
      EVP_PKEY_CTX_hkdf_mode(hkdf,
                             EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) > 0 &&
      EVP_PKEY_CTX_set_hkdf_md(hkdf, md) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_salt(hkdf, pointer(salt),
                                  static_cast<int>(salt.size())) > 0 &&
      EVP_PKEY_CTX_set1_hkdf_key(hkdf, pointer(key),
                                 static_cast<int>(key.size())) > 0 &&
      EVP_PKEY_CTX_add1_hkdf_info(hkdf, pointer(info),
                                  static_cast<int>(info.size())) > 0 &&
      EVP_PKEY_derive(hkdf, reference_derived.data(),
                      &reference_derived_size) > 0;
  EVP_PKEY_CTX_free(hkdf);
  if (!hkdf_ok || reference_derived_size != reference_derived.size() ||
      !same("HKDF", hash_name, test_case, derived.data(),
            reference_derived.data(), derived.size()))
    return false;

  const uint32_t iterations = 1 + static_cast<uint32_t>(random() % 20);
  ctl::kdf::pbkdf2<Hash>::derive(key, salt, iterations, derived);
  if (PKCS5_PBKDF2_HMAC(
          reinterpret_cast<const char *>(pointer(key)),
          static_cast<int>(key.size()), pointer(salt),
          static_cast<int>(salt.size()), static_cast<int>(iterations), md,
          static_cast<int>(reference_derived.size()),
          reference_derived.data()) != 1 ||
      !same("PBKDF2", hash_name, test_case, derived.data(),
            reference_derived.data(), derived.size()))
    return false;

  return true;
}

} // namespace

int main() {
  std::mt19937_64 random(0x43544c2d53484132ull);
  for (size_t test_case = 0; test_case < 300; ++test_case) {
    if (!check_case<ctl::hash::sha224>(EVP_sha224(), "SHA-224", random,
                                       test_case) ||
        !check_case<ctl::hash::sha256>(EVP_sha256(), "SHA-256", random,
                                       test_case) ||
        !check_case<ctl::hash::sha384>(EVP_sha384(), "SHA-384", random,
                                       test_case) ||
        !check_case<ctl::hash::sha512>(EVP_sha512(), "SHA-512", random,
                                       test_case) ||
        !check_case<ctl::hash::sha512_224>(EVP_sha512_224(), "SHA-512/224",
                                           random, test_case) ||
        !check_case<ctl::hash::sha512_256>(EVP_sha512_256(), "SHA-512/256",
                                           random, test_case) ||
        !check_case<ctl::hash::sha3_224>(EVP_sha3_224(), "SHA3-224", random,
                                         test_case) ||
        !check_case<ctl::hash::sha3_256>(EVP_sha3_256(), "SHA3-256", random,
                                         test_case) ||
        !check_case<ctl::hash::sha3_384>(EVP_sha3_384(), "SHA3-384", random,
                                         test_case) ||
        !check_case<ctl::hash::sha3_512>(EVP_sha3_512(), "SHA3-512", random,
                                         test_case) ||
        !check_case<ctl::hash::blake2s_256>(EVP_blake2s256(), "BLAKE2s-256",
                                            random, test_case) ||
        !check_case<ctl::hash::blake2b_512>(EVP_blake2b512(), "BLAKE2b-512",
                                            random, test_case))
      return 1;
  }
  std::cout << "300 cases x 12 fixed hashes agree with OpenSSL for hashing, "
               "HMAC, HKDF and PBKDF2\n";
}
