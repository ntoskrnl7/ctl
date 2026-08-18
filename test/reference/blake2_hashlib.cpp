/**
 * @file blake2_hashlib.cpp
 * @brief Emits BLAKE2 answers for the independent hashlib checker
 *
 * Every permitted digest byte length is instantiated, and messages from zero
 * through 512 bytes cross both sides of the BLAKE2s and BLAKE2b block
 * boundaries. Build and compare from the repository root with:
 *
 *   c++ -std=c++17 -O2 -Iinclude test/reference/blake2_hashlib.cpp \
 *       -o /tmp/blake2_hashlib
 *   python3 test/reference/blake2_hashlib.py /tmp/blake2_hashlib
 */

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <ctl/hash/blake2>

namespace {

std::vector<uint8_t> patterned(size_t size) {
  std::vector<uint8_t> result(size);
  for (size_t i = 0; i < result.size(); ++i)
    result[i] = static_cast<uint8_t>(i * 73u + 19u);
  return result;
}

template <class Hash>
void emit(const char family, size_t digest_bytes, size_t message_size,
          ctl::bytes message) {
  typename Hash::digest_t digest = {0};
  Hash::hash(message, digest);

  std::ostringstream encoded;
  encoded << std::hex << std::setfill('0');
  for (uint8_t byte : digest)
    encoded << std::setw(2) << static_cast<unsigned int>(byte);
  std::cout << family << '\t' << digest_bytes << '\t' << message_size << '\t'
            << encoded.str() << '\n';
}

template <template <size_t> class Hash, size_t... Index>
void emit_family(const char family, size_t message_size, ctl::bytes message,
                 std::index_sequence<Index...>) {
  (emit<Hash<(Index + 1) * 8>>(family, Index + 1, message_size, message), ...);
}

} // namespace

int main() {
  for (size_t size = 0; size <= 512; ++size) {
    const std::vector<uint8_t> message = patterned(size);
    emit_family<ctl::hash::blake2s>('s', size, message,
                                    std::make_index_sequence<32>());
    emit_family<ctl::hash::blake2b>('b', size, message,
                                    std::make_index_sequence<64>());
  }
}
