/**
 * @file shake_hashlib.cpp
 * @brief Emits SHAKE answers for the independent hashlib checker
 *
 * Input and output sizes cross both SHAKE rates and their immediate
 * boundaries. Build and compare from the repository root with:
 *
 *   c++ -std=c++17 -O2 -Iinclude test/reference/shake_hashlib.cpp \
 *       -o /tmp/shake_hashlib
 *   python3 test/reference/shake_hashlib.py /tmp/shake_hashlib
 */

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include <ctl/hash/shake>

namespace {

const size_t sizes[] = {0,   1,   2,   7,   31,  63,  127, 135, 136,
                        137, 167, 168, 169, 199, 200, 255, 256, 271,
                        272, 273, 335, 336, 337, 511, 512};

std::vector<uint8_t> patterned(size_t size) {
  std::vector<uint8_t> result(size);
  for (size_t i = 0; i < result.size(); ++i)
    result[i] = static_cast<uint8_t>(i * 73u + 19u);
  return result;
}

template <class Xof>
void emit(char family, size_t message_size, ctl::bytes message,
          size_t output_size) {
  std::vector<uint8_t> output(output_size);
  Xof::expand(message, output);

  std::ostringstream encoded;
  encoded << std::hex << std::setfill('0');
  for (uint8_t byte : output)
    encoded << std::setw(2) << static_cast<unsigned int>(byte);
  std::cout << family << '\t' << message_size << '\t' << output_size << '\t'
            << encoded.str() << '\n';
}

template <class Xof> void emit_family(char family) {
  for (size_t message_size : sizes) {
    const std::vector<uint8_t> message = patterned(message_size);
    for (size_t output_size : sizes)
      emit<Xof>(family, message_size, message, output_size);
  }
}

} // namespace

int main() {
  emit_family<ctl::hash::shake128>('1');
  emit_family<ctl::hash::shake256>('2');
}
