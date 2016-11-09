#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
  #define EXPORT __declspec(dllexport)
#else
  #define EXPORT extern
#endif

EXPORT uint64_t compute_hash(const uint8_t *in, uint32_t len);
EXPORT uint32_t hash32(uint8_t* buffer, uint32_t len);
EXPORT uint32_t hash32salt(uint8_t* buffer, uint32_t len, uint32_t salt);
EXPORT uint64_t hash64salt(uint8_t* buffer, uint32_t len, uint32_t salt);
EXPORT uint64_t hash64salt64(uint8_t* buffer, uint32_t len, uint64_t salt);