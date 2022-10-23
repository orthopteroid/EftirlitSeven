#ifndef _fnv1a32_H_
#define _fnv1a32_H_

#define FNV1A32_PRIME 0x01000193
#define FNV1A32_BASIS 0x811c9dc5

#ifdef __cplusplus

#include <stdint.h>

constexpr uint32_t e7_fnv1a32(const char* sz)
{
  uint32_t hash = FNV1A32_BASIS, i = 0;
  for(i = 0; sz[i] != 0; i++)
  {
    hash = (hash ^ (uint32_t)sz[i]) * FNV1A32_PRIME;
  }
  return hash;
}

constexpr uint32_t e7_fnv1a32_len(const char* sz, uint32_t len)
{
  uint32_t hash = FNV1A32_BASIS, i = 0;
  for(i = 0; (sz[i] != 0) && (i < len); i++)
  {
    hash = (hash ^ (uint32_t)sz[i]) * FNV1A32_PRIME;
  }
  return hash;
}

#else // __cplusplus

#include <linux/types.h>

uint32_t e7_fnv1a32(const char* sz);
uint32_t e7_fnv1a32_len(const char* sz, uint32_t len);

#endif // __cplusplus

#endif // _fnv1a32_H_
