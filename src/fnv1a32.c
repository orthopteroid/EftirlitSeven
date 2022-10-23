#include "fnv1a32.h"

#ifndef __cplusplus

uint32_t e7_fnv1a32(const char* sz)
{
  uint32_t hash = FNV1A32_BASIS, i = 0;
  for(i = 0; sz[i] != 0; i++)
  {
    hash = (hash ^ (uint32_t)sz[i]) * FNV1A32_PRIME;
  }
  return hash;
}

uint32_t e7_fnv1a32_len(const char* sz, uint32_t len)
{
  uint32_t hash = FNV1A32_BASIS, i = 0;
  for(i = 0; (sz[i] != 0) && (i < len); i++)
  {
    hash = (hash ^ (uint32_t)sz[i]) * FNV1A32_PRIME;
  }
  return hash;
}

#endif // __cplusplus


