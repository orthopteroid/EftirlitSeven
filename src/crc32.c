#include "crc32.h"

#ifndef __cplusplus

uint32_t e7_crc32_tab[] = {
  CRC32_TABLE
};

uint32_t e7_crc32(const char* sz)
{
  uint32_t crc = ~0, i = 0;
  for(i = 0;  sz[i] != 0;  i++) {
      crc = (crc >> 8) ^ e7_crc32_tab[ (crc & (uint32_t)0xFF) ^ sz[i] ];
  }
  return ~crc;
}

uint32_t e7_crc32_continued(uint32_t previouscrc, const char* s, uint32_t len)
{
  uint32_t crc = ~previouscrc, i = 0;
  for(i = 0;  i < len;  i++) {
      crc = (crc >> 8) ^ e7_crc32_tab[ (crc & (uint32_t)0xFF) ^ s[i] ];
  }
  return ~crc;
}

#endif // __cplusplus


