#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

uint32_t swap_uint32( uint32_t val );
uint64_t swap_uint64( uint64_t val );

int is_little_endian();

uint32_t* preprocessing(char *message, uint64_t N, uint64_t l, uint64_t k);
uint32_t* prepare_message_schedule(uint32_t *M);

#endif