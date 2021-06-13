#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE 16 // AES block size is 128 bits (16 bytes)
#define KEY_SIZE 16 // AES-128

// All bytes are interpreted as finite field elements of GF(2^8).
// Addition of polynomials in GF(2^8) is performed with the XOR operation on their bit representations.
// Multiplication is performed modulo an irreducible polynomial m(x).

// Bit representation of the irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1.
static const uint8_t m = 0x1b;

// Multiplying a polynomial by x (or 0x02)
static inline uint8_t xtime(uint8_t a){
    if(a & 0x80){ // If the degree is already 7, we need to subtract a by m(x) once. Subtraction is equivalent to an XOR operation for GF(2).
        return (a << 1) ^ m;
    }else{
        return a << 1;
    }
}

static inline void sub_bytes(uint8_t* state){

}

static inline void shift_rows(uint8_t* state){

}

static inline void mix_columns(uint8_t* state){

}

static inline void add_round_key(uint8_t* state){
    
}

int main(int argc, char *argv[]){
    char *message = "Detta är texten"; // 128-bit message
    uint8_t* state = (uint8_t*) malloc(BLOCK_SIZE);
    memcpy(state, message, BLOCK_SIZE);
    for(int i=0; i<BLOCK_SIZE; i++){
        printf("%02x\n", state[i]);
    }
    free(state);
    return 0;
}