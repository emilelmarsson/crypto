#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

// Choice function; if a is 1 pick b, otherwise pick c.
static inline uint32_t ch(uint32_t a, uint32_t b, uint32_t c){
    return (a & b) ^ ((~a) & c);
}

// Majority function (speaks for itself)
static inline uint32_t maj(uint32_t a, uint32_t b, uint32_t c){
    return (a & b) ^ (a & c) ^ (b & c);
}

// Bitwise circular right shift function (from Wikipedia)
static inline uint32_t rotr (uint32_t value, unsigned int count) {
    const unsigned int mask = CHAR_BIT * sizeof(value) - 1;
    count &= mask;
    return (value >> count) | (value << (-count & mask));
}

static inline uint32_t Sigma0(uint32_t a){
    return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
}

static inline uint32_t Sigma1(uint32_t a){
    return rotr(a, 6) ^ rotr(a, 11) ^ rotr(a, 25);
}

static inline uint32_t s0(uint32_t a){
    return rotr(a, 7) ^ rotr(a, 18) ^ (a >> 3);
}

static inline uint32_t s1(uint32_t a){
    return rotr(a, 17) ^ rotr(a, 19) ^ (a >> 10);
}

// Initialize hash values: (first 32 bits of the fractional parts of the square roots of the first 8 primes):
static uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19};

// First 32 bits of the fractional parts of the cube roots of the first 64 prime numbers.
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Byte-swapping 32-bit unsigned integer (little-endian to big-endian representation) from Stack Overflow
uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

// Byte-swapping 64-bit unsigned integer (little-endian to big-endian representation) from Stack Overflow
uint64_t swap_uint64( uint64_t val )
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}

int is_little_endian(){
    volatile uint32_t i=0x01234567;
    return (*((uint8_t*)(&i))) == 0x67;
}

uint32_t* preprocessing(char *message, uint64_t N, uint64_t l, uint64_t k){
    uint32_t* M = (uint32_t*) malloc(N * sizeof(uint32_t) * 16);

    memcpy(M, message, strlen(message)); // Read message

    if(is_little_endian()){ // If little-endian, swap the bytes. SHA-2 is specified for big-endian integers.
        for(int i=0; i<N*16; i++){
            M[i] = swap_uint32(M[i]);
        }
    }

    // Padding, 1 bit followed by k zeros to ensure 512 bit block length. Unsure how to do this in a better way.
    M[(N-1)*16 + (l%512)/32] |= (0x1 << (31 - (l % 32)));

    memcpy(&M[(N * 16) - 2], &l, sizeof(l)); // Final 64 bits should contain the length of the message in bits
    
    if(is_little_endian()){
        uint32_t temp = M[(N * 16) - 2]; // Swap the last two 32-bit words. I'm not sure how to do this in a better way.
        M[(N * 16) - 2] = M[(N * 16) - 1];
        M[(N * 16) - 1] = temp;
    }

    return M;
}

// Prepare message schedule for current message block
uint32_t* prepare_message_schedule(uint32_t *M){
    uint32_t* W = (uint32_t*) malloc(sizeof(uint32_t) * 64);

    for(int i=0; i<64; i++){
        if(i < 16){
            W[i] = M[i];
        }else{
            W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
        }
    }

    return W;
}

int main(int argc, char *argv[]){
    if(argc < 2 || argc > 2){
        printf("One argument expected.\n");
    }else{
        char *message = argv[1]; // Message

        uint64_t l = strlen(message) * 8; // Message length (in bits)
        uint64_t k = 448 - (l % 512) - 1; // Bits of zero-padding
        uint64_t N = (l / 512) + 1; // Message length (in 512-bit blocks)

        uint32_t* M = preprocessing(message, N, l, k);

        // Hash computation
        for(int i=0; i<N; i++){
            uint32_t *W = prepare_message_schedule(&M[i * 16]);

            // Initialize the eight working variables with intermediate hash value.
            uint32_t a = H[0];
            uint32_t b = H[1];
            uint32_t c = H[2];
            uint32_t d = H[3];
            uint32_t e = H[4];
            uint32_t f = H[5];
            uint32_t g = H[6];
            uint32_t h = H[7];

            // Compression function (all addition is mod 2^32)
            for(int t=0; t<64; t++){
                uint32_t T1 = h + Sigma1(e) + ch(e, f, g) + K[t] + W[t];
                uint32_t T2 = Sigma0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            H[0] = a + H[0];
            H[1] = b + H[1];
            H[2] = c + H[2];
            H[3] = d + H[3];
            H[4] = e + H[4];
            H[5] = f + H[5];
            H[6] = g + H[6];
            H[7] = h + H[7];

            free(W);
        }

        for(int i=0; i<8; i++){
            printf("%08x", H[i]);
        }
        printf("\n");

        free(M);
    }
    return 0;
}