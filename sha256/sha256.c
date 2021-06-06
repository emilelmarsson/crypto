#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

// Choice function; if a is 1 pick b, otherwise pick c.
static inline uint32_t ch(uint32_t a, uint32_t b, uint32_t c){
    return (a & b) ^ ((~a) & c);
}

// Majority function
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

// Byte-swapping 32-bit unsigned integer (little-endian to big-endian representation) from Stack Overflow
static inline uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

// Byte-swapping 64-bit unsigned integer (little-endian to big-endian representation) from Stack Overflow
static inline uint64_t swap_uint64( uint64_t val )
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}

static uint32_t* preprocessing(char *message, uint64_t N, uint64_t l, uint64_t k){
    uint32_t* M = (uint32_t*) malloc(N * BLOCK_SIZE_BYTES);

    memcpy(M, message, l / 8); // Read message

    #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN // If little-endian, swap the bytes. SHA-2 is specified for big-endian integers.
        for(int i=0; i<N*16; i++){
            M[i] = swap_uint32(M[i]);
        }
    #endif

    // Padding last block after message, a one followed by k zeros to ensure 512 bit block length.
    M[(N-1)*16 + (l%BLOCK_SIZE)/WORD_SIZE] |= (0x1 << ((WORD_SIZE - 1) - (l % WORD_SIZE))); // Setting 1 bit. Unsure how to do this in a better way.

    memcpy(&M[(N * WORDS_IN_BLOCK) - 2], &l, sizeof(l)); // Final 64 bits should contain the length of the message.
    
    #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN // gcc compile-time little-endian check
        uint32_t temp = M[(N * 16) - 2]; // Swap the last two 32-bit words. I'm not sure how to do this in a better way.
        M[(N * 16) - 2] = M[(N * 16) - 1];
        M[(N * 16) - 1] = temp;
    #endif

    return M;
}

// Prepare a message schedule for compression of current message block.
static uint32_t* prepare_message_schedule(uint32_t *M){
    uint32_t* W = (uint32_t*) malloc(sizeof(uint32_t) * WORDS_IN_WORKING_SCHEDULE);

    for(int i=0; i<WORDS_IN_WORKING_SCHEDULE; i++){
        if(i < 16){
            W[i] = M[i];
        }else{
            W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
        }
    }

    return W;
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

int main(int argc, char *argv[]){
    if(argc < 2 || argc > 2){
        printf("One argument expected.\n");
    }else{
        char *message = argv[1]; // Message

        uint64_t l = strlen(message) * 8; // Message length (in bits)
        uint64_t k = (BITS_OF_ZERO_PADDING - (l % BLOCK_SIZE) - 1) % BLOCK_SIZE; // Bits of zero-padding (final 64 bits contain the length of the message)
        uint64_t N = (l / BLOCK_SIZE) + 1; // Message length (in 512-bit blocks)

        uint32_t* M = preprocessing(message, N, l, k);

        // Hash computation
        for(int i=0; i<N; i++){
            uint32_t *W = prepare_message_schedule(&M[i * WORDS_IN_BLOCK]);

            // Initialize the eight working variables with first/intermediate hash value.
            uint32_t a = H[0];
            uint32_t b = H[1];
            uint32_t c = H[2];
            uint32_t d = H[3];
            uint32_t e = H[4];
            uint32_t f = H[5];
            uint32_t g = H[6];
            uint32_t h = H[7];

            // Compression function
            for(int t=0; t<ROUNDS; t++){
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

            // Calculate intermediate hash value
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

        // Print final hash values
        for(int i=0; i<8; i++){
            printf("%08x", H[i]);
        }
        printf("\n");

        free(M);
    }
    return 0;
}