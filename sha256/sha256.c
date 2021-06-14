#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>

#define MAXBUFLEN 100000
#define WORD_SIZE 32
#define WORD_SIZE_BYTES 4
#define BLOCK_SIZE 512
#define BLOCK_SIZE_BYTES 64
#define WORDS_IN_BLOCK 16
#define WORDS_IN_WORKING_SCHEDULE 64
#define ROUNDS 64 // "Rounds of compression"
#define BITS_OF_ZERO_PADDING 448

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

    #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN // gcc compile-time little-endian check
        for(int i=0; i<N*WORDS_IN_BLOCK; i++){ // If little-endian, swap the bytes. SHA-2 is specified for big-endian integers.
            M[i] = swap_uint32(M[i]);
        }
    #endif

    // Padding last block after message, a one followed by k zeros to ensure 512 bit block length.
    M[(N-1)*WORDS_IN_BLOCK + (l%BLOCK_SIZE)/WORD_SIZE] |= (0x1 << ((WORD_SIZE - 1) - (l % WORD_SIZE))); // Setting 1 bit. Unsure how to do this in a better way.

    memcpy(&M[(N * WORDS_IN_BLOCK) - 2], &l, sizeof(l)); // Final 64 bits should contain the length of the message.
    
    #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN // gcc compile-time little-endian check
        uint32_t temp = M[(N * WORDS_IN_BLOCK) - 2]; // Swap the last two 32-bit words. I'm not sure how to do this in a better way.
        M[(N * WORDS_IN_BLOCK) - 2] = M[(N * WORDS_IN_BLOCK) - 1];
        M[(N * WORDS_IN_BLOCK) - 1] = temp;
    #endif

    return M;
}

// Prepare a message schedule for compression of current message block.
static uint32_t* prepare_message_schedule(uint32_t *M){
    uint32_t* W = (uint32_t*) malloc(sizeof(uint32_t) * WORDS_IN_WORKING_SCHEDULE);

    for(int i=0; i<WORDS_IN_WORKING_SCHEDULE; i++){
        if(i < WORDS_IN_BLOCK){
            W[i] = M[i];
        }else{
            W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
        }
    }

    return W;
}

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

void sha256(char *message, size_t len){
    // Initialize hash values: (first 32 bits of the fractional parts of the square roots of the first 8 primes):
    uint32_t H[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19};

    uint64_t l = len * 8; // Message length (in bits)
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

    free(M);
}

/*void hash_file(char* filename){
    char message[MAXBUFLEN+1];
    FILE *fp = fopen(filename, "r");
    if(fp != NULL){
        size_t len = fread(message, sizeof(char), MAXBUFLEN, fp);
        if(ferror( fp ) != 0) {
            fprintf(stderr, "%s: Error reading file.\n", filename);
        } else {
            message[len++] = '\0';

            sha256(message);
            printf("  %s\n", filename);
        }
        fclose(fp);
    }else{
        fprintf(stderr, "%s: No such file.\n", filename);
    }
}*/

unsigned int as_hex(char c)
{
    if ('0' <= c && c <= '9') { return c - '0'; }
    if ('a' <= c && c <= 'f') { return c + 10 - 'a'; }
    if ('A' <= c && c <= 'F') { return c + 10 - 'A'; }
    abort();
}

// Input on form "string to be hashed" or -f file2 file3 file4...
int main(int argc, char *argv[]){
    /*if(argc < 2){
        fputs("Error: No argument supplied.\n", stderr);
    }else{
        if(argc > 2 && strcmp(argv[1], "-f") == 0){ // Read from file
            for(int i=2; i<argc; i++){
                hash_file(argv[i]);
            }
        }else{ // Read from input
            sha256(argv[1]);
            printf("\n");
        }
    }*/
    char input[2000];
    while (scanf("%s\n", input) == 1) {
        size_t len = strlen(input);
        uint8_t *message = (uint8_t*) malloc(len / 2);
        for(int i=0; i<len; i+=2){
            message[i/2] = (as_hex(input[i]) << 4) + as_hex(input[i+1]);
        }
        sha256((char*)message, len/2);
        printf("\n");
        free(message);
    }
    printf("\n");
    return 0;
}