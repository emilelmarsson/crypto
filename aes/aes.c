#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// All bytes are interpreted as finite field elements.
// Addition and multiplication in AES are defined for the finite field GF(2^8) / m(x).

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

int main(int argc, char *argv[]){

    return 0;
}