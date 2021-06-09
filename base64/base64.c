#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define ENCODE_SIXTET(s) (s == -1 ? '=' : (s < 26 ? s+'A' : (s < 52 ? (s-26)+'a' : (s < 62 ? (s-52)+'0' : (s == 62 ? '+' : '/')))))

char* encode(char *m){
    size_t len = strlen(m);
    size_t new_len = (1 + ((len - 1) / 3)) * 4 + 1; // (ceil(len / 3) * 4) + 1
    char *d = (char*) malloc(new_len);
    
    int s1, s2, s3, s4;
    for(int i=0,j=0; i<len; i+=3,j+=4){
        s1 = ((uint8_t)m[i]) >> 2;
        s2 = ((((uint8_t)m[i]) & 0x3) << 4);
        if(len - i > 1){
            s2 ^= (((uint8_t)m[i+1]) >> 4);
            s3 = ((((uint8_t)m[i+1]) & 0xf) << 2);
            if(len - i > 2){
                s3 ^= (((uint8_t)m[i+2]) >> 6);
                s4 = ((uint8_t)m[i+2]) & 0x3f;
            }else{
                s4 = -1;
            }
        }else{
            s2 ^= 0;
            s3 = -1;
            s4 = -1;
        }

        d[j] = ENCODE_SIXTET(s1);
        d[j+1] = ENCODE_SIXTET(s2);
        d[j+2] = ENCODE_SIXTET(s3);
        d[j+3] = ENCODE_SIXTET(s4);
    }

    d[new_len - 1] = '\0';
    return d;
}

int main(int argc, char *argv[]){
    char* d = encode(argv[1]);
    printf("%s\n", d);
    free(d);
    return 0;
}