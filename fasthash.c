/**********************************************************************
 * Copyright (c) 2019 Auston                                           *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

//   compile with:
//   gcc fasthash.c sha2.c ripemd160.c -I . -c -fPIC
//   gcc -shared -o fasthash.so fasthash.o sha2.o ripemd160.o

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha2.h"
#include "ripemd160.h"
#include "fasthash.h"

/*
void rand_privkey(unsigned char *privkey) {
    // Not cryptographically secure, but good enough for quick verification tests
    for ( size_t pos = 0; pos < 32; pos++ ) {
        privkey[pos] = rand() & 0xFF;
    }
}

void hex_dump(void *data, size_t len) {
    unsigned char *chr = data;
    for ( size_t pos = 0; pos < len; pos++, chr++ ) { printf("%02x ", *chr & 0xFF); }
}


void *safe_calloc(size_t num, size_t size) {
    void *rtn = calloc(num, size);
    if ( !rtn ) {
        printf("calloc failed to allocate %zu items of size %zu\n", num, size);
        exit(EXIT_FAILURE);
    }
    return rtn;
}
*/
unsigned char *safe_calloc2(size_t length,size_t dataSize);

//048b73fbfa60c7405870e7c8030d16f7
//421d693fdfa27938c2c86d0782122e27
//8fc44168ef3a8a373104d0fa3460b121
//caeb51dcb0f0003d4ada7702660496ef
const unsigned char baseline_sample[65] = {
    0x04, 0x8b, 0x73, 0xfb, 0xfa, 0x60, 0xc7, 0x40, 0x58, 0x70, 0xe7, 0xc8, 0x03, 0x0d, 0x16, 0xf7,
    0x42, 0x1d, 0x69, 0x3f, 0xdf, 0xa2, 0x79, 0x38, 0xc2, 0xc8, 0x6d, 0x07, 0x82, 0x12, 0x2e, 0x27,
    0x8f, 0xc4, 0x41, 0x68, 0xef, 0x3a, 0x8a, 0x37, 0x31, 0x04, 0xd0, 0xfa, 0x34, 0x60, 0xb1, 0x21,
    0xca, 0xeb, 0x51, 0xdc, 0xb0, 0xf0, 0x00, 0x3d, 0x4a, 0xda, 0x77, 0x02, 0x66, 0x04, 0x96, 0xef, 0xe5
};

//98b4d51cd757b79abe5889246956ea8f87744b42
const unsigned char expected[20] = {
    0x98, 0xb4, 0xd5, 0x1c, 0xd7, 0x57, 0xb7, 0x9a, 0xbe, 0x58, 0x89, 0x24, 0x69, 0x56, 0xea, 0x8f, 0x87, 0x74, 0x4b, 0x42
};

void fasthash_compress_pubkey(unsigned char *pubkey, unsigned char *result2){
    unsigned char *result1 = (unsigned char*)safe_calloc2(32, sizeof(unsigned char));
    sha256(pubkey,65,result1);
    ripemd160(result1,32,result2);
    free(result1);
    return ;
}

/*
int main(int argc, char **argv) {
    unsigned int param   = ( argc > 1 ? atoi(argv[1]) : 16 );    // Number of iterations as 2^N
 
    printf("param = %u\n", param);
    printf("\n");

    // Verify serial pubkey generation
    unsigned char *sample = (unsigned char*)safe_calloc(1, 65 * sizeof(unsigned char));
    unsigned char *actual = (unsigned char*)safe_calloc(1, 20 * sizeof(unsigned char));
    unsigned char *result2 = (unsigned char*)safe_calloc(1, 20 * sizeof(unsigned char));

    // Quick baseline test to make sure we can trust our "expected" results
    //memcpy(privkey,  baseline_privkey,  32);
    memcpy(sample, baseline_sample, 65);
    result2 = fasthash_compress_pubkey(sample);

    printf("  expected = "); hex_dump(expected, 20); printf("\n");
    printf("  actual   = "); hex_dump(result2,  20); printf("\n");
    if ( memcmp(expected, result2, 20) != 0 ) {
        printf("Baseline verification failed\n");
        return 1;
    }
    printf("Baseline verification finished.\n");
    return 0;
}
*/