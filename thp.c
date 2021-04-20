/**********************************************************************
 * Copyright (c) 2019 Auston                                           *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

//   compile with:
//   gcc thp.c -I . -L lib
//   gcc thp.c -I . -L lib -I ../secp256k1fu -I ../secp256k1fu/src -I ../fasthash


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 

#include "fasthash.c"
#include "sha2.c"
#include "ripemd160.c"
#include "bulkprivkey.c"
#include "hash.c"

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

unsigned char *safe_calloc2(size_t length,size_t dataSize){
    unsigned char *tmp;
    if ((tmp = calloc(length,dataSize)) == NULL) {
        printf("ERROR: calloc failed");
        exit(0);
    }
    return tmp;
}

//fffffffffffffffffffffffffffffffe
//baaedce6af48a03bbfd2 5e8cd0363f29  private key
const unsigned char baseline_privatekey[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x3f, 0x29
};

//048b73fbfa60c7405870e7c8030d16f7
//421d693fdfa27938c2c86d0782122e27
//8fc44168ef3a8a373104d0fa3460b121
//caeb51dcb0f0003d4ada7702660496ef
const unsigned char baseline_publickey[65] = {
    0x04, 0x8b, 0x73, 0xfb, 0xfa, 0x60, 0xc7, 0x40, 0x58, 0x70, 0xe7, 0xc8, 0x03, 0x0d, 0x16, 0xf7,
    0x42, 0x1d, 0x69, 0x3f, 0xdf, 0xa2, 0x79, 0x38, 0xc2, 0xc8, 0x6d, 0x07, 0x82, 0x12, 0x2e, 0x27,
    0x8f, 0xc4, 0x41, 0x68, 0xef, 0x3a, 0x8a, 0x37, 0x31, 0x04, 0xd0, 0xfa, 0x34, 0x60, 0xb1, 0x21,
    0xca, 0xeb, 0x51, 0xdc, 0xb0, 0xf0, 0x00, 0x3d, 0x4a, 0xda, 0x77, 0x02, 0x66, 0x04, 0x96, 0xef, 0xe5
};

//98b4d51cd757b79abe5889246956ea8f87744b42
const unsigned char baseline_publickeycompress[20] = {
    0x98, 0xb4, 0xd5, 0x1c, 0xd7, 0x57, 0xb7, 0x9a, 0xbe, 0x58, 0x89, 0x24, 0x69, 0x56, 0xea, 0x8f, 0x87, 0x74, 0x4b, 0x42
};

void loadhashtable(hashtable_t *hashtable)
{
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    size_t read;

    fp = fopen("huge500pubk.csv", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    printf("Retrieved lines of file huge500pubk.csv!");
    while ((read = getline(&line, &len, fp)) != -1) {
        printf("%s", line);
        const char sep = ';';
        char *token1;
        char *token2;

        token1 = strtok(line, &sep);  /* get the first  token */
        token2 = strtok(NULL, &sep); /* get the second token */
        
        ht_set( hashtable, token1, token2 );
        //printf("%s", line);
    }

    fclose(fp);
    if (line)
        free(line);
    return;
}


int main(int argc, char **argv) {
    unsigned int bmul_size  = ( argc > 2 ? atoi(argv[1]) : 20 );    // ecmult_big window size in bits
    unsigned int batch_size = ( argc > 3 ? atoi(argv[2]) : 16 );    // ecmult_batch size in keys
    

    printf("bmul  size = %u\n", bmul_size);
    printf("batch size = %u\n", batch_size);
    printf("\n");

    hashtable_t *hashtable = ht_create( 65536 );
    loadhashtable(hashtable);

    unsigned char *privkey  = (unsigned char*)safe_calloc2(batch_size * 32, sizeof(unsigned char));
    unsigned char *publkey  = (unsigned char*)safe_calloc2(batch_size * 65, sizeof(unsigned char));

    secp256k1_batch_create_context(bmul_size, batch_size);
    
    clock_t start, end;
    start = clock();
    
    int test_count = 65536;
    long total_keys = 0;
    double cpu_time_used;
    for ( size_t batch = 0; batch < test_count / batch_size; batch++ ) {
        total_keys+=batch_size;
        for ( size_t i = 0; i < batch_size; i++ ) {
            rand_privkey(&privkey[32 * i]);
        }
        
        //test knowed pk
        memcpy(privkey,baseline_privatekey,32);

        //if(memcmp(privkey,baseline_privatekey,32)==0){
        //    printf( "-- private key ok-- \n");
        //}

        secp256k1_batch_generate_publkey(privkey, publkey);

        //if(memcmp(publkey,baseline_publickey,65)==0){
        //    printf( "-- public key ok-- \n");
        //}

        for ( size_t i = 0; i < batch_size; i++ ) {
            unsigned char *pk = &( privkey[32 * i]);
            unsigned char *pb = &(  publkey[65 * i]);
            unsigned char *pbcomp = (unsigned char*)safe_calloc2(20, sizeof(unsigned char));

            fasthash_compress_pubkey(pb, pbcomp);
            //printf("  pubcomp  = "); hex_dump(pbcomp, 20); printf("\n");
            unsigned char *adr = ht_get( hashtable, pbcomp );

            if(adr != NULL){
                printf( "%s\n",  adr);
                printf("Batch verification sucess on batch %zu item %zu\n", batch, i);
                printf("  privkey  = "); hex_dump(pk, 32); printf("\n");
                printf("  publkey  = "); hex_dump(pb, 65); printf("\n");
                printf("  pubcomp  = "); hex_dump(pbcomp, 20); printf("\n");
            }
            free(pbcomp);
        }
        if(total_keys % 100000){
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("testing key/sec   = %12.2f\n", total_keys / cpu_time_used);
        }


    }

    free(privkey); free(publkey);
    printf("Batched verification passed\n");
    printf("\n");

    return 0;
}
