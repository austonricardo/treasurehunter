/**********************************************************************
 * Copyright (c) 2019 Auston                                           *
 **********************************************************************/

//   compile with:
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I src/ -I ./ thp.c -lgmp -o thp


#include <stdio.h>
#include <stdlib.h>
#include <time.h> 

#include "fasthash.c"
#include "sha2.c"
#include "ripemd160.c"
#include "bulkprivkey.c"
#include "hashmap.c"

//Hashmap configuration - Start
#define KEY_LENGTH (20)
#define KEY_PREFIX ("")
#define KEY_COUNT (1024)
#define VALUE_MAX_LENGTH (34)
#define TEST false

typedef struct data_struct_s
{
    unsigned char key_string[KEY_LENGTH];
    unsigned char value[VALUE_MAX_LENGTH];
} data_struct_t;
//Hashmap configuration - End


void rand_privkey(unsigned char *privkey) {
    // Not cryptographically secure, but good enough for quick verification tests
    for ( size_t pos = 0; pos < 32; pos++ ) {
        privkey[pos] = rand() & 0xFF;
    }
}

void hex_dump(void *data, size_t len) {
    unsigned char *chr = data;
    for ( size_t pos = 0; pos < len; pos++, chr++ ) { printf("%02x", *chr & 0xFF); }
}

void hex_file_dump(FILE* f, void *data, size_t len) {
    unsigned char *chr = data;
    for ( size_t pos = 0; pos < len; pos++, chr++ ) { fprintf(f,"%02x", *chr & 0xFF); }
}

void logger(FILE * log,unsigned char* pk, unsigned char* pbcomp, unsigned char* adr){
    fprintf(log, "adr:%s pub:",adr);
    hex_file_dump(log,pbcomp, 20);
    fprintf(log," prk:");
    hex_file_dump(log,pk, 32);
    fprintf(log,"\n");
    return;
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

uint8_t hextobin(const char * str, unsigned char * bytes, size_t blen)
{
   uint8_t pos;
   uint8_t idx0;
   uint8_t idx1;

   // mapping of ASCII characters to hex values
   const unsigned char charmap[] =
   {
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
     0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
     0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
     0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
   };

   bzero(bytes, blen);
   for (pos = 0; ((pos < (blen*2)) && (pos < strlen(str))); pos += 2)
   {
      idx0 = (uint8_t)str[pos+0];
      idx1 = (uint8_t)str[pos+1];
      bytes[pos/2] = (unsigned char)(charmap[idx0] << 4) | charmap[idx1];
   };

   return(0);
}

void loadhashtable(map_t *hashtable)
{
    FILE * fp;
    unsigned char * line = NULL;
    size_t len = 0;
    size_t read;

    fp = fopen("adrblc.db6", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    printf("Retrieved content of file huge500pubk.csv\n");
    const char sep[2] = ";";
    while ((read = getline(&line, &len, fp)) != -1) {
        printf("%s\n", line);
        unsigned char *token1;
        unsigned char *token2;
        unsigned char *key = (unsigned char *)malloc(sizeof(unsigned char)*20);

        token1 = strtok(line, &sep);  /* get the first  token */
        token2 = strtok(NULL, &sep); /* get the second token */
        
        /* Store the key string along side the numerical value so we can free it later */
        data_struct_t* item = (data_struct_t*)malloc(sizeof(data_struct_t));
        //printf("foi token2:%s token1: %s\n",token2,token1);
        hextobin(token1, key, KEY_LENGTH);

        //printf("  key  = "); hex_dump(key, KEY_LENGTH); printf("\n");

        memcpy(item->key_string,key,KEY_LENGTH);
        memcpy(item->value,token2,VALUE_MAX_LENGTH);

        int status = hashmap_put(hashtable, key, item);
        if(status==MAP_OK){
            printf(" hashmapped :"); hex_dump(item->key_string, KEY_LENGTH); printf(" -> "); hex_dump(item->value, VALUE_MAX_LENGTH); printf("\n");
        }else{
            printf("put %s in hashmap failed with error: %s\n", token1,status);
        }
    }

    fclose(fp);
    if (line)
        free(line);
    return;
}


int main(int argc, char **argv) {
    unsigned int bmul_size  = ( argc > 1 ? atoi(argv[1]) : 18 );    // ecmult_big window size in bits
    unsigned int batch_size = ( argc > 2 ? atoi(argv[2]) : 16 );    // ecmult_batch size in keys
    
    printf("bmul  size = %u\n", bmul_size);
    printf("batch size = %u\n", batch_size);
    printf("\n");

    unsigned char *privkey  = (unsigned char*)safe_calloc2(batch_size * 32, sizeof(unsigned char));
    unsigned char *publkey  = (unsigned char*)safe_calloc2(batch_size * 65, sizeof(unsigned char));

    secp256k1_batch_create_context(bmul_size, batch_size);

    int status;
    map_t mymap;
    //unsigned char key_string[KEY_LENGTH];
    data_struct_t* value;
    value = malloc(sizeof(data_struct_t));
    mymap = hashmap_new();
    loadhashtable(mymap);
    /* Store the key string along side the numerical value so we can free it later */

    //log file
    FILE *log = fopen("thm.log", "a+");


    int test_count = 1024 * 1024;
    long total_keys = 0;
    double cpu_time_used;
    unsigned char find_key[KEY_LENGTH];

    clock_t start, end;
    start = clock();
    size_t batch = 0;

    while (  batch < test_count / batch_size) {
        batch++;
        total_keys+=batch_size;
        for ( size_t i = 0; i < batch_size; i++ ) {
            rand_privkey(&privkey[32 * i]);
        }
        
        if(TEST){
            //test knowed pk
            memcpy(privkey,baseline_privatekey,32);
        }

        secp256k1_batch_generate_publkey(privkey, publkey);

        for ( size_t i = 0; i < batch_size; i++ ) {
            unsigned char *pk = &( privkey[32 * i]);
            unsigned char *pb = &(  publkey[65 * i]);
            unsigned char *pbcomp = (unsigned char*)safe_calloc2(20, sizeof(unsigned char));

            fasthash_compress_pubkey(pb, pbcomp);
            //printf("  pubcomp  = "); hex_dump(pbcomp, KEY_LENGTH); printf("\n");
            //memcpy(find_key,pbcomp,KEY_LENGTH);
            //printf("  find key = "); hex_dump(find_key, KEY_LENGTH); printf("\n");
            status = hashmap_get(mymap, pbcomp, (void**)(&value));
            
            /* Make sure the value was both found and the correct number */
            if(status==MAP_OK){
                unsigned char *adr=&(value->value);
                if(adr != NULL){
                    printf("=============Key founded %zu item %zu=======\n", batch, i);
                    printf("  privkey  = "); hex_dump(pk, 32); printf("\n");
                    printf("  publkey  = "); hex_dump(pb, 65); printf("\n");
                    printf("  pubcomp  = "); hex_dump(pbcomp, 20); printf("\n");
                    printf("  address  = %s\n", adr);
                    printf("=============Key founded %zu item %zu=======\n", batch, i);
                    logger(log,pk,pbcomp,adr);
                }
            }

            free(pbcomp);
        }
        if((total_keys % (1024*1024))==0){
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("testing %12.2f key/sec\n", total_keys / cpu_time_used);
            if(TEST==false){
                //Infinite loop without overflow
                start = clock();
                total_keys = 0;
                batch =0;
            }
        }


    }

    free(privkey); free(publkey);
    fclose(log);
    printf("Process finished\n");
    printf("\n");

    return 0;
}
