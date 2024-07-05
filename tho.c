/**********************************************************************
 * Copyright (c) 2019 Auston                                           *
 **********************************************************************/

//   compile with:
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I src/ -I ./ thp.c -lgmp -o thp
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I src/ -I ./ tho.c -lgmp -o tho
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I src/ -I ./ -I include/ tho.c -lgmp -o tho2

#include <stdio.h>
#include <stdlib.h>
#include <time.h> 
#include <sys/wait.h>
//#include <sys/mman.h>
//#include <unistd.h>

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

typedef struct thread_procwork_args
{
    int tid;
    FILE *log;
    map_t* mymap;
    bp_bigcontext * bpcontext;
    int pool_size;
    int variant_byte_pos;
    unsigned char variant_byte_initial;
    unsigned char variant_byte_final;
} tpargs;


void rand_privkey(unsigned char *privkey) {
    // Not cryptographically secure, but good enough for quick verification tests
    for ( size_t pos = 0; pos < 32; pos++ ) {
        privkey[pos] = rand() & 0xFF;
    }
}


void rand_privkey_part(unsigned char *privkey, int part, int total) {
    // Not cryptographically secure, but good enough for quick verification tests
    int slice = 0xFF/total;
    privkey[0] = slice * part + (rand() & slice);
}

void rand_privkey_range_with_params_init(unsigned char *privkey, int variant_byte_pos, unsigned char variant_byte_initial, unsigned char variant_byte_final) {
    // Initialize entire array to zeros
    memset(privkey, 0, sizeof(privkey));

    // Generate random value for the specified byte
    privkey[variant_byte_pos] = rand() % (variant_byte_final - variant_byte_initial + 1) + variant_byte_initial;

    //randomiza restantes
    for ( size_t pos = variant_byte_pos + 1; pos < 32; pos++ ) {
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

void logger(unsigned char* tid, FILE * log,unsigned char* pk, unsigned char* pbcomp, unsigned char* adr){
    fprintf(log, "tid:%d adr:%s pub:", tid, adr);
    hex_file_dump(log,pbcomp, 20);
    fprintf(log," prk:");
    hex_file_dump(log,pk, 32);
    fprintf(log,"\n");
    return;
}
/*
void *safe_calloc(size_t num, size_t size) {
    void *rtn = calloc(num, size);
    if ( !rtn ) {
        printf("calloc failed to allocate %zu items of size %zu\n", num, size);
        exit(EXIT_FAILURE);
    }
    return rtn;
}
*/
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
/*
void* create_shared_memory(size_t size) {
  // Our memory buffer will be readable and writable:
  int protection = PROT_READ | PROT_WRITE;

  // The buffer will be shared (meaning other processes can access it), but
  // anonymous (meaning third-party processes cannot obtain an address for it),
  // so only this process and its children will be able to use it:
  int visibility = MAP_SHARED; //MAP_ANONYMOUS | 

  // The remaining parameters to `mmap()` are not important for this use case,
  // but the manpage for `mmap` explains their purpose.
  return mmap(NULL, size, protection, visibility, -1, 0);
}
*/

void loadhashtable(map_t *hashtable)
{
    FILE * fp;
    unsigned char * line = NULL;
    size_t len = 0;
    size_t read;

    fp = fopen("adrblc-checked-1btc.db6", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    printf("Retrieved content of file adrblc-checked-1btc.db6\n");
    const char sep[2] = ";";
    int adrcount = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        if(TEST){
            printf("%s\n", line);
        }
        unsigned char *token1;
        unsigned char *token2;
        unsigned char *key = (unsigned char *)malloc(sizeof(unsigned char)*20);

        token1 = strtok(line, &sep);  /* get the first  token */
        token2 = strtok(NULL, &sep); /* get the second token */
        
        /* Store the key string along side the numerical value so we can free it later */
        data_struct_t* item = (data_struct_t*)malloc(sizeof(data_struct_t));
        //printf("foi token2:%s token1: %s\n",token2,token1);
        hextobin(token1, key, KEY_LENGTH);

        

        memcpy(item->key_string,key,KEY_LENGTH);
        memcpy(item->value,token2,VALUE_MAX_LENGTH);

        if(TEST){
            printf("  key  = "); hex_dump(key, KEY_LENGTH); printf("\n");
        }

        int status = hashmap_put(hashtable, key, item);
        if(TEST){
            if(status==MAP_OK){
                printf(" hashmapped :"); hex_dump(item->key_string, KEY_LENGTH); printf(" -> "); hex_dump(item->value, VALUE_MAX_LENGTH); printf("\n");
            }else{
                printf("put %s in hashmap failed with error: %d\n", token1,status);
            }
        }
        adrcount++;
    }
    printf("put %d address in hashmap\n", adrcount);

    fclose(fp);
    if (line)
        free(line);
    return;
}


void* procwork(tpargs *args) {    
    unsigned char tid = args->tid;
    printf("Starting process %d\n",tid);
    
    unsigned int batch_size = args->bpcontext->batch_size;

    unsigned char *privkey  = (unsigned char*)safe_calloc2(batch_size * 32, sizeof(unsigned char));
    unsigned char *publkey  = (unsigned char*)safe_calloc2(batch_size * 65, sizeof(unsigned char));

    int test_count = 1024;
    long total_keys = 0;
    double cpu_time_used;
    
    unsigned char find_key[KEY_LENGTH];
    data_struct_t* value = malloc(sizeof(data_struct_t));
    int status;

    clock_t start, end;
    start = clock();
    size_t batch = 0;

    if(TEST==false){
        test_count = 1024*1024;
    }

    while (  batch < test_count / batch_size) {
        batch++;
        total_keys+=batch_size;
        for ( size_t i = 0; i < batch_size; i++ ) {
            //rand_privkey(&privkey[32 * i]);
            //rand_privkey_part(&privkey[32 * i],args->tid,args->pool_size);
            rand_privkey_range_with_params_init(&privkey[32 * i],args->variant_byte_pos,args->variant_byte_initial,args->variant_byte_final);
        }
        
        if(TEST){
            //test knowed pk
            memcpy(privkey,baseline_privatekey,32);
        }

        secp256k1_batch_generate_publkey(privkey, publkey, args->bpcontext);

        for ( size_t i = 0; i < batch_size; i++ ) {
            unsigned char *pk = &( privkey[32 * i]);
            unsigned char *pb = &(  publkey[65 * i]);
            unsigned char *pbcomp = (unsigned char*)safe_calloc2(20, sizeof(unsigned char));

            fasthash_compress_pubkey(pb, pbcomp);
            //printf("  pubcomp  = "); hex_dump(pbcomp, KEY_LENGTH); printf("\n");
            //memcpy(find_key,pbcomp,KEY_LENGTH);
            //printf("  find key = "); hex_dump(find_key, KEY_LENGTH); printf("\n");
            status = hashmap_get(args->mymap, pbcomp, (void**)(&value));
            
            //Imprime chave privada gerada para testes
            //printf("tid %d privkey: ", tid); hex_dump(pk, 32); printf("; publkey:"); hex_dump(pbcomp, 20);printf("\n");
            
            /* Make sure the value was both found and the correct number */
            if(status==MAP_OK){
                unsigned char *adr=&(value->value);
                if(adr != NULL){
                    printf("tid %d =============Key founded %zu item %zu=======\n", tid, batch, i);
                    printf("tid %d   privkey  = ", tid); hex_dump(pk, 32); printf("\n");
                    printf("tid %d   publkey  = ", tid); hex_dump(pb, 65); printf("\n");
                    printf("tid %d   pubcomp  = ", tid); hex_dump(pbcomp, 20); printf("\n");
                    printf("tid %d   address  = %s\n", tid, adr);
                    printf("tid %d =============Key founded %zu item %zu=======\n", tid, batch, i);
                    logger(tid,args->log,pk,pbcomp,adr);
                }
            }

            free(pbcomp);
        }
        if((total_keys % (test_count))==0){
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("tid %d testing %12.2f key/sec\n", tid, total_keys / cpu_time_used);
            if(TEST==false){
                //Infinite loop without overflow
                start = clock();
                total_keys = 0;
                batch =0;
            }
        }   
    }
    free(privkey); free(publkey); 
}

void hex_str_to_byte_array(const char *hex_str, unsigned char *byte_array, size_t byte_array_size) {
    size_t hex_str_len = strlen(hex_str);
    size_t byte_array_len = (hex_str_len + 1) / 2;

    memset(byte_array, 0, byte_array_size);

    for (size_t i = 0; i < hex_str_len; i++) {
        char hex_digit = hex_str[hex_str_len - 1 - i];
        int value = 0;
        if (hex_digit >= '0' && hex_digit <= '9') {
            value = hex_digit - '0';
        } else if (hex_digit >= 'a' && hex_digit <= 'f') {
            value = hex_digit - 'a' + 10;
        } else if (hex_digit >= 'A' && hex_digit <= 'F') {
            value = hex_digit - 'A' + 10;
        }

        byte_array[byte_array_len - 1 - (i / 2)] |= value << ((i % 2) * 4);
    }
}

void calculate_variant_byte(const char *lower_str, const char *upper_str, int *variant_pos, unsigned char *min_val, unsigned char *max_val) {
    size_t byte_array_size = 32;
    unsigned char lower_bytes[32] = {0};
    unsigned char upper_bytes[32] = {0};

    hex_str_to_byte_array(lower_str, lower_bytes, byte_array_size);
    hex_str_to_byte_array(upper_str, upper_bytes, byte_array_size);

    for (size_t i = 0; i < byte_array_size; i++) {
        if (lower_bytes[i] != upper_bytes[i]) {
            *variant_pos = i;
            *min_val = lower_bytes[i];
            *max_val = upper_bytes[i];
            return;
        }
    }

    *variant_pos = -1;
    *min_val = 0;
    *max_val = 0;
}

void pad_with_zeros(char *dest, const char *src, size_t total_length) {
    size_t src_len = strlen(src);
    if (src_len > total_length) {
        fprintf(stderr, "Erro: A string de entrada é maior que o tamanho permitido.\n");
        exit(1);
    }

    // Preencher com zeros à esquerda
    memset(dest, '0', total_length - src_len);
    // Copiar a string original para o final do buffer de destino
    strcpy(dest + (total_length - src_len), src);
}


int main(int argc, char **argv) {
    unsigned int bmul_size  = ( argc > 1 ? atoi(argv[1]) : 20 );    // ecmult_big window size in bits
    unsigned int batch_size = ( argc > 2 ? atoi(argv[2]) : 16 );    // ecmult_batch size in keys
    unsigned int pool_size  = ( argc > 3 ? atoi(argv[3]) : 2 );    // number of parallel threads

    const char *lower_str = ( argc > 4 ? argv[4] : "0000000000000000000000000000000000000000000000020000000000000000" );
    const char *upper_str = ( argc > 5 ? argv[5] : "000000000000000000000000000000000000000000000003ffffffffffffffff" );

    if (strlen(lower_str) > 64 || strlen(upper_str) > 64) {
        fprintf(stderr, "Erro: As strings de limite devem ter no máximo 64 caracteres.\n");
        return 1;
    }

    // Arrays para armazenar as strings de 64 caracteres
    char lower_str_padded[65] = {0}; // 64 caracteres + 1 para o terminador nulo
    char upper_str_padded[65] = {0};

    // Preencher as strings com zeros à esquerda
    pad_with_zeros(lower_str_padded, lower_str, 64);
    pad_with_zeros(upper_str_padded, upper_str, 64);

    int variant_pos;
    unsigned char variant_min_val, variant_max_val;

    calculate_variant_byte(lower_str_padded, upper_str_padded, &variant_pos, &variant_min_val, &variant_max_val);

    if (variant_pos != -1) {
        printf("Posicao variante: %d\n", variant_pos);
        printf("Valor minimo: 0x%02x\n", variant_min_val);
        printf("Valor maximo: 0x%02x\n", variant_max_val);
    } else {
        printf("As strings de limite são idênticas.\n");
    }

    printf("bmul  size = %u\n", bmul_size);
    printf("batch size = %u\n", batch_size);
    printf("pool size = %u\n", pool_size);
    printf("\n");

    bp_bigcontext * bpcontext = (bp_bigcontext *)malloc(sizeof(bp_bigcontext));
    //bp_bigcontext * bpcontext = (bp_bigcontext *)create_shared_memory(sizeof(bp_bigcontext));
    bpcontext->batch_size = batch_size;
    secp256k1_batch_create_context(bmul_size, batch_size, bpcontext);

    map_t mymap;
    mymap = hashmap_new();
    
    loadhashtable(mymap);
    /* Store the key string along side the numerical value so we can free it later */

    //log file
    FILE *log = fopen("tho.log", "a+");

    tpargs * args = (tpargs *)malloc(sizeof(tpargs));
    args->bpcontext = bpcontext;
    args->log = log;
    args->mymap = mymap;
    args->pool_size =pool_size;
    args->variant_byte_pos = variant_pos;
    args->variant_byte_initial = variant_min_val;
    args->variant_byte_final = variant_max_val;

    // Let us create three threads 
    pid_t pid[pool_size];
    for (int i = 1; i < pool_size; i++){ 
        args->tid = i;
        pid[i] = fork();
        if (pid[i] < 0) {
            perror("fork error");
        } else if (pid[i] > 0) {
            /* in parent process */
        } else {
            /* in child process */
            procwork(args);
        }
    }
    if(pid[1] > 0){
        /* in parent process */
        args->tid = 0;
        procwork(args);
    }

    fclose(log);
    printf("principal Process finished\n");
    return 0;
}
