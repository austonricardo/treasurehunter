/**********************************************************************
 * Copyright (c) 2016 Auston                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

// After building secp256k1_fast_unsafe, compile bulkprivkey with:
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I src/ -I ./ bulkprivkey.c timer.c -lgmp -o bulkprivkey


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HAVE_CONFIG_H
#include "secp256k1.h"
#include "ecmult_big_impl.h"
#include "secp256k1_batch_impl.h"

typedef struct bulkprivkey_context
{
    secp256k1_context* ctx;
    secp256k1_ecmult_big_context* bmul;
    secp256k1_scratch *scr;
    unsigned int * batch_size;
} bp_bigcontext;

// Hackishly converts an uncompressed public key to a compressed public key
// The input is considered 65 bytes, the output should be considered 33 bytes
void secp256k1_pubkey_uncomp_to_comp(unsigned char *pubkey);

 
// Initializing secp256k1 context
int secp256k1_batch_create_context(unsigned int bmul_size, unsigned int batch_size, bp_bigcontext * bpcontext);

// privkey array of unsigned char multiple of 32 * batch_size (32 by privatekey)
// publkey array of unsigned char multiple of 65 * batch_size (32 by privatekey)
int secp256k1_batch_generate_publkey(unsigned char *privkey, unsigned char *publkey, bp_bigcontext * bpcontext);