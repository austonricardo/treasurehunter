/**********************************************************************
 * Copyright (c) 2016 Auston                                          *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

// After building secp256k1_fast_unsafe, compile bulkprivkey with:
// delete this-> gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I src/ -I ./ bulkprivkey.c timer.c -lgmp -o bulkprivkey
// gcc -g -fPIC -c bulkprivkey.c -I src/ -I ./
// gcc -o bulkprivkey.so -shared bulkprivkey.o

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#include "secp256k1.c" 
#include "ecmult_big_impl.h"
#include "secp256k1_batch_impl.h"
#include "bulkprivkey.h"

// Hackishly converts an uncompressed public key to a compressed public key
// The input is considered 65 bytes, the output should be considered 33 bytes
void secp256k1_pubkey_uncomp_to_comp(unsigned char *pubkey) {
    pubkey[0] = 0x02 | (pubkey[64] & 0x01);
}

// Initializing secp256k1 context
int secp256k1_batch_create_context(unsigned int bmul_size, unsigned int batch_size, bp_bigcontext * bpcontext){
    bpcontext->ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    bpcontext->bmul = secp256k1_ecmult_big_create(bpcontext->ctx, bmul_size);
    bpcontext->batch_size = batch_size;
    //Initializing secp256k1_scratch for batched key calculations
    bpcontext->scr = secp256k1_scratch_create(bpcontext->ctx, bpcontext->batch_size);
}

// privkey array of unsigned char multiple of 32 * batch_size (32 by privatekey)
// publkey array of unsigned char multiple of 65 * batch_size (32 by privatekey)
int secp256k1_batch_generate_publkey(unsigned char *privkey, unsigned char *publkey, bp_bigcontext * bpcontext)
{
    int actual_count = secp256k1_ec_pubkey_create_serialized_batch(bpcontext->ctx, bpcontext->bmul, bpcontext->scr, publkey, privkey, bpcontext->batch_size, 0);
    return actual_count;
}
