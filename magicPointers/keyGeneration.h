#ifndef keyGeneration_h
#define keyGeneration_h

#include "generatePemFile.h"
#include "getPeerKey.h"
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <strings.h>
#include <stdlib.h>  // required for Malloc

void *generate_ec_key(int type);
unsigned char *generate_ecdh(size_t *secret_len);
#endif /* keyGeneration_h */
