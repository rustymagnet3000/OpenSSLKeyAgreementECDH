#ifndef keyGeneration_h
#define keyGeneration_h

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>

#include "generatePemFile.h"
#include "getPeerKey.h"

unsigned char *generate_ecdh(bool *res, size_t *secret_len);

#endif /* keyGeneration_h */
