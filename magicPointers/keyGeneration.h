#ifndef keyGeneration_h
#define keyGeneration_h

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/pem.h>
#include "generateHmac.h"

bool result_ecdh_key_derivation();

#endif /* keyGeneration_h */
