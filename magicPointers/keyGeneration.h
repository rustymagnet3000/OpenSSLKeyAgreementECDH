#ifndef keyGeneration_h
#define keyGeneration_h

#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#include "generateHmac.h"

bool result_ecdh_key_derivation(char *peer_key_file_location, char *binary_key_file_location);
bool read_peer_key(char *file_location);

#endif /* keyGeneration_h */
