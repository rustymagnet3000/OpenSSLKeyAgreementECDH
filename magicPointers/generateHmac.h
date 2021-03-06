#ifndef GENERATEHMAC_H_   /* Include guard */
#define GENERATEHMAC_H_
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

unsigned char *generate_sha256_hmac(unsigned char *derived_secret, const size_t *derived_secret_length, char *location_write_file);

#endif // GENERATEHMAC_H_
