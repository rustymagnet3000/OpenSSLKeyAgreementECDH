#ifndef GENERATEHMAC_H_   /* Include guard */
#define GENERATEHMAC_H_
#include <stdlib.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

unsigned char *generate_sha256_hmac(unsigned char *key, size_t *keylen, unsigned char *data, size_t *datalen);

#endif // GENERATEHMAC_H_
