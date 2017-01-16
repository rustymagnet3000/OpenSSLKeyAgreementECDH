#ifndef GENERATEHMAC_H_   /* Include guard */
#define GENERATEHMAC_H_
#include <stdlib.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

unsigned char *generate_sha256_hmac(unsigned char *data, const size_t *datalen);

#endif // GENERATEHMAC_H_
