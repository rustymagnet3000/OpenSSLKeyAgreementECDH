#ifndef GENERATEHMAC_H_   /* Include guard */
#define GENERATEHMAC_H_
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>

void print_it(const char* label, const unsigned char* buff, size_t len);

int sign_it(const unsigned char* msg, size_t mlen, unsigned char** sig, size_t* slen, EVP_PKEY* pkey);

#endif // GENERATEHMAC_H_
