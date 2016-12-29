#ifndef generatePemFile_h
#define generatePemFile_h

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void *generate_pem_file(EVP_PKEY *evp_pkey);

#endif /* generatePemFile_h */
