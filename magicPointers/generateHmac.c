#include "generateHmac.h"
#include <stdlib.h>
#include <string.h>
#include "openssl/evp.h" 

void generateHmac(const char *ptr)
{
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    
    // Context creation
    EVP_MD_CTX* md_ctx;
    md_ctx = malloc(sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(md_ctx);
    
    // Hashing: you declare the hash function here
    EVP_DigestInit(md_ctx, EVP_sha512());
    EVP_DigestUpdate(md_ctx, ptr, strlen(ptr));
    EVP_DigestFinal(md_ctx, md_value, &md_len);

    // Print Result
    printf("The pointer points towards: %s \nThe string lenght is: %lu\n", ptr, strlen(ptr));
    printf("Digest is: ");
    for(i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");
    
    // Clean-up
    EVP_MD_CTX_cleanup(md_ctx);
    free(md_ctx);
}
