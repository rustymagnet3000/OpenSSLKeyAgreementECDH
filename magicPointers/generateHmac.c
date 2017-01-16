#include "generateHmac.h"

#define DERIVED_KEY_FILENAME "serBinaryKey.bin"

static void get_hmac_key(unsigned char *key_ptr, size_t *key_size) {
    
    /* TODO: Replace this 20 char NIST Key with secret key */
    memset( key_ptr, 0x0B, sizeof( unsigned char ) * *key_size );
    
    printf("In get hmac Key function. The Key is: %p\n", key_ptr);
    for(int i = 0; i < *key_size; i++)
        printf("%02x ", key_ptr[i]);
    printf("\n");
}

static void *generate_bin_key_file(unsigned char *derived_secret, unsigned int *secret_length)
{
    FILE *bin_fp;
    
    bin_fp = fopen(DERIVED_KEY_FILENAME,"wb");
    if (!bin_fp)
    {
        printf("Unable to open file!");
    }
    
    fwrite(derived_secret, *secret_length, 1, bin_fp);
    
    fclose(bin_fp);
    return(0);
}

/* TODO: add error handling */
unsigned char *generate_sha256_hmac(unsigned char *derived_secret, const size_t *derived_secret_length)
{
    HMAC_CTX ctx;
    unsigned int hmac_output_length;
    size_t key_size = 20;
    unsigned char *key_ptr = malloc( sizeof( unsigned char ) * key_size );
    get_hmac_key(key_ptr, &key_size);
    unsigned char out[SHA256_DIGEST_LENGTH];
    static unsigned char res_hexstring[32];

    HMAC_Init(&ctx, key_ptr, (int) key_size, EVP_sha256());
    HMAC_Update(&ctx, derived_secret, *derived_secret_length);
    HMAC_Final(&ctx, out, &hmac_output_length);

    generate_bin_key_file(derived_secret, &hmac_output_length);

    for(int i = 0; i < hmac_output_length; i++)
        sprintf((char *)&(res_hexstring[i * 2]), "%02x", out[i]);
    
    HMAC_cleanup(&ctx);
    return res_hexstring;
}
