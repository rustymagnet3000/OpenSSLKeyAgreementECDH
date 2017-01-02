#include "generateHmac.h"

unsigned char *generate_sha256_hmac(unsigned char *key, size_t keylen, unsigned char *data, size_t datalen)
{
    int i;
    HMAC_CTX ctx;
    unsigned int len;
    unsigned char out[SHA256_DIGEST_LENGTH];
    static unsigned char res_hexstring[32];
    
    HMAC_Init(&ctx, key, (int) keylen, EVP_sha256());
    HMAC_Update(&ctx, data, datalen);
    HMAC_Final(&ctx, out, &len);
    
    for(i = 0; i < len; i++)
        sprintf(&(res_hexstring[i * 2]), "%02x", out[i]);
    
    HMAC_cleanup(&ctx);
    return res_hexstring;
}
