#include <stdio.h>
#include <stdlib.h>
#include "keyGeneration.h"
#include "generateHmac.h"
#include "getPeerKey.h"
#define DERIVED_KEY_FILENAME "appDerivedKey.pem"
#define READ_SIZE 128

void print_hex(unsigned char *bs, unsigned int n)
{
    int i;
    for(i = 0; i < n; i++)
        printf("%02x",bs[i]);
}

unsigned char *read_file(FILE *f, int *len)
{
    unsigned char *buf = NULL, *last = NULL;
    unsigned char inbuf[READ_SIZE];
    int tot, n;

    tot = 0;
    for(;;)
    {
        n = fread(inbuf, sizeof(unsigned char), READ_SIZE, f);
        if (n > 0)
        {
            last = buf;
            buf = (unsigned char *)malloc(tot + n);
            memcpy(buf, last, tot);
            memcpy(&buf[tot], inbuf, n);
            if (last)
                free(last);
            tot += n;
            if (feof(f) > 0)
            {
                *len = tot;
                return buf;
            }
        }
        else
        {
            if(buf)
                free(buf);
            break;
        }
    }
    return NULL;
}

    
int hmac_file_and_print(unsigned char *fname)
{
    static const char key[16] = { 0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
    
    FILE *fp = fopen(DERIVED_KEY_FILENAME, "rb");
    unsigned char *contents;
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int flen, dlen;
    
    if(!fp)
        return (0);
    
    contents = read_file(fp, &flen);
    fclose(fp);
    if(!contents)
        return 0;
    
    HMAC(EVP_sha256(), key, sizeof(key), contents, flen, result, &dlen);
    
    printf("HMAC(%s, ", fname);
    print_hex(key, sizeof(key));
    printf(")=");
    print_hex(result, dlen);
    printf("\n");
    return 1;
    
}

int main()
{
    OpenSSL_add_all_algorithms();

//    EVP_PKEY *peerKey = NULL;
//    unsigned char *secret = malloc( sizeof( unsigned char ) * 32 );
//    size_t s = sizeof(secret);
//    secret = generate_ecdh(&s);

    const unsigned char msg[] = "Hi There";
    const unsigned char static_key[] = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"; // test vector
    int length_key = strlen(static_key);
    
    unsigned char* key_static = (unsigned char *)malloc(256 * sizeof(unsigned char));
    
    /* EVP_PKEY_EC is an enum value with an Int value of 408 */
    //  generate_ec_key(EVP_PKEY_EC);

    printf("Testing HMAC functions with EVP_DigestSign\n");

    
    /* Sign HMAC key */
    EVP_PKEY *skey = NULL;
    // const EVP_MD* md = EVP_get_digestbyname("SHA256");
    // unsigned int size = EVP_MD_size(md);
    unsigned int size2
    = SHA256_DIGEST_LENGTH;
    
   // const char *static_key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

    
    
    skey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, static_key, length_key);
    
    unsigned char *ptr = HMAC(EVP_sha256(), static_key, length_key, msg, sizeof(msg), NULL, NULL);
    
    if(ptr != NULL) {
        printf("Created signature without EVP \n");
        print_it("Signature", ptr, size2);
    }
    
    assert(skey != NULL);
    if(skey == NULL) {
        printf("EVP_PKEY_new_mac_key failed, error 0x%lx\n", ERR_get_error());
        return(99);
    }
    
    unsigned char* sig = NULL;
    size_t slen = 0;
    
    /* Using the signing key */
    int rc = sign_it(msg, sizeof(msg), &sig, &slen, skey);
    assert(rc == 0);
    if(rc == 0) {
        printf("Created signature\n");
        print_it("Signature", sig, slen);
    } else {
        printf("Failed to create signature, return code %d\n", rc);
        exit(1); /* Should cleanup here */
    }
    
    return(0);
}
