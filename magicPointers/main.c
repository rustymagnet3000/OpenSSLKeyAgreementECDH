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
    static const char key[16] = { 0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11 };
    
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
    
    printf("HMAC (%s, ", fname);
    print_hex(key, sizeof(key));
    printf(")=");
    print_hex(result, dlen);

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
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int dlen;

    printf("Testing HMAC functions with EVP_DigestSign\n");
  //  HMAC(EVP_sha256(), static_key, sizeof(static_key), msg, sizeof(msg), result, dlen);
    hmac_file_and_print(DERIVED_KEY_FILENAME);
    
    return(0);
}
