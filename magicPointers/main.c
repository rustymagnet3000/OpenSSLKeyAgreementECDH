#include <stdio.h>
#include <stdlib.h>
#include "keyGeneration.h"
#include "generateHmac.h"
#include "getPeerKey.h"

int main()
{
 //   EVP_PKEY *peerKey = NULL;
    
//    unsigned char *secret = malloc( sizeof( unsigned char ) * 32 );
//    size_t s = sizeof(secret);
//    secret = generate_ecdh(&s);
    
    /* EVP_PKEY_EC is an enum value with an Int value of 408 */
    //  generate_ec_key(EVP_PKEY_EC);

    printf("Testing HMAC functions with EVP_DigestSign\n");
    
    OpenSSL_add_all_algorithms();
    
    /* Sign HMAC key */
    EVP_PKEY *skey = (EVP_PKEY*)malloc(sizeof(EVP_PKEY));

    const char hn[] = "SHA256";
    const unsigned char static_key[] = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    
    const EVP_MD* md = EVP_get_digestbyname(hn);
    int size = EVP_MD_size(md);
    *skey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, <POINTER>, EVP_MAX_MD_SIZE);

    
    assert(*skey != NULL);
    if(*skey == NULL) {
        printf("EVP_PKEY_new_mac_key failed, error 0x%lx\n", ERR_get_error());
        return(99);
    }
    
    const unsigned char msg[] = "Now is the time for all good men to come to the aide of their country";
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
