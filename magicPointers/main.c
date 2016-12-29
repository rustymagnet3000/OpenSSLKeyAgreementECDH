#include <stdio.h>
#include <stdlib.h>
#include "keyGeneration.h"
#include "getPeerKey.h"

#define FILE_MAX 200

int main()
{
 //   EVP_PKEY *peerKey = NULL;
    
    unsigned char *secret = malloc( sizeof( unsigned char ) * 32 );
    size_t s = sizeof(secret);
    /* EVP_PKEY_EC is an enum value with an Int value of 408 */
    //  generate_ec_key(EVP_PKEY_EC);
    
    secret = generate_ecdh(&s);
    
    return(0);
}
