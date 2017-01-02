#include "keyGeneration.h"
#include "generateHmac.h"
#include "getPeerKey.h"

#define DERIVED_KEY_FILENAME "appDerivedKey.pem"

int main()
{
    OpenSSL_add_all_algorithms();

//    EVP_PKEY *peerKey = NULL;
//    unsigned char *secret = malloc( sizeof( unsigned char ) * 32 );
//    size_t s = sizeof(secret);
//    secret = generate_ecdh(&s);

    // TO DO: Replaced the Test Vector hexadecimal byte array AND  hex plaintext with the derived Shared Secret

    printf("Testing the SHA256-HMAC function\n");

    static unsigned char key[] = {0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    
    static unsigned char data[] = {0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65};
    
    unsigned char *hashedDerivedKey = generate_sha256_hmac(key, sizeof(key), data, sizeof(data));
    printf("Derived SHA256-HMAC digest was: %s\n", hashedDerivedKey);
    
    return(0);
}
