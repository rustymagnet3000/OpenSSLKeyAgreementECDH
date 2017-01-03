#include "keyGeneration.h"
#include "generateHmac.h"
#include "getPeerKey.h"

#define DERIVED_KEY_FILENAME "appDerivedKey.pem"

void placeholder() {
    printf("Testing the SHA256-HMAC function\n");
    
    static unsigned char key[] = {0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    
    static unsigned char data[] = {0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65};
    
    unsigned char *hashedDerivedKey = generate_sha256_hmac(key, sizeof(key), data, sizeof(data));
    printf("Derived SHA256-HMAC digest was: %s\n", hashedDerivedKey);
}

int main()
{
    unsigned char *secret = malloc( sizeof( unsigned char ) * 32 );
    size_t s = sizeof(secret);
    secret = generate_ecdh(&s);

    return(0);
}
