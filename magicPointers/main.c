#include "keyGeneration.h"
#include "generateHmac.h"
#include "getPeerKey.h"

int main()
{
    unsigned char *derivedSecret = malloc( sizeof( unsigned char ) * 32 );
    size_t s = sizeof(derivedSecret);
    static unsigned char key[] = {0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};

    derivedSecret = generate_ecdh(&s);
    
    printf("\n✅\tSecret Key in memory:\n");
    int i;
    
    for(i = 0; i < 32; i++)
        printf("%02x", derivedSecret[i]);

    unsigned char *hashedDerivedKey = generate_sha256_hmac(key, sizeof(key), derivedSecret, sizeof(derivedSecret));
    
    printf("\n✅\tDerived SHA256-HMAC digest was: \n%s\n\n", hashedDerivedKey);
    
    return(0);
}
