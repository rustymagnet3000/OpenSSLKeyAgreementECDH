#include "keyGeneration.h"
#include "generateHmac.h"
#include "getPeerKey.h"
#include "generateBinaryKeyFile.h"

int main()
{
    unsigned char *derived_secret = malloc( sizeof( unsigned char ) * 32 );
    size_t secret_size = sizeof(derived_secret);
    static unsigned char key[] = {0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    size_t key_size = sizeof(key);
    derived_secret = generate_ecdh(&secret_size);
    
    printf("\n✅\tSecret Key in memory:\n");
    int i;
    
    for(i = 0; i < 32; i++)
        printf("%02x", derived_secret[i]);

    unsigned char *derived_keyed_hashed = generate_sha256_hmac(key, &key_size, derived_secret, &secret_size);
    
    printf("\n✅\tDerived SHA256-HMAC digest was: \n%s\n\n", derived_keyed_hashed);
    
    generate_bin_key_file(derived_keyed_hashed);

    return(0);
}
