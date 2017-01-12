#include "conductor.h"

/* global */
size_t secret_size = 32;
unsigned char *derived_secret;

bool result_ec_key_generation() {
    
    bool result = false;
    
    derived_secret = malloc( sizeof( unsigned char ) * secret_size );
    derived_secret = generate_ecdh(&secret_size);

    printf("\n✅\tSecret Key in memory:\n");
    
    int i;
    
    for(i = 0; i < secret_size; i++)
        printf("%02x", derived_secret[i]);
    
    return result;
}

bool result_derived_secret() {
    
    bool result = true;
    
    static unsigned char key[] = {0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    size_t key_size = sizeof(key);
    

    unsigned char *derived_keyed_hashed = generate_sha256_hmac(key, &key_size, derived_secret, &secret_size);
    
    printf("\n✅\tDerived SHA256-HMAC digest was: \n%s\n\n", derived_keyed_hashed);
    
    generate_bin_key_file(derived_keyed_hashed);

    return result;
}
