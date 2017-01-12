#include "conductor.h"

/* global */
size_t secret_size = 32;
unsigned char *derived_secret;
bool step1result;
bool step2result;

bool result_ec_key_generation() {
    
    step1result = false;
    derived_secret = malloc( sizeof( unsigned char ) * secret_size );
    derived_secret = generate_ecdh(&step1result, &secret_size);

    if (derived_secret != NULL){
        int i;
        printf("\n✅\tSecret Key in memory:\n");
        for(i = 0; i < secret_size; i++)
            printf("%02x", derived_secret[i]);
    }
    return step1result;
}

bool result_derived_secret() {
    
    bool step2result = false;
    
    if(step1result == false) goto end;
    
    static unsigned char key[] = {0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B};
    size_t key_size = sizeof(key);

    unsigned char *derived_keyed_hashed = generate_sha256_hmac(key, &key_size, derived_secret, &secret_size);
    
    printf("\n✅\tDerived SHA256-HMAC digest was: \n%s\n\n", derived_keyed_hashed);
    
    generate_bin_key_file(derived_keyed_hashed);
    
    step2result = true;
    goto end;
    
end:
    return step2result;
}
