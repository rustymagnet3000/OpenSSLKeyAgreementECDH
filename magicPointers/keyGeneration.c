#include "keyGeneration.h"

#define PUBLIC_KEY_FILENAME "serPubKey.pem"
#define PRIVATE_KEY_FILENAME "serPriKey.pem"
#define MAX_FILE_LOCATION 1024

static void *generate_pem_file(EVP_PKEY *evp_pkey)
{
    FILE *fp;
    
    if((fp = fopen(PUBLIC_KEY_FILENAME, "w")) == NULL)
        goto err;
    
    if (!PEM_write_PUBKEY(fp, evp_pkey))
        goto err;
    
    if((fp = fopen(PRIVATE_KEY_FILENAME, "w")) == NULL)
        goto err;
    
    // TODO: Write an encrypted private key
    if (!PEM_write_PrivateKey(fp, evp_pkey, NULL, NULL, 0, 0, NULL))
        goto err;
    
    printf("✅\tGenerated EC Key Pair.\n✅\tWritten PEM files.\n");
    goto end;
    
err:
    ERR_print_errors_fp(stderr);
    goto end;
    
end:
    fclose(fp);
    return(0);
}

bool read_peer_key(char *file_location)
{
    bool result = false;
    char file_location_buffer[MAX_FILE_LOCATION];
    char *ptr_final_file_location;
    size_t length;
    
    length = strlcpy(file_location_buffer, file_location, sizeof(file_location_buffer)); // Copy to a fast block of memory on the stack:
    
   
    if(length == 0) goto err;
    
    if (length < sizeof(file_location_buffer)) {
        ptr_final_file_location = file_location_buffer;
        printf("The final filepath is: %s\n", ptr_final_file_location);
    } else {
        goto err;
    }
    
    result = true;
    goto end;
    
err:
    result = false;
    printf("❗️error reading peer public key\n");
    goto end;
    
end:
    return result;
}


static EVP_PKEY *get_peer_key(char *peer_key_file_final)
{
    FILE *fp;
    EVP_PKEY *peer_key = NULL;

    if((fp = fopen(peer_key_file_final, "r")) == NULL)
        goto err;
    
    fseek(fp, 0, SEEK_END);
    unsigned long fileLength = (unsigned long)ftell(fp);
    rewind(fp);
    
    if(fileLength == 0 )
        goto err;
    
    peer_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    
    if (peer_key == NULL)
        goto err;
    
    printf("✅\tPeer Public Key file. Read %lu characters.", fileLength);
    goto end;
    
err:
    printf("❗️error reading peer public key\n");
    peer_key = NULL;
    
end:
    fclose(fp);
    return(peer_key);
}



static unsigned char *generate_ecdh(bool *res, size_t *secret_len, char *peer_key_file)
{
    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY_CTX *ctx;
    unsigned char *secret;
    EVP_PKEY *pkey = NULL, *peerkey, *params = NULL;

    /* Create the context for parameter generation */
    if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) goto err;
    
    /* Initialise the parameter generation */
    if(1 != EVP_PKEY_paramgen_init(pctx))  goto err;
    
    /* NIST-Prime-256 = ANSI X9.62 Prime 256v1 curve in OpenSSL enum value */
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) goto err;
 
    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)) goto err;
    
    /* Create the context for the key generation */
    if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) goto err;
    
    /* Generate the key */
    if(1 != EVP_PKEY_keygen_init(kctx)) goto err;
    if (1 != EVP_PKEY_keygen(kctx, &pkey)) goto err;

    /* Generate the Key PEM files  */
    generate_pem_file(pkey);
    
    /* Get the peer's public key: updated so null returned on error  */
    if((peerkey = get_peer_key(peer_key_file)) == NULL) goto err;
    
    /* Create the context for the shared secret derivation */
    if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) goto err;
    
    /* Initialise */
    if(1 != EVP_PKEY_derive_init(ctx)) goto err;
    
    /* Provide the peer public key */
    if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) goto err;
    
    /* Determine buffer length for shared secret */
    if(1 != EVP_PKEY_derive(ctx, NULL, secret_len)) goto err;
    
    /* Create the buffer */
    if(NULL == (secret = OPENSSL_malloc(*secret_len))) goto err;
    
    /* Derive the shared secret */
    if(1 != (EVP_PKEY_derive(ctx, secret, secret_len))) goto err;
    
    *res = true;
    goto end;

err:
    *res = false;
    secret = NULL;
    ERR_print_errors_fp(stderr);
    goto end;
    
end:
    if(ctx) EVP_PKEY_CTX_free(ctx);
    if(peerkey) EVP_PKEY_free(peerkey);
    if(pkey) EVP_PKEY_free(pkey);
    if(kctx) EVP_PKEY_CTX_free(kctx);
    if(params) EVP_PKEY_free(params);
    if(pctx) EVP_PKEY_CTX_free(pctx);
    return secret;
}

bool result_ecdh_key_derivation(char *peer_key_file_location, char *binary_key_file_location) {

    bool ecdh_result = false;
    unsigned char *derived_secret;
    unsigned char *derived_keyed_hashed;
    size_t secret_size = 32;
    
    derived_secret = malloc( sizeof( unsigned char ) * secret_size );
    derived_secret = generate_ecdh(&ecdh_result, &secret_size, peer_key_file_location);
    
    if(ecdh_result == false) goto err;
    if(derived_secret == NULL) goto err;
    
    printf("\n✅\tSecret Key in memory:\n");
    for(int i = 0; i < secret_size; i++)
        printf("%02x", derived_secret[i]);
    
    derived_keyed_hashed = generate_sha256_hmac(derived_secret, &secret_size, binary_key_file_location);
    
    if(derived_keyed_hashed == NULL) goto err;
    
    printf("\n✅\tDerived SHA256-HMAC digest was: \n%s\n\n", derived_keyed_hashed);
    goto end;
    
err:
    ecdh_result = false;
    ERR_print_errors_fp(stderr);
    goto end;

end:
    if(derived_secret) free(derived_secret);
    return ecdh_result;
}
