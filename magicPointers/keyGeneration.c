#include "keyGeneration.h"

#define PEER_PUBLIC_KEY_FILENAME "appPubKey.pem"
#define PUBLIC_KEY_FILENAME "serPubKey.pem"
#define PRIVATE_KEY_FILENAME "serPriKey.pem"

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
    
    printf("✅\tGenerated EC Key Pair and written PEM files\n");
    goto end;
    
err:
    ERR_print_errors_fp(stderr);
    goto end;
    
end:
    fclose(fp);
    return(0);
}

static void *get_peer_key()
{
    FILE *fp;
    EVP_PKEY *peerKey = NULL;
    
    if((fp = fopen(PEER_PUBLIC_KEY_FILENAME, "r")) == NULL)
        goto err;
    
    fseek(fp, 0, SEEK_END);
    unsigned long fileLength = (unsigned long)ftell(fp);
    rewind(fp);
    
    if(fileLength == 0 )
        goto err;
    
    peerKey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (peerKey == NULL)
        goto err;
    
    printf("✅\tRead %lu characters from Peer Public Key file", fileLength);
    goto end;
    
err:
    printf("❗️error reading peer public key\n");
    ERR_print_errors_fp(stderr);
    peerKey = NULL;
    
end:
    fclose(fp);
    return(peerKey);
}



static unsigned char *generate_ecdh(bool *res, size_t *secret_len)
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
    
    /* Get the peer's public key  */
    peerkey = get_peer_key();
    if (!peerkey) goto err;
    
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
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    return secret;
}

bool result_ecdh_key_derivation() {

    bool ecdh_result = false;
    unsigned char *derived_secret;
    unsigned char *derived_keyed_hashed;
    size_t secret_size = 32;
    
    derived_secret = malloc( sizeof( unsigned char ) * secret_size );
    derived_secret = generate_ecdh(&ecdh_result, &secret_size);
    
    if(ecdh_result == false) goto err;
    if(derived_secret == NULL) goto err;
    
    printf("\n✅\tSecret Key in memory:\n");
    for(int i = 0; i < secret_size; i++)
        printf("%02x", derived_secret[i]);
    
    derived_keyed_hashed = generate_sha256_hmac(derived_secret, &secret_size);
    if(derived_keyed_hashed == NULL) goto err;
    
    printf("\n✅\tDerived SHA256-HMAC digest was: \n%s\n\n", derived_keyed_hashed);
    
    goto end;
    
err:
    ecdh_result = false;
    ERR_print_errors_fp(stderr);
    goto end;


end:
    free(derived_secret);
    
    return ecdh_result;
}
