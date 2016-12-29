#include "keyGeneration.h"

void *generate_ec_key(int type)
{
    EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
    EVP_PKEY *params = NULL, *key = NULL;
    
    /* Check whether we need to generate parameters first */
    if(type == EVP_PKEY_EC)
    {
        /* Create the context for generating the parameters */
        if(!(pctx = EVP_PKEY_CTX_new_id(type, NULL))) goto err;
        if(!EVP_PKEY_paramgen_init(pctx)) goto err;
        
        /* Set the param gen parameters according to the type */
        /* NID_X9_62_prime256v1 == NIST Prime-Curve P-256 */
        if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                                           NID_X9_62_prime256v1)) goto err;
        
        
        /* Generate parameters */
        if (!EVP_PKEY_paramgen(pctx, &params)) goto err;
        
        /* Create context for the key generation */
        if(!(kctx = EVP_PKEY_CTX_new(params, NULL))) goto err;
    }
    else
    {
        /* Create context for the key generation */
        if(!(kctx = EVP_PKEY_CTX_new_id(type, NULL))) goto err;
    }
    
    /* Generate the key */
    
    if(!EVP_PKEY_keygen_init(kctx)) goto err;
    
    if (!EVP_PKEY_keygen(kctx, &key)) goto err;
        
    goto end;
err:
    
    ERR_print_errors_fp(stderr);
    
end:
    
    if(pctx) EVP_PKEY_CTX_free(pctx);
    if(params) EVP_PKEY_free(params);
    if(kctx) EVP_PKEY_CTX_free(kctx);
    
    generate_pem_file(key);
    return key;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char *generate_ecdh(size_t *secret_len)
{
    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY_CTX *ctx;
    unsigned char *secret;
    EVP_PKEY *pkey = NULL, *peerkey, *params = NULL;
    /* NB: assumes pkey, peerkey have been already set up */
    
    /* Create the context for parameter generation */
    if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) handleErrors();
    
    /* Initialise the parameter generation */
    if(1 != EVP_PKEY_paramgen_init(pctx)) handleErrors();
    
    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) handleErrors();
    
    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)) handleErrors();
    
    /* Create the context for the key generation */
    if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors();
    
    /* Generate the key */
    if(1 != EVP_PKEY_keygen_init(kctx)) handleErrors();
    if (1 != EVP_PKEY_keygen(kctx, &pkey)) handleErrors();
    
    /* Get the peer's public key  */
    peerkey = get_peer_key();
    
    /* Create the context for the shared secret derivation */
    if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) handleErrors();
    
    /* Initialise */
    if(1 != EVP_PKEY_derive_init(ctx)) handleErrors();
    
    /* Provide the peer public key */
    if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) handleErrors();
    
    /* Determine buffer length for shared secret */
    if(1 != EVP_PKEY_derive(ctx, NULL, secret_len)) handleErrors();
    
    /* Create the buffer */
    if(NULL == (secret = OPENSSL_malloc(*secret_len))) handleErrors();
    
    /* Derive the shared secret */
    if(1 != (EVP_PKEY_derive(ctx, secret, secret_len))) handleErrors();
    
    printf("✅ secret key derived:\t");
    
    int i;
    for(i = 0; i < *secret_len; i++)
        printf("%02x", secret[i]);
    printf("\n");
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    
    /* TO DO: HMAC THE SECRET */
    return secret;
}
