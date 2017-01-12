#include "keyGeneration.h"

unsigned char *generate_ecdh(bool *res, size_t *secret_len)
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
    
end:
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    
    return secret;
}
