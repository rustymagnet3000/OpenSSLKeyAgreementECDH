#include "generatePemFile.h"

#define PUBLIC_KEY_FILENAME "serPubKey.pem"
#define PRIVATE_KEY_FILENAME "serPriKey.pem"

void *generate_pem_file(EVP_PKEY *evp_pkey)
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
