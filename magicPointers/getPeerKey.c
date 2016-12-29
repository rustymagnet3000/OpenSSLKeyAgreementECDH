#include "getPeerKey.h"

#define PEER_PUBLIC_KEY_FILENAME "appPubKey.pem"

void *get_peer_key()
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

    printf("✅ read %lu characters from Peer Public Key file\n\n", fileLength);
    goto end;
    
err:
    printf("❗️error reading peer public key\n\n");
    ERR_print_errors_fp(stderr);
    
end:
    fclose(fp);
    return(peerKey);
}
