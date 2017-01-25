#include "keyGeneration.h"

int main()
{
    static bool result;
    bool result_peer_key = false;
    char *location_to_read_peer_key = "peerPubKey.pem";
    char *location_to_write_bin_key = "server_Bin_Key.pem";
    
    if (read_peer_key(location_to_read_peer_key))
    {
        result_peer_key = true;
        result = result_ecdh_key_derivation(location_to_read_peer_key, location_to_write_bin_key);
        
        printf("\nKey Derivation success: %s\n", result ? "true" : "false" );
    }
    
    fputs(result_peer_key ? "File path for Peer Key: success\n" : "Status: false\n", stdout);

    return(0);
}
