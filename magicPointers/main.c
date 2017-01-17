#include "keyGeneration.h"

int main()
{
    static bool result;

    result = result_ecdh_key_derivation();
    printf("\nKey Derivation success: %s\n", result ? "true" : "false" );
    
    return(0);
}
