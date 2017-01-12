#include "conductor.h"

int main()
{
    
    static bool step1 = false;
    static bool step2 = false;
    
    step1 = result_ec_key_generation();
    printf("\nStep 1: %s\n", step1 ? "true" : "false" );
    
    step2 = result_derived_secret();
    printf("Step 2: %s\n", step2 ? "true" : "false" );
    return(0);

}
