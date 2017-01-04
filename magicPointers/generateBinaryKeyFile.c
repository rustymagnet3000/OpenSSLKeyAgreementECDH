#include "generateBinaryKeyFile.h"

#define DERIVED_KEY_FILENAME "serBinaryKey.bin"

void *generate_bin_key_file(unsigned char *derived_secret, size_t *secret_size)
{
    
    FILE *bin_fp;

    bin_fp = fopen(DERIVED_KEY_FILENAME,"wb");
    if (!bin_fp)
    {
        printf("Unable to open file!");
    }
    
    fwrite(derived_secret, *secret_size, 1, bin_fp);

    fclose(bin_fp);
    return(0);
}
