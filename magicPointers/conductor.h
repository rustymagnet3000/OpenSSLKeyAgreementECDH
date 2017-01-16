#ifndef conductor_h
#define conductor_h

#include <stdio.h>
#include <stdbool.h>
#include "keyGeneration.h"
#include "generateHmac.h"

bool result_ec_key_generation();
bool result_derived_secret();

#endif /* conductor_h */
