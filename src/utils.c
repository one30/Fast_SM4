#include <stdio.h>
#include "utils.h"


void dump_hex(uint8_t * h, int len)
{
    while(len--)
    {   
        printf("%02hhx",*h++);
        if(len%16==0) printf("\n");
    }
    printf("\n");
}

