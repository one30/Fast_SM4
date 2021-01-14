/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2020-11-15 00:00:54
 * @LastEditTime : 2021-01-13 17:07:06
 * @FilePath     : /src/utils.c
 */
#include <stdio.h>
#include "utils.h"


void dump_hex(uint8_t * h, int len)
{
    while(len--)
    {   
        printf("%02hhx ",*h++);
        if(len%16==0) printf("\n");
    }
    printf("\n");
}

