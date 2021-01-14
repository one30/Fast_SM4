/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2020-11-11 21:14:16
 * @LastEditTime : 2021-01-14 13:28:57
 * @FilePath     : /test/main.c
 */
#include <stdio.h>
#include "sm4_bs256.h"

int main(int argc, char * argv[]){
    printf("bitslice!\n");
    sm4_bs256_ecb_test();
    //sm4_bs256_ctr_test();
    sm4_bs256_gcm_test();
}