#include <stdio.h>
#include <string.h>

#include "des.h"
#include "des_crypt.h"

key_set DES_key_sets[17];

void DES_init(unsigned char *key)
{
    generate_sub_keys(key, DES_key_sets);
    
    return;
}


void DES_crypt(unsigned char *inBuf, unsigned int inLen, unsigned char *outBuf, BOOL encrypt)
{
    int mode = encrypt ? ENCRYPTION_MODE : DECRYPTION_MODE;

    unsigned char tmpBuf[8];
    unsigned char cryptBuf[8];
    while(inLen >= 8)
    {
        process_message(inBuf, cryptBuf, DES_key_sets, mode);
        memcpy_s(outBuf, 8, cryptBuf, 8);
        inBuf += 8;
        outBuf += 8;
        inLen -= 8;
    }

    if(inLen > 0)
    {
        memset(tmpBuf, 0, 8);
        memcpy_s(tmpBuf, 8, inBuf, inLen);
        process_message(tmpBuf, cryptBuf, DES_key_sets, mode);
        memcpy_s(outBuf, inLen, cryptBuf, inLen);
    }    
    return;
}

