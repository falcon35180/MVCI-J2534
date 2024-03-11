#include <windows.h>

void DES_init(unsigned char *key);
void DES_crypt(unsigned char *inBuf, unsigned int inLen, unsigned char *outBuf, BOOL encrypt);

