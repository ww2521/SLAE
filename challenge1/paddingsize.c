#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main()
{
    printf("sizeof(sockaddr)=0x%x\n",sizeof(struct sockaddr));
    printf("0x%x",sizeof(struct sockaddr)-__SOCKADDR_COMMON_SIZE-sizeof(in_port_t)-sizeof(struct in_addr));
    return 0;
}
