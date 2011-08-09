#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <strings.h>

#include "netflow.h"

int main(void)
{
  var_init();
  int sockfd;
  struct sockaddr_in servaddr, cliaddr;
  socklen_t clen = sizeof (cliaddr);
  unsigned char netflow_packet[NETFLOW_MSG_SIZE];
  int ret;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0); /* create a socket */

  /* init servaddr */
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(SERV_PORT);

  /* bind address and port to socket */
  if(bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
  {
    perror("bind error");
    exit(1);
  }

  unsigned short int packet_version;
  for(;;)
  {
    ret = recvfrom(sockfd, netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &cliaddr, &clen);
    if (ret < 1)
    { 
      continue; /* we don't have enough data to decode the version */ 
    }
    //cout << __LINE__ << " packet length is : " << ret << endl;
    packet_version = ntohs(((struct struct_header_v9 *)netflow_packet)->version);
    if (packet_version == 9)
    {
      process_v9_packet(netflow_packet, ret);
    }
  }
  return 0;
}
