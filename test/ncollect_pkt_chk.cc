#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <strings.h>

#include <iostream>

#include "../netflow.h"
#include "../parse_conf.h"

#define NETFLOW_MSG_SIZE 1550

static conf_params cfg_params;
static const char *CONF_FILE = "../ncollect.cfg";

void parse_conf(){
  parse_conf_params(CONF_FILE, cfg_params);
}

void printPacket(unsigned char *pkt){
  unsigned char* dummy = new unsigned char[NETFLOW_MSG_SIZE];
  *dummy = *pkt;
  std::cout << "My packet is: " << pkt << std::endl;
}

int main(int argc, char **argv)
{
  int sockfd;
  struct sockaddr_in servaddr, cliaddr;
  socklen_t clen = sizeof (cliaddr);
  unsigned char *netflow_packet = new unsigned char[NETFLOW_MSG_SIZE];
  int ret;

  parse_conf();
  sockfd = socket(AF_INET, SOCK_DGRAM, 0); /* create a socket */

  /* init servaddr */
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(cfg_params.port);
  printf("Now listening to the port %u\n", cfg_params.port);

  /* bind address and port to socket */
  if(bind(sockfd, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr)) == -1)
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
      //     printf("Fuck\n");
      continue; /* we don't have enough data to decode the version */ 
    }
    //    std::cout << __LINE__ << " packet length is : " << ret << std::endl;

    packet_version = ntohs((reinterpret_cast<struct_header_v9 *>(netflow_packet))->version);
    if (packet_version == 9)
    {
      printf("Packet version is %d\n", packet_version);
      printf("Pointer val: %p\n", netflow_packet);
      std::cout << "Netflow packet is: " << netflow_packet << std::endl;

      printPacket(netflow_packet);
    }
  }
  free(netflow_packet);
  return 0;
}
