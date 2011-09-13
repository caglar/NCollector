/*
 * =====================================================================================
 *
 *       Filename:  listener.cc
 *
 *    Description:  test listener for the flow replays
 *
 *        Version:  1.0
 *        Created:  09/07/2011 12:16:06 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (Caglar), 
 *        Company:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "netflow.h"
#include "parse_conf.h"


#define NETFLOW_MSG_SIZE 1551

static conf_params cfg_params;
static const char *CONF_FILE = "ncollect.cfg";

void parse_conf(){
  parse_conf_params(CONF_FILE, cfg_params);
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
  var_init();
  int sockfd;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  int numbytes;
  struct sockaddr_storage their_addr;
  unsigned char buf[NETFLOW_MSG_SIZE];
  socklen_t addr_len;
  char s[INET6_ADDRSTRLEN];
  char port[6];

  parse_conf();
  sprintf(port, "%u", cfg_params.port);
  //itoa(cfg_params.port, port, 10);

  printf("Listening to port %s\n", port);
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol)) == -1) {
      perror("ncollect: socket error!");
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("ncollect: bind error");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "ncollect: failed to bind socket\n");
    return 2;
  }

  freeaddrinfo(servinfo);

  unsigned short int packet_version;

  for (;;){
    printf("ncollect: waiting to recvfrom...\n");

    addr_len = sizeof their_addr;
    if ((numbytes = recvfrom(sockfd, buf, NETFLOW_MSG_SIZE - 1, 0,
                             (struct sockaddr *)&their_addr, &addr_len)) == -1) {
      perror("recvfrom");
      exit(1);
    }

    printf("ncollect: got packet from %s\n",
           inet_ntop(their_addr.ss_family,
                     get_in_addr((struct sockaddr *)&their_addr),
                     s, sizeof s));
    packet_version = ntohs((reinterpret_cast<struct_header_v9 *>(buf))->version);
    
    if (packet_version == 9) {
      printf("ncollect: packet is %d bytes long\n", numbytes);
      buf[numbytes] = '\0';
      printf("ncollect: packet contains \"%s\"\n", buf);
      process_v9_packet(buf, numbytes, cfg_params);
    }
  }
  close(sockfd);
  return 0;
}
