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

#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>


#include "netflow.h"
#include "parse_conf.h"


#define NETFLOW_MSG_SIZE 1551

static conf_params cfg_params;
static const char *CONF_FILE = "ncollect.cfg";

void parse_conf(){
  parse_conf_params(CONF_FILE, cfg_params);
}

/* Change this to whatever your daemon is called */
#define DAEMON_NAME "ncollectd"

/* Change this to the user under which to run */
#define RUN_AS_USER "ncollect"

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1


static void child_handler(int signum)
{
  switch(signum) {
   case SIGALRM: exit(EXIT_FAILURE); break;
   case SIGUSR1: exit(EXIT_SUCCESS); break;
   case SIGCHLD: exit(EXIT_FAILURE); break;
  }
}

static void daemonize( const char *lockfile )
{
  pid_t pid, sid, parent;
  int lfp = -1;

  /* already a daemon */
  if ( getppid() == 1 ) return;

  /* Create the lock file as the current user */
  if ( lockfile && lockfile[0] ) {
    lfp = open(lockfile,O_RDWR|O_CREAT,0640);
    if ( lfp < 0 ) {
      syslog( LOG_ERR, "unable to create lock file %s, code=%d (%s)",
              lockfile, errno, strerror(errno) );
      exit(EXIT_FAILURE);
    }
  }

  /* Drop user if there is one, and we were run as root */
  if ( getuid() == 0 || geteuid() == 0 ) {
    struct passwd *pw = getpwnam(RUN_AS_USER);
    if ( pw ) {
      syslog( LOG_NOTICE, "setting user to " RUN_AS_USER );
      setuid( pw->pw_uid );
    }
  }

  /* Trap signals that we expect to recieve */
  signal(SIGCHLD,child_handler);
  signal(SIGUSR1,child_handler);
  signal(SIGALRM,child_handler);

  /* Fork off the parent process */
  pid = fork();
  if (pid < 0) {
    syslog( LOG_ERR, "unable to fork daemon, code=%d (%s)",
            errno, strerror(errno) );
    exit(EXIT_FAILURE);
  }
  /* If we got a good PID, then we can exit the parent process. */
  if (pid > 0) {

    /* Wait for confirmation from the child via SIGTERM or SIGCHLD, or
       for two seconds to elapse (SIGALRM).  pause() should not return. */
    alarm(2);
    pause();

    exit(EXIT_FAILURE);
  }

  /* At this point we are executing as the child process */
  parent = getppid();

  /* Cancel certain signals */
  signal(SIGCHLD,SIG_DFL); /* A child process dies */
  signal(SIGTSTP,SIG_IGN); /* Various TTY signals */
  signal(SIGTTOU,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGHUP, SIG_IGN); /* Ignore hangup signal */
  signal(SIGTERM,SIG_DFL); /* Die on SIGTERM */

  /* Change the file mode mask */
  umask(0);

  /* Create a new SID for the child process */
  sid = setsid();
  if (sid < 0) {
    syslog( LOG_ERR, "unable to create a new session, code %d (%s)",
            errno, strerror(errno) );
    exit(EXIT_FAILURE);
  }

  /* Change the current working directory.  This prevents the current
     directory from being locked; hence not being able to remove it. */
  if ((chdir("/")) < 0) {
    syslog( LOG_ERR, "unable to change directory to %s, code %d (%s)",
            "/", errno, strerror(errno) );
    exit(EXIT_FAILURE);
  }

  /* Redirect standard files to /dev/null */
  freopen( "/dev/null", "r", stdin);
  freopen( "/dev/null", "w", stdout);
  freopen( "/dev/null", "w", stderr);

  /* Tell the parent process that we are A-okay */
  kill( parent, SIGUSR1 );
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

  openlog( DAEMON_NAME, LOG_PID, LOG_LOCAL5 );
  syslog( LOG_INFO, "starting" );

  parse_conf();
  sprintf(port, "%u", cfg_params.port);
  //itoa(cfg_params.port, port, 10);

  /* Daemonize */
  if (cfg_params.daemonize) {
    daemonize("/var/lock/" DAEMON_NAME);
  }
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
 
 /* Finish up */
  syslog( LOG_NOTICE, "terminated" );
  closelog();
  close(sockfd);

  return 0;
}
