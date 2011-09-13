#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parse_conf.h"

#define MAX_SIZE 1000
char *
c_trim(char *str)
{
  size_t len = 0;
  char *frontp = str - 1;
  char *endp = NULL;

  if (str == NULL)
    return NULL;

  if (str[0] == '\0')
    return str;

  len = strlen(str);
  endp = str + len;

  /* Move the front and back pointers to address
   * the first non-whitespace characters from
   * each end.
   */
  while (isspace(*(++frontp)))
    ;
  while (isspace(*(--endp)) && endp != frontp)
    ;

  if (str + len - 1 != endp)
    *(endp + 1) = '\0';
  else if (frontp != str && endp == frontp)
    *str = '\0';

  /* Shift the string so that it starts at str so
   * that if it's dynamically allocated, we can
   * still free it on the returned pointer.  Note
   * the reuse of endp to mean the front of the
   * string buffer now.
   */
  endp = str;
  if (frontp != str) {
    while (*frontp)
      *endp++ = *frontp++;
    *endp = '\0';
  }

  return str;
}

void
parse_conf_params(const char *filename, conf_params &confs)
{
  char *line = new char[MAX_SIZE];
  FILE *fp ;
  fp = fopen(filename, "r");
  if (!fp) {
    syslog(LOG_ALERT, "Can not read the file: %s\n", filename);
    exit(EXIT_FAILURE);
  }
  while (fgets(line, MAX_SIZE, fp) != NULL) {
    char *val = strchr(line, '=');
    confs.debug_option = false;
    confs.enable_mysql = false;
    confs.enable_replay = false;
    //if the line is not a comment
    if (strcasestr(line, "#") == NULL && val != NULL) {
      while(strstr(val, "=")){
        ++val;
      }
      val = c_trim(val);
      //check for each case
      if (strcasestr(line, "ENABLE_MYSQL") != NULL) {
        if (strcmp(val, "1") == 0) {
          confs.enable_mysql = true;
          printf("Mysql is enabled!\n");
        }
      } else if (strcasestr(line, "MYSQL_USERNAME") != NULL) {
        confs.db_params.username = (char *) malloc(strlen(val)+1);
        strncpy(confs.db_params.username, val, strlen(val) + 1);
      } else if (strcasestr(line, "MYSQL_HOST")) {
        confs.db_params.host = (char *) malloc(strlen(val)+1);
        strncpy(confs.db_params.host, val, strlen(val) + 1);
      } else if (strcasestr(line, "MYSQL_DBNAME")) {
        confs.db_params.dbname = (char *) malloc(strlen(val)+1);
        strncpy(confs.db_params.dbname, val, strlen(val) +1);
      } else if (strcasestr(line, "MYSQL_PASS")) {
        confs.db_params.password = (char *) malloc(strlen(val)+1);
        strncpy(confs.db_params.password, val, strlen(val) + 1);
      } else if (strcasestr(line, "PORT") && (strcasestr(line, "REPLAY_PORT") == NULL)) {
        confs.port = (unsigned int) atoi(val);
      } else if (strcasestr(line, "DEBUG_OPTION")) {
        if (strcmp(val, "1") == 0) {
          confs.debug_option = true;
        }
      } else if (strcasestr(line, "ENABLE_REPLAY")) {
        if (strcmp(val, "1") == 0) {
          confs.enable_replay = true;
          printf("Replay is on\n");
        }
      } else if (strcasestr(line, "REPLAY_PORT")) {
        confs.replay_port = (char *) malloc(strlen(val) + 1);
        strncpy(confs.replay_port, val, strlen(val) + 1);

      } else if (strcasestr(line, "REPLAY_DEST")) {
        confs.replay_dest = (char *) malloc(strlen(val) + 1);
        strncpy(confs.replay_dest, val, strlen(val) + 1);
      }
    }
  }
}
