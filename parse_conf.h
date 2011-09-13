#ifndef PARSE_CONF_H
#define PARSE_CONF_H

struct mysql_params{
	char *username;
	char *host;
	char *dbname;
	char *password;
};

struct conf_params{
	bool enable_mysql;
	mysql_params db_params;
	unsigned int port;
	bool debug_option;
	bool enable_replay;
	char* replay_port;
	char* replay_dest;
};

void
parse_conf_params(const char *filename, conf_params &confs);

#endif
