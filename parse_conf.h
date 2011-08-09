#ifndef PARSE_CONF_H
#define PARSE_CONF_H

struct mysql_params{
	char *username;
	char *host;
	char *dbname;
	char *password;
};

struct conf_params{
	mysql_params db_params;
	unsigned int port;
	bool debug_option;
};

void parse_confs(char *filename, conf_params &confs);

#endif
