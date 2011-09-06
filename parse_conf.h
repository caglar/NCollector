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
	bool replay_flows;
	unsigned int replay_port;
};

void
parse_conf_params(char *filename, conf_params &confs);

#endif
