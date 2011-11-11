clean: obj
	rm *.o
CXX=g++-4.4
OPT_FLAGS=-O4 -march=native -fno-strict-aliasing
FLAGS=-Wall -ggdb $(OPT_FLAGS)
PTHREAD=-lpthread -D_REENTRANT
obj: ncollect.o netflow.o parse_conf.o
	$(CXX) $(FLAGS) -o ncollect -I /usr/include/mysql/ -L /usr/local/lib/ -lmysqlclient -lmysqlpp netflow.o ncollect.o parse_conf.o
ncollect.o: ncollect.cc parse_conf.o
	$(CXX) $(FLAGS) -I /usr/include/mysql/ -L /usr/local/lib/ -lmysqlclient -lmysqlpp -c ncollect.cc
netflow.o: netflow.cc
	$(CXX) $(FLAGS) $(PTHREAD) -c -I /usr/include/mysql/ -L /usr/local/lib/ -lmysqlclient -lmysqlpp netflow.cc
parse_conf.o: parse_conf.cc
	$(CXX) $(FLAGS) -c  parse_conf.cc
