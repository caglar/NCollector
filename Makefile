clean: obj
	rm *.o
OPT_FLAGS=-O4 -march=native -fno-strict-aliasing
FLAGS=-Wall -ggdb $(OPT_FLAGS)
PTHREAD=-lpthread -D_REENTRANT
obj: ncollect.o netflow.o parse_conf.o
	g++ $(FLAGS) -o ncollect -L /usr/local/lib/ -lmysqlpp netflow.o ncollect.o parse_conf.o
ncollect.o: ncollect.cc parse_conf.o
	g++ $(FLAGS) -c ncollect.cc
netflow.o: netflow.cc
	g++ $(FLAGS) $(PTHREAD) -c -I /usr/local/include/mysql++ -I /usr/include/mysql netflow.cc
parse_conf.o: parse_conf.cc
	g++ $(FLAGS) -c  parse_conf.cc
