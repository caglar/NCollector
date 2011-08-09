clean: obj
	rm *.o
obj: main.o
	g++ -O4 -Wall -march=native -o collector -L /usr/local/lib/ -lmysqlpp main.o
main.o: main.cpp
	g++ -O4 -Wall -c -march=native -I /usr/local/include/mysql++ -I /usr/include/mysql main.cpp
