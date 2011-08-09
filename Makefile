clean: obj
	rm *.o
obj: main.o
	g++ -O4 -Wall -o collector -L /usr/local/lib/ -lmysqlpp main.o

main.o: main.cpp
	g++ -O4 -Wall -c -I /usr/local/include/mysql++ -I /usr/include/mysql main.cpp
