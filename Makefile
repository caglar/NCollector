clean: obj
	rm *.o
obj: ncollect.o netflow.o 
	g++ -O4 -Wall -march=native -o ncollect -L /usr/local/lib/ -lmysqlpp netflow.o ncollect.o
ncollect.o: ncollect.cc
	g++ -O4 -Wall -c -march=native ncollect.cc
netflow.o: netflow.cc
	g++ -O4 -Wall -c -march=native -I /usr/local/include/mysql++ -I /usr/include/mysql netflow.cc
