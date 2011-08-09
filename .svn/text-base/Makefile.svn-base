clean: obj
	rm *.o
obj: main.o
	g++ -o collector -L /usr/local/lib/ -lmysqlpp main.o
#-lmysqlpp指定连接的库，在默认的库文件存放地：/usr/lib等路径中搜索

main.o: main.cpp
	g++ -c -I /usr/local/include/mysql++ -I /usr/include/mysql main.cpp
#-I /usr/include/mysql++ -I /usr/include/mysql指定包含的头文件所在目录

