all:
	g++ -std=c++11 main.cpp -I. -lcryptopp -lpthread -lboost_system -lsqlite3 -o protocol
