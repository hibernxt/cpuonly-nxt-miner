CC=g++
CFLAGS=-I. -m64
LDFLAGS=-static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive -static-libstdc++ -static-libgcc -lcrypto -ldl -lboost_thread -lboost_system -m64
%.o: %.cpp $(DEPS)
	$(CC) -O2 -Wall -std=c++0x -c -o $@ $< $(CFLAGS)

miner: nxtminer.o happyhttp.o
	g++ -o miner nxtminer.o happyhttp.o $(LDFLAGS) 
