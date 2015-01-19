CC=g++
CFLAGS=-I.
LDFLAGS=-static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive curl-7.40.0/libstatic_curl.a -static-libstdc++ -static-libgcc  
%.o: %.cpp $(DEPS)
	$(CC) -O2 -Wall -std=c++0x -c -o $@ $< $(CFLAGS)

miner: main.o uint128_t.o uint256_t.o
	g++ -o miner main.o uint128_t.o uint256_t.o $(LDFLAGS) 
