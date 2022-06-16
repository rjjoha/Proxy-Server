CXX = g++
CXXFLAGS = -Wall -pthread -lssl -lcrypto -std=c++11

all: bin/myproxy

bin/myproxy: src/myproxy.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@


clean:
	rm -f *.o
	rm bin/myproxy