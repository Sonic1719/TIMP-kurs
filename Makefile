COMPILER = g++
FLAGS = -std=c++14 -Wall

all: main.o server.o
	$(COMPILER) $(FLAGS) main.o server.o -o server_static -lboost_program_options -lcryptopp

main.o: main.cpp server.h
	$(COMPILER) $(FLAGS) -c main.cpp -o main.o

server.o: server.cpp server.h
	$(COMPILER) $(FLAGS) -c server.cpp -o server.o

clean:
	rm -f *.o server_static
