FLAGS = -Wall -O3 -std=c++11

all: service.o client.o udp_stream.o
	g++ -lpthread -lasound -o service service.o udp_stream.o
	g++ -lpthread -lasound -o client client.o udp_stream.o

service.o: service.cpp
	g++ $(FLAGS) -c service.cpp

client.o: client.cpp
	g++ $(FLAGS) -c client.cpp
	
udp_stream.o: udp_stream.cpp
	g++ $(FLAGS) -c udp_stream.cpp

clean:
	rm *.o
