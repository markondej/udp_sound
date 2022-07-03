FLAGS = -Wall -O3 -std=c++11

all: service.o client.o udp_stream.o
	g++ -o service service.o udp_stream.o -lpthread -lasound 
	g++ -o client client.o udp_stream.o -lpthread -lasound 

service.o: service.cpp
	g++ $(FLAGS) -c service.cpp

client.o: client.cpp
	g++ $(FLAGS) -c client.cpp
	
udp_stream.o: udp_stream.cpp
	g++ $(FLAGS) -c udp_stream.cpp

clean:
	rm *.o
