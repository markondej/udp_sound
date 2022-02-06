PRODUCT_NAME = UDP Sound Stream
PRODUCT_VERSION = 0.9.0.0
FLAGS = -Wall -O3 -std=c++11

all: service.o client.o udp_stream.o
	g++ -lpthread -lasound -o service service.o udp_stream.o
	g++ -lpthread -lasound -o client client.o udp_stream.o

service.o: service.cpp
	g++ $(FLAGS) -DPRODUCT_NAME="\"$(PRODUCT_NAME)\"" -DPRODUCT_VERSION="\"$(PRODUCT_VERSION)\"" -c service.cpp

client.o: client.cpp
	g++ $(FLAGS) -DPRODUCT_NAME="\"$(PRODUCT_NAME)\"" -DPRODUCT_VERSION="\"$(PRODUCT_VERSION)\"" -c client.cpp
	
udp_stream.o: udp_stream.cpp
	g++ $(FLAGS) -c udp_stream.cpp

clean:
	rm *.o
