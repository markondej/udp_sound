CXX = g++
CXXFLAGS = -Wall -O3 -std=c++11

LIBS = -lpthread -lasound

CLIENT_OBJS = client.o udp_stream.o
SERVICE_OBJS = service.o udp_stream.o

.PHONY: clean all

all: client service

client: $(CLIENT_OBJS)
	$(CXX) -o client $(CLIENT_OBJS) $(LIBS)

service: $(SERVICE_OBJS)
	$(CXX) -o service $(SERVICE_OBJS) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm *.o
