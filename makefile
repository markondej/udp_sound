FLAGS = -Wall -O2

all: player.o wave_play.o
	g++ -lasound -o wave_play wave_play.o player.o

player.o: player.cpp player.h
	g++ $(FLAGS) -c player.cpp
	
wave_play.o: wave_play.cpp
	g++ $(FLAGS) -c wave_play.cpp
	
clean:
	rm *.o