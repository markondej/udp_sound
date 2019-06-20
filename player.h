#ifndef PLAYER_H
#define PLAYER_H

#define PLAYER_BUFFER_TIME 500000
#define PLAYER_PERIOD_TIME 100000

#include <alsa/asoundlib.h>
#include <string>
#include <vector>
#include "pcm_wave_header.h"

class Player
{
    public:
        Player(std::string filename);
        virtual ~Player();
        int checkDataFormat(PCMWaveHeader *header);
        void play();
    private:
        PCMWaveHeader header;
        std::string filename;
        std::vector<char> data;
        int initAudioParams(snd_pcm_t *handle, unsigned int sampleRate, unsigned int channels, unsigned int bytesPerSample, unsigned int *periodSize);
};

#endif // PLAYER_H
