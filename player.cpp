#include "player.h"
#include <exception>
#include <iostream>
#include <fstream>

Player::Player(std::string filename)
{
    std::vector<char> buffer;
    unsigned int length;
    int error;

    std::ifstream is(filename.c_str(), std::ifstream::binary);

    if (!is) {
        std::cout << "Cannot open '" << filename << "', file does not exist" << std::endl;
        throw std::exception();
    }

    is.seekg(0, is.end);
    length = is.tellg();
    is.seekg(0, is.beg);

    if (length < sizeof(PCMWaveHeader)) {
        std::cout << "Error while opening '" << filename << "', data corrupted" << std::endl;
        throw std::exception();
    }

    buffer.resize(length);
    is.read(&buffer[0], length);
    is.close();

    memcpy(&header, &buffer[0], sizeof(PCMWaveHeader));

    if ((error = checkDataFormat(&header)) > 0) {
        std::cout << "Error while opening '" << filename << "', unsupported data format (" << error << ")" << std::endl;
        throw std::exception();
    }

    if (length < sizeof(PCMWaveHeader) + header.subchunk2Size) {
        std::cout << "Error while opening '" << filename << "', data corrupted" << std::endl;
        throw std::exception();
    }

    data.resize(header.subchunk2Size);
    memcpy(&data[0], &buffer[sizeof(PCMWaveHeader)], header.subchunk2Size);

    this->filename = filename;
}

Player::~Player()
{
}

void Player::play()
{
    snd_pcm_t *handle;
    unsigned int offset, size, periodSize, frameBytes;
    int error;

    frameBytes = (header.bitsPerSample >> 3) * header.channels;

    std::cout << "Playing '" << filename << "': ";
    std::cout << header.sampleRate << " Hz, ";
    std::cout << header.bitsPerSample << " bits, ";
    std::cout << ((header.channels != 1) ? "stereo" : "mono") << std::endl;

    if ((error = snd_pcm_open(&handle, "default", SND_PCM_STREAM_PLAYBACK, 0)) < 0) {
        std::cout << "Error, cannot open audio interface (" << snd_strerror(error) << ")" << std::endl;
        throw std::exception();
    }

    if ((error = initAudioParams(handle, header.sampleRate, header.channels, (header.bitsPerSample >> 3), &periodSize)) < 0) {
        std::cout << "Error, cannot initialize audio interface (" << snd_strerror(error) << ")" << std::endl;
        snd_pcm_close(handle);
        throw std::exception();
    }

    if ((error = snd_pcm_prepare(handle)) < 0) {
        std::cout << "Error, cannot prepare audio interface for use (" << snd_strerror(error) << ")" << std::endl;
        snd_pcm_close(handle);
        throw std::exception();
    }

    offset = 0;

    while (offset < header.subchunk2Size) {
        size = periodSize;
        if (offset + periodSize > header.subchunk2Size) {
            size = header.subchunk2Size - offset;
        }
        error = snd_pcm_writei(handle, &data[offset], size / frameBytes);
        if (error == -EAGAIN) {
            continue;
        } else if (error == -EPIPE) {
            if ((error = snd_pcm_prepare(handle)) < 0) {
                std::cout << "Cannot recover from underrun (" << snd_strerror(error) << ")" << std::endl;
                break;
            }
        } else if (error == -ESTRPIPE) {
            while ((error = snd_pcm_resume(handle)) == -EAGAIN) {
                usleep(PLAYER_BUFFER_TIME);
            }
            if (error < 0) {
                if ((error = snd_pcm_prepare(handle)) < 0) {
                    std::cout << "Cannot recover from suspend (" << snd_strerror(error) << ")" << std::endl;
                    break;
                }
            }
        } else if (error < 0) {
            std::cout << "Unknown ALSA avail update return value (" << snd_strerror(error) << ")" << std::endl;
            break;
        }
        offset += error * frameBytes;
        usleep(PLAYER_PERIOD_TIME >> 2);
    }
    if (error < 0) {
        snd_pcm_close(handle);
        throw std::exception();
    }
    usleep(PLAYER_BUFFER_TIME);

    snd_pcm_close(handle);
}

int Player::checkDataFormat(PCMWaveHeader *header)
{
    int error = 0;

    if (std::string(header->chunkID, 4) != std::string("RIFF")) {
        error |= 0x01;
    }
    if (std::string(header->format, 4) != std::string("WAVE")) {
        error |= (0x01 << 1);
    }
    if (std::string(header->subchunk1ID, 4) != std::string("fmt ")) {
        error |= (0x01 << 2);
    }
    if (header->subchunk1Size != 16) {
        error |= (0x01 << 3);
    }
    if (header->audioFormat != WAVE_FORMAT_PCM) {
        error |= (0x01 << 4);
    }
    if (header->byteRate != (header->bitsPerSample >> 3) * header->channels * header->sampleRate) {
        error |= (0x01 << 5);
    }
    if (header->blockAlign != (header->bitsPerSample >> 3) * header->channels) {
        error |= (0x01 << 6);
    }
    if (((header->bitsPerSample >> 3) != 1) && ((header->bitsPerSample >> 3) != 2)) {
        error |= (0x01 << 7);
    }
    if (std::string(header->subchunk2ID, 4) != std::string("data")) {
        error |= (0x01 << 8);
    }

    return error;
}

int Player::initAudioParams(snd_pcm_t *handle, unsigned int sampleRate, unsigned int channels, unsigned int bytesPerSample, unsigned int *periodSize)
{
    int error, dir;
    unsigned int rate, bufferTime, periodTime, bufferSize;
    snd_pcm_hw_params_t *hwParams;
    snd_pcm_sw_params_t *swParams;
    snd_pcm_uframes_t size;

    snd_pcm_hw_params_malloc(&hwParams);

    if ((error = snd_pcm_hw_params_any(handle, hwParams)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }

    if ((error = snd_pcm_hw_params_set_access(handle, hwParams, SND_PCM_ACCESS_RW_INTERLEAVED)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }

    if ((error = snd_pcm_hw_params_set_format(handle, hwParams, (bytesPerSample != 1) ? SND_PCM_FORMAT_S16_LE : SND_PCM_FORMAT_U8)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }

    if ((error = snd_pcm_hw_params_set_channels(handle, hwParams, channels)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }

    rate = sampleRate;
    if ((error = snd_pcm_hw_params_set_rate_near(handle, hwParams, &rate, 0)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }
    if (sampleRate != rate) {
        snd_pcm_hw_params_free(hwParams);
        return -EINVAL;
    }

    bufferTime = PLAYER_BUFFER_TIME;
    if ((error = snd_pcm_hw_params_set_buffer_time_near(handle, hwParams, &bufferTime, &dir)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }

    if ((error = snd_pcm_hw_params_get_buffer_size(hwParams, &size)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }
    bufferSize = size;

    periodTime = PLAYER_PERIOD_TIME;
    if ((error = snd_pcm_hw_params_set_period_time_near(handle, hwParams, &periodTime, &dir)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }

    if ((error = snd_pcm_hw_params_get_period_size(hwParams, &size, &dir)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }
    *periodSize = size;

    if ((error = snd_pcm_hw_params(handle, hwParams)) < 0) {
        snd_pcm_hw_params_free(hwParams);
        return error;
    }

    snd_pcm_hw_params_free(hwParams);
    snd_pcm_sw_params_malloc(&swParams);

    if ((error = snd_pcm_sw_params_current(handle, swParams)) < 0) {
        snd_pcm_sw_params_free(swParams);
        return error;
    }

    if ((error = snd_pcm_sw_params_set_start_threshold(handle, swParams, (bufferSize / (*periodSize)) * (*periodSize))) < 0) {
        snd_pcm_sw_params_free(swParams);
        return error;
    }

    if ((error = snd_pcm_sw_params_set_avail_min(handle, swParams, (*periodSize))) < 0) {
        snd_pcm_sw_params_free(swParams);
        return error;
    }

    if ((error = snd_pcm_sw_params(handle, swParams)) < 0) {
        snd_pcm_sw_params_free(swParams);
        return error;
    }

    snd_pcm_sw_params_free(swParams);
    return 0;
}
