# ALSA UDP streaming app

This application streams sound form one linux input device to another devices output using UDP/IP communication. Works with Raspberry Pi.

## How to run

Clone/Download this repository to your devices and build it, by typing in terminal/console (on both linux devices):
```
git clone https://github.com/markondej/udp_stream
cd udp_stream
make
```

ALSA libraries are required, so install it before building application. Ie. on Debian this can be done by:
```
sudo apt install libasound2-dev
```

Then run service on device with sound input:
```
./service 0.0.0.0 6734 plughw:1,0 44100 1 16
```
Notice:
* 0.0.0.0 is an IP address on which service will be available, this can be set to any of device's address ie. 192.168.0.64 (0.0.0.0 means binding on all available interfaces with IP address assigned)
* 6734 is an UDP port on which service is listening
* plughw:1,0 is ALSA input device which should be used, use 'arecord -l' to find out which devices are available
* 44100 is sampling rate
* 1 states only one channel will be used
* 16 is number of bits per sample
	
On the output device type:
```
./client 192.168.0.64 6734 hw:1,0
```
Notice:
* 192.168.0.64 is an IP address of device with running service
* 6734 is UDP port on which service is listening
* hw:1,0 is ALSA output device which should be used, use 'aplay -l' to find out which devices are available
