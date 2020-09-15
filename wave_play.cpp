#include <iostream>
#include "player.h"

using namespace std;

int main(int argc, char **argv)
{
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " [FILE]" << endl;
        return 0;
    }

    string filename = argv[1];
    try {
        Player *player = new Player(filename);
        player->play();
        delete player;
    } catch (exception &e) {
        return 1;
    }
    return 0;
}
