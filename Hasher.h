#ifndef RADIUS_HASHER_H
#define RADIUS_HASHER_H

#include <string.h>
#include <iostream>
#include <string>
#include <gcrypt.h>

using namespace std;

class Hasher {
public:
    static string makeHash(string[]);
};

#endif //RADIUS_HASHER_H