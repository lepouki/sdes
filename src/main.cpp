#include <iostream>

#include "sdes/sdes.hpp"

int main()
{
    sdes::Mappings m;
    sdes::SDES algorithm(1, m);

    const auto kBlock = 1234;
    const auto kCipher = algorithm.Encrypt(kBlock);

    std::cerr
        << kBlock << " > "
        << kCipher << " > "
        << algorithm.Decrypt(kCipher)
        << std::endl;
}
