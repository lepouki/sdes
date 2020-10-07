#include <iostream>

#include "sdes/sdes.hpp"

int
main()
{
    sdes::Mappings mappings(16); // Give it the number of rounds
    sdes::SDES algorithm(12354654642, mappings);
    std::cerr << algorithm.Encrypt(123456789) << std::endl;
}
