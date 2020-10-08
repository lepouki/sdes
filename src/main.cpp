#include <iostream>

#include "sdes/sdes.hpp"
#include "sdes/MessageOperations.hpp"

int main()
{
    // Decompose the message into 64-bits blocks
    const auto kBlocks = sdes::DecomposeMessage("My name Jeff");
    const auto kNumBlocks = kBlocks.size();

    // Initialize the encryption/decryption algorithm
    sdes::Mappings m;
    sdes::SDES algorithm(69420 /* Master key */, m);

    // Store the encrypted blocks
    std::vector<std::uint64_t> ciphers(kNumBlocks);

    for (unsigned i = 0; i < kNumBlocks; ++i)
    {
        const auto kBlock = kBlocks[i];
        ciphers[i] = algorithm.Encrypt(kBlock);
    }

    // Decrypt the encrypted blocks
    for (auto& cipher : ciphers)
    {
        cipher = algorithm.Decrypt(cipher);
    }

    // Recompose the original message
    std::cout << sdes::RecomposeMessage(ciphers) << std::endl;
}
