#include <iostream>

#include "sdes/sdes.hpp"
#include "sdes/MessageOperations.hpp"

inline void PrintBlock(std::uint64_t block)
{
    for (unsigned i = 0; i < 8; ++i)
    {
        const auto kChar = block >> (i * 8u);

        // Remove the 8th bit to get ASCII characters only
        std::cout << static_cast<char>(kChar & 0x7Fu);
    }
}

inline void PrintBlocks(const std::vector<std::uint64_t>& blocks)
{
    for (const auto& kBlock : blocks)
    {
        PrintBlock(kBlock);
    }

    std::cout << std::endl;
}

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

    // Print the encrypted message (non alphanumeric characters may break the output)
    PrintBlocks(ciphers);

    // Decrypt the encrypted blocks
    for (auto& cipher : ciphers)
    {
        cipher = algorithm.Decrypt(cipher);
    }

    // Recompose the original message
    std::cout << sdes::RecomposeMessage(ciphers) << std::endl;
}
