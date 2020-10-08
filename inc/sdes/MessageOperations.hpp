//
// Created by lepouki on 10/8/2020.
//

#ifndef SDES_MESSAGE_OPERATIONS_HPP
#define SDES_MESSAGE_OPERATIONS_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace sdes
{

    inline std::vector<std::uint64_t> DecomposeMessage(const std::string& message) noexcept;
    inline std::string RecomposeMessage(const std::vector<std::uint64_t>& messageBlocks) noexcept;

    // Implementation //

    std::vector<std::uint64_t> DecomposeMessage(const std::string& message) noexcept
    {
        // 1 extra block to store the size of the last block
        std::vector<std::uint64_t> blocks(message.size() / 8 + 2);

        std::size_t charIndex = 0;

        for (unsigned i = 0; i < blocks.size() - 1 /* Exclude the last block */; ++i)
        {
            auto& block = blocks[i];

            // Insert up to 8 bytes into the block
            for (unsigned j = 0; j < 8 && charIndex < message.size(); ++j)
            {
                const auto kChar = message[charIndex];
                block |= static_cast<std::uint64_t>(kChar) << (j * 8u);
                ++charIndex;
            }
        }

        blocks.back() = message.size() % 8; // Size of the last block
        return blocks;
    }

    std::string RecomposeMessage(const std::vector<std::uint64_t>& messageBlocks) noexcept
    {
        const auto kLastBlockSize = messageBlocks.back();
        const auto kOriginalMessageLength = (messageBlocks.size() - 2) * 8 + kLastBlockSize;

        std::string message(kOriginalMessageLength, '*');
        std::size_t charIndex = 0;

        for (unsigned i = 0; i < messageBlocks.size() - 1 /* Exclude the last block */; ++i)
        {
            auto& block = messageBlocks[i];

            // Retrieve up to 8 bytes from the block
            for (unsigned j = 0; j < 8 && charIndex < message.size(); ++j)
            {
                const auto kChar = block >> (j * 8u);
                message[charIndex] = static_cast<char>(kChar);
                ++charIndex;
            }
        }

        // Not sure if this should be moved or if RVO works here
        return std::move(message);
    }

} // namespace sdes

#endif // SDES_MESSAGE_OPERATIONS_HPP
