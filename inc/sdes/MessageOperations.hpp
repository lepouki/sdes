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

    [[nodiscard]]
    inline std::vector<std::uint64_t> DecomposeMessage(const std::string& message) noexcept;

    [[nodiscard]]
    inline std::string RecomposeMessage(const std::vector<std::uint64_t>& message) noexcept;

    // Implementation //

    std::vector<std::uint64_t> DecomposeMessage(const std::string& message) noexcept
    {
        std::vector<std::uint64_t> blocks(message.size() / 8 + 2); // 1 extra block to store the size of the last block

        std::size_t charIndex = 0;

        for (std::size_t i = 0; i < blocks.size() - 1; ++i) // Exclude the last block
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

    std::string RecomposeMessage(const std::vector<std::uint64_t>& message) noexcept
    {
        const auto kLastBlockSize = message.back();
        const auto kTextMessageLength = (message.size() - 2) * 8 + kLastBlockSize;

        std::string text;
        text.reserve(kTextMessageLength);

        std::size_t charIndex = 0;

        for (std::size_t i = 0; i < message.size() - 1; ++i) // Exclude the last block
        {
            const auto kBlock = message[i];

            // Retrieve up to 8 bytes from the block
            for (unsigned j = 0; j < 8 && charIndex < text.capacity(); ++j)
            {
                const auto kChar = kBlock >> (j * 8u);
                text += static_cast<char>(kChar);
                ++charIndex;
            }
        }

        // Not sure if this should be moved or if RVO works here
        return std::move(text);
    }

} // namespace sdes

#endif // SDES_MESSAGE_OPERATIONS_HPP
