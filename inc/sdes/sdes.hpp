//
// Created by lepouki on 10/7/2020.
//

#ifndef SDES_SDES_HPP
#define SDES_SDES_HPP

#include <cstdint>

#include <array>
#include <utility>

#include "Mappings.hpp"

namespace sdes
{

    class SDES
    {
    public:
        constexpr SDES(std::uint64_t key, const Mappings& mappings) noexcept;

    public:
        constexpr void SetKey(std::uint64_t key) noexcept;

        [[maybe_unused]]
        [[nodiscard]]
        constexpr std::uint64_t GetKey() const noexcept { return mKey; }

    public:
        [[nodiscard]]
        constexpr std::uint64_t Encrypt(std::uint64_t block) noexcept;

        [[nodiscard]]
        constexpr std::uint64_t Decrypt(std::uint64_t block) noexcept;

    private:
        // One half of the master key, stored as a 32-bit int
        class KeyHalf
        {
        public:
            constexpr explicit KeyHalf(std::uint32_t value) noexcept;

        public:
            [[nodiscard]]
            constexpr explicit operator std::uint32_t() const noexcept { return mValue; }

        public: // Shift operators with wrapping (not standard compliant for the return type, who cares)
            constexpr void operator<<=(std::uint16_t offset) noexcept;
            constexpr void operator>>=(std::uint16_t offset) noexcept;

        private:
            std::uint32_t mValue;

        private:
            constexpr void Clamp() noexcept;
        };

        using KeyHalves = std::pair<KeyHalf, KeyHalf>;

    private:
        static constexpr void Swap(std::uint32_t& upper, std::uint32_t& lower) noexcept;

        // Splits a block into an array of sub blocks
        template<typename SubBlock, std::size_t NumSplits, std::size_t BlockSize, typename /* Deduced */ Block>
        [[nodiscard]]
        static constexpr std::array<SubBlock, NumSplits> Split(Block block) noexcept;

        // Glues an array of sub blocks into a single block
        template<typename Block, std::size_t SubBlockSize, typename /* Deduced */ SubBlock, std::size_t /* Deduced */ NumSplits>
        [[nodiscard]]
        static constexpr Block Glue(const std::array<SubBlock, NumSplits>& subBlocks) noexcept;

        // Recomposes the cipher blocks from its halves
        [[nodiscard]]
        static constexpr std::uint64_t MakeCipherBlock(std::uint32_t upper, std::uint32_t lower) noexcept;

    private:
        std::uint64_t mKey;
        const Mappings& mMappings;

    private:
        [[nodiscard]]
        constexpr std::uint64_t Compute(std::uint64_t block, bool encrypt) const noexcept;

        [[nodiscard]]
        constexpr KeyHalves InitializeKeyHalves(bool encrypt) const noexcept;

        // Recomposes the sub key from its halves
        [[nodiscard]]
        constexpr std::uint64_t GetSubKey(const KeyHalves& keyHalves) const noexcept;

        [[nodiscard]]
        constexpr std::uint32_t F(std::uint64_t subKey, std::uint32_t blockHalf) const noexcept;

    private:
        // Shifts the keys halves based on the provided round
        template<typename /* Deduced */ KeyShift>
        constexpr void ComputeKeyHalvesForRound(KeyHalves& halves, unsigned round, const KeyShift& keyShift) const noexcept;
    };

    // Implementation //

    template<typename SubBlock, std::size_t NumSplits, std::size_t BlockSize, typename Block>
    constexpr std::array<SubBlock, NumSplits> SDES::Split(Block block) noexcept
    {
        static_assert(NumSplits < BlockSize, "NumSplits is too big");
        static_assert(BlockSize % NumSplits == 0, "NumSplits must be a multiple of BlockSize");

        constexpr auto kSubBlockSize = (BlockSize / NumSplits);
        constexpr auto kSubBlockMask = (static_cast<Block>(1) << kSubBlockSize) - 1u;

        std::array<SubBlock, NumSplits> subBlocks = {};

        for (unsigned i = 0; i < NumSplits; ++i)
        {
            subBlocks[i] = static_cast<SubBlock>(block & kSubBlockMask);
            block >>= kSubBlockSize;
        }

        return subBlocks;
    }

    template<typename Block, std::size_t SubBlockSize, typename SubBlock, std::size_t NumSplits>
    [[nodiscard]]
    constexpr Block SDES::Glue(const std::array<SubBlock, NumSplits>& subBlocks) noexcept
    {
        static_assert(NumSplits * SubBlockSize <= (sizeof(Block) * 8), "Sub blocks don't fit in the desired block type");

        Block block = 0;

        for (unsigned i = 0; i < NumSplits; ++i)
        {
            const auto kSubBlock = subBlocks[i];
            block |= static_cast<Block>(kSubBlock) << (i * SubBlockSize);
        }

        return block;
    }

    template<typename KeyShift>
    constexpr void SDES::ComputeKeyHalvesForRound(KeyHalves& halves, unsigned round, const KeyShift& keyShift) const noexcept
    {
        const auto kOffset = mMappings.GetKeyOffsetForRound(round);

        keyShift(halves.first, kOffset);
        keyShift(halves.second, kOffset);
    }

    constexpr SDES::SDES(std::uint64_t key, const Mappings& mappings) noexcept
        : mKey(0)
        , mMappings(mappings)
    {
        SetKey(key);
    }

    constexpr void SDES::SetKey(std::uint64_t key) noexcept
    {
        mKey = mMappings.PC1(key);
    }

    constexpr std::uint64_t SDES::Encrypt(std::uint64_t block) noexcept
    {
        return Compute(block, true);
    }

    constexpr std::uint64_t SDES::Decrypt(std::uint64_t block) noexcept
    {
        return Compute(block, false);
    }

    constexpr SDES::KeyHalf::KeyHalf(std::uint32_t value) noexcept
        : mValue(value)
    {
    }

    constexpr void SDES::KeyHalf::operator<<=(std::uint16_t offset) noexcept
    {
        const auto kDiff = (28u - offset);
        mValue = (mValue << offset) + (mValue >> kDiff);
        Clamp();
    }

    constexpr void SDES::KeyHalf::operator>>=(std::uint16_t offset) noexcept
    {
        const auto kDiff = (28u - offset);
        mValue = (mValue >> offset) + (mValue << kDiff);
        Clamp();
    }

    constexpr void SDES::KeyHalf::Clamp() noexcept
    {
        mValue &= 0x0FFFFFFFu; // Keep only the first 28 bits
    }

    constexpr void SDES::Swap(std::uint32_t& upper, std::uint32_t& lower) noexcept
    {
        const auto kTemp = upper;

        upper = lower;
        lower = kTemp;
    }

    constexpr std::uint64_t SDES::Compute(std::uint64_t block, bool encrypt) const noexcept
    {
        auto keyHalves = InitializeKeyHalves(encrypt);

        block = mMappings.IP(block);
        auto [upper, lower] = Split<std::uint32_t, 2, 64>(block);

        for (unsigned i = 0; i < 16; ++i)
        {
            if (encrypt)
            {
                constexpr auto kKeyShift = [](KeyHalf& half, std::uint16_t offset) { half <<= offset; };
                ComputeKeyHalvesForRound(keyHalves, i, kKeyShift);
            }
            // Don't shift on the first round when decrypting
            else if (i > 0)
            {
                constexpr auto kKeyShift = [](KeyHalf& half, std::uint16_t offset) { half >>= offset; };
                ComputeKeyHalvesForRound(keyHalves, 16 - i, kKeyShift);
            }

            upper ^= F(GetSubKey(keyHalves), lower);
            Swap(upper, lower);
        }

        return mMappings.FP(MakeCipherBlock(upper, lower));
    }

    constexpr auto SDES::InitializeKeyHalves(bool encrypt) const noexcept -> KeyHalves
    {
        auto [upper, lower] = Split<std::uint32_t, 2, 56>(mKey);
        KeyHalves halves(upper, lower);

        if (!encrypt)
        {
            for (unsigned i = 0; i < 16; ++i)
            {
                const auto kOffset = mMappings.GetKeyOffsetForRound(i);

                halves.first <<= kOffset;
                halves.second <<= kOffset;
            }

            // When decrypting we must start with the last sub key
        }

        return halves;
    }

    constexpr std::uint64_t SDES::GetSubKey(const KeyHalves& keyHalves) const noexcept
    {
        const std::array<std::uint32_t, 2> kHalves =
        {
            static_cast<std::uint32_t>(keyHalves.second),
            static_cast<std::uint32_t>(keyHalves.first)
        };

        return mMappings.PC2(Glue<std::uint64_t, 28>(kHalves));
    }

    constexpr std::uint32_t SDES::F(std::uint64_t subKey, std::uint32_t blockHalf) const noexcept
    {
        const auto kCompressed = mMappings.S(mMappings.E(blockHalf) ^ subKey);
        return mMappings.P(kCompressed);
    }

    constexpr std::uint64_t SDES::MakeCipherBlock(std::uint32_t upper, std::uint32_t lower) noexcept
    {
        const std::array<std::uint32_t, 2> kHalves = { lower, upper };
        return Glue<std::uint64_t, 32>(kHalves);
    }

} // namespace sdes

#endif // SDES_SDES_HPP
