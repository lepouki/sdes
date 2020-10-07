//
// Created by lepouki on 10/7/2020.
//

#ifndef SDES_SDES_HPP
#define SDES_SDES_HPP

#include <cstdint>
#include <array>

#include "Mappings.hpp"

namespace sdes
{

    class SDES
    {
    public:
        constexpr SDES(std::uint64_t key, const Mappings& mappings) noexcept;

    public:
        constexpr void SetKey(std::uint64_t key) noexcept;

        [[nodiscard]]
        constexpr std::uint64_t GetKey() const noexcept { return mKey; }

    public:
        [[nodiscard]]
        constexpr std::uint64_t Encrypt(std::uint64_t block) noexcept;

        [[nodiscard]]
        constexpr std::uint64_t Decrypt(std::uint64_t block) noexcept;

    private:
        std::uint64_t mKey;
        const Mappings& mMappings;

    private:
        [[nodiscard]]
        constexpr std::uint64_t Compute(std::uint64_t block, bool encrypt) noexcept;

    private:
        template<typename SubBlock, std::size_t NumSplits, std::size_t BlockSize, typename /* Deduced */ Block>
        [[nodiscard]]
        constexpr std::array<SubBlock, NumSplits> Split(Block block) const noexcept;
    };

    // Implementation //

    template<typename SubBlock, std::size_t NumSplits, std::size_t BlockSize, typename Block>
    constexpr std::array<SubBlock, NumSplits> SDES::Split(Block block) const noexcept
    {
        static_assert(NumSplits <= BlockSize, "NumSplits is too big");
        static_assert(BlockSize % NumSplits == 0, "NumSplits must be a multiple of BlockSize");

        constexpr auto kOne = static_cast<Block>(1);
        constexpr auto kSplitSize = BlockSize / NumSplits;

        std::array<SubBlock, NumSplits> splits = {};

        for (unsigned i = 0; i < NumSplits; ++i)
        {
            const auto kIndex = i * kSplitSize;
            const auto kUpperBoundary = kOne << (kIndex + kSplitSize + 1);
            const auto kBlockMask = kUpperBoundary - (kOne << kIndex);

            splits[i] = (block & kBlockMask) >> kIndex;
        }

        return splits;
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

    constexpr std::uint64_t SDES::Compute(std::uint64_t block, bool encrypt) noexcept
    {
        block = mMappings.IP(block);
        const auto [kUpper, kLower] = Split<std::uint32_t, 2, 64>(block);
        return 0;
    }

} // namespace sdes

#endif // SDES_SDES_HPP
