//
// Created by lepouki on 10/7/2020.
//

#ifndef SDES_SDES_HPP
#define SDES_SDES_HPP

#include <cstdint>

#include "Mappings.hpp"

namespace sdes
{

    class SDES
    {
    public:
        constexpr
        SDES(std::uint64_t key, const Mappings& mappings) noexcept;

    public:
        constexpr void
        SetKey(std::uint64_t key) noexcept;

        constexpr std::uint64_t
        [[nodiscard]] GetKey() const noexcept { return mKey; }

    public:
        constexpr std::uint64_t
        [[nodiscard]] Encrypt(std::uint64_t block) noexcept;

        constexpr std::uint64_t
        [[nodiscard]] Decrypt(std::uint64_t block) noexcept;

    private:
        std::uint64_t mKey;
        const Mappings& mMappings;

    private:
        constexpr std::uint64_t
        [[nodiscard]] Compute(std::uint64_t block, bool encrypt) noexcept;

    private:
        template<typename SubBlock, std::size_t NumSplits, std::size_t BlockSize, typename /* Deduced */ Block>
        constexpr std::array<SubBlock, NumSplits>
        [[nodiscard]] SplitBlock(Block block) const noexcept;
    };

    // Implementation //

    constexpr
    SDES::SDES(std::uint64_t key, const Mappings& mappings) noexcept
        : mKey(0)
        , mMappings(mappings)
    {
        SetKey(key);
    }

    constexpr void
    SDES::SetKey(std::uint64_t key) noexcept
    {
        mKey = mMappings.PC1(key);
    }

    constexpr std::uint64_t
    SDES::Encrypt(std::uint64_t block) noexcept
    {
        return Compute(block, true);
    }

    constexpr std::uint64_t
    SDES::Decrypt(std::uint64_t block) noexcept
    {
        return Compute(block, false);
    }

    constexpr std::uint64_t
    SDES::Compute(std::uint64_t block, bool encrypt) noexcept
    {
        block = mMappings.IP(block);
        const auto [kUpper, kLower] = SplitBlock<std::uint32_t, 2, 64>(block);
        return mMappings.FP(block);
    }

    template<typename SubBlock, std::size_t NumSplits, std::size_t BlockSize, typename Block>
    constexpr std::array<SubBlock, NumSplits>
    SDES::SplitBlock(Block block) const noexcept
    {
        static_assert(NumSplits <= BlockSize, "NumSplits is too big");
        static_assert(BlockSize % NumSplits == 0, "NumSplits must be a multiple of BlockSize");

        constexpr auto kOne = static_cast<Block>(1);
        constexpr auto kSplitSize = BlockSize / NumSplits;

        std::array<SubBlock, NumSplits> splits;

        for (unsigned i = 0; i < NumSplits; ++i)
        {
            const auto kIndex = i * kSplitSize;
            const auto kSizeBoundary = kOne << (kIndex + kSplitSize + 1);
            const auto kBlockMask = (kSizeBoundary) - (kOne << kIndex);

            splits[i] = (block & kBlockMask) >> kIndex;
        }

        return splits;
    }

} //namespace sdes

#endif //SDES_SDES_HPP
