//
// Created by lepouki on 10/7/2020.
//

#ifndef SDES_MAPPINGS_HPP
#define SDES_MAPPINGS_HPP

#include <cstdint>

#include <array>

namespace sdes
{

    class Mappings
    {
    public:
        template<std::size_t NumBits>
        using MapFunction = std::array<std::uint16_t, NumBits>;

    public:
        [[nodiscard]]
        constexpr std::uint64_t IP(std::uint64_t block) const noexcept;

        [[nodiscard]]
        constexpr std::uint64_t FP(std::uint64_t block) const noexcept;

        [[nodiscard]]
        constexpr std::uint64_t PC1(std::uint64_t block) const noexcept;

        [[nodiscard]]
        constexpr std::uint64_t PC2(std::uint64_t block) const noexcept;

        [[nodiscard]]
        constexpr std::uint64_t E(std::uint32_t block) const noexcept;

        [[nodiscard]]
        constexpr std::uint32_t S(std::uint64_t block) const noexcept;

        [[nodiscard]]
        constexpr std::uint32_t P(std::uint32_t block) const noexcept;

    public:
        [[nodiscard]]
        static constexpr std::uint16_t GetKeyOffsetForRound(unsigned round) noexcept;

    private:
        template<typename To, typename /* Deduced */ From, std::size_t /* Deduced */ ToSize>
        [[nodiscard]]
        constexpr To Map(From block, const MapFunction<ToSize>& function) const noexcept;
    };

    // Implementation //

    template<typename To, typename From, std::size_t ToSize>
    constexpr To Mappings::Map(From block, const MapFunction<ToSize>& function) const noexcept
    {
        static_assert(ToSize <= (sizeof(To) * 8), "ToSize is too big");

        To result = 0;

        for (std::size_t i = 0; i < ToSize; ++i)
        {
            // Get 'function[i]'th bit from the original block
            const auto kBit = static_cast<To>(1u) << (function[i] - 1u); // Functions are 1-indexed
            const bool kValue = block & kBit;

            // Or to the resulting block
            result |= static_cast<To>(kValue) << i;
        }

        return result;
    }

    constexpr std::uint64_t Mappings::IP(std::uint64_t block) const noexcept
    {
        constexpr MapFunction<64> kIP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17,  9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        return Map<std::uint64_t>(block, kIP);
    }

    constexpr std::uint64_t Mappings::FP(std::uint64_t block) const noexcept
    {
        constexpr MapFunction<64> kFP =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41,  9, 49, 17, 57, 25 
        };

        return Map<std::uint64_t>(block, kFP);
    }

    constexpr std::uint64_t Mappings::PC1(std::uint64_t block) const noexcept
    {
        constexpr MapFunction<56> kPC1 =
        {
            57, 49, 41, 33, 25, 17,  9,
             1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27,
            19, 11,  3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29,
            21, 13,  5, 28, 20, 12,  4
        };

        return Map<std::uint64_t>(block, kPC1);
    }

    constexpr std::uint64_t Mappings::PC2(std::uint64_t block) const noexcept
    {
        constexpr MapFunction<48> kPC2 =
        {
            14, 17, 11, 24,  1,  5,
             3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8,
            16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        return Map<std::uint64_t>(block, kPC2);
    }

    constexpr std::uint64_t Mappings::E(std::uint32_t block) const noexcept
    {
        constexpr MapFunction<48> kE =
        {
            32,  1,  2,  3,  4,  5,
             4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
        };

        return Map<std::uint64_t>(block, kE);
    }

    constexpr std::uint32_t Mappings::S(std::uint64_t block) const noexcept
    {
        // S-boxes are simplified to a single map function

        constexpr MapFunction<32> kS =
        {
            17, 26,  8, 28, 21, 23,  3, 16,
            47, 20, 14, 32, 11, 36, 33,  6,
             9, 30, 40, 31,  2, 35, 42, 12,
            19,  4, 39, 13, 25, 38,  1, 37
        };

        return Map<std::uint32_t>(block, kS);
    }

    constexpr std::uint32_t Mappings::P(std::uint32_t block) const noexcept
    {
        constexpr MapFunction<32> kP =
        {
            16,  7, 20, 21, 29, 12, 28, 17,
             1, 15, 23, 26,  5, 18, 31, 10,
             2,  8, 24, 14, 32, 27,  3,  9,
            19, 13, 30,  6, 22, 11,  4, 25
        };

        return Map<std::uint32_t>(block, kP);
    }

    constexpr std::uint16_t Mappings::GetKeyOffsetForRound(unsigned round) noexcept
    {
        // Round offsets must be less than 28 bits

        constexpr MapFunction<16> kKeyOffsets =
        {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
        };

        return kKeyOffsets[round];
    }

} // namespace sdes

#endif // SDES_MAPPINGS_HPP
