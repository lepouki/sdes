//
// Created by lepouki on 10/7/2020.
//

#ifndef SDES_MAPPINGS_HPP
#define SDES_MAPPINGS_HPP

#include <cstdint>
#include <array>
#include <utility>

namespace sdes
{

    /*
     * Stores the mappings for different steps of encryption/decryption.
     */
    class Mappings
    {
    public:
        template<std::size_t Size>
        using MapFunction = std::array<std::uint16_t, Size>;

    public:
        std::uint32_t mNumRounds;

    public:
        constexpr explicit
        Mappings(std::uint32_t numRounds) noexcept;

    public:
        constexpr std::uint64_t
        [[nodiscard]] IP(std::uint64_t block) const noexcept;

        constexpr std::uint64_t
        [[nodiscard]] FP(std::uint64_t block) const noexcept;

        constexpr std::uint64_t
        [[nodiscard]] PC1(std::uint64_t key) const noexcept;

    private:
        template<typename To, typename /* Deduced */ From, std::size_t /* Deduced */ ToSize>
        constexpr To
        [[nodiscard]] MapBlock(From block, const MapFunction<ToSize>& function) const noexcept;
    };

    constexpr
    Mappings::Mappings(std::uint32_t numRounds) noexcept
        : mNumRounds(numRounds)
    {
    }

    constexpr std::uint64_t
    Mappings::IP(std::uint64_t block) const noexcept
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
            63, 55, 47, 39, 31, 23, 15, 7,
        };

        return MapBlock<std::uint64_t>(block, kIP);
    }

    constexpr std::uint64_t
    Mappings::FP(std::uint64_t block) const noexcept
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
            33, 1, 41,  9, 49, 17, 57, 25,
        };

        return MapBlock<std::uint64_t>(block, kFP);
    }

    constexpr std::uint64_t
    Mappings::PC1(std::uint64_t key) const noexcept
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

        return MapBlock<std::uint64_t>(key, kPC1);
    }

    template<typename To, typename From, std::size_t ToSize>
    constexpr To
    Mappings::MapBlock(From block, const MapFunction<ToSize>& function) const noexcept
    {
        static_assert(ToSize <= (sizeof(To) * 8), "ToSize is too big");
        To result = 0;

        for (unsigned i = 0; i < ToSize; ++i)
        {
            bool value = block & 1;
            result |= static_cast<To>(value) << (function[i] - 1); // Functions are 1-indexed
            block >>= 1;
        }

        return result;
    }

} // namespace sdes

#endif // SDES_MAPPINGS_HPP
