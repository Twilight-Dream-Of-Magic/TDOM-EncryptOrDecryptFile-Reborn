/*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * 本文件是 TDOM-EncryptOrDecryptFile-Reborn 的一部分。
 *
 * TDOM-EncryptOrDecryptFile-Reborn 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 TDOM-EncryptOrDecryptFile-Reborn 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */

 /*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * This file is part of TDOM-EncryptOrDecryptFile-Reborn.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

namespace CommonSecurity
{
	enum class ChunkedDataPaddingMode : std::uint8_t
	{
		//In ANSI X9.23, between 1 and 8 bytes are always added as padding. The block is padded with random bytes (although many implementations use 00) and the last byte of the block is set to the number of bytes added.[6]
		//Example: In the following example the block size is 8 bytes, and padding is required for 4 bytes (in hexadecimal format)
		//| DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 04 |
		ANSI_X9_23 = 0,

		//ISO 10126 (withdrawn, 2007[7][8]) specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.
		//Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
		//| DD DD DD DD DD DD DD DD | DD DD DD DD 81 A6 23 04 |
		ISO_10126 = 1,

		//PKCS is Public Key Cryptography Standards(https://en.wikipedia.org/wiki/PKCS)
		//PKCS#7 is described in RFC 5652(https://tools.ietf.org/html/rfc5652#section-6.3).
		//Padding is in whole bytes.
		//The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added. 
		//The number of bytes added will depend on the block boundary to which the message needs to be extended.
		//The padding will be one of:
		//01
		//02 02
		//03 03 03
		//04 04 04 04
		//05 05 05 05 05
		//06 06 06 06 06 06
		PKCS7 = 2,

		NONE = 3
	};

	template<ChunkedDataPaddingMode PaddingMode>
	/*
		https://en.wikipedia.org/wiki/Padding_(cryptography)
	*/
	struct ChunkedDataPadders
	{
		template<typename ByteType>
		void Pad( std::vector<ByteType>& UnprocessedChunkedData, std::size_t DataBlockSize )
		{
			static_assert(std::same_as<ByteType, std::uint8_t> || std::same_as<ByteType, std::byte>, "");
			my_cpp2020_assert( DataBlockSize != 0U, "CommonSecurity::ChunkedDataPadders::Pad() Wait! What are you doing? You can't give me byte blocks of zero size!", std::source_location::current() );

			if constexpr ( PaddingMode == ChunkedDataPaddingMode::ANSI_X9_23 )
			{
				std::size_t			  PaddedByteSize = UnprocessedChunkedData.size() < DataBlockSize ? DataBlockSize - UnprocessedChunkedData.size() : DataBlockSize - ( UnprocessedChunkedData.size() % DataBlockSize );
				std::vector<ByteType> PaddingDataItem( PaddedByteSize, ByteType { 0x00 } );

				if ( PaddedByteSize == std::size_t { 1 } )
				{
					UnprocessedChunkedData.push_back( static_cast<ByteType>(PaddedByteSize) );
				}
				else
				{
					PaddingDataItem[ PaddingDataItem.size() - 1 ] = static_cast<ByteType>(PaddedByteSize);
					UnprocessedChunkedData.insert( UnprocessedChunkedData.end(), PaddingDataItem.begin(), PaddingDataItem.end() );
				}
			}
			else if constexpr ( PaddingMode == ChunkedDataPaddingMode::ISO_10126 )
			{
				std::size_t								PaddedByteSize = UnprocessedChunkedData.size() < DataBlockSize ? DataBlockSize - UnprocessedChunkedData.size() : DataBlockSize - ( UnprocessedChunkedData.size() % DataBlockSize );
				std::vector<ByteType>					PaddingDataItem( PaddedByteSize, ByteType { 0x00 } );
				std::random_device						HardwareRandomDevice;
				CommonSecurity::RNG_Xoshiro::xoshiro256 PRNG;
				PRNG.seed(HardwareRandomDevice);

				for ( auto& ByteData : PaddingDataItem )
				{
					ByteData = static_cast<ByteType>( PRNG() );
				}
				PaddingDataItem[ PaddingDataItem.size() - 1 ] = static_cast<ByteType>(PaddedByteSize);
				UnprocessedChunkedData.insert( UnprocessedChunkedData.end(), PaddingDataItem.begin(), PaddingDataItem.end() );
			}
			else if constexpr ( PaddingMode == ChunkedDataPaddingMode::PKCS7 )
			{
				my_cpp2020_assert( DataBlockSize <= std::numeric_limits<std::uint8_t>::max(), "", std::source_location::current() );

				std::size_t PaddedDataByteSize = UnprocessedChunkedData.size() + DataBlockSize - (UnprocessedChunkedData.size() % DataBlockSize);
				std::size_t PaddingDataByteSize = PaddedDataByteSize - UnprocessedChunkedData.size();

				const std::vector<ByteType> PaddingDataItem(PaddingDataByteSize, static_cast<ByteType>(PaddingDataByteSize));
				UnprocessedChunkedData.insert(UnprocessedChunkedData.end(), PaddingDataItem.begin(), PaddingDataItem.end());
			}
			else if constexpr ( PaddingMode == ChunkedDataPaddingMode::NONE )
			{
				static_assert( CommonToolkit::Dependent_Always_Failed<PaddingMode>, "It doesn't make sense to use ChunkedDataPadders in this mode" );
			}
		}

		template<typename ByteType>
		void Unpad( std::vector<ByteType>& ProcessedChunkedData, std::size_t DataBlockSize )
		{
			static_assert(std::same_as<ByteType, std::uint8_t> || std::same_as<ByteType, std::byte>, "");
			
			my_cpp2020_assert( DataBlockSize != 0U, "CommonSecurity::ChunkedDataPadders::Unpad() Wait! What are you doing? You can't give me byte blocks of zero size!", std::source_location::current() );
			my_cpp2020_assert( ProcessedChunkedData.size() % DataBlockSize == 0, "CommonSecurity::ChunkedDataPadders::Unpad() Wait! What are you doing? You can't give me an unaligned data or unpadded data to work with.", std::source_location::current() );

			if constexpr ( PaddingMode == ChunkedDataPaddingMode::ANSI_X9_23 )
			{
				std::size_t PaddedByteSize = ProcessedChunkedData.back();
				bool		IsAllZeroByteBlock = std::ranges::all_of
				(
					ProcessedChunkedData.end() - PaddedByteSize,
					ProcessedChunkedData.end() - 1,
					[]( ByteType ByteTypeData )
					{
						return ByteTypeData == ByteType{0x00};
					} 
				);

				if ( IsAllZeroByteBlock && PaddedByteSize != ByteType { 0x01 } )
				{
					ProcessedChunkedData.erase( ProcessedChunkedData.end() - PaddedByteSize, ProcessedChunkedData.end() );
					ProcessedChunkedData.shrink_to_fit();
				}
				else if ( PaddedByteSize == static_cast<std::size_t>( 0x01 ) )
				{
					ProcessedChunkedData.pop_back();
					ProcessedChunkedData.shrink_to_fit();
				}
				else
				{
					std::cout << "Although after the previous encryption step, arbitrary data was padded to ensure data alignment;\nNow when you try to remove the padded arbitrary data after the completion of the decryption step, a serious logic error occurs and your data cannot be recovered." << "\n";
					my_cpp2020_assert( false, "Oops, maybe the padding data was corrupted?", std::source_location::current() );
				}
			}
			else if constexpr ( PaddingMode == ChunkedDataPaddingMode::ISO_10126 )
			{
				std::size_t PaddedByteSize = ProcessedChunkedData.back();
				if ( PaddedByteSize > static_cast<std::size_t>( 0x00 ) )
				{
					ProcessedChunkedData.erase( ProcessedChunkedData.end() - PaddedByteSize, ProcessedChunkedData.end() );
					ProcessedChunkedData.shrink_to_fit();
				}
				else
				{
					std::cout << "Although after the previous encryption step, arbitrary data was padded to ensure data alignment;\nNow when you try to remove the padded arbitrary data after the completion of the decryption step, a serious logic error occurs and your data cannot be recovered." << "\n";
					my_cpp2020_assert( false, "Oops, maybe the padding data was corrupted?", std::source_location::current() );
				}
			}
			else if constexpr ( PaddingMode == ChunkedDataPaddingMode::PKCS7 )
			{
				my_cpp2020_assert( DataBlockSize <= std::numeric_limits<std::uint8_t>::max(), "", std::source_location::current() );

				std::size_t PaddingDataByteSize = ProcessedChunkedData.back();

				if(PaddingDataByteSize == 0)
				{
					std::cout << "Although after the previous encryption step, arbitrary data was padded to ensure data alignment;\nNow when you try to remove the padded arbitrary data after the completion of the decryption step, a serious logic error occurs and your data cannot be recovered." << "\n";
					my_cpp2020_assert( false, "Oops, maybe the padding data was corrupted?", std::source_location::current() );
				}

				const std::vector<ByteType> PaddingDataItem(PaddingDataByteSize, static_cast<ByteType>(PaddingDataByteSize));
				auto SearchHasBeenFoundSubrange = std::ranges::search(ProcessedChunkedData.end() - PaddingDataByteSize * 2, ProcessedChunkedData.end(), PaddingDataItem.begin(), PaddingDataItem.end());
				if(SearchHasBeenFoundSubrange.begin() != SearchHasBeenFoundSubrange.end())
				{
					ProcessedChunkedData.erase(SearchHasBeenFoundSubrange.begin(), SearchHasBeenFoundSubrange.end());
					ProcessedChunkedData.shrink_to_fit();
				}
				else
				{
					std::cout << "Although after the previous encryption step, arbitrary data was padded to ensure data alignment;\nNow when you try to remove the padded arbitrary data after the completion of the decryption step, a serious logic error occurs and your data cannot be recovered." << "\n";
					my_cpp2020_assert( false, "Oops, maybe the padding data was corrupted?", std::source_location::current() );
				}
			}
			else if constexpr ( PaddingMode == ChunkedDataPaddingMode::NONE )
			{
				static_assert( CommonToolkit::Dependent_Always_Failed<PaddingMode>, "It doesn't make sense to use ChunkedDataPadders in this mode!" );
			}
		}

		ChunkedDataPadders() = default;
		~ChunkedDataPadders() = default;
	};

	class ChunkedDataMixPadders
	{
		
	private:

		const std::size_t DataByteBlockSize;

		void DataPadding(std::vector<std::uint8_t>& data, const std::uint32_t NeedPaddingSize)
		{
			std::uint32_t NeedLoopSaltCout = static_cast<std::uint32_t>(DataByteBlockSize);

			std::random_device RandomDevice;
			CommonSecurity::RNG_Xoshiro::xoshiro256 RandomNumberGenerator(CommonSecurity::GenerateSecureRandomNumberSeed<std::uint32_t>(RandomDevice));
			CommonSecurity::RND::UniformIntegerDistribution RandomNumberDistribution(0, 255);

			//Random Salt Data
			while (NeedLoopSaltCout > 0)
			{
				data.push_back(static_cast<std::uint8_t>(RandomNumberDistribution(RandomNumberGenerator)));
				--NeedLoopSaltCout;
			}

			//Same PKCS7 Data
			const std::vector<std::uint8_t> SameByteDatas(NeedPaddingSize, static_cast<std::uint8_t>(NeedPaddingSize));
			data.insert(data.end(), SameByteDatas.begin(), SameByteDatas.end());
		}

		void DataUnpadding(std::vector<std::uint8_t>& data, const std::uint32_t NeedUnpaddingSize)
		{
			//Same PKCS7 Data
			auto SearchHasBeenFoundSubrange = std::ranges::search_n(data.end() - NeedUnpaddingSize * 2, data.end(), NeedUnpaddingSize, static_cast<std::uint8_t>(NeedUnpaddingSize));
				
			if(SearchHasBeenFoundSubrange.begin() != SearchHasBeenFoundSubrange.end())
			{
				data.erase(SearchHasBeenFoundSubrange.begin(), SearchHasBeenFoundSubrange.end());
			}
			else
			{
				std::cout << "Maybe the padding data was corrupted?" << std::endl;
				throw std::logic_error("");
			}

			//Random Salt Data
			data.erase(data.end() - DataByteBlockSize, data.end());
		}

	public:

		void DataPadding(std::vector<std::uint8_t>& ByteData)
		{
			if(ByteData.size() % DataByteBlockSize != 0)
				this->DataPadding(ByteData, DataByteBlockSize - ( ByteData.size() % DataByteBlockSize) );
		}

		void DataUnpadding(std::vector<std::uint8_t>& ByteData)
		{
			std::uint8_t SameByteData = ByteData.back();
			std::size_t SameByteDatasCount = 0;

			for(auto rbegin = ByteData.rbegin() + 1, rend = ByteData.rbegin() + 16; rbegin != rend; ++rbegin)
			{
				if( rbegin + 1 != rend && *rbegin == *(rbegin + 1))
					++SameByteDatasCount;
			}

			if(SameByteDatasCount == static_cast<std::size_t>(SameByteData))
			{
				this->DataUnpadding(ByteData, SameByteDatasCount);
			}
		}

		ChunkedDataMixPadders(const std::size_t DataByteBlockSize)
			:
			DataByteBlockSize(DataByteBlockSize)
		{

		}

		~ChunkedDataMixPadders() = default;
	};
}

namespace CommonSecurity::AES::DefineConstants
{
	inline constexpr std::array<std::uint8_t, 256> Subtitute_ByteBox
	{
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};

	inline constexpr std::array<std::uint8_t, 256> InverseSubtitute_ByteBox
	{
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	};

	constexpr std::uint32_t Binary_Polynomial_Data = (1U << 8) ^ (1U << 4) ^ (1U << 3) ^ (1U << 1) ^ (1U << 0);

	inline constexpr std::array<std::uint32_t, 16>
	GeneratePowerXTimeTable()
	{
		std::array<std::uint32_t, 16> PowerXTimeTable
		{ 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 };

		std::uint32_t Poly = 1;

		for(std::uint32_t Index = 0; Index < PowerXTimeTable.size(); Index++)
		{
			if(PowerXTimeTable[Index] != Poly)
				PowerXTimeTable[Index] = Poly;

			Poly <<= 1;
			if( (Poly & 256U) != 0 )
			{
				Poly ^= Binary_Polynomial_Data;
			}
		}

		return PowerXTimeTable;
	}

	// Multiply value and constant-value as GF(2) polynomials modulo poly
	inline constexpr std::uint32_t
	MultiplicationOfWordWithGaloisField(std::uint32_t Multiplied, std::uint32_t Multiplier)
	{
		std::uint32_t A = Multiplied;
		std::uint32_t B = Multiplier;
		std::uint32_t C = 0U;

		for(std::uint32_t Index = 1; Index < 256 && B != 0; Index <<= 1)
		{
			// Invariant: k == 1<<n, i == b * xⁿ
			if ((B & Index) != 0U)
			{
				// C += A in GF(2); xor in binary
				C ^= A;
				B ^= Index; // turn off bit to end loop early
			}

			// A *= x in GF(2) modulo the polynomial
			A <<= 1;
			if((A & 256) != 0U)
			{
				A ^= Binary_Polynomial_Data;
			}
		}

		return C;
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateEncryptionWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];
			std::uint32_t Byte2 = MultiplicationOfWordWithGaloisField(Byte, 0x2U);
			std::uint32_t Byte3 = MultiplicationOfWordWithGaloisField(Byte, 0x3U);

			std::uint32_t Word = Byte2 << 24 | Byte << 16 | Byte << 8 | Byte3;
			for(std::uint32_t Index2 = 0; Index2 < 4; Index2++)
			{
				if(ProcessBlockTable[Index2][Index] != Word)
					ProcessBlockTable[Index2][Index] = Word;

				Word = Word << 24 | Word >> 8;
			}
		}

		return ProcessBlockTable;
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateDecryptionWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = InverseSubtitute_ByteBox[Index];
			std::uint32_t Byte2 = MultiplicationOfWordWithGaloisField(Byte, 0x9U);
			std::uint32_t Byte3 = MultiplicationOfWordWithGaloisField(Byte, 0xBU);
			std::uint32_t Byte4 = MultiplicationOfWordWithGaloisField(Byte, 0xDU);
			std::uint32_t Byte5 = MultiplicationOfWordWithGaloisField(Byte, 0xEU);

			std::uint32_t Word = Byte5 << 24 | Byte2 << 16 | Byte4 << 8 | Byte3;
			for(std::uint32_t Index2 = 0; Index2 < 4; Index2++)
			{
				if(ProcessBlockTable[Index2][Index] != Word)
					ProcessBlockTable[Index2][Index] = Word;

				Word = Word << 24 | Word >> 8;
			}
		}

		return ProcessBlockTable;
	}
}

namespace CommonSecurity::AES::ProcedureFunctions
{
	//For Key Schedule

	/**
		In computing, the modulo operation returns the remainder or signed remainder of a division, after one number is divided by another (called the modulus of the operation).
		Given two positive numbers a and n, a modulo n (abbreviated as a mod n) is the remainder of the Euclidean division of a by n, where a is the dividend and n is the divisor.
		The modulo operation is to be distinguished from the symbol mod, which refers to the modulus[1] (or divisor) one is operating from.
		For example, the expression "5 mod 2" would evaluate to 1, because 5 divided by 2 has a quotient of 2 and a remainder of 1, while "9 mod 3" would evaluate to 0
		Because the division of 9 by 3 has a quotient of 3 and a remainder of 0; there is nothing to subtract from 9 after multiplying 3 times 3.
		Although typically performed with a and n both being integers, many computing systems now allow other types of numeric operands.
		The range of values for an integer modulo operation of n is 0 to n − 1 inclusive (a mod 1 is always 0; a mod 0 is undefined, possibly resulting in a division by zero error in some programming languages).
		See Modular arithmetic for an older and related convention applied in number theory.
		When exactly one of a or n is negative, the naive definition breaks down, and programming languages differ in how these values are defined.

		模除（又称模数、取模操作、取模运算等，英语：modulo 有时也称作 modulus
		得到的是一个数除以另一个数的余数。
		给定两个正整数：被除数 a 和除数 n，a modulo n (缩写为 a mod n)
		得到的是使用欧几里德除法时 a/n 的余数。
		举个例子：计算表达式 "5 mod 2" 得到 1，因为 5÷2=2...1（5 除以 2 商 2 余1）；而 "9 mod 3" 得到 0，因为 9÷3=3...0；
		注意：如果使用计算器做除法，不能整除时，你不会得到商，而是会得到一个小数，如：5÷2=2.5。
		虽然通常情况下 a 和 n 都是整数，但许多计算系统允许其他类型的数字操作，如：对浮点数取模。
		一个整数对 n 取模的结果范围为： 0 到 n − 1（a mod 1 恒等于 0；a mod 0 则是未定义的，在编程语言里可能会导致除零错误）。
		有关概念在数论中的应用请参阅模算数。
		当 a 和 n 均为负数时，通常的定义就不适用了，不同的编程语言对结果有不同的处理。

		GF is Galois field
			在数学中，有限域（英语：finite field）或伽罗瓦域（英语：Galois field，为纪念埃瓦里斯特·伽罗瓦命名）是包含有限个元素的域。
			与其他域一样，有限域是进行加减乘除运算都有定义并且满足特定规则的集合。
			有限域最常见的例子是当 p 为素数时，整数对 p 取模。
			有限域的元素个数称为它的阶。
			有限域在许多数学和计算机科学领域的基础，包括数论、代数几何、伽罗瓦理论、有限几何学、密码学和编码理论。
			In mathematics, a finite field or Galois field (so-named in honor of Évariste Galois) is a field that contains a finite number of elements.
			As with any field, a finite field is a set on which the operations of multiplication, addition, subtraction and division are defined and satisfy certain basic rules.
			The most common examples of finite fields are given by the integers mod p when p is a prime number.
			The order of a finite field is its number of elements, which is either a prime number or a prime power.
			For every prime number p and every positive integer k there are fields of order p^k, all of which are isomorphic.
			Finite fields are fundamental in a number of areas of mathematics and computer science, including number theory, algebraic geometry, Galois theory, finite geometry, cryptography and coding theory.

		Paper 3.2 Bytes (Part)
			
			All byte values in the AES algorithm will be presented as the concatenation of its individual bit
			values (0 or 1) between braces in the order
			Byte {bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0}.
			These bytes are
			interpreted as finite field elements using a polynomial representation:

			Mathematical equations 3.1
			bit7*x^7 + bit6*x^6 + bit5*x^5 + bit4*x^4 + bit3*x^3 + bit2*x^2 + bit1*x + bit0

			For example, {01100011} identifies the specific finite field element x
			x^6 + x^5 + x +1.

		Paper 3.2 字节 (部分)

			在AES算法中，所有的字节值都将以其单独的比特值（0或1）的串联形式出现在大括号中。
			值（0或1）在大括号之间的连接，顺序为
			字节{bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0}。
			这些字节被
			被解释为使用多项式表示的有限场元素。

			数学方程式 3.1
			bit7*x^7 + bit6*x^6 + bit5*x^5 + bit4*x^4 + bit3*x^3 + bit2*x^2 + bit1*x + bit0

			例如，{01100011}确定了具体的有限场元素x
			x^6 + x^5 + x +1

		Paper 4. Mathematical Preliminaries
			All bytes in the AES algorithm are interpreted as finite field elements using the notation introduced in Sec. 3.2.
			Finite field elements can be added and multiplied, but these operations are different from those used for numbers.
			The following subsections introduce the basic mathematical concepts needed for Sec. 5.

		论文 4. 数学预演
			在AES算法中，所有的字节都被解释为有限场元素，使用的符号是 3.2节中介绍的符号。
			有限场元素可以被添加和相乘，但这些操作 与用于数字的操作不同。
			下面几个小节介绍了 第5章所需的基本数学概念。

		Parer 4.1 Addition

			The addition of two elements in a finite field is achieved by "adding" the coefficients for the corresponding powers in the polynomials for the two elements.
			The addition is performed with the XOR operation (denoted by (Exclusive-OR) ) - i.e., modulo 2 - so that 1 Exclusive-OR 1 = 0 , 1 Exclusive-OR  0 = 1, and 0 Exclusive-OR 0 = 0 .
			Consequently, subtraction of polynomials is identical to addition of polynomials.

			Alternatively, addition of finite field elements can be described as the modulo 2 addition of corresponding bits in the byte.
			For two bytes {bit_a7,bit_a6,bit_a5,bit_a4,bit_a3,bit_a2,bit_a1,bit_a0} and {bit_b7,bit_b6,bit_b5,bit_b4,bit_b3,bit_b2,bit_b1,bit_b0}, the sum is {bit_c7,bit_c6,bit_c5,bit_c4,bit_c3,bit_c2,bit_c1,bit_c0}
			Where each bit_ci = bit_ai (+) bit_bi (i.e., bit_c7 = bit_a7 (+) bit_b7, bit_c6 = bit_a6 (+) bit_b6, ...... bit_c0 = bit_a0 (+) bit_b0).

			For example, the following expressions are equivalent to one another:
			(x^6 + x^4 + x^2 + x + 1) + (x^7 + x + 1) = x^7 + x^6 + x^4 + x^2 (polynomial notation)
			{01010111} (+) {10000011} = {11010100} (binary notation);
			{57} (+) {83} = {d4} (hexadecimal notation).

		论文 4.1 加法
			有限域中两个元素的相加是通过 "添加 "这两个元素的多项式中的相应幂的系数来实现的。
			加法是通过XOR操作（用(Exclusive-OR)表示）进行的。- 即模数2--因此，1 Exclusive-OR 1 = 0 ，1 Exclusive-OR 0 = 1，0 Exclusive-OR 0 = 0。
			因此，多项式的减法与多项式的加法是相同的。

			另外，有限场元素的加法可以描述为字节中相应位的模2加法。
			对于两个字节{bit_a7,bit_a6,bit_a5,bit_a4,bit_a3,bit_a2,bit_a1,bit_a0}和{bit_b7,bit_b6,bit_b5, bit_b4,bit_b3,bit_b2,bit_b1,bit_b0}，其总和为{bit_c7,bit_c6,bit_c5,bit_c4,bit_c3,bit_c2,bit_c1,bit_c0}。
			其中每个bit_ci = bit_ai (+) bit_bi（即bit_c7 = bit_a7 (+) bit_b7, bit_c6 = bit_a6 (+) bit_b6, ...... bit_c0 = bit_a0 (+) bit_b0）。

			例如，下面的表达式是相互等价的。
			(x^6 + x^4 + x^2 + x + 1) + (x^7 + x + 1) = x^7 + x^6 + x^4 + x^2 (多项式记号)
			{01010111} (+) {10000011} = {11010100}（二进制记法）
			{57}（+）{83}={d4}（十六进制记法）

		Paper 4.2 Multiplication
			In the polynomial representation, multiplication in GF(2^8) (denoted by •) corresponds with the multiplication of polynomials modulo an irreducible polynomial of degree 8.
			A polynomial is irreducible if its only divisors are one and itself.
			
			For the AES algorithm, this irreducible polynomial is

			Mathematical equations 4.1
			m(x) = x^8 + x^4 + x^3 + x + 1 (4.1)

			Or {01}{1b} in hexadecimal notation.

			For example, {57} • {83} = {c1}

			(x^6 + x^4 + x^2 + x + 1)*(x^7 + x + 1)
			= x^13 + x^11 + x^9 + x^8 + x^7 + x^7 + x^5 + x^3 + x^2 + x + x^6 + x^4 + x^2 + x + 1
			= x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1
			
			and x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1 modulo (x^8 + x^4 + x^3 + x + 1)
			= x^7 + x^6 + 1

			The modular reduction by m(x) ensures that the result will be a binary polynomial of degree less than 8, and thus can be represented by a byte.
			Unlike addition, there is no simple operation at the byte level that corresponds to this multiplication.
			The multiplication defined above is associative, and the element {01} is the multiplicative identity.
			For any non-zero binary polynomial b(x) of degree less than 8, the multiplicative inverse of b(x), denoted b^-1(x), can be found as follows: the extended Euclidean algorithm [7]
			is used to compute polynomials a(x) and c(x) such that
			
			Mathematical equations 4.2
			b(x)*a(x) + m(x)*c(x) = 1
			
			Hence, a(x) • b(x) mod(m(x)) = 1
			which means

			Mathematical equations 4.3
			b^-1 (x) = a(x) mod m(x)
			Moreover, for any a(x), b(x) and c(x) in the field, it holds that
			a(x) • (b(x) + c(x)) = a(x) • b(x) + a(x) • c(x).
			It follows that the set of 256 possible byte values, with (Exclusive-OR operation) used as addition and the multiplication defined as above, has the structure of the finite field GF(2^8).


		论文 4.2 乘法
			在多项式表示中，GF(2^8)中的乘法（用•表示）对应于多项式与8度的不可还原多项式的乘法。
			如果一个多项式的除数只有一个和它本身，那么它就是不可还原的。
			
			对于AES算法，这个不可还原的多项式是

			数学方程式 4.1
			m(x) = x^8 + x^4 + x^3 + x + 1 (4.1)

			或者是十六进制的{01}{1b}
			例如，{57}•{83}={c1}
			Because (因为):

			(x^6 + x^4 + x^2 + x + 1)*(x^7 + x + 1)
			= x^13 + x^11 + x^9 + x^8 + x^7 + x^7 + x^5 + x^3 + x^2 + x + x^6 + x^4 + x^2 + x + 1
			= x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1
			
			and x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1 modulo (x^8 + x^4 + x^3 + x + 1)
			= x^7 + x^6 + 1

			m(x)的模块化还原保证了结果将是一个小于8度的二进制多项式，因此可以用一个字节来表示。
			与加法不同的是，在字节级没有对应于这种乘法的简单操作。
			上面定义的乘法是关联性的，元素{01}是乘法的身份。
			对于任何小于8度的非零二元多项式b(x)，b(x)的乘法逆数，表示为b^-1(x)，可以按如下方法找到：扩展的欧几里得算法[7] 。
			用来计算多项式a(x)和c(x)，以便于
			数学方程式 4.2
			b(x)*a(x)+m(x)*c(x)=1
			因此，a（x）• b（x）mod（m（x））= 1
			这意味着
			数学方程式 4.3
			b^-1 (x) = a(x) mod m(x)
			此外，对于场中的任何a(x), b(x)和c(x)，可以看出
			a(x) - (b(x) + c(x)) = a(x) - b(x) + a(x) - c(x)。
			由此可见，256个可能的字节值的集合，用（Exclusive-OR操作）作为加法，乘法定义如上，具有有限域GF(2^8)的结构。

		Paper 4.2.1 Multiplication by x

			Multiplying the binary polynomial defined in equation (3.1) with the polynomial x results in

			Mathematical equations 4.4
			bit7*x^8 + bit6*x^7 + bit5*x^6 + bit4*x^5 + bit3*x^4 + bit2*x^3 + bit1*x^2 + bit0*x

			The result x • b(x) is obtained by reducing the above result modulo m(x), as defined in math equation (4.1)
			If bit7 = 0, the result is already in reduced form.
			Else bit7 = 1, the reduction is accomplished by subtracting (i.e., (Exclusive-OR operation)ing) the polynomial m(x).
			It follows that multiplication by x (i.e., {00000010} or {02}) can be implemented at the byte level as a left shift and a subsequent conditional bitwise (+) with {1b}.
			
			This operation on bytes is denoted by xtime().
			Multiplication by higher powers of x can be implemented by repeated application of xtime().
			By adding intermediate results, multiplication by any constant can be implemented.

		论文 4.2.1 乘以x

			将数学方程式（3.1）中定义的二元多项式与多项式x相乘的结果是

			数学方程式4.4
			bit7*x^8 + bit6*x^7 + bit5*x^6 + bit4*x^5 + bit3*x^4 + bit2*x^3 + bit1*x^2 + bit0*x

			结果x-b(x)是通过减少上述结果的模数m(x)得到的，如数学方程(4.1)所定义的那样
			如果binray bit7 = 0，结果已经是还原形式。
			否则binray bit7 = 1, 减少是通过减去（即（Exclusive-OR操作））多项式m(x)来完成的。
			由此可见，x的乘法（即{00000010}或{02}）可以在字节级实现为左移和随后与{1b}的条件性位操作（+）。
			
			这种对字节的操作用xtime()来表示。
			x的高次幂乘法可以通过重复应用xtime()来实现。
			通过添加中间结果，可以实现与任何常数的乘法。
	*/
	inline constexpr std::uint8_t XTime(std::uint8_t Xbyte)
	{
		std::uint8_t bitMask = 0x80, moduloInnumerableMask = 0x1b;
		std::uint8_t highBit = Xbyte & bitMask;
		
		// Rotate ByteA left (multiply by (?) in GF(2^8))
		Xbyte <<= 1;
		//Xbyte = Xbyte << 1;

		// If LSB is active (equivalent to a '1' in the polynomial of ByteB)
		/* If the polynomial for ByteB has a constant term, add the corresponding ByteA to Result */
		if(highBit)
		{
			// result += ByteA in GF(2^8)
			/* Addition in GF(2^m) is an XOR of the polynomial coefficients */
			Xbyte ^= moduloInnumerableMask;
			//Xbyte = Xbyte ^ moduloInnumerableMask
		}
		return Xbyte;
	}

	/***********************************************************************************************
	* This function implements GF(2^8) mulitplication using a variation of peasent multiplication.
	* This algo takes advantage of multiplication's distributive property.
	*
	* e.g. 4 * 9 = 4 * (1* 2^0 + 0 * 2^1 + 0 * 2^2 + 1 * 2^3)
	* by the modulo polynomial relation x^8 + x^4 + x^3 + x + 1 = 0
	* (the other way being to do carryless multiplication followed by a modular reduction)
	*
	* Algorithm described in...
	* https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	***********************************************************************************************/
	inline constexpr std::uint8_t MultiplicationOfByteWithGaloisField(std::uint8_t ByteA, std::uint8_t ByteB)
	{
		// Taken and documented from https://en.wikipedia.org/wiki/Rijndael_MixColumns

		/* Accumulator for the product of the multiplication */
		std::uint8_t result = 0x00;
		const std::uint8_t BitMask = 0x01;

		for (int counter = 0; counter < 8; ++counter)
		{
			//ByteA is LeftByteData
			//ByteB is RightByteData

			// ByteA >= 128 = 0b0100'0000
			/* GF modulo: if a has a nonzero term x^7, then must be reduced when it becomes x^8 */
			std::uint8_t Bit = (ByteB & BitMask);
			
			if (Bit != static_cast<std::uint8_t>(0x00))
			{
				std::uint8_t XByte = ByteA; 

				for (int counter2 = 0; counter2 < counter; ++counter2)
				{
					XByte = XTime(XByte);
				}

				// Must reduce
				// ByteA -= 00011011 == modulo(x^8 + x^4 + x^3 + x + 1) = AES irreducible
				/* Subtract (XOR) the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1'0001'1011) – you can change it but it must be irreducible */
				result ^= XByte;
				//result = result ^ Xbyte
			}
			// Rotate ByteB right (divide by (?) in GF(2^8))
			ByteB >>= 1;
			//ByteB = ByteB >> 1;
		}

		return result;
	}

	//The generate round constant word from array index
	//从数组索引生成每轮常数字
	inline void RCON(std::array<std::uint8_t, 4>& Word, int roundCount)
	{
		//Byte data

		std::uint8_t constantByteForThisRound { 1 };

		for(signed int indexCount = 0; indexCount < roundCount - 1; ++indexCount)
		{
			constantByteForThisRound = XTime(constantByteForThisRound);
		}

		Word[0] = constantByteForThisRound;
		Word[1] = Word[2] = Word[3] = 0;
	}

	inline void AES_ExclusiveOR_ByteDataBlock
	(
		const std::vector<std::uint8_t> ADataBlock,
		const std::vector<std::uint8_t> BDatalock,
		std::vector<std::uint8_t> &CDataBlock,
		std::uint32_t count
	)
	{
		for (std::uint32_t index = 0; index < count; ++index)
			CDataBlock.operator[](index) = ADataBlock.operator[](index) ^ BDatalock.operator[](index);
	}

	template<std::size_t SIZE_OF_WORD>
	std::array<std::uint8_t, SIZE_OF_WORD> ExclusiveOR_Words
	(
		const std::array<std::uint8_t, SIZE_OF_WORD> &lhs,
		const std::array<std::uint8_t, SIZE_OF_WORD> &rhs
	)
	{
		std::array<std::uint8_t, SIZE_OF_WORD> result;
		std::ranges::transform
		(
			rhs.begin(),
			rhs.end(),
			lhs.begin(),
			result.begin(),
			[](const std::uint8_t &rhs_byte, const std::uint8_t &lhs_byte) -> std::uint8_t
			{
				return rhs_byte ^ lhs_byte;
			}
		);
		return result;
	}

	//在密钥扩展例程中使用的函数，它接收一个四字节的输入字，并对四个字节中的每个字节应用一个S-box，以产生一个输出字。
	//Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word.
	inline void KeyWordAES_Subtitute(std::array<std::uint8_t, 4>& Word)
	{
		constexpr std::array<std::array<std::uint8_t, 16>, 16> Forward_S_Box
		{
			{
				{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
				{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
				{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
				{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
				{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
				{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
				{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
				{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
				{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
				{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
				{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
				{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
				{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
				{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
				{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
				{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
			},
		};

		std::ranges::transform
		(
			Word.begin(),
			Word.end(),
			Word.begin(),
			[&Forward_S_Box](const std::uint8_t &byte) -> std::uint8_t
			{
				return Forward_S_Box[byte / 16][byte % 16];
			}
		);
	}

	inline void KeyWordAES_LeftRotate(std::uint32_t& Word)
	{
		//Double Word
		Word = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(Word, 4);
	}

	inline void KeyWordAES_LeftRotate(std::array<std::uint8_t, 4>& Word)
	{
		/*
			Example Code:
			for (int k{}; k != 5; ++k) {
				std::iota(s.begin(), s.end(), 'A');
				std::ranges::rotate(s, s.begin() + k);
				std::cout << "Rotate left (" << k << "): " << s << '\n';
			}
			
			std::cout << '\n';
			
			for (int k{}; k != 5; ++k) {
				std::iota(s.begin(), s.end(), 'A');
				std::ranges::rotate(s, s.end() - k);
				std::cout << "Rotate right (" << k << "): " << s << '\n';
			}
		*/

		//std::ranges::rotate(Word, Word.begin() + 1);
		std::ranges::rotate(Word.begin(), Word.begin() + 1, Word.end());
	}

	/*
		The MixColumns() transformation operates on the State column-by-column, treating each column as a four-term polynomial as described in Sec. 4.3.
		The columns are considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a fixed polynomial a(x), given by

		Mathematical equations 5.5
		a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

		Mathematical equations 5.6
		As described in Sec. 4.3, this can be written as a matrix multiplication.
		state' = a(x) (*) state(x):

		As a result of this multiplication, the four bytes in a column are replaced by the following:
		state'[0][column] = ({02} • state[0][column]) (+) ({03} • state[1][column]) (+) state[2][column] (+) state[3][column]
		state'[1][column] = state[0][column] (+) ({02} • state[1][column]) (+) ({03} • state[2][column]) (+) state[3][column]
		state'[2][column] = state[0][column] (+) state[1][column] (+) ({02} • state[2][column]) (+) ({03} • state[3][column])
		state'[3][column] = ({03} • state[0][column]) (+) state[1][column] (+) state[2][column] (+) ({02} • state[3][column])

		MixColumns()转换对状态逐列操作，如第4.3节所述，将每一列作为一个四项多项式处理。
		这些列被视为GF(2^8)上的多项式，并与固定的多项式a(x)相乘以x^4+1，给出如下

		数学公式5.5
		a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

		数学方程5.6
		如第4.3节所述，这可以写成一个矩阵乘法。
		state' = a(x) (*) state(x)

		作为这个乘法的结果，一列中的四个字节被替换成以下内容:
		state'[0][column] = ({02} • state[0][column]) (+) ({03} • state[1][column]) (+) state[2][column] (+) state[3][column]
		state'[1][column] = state[0][column] (+) ({02} • state[1][column]) (+) ({03} • state[2][column]) (+) state[3][column]
		state'[2][column] = state[0][column] (+) state[1][column] (+) ({02} • state[2][column]) (+) ({03} • state[3][column])
		state'[3][column] = ({03} • state[0][column]) (+) state[1][column] (+) state[2][column] (+) ({02} • state[3][column])
		
		In the MixColumns step, the four bytes of each column of the state are combined using an invertible linear transformation.
		The MixColumns function takes four bytes as input and outputs four bytes, where each input byte affects all four output bytes.
		Together with ShiftRows, MixColumns provides diffusion in the cryptographs.

		在MixColumns步骤中，状态的每一列的四个字节用一个可逆的线性变换进行组合。
		MixColumns函数将四个字节作为输入，并输出四个字节，其中每个输入字节会影响所有四个输出字节。
		与ShiftRows一起，MixColumns在密码器中提供了扩散性。
	*/
	inline void MixColumns(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		using namespace AES::DefineConstants;

		// AES_BLOCK_SIDE is 4
		#if 0

		std::deque<std::vector<std::uint8_t>> _stateByteDataBlock
		{
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0}
		};

		// matrix multiplication in GF(2^8)
		// * => galoisMul, + => ^

		for(std::uint32_t row = 0; row < 4; ++row)
		{
			for(std::uint32_t column = 0; column < 4; ++column)
			{
				_stateByteDataBlock.operator[](row).operator[](column) = 0x00;
				
				// Dot product of row (r) of the MixColumns and the column (c) of the state
				// MixColumns的r行与状态的c列的点积
				_stateByteDataBlock.operator[](row).operator[](column) ^= MultiplicationOfByteWithGaloisField(CMDS.operator[](row).operator[](column), stateByteDataBlock.operator[](row).operator[](column));
			}
		}

		stateByteDataBlock.swap(_stateByteDataBlock);

		_stateByteDataBlock.clear();

		#else

		std::uint8_t rowDatas[4], columnDatas[4];
		for (int column = 0; column < 4; ++column)
		{
			for (int row = 0; row < 4; ++row)
			{
				rowDatas[row] = stateByteDataBlock[row][column];
			}
			columnDatas[0] = MultiplicationOfByteWithGaloisField(0x02, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[1]) ^ rowDatas[2] ^ rowDatas[3];
			columnDatas[1] = rowDatas[0] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[2]) ^ rowDatas[3];
			columnDatas[2] = rowDatas[0] ^ rowDatas[1] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[3]);
			columnDatas[3] = MultiplicationOfByteWithGaloisField(0x03, rowDatas[0]) ^ rowDatas[1] ^ rowDatas[2] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[3]);
			for (int row = 0; row < 4; ++row)
			{
				stateByteDataBlock[row][column] = columnDatas[row];
			}
		}

		#endif

	}

	/*
		
		InvMixColumns() is the inverse of the MixColumns() transformation.
		InvMixColumns() operates on the State column-by-column, treating each column as a fourterm polynomial as described in Sec. 4.3.
		The columns are considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a fixed polynomial a^-1*(x), given by
		Mathematical equations 5.9

		a^-1*x = {0b}*x^3 + {0d}*x^2 + {09}*x + {0e}

		Mathematical equations 5.10
		As described in Sec. 4.3, this can be written as a matrix multiplication.
		state'[x] = a^-1*x (*) state[x]

		As a result of this multiplication, the four bytes in a column are replaced by the following:

		state'[0][column] = ({0e} • state[0][column]) (+) ({0b} • state[1][column]) (+) ({0d} • state[2][column]) (+) ({09} • state[3][column])
		state'[1][column] = ({09} • state[0][column]) (+) ({0e} • state[1][column]) (+) ({0b} • state[2][column]) (+) ({0d} • state[3][column])
		state'[2][column] = ({0d} • state[0][column]) (+) ({09} • state[1][column]) (+) ({0e} • state[2][column]) (+) ({0b} • state[3][column])
		state'[3][column] = ({0b} • state[0][column]) (+) ({0d} • state[1][column]) (+) ({09} • state[2][column]) (+) ({0e} • state[3][column])

		InvMixColumns()是MixColumns()的逆向转换。
		InvMixColumns()对状态逐列操作，如第4.3节所述，将每一列作为一个四项式多项式处理。
		这些列被视为GF(2^8)上的多项式，并与固定的多项式a^-1*(x)相乘以x^4+1，给出如下
		数学方程式 5.9

		a^-1*x = {0b}*x^3 + {0d}*x^2 + {09}*x + {0e}

		数学方程式5.10
		如第4.3节所述，这可以写成一个矩阵乘法。
		state'[x] = a^-1*x (*) state[x]

		作为这个乘法的结果，一列中的四个字节被替换成以下内容:

		state'[0][column] = ({0e} • state[0][column]) (+) ({0b} • state[1][column]) (+) ({0d} • state[2][column]) (+) ({09} • state[3][column])
		state'[1][column] = ({09} • state[0][column]) (+) ({0e} • state[1][column]) (+) ({0b} • state[2][column]) (+) ({0d} • state[3][column])
		state'[2][column] = ({0d} • state[0][column]) (+) ({09} • state[1][column]) (+) ({0e} • state[2][column]) (+) ({0b} • state[3][column])
		state'[3][column] = ({0b} • state[0][column]) (+) ({0d} • state[1][column]) (+) ({09} • state[2][column]) (+) ({0e} • state[3][column])

	*/
	inline void InverseMixColumns(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		using namespace AES::DefineConstants;

		// AES_BLOCK_SIDE is 4
		#if 0

		std::deque<std::vector<std::uint8_t>> _stateByteDataBlock
		{
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0}
		};

		// matrix multiplication in GF(2^8)
		// * => galoisMul, + => ^

		for(std::uint32_t row = 0; row < 4; ++row)
		{
			for(std::uint32_t column = 0; column < 4; ++column)
			{
				_stateByteDataBlock.operator[](row).operator[](column) = 0x00;
				
				// Dot product of row (r) of the InverseMixColumns and the column (c) of the state
				// InverseMixColumns的r行与状态的c列的点积
				_stateByteDataBlock.operator[](row).operator[](column) ^= MultiplicationOfByteWithGaloisField(INVERSE_CMDS.operator[](row).operator[](column), stateByteDataBlock.operator[](row).operator[](column));
			}
		}

		stateByteDataBlock.swap(_stateByteDataBlock);

		_stateByteDataBlock.clear();

		#else

		std::uint8_t rowDatas[4], columnDatas[4];
		for (int column = 0; column < 4; ++column)
		{
			for (int row = 0; row < 4; ++row)
			{
				rowDatas[row] = stateByteDataBlock[row][column];
			}
			columnDatas[0] = MultiplicationOfByteWithGaloisField(0x0e, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[3]);
			columnDatas[1] = MultiplicationOfByteWithGaloisField(0x09, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[3]);
			columnDatas[2] = MultiplicationOfByteWithGaloisField(0x0d, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[3]);
			columnDatas[3] = MultiplicationOfByteWithGaloisField(0x0b, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[3]);
			for (int row = 0; row < 4; ++row)
			{
				stateByteDataBlock[row][column] = columnDatas[row];
			}
		}

		#endif
	}

	
	//Transformation in the Cipher that processes the State by cyclically shifting the last three rows of the State by different offsets.
	//密码中的转换，通过循环处理状态 将状态的最后三行按不同的偏移量进行移位。

	/*
		In the ShiftRows() transformation, the bytes in the last three rows of the State are cyclically shifted over different numbers of bytes (offsets).
		The first row, r = 0, is not shifted.
		Specifically, the ShiftRows() transformation proceeds as follows:
		
		Mathematical equations 5.3
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)

		where the shift value shift(row,Nb) depends on the row number, row, as follows (recall that Nb = 4):
		
		Mathematical equations 5.4
		shift(1,4) = 1;
		shift(2,4) = 2;
		shift(3,4) = 3;
			
		This has the effect of moving bytes to "lower" positions in the row (i.e., lower values of column in a given row),
		While the "lowest "bytes wrap around into the "top" of the row (i.e., higher values of column in a given row).

		在ShiftRows()转换中，State最后三行的字节在不同的字节数（偏移量）上被循环移位
		第一行，r = 0，不被移位。
		具体来说，ShiftRows()转换的过程如下。
			
		数学公式5.3
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)

		其中移位值shift(row,Nb)取决于行数row，如下所示（记得Nb=4）
		
		数学公式5.4
		shift(1,4) = 1;
		shift(2,4) = 2;
		shift(3,4) = 3。
		
		这样做的效果是将字节移到行中的 "较低 "位置（即在给定行中列的低值）
		而 "最低的 "字节则环绕到行的 "顶部"（即某一行中列的数值较高）
		
		The ShiftRows step operates on the rows of the state;
		It cyclically shifts the bytes in each row by a certain offset.
		In this way, each column of the output state of the ShiftRows step is composed of bytes from each column of the input state.
		The importance of this step is to avoid the columns being encrypted independently, in which case AES would degenerate into four independent block ciphers.

		ShiftRows步骤对状态的行进行操作。
		它循环地将每一行的字节按一定的偏移量移动。
		这样，ShiftRows步骤的输出状态的每一列都是由输入状态的每一列的字节组成。
		这一步的重要性在于避免各列被独立加密，在这种情况下，AES将退化为四个独立的块密码。
	*/
	inline void ShiftRows(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		std::size_t counter = 0;
		for (auto &row : stateByteDataBlock)
		{
			std::ranges::rotate(row.begin(), row.begin() + counter, row.end());
			++counter;
		}
	}

	/*
		This is the inverse of the ShiftRows() transformation.
		The bytes in the last three rows of the State are cyclically shifted over different numbers of bytes (offsets).
		The first row, r = 0, is not shifted.
		The bottom three rows are cyclically shifted by Nb - shift(r, Nb) bytes, where the shift value shift(r,Nb) depends on the row number, and is given in equation (5.4)
		(see Sec. 5.1.2).

		Specifically, the InvShiftRows() transformation proceeds as follows:
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)
		Conditions for variables: 0 < row < 4 and 0 <= column < Nb

		这是ShiftRows()转换的逆运算。
		最后三行的字节在不同的字节数（偏移量）上被循环移位。
		第一行，row = 0，不被移位。
		最下面的三行被循环移位Nb-shift(r,Nb)字节，其中shift(r,Nb)的值取决于行数，在公式(5.4)中给出
		(见第5.1.2节)。

		具体来说，InvShiftRows()转换的过程如下。
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)
		变量的条件：0 < row < 4 和 0 <= column < Nb
	*/
	inline void InverseShiftRows(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		std::size_t counter = 0;
		for (auto &row : stateByteDataBlock)
		{
			std::ranges::rotate(row.rbegin(), row.rbegin() + counter, row.rend());
			++counter;
		}
	}

	/*
		The SubBytes() transformation is a non-linear byte substitution that operates independently on each byte of the State using a substitution table (S-box).
		This S-box which is invertible, is constructed by composing two transformations:
		1. Take the multiplicative inverse in the finite field GF(2^8), described in Sec. 4.2;
		the element {00} is mapped to itself.
		2. Apply the following affine transformation (over GF(2) ):
		Mathematical equations 5.1
		bit[index] = bit[index] (+) bit[index + 4 mod 8] (+) bit[index + 5 mod 8] (+) bit[index + 6 mod 8] (+) bit[index + 7 mod 8] (+) c[index]

		for 0 <= index < 8 , where bit[index] is the index ^ the bit of the byte, and c[index] is the index ^ the bit of a byte c with the value {63} or {01100011}.
		Here and elsewhere, a prime on a variable (e.g., bit' ) indicates that the variable is to be updated with the value on the right.

		SubBytes()转换是一种非线性的字节替换，它使用一个替换表（S-box）对State的每个字节独立操作。
		这个S-box是可反转的，它是由两个转换组成的。
		1. 在有限域GF(2^8)中进行乘法逆运算，在第4.2节中描述。
		元素{00}被映射到它自己。
		2. 应用下面的仿射变换（在GF(2)上）。
		数学公式5.1
		bit[index] = bit[index] (+) bit[index + 4 mod 8] (+) bit[index + 5 mod 8] (+) bit[index + 6 mod 8] (+) bit[index + 7 mod 8] (+) c[index]
		for 0 <= index < 8 , 其中bit[index]是字节的index ^ the位，c[index]是字节c的index ^ the位，值为{63}或{01100011}。
		在这里和其他地方，变量上的素数（例如，bit'）表示该变量要用右边的值来更新。

		In the SubBytes step, each byte arrays[i][j] in the state array is replaced with a SubByte S-box[arrays[i][j]] using an 8-bit substitution box.
		Note that before round 0, the state array is simply the plaintext/input.
		This operation provides the non-linearity in the cipher.
		The S-box used is derived from the multiplicative inverse over GF(2^8), known to have good non-linearity properties.
		To avoid attacks based on simple algebraic properties, the S-box is constructed by combining the inverse function with an invertible affine transformation.
		The S-box is also chosen to avoid any fixed points (and so is a derangement), i.e., S-box[arrays[i][j]] != arrays[i][j] , and also any opposite fixed points, i.e., S-box[arrays[i][j]] (+) arrays[i][j] != FF16.
		While performing the decryption, the InvSubBytes step (the inverse of SubBytes) is used, which requires first taking the inverse of the affine transformation and then finding the multiplicative inverse.

		在SubBytes步骤中，状态数组中的每个字节arrays[i][j]被替换为SubByte S-box[arrays[i][j]]，使用一个8位替换框。
		注意，在第0轮之前，状态数组只是明文/输入。
		这个操作提供了密码中的非线性。
		所用的S-box是由GF(2^8)上的乘法逆推而来，已知其具有良好的非线性特性。
		为了避免基于简单代数特性的攻击，S-box是通过将反函数与可反转的仿射变换相结合而构建的。
		S-box的选择也是为了避免任何固定点（因此是一个脱轨），即S-box[arrays[i][j]] != arrays[i][j] ，以及任何相反的固定点，即S-box[ arrays[i][j] ] (+) arrays[i][j] != FF16。
		在进行解密时，使用了InvSubBytes步骤（SubBytes的逆），这需要先取仿射变换的逆，然后找到乘法的逆。
	*/

	//在密钥扩展例程中使用的函数，它接收一个四字节的输入字，并对四个字节中的每个字节应用一个S-box，以产生一个输出字。
	//Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word.
	inline void SubtituteBytes(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		using namespace AES::DefineConstants;

		//
		//Row is 0x?0
		//Column is 0x0?
		//Example: 0x00 <-> 0x63
		//1. Search Forward_S_Box, the row is 0 and the column is 0, then find the data 0x63
		//2. Search Backward_S_Box, the row is 6 and the column is 3, then find the data 0x00
		//
		//例子：0x00 <-> 0x63
		//1.搜索Forward_S_Box，行是0和列是0，然后找到数据0x63
		//2.搜索Backward_S_Box，行是6和列是3，然后找到数据0x00
		constexpr std::array<std::array<std::uint8_t, 16>, 16> Forward_S_Box
		{
			{
				{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
				{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
				{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
				{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
				{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
				{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
				{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
				{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
				{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
				{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
				{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
				{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
				{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
				{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
				{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
				{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
			},
		};

		for(auto& row : stateByteDataBlock)
		{
			std::ranges::transform
			(
				row.begin(),
				row.end(),
				row.begin(),
				[&Forward_S_Box](const std::uint8_t &byte) -> std::uint8_t
				{
					return Forward_S_Box[byte / 16][byte % 16];
				}
			);
		}
	}

	/*
		InvSubBytes() is the inverse of the byte substitution transformation, in which the inverse S-box is applied to each byte of the State.
		This is obtained by applying the inverse of the affine transformation (5.1) followed by taking the multiplicative inverse in GF(2^8).

		InvSubBytes()是字节替换变换的逆运算，其中逆S-box被应用于状态的每个字节。
		这是由应用仿射变换的逆（5.1），然后在GF(2^8)中取乘法逆得到的。
	*/
	inline void InverseSubtituteBytes(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		using namespace AES::DefineConstants;

		//
		//Row is 0x?0
		//Column is 0x0?
		//Example: 0x00 <-> 0x52
		//1. Search Forward_S_Box, the row is 0 and the column is 0, then find the data 0x52
		//2. Search Backward_S_Box, the row is 5 and the column is 2, then find the data 0x00
		//
		//例子：0x00 <-> 0x52
		//1.搜索Forward_S_Box，行是0和列是0，然后找到数据0x52
		//2.搜索Backward_S_Box，行是5和列是2，然后找到数据0x00
		constexpr std::array<std::array<std::uint8_t, 16>, 16> Backward_S_Box
		{
			{
				{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
				{0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
				{0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
				{0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
				{0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
				{0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
				{0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
				{0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
				{0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
				{0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
				{0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
				{0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
				{0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
				{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
				{0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
				{0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
			},
		};

		for(auto& row : stateByteDataBlock)
		{
			std::ranges::transform
			(
				row.begin(),
				row.end(),
				row.begin(),
				[&Backward_S_Box](const std::uint8_t &byte) -> std::uint8_t
				{
					return Backward_S_Box[byte / 16][byte % 16];
				}
			);
		}
	}

	/*
		In the AddRoundKey step, the subkey is combined with the state.
		For each round, a subkey is derived from the main key using Rijndael's key schedule; each subkey is the same size as the state.
		The subkey is added by combining each byte of the state with the corresponding byte of the subkey using bitwise (+).

		在AddRoundKey步骤中，子密钥与状态相结合。
		对于每一轮，使用Rijndael的密钥计划从主密钥中导出一个子密钥；每个子密钥的大小与状态相同。
		子密钥的添加是通过将状态的每个字节与子密钥的相应字节用位法（+）结合起来。

		Transformation in the Cipher and Inverse Cipher in which a Round Key is added to the State using an XOR operation.
		The length of a Round Key equals the size of the State data block (i.e., for Nb = 4, the Round Key length equals 128 bits/16 bytes).

		在密码器和反密码器中的转换，其中一个轮密钥是使用XOR操作添加到状态数据中
		轮密钥的长度等于状态数据块的大小（例如，对于Nb=4，轮密钥的长度等于128比特/16字节）
	*/
	inline void AddRoundKey(std::array<std::array<std::uint8_t, 4>, 4>& blockByteState, const std::vector<std::uint8_t>::const_iterator blockKeyIterator)
	{
		// AES_BLOCK_SIDE is 4
		// Add in GF(2^8) corresponding bytes of the subkey and state
		for(std::size_t row = 0; row < 4; ++row)
		{
			for(std::size_t column = 0; column < 4; ++column)
			{
				blockByteState.operator[](row).operator[](column) = blockByteState.operator[](row).operator[](column) ^ blockKeyIterator.operator[](row + 4 * column);
			}
		}
	}
}

namespace CommonSecurity::AES
{
	enum class AES_SecurityLevel
	{
		//128 bit
		ZERO = 0,
		//192 bit
		ONE = 1,
		//256 bit
		TWO = 2
	};

	template<AES_SecurityLevel SecurityLevel>
	constexpr std::array<std::size_t, 2>
	AES_SecurityLevelInforamtion()
	{
		//The number of 32-bit words comprising the cipher key in this AES cipher.
		//Paper content: Number of 32-bit words comprising the Cipher Key. 
		//For this standard, Nk = 4, 6, or 8. (Also see Sec. 6.3.) 
		//Nk is key word size
		std::size_t Number_Key_Data_Block_Size = 0;

		//The number of rounds in this AES cipher.
		//Paper content: Number of rounds, which is a function of Nk and Nb (which is fixed).
		//For this standard, Nr = 10, 12, or 14. (Also see Sec. 6.3.) 
		//Nr is * of rounds
		std::size_t Number_Execute_Round_Count = 0;

		if constexpr(SecurityLevel == CommonSecurity::AES::AES_SecurityLevel::ZERO)
		{
			Number_Key_Data_Block_Size = 4;
			Number_Execute_Round_Count = 10;

			return { Number_Key_Data_Block_Size, Number_Execute_Round_Count };
		}
		else if constexpr(SecurityLevel == CommonSecurity::AES::AES_SecurityLevel::ONE)
		{
			Number_Key_Data_Block_Size = 6;
			Number_Execute_Round_Count = 12;

			return { Number_Key_Data_Block_Size, Number_Execute_Round_Count };
		}
		else if constexpr(SecurityLevel == CommonSecurity::AES::AES_SecurityLevel::TWO)
		{
			Number_Key_Data_Block_Size = 8;
			Number_Execute_Round_Count = 14;

			return { Number_Key_Data_Block_Size, Number_Execute_Round_Count };
		}
		else
		{
			static_assert(CommonToolkit::Dependent_Always_Failed<SecurityLevel>, "Wrong AES DataWorker security level is selected !");
		}
	}

	/*
		Description of the Cryptographs(密码器的说明):

			AES is based on a design principle known as a substitution–permutation network, and is efficient in both software and hardware.
			Unlike its predecessor DES, AES does not use a Feistel network. AES is a variant of Rijndael, with a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
			By contrast, Rijndael per se is specified with block and key sizes that may be any multiple of 32 bits, with a minimum of 128 and a maximum of 256 bits.

			AES是基于一种被称为替换-互斥网络的设计原理，在软件和硬件上都很高效。 
			与其前身DES不同，AES不使用Feistel网络。
			AES是Rijndael的一个变种，其固定块大小为128比特，密钥大小为128、192或256比特。
			相比之下，Rijndael本身规定的块和密钥大小可以是32位的任何倍数，最小为128位，最大为256位。

			AES operates on a 4 × 4 column-major order array of bytes, termed the state.
			Most AES calculations are done in a particular finite field.
			AES在一个4×4列主序的字节数组上操作，称为状态。
			大多数AES的计算是在一个特定的有限域中进行的。
			For instance, 16 bytes, {byte0,byte1,......,btye15} are represented as this two-dimensional array:
			例如，16个字节，{byte0,byte1,......,btye15}被表示为这个二维阵列。
		
			(Byte data has been represented in hexadecimal 字节数据已用16进制表示)
			Byte two_dimensional_array
			{
				{0x00, 0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06, 0x07},
				{0x08, 0x09, 0x0F, 0x10},
				{0x11, 0x12, 0x13, 0x14},
			}

			The key size used for an AES cipher specifies the number of transformation rounds that convert the input, called the plaintext, into the final output, called the ciphertext. 
			The number of rounds are as follows:
			10 rounds for 128-bit keys.
			12 rounds for 192-bit keys.
			14 rounds for 256-bit keys.

			用于AES密码的密钥大小规定了将输入（称为明文）转换成最终输出（称为密文）的转换轮数。 
			轮数如下。
			128位密钥为10轮。
			192位密钥的12轮。
			256位密钥的14轮。

		Paper: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

		High-level description of the algorithm(密码器算法的高级说明):

			1.Key Expansion (密钥的扩展):
			Round keys are derived from the cipher key using the AES key schedule.
			AES requires a separate 128-bit round key block for each round plus one more.
			每一轮的子密钥都是使用AES的密钥计划从主密码密钥衍生出来的
			AES要求每一轮都有一个单独的128位比特的每轮密钥块，再加一个。

			2.Initial(1) round key addition (添加首轮密钥):

				2-1.AddRoundKey:
				Each byte of the state is combined with a byte of the round key using bitwise exclusive-OR operation.
				状态的每一个字节都与圆周率密钥的一个字节用按比特单位的异或运算结合起来。

			3.9,11 or 13 rounds (9、11或13轮):

				3-1.SubBytes:
				A non-linear substitution step where each byte is replaced with another according to a lookup table.
				一个非线性替换步骤，每个字节根据一个查找表被替换成另一个字节。

				3-2 ShiftRows:
				A transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
				转位步骤，状态的最后三行被循环地移位一定的步数。

				3-3: MixColumns:
				A linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
				一个线性混合操作，对状态的列进行操作，将每一列中的四个字节合并。

				3-4: 
					Execute 2-1 operation
					执行2-1 操作
			4.Final round (making 10, 12 or 14 rounds in total) 最后一轮（总共有10轮、12轮或14轮）:
				4-1: 
					Execute 3-1 operation
					执行3-1 操作
				4-2: 
					Execute 3-2 operation
					执行3-2 操作
				4-3: 
					Execute 2-1 operation
					执行2-1 操作
	*/
	
	template<AES_SecurityLevel SecurityLevel>
	class ExperimentalAlgorithm
	{

	private:

		template <AES_SecurityLevel>
		friend class DataWorker;

		static constexpr std::size_t ONE_WORD_BYTE_SIZE = sizeof(std::uint32_t);
		
		//The number of 32-bit words comprising the plaintext and columns comprising the state matrix of an AES cipher.
		//Paper content: Number of columns (32-bit words) comprising the State. For this standard, Nb = 4. (Also see Sec. 6.3.)
		//Nb is block word size
		static constexpr std::size_t NUMBER_DATA_BLOCK_COUNT = 4;
		
		static constexpr auto AES_CONFIG_INFORMATION = AES_SecurityLevelInforamtion<SecurityLevel>();

		static constexpr std::size_t Number_Key_Data_Block_Size = AES_CONFIG_INFORMATION[0];

		static constexpr std::size_t Number_Execute_Round_Count = AES_CONFIG_INFORMATION[1];
		
		static constexpr std::uint8_t Number_Block_Data_Byte_Size = ONE_WORD_BYTE_SIZE * NUMBER_DATA_BLOCK_COUNT * sizeof(std::uint8_t);
		
		std::vector<std::uint8_t> EncryptBlockData(const std::vector<std::uint8_t>& byteData, const std::vector<std::uint8_t>& expandedByteRoundKeyBlock)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			if(byteData.size() == GetBlockSize_DataByte() && expandedByteRoundKeyBlock.size() == GetBlockSize_ExpandedKeyByte())
			{
				std::vector<std::uint8_t> encryptedByteDataBlock(byteData.size());
				
				std::array<std::array<std::uint8_t, 4>, 4> currentStateBlock
				{
					{
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 }
					},
				};
				
				std::uint32_t row = 0, column = 0;
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						stateBlockContent.operator[](column) = byteData.operator[](row + 4 * column);
					}
					++row;
				}
				row = 0, column = 0;
				
				// ROUND: 0
				AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin());
				
				// ROUNDS: 1 ~ NRound-1
				for (std::uint32_t round = 1; round <= this->Number_Execute_Round_Count - 1; ++round)
				{
					SubtituteBytes(currentStateBlock);
					ShiftRows(currentStateBlock);
					MixColumns(currentStateBlock);
					
					AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin() + round * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				}
				
				// ROUND: NRound
				SubtituteBytes(currentStateBlock);
				ShiftRows(currentStateBlock);
				
				AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin() + this->Number_Execute_Round_Count * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						encryptedByteDataBlock.operator[](row + 4 * column) = stateBlockContent.operator[](column);
					}
					++row;
				}
				row = 0, column = 0;
				
				return encryptedByteDataBlock;
			}
			else
			{
				throw std::length_error("");
			}
		}

		std::vector<std::uint8_t> DecryptBlockData(const std::vector<std::uint8_t>& byteData, const std::vector<std::uint8_t>& expandedByteRoundKeyBlock)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			if(byteData.size() == GetBlockSize_DataByte() && expandedByteRoundKeyBlock.size() == GetBlockSize_ExpandedKeyByte())
			{
				std::vector<std::uint8_t> decryptedByteDataBlock(byteData.size());
				
				std::array<std::array<std::uint8_t, 4>, 4> currentStateBlock
				{
					{
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 }
					},
				};
				
				std::uint32_t row = 0, column = 0;
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						stateBlockContent.operator[](column) = byteData.operator[](row + 4 * column);
					}
					++row;
				}
				row = 0, column = 0;
				
				// INVERSE ROUND: NRound
				AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin() + this->Number_Execute_Round_Count * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				
				// INVERSE ROUNDS: NRound-1 ~ 1
				for (std::uint32_t round = this->Number_Execute_Round_Count - 1; round >= 1; --round)
				{
					InverseSubtituteBytes(currentStateBlock);
					InverseShiftRows(currentStateBlock);
					
					AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin() + round * 4 * this->NUMBER_DATA_BLOCK_COUNT);
					
					InverseMixColumns(currentStateBlock);
				}
				
				// INVERSE ROUND: 0
				InverseSubtituteBytes(currentStateBlock);
				InverseShiftRows(currentStateBlock);
				
				AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin());
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						decryptedByteDataBlock.operator[](row + 4 * column) = stateBlockContent.operator[](column);
					}
					++row;
				}
				row = 0, column = 0;
				
				return decryptedByteDataBlock;
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			KEY SCHEDULING
			https://en.wikipedia.org/wiki/AES_key_schedule
			https://autonome-antifa.org/IMG/pdf/Rijndael.pdf
		*/
		void KeyExpansion(const std::vector<std::uint8_t>& byteKeys, std::vector<std::vector<std::uint8_t>>& expandedRoundKeys)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			//Key schedule round : The size of the key schedule depends on the number of rounds
			constexpr std::uint32_t KeyScheduleRound = this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
			
			expandedRoundKeys.resize( byteKeys.size() / (this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size), std::vector<std::uint8_t>{});
			for(std::size_t blockIndex = 0; blockIndex < expandedRoundKeys.size(); ++blockIndex)
			{
				expandedRoundKeys[blockIndex].resize(this->ONE_WORD_BYTE_SIZE * KeyScheduleRound);

				for(std::uint32_t index = 0; index < this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size; ++index)
				{
					expandedRoundKeys[blockIndex][index] = byteKeys[index];
				}
			}
			
			using ByteArray4 = std::array<std::uint8_t, 4>;
			
			ByteArray4 temporaryWord { 0, 0, 0, 0 };
			//Round constants
			ByteArray4 RCON_Word_Data { 0, 0, 0, 0 };
			
			// 同余式
			// congruent exprssion
			// a ≡ b (mod m)
			
			// Definition of congruence theorem
			// An important concept in number theory.
			// Given a positive integer c
			// Two integers a and b are said to be congruent to mod c if they satisfy that a-b is divisible by m, i.e., (a-b)/c yields an integer.
			// congruence of modulo c is an equivalence of integers
			
			// 同余定理的定义
			// 数论中的重要概念。
			// 给定一个正整数c
			// 如果两个整数a和b满足a-b能够被m整除，即(a-b)/c得到一个整数，那么就称整数a与b对模c同余。
			// 对模c同余是整数的一个等价关系
			
			//N是论文内容中的变量Nk（KeyWordSize）。
			//N is the variable Nk (KeyWordSize) from the paper content.
			
			//Index_Round是密钥安排轮次的索引
			//Index_Round is the index of the key schedule round
			
			for(std::size_t blockIndex = 0; blockIndex < expandedRoundKeys.size(); ++blockIndex)
			{
				for(std::size_t roundIndex = this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size; roundIndex < this->ONE_WORD_BYTE_SIZE * KeyScheduleRound; roundIndex += 4)
				{
					temporaryWord[0] = expandedRoundKeys[blockIndex][roundIndex - sizeof(std::uint32_t) + 0];
					temporaryWord[1] = expandedRoundKeys[blockIndex][roundIndex - sizeof(std::uint32_t) + 1];
					temporaryWord[2] = expandedRoundKeys[blockIndex][roundIndex - sizeof(std::uint32_t) + 2];
					temporaryWord[3] = expandedRoundKeys[blockIndex][roundIndex - sizeof(std::uint32_t) + 3];
				
					//Condition 1: N ≤ 6
					//Code: this->NKeyWordSize <= 6
					//Condition 2: index ≡ 0 ( modulo N )
					//Condition 1 And Condition 2
					//Code: roundIndex % this->NKeyWordSize == 0
					if(roundIndex / 4 % this->Number_Key_Data_Block_Size == 0)
					{
						KeyWordAES_LeftRotate(temporaryWord);
						KeyWordAES_Subtitute(temporaryWord);
						RCON(RCON_Word_Data, roundIndex / (this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size));
					
						ByteArray4 temporaryWord2 { 0, 0, 0, 0 };
					
						for (int indexByte = 0; indexByte < 4; ++indexByte)
						{
							temporaryWord2[indexByte] = temporaryWord[indexByte] ^ RCON_Word_Data[indexByte];
						}
					
						temporaryWord = temporaryWord2;
					}
				
					//Condition 1: N ＞ 6
					//Code: this->NKeyWordSize > 6
					//Condition 2: index ≡ 4 ( modulo N )
					//Condition 1 Or Condition 2
					//Code: ((roundIndex - 4) % this->NKeyWordSize) == 0
					else if(this->Number_Key_Data_Block_Size > 6 && roundIndex / 4 % this->Number_Key_Data_Block_Size == 4)
					{
						KeyWordAES_Subtitute(temporaryWord);
					}
				
					expandedRoundKeys[blockIndex][roundIndex + 0] = expandedRoundKeys[blockIndex][roundIndex + 0 - sizeof(std::uint32_t) * this->Number_Key_Data_Block_Size] ^ temporaryWord[0];
					expandedRoundKeys[blockIndex][roundIndex + 1] = expandedRoundKeys[blockIndex][roundIndex + 1 - sizeof(std::uint32_t) * this->Number_Key_Data_Block_Size] ^ temporaryWord[1];
					expandedRoundKeys[blockIndex][roundIndex + 2] = expandedRoundKeys[blockIndex][roundIndex + 2 - sizeof(std::uint32_t) * this->Number_Key_Data_Block_Size] ^ temporaryWord[2];
					expandedRoundKeys[blockIndex][roundIndex + 3] = expandedRoundKeys[blockIndex][roundIndex + 3 - sizeof(std::uint32_t) * this->Number_Key_Data_Block_Size] ^ temporaryWord[3];
				}
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(temporaryWord.data(), temporaryWord.size());
			my_cpp2020_assert(CheckPointer == temporaryWord.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(RCON_Word_Data.data(), RCON_Word_Data.size());
			my_cpp2020_assert(CheckPointer == RCON_Word_Data.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		constexpr std::uint8_t GetBlockSize_DataByte() const
		{
			return this->Number_Block_Data_Byte_Size;
		}

		constexpr std::size_t GetBlockSize_KeyByte() const
		{
			return this->Number_Key_Data_Block_Size * this->ONE_WORD_BYTE_SIZE;
		}

		constexpr std::size_t GetBlockSize_ExpandedKeyByte()
		{
			return this->ONE_WORD_BYTE_SIZE * this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
		}
	};

	template<AES_SecurityLevel SecurityLevel>
	class OfficialAlgorithm
	{

	private:

		template <AES_SecurityLevel>
		friend class DataWorker;

		static constexpr std::size_t ONE_WORD_BYTE_SIZE = sizeof(std::uint32_t);
		
		//The number of 32-bit words comprising the plaintext and columns comprising the state matrix of an AES cipher.
		//Paper content: Number of columns (32-bit words) comprising the State. For this standard, Nb = 4. (Also see Sec. 6.3.)
		//Nb is block word size
		static constexpr std::size_t NUMBER_DATA_BLOCK_COUNT = 4;
		
		static constexpr auto AES_CONFIG_INFORMATION = AES_SecurityLevelInforamtion<SecurityLevel>();

		static constexpr std::size_t Number_Key_Data_Block_Size = AES_CONFIG_INFORMATION[0];

		static constexpr std::size_t Number_Execute_Round_Count = AES_CONFIG_INFORMATION[1];
		
		static constexpr std::uint8_t Number_Block_Data_Byte_Size = ONE_WORD_BYTE_SIZE * NUMBER_DATA_BLOCK_COUNT * sizeof(std::uint8_t);

		static constexpr std::array<std::uint32_t, 16> PowerXTimeTable = AES::DefineConstants::GeneratePowerXTimeTable();

		static constexpr std::array<std::array<std::uint32_t, 256>, 4> EncryptionWordTable = AES::DefineConstants::GenerateEncryptionWordTable();

		static constexpr std::array<std::array<std::uint32_t, 256>, 4> DecryptionWordTable = AES::DefineConstants::GenerateDecryptionWordTable();

		std::vector<std::uint32_t> EncryptionKey = std::vector<std::uint32_t>(this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1), 0);
		std::vector<std::uint32_t> DecryptionKey = std::vector<std::uint32_t>(this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1), 0);

		std::vector<std::uint8_t> EncryptBlockData(const std::vector<std::uint8_t>& byteData)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			if(byteData.size() == GetBlockSize_DataByte())
			{
				std::vector<std::uint8_t> encryptedByteDataBlock(byteData.size(), 0x00);
				
				auto wordDataBlock = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(byteData.data(), byteData.size());

				auto& WordA = wordDataBlock[0];
				auto& WordB = wordDataBlock[1];
				auto& WordC = wordDataBlock[2];
				auto& WordD = wordDataBlock[3];

				// First round just XORs input with key.
				WordA ^= EncryptionKey[0];
				WordB ^= EncryptionKey[1];
				WordC ^= EncryptionKey[2];
				WordD ^= EncryptionKey[3];

				// Middle rounds shuffle using tables.
				// Number of rounds is set by length of expanded key.
				std::size_t WordKeyOffest = 4;
				std::uint32_t T0 = 0U, T1 = 0U, T2 = 0U, T3 = 0U;
				for(std::size_t round = 0U; round < EncryptionKey.size() / 4 - 2; ++round)
				{
					T0 = EncryptionKey[ WordKeyOffest + 0 ]
						^ EncryptionWordTable[0][ static_cast<std::uint8_t>( WordA >> 24 ) ]
						^ EncryptionWordTable[1][ static_cast<std::uint8_t>( WordB >> 16 ) ]
						^ EncryptionWordTable[2][ static_cast<std::uint8_t>( WordC >> 8 ) ]
						^ EncryptionWordTable[3][ static_cast<std::uint8_t>( WordD ) ];

					T1 = EncryptionKey[ WordKeyOffest + 1 ]
						^ EncryptionWordTable[0][ static_cast<std::uint8_t>( WordB >> 24 ) ]
						^ EncryptionWordTable[1][ static_cast<std::uint8_t>( WordC >> 16 ) ]
						^ EncryptionWordTable[2][ static_cast<std::uint8_t>( WordD >> 8 ) ]
						^ EncryptionWordTable[3][ static_cast<std::uint8_t>( WordA ) ];

					T2 = EncryptionKey[ WordKeyOffest + 2 ]
						^ EncryptionWordTable[0][ static_cast<std::uint8_t>( WordC >> 24 ) ]
						^ EncryptionWordTable[1][ static_cast<std::uint8_t>( WordD >> 16 ) ]
						^ EncryptionWordTable[2][ static_cast<std::uint8_t>( WordA >> 8 ) ]
						^ EncryptionWordTable[3][ static_cast<std::uint8_t>( WordB ) ];

					T3 = EncryptionKey[ WordKeyOffest + 3 ]
						^ EncryptionWordTable[0][ static_cast<std::uint8_t>( WordD >> 24 ) ]
						^ EncryptionWordTable[1][ static_cast<std::uint8_t>( WordA >> 16 ) ]
						^ EncryptionWordTable[2][ static_cast<std::uint8_t>( WordB >> 8 ) ]
						^ EncryptionWordTable[3][ static_cast<std::uint8_t>( WordC ) ];

					WordKeyOffest += 4;

					WordA = T0, WordB = T1, WordC = T2, WordD = T3;
				}

				// Last round uses s-box directly and XORs to produce output.
				WordA = static_cast<std::uint32_t>( Subtitute_ByteBox[ T0 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T1 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T2 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T3 & 0xff ] );

				WordB = static_cast<std::uint32_t>( Subtitute_ByteBox[ T1 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T2 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T3 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T0 & 0xff ] );

				WordC = static_cast<std::uint32_t>( Subtitute_ByteBox[ T2 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T3 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T0 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T1 & 0xff ] );

				WordD = static_cast<std::uint32_t>( Subtitute_ByteBox[ T3 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T0 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T1 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T2 & 0xff ] );
				
				WordA ^= EncryptionKey[WordKeyOffest + 0];
				WordB ^= EncryptionKey[WordKeyOffest + 1];
				WordC ^= EncryptionKey[WordKeyOffest + 2];
				WordD ^= EncryptionKey[WordKeyOffest + 3];

				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(wordDataBlock, encryptedByteDataBlock.data());

				return encryptedByteDataBlock;
			}
			else
			{
				throw std::length_error("");
			}
		}

		std::vector<std::uint8_t> DecryptBlockData(const std::vector<std::uint8_t>& byteData)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			if(byteData.size() == GetBlockSize_DataByte())
			{
				std::vector<std::uint8_t> decryptedByteDataBlock(byteData.size(), 0x00);
				
				auto wordDataBlock = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(byteData.data(), byteData.size());
				
				auto& WordA = wordDataBlock[0];
				auto& WordB = wordDataBlock[1];
				auto& WordC = wordDataBlock[2];
				auto& WordD = wordDataBlock[3];

				// First round just XORs input with key.
				WordA ^= DecryptionKey[0];
				WordB ^= DecryptionKey[1];
				WordC ^= DecryptionKey[2];
				WordD ^= DecryptionKey[3];

				// Middle rounds shuffle using tables.
				// Number of rounds is set by length of expanded key.
				std::size_t WordKeyOffest = 4;
				std::uint32_t T0 = 0U, T1 = 0U, T2 = 0U, T3 = 0U;
				for(std::size_t round = 0U; round < DecryptionKey.size() / 4 - 2; ++round)
				{
					T0 = DecryptionKey[ WordKeyOffest + 0 ]
						^ DecryptionWordTable[0][ static_cast<std::uint8_t>( WordA >> 24 ) ]
						^ DecryptionWordTable[1][ static_cast<std::uint8_t>( WordD >> 16 ) ]
						^ DecryptionWordTable[2][ static_cast<std::uint8_t>( WordC >> 8 ) ]
						^ DecryptionWordTable[3][ static_cast<std::uint8_t>( WordB ) ];

					T1 = DecryptionKey[ WordKeyOffest + 1 ]
						^ DecryptionWordTable[0][ static_cast<std::uint8_t>( WordB >> 24 ) ]
						^ DecryptionWordTable[1][ static_cast<std::uint8_t>( WordA >> 16 ) ]
						^ DecryptionWordTable[2][ static_cast<std::uint8_t>( WordD >> 8 ) ]
						^ DecryptionWordTable[3][ static_cast<std::uint8_t>( WordC ) ];

					T2 = DecryptionKey[ WordKeyOffest + 2 ]
						^ DecryptionWordTable[0][ static_cast<std::uint8_t>( WordC >> 24 ) ]
						^ DecryptionWordTable[1][ static_cast<std::uint8_t>( WordB >> 16 ) ]
						^ DecryptionWordTable[2][ static_cast<std::uint8_t>( WordA >> 8 ) ]
						^ DecryptionWordTable[3][ static_cast<std::uint8_t>( WordD ) ];

					T3 = DecryptionKey[ WordKeyOffest + 3 ]
						^ DecryptionWordTable[0][ static_cast<std::uint8_t>( WordD >> 24 ) ]
						^ DecryptionWordTable[1][ static_cast<std::uint8_t>( WordC >> 16 ) ]
						^ DecryptionWordTable[2][ static_cast<std::uint8_t>( WordB >> 8 ) ]
						^ DecryptionWordTable[3][ static_cast<std::uint8_t>( WordA ) ];

					WordKeyOffest += 4;

					WordA = T0, WordB = T1, WordC = T2, WordD = T3;
				}

				// Last round uses s-box directly and XORs to produce output.
				WordA = static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T0 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T3 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T2 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T1 & 0xff ] );

				WordB = static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T1 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T0 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T3 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T2 & 0xff ] );

				WordC = static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T2 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T1 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T0 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T3 & 0xff ] );

				WordD = static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T3 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T2 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T1 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T0 & 0xff ] );
				
				WordA ^= DecryptionKey[WordKeyOffest + 0];
				WordB ^= DecryptionKey[WordKeyOffest + 1];
				WordC ^= DecryptionKey[WordKeyOffest + 2];
				WordD ^= DecryptionKey[WordKeyOffest + 3];

				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(wordDataBlock, decryptedByteDataBlock.data());

				return decryptedByteDataBlock;
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			KEY SCHEDULING
			https://en.wikipedia.org/wiki/AES_key_schedule
			https://autonome-antifa.org/IMG/pdf/Rijndael.pdf
		*/
		void KeyExpansion(std::span<const std::uint8_t> byteKeys)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			//Key schedule round : The size of the key schedule depends on the number of rounds
			constexpr std::uint32_t KeyScheduleRound = this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
			
			//Determine the number of 32-bit words in the key
			std::size_t WordKeysSize = byteKeys.size() / sizeof(std::uint32_t);

			//Copy the original key
			std::memmove(EncryptionKey.data(), byteKeys.data(), WordKeysSize * sizeof(std::uint32_t));
			if constexpr(std::endian::native == std::endian::big)
			{
				for(auto& Word : EncryptionKey)
				{
					Word = CommonToolkit::ByteSwap::byteswap(Word);
				}
			}

			//Generate the key schedule (encryption)
			for(std::size_t Index = WordKeysSize; Index < KeyScheduleRound; Index++)
			{
				std::uint32_t Word = EncryptionKey[Index - 1];
				if(Index % WordKeysSize == 0)
				{
					//Left rotate word data
					//Word = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(Word, 4);
					Word = ( Word << 8 ) | ( Word >> 24 );

					//Substitute word data
					Word = static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word & 0xff ] );

					Word = Word ^ (static_cast<std::uint32_t>( this->PowerXTimeTable[Index / this->Number_Key_Data_Block_Size - 1] ) << 24);
				}
				else if((WordKeysSize > 6) && (Index % WordKeysSize) == 4)
				{
					//Substitute word data
					Word = static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word & 0xff ] );
				}
				EncryptionKey[Index] = EncryptionKey[Index - WordKeysSize] ^ Word;
			}

			//Generate the key schedule (decryption)
			for(std::size_t Index = 0; Index < KeyScheduleRound; Index += 4)
			{
				std::size_t KeyOffset = KeyScheduleRound - Index - 4;
				for(std::size_t Index2 = 0; Index2 < 4; Index2++)
				{
					std::uint32_t Word = EncryptionKey[KeyOffset + Index2];
					if((Index > 0) && (Index + 4) < KeyScheduleRound)
					{
						Word = DecryptionWordTable[0][ Subtitute_ByteBox[ Word >> 24 ] ]
							^ DecryptionWordTable[1][ Subtitute_ByteBox[ Word >> 16 & 0xff ] ]
							^ DecryptionWordTable[2][ Subtitute_ByteBox[ Word >> 8 & 0xff ] ]
							^ DecryptionWordTable[3][ Subtitute_ByteBox[ Word & 0xff ] ];
					}
					DecryptionKey[Index + Index2] = Word;
				}
			}
		}

		constexpr std::uint8_t GetBlockSize_DataByte() const
		{
			return this->Number_Block_Data_Byte_Size;
		}

		constexpr std::size_t GetBlockSize_KeyByte() const
		{
			return this->Number_Key_Data_Block_Size * this->ONE_WORD_BYTE_SIZE;
		}

		constexpr std::size_t GetBlockSize_ExpandedKeyByte()
		{
			return this->ONE_WORD_BYTE_SIZE * this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
		}
	};
}

namespace CommonSecurity::TripleDES::DefineConstants
{
	template<bool Experimental>
	struct SubstitutionBox;

	//For the generation of FeistelBox
	//用于生成Feistel盒子
	inline constexpr std::uint64_t
	PermuteBlock(std::uint64_t data, std::array<std::uint8_t, 32> permuteation_table)
	{
		constexpr std::uint64_t bit_mask = 1;

		std::uint64_t permuted_data = 0;

		for(std::size_t index = 0; index < permuteation_table.size(); index++)
		{
			std::uint64_t bit = (data >> permuteation_table[index]) & bit_mask;
			permuted_data |= (bit << static_cast<std::uint32_t>( (permuteation_table.size() - 1) - index) );
		}

		return permuted_data;
	}

	//For the generation of subkeys, you need to use the Key Parity Choice table
	//对于子密钥的生成，你需要使用密钥奇偶性选择表
	inline constexpr std::uint64_t
	PermuteBlock(std::uint64_t data, std::array<std::uint8_t, 48> permuteation_table)
	{
		constexpr std::uint64_t bit_mask = 1;

		std::uint64_t permuted_data = 0;

		for(std::size_t index = 0; index < permuteation_table.size(); index++)
		{
			std::uint64_t bit = (data >> permuteation_table[index]) & bit_mask;
			permuted_data |= (bit << static_cast<std::uint32_t>( (permuteation_table.size() - 1) - index) );
		}

		return permuted_data;
	}

	//For the generation of subkeys, you need to use the selection table (representing the permutation function and the compression function) uses
	//对于子密钥的生成，你需要使用（代表排列组合函数和压缩函数）用途的选择表
	inline constexpr std::uint64_t
	PermuteBlock(std::uint64_t data, std::array<std::uint8_t, 56> permuteation_table)
	{
		constexpr std::uint64_t bit_mask = 1;

		std::uint64_t permuted_data = 0;

		for(std::size_t index = 0; index < permuteation_table.size(); index++)
		{
			std::uint64_t bit = (data >> permuteation_table[index]) & bit_mask;
			permuted_data |= (bit << static_cast<std::uint32_t>( (permuteation_table.size() - 1) - index) );
		}

		return permuted_data;
	}

	inline constexpr std::array<std::array<std::uint32_t, 64>, 8>
	GenerateFeistelBox();

	template<>
	struct SubstitutionBox<true>
	{
		static constexpr std::array<std::array<char, 64>, 8> PlaneData
		{{
			{{
				14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
				0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
				4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
				15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
			}},
			{{
				15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
				3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
				0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
				13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
			}},
			{{
				10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
				13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
				13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
				1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
			}},
			{{
				7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
				13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
				10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
				3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
			}},
			{{
				2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
				14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
				4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
				11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
			}},
			{{
				12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
				10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
				9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
				4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
			}},
			{{
				4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
				13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
				1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
				6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
			}},
			{{
				13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
				1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
				7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
				2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
			}}
		}};
	};

	template<>
	struct SubstitutionBox<false>
	{
		//Byte Data Substitution Box
		//字节数据代换盒
		//Here it means that each S-box is a 4x16 permutation table, 6 bits -> 4 bits, 8 S-boxes
		//在这里表示每个S盒是4x16的置换表，6位 -> 4位，8个S盒
		static constexpr std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> CubeData
		{{
			{{
				/* Box 0 */
				{{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 }},
				{{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 }},
				{{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 }},
				{{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }}
			}},

			{{
				/* Box 1 */
				{{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 }},
				{{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 }},
				{{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 }},
				{{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }}
			}},

			{{
				/* Box 2 */
				{{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 }},
				{{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 }},
				{{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 }},
				{{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }}
			}},

			{{
				/* Box 3 */
				{{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 }},
				{{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 }},
				{{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 }},
				{{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }}
			}},

			{{
				/* Box 4 */
				{{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 }},
				{{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 }},
				{{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 }},
				{{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }}
			}},
		
			{{
				/* Box 5 */
				{{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 }},
				{{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 }},
				{{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 }},
				{{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }}
			}},

			{{
				/* Box 6 */
				{{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 }},
				{{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 }},
				{{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 }},
				{{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }}
			}},

			{{
				/* Box 7 */
				{{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 }},
				{{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 }},
				{{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 }},
				{{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }}
			}}
		}};
	};

	inline constexpr std::array<std::array<std::uint32_t, 64>, 8>
	GenerateFeistelBox()
	{
		std::array<std::array<std::uint32_t, 64>, 8> FeistelBox{};

		constexpr std::array<std::uint8_t, 32> permutation_function_box_data
		{
			16, 25, 12, 11, 3, 20, 4, 15,
			31, 17, 9, 6, 27, 14, 1, 22,
			30, 24, 8, 18, 0, 5, 29, 23,
			13, 19, 2, 26, 10, 21, 28, 7,
		};

		for(std::uint32_t box_index = 0; box_index < SubstitutionBox<false>::CubeData.size(); box_index++)
		{
			for(std::uint32_t group_index = 0; group_index < SubstitutionBox<false>::CubeData[0].size(); group_index++)
			{
				for(std::uint32_t index = 0; index < SubstitutionBox<false>::CubeData[0][0].size(); index++)
				{
					std::uint64_t feistel_value = static_cast<std::uint64_t>(SubstitutionBox<false>::CubeData[box_index][group_index][index]) << (4U * (7U - box_index));
					feistel_value = PermuteBlock(feistel_value, permutation_function_box_data);

					// Row is determined by the 1st and 6th bit.
					// Column is the middle four bits.
					// 行是由第1比特位和第6比特位决定的。
					// 列是中间的4个比特位。
					std::uint8_t row = static_cast<std::uint8_t>( ( (group_index & 2U) << 4U ) | group_index & 1U );
					std::uint8_t column = static_cast<std::uint8_t>(index << 1U);
					std::uint32_t table_index = row | column;

					// The rotation was performed in the feistel rounds, being factored out and now mixed into the feistel-box.
					// 旋转是在feistel轮中进行的，被因子化了，现在混在feistel-box中。
					feistel_value = (feistel_value << 1U) | (feistel_value >> 31U);

					FeistelBox[box_index][table_index] = static_cast<std::uint32_t>(feistel_value);
				}
			}
		}

		return FeistelBox;
	}

	// Contains the SubstitutionBox and PermutationFunctionBox, then use PermutationBlock function to generate the XOR Table
	// 包含SubstitutionBox和PermutationFunctionBox，然后使用PermutationBlock函数来生成XOR表
	// FeistelBox[box_index][16 * group_index + index]
	// for SubstitutionBox<true>::CubeData[box_index][group_index][index] << 4 * (7-box_index)
	inline constexpr std::array<std::array<std::uint32_t, 64>, 8> FeistelBox = GenerateFeistelBox();
}

namespace CommonSecurity::TripleDES::ProcedureFunctions
{
	template<bool Experimental>
	class DataWorker;

	template<>
	class DataWorker<true>
	{

	private:

		//First Step (Used to perform an initial permutation)
		//第一个步骤
		//Forward Permutation Table
		static constexpr std::array<std::uint8_t, 64> InitialPermutationTable
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

		//Last Step (Used to perform a final permutation) This is the inverse of InitialPermutationTable
		//最后一步
		//Backward Permutation Table
		static constexpr std::array<std::uint8_t, 64> FinalPermutationTable
		{
			40,  8, 48, 16, 56, 24, 64, 32,
			39,  7, 47, 15, 55, 23, 63, 31,
			38,  6, 46, 14, 54, 22, 62, 30,
			37,  5, 45, 13, 53, 21, 61, 29,
			36,  4, 44, 12, 52, 20, 60, 28,
			35,  3, 43, 11, 51, 19, 59, 27,
			34,  2, 42, 10, 50, 18, 58, 26,
			33,  1, 41,  9, 49, 17, 57, 25
		};

		//Transform:(Results like data compression), Used in the key schedule to select 56 bits from a 64-bit input
		//变换:（结果类似于数据压缩），在密钥计划中用于从64位输入中选择56位
		static constexpr std::array<std::uint8_t, 56> KeyParityChoiceTable
		{
			57, 49, 41, 33, 25, 17, 9,  1,
			58, 50, 42, 34, 26, 18, 10, 2,
			59, 51, 43, 35, 27, 19, 11, 3,
			60, 52, 44, 36, 63, 55, 47, 39, 
			31, 23, 15, 7, 62, 54, 46, 38,
			30, 22, 14, 6, 61, 53, 45, 37,
			29, 21, 13, 5, 28, 20, 12, 4
		};

		//Transform:(Results like data compression), Used in the key schedule to produce each subkey by selecting 48 bits from the 56-bit input
		//变换：（结果类似于数据压缩），在密钥计划中使用，通过从56位输入中选择48位来产生每个子密钥
		static constexpr std::array<std::uint8_t, 48> KeyPermutationCompressionChoiceTable
		{
			14, 17, 11, 24, 1,  5,  3,  28,
			15, 6,  21, 10, 23, 19, 12, 4, 
			26, 8,  16, 7,  27, 20, 13, 2,
			41, 52, 31, 37, 47, 55, 30, 40,
			51, 45, 33, 48, 44, 49, 39, 56,
			34, 53, 46, 42, 50, 36, 29, 32
		};

		//Used to expand an input block of 32 bits, producing extension an output block of 48 bits.
		//32位数据扩展为48位数据
		static constexpr std::array<std::uint8_t, 48> DataExtensionPermutationTable
		{
			32, 1,  2,  3,  4,  5,  4,  5, 
			6,  7,  8,  9,  8,  9,  10, 11,
			12, 13, 12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21, 20, 21,
			22, 23, 24, 25, 24, 25, 26, 27,
			28, 29, 28, 29, 30, 31, 32, 1
		};

		//Byte Data Permutation Function Box (Yields a 32-bit output from a 32-bit input)
		//字节数据置换方法盒
		static constexpr std::array<std::uint8_t, 32> PermutationFunctionBox
		{
			16, 7,  20, 21,
			29, 12, 28, 17,
			1,  15, 23, 26,
			5,  18, 31, 10,
			2,  8,  24, 14,
			32, 27, 3,  9,
			19, 13, 30, 6,
			22, 11, 4,  25
		};
		
		static constexpr std::uint32_t LOW_BIT32_ONE_MASK = 0x00000001;
		static constexpr std::uint64_t LOW_BIT64_ONE_MASK = 0x0000000000000001;
		static constexpr std::uint64_t LOW_BIT64_MASK  = 0x00000000FFFFFFFF;

		//缓存的主密钥 (64位)
		//Cached original master key (64-bit)
		std::uint64_t OriginalKey;
		std::uint64_t RecordOriginalKey;

		//缓存的16轮子密钥（48位）
		//Cached 16 rounds of subkeys (48 bit)
		std::array<std::uint64_t, 16> SubKeyArray;

		template<typename InputType, typename OutputType>
		void PermuteDataBlocks(InputType&& Data, OutputType&& PermutedData, std::size_t DataTableSize, const std::uint8_t* PermutationTable, auto PermutationTableSize, auto BitMask)
		{
			for (decltype(PermutationTableSize) index = 0; index < PermutationTableSize; index++)
			{
				PermutedData <<= 1;
				PermutedData |= (Data >> ( DataTableSize - PermutationTable[index]) ) & BitMask;
			}
		}

		std::uint32_t RoundFeistelFunction(const std::uint32_t CurrentRoundDataBlock, std::uint64_t CurrentRoundKey)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;
			
			/* 48 Bits */
			std::uint64_t SubstitutionBoxInput = 0;
			
			/* 32 Bits */
			std::uint32_t SubstitutionBoxOutput = 0;

			//Extend the data block and then re-permute the operation
			//对数据块进行扩展，然后重新置换操作
			this->PermuteDataBlocks(CurrentRoundDataBlock, SubstitutionBoxInput, 32, DataExtensionPermutationTable.data(), DataExtensionPermutationTable.size(), LOW_BIT32_ONE_MASK);

			//Use the key's data (48 Bits) for exclusive-or operation with the original data (48 Bits)
			//使用密钥的数据与原始数据进行异或操作
			SubstitutionBoxInput ^= CurrentRoundKey;

			//The 48-bit extended replacement key, divided into eight groups of six bits each
			//48位扩展置换后的密钥，分成8组，每组6位
			for(std::size_t Counter = 0; Counter < 8; ++Counter)
			{
				// 00 00 RCCC CR00 00 00 00 00 00 s_input
				// 00 00 1000 0100 00 00 00 00 00 row mask
				// 00 00 0111 1000 00 00 00 00 00 column mask

				char row = 0, column = 0;

				row = static_cast<char>( (SubstitutionBoxInput & (0x0000840000000000 >> (6 * Counter))) >> (42 - 6 * Counter) );
				row = (row >> 4) | row & 0x01;

				column = static_cast<char>( (SubstitutionBoxInput & (0x0000780000000000 >> (6 * Counter))) >> (43 - 6 * Counter) );

				SubstitutionBoxOutput <<= 4;
				SubstitutionBoxOutput |= static_cast<std::uint32_t>( SubstitutionBox<true>::PlaneData[Counter][16 * row + column] & 0x0f );
			}

			//The value of PermutationFunctionBox is accessed through the index inside the loop, and then given to Transformed_S_Box
			//The index is 32 subtracted from the value of PermutationFunctionBox already accessed, and the data can be transformed
			//通过循环内部的索引访问P_Box的值，然后给Transformed_S_Box
			//索引是32减去已经访问P_Box的值，就可以对数据进行变换

			std::uint32_t ProcessedCurrentRoundData = 0;
			this->PermuteDataBlocks(SubstitutionBoxOutput, ProcessedCurrentRoundData, 32, PermutationFunctionBox.data(), PermutationFunctionBox.size(), LOW_BIT32_ONE_MASK);

			return ProcessedCurrentRoundData;
		}

		void GenerateSubKeys()
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			//Generate the number of bits to be circular left-shift or circular right-shift for each (16) key rounds
			//Size of left rotation or right rotation per round in each half of the key schedule
			//生成每一轮(16个)密钥要循环左移或循环右移的比特数
			//在密钥计划的每一半中，每轮左旋或右旋的大小

			constexpr std::array<std::uint8_t, 16> BitRotateLeftWithRound
			{
				1, 1, 2, 2, 2, 2, 2, 2,
				1, 2, 2, 2, 2, 2, 2, 1
			};

			constexpr std::array<std::uint8_t, 16> BitRotateRightWithRound
			{
				1, 2, 2, 2, 2, 2, 2, 1,
				2, 2, 2, 2, 2, 2, 1, 1
			};
			
			/* 56 Bits */
			std::uint64_t BinaryKeyNotParityMarker = 0;
			
			/* 48 Bits */
			std::uint64_t GenerateCompressedBinaryKey = 0;

			//通过访问置换选择表1，去掉奇偶标记位，将64位密钥变成56位
			//Select Table 1 by accessing the permutation, removing the parity marker bits and turning the 64-bit key into a 56-bit
			this->PermuteDataBlocks(OriginalKey, BinaryKeyNotParityMarker, 64, KeyParityChoiceTable.data(), KeyParityChoiceTable.size(), LOW_BIT64_ONE_MASK);

			//Split the 56-bit key into the first 28 bits and the last 28 bits
			//将56位密钥分解成为前28位和后28位
			std::uint32_t BinaryKeyHighDigitPart = static_cast<std::uint32_t>( (BinaryKeyNotParityMarker >> 28) & 0x000000000FFFFFFF );
			std::uint32_t BinaryKeyLowDigitPart = static_cast<std::uint32_t>(BinaryKeyNotParityMarker & 0x000000000FFFFFFF);

			/* Calculate the key schedule for 16 rounds */
			/* 计算16个轮回的密钥日程表 */
			for (std::uint32_t RoundNumber = 0; RoundNumber < 16; RoundNumber++)
			{
				/*
					//Circular left shifting
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart << 1) | 0x00000001 & (BinaryKeyHighDigitPart >> 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart << 1) | 0x00000001 & (BinaryKeyLowDigitPart >> 27);

					//Circular right shifting
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart >> 1) | 0x00000001 & (BinaryKeyHighDigitPart << 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart >> 1) | 0x00000001 & (BinaryKeyLowDigitPart << 27);
				*/

				//Perform circular left-shift and circular right-shift for the front and back parts of the 56-bit key (The original version for the key operation are circular left shift, maybe for the key operation are circular right shift?)
				//对56位密钥的前后部分，进行循环左移和循环右移（原版对于密钥的操作都是循环左移，也许可以对于密钥的操作都是循环右移？）
				for(std::uint32_t RoundNumber2 = 0; RoundNumber2 < BitRotateLeftWithRound[RoundNumber]; RoundNumber2++)
				{
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart << 1) | 0x00000001 & (BinaryKeyHighDigitPart >> 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart >> 1) | 0x00000001 & (BinaryKeyLowDigitPart << 27);
				}

				//Concatenation into a 56-bit key
				//组合成56比特位密钥
				BinaryKeyNotParityMarker = ( static_cast<std::uint64_t>(BinaryKeyHighDigitPart) << 28 ) | static_cast<std::uint64_t>(BinaryKeyLowDigitPart);

				this->SubKeyArray.operator[](RoundNumber) = 0;

				//Turn a 56-bit key into a 48-bit key by accessing permutation selection table 2
				//通过访问置换选择表2，将56位密钥变成48位
				this->PermuteDataBlocks(BinaryKeyNotParityMarker, GenerateCompressedBinaryKey, 56, KeyPermutationCompressionChoiceTable.data(), KeyPermutationCompressionChoiceTable.size(), LOW_BIT64_ONE_MASK);

				this->SubKeyArray.operator[](RoundNumber) = GenerateCompressedBinaryKey;
			}
		}

		std::uint64_t Encryption(const std::uint64_t PlainBits)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::uint64_t CurrentBits;

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			this->PermuteDataBlocks(PlainBits, CurrentBits, 64, InitialPermutationTable.data(), InitialPermutationTable.size(), LOW_BIT64_ONE_MASK);

			//Step 2: PlainBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			std::uint32_t BinaryData_LeftBits = static_cast<std::uint32_t>( CurrentBits >> 32 ) & LOW_BIT64_MASK;
			std::uint32_t BinaryData_RightBits = CurrentBits & LOW_BIT64_MASK;

			//Step 3: Total 16 rounds of iterations (Sub-key forward sequential application)
			//共16轮迭代（子密钥正向顺序应用）
			
			for (auto& SubKey : this->SubKeyArray)
			{
				std::uint32_t TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = static_cast<std::uint64_t>(BinaryData_RightBits) << 32 | static_cast<std::uint64_t>(BinaryData_LeftBits);

			std::uint64_t CipherBits;

			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			this->PermuteDataBlocks(CurrentBits, CipherBits, 64, FinalPermutationTable.data(), FinalPermutationTable.size(), LOW_BIT64_ONE_MASK);

			return CipherBits;
		}

		std::uint64_t Decryption(const std::uint64_t CipherBits)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::uint64_t CurrentBits;

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			this->PermuteDataBlocks(CipherBits, CurrentBits, 64, InitialPermutationTable.data(), InitialPermutationTable.size(), LOW_BIT64_ONE_MASK);

			//Step 2: CipherBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			std::uint32_t BinaryData_LeftBits = static_cast<std::uint32_t>( CurrentBits >> 32 ) & LOW_BIT64_MASK;
			std::uint32_t BinaryData_RightBits = CurrentBits & LOW_BIT64_MASK;

			//Step 3: Total 16 rounds of iterations (Sub-key backward sequential application)
			//共16轮迭代（子密钥反向顺序应用）
			for (auto& SubKey : std::ranges::subrange(this->SubKeyArray.rbegin(), this->SubKeyArray.rend()))
			{
				std::uint32_t TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = static_cast<std::uint64_t>(BinaryData_RightBits) << 32 | static_cast<std::uint64_t>(BinaryData_LeftBits);

			std::uint64_t PlainBits;

			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			this->PermuteDataBlocks(CurrentBits, PlainBits, 64, FinalPermutationTable.data(), FinalPermutationTable.size(), LOW_BIT64_ONE_MASK);

			return PlainBits;
		}

	public:

		void UpadateMainKeyOnly(std::uint64_t& Key)
		{
			if(Key != this->RecordOriginalKey)
			{
				this->OriginalKey = Key;
				this->RecordOriginalKey = Key;
			}
		}

		void UpadateSubKeyOnly()
		{
			this->GenerateSubKeys();
		}

		//The update sub-round key by the main-round key
		//通过主轮密钥更新子轮密钥 
		void UpadateMainKeyAndSubKey(std::uint64_t& Key)
		{
			this->UpadateMainKeyOnly(Key);
			this->UpadateSubKeyOnly();
		}

		std::vector<std::uint8_t> DES_Executor
		(
			Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
			const std::vector<std::uint8_t>& dataBlock,
			bool updateSubKey
		)
		{
			std::size_t dataBlockByteSize = dataBlock.size();

			/*
				Data buffer
			*/

			std::uint64_t Bitset64Object_Plain;
			std::uint64_t Bitset64Object_Cipher;

			if(updateSubKey)
			{
				this->UpadateSubKeyOnly();
			}

			my_cpp2020_assert(dataBlockByteSize != 0 && dataBlockByteSize % 8 == 0, "The size of the input data must be a multiple of eight to ensure that the output data is properly sized! ", std::source_location::current());

			CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange memoryDataFormatExchanger;

			if(dataBlockByteSize == std::numeric_limits<std::uint8_t>::digits)
			{
				//Byte array data container size is 64 bits
				if(executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte(dataBlock);
					Bitset64Object_Cipher = this->Encryption(Bitset64Object_Plain);
					auto spanData = memoryDataFormatExchanger.Unpacker_8Byte(Bitset64Object_Cipher);
					return std::vector<std::uint8_t>(spanData.begin(), spanData.end());
				}
				else if (executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					Bitset64Object_Cipher = memoryDataFormatExchanger.Packer_8Byte(dataBlock);
					Bitset64Object_Plain = this->Decryption(Bitset64Object_Cipher);
					auto spanData = memoryDataFormatExchanger.Unpacker_8Byte(Bitset64Object_Plain);
					return std::vector<std::uint8_t>(spanData.begin(), spanData.end());
				}
				else
				{
					std::cout << "Wrong DES DataWorker worker is selected" << std::endl;
					abort();
				}
			}
			else
			{
				//Byte array data container size is not 64 bits

				std::vector<std::uint8_t> processedDataBlock(dataBlock.size(), 0x00);

				my_cpp2020_assert(dataBlock.size() % sizeof(std::uint64_t) == 0, "This data vector size a in't right !", std::source_location::current());

				switch (executeMode)
				{
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
					{
						//For each 8-byte size of data to be processed
						for(std::size_t DataIndex = 0; DataIndex != dataBlock.size(); DataIndex += sizeof(std::uint64_t))
						{
							std::span<const std::uint8_t> byteSpanData0 ( dataBlock.begin() + DataIndex, dataBlock.begin() + DataIndex + sizeof(std::uint64_t) );
							Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte( byteSpanData0 );
							Bitset64Object_Cipher = this->Encryption( Bitset64Object_Plain );
							auto byteSpanData = memoryDataFormatExchanger.Unpacker_8Byte( Bitset64Object_Cipher );
							
							std::ranges::move(byteSpanData.begin(), byteSpanData.end(), processedDataBlock.begin() + DataIndex);
						}

						break;
					}
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
					{
						//For each 8-byte size of data to be processed
						for(std::size_t DataIndex = 0; DataIndex != dataBlock.size(); DataIndex += sizeof(std::uint64_t))
						{
							std::span<const std::uint8_t> byteSpanData0( dataBlock.begin() + DataIndex, dataBlock.begin() + DataIndex + sizeof(std::uint64_t) );
							Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte( byteSpanData0 );
							Bitset64Object_Cipher = this->Decryption( Bitset64Object_Plain );
							auto byteSpanData = memoryDataFormatExchanger.Unpacker_8Byte( Bitset64Object_Cipher );
							
							std::ranges::move(byteSpanData.begin(), byteSpanData.end(), processedDataBlock.begin() + DataIndex);
						}

						break;
					}
					default:
					{
						std::cout << "Wrong DES DataWorker worker is selected" << std::endl;
						abort();
					}
				}

				return processedDataBlock;
			}
		}
	};

	template<>
	class DataWorker<false>
	{

	private:

		#define DES_ALGORITHM_ROL32(word, n)   (((word) << (n)) | ((word) >> (32U - (n))))
		#define DES_ALGORITHM_ROR32(word, n)   (((word) >> (n)) | ((word) << (32U - (n))))
		#define DES_ALGORITHM_ROL28(word, n) ((((word) << (n)) | ((word) >> (28U - (n)))) & 0x0FFFFFFF)
		#define DES_ALGORITHM_ROR28(word, n) ((((word) >> (n)) | ((word) << (28U - (n)))) & 0x0FFFFFFF)

		std::array<std::uint32_t, 32> Subkeys
		{ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };

		//Permutation of bit fields between words (Eric Young's technique)
		//字与字之间的位域互换（Eric Young的技术）
		void CipherDataSwapAndMove
		(
			std::uint32_t& left_data,
			std::uint32_t& right_data,
			const std::uint32_t shift_count,
			const std::uint32_t permutation_constant
		)
		{
			std::uint32_t temporary_value = ( (left_data >> shift_count) ^ right_data ) & permutation_constant;
			right_data ^= temporary_value;
			left_data ^= temporary_value << shift_count;
			temporary_value = 0U;
		}

		//Permuted choice 1
		void KeyParityChoice(std::uint32_t& left_key, std::uint32_t& right_key)
		{
			std::uint32_t temporary_value = 0U;
			this->CipherDataSwapAndMove(left_key, right_key, 4, 0x0F0F0F0F);
			this->CipherDataSwapAndMove(left_key, right_key, 16, 0x0000FFFF);
			this->CipherDataSwapAndMove(right_key, left_key, 2, 0x33333333);
			this->CipherDataSwapAndMove(right_key, left_key, 8, 0x00FF00FF);
			this->CipherDataSwapAndMove(left_key, right_key, 1, 0x55555555);
			this->CipherDataSwapAndMove(right_key, left_key, 8, 0x00FF00FF);
			this->CipherDataSwapAndMove(left_key, right_key, 16, 0x0000FFFF);
			temporary_value = (left_key << 4) & 0x0FFFFFF0;
			temporary_value |= (right_key >> 24) & 0x0000000F;
			left_key = (right_key << 20) & 0x0FF00000;
			left_key |= (right_key << 4) & 0x000FF000;
			left_key |= (right_key >> 12) & 0x00000FF0;
			left_key |= (right_key >> 28) & 0x0000000F;
			right_key = temporary_value;
		}
		
		//Permuted choice 2 (first half)
		std::uint32_t KeyPermutationCompressionChoiceLeft(std::uint32_t left_key, std::uint32_t right_key)
		{
			return ( ( ( left_key << 4 ) & 0x24000000 )
				| ( ( left_key << 28 ) & 0x10000000 )
				| ( ( left_key << 14 ) & 0x08000000 )
				| ( ( left_key << 18 ) & 0x02080000 )
				| ( ( left_key << 6 ) & 0x01000000 )
				| ( ( left_key << 9 ) & 0x00200000 )
				| ( ( left_key >> 1 ) & 0x00100000 )
				| ( ( left_key << 10 ) & 0x00040000 )
				| ( ( left_key << 2 ) & 0x00020000 )
				| ( ( left_key >> 10 ) & 0x00010000 )
				| ( ( right_key >> 13 ) & 0x00002000 )
				| ( ( right_key >> 4 ) & 0x00001000 )
				| ( ( right_key << 6 ) & 0x00000800 )
				| ( ( right_key >> 1 ) & 0x00000400 )
				| ( ( right_key >> 14 ) & 0x00000200 )
				| ( ( right_key >> 0 ) & 0x00000100 )
				| ( ( right_key >> 5 ) & 0x00000020 )
				| ( ( right_key >> 10 ) & 0x00000010 )
				| ( ( right_key >> 3 ) & 0x00000008 )
				| ( ( right_key >> 18 ) & 0x00000004 )
				| ( ( right_key >> 26 ) & 0x00000002 )
				| ( ( right_key >> 24 ) & 0x00000001 ) );
		}

		//Permuted choice 2 (second half)
		std::uint32_t KeyPermutationCompressionChoiceRight(std::uint32_t left_key, std::uint32_t right_key)
		{
			return ( ( ( left_key << 15 ) & 0x20000000 )
				| ( ( left_key << 17 ) & 0x10000000 )
				| ( ( left_key << 10 ) & 0x08000000 )
				| ( ( left_key << 22 ) & 0x04000000 )
				| ( ( left_key >> 2 ) & 0x02000000 )
				| ( ( left_key << 1 ) & 0x01000000 )
				| ( ( left_key << 16 ) & 0x00200000 )
				| ( ( left_key << 11 ) & 0x00100000 )
				| ( ( left_key << 3 ) & 0x00080000 )
				| ( ( left_key >> 6 ) & 0x00040000 )
				| ( ( left_key << 15 ) & 0x00020000 )
				| ( ( left_key >> 4 ) & 0x00010000 )
				| ( ( right_key >> 2 ) & 0x00002000 )
				| ( ( right_key << 8 ) & 0x00001000 )
				| ( ( right_key >> 14 ) & 0x00000808 )
				| ( ( right_key >> 9 ) & 0x00000400 )
				| ( ( right_key >> 0 ) & 0x00000200 )
				| ( ( right_key << 7 ) & 0x00000100 )
				| ( ( right_key >> 7 ) & 0x00000020 )
				| ( ( right_key >> 3 ) & 0x00000011 )
				| ( ( right_key << 2 ) & 0x00000004 )
				| ( ( right_key >> 21 ) & 0x00000002 ) );
		}

		// This is equivalent to the permutation defined by InitialPermutationTable
		void PermuteInitialBlock(std::uint32_t& left_data, std::uint32_t& right_data)
		{
			this->CipherDataSwapAndMove(left_data, right_data, 4U, 0x0f0f0f0fU);
			this->CipherDataSwapAndMove(left_data, right_data, 16U, 0x0000ffffU);
			this->CipherDataSwapAndMove(right_data, left_data, 2U, 0x33333333U);
			this->CipherDataSwapAndMove(right_data, left_data, 8U, 0x00ff00ffU);
			this->CipherDataSwapAndMove(left_data, right_data, 1U, 0x55555555U);
			left_data = DES_ALGORITHM_ROL32(left_data, 1U);
			right_data = DES_ALGORITHM_ROL32(right_data, 1U);
		}

		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ProcessMode>
		/*
			In cryptography, a Feistel cipher (also known as Luby–Rackoff block cipher) is a symmetric structure used in the construction of block ciphers,
			named after the German-born physicist and cryptographer Horst Feistel,
			who did pioneering research while working for IBM; it is also commonly known as a Feistel network.

			A large proportion of block ciphers use the scheme, including the US Data Encryption Standard,the Soviet/Russian GOST and the more recent Blowfish and Twofish ciphers.
				
			In a Feistel cipher, encryption and decryption are very similar operations,
			and both consist of iteratively running a function called a "round function" a fixed number of times.
			https://en.wikipedia.org/wiki/Feistel_cipher

			K[0],K[1],K[2]...,K[n] represent the subkeys, which are used as the input for each round.

			The original data is divided into equal parts on the left and right side, (L[0],R[0])

			The following operation is performed in each round.

			L[i+1] = R[i] 

			R[i+1] = L[i] ⊕ F(R[i] ,K[i])

			The final result of encryption is (R[i+1],L[i+1])

			The decryption process is the reverse order of the encryption process, where each round of decryption performs the following operation.

			R[i] = L[i+1]

			L[i] = R[i+1] ⊕ F(L[i+1],K[i])

			Finally we get our original data (R[0],L[0])

			Theoretical study of Feistel networks:
			Michael Luby and Charles Rackoff proved that if the round function is a cryptographically secure pseudorandom function using Ki as the seed
			Then after three rounds, the generated grouped passwords are already pseudo-randomly arranged.
			A "strong" pseudo-random permutation can be generated after four rounds

			Other uses:
			The Feistel construction is also used in cryptographic algorithms other than block ciphers. 
			For example, the optimal asymmetric encryption padding (OAEP) scheme uses a simple Feistel network to randomize ciphertexts in certain asymmetric-key encryption schemes.

			A generalized Feistel algorithm can be used to create strong permutations on small domains of size not a power of two (see format-preserving encryption).
			https://en.wikipedia.org/wiki/Format-preserving_encryption

			在密码学中，费斯特尔密码（也被称为卢比-拉科夫区块密码）是一种用于构建区块密码的对称结构。
			以德国出生的物理学家和密码学家Horst Feistel命名。
			他在为IBM工作时做了开创性的研究；它也通常被称为Feistel网络。

			很大一部分区块密码都使用该方案，包括美国的数据加密标准、苏联/俄罗斯的GOST以及最近的Blowfish和Twofish密码器。
				
			在费斯特尔密码中，加密和解密是非常相似的操作。
			两者都是由一个被称为 "圆形函数 "的函数迭代运行固定次数组成的。
			
			K[0],K[1],K[2]…,K[n]表示的是子密钥，分别作为各轮的输入。

			原始数据被分成了左右两边相等的部分，(L[0],R[0])

			每一轮都会进行下面的操作：

			L[i+1] = R[i] 

			R[i+1] = L[i]  ⊕ F(R[i] ,K[i])

			最后的加密出的结果就是(R[i+1],L[i+1])

			解密的过程是加密过程的逆序，每一轮解密都会进行下面的操作：

			R[i] = L[i+1]

			L[i] = R[i+1] ⊕ F(L[i+1],K[i])

			最终得到我们的原始数据(R[0],L[0])

			Feistel网络的理论研究:
			Michael Luby 和 Charles Rackoff 证明了如果轮函数是使用Ki为种子的密码安全的伪随机函数
			那么经过三轮操作之后，生成的分组密码就已经是伪随机排列了。
			经过四轮操作可以生成“强”伪随机排列。

			其他用途
			Feistel结构也被用于除区块密码之外的加密算法中。 
			例如，最佳非对称加密填充（OAEP）方案使用一个简单的Feistel网络来随机化某些非对称密钥加密方案中的密码文本。

			一个广义的Feistel算法可以用来在大小不是二的幂的小域上创建强的互换（见格式保护加密）。
		*/
		void FeistelTransform
		(
			std::uint32_t& left_data, std::uint32_t& right_data
		)
		{
			// DES Feistel Structure Transform Function
			
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;
			using CommonSecurity::TripleDES::DefineConstants::FeistelBox;

			//16 rounds of computation are needed

			if constexpr(ProcessMode == CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
			{
				std::uint32_t _left_data_ = left_data;
				std::uint32_t _right_data_ = right_data;

				std::uint32_t temporary_value = 0U;

				//For encryption, keys in the key schedule must be applied in Positive index order
				for(std::uint32_t subkey_index = 0; subkey_index < 32; subkey_index += 4U)
				{
					//Apply odd round function
					temporary_value = _right_data_ ^ this->Subkeys[subkey_index + 0U];
					_left_data_ ^= FeistelBox[1][(temporary_value >> 24U) & 0x3f];
					_left_data_ ^= FeistelBox[3][(temporary_value >> 16U) & 0x3f];
					_left_data_ ^= FeistelBox[5][(temporary_value >> 8U) & 0x3f];
					_left_data_ ^= FeistelBox[7][(temporary_value) & 0x3f];

					temporary_value = DES_ALGORITHM_ROR32(_right_data_, 4U) ^ this->Subkeys[subkey_index + 1U];
					_left_data_ ^= FeistelBox[0][(temporary_value >> 24U) & 0x3f];
					_left_data_ ^= FeistelBox[2][(temporary_value >> 16U) & 0x3f];
					_left_data_ ^= FeistelBox[4][(temporary_value >> 8U) & 0x3f];
					_left_data_ ^= FeistelBox[6][(temporary_value) & 0x3f];

					//Apply even round function
					temporary_value = _left_data_ ^ this->Subkeys[subkey_index + 2U];
					_right_data_ ^= FeistelBox[1][(temporary_value >> 24U) & 0x3f];
					_right_data_ ^= FeistelBox[3][(temporary_value >> 16U) & 0x3f];
					_right_data_ ^= FeistelBox[5][(temporary_value >> 8U) & 0x3f];
					_right_data_ ^= FeistelBox[7][(temporary_value) & 0x3f];

					temporary_value = DES_ALGORITHM_ROR32(_left_data_, 4U) ^ this->Subkeys[subkey_index + 3U];
					_right_data_ ^= FeistelBox[0][(temporary_value >> 24U) & 0x3f];
					_right_data_ ^= FeistelBox[2][(temporary_value >> 16U) & 0x3f];
					_right_data_ ^= FeistelBox[4][(temporary_value >> 8U) & 0x3f];
					_right_data_ ^= FeistelBox[6][(temporary_value) & 0x3f];
				}

				left_data = _left_data_;
				right_data = _right_data_;

				temporary_value = 0U;
				_left_data_ = 0U;
				_right_data_ = 0U;
			}
			else if constexpr(ProcessMode == CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
			{
				std::uint32_t _left_data_ = left_data;
				std::uint32_t _right_data_ = right_data;

				std::uint32_t temporary_value = 0U;

				//For decryption, keys in the key schedule must be applied in Inverse index order
				for(std::uint32_t subkey_index = 32; subkey_index > 0; subkey_index -= 4U)
				{
					//Apply even round function
					temporary_value = DES_ALGORITHM_ROR32(_left_data_, 4U) ^ this->Subkeys[subkey_index - 1U];
					_right_data_ ^= FeistelBox[6][(temporary_value) & 0x3f];
					_right_data_ ^= FeistelBox[4][(temporary_value >> 8U) & 0x3f];
					_right_data_ ^= FeistelBox[2][(temporary_value >> 16U) & 0x3f];
					_right_data_ ^= FeistelBox[0][(temporary_value >> 24U) & 0x3f];

					temporary_value = _left_data_ ^ this->Subkeys[subkey_index - 2U];
					_right_data_ ^= FeistelBox[7][(temporary_value) & 0x3f];
					_right_data_ ^= FeistelBox[5][(temporary_value >> 8U) & 0x3f];
					_right_data_ ^= FeistelBox[3][(temporary_value >> 16U) & 0x3f];
					_right_data_ ^= FeistelBox[1][(temporary_value >> 24U) & 0x3f];

					//Apply odd round function
					temporary_value = DES_ALGORITHM_ROR32(_right_data_, 4U) ^ this->Subkeys[subkey_index - 3U];
					_left_data_ ^= FeistelBox[6][(temporary_value) & 0x3f];
					_left_data_ ^= FeistelBox[4][(temporary_value >> 8U) & 0x3f];
					_left_data_ ^= FeistelBox[2][(temporary_value >> 16U) & 0x3f];
					_left_data_ ^= FeistelBox[0][(temporary_value >> 24U) & 0x3f];

					temporary_value = _right_data_ ^ this->Subkeys[subkey_index - 4U];
					_left_data_ ^= FeistelBox[7][(temporary_value) & 0x3f];
					_left_data_ ^= FeistelBox[5][(temporary_value >> 8U) & 0x3f];
					_left_data_ ^= FeistelBox[3][(temporary_value >> 16U) & 0x3f];
					_left_data_ ^= FeistelBox[1][(temporary_value >> 24U) & 0x3f];
				}

				left_data = _left_data_;
				right_data = _right_data_;

				temporary_value = 0U;
				_left_data_ = 0U;
				_right_data_ = 0U;
			}
			else
			{
				static_assert(CommonToolkit::Dependent_Always_Failed<ProcessMode>,"");
			}
		}

		// This is equivalent to the permutation defined by FinalPermutationTable
		void PermuteFinalBlock(std::uint32_t& left_data, std::uint32_t& right_data)
		{
			left_data = DES_ALGORITHM_ROR32(left_data, 1U);
			right_data = DES_ALGORITHM_ROR32(right_data, 1U);
			this->CipherDataSwapAndMove(left_data, right_data, 1U, 0x55555555U);
			this->CipherDataSwapAndMove(right_data, left_data, 8U, 0x00ff00ffU);
			this->CipherDataSwapAndMove(right_data, left_data, 2U, 0x33333333U);
			this->CipherDataSwapAndMove(left_data, right_data, 16U, 0x0000ffffU);
			this->CipherDataSwapAndMove(left_data, right_data, 4U, 0x0f0f0f0fU);
		}

	public:

		static constexpr std::uint32_t BlockByteSize = 8;

		// Generate 16 subkeys of 56 bit words from the original byte key
		// 从原始字节密钥中生成16个56位的子密钥
		void GenerateSubkeys(std::span<const std::uint8_t> bytes_key)
		{
			using CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange;
			using CommonSecurity::TripleDES::DefineConstants::PermuteBlock;

			my_cpp2020_assert(bytes_key.size() == BlockByteSize, "CommonSecurity::TripleDES::TripleDES : The size of the bytes key is not valid!", std::source_location::current());

			MemoryDataFormatExchange memory_data_format_exchanger;
			std::uint32_t left_key = memory_data_format_exchanger.Packer_4Byte(bytes_key.subspan(0, sizeof(std::uint32_t)));
			std::uint32_t right_key = memory_data_format_exchanger.Packer_4Byte(bytes_key.subspan(4, sizeof(std::uint32_t)));

			// Apply PC1 permutation table to key
			this->KeyParityChoice(left_key, right_key);

			// Generate subkeys using the key schedule
			// 用密钥计划安排生成子密钥
			for (std::uint32_t round = 0; round < 16; round++)
			{
				if(round == 0 || round == 1 || round == 8 || round == 15)
				{
					#if 1

					// 28-bit circular left shift
					left_key = DES_ALGORITHM_ROL28(left_key, 1);
					right_key = DES_ALGORITHM_ROL28(right_key, 1);

					#else

					// 28-bit circular right shift
			
					left_key = DES_ALGORITHM_ROR28(left_key, 1);
					right_key = DES_ALGORITHM_ROR28(right_key, 1);

					#endif
				}
				else
				{
					#if 1

					// 28-bit circular left shift
					left_key = DES_ALGORITHM_ROL28(left_key, 2);
					right_key = DES_ALGORITHM_ROL28(right_key, 2);

					#else

					// 28-bit circular right shift
			
					left_key = DES_ALGORITHM_ROR28(left_key, 2);
					right_key = DES_ALGORITHM_ROR28(right_key, 2);

					#endif
				}

				// Apply PC2 permutation table to subkey
				this->Subkeys[2 * round] = this->KeyPermutationCompressionChoiceLeft(left_key, right_key);
				this->Subkeys[2 * round + 1] = this->KeyPermutationCompressionChoiceRight(left_key, right_key);
			}
		}

		// Process one data chunk at a time (The size is 8 bytes)
		// 每次处理一个数据分块(大小为8个字节)
		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ProcessMode>
		void ProcessDataBlock
		(
			std::span<const std::uint8_t> source_bytes_data,
			std::span<std::uint8_t> destination_byte_data
		)
		{
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;
			using CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange;

			my_cpp2020_assert(source_bytes_data.size() == BlockByteSize, "CommonSecurity::TripleDES::DataWorker : The size of the bytes source data is not valid!", std::source_location::current());
			my_cpp2020_assert(destination_byte_data.size() == BlockByteSize, "CommonSecurity::TripleDES::DataWorker : The size of the bytes destination data is not valid!", std::source_location::current());

			MemoryDataFormatExchange memory_data_format_exchanger;

			if constexpr(ProcessMode == CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
			{
				std::uint32_t left_data_block = memory_data_format_exchanger.Packer_4Byte(source_bytes_data.subspan(0, sizeof(std::uint32_t)));
				std::uint32_t right_data_block = memory_data_format_exchanger.Packer_4Byte(source_bytes_data.subspan(4, sizeof(std::uint32_t)));

				//Initial permutation
				this->PermuteInitialBlock(left_data_block, right_data_block);

				//When calling this FeistelTransform function, use the two 32-bit word data, please do not arbitrarily swap the order of their function parameters, because which can cause a huge data change.
				//当调用这个FeistelTransform函数时，使用两个32位字的数据，请不要任意调换其函数参数的顺序，因为这样会造成巨大的数据变化。
				this->FeistelTransform<ProcessMode>(left_data_block, right_data_block);

				//Inverse of initial permutation
				this->PermuteFinalBlock(right_data_block, left_data_block);

				auto processed_bytes_span = memory_data_format_exchanger.Unpacker_4Byte(right_data_block);
				std::memmove(destination_byte_data.data(), processed_bytes_span.data(), processed_bytes_span.size());
				auto processed_bytes_span2 = memory_data_format_exchanger.Unpacker_4Byte(left_data_block);
				std::memmove(destination_byte_data.data() + 4, processed_bytes_span2.data(), processed_bytes_span2.size());
			}
			else if constexpr(ProcessMode == CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
			{
				std::uint32_t right_data_block = memory_data_format_exchanger.Packer_4Byte(source_bytes_data.subspan(0, sizeof(std::uint32_t)));
				std::uint32_t left_data_block = memory_data_format_exchanger.Packer_4Byte(source_bytes_data.subspan(4, sizeof(std::uint32_t)));

				//Initial permutation
				this->PermuteInitialBlock(right_data_block, left_data_block);
				
				//When calling this FeistelTransform function, use the two 32-bit word data, please do not arbitrarily swap the order of their function parameters, because which can cause a huge data change.
				//当调用这个FeistelTransform函数时，使用两个32位字的数据，请不要任意调换其函数参数的顺序，因为这样会造成巨大的数据变化。
				this->FeistelTransform<ProcessMode>(left_data_block, right_data_block);

				//Inverse of initial permutation
				this->PermuteFinalBlock(left_data_block, right_data_block);

				auto processed_bytes_span = memory_data_format_exchanger.Unpacker_4Byte(left_data_block);
				std::memmove(destination_byte_data.data(), processed_bytes_span.data(), processed_bytes_span.size());
				auto processed_bytes_span2 = memory_data_format_exchanger.Unpacker_4Byte(right_data_block);
				std::memmove(destination_byte_data.data() + 4, processed_bytes_span2.data(), processed_bytes_span2.size());
			}
			else
			{
				static_assert(CommonToolkit::Dependent_Always_Failed<ProcessMode>,"");
			}
		}

		DataWorker() = default;

		~DataWorker()
		{
			memory_set_no_optimize_function<0x00>(this->Subkeys.data(), this->Subkeys.size() * sizeof(std::uint32_t));
		}

		#undef DES_ALGORITHM_ROL32
		#undef DES_ALGORITHM_ROR32
		#undef DES_ALGORITHM_ROL28
		#undef DES_ALGORITHM_ROR28
	};

	template<bool Experimental>
	struct TripleDES;

	template<>
	struct TripleDES<true>
	{
		DataWorker<true> DES_Worker, DES_Worker2, DES_Worker3;
	};

	template<>
	struct TripleDES<false>
	{
		DataWorker<false> DES_Worker, DES_Worker2, DES_Worker3;

		void GenerateSubkeys(std::span<const std::uint8_t> bytes_key)
		{
			//Check key length
			if(bytes_key.size() == 8)
			{
			   //This option provides backward compatibility with DES, because the
			   //first and second DES operations cancel out
			   DES_Worker.GenerateSubkeys( bytes_key );
			   DES_Worker2.GenerateSubkeys( bytes_key );
			   DES_Worker3.GenerateSubkeys( bytes_key );
			}
			else if(bytes_key.size() == 16)
			{
			   //If the key length is 128 bits including parity, the first 8 bytes of the
			   //encoding represent the key used for the two outer DES operations, and
			   //the second 8 bytes represent the key used for the inner DES operation
			   DES_Worker.GenerateSubkeys( bytes_key.subspan(0, sizeof(std::uint64_t)) );
			   DES_Worker2.GenerateSubkeys( bytes_key.subspan(8, sizeof(std::uint64_t)) );
			   DES_Worker3.GenerateSubkeys( bytes_key.subspan(0, sizeof(std::uint64_t)) );
			}
			else if(bytes_key.size() == 24)
			{
			   //If the key length is 192 bits including parity, then 3 independent DES
			   //keys are represented, in the order in which they are used for encryption
			   DES_Worker.GenerateSubkeys( bytes_key.subspan(0, sizeof(std::uint64_t)) );
			   DES_Worker2.GenerateSubkeys( bytes_key.subspan(8, sizeof(std::uint64_t)) );
			   DES_Worker3.GenerateSubkeys( bytes_key.subspan(16, sizeof(std::uint64_t)) );
			}
			else
			{
			   my_cpp2020_assert(false, "CommonSecurity::TripleDES::TripleDES : The size of the bytes key is not valid!", std::source_location::current());
			}
		}

		void BlockEncryption
		(
			std::span<const std::uint8_t> source_bytes_data,
			std::span<std::uint8_t> destination_byte_data
		)
		{
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

			//The first pass is a DES encryption
			DES_Worker.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(source_bytes_data, destination_byte_data);
			//The second pass is a DES decryption of the first ciphertext result
			DES_Worker2.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(destination_byte_data, destination_byte_data);
			//The third pass is a DES encryption of the second pass result
			DES_Worker3.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(destination_byte_data, destination_byte_data);
		}

		void BlockDecryption
		(
			std::span<const std::uint8_t> source_bytes_data,
			std::span<std::uint8_t> destination_byte_data
		)
		{
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

			//The first pass is a DES decryption
			DES_Worker3.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(source_bytes_data, destination_byte_data);
			//The second pass is a DES encryption of the first pass result
			DES_Worker2.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(destination_byte_data, destination_byte_data);
			//The third pass is a DES decryption of the second ciphertext result
			DES_Worker.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(destination_byte_data, destination_byte_data);
		}
	};
}

namespace CommonSecurity::RC6::DefineConstants
{
	inline constexpr std::uint32_t RC6_KeyBitSize_MaxLimit = 255 * std::numeric_limits<std::uint8_t>::digits;

	/*
	
	double Number_GoldenRatio 0.618033988749895 = 1 / ((1 + std::sqrt(5)) / 2) is 1 / 1.618033988749895;
	(std::numbers::phi == 1 / 0.618033988749895) is true
	(0.618033988749895 == 1 / std::numbers::phi) is true
	where Φ is the golden ratio constant
	
	*/
	inline constexpr double Number_GoldenRatio = std::numbers::phi - 1;

	/*
	
	double Number_BaseOfTheNaturalLogarithm = sum( 1/(factorial(items_number)) + 1/(factorial(items_number - 1 )) + 1/(factorial(items_number - 2)) ..... + 1/(factorial(1)) + 1/(factorial(0)) ) is 2.718281828459045
	If items_number approaches infinity, hen it is the limit of (1 + 1/items_number)^items_number
	where e is the base of natural logarithm function
	
	*/
	inline constexpr double Number_BaseOfTheNaturalLogarithm = std::numbers::e;
}

namespace CommonSecurity::RC6::ProcedureFunctions
{
	#if 0

	//Rotate the w-bit word a(source_value) to the left by the amount given by the least significant log w bits of b(offset_value)
	//将w位的字a(source_value)向左旋转，旋转量由b(offset_value)的最小有效对数w位给出。
	inline std::uint32_t LeftRotateBit(std::uint32_t source_value, std::uint32_t offset_value, const std::uint32_t word_bit_size = 32, const std::uint32_t log2_word_bit_size = RC6::DefineConstants::LSB_32_Value)
	{
		std::uint32_t mask = 0xFFFFFFFF >> (word_bit_size - log2_word_bit_size);
		offset_value &= mask;
		std::uint32_t value = (source_value << offset_value) | (source_value >> (word_bit_size - offset_value));
		return value;
	}

	//Rotate the w-bit word a(source_value) to the right by the amount given by the least significant log w bits of b(offset(source_value)
	//将w位的字a(source_value)向右旋转，旋转量由b(offset_value)的最小有效对数w位给出。
	inline std::uint32_t RightRotateBit(std::uint32_t source_value, std::uint32_t offset_value, const std::uint32_t word_bit_size = 32, const std::uint32_t log2_word_bit_size = RC6::DefineConstants::LSB_32_Value)
	{
		std::uint32_t mask = 0xFFFFFFFF >> (word_bit_size - log2_word_bit_size);
		offset_value &= mask;
		std::uint32_t value = (source_value >> offset_value) | (source_value << (word_bit_size - offset_value));
		return value;
	}

	#endif

	/**
	 * Rotate a N-bit value left
	 * @param word: value to rotate
	 * @param shift: bits to roll
	 */
	template<class Type>
	inline Type LeftRotateBit(Type word, int shift)
	{
		return (word << shift) | (word >> (std::numeric_limits<Type>::digits - shift));
	}

	/**
	 * Rotate a N-bit value right
	 * @param word: value to rotate
	 * @param shift: bits to roll
	 */
	template<class Type>
	inline Type RightRotateBit(Type word, int shift)
	{
		return (word >> shift) | (word << (std::numeric_limits<Type>::digits - shift));
	}
}

namespace CommonSecurity::ChinaShangYongMiMa4::DefineConstants
{
	inline constexpr std::array<std::uint8_t, 256> Subtitute_ByteBox
	{
		0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
	};

	//用于支持每轮密钥生成的常量字
	//Constant words used to support each round of key generation
	inline constexpr std::array<std::uint32_t, 32> ConstentWords
	{
		0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
	};

	//用于支持密钥生成的系统功能参数字
	//System function argument words used to support key generation
	inline constexpr std::array<std::uint32_t, 4> SystemWords
	{
		0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
	};

	//Reference chinese paper: http://html.rhhz.net/ZGKXYDXXB/20180205.htm
	//Reference source code: https://github.com/Jemtaly/CryptoXX/blob/main/Cipher/sm4.hpp

	#if 0

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateMixDataTransformedWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		for(std::uint32_t Index = 0, Round = 0; Index < 256 && Round < 256; Index++, ++Round)
		{
			//Tau_NonlinearTransform Function

			std::uint32_t ByteA = Subtitute_ByteBox[Index];
			std::uint32_t ByteB = Subtitute_ByteBox[Index];
			std::uint32_t ByteC = Subtitute_ByteBox[Index];
			std::uint32_t ByteD = Subtitute_ByteBox[Index];
			
			std::uint32_t WordA = ByteA << 24;
			std::uint32_t WordB = ByteB << 16;
			std::uint32_t WordC = ByteC << 8;
			std::uint32_t WordD = ByteD;

			//T0 - LinearTransform0 Function
			WordA = WordA
				^ std::rotl(WordA, static_cast<std::uint32_t>(2))
				^ std::rotl(WordA, static_cast<std::uint32_t>(10))
				^ std::rotl(WordA, static_cast<std::uint32_t>(18))
				^ std::rotl(WordA, static_cast<std::uint32_t>(24));

			//T1 - LinearTransform0 Function
			WordB = WordB
				^ std::rotl(WordB, static_cast<std::uint32_t>(2))
				^ std::rotl(WordB, static_cast<std::uint32_t>(10))
				^ std::rotl(WordB, static_cast<std::uint32_t>(18))
				^ std::rotl(WordB, static_cast<std::uint32_t>(24));

			//T2 - LinearTransform0 Function
			WordC = WordC
				^ std::rotl(WordC, static_cast<std::uint32_t>(2))
				^ std::rotl(WordC, static_cast<std::uint32_t>(10))
				^ std::rotl(WordC, static_cast<std::uint32_t>(18))
				^ std::rotl(WordC, static_cast<std::uint32_t>(24));

			//T3 - LinearTransform0 Function
			WordD = WordD
				^ std::rotl(WordD, static_cast<std::uint32_t>(2))
				^ std::rotl(WordD, static_cast<std::uint32_t>(10))
				^ std::rotl(WordD, static_cast<std::uint32_t>(18))
				^ std::rotl(WordD, static_cast<std::uint32_t>(24));

			if(ProcessBlockTable[3][Round] != WordA)
				ProcessBlockTable[3][Round] = WordA;

			if(ProcessBlockTable[2][Round] != WordB)
				ProcessBlockTable[2][Round] = WordB;

			if(ProcessBlockTable[1][Round] != WordC)
				ProcessBlockTable[1][Round] = WordC;

			if(ProcessBlockTable[0][Round] != WordD)
				ProcessBlockTable[0][Round] = WordD;
		}

		return ProcessBlockTable;
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateMixKeyTransformedWordTable()
	{
		for(std::uint32_t Index = 0, Round = 0; Index < 256 && Round < 256; Index++, ++Round)
		{
			//Tau_NonlinearTransform Function

			std::uint32_t ByteA = Subtitute_ByteBox[Index];
			std::uint32_t ByteB = Subtitute_ByteBox[Index];
			std::uint32_t ByteC = Subtitute_ByteBox[Index];
			std::uint32_t ByteD = Subtitute_ByteBox[Index];
			
			std::uint32_t WordA = ByteA << 24;
			std::uint32_t WordB = ByteB << 16;
			std::uint32_t WordC = ByteC << 8;
			std::uint32_t WordD = ByteD;

			//T0 - LinearTransform1 Function
			WordA = WordA
				^ std::rotl(WordA, static_cast<std::uint32_t>(13))
				^ std::rotl(WordA, static_cast<std::uint32_t>(23));

			//T1 - LinearTransform1 Function
			WordB = WordB
				^ std::rotl(WordB, static_cast<std::uint32_t>(13))
				^ std::rotl(WordB, static_cast<std::uint32_t>(23));

			//T2 - LinearTransform1 Function
			WordC = WordC
				^ std::rotl(WordC, static_cast<std::uint32_t>(13))
				^ std::rotl(WordC, static_cast<std::uint32_t>(23));

			//T3 - LinearTransform1 Function
			WordD = WordD
				^ std::rotl(WordD, static_cast<std::uint32_t>(13))
				^ std::rotl(WordD, static_cast<std::uint32_t>(23));

			if(ProcessBlockTable[3][Round] != WordA)
				ProcessBlockTable[3][Round] = WordA;

			if(ProcessBlockTable[2][Round] != WordB)
				ProcessBlockTable[2][Round] = WordB;

			if(ProcessBlockTable[1][Round] != WordC)
				ProcessBlockTable[1][Round] = WordC;

			if(ProcessBlockTable[0][Round] != WordD)
				ProcessBlockTable[0][Round] = WordD;
		}
	}

	#else

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateMixDataTransformedWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		std::uint32_t Round = 0;

		constexpr std::uint32_t ByteBits = std::numeric_limits<std::uint8_t>::digits;
		constexpr std::uint32_t WordBits = std::numeric_limits<std::uint32_t>::digits;
		
		//T3
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform1 Function

			std::uint32_t Word = Byte ^ Byte << 2 ^ Byte << 10 ^ Byte << 18 ^ Byte << 24;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T2
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform1 Function

			std::uint32_t Word = Byte ^ Byte << 2 ^ Byte << 10 ^ Byte << 18 ^ Byte << 24;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T1
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform1 Function

			std::uint32_t Word = Byte ^ Byte << 2 ^ Byte << 10 ^ Byte << 18 ^ Byte << 24;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T0
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform1 Function

			std::uint32_t Word = Byte ^ Byte << 2 ^ Byte << 10 ^ Byte << 18 ^ Byte << 24;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		return ProcessBlockTable;
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateMixKeyTransformedWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		std::uint32_t Round = 0;

		constexpr std::uint32_t ByteBits = std::numeric_limits<std::uint8_t>::digits;
		constexpr std::uint32_t WordBits = std::numeric_limits<std::uint32_t>::digits;

		//T3
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform0 Function

			std::uint32_t Word = Byte ^ Byte << 13 ^ Byte << 23;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T2
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform0 Function

			std::uint32_t Word = Byte ^ Byte << 13 ^ Byte << 23;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T1
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform0 Function

			std::uint32_t Word = Byte ^ Byte << 13 ^ Byte << 23;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T0
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform0 Function

			std::uint32_t Word = Byte ^ Byte << 13 ^ Byte << 23;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		return ProcessBlockTable;
	}

	#endif
}

namespace CommonSecurity::ChinaShangYongMiMa4::ProcedureFunctions
{
	class ExperimentalAlgorithm
	{
	
	private:

		std::array<std::uint32_t, 32> EachRoundKeyWords {};

		static constexpr std::array<std::array<std::uint8_t, 16>, 16> Subtitute_ByteBoxMatrix
		{
			{
				{0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
				{0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
				{0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
				{0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
				{0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
				{0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
				{0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
				{0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
				{0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
				{0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
				{0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
				{0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
				{0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
				{0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
				{0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
				{0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
			}
		};

		std::uint32_t Tau_NonlinearFunction(std::uint32_t Word)
		{
			std::array<std::uint8_t, 4> Bytes{ 0, 0, 0, 0 };
			std::uint32_t ChangedWord = 0;

			for (std::uint32_t Index = 0; Index < 4; Index++)
			{
				Bytes[Index] = Word >> (24 - Index * std::numeric_limits<std::uint8_t>::digits);
				Bytes[Index] = Subtitute_ByteBoxMatrix[Bytes[Index] >> 4][Bytes[Index] & 0x0f];
				ChangedWord |= Bytes[Index] << (24 - Index * std::numeric_limits<std::uint8_t>::digits);
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(Bytes.data(), sizeof(std::uint32_t));
			my_cpp2020_assert(CheckPointer == Bytes.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			return ChangedWord;
		}

		//For Data Round Function
		std::uint32_t LinearFunction0(std::uint32_t Word)
		{
			return Word
				^ std::rotl(Word, static_cast<std::uint32_t>(2))
				^ std::rotl(Word, static_cast<std::uint32_t>(10))
				^ std::rotl(Word, static_cast<std::uint32_t>(18))
				^ std::rotl(Word, static_cast<std::uint32_t>(24));
		}

		//For Key Expansion Function
		std::uint32_t LinearFunction1(std::uint32_t Word)
		{
			return Word
				^ std::rotl(Word, static_cast<std::uint32_t>(13))
				^ std::rotl(Word, static_cast<std::uint32_t>(23));
		}

		std::uint32_t MixerTransform0(std::uint32_t Word)
		{
			return LinearFunction0( Tau_NonlinearFunction(Word) );
		}

		std::uint32_t MixerTransform1(std::uint32_t Word)
		{
			return LinearFunction1( Tau_NonlinearFunction(Word) );
		}

		std::uint32_t EndianConvert(std::uint32_t Word)
		{
			return ((Word << 24) & 0xff000000)
				| ((Word << 8) & 0x00ff0000)
				| ((Word >> 8) & 0x0000ff00)
				| ((Word >> 24) & 0x000000ff);
		}

	public:

		static constexpr std::uint32_t Number_Block_Data_Byte_Size = 16;

		void KeyExpansion
		(
			std::span<const std::uint8_t> KeyByteData
		)
		{
			using DefineConstants::ConstentWords;
			using DefineConstants::SystemWords;

			my_cpp2020_assert(KeyByteData.size() == Number_Block_Data_Byte_Size, "CommonSecurity::ChinaShangYongMiMa4::DataWorker : The size of the key byte array is invalid!", std::source_location::current());

			std::array<std::uint32_t, 4> MasterKeyWords {};
			std::array<std::uint32_t, 36> TemporaryIterationKeyWords {};

			MasterKeyWords[0] = static_cast<std::uint32_t>(KeyByteData[0] << 24)
				| static_cast<std::uint32_t>(KeyByteData[1] << 16)
				| static_cast<std::uint32_t>(KeyByteData[2] << 8)
				| static_cast<std::uint32_t>(KeyByteData[3]);
			MasterKeyWords[1] = static_cast<std::uint32_t>(KeyByteData[4] << 24)
				| static_cast<std::uint32_t>(KeyByteData[5] << 16)
				| static_cast<std::uint32_t>(KeyByteData[6] << 8)
				| static_cast<std::uint32_t>(KeyByteData[7]);
			MasterKeyWords[2] = static_cast<std::uint32_t>(KeyByteData[8] << 24)
				| static_cast<std::uint32_t>(KeyByteData[9] << 16)
				| static_cast<std::uint32_t>(KeyByteData[10] << 8)
				| static_cast<std::uint32_t>(KeyByteData[11]);
			MasterKeyWords[3] = static_cast<std::uint32_t>(KeyByteData[12] << 24)
				| static_cast<std::uint32_t>(KeyByteData[13] << 16)
				| static_cast<std::uint32_t>(KeyByteData[14] << 8)
				| static_cast<std::uint32_t>(KeyByteData[15]);

			TemporaryIterationKeyWords[0] = MasterKeyWords[0] ^ SystemWords[0];
			TemporaryIterationKeyWords[1] = MasterKeyWords[1] ^ SystemWords[1];
			TemporaryIterationKeyWords[2] = MasterKeyWords[2] ^ SystemWords[2];
			TemporaryIterationKeyWords[3] = MasterKeyWords[3] ^ SystemWords[3];

			for(std::size_t Index = 0; Index < 32; ++Index)
			{
				//Apply SM4 Key Expand Core Function And Update Round Key
				EachRoundKeyWords[Index] = TemporaryIterationKeyWords[Index + 4] = TemporaryIterationKeyWords[Index]
					^ MixerTransform1( TemporaryIterationKeyWords[Index + 1] ^ TemporaryIterationKeyWords[Index + 2] ^ TemporaryIterationKeyWords[Index + 3] ^ ConstentWords[Index] );
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(MasterKeyWords.data(), sizeof(std::uint32_t) * MasterKeyWords.size());
			my_cpp2020_assert(CheckPointer == MasterKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(TemporaryIterationKeyWords.data(), sizeof(std::uint32_t) * TemporaryIterationKeyWords.size());
			my_cpp2020_assert(CheckPointer == TemporaryIterationKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ExecuteMode>
		void RoundFunction
		(
			std::span<std::uint8_t> OriginalByteData
		)
		{
			my_cpp2020_assert(OriginalByteData.size_bytes() == Number_Block_Data_Byte_Size, "CommonSecurity::ChinaShangYongMiMa4::DataWorker : The size of the data byte array is invalid!", std::source_location::current());

			std::array<std::uint32_t, 36> TemporaryIterationDataWords {};
			std::array<std::uint32_t, 4> ProcessBuffer {};

			std::memmove(ProcessBuffer.data(), OriginalByteData.data(), Number_Block_Data_Byte_Size);

			TemporaryIterationDataWords[0] = this->EndianConvert(ProcessBuffer[0]);
			TemporaryIterationDataWords[1] = this->EndianConvert(ProcessBuffer[1]);
			TemporaryIterationDataWords[2] = this->EndianConvert(ProcessBuffer[2]);
			TemporaryIterationDataWords[3] = this->EndianConvert(ProcessBuffer[3]);

			for(std::uint32_t Index = 0, KeyIndex = 0; Index < 32; ++Index)
			{
				if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
					KeyIndex = Index;
				else if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
					KeyIndex = 31 - Index;
				else
					break;

				//Apply SM4 Data Process Core Function And Update Round Data
				TemporaryIterationDataWords[Index + 4] = TemporaryIterationDataWords[Index]
					^ MixerTransform0(TemporaryIterationDataWords[Index + 1] ^ TemporaryIterationDataWords[Index + 2] ^ TemporaryIterationDataWords[Index + 3] ^ this->EachRoundKeyWords[KeyIndex]);
			}

			ProcessBuffer[0] = this->EndianConvert(TemporaryIterationDataWords[35]);
			ProcessBuffer[1] = this->EndianConvert(TemporaryIterationDataWords[34]);
			ProcessBuffer[2] = this->EndianConvert(TemporaryIterationDataWords[33]);
			ProcessBuffer[3] = this->EndianConvert(TemporaryIterationDataWords[32]);

			std::memmove(OriginalByteData.data(), ProcessBuffer.data(), Number_Block_Data_Byte_Size);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(TemporaryIterationDataWords.data(), sizeof(std::uint32_t) * TemporaryIterationDataWords.size());
			my_cpp2020_assert(CheckPointer == TemporaryIterationDataWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(ProcessBuffer.data(), sizeof(std::uint32_t) * ProcessBuffer.size());
			my_cpp2020_assert(CheckPointer == ProcessBuffer.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		ExperimentalAlgorithm() = default;

		~ExperimentalAlgorithm()
		{
			volatile void* CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>(EachRoundKeyWords.data(), sizeof(std::uint32_t) * EachRoundKeyWords.size());
			my_cpp2020_assert(CheckPointer == EachRoundKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}
	};

	class OfficialAlgorithm
	{
		
	private:

		std::array<std::uint32_t, 32> EachRoundKeyWords {};

		//For Data Round Function
		static constexpr std::array<std::array<std::uint32_t, 256>, 4> MixDataTransformedWordTable = DefineConstants::GenerateMixDataTransformedWordTable();

		//For Key Expansion Function
		static constexpr std::array<std::array<std::uint32_t, 256>, 4> MixKeyTransformedWordTable = DefineConstants::GenerateMixKeyTransformedWordTable();

		std::uint32_t EndianConvert(std::uint32_t Word)
		{
			return ((Word << 24) & 0xff000000)
				| ((Word << 8) & 0x00ff0000)
				| ((Word >> 8) & 0x0000ff00)
				| ((Word >> 24) & 0x000000ff);
		}

	public:

		static constexpr std::uint32_t Number_Block_Data_Byte_Size = 16;

		void KeyExpansion
		(
			std::span<const std::uint8_t> KeyByteData
		)
		{
			using DefineConstants::ConstentWords;
			using DefineConstants::SystemWords;

			my_cpp2020_assert(KeyByteData.size() == Number_Block_Data_Byte_Size, "CommonSecurity::ChinaShangYongMiMa4::DataWorker : The size of the key byte array is invalid!", std::source_location::current());

			std::array<std::uint32_t, 4> MasterKeyWords {};
			std::array<std::uint32_t, 36> TemporaryIterationKeyWords {};

			MasterKeyWords[0] = static_cast<std::uint32_t>(KeyByteData[0] << 24)
				| static_cast<std::uint32_t>(KeyByteData[1] << 16)
				| static_cast<std::uint32_t>(KeyByteData[2] << 8)
				| static_cast<std::uint32_t>(KeyByteData[3]);
			MasterKeyWords[1] = static_cast<std::uint32_t>(KeyByteData[4] << 24)
				| static_cast<std::uint32_t>(KeyByteData[5] << 16)
				| static_cast<std::uint32_t>(KeyByteData[6] << 8)
				| static_cast<std::uint32_t>(KeyByteData[7]);
			MasterKeyWords[2] = static_cast<std::uint32_t>(KeyByteData[8] << 24)
				| static_cast<std::uint32_t>(KeyByteData[9] << 16)
				| static_cast<std::uint32_t>(KeyByteData[10] << 8)
				| static_cast<std::uint32_t>(KeyByteData[11]);
			MasterKeyWords[3] = static_cast<std::uint32_t>(KeyByteData[12] << 24)
				| static_cast<std::uint32_t>(KeyByteData[13] << 16)
				| static_cast<std::uint32_t>(KeyByteData[14] << 8)
				| static_cast<std::uint32_t>(KeyByteData[15]);

			TemporaryIterationKeyWords[0] = MasterKeyWords[0] ^ SystemWords[0];
			TemporaryIterationKeyWords[1] = MasterKeyWords[1] ^ SystemWords[1];
			TemporaryIterationKeyWords[2] = MasterKeyWords[2] ^ SystemWords[2];
			TemporaryIterationKeyWords[3] = MasterKeyWords[3] ^ SystemWords[3];

			std::uint32_t TemporaryKeyWord = 0;

			for(std::size_t Index = 0; Index < 32; ++Index)
			{
				//Apply SM4 Key Expand Core Function
				TemporaryKeyWord = TemporaryIterationKeyWords[Index + 1] ^ TemporaryIterationKeyWords[Index + 2] ^ TemporaryIterationKeyWords[Index + 3] ^ ConstentWords[Index];
				TemporaryIterationKeyWords[Index + 4] = TemporaryIterationKeyWords[Index]
					^ MixKeyTransformedWordTable[0][TemporaryKeyWord & 0xff]
					^ MixKeyTransformedWordTable[1][TemporaryKeyWord >> 8 & 0xff]
					^ MixKeyTransformedWordTable[2][TemporaryKeyWord >> 16 & 0xff]
					^ MixKeyTransformedWordTable[3][TemporaryKeyWord >> 24];
				
				//Update Round Key
				EachRoundKeyWords[Index] = TemporaryIterationKeyWords[Index + 4];
			}

			TemporaryKeyWord = 0;

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(MasterKeyWords.data(), sizeof(std::uint32_t) * MasterKeyWords.size());
			my_cpp2020_assert(CheckPointer == MasterKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(TemporaryIterationKeyWords.data(), sizeof(std::uint32_t) * TemporaryIterationKeyWords.size());
			my_cpp2020_assert(CheckPointer == TemporaryIterationKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ExecuteMode>
		void RoundFunction
		(
			std::span<std::uint8_t> OriginalByteData
		)
		{
			my_cpp2020_assert(OriginalByteData.size_bytes() == Number_Block_Data_Byte_Size, "CommonSecurity::ChinaShangYongMiMa4::DataWorker : The size of the data byte array is invalid!", std::source_location::current());

			std::array<std::uint32_t, 36> TemporaryIterationDataWords {};
			std::array<std::uint32_t, 4> ProcessBuffer {};

			std::memmove(ProcessBuffer.data(), OriginalByteData.data(), Number_Block_Data_Byte_Size);

			TemporaryIterationDataWords[0] = this->EndianConvert(ProcessBuffer[0]);
			TemporaryIterationDataWords[1] = this->EndianConvert(ProcessBuffer[1]);
			TemporaryIterationDataWords[2] = this->EndianConvert(ProcessBuffer[2]);
			TemporaryIterationDataWords[3] = this->EndianConvert(ProcessBuffer[3]);

			std::uint32_t TemporaryDataWord = 0;

			for(std::uint32_t Index = 0, KeyIndex = 0; Index < 32; ++Index)
			{
				if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
					KeyIndex = Index;
				else if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
					KeyIndex = 31 - Index;
				else
					break;

				//Apply SM4 Data Process Core Function
				TemporaryDataWord = TemporaryIterationDataWords[Index + 1] ^ TemporaryIterationDataWords[Index + 2] ^ TemporaryIterationDataWords[Index + 3] ^ this->EachRoundKeyWords[KeyIndex];

				//Update Round Data
				TemporaryIterationDataWords[Index + 4] = TemporaryIterationDataWords[Index]
					^ MixDataTransformedWordTable[0][TemporaryDataWord & 0xff]
					^ MixDataTransformedWordTable[1][TemporaryDataWord >> 8 & 0xff]
					^ MixDataTransformedWordTable[2][TemporaryDataWord >> 16 & 0xff]
					^ MixDataTransformedWordTable[3][TemporaryDataWord >> 24];
			}

			TemporaryDataWord = 0;

			ProcessBuffer[0] = this->EndianConvert(TemporaryIterationDataWords[35]);
			ProcessBuffer[1] = this->EndianConvert(TemporaryIterationDataWords[34]);
			ProcessBuffer[2] = this->EndianConvert(TemporaryIterationDataWords[33]);
			ProcessBuffer[3] = this->EndianConvert(TemporaryIterationDataWords[32]);

			std::memmove(OriginalByteData.data(), ProcessBuffer.data(), Number_Block_Data_Byte_Size);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(TemporaryIterationDataWords.data(), sizeof(std::uint32_t) * TemporaryIterationDataWords.size());
			my_cpp2020_assert(CheckPointer == TemporaryIterationDataWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(ProcessBuffer.data(), sizeof(std::uint32_t) * ProcessBuffer.size());
			my_cpp2020_assert(CheckPointer == ProcessBuffer.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		OfficialAlgorithm() = default;

		~OfficialAlgorithm()
		{
			volatile void* CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>(EachRoundKeyWords.data(), sizeof(std::uint32_t) * EachRoundKeyWords.size());
			my_cpp2020_assert(CheckPointer == EachRoundKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}
	};
}

namespace CommonSecurity::Twofish::DefineConstants
{
	//Constants and variables

	/*
		how many rounds of encryption/decryption (number 16/24/32 of rounds for 128/192/256-bit keys, default round is 16)
	*/
	inline constexpr std::uint32_t Constant_MinCipherRounds = 16U;
	inline constexpr std::uint32_t Constant_MaxCipherRounds = 32U;

	inline constexpr std::uint32_t Constant_MinKeySize = 128U; // minimum number of bits of each key data block
	inline constexpr std::uint32_t Constant_MaxKeySize = 256U; // maximum number of bits of each key data block

    inline constexpr std::uint32_t Constant_DataBlockSize = 128U; // how many bits for each data block (128)
	inline constexpr std::uint32_t Constant_StepKeyBit = (Constant_MaxKeySize - Constant_DataBlockSize) / 2U;

	//Constants and variables - Subkey array indices

    inline constexpr std::uint32_t Constant_InputWhitenIndex = 0;
    inline constexpr std::uint32_t Constant_OutputWhitenIndex = Constant_InputWhitenIndex + Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits;
    inline constexpr std::uint32_t Constant_SubkeyRounds = Constant_OutputWhitenIndex + Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits;
	inline constexpr std::uint32_t Constant_TotalSubkeys = Constant_SubkeyRounds + 2 * Constant_MaxCipherRounds;

	//Constants and variables - Subkey array operation

    inline constexpr std::uint32_t Constant_SubkeysStep = 0x02020202U; //a fixed constant used to generate even subkeys
    inline constexpr std::uint32_t Constant_SubkeysBump = 0x01010101U; //a fixed constant used to generate odd subkeys
    inline constexpr std::uint32_t Constant_SubkeyRotateLeft = 9U; //fixed number determining bit shift in keys generator

	//Fixed 8x8 permutation substitution box
	inline constexpr std::array<std::array<std::uint8_t, 256>, 2> PSB_Matrix_Fixed
	{{
        {{
            0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
            0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
            0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
            0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
            0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
            0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
            0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
            0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
            0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
            0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
            0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
            0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
            0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
            0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
            0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
            0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
            0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
            0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
            0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
            0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
            0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
            0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
            0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
            0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
            0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
            0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
            0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
            0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
            0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
            0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
            0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
            0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
		}},
        {{
            0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
            0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
            0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
            0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
            0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
            0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
            0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
            0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
            0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
            0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
            0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
            0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
            0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
            0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
            0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
            0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
            0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
            0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
            0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
            0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
            0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
            0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
            0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
            0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
            0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
            0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
            0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
            0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
            0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
            0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
            0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
            0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
		}}
	}};

	//Primitive polynomial for Galois finite field(256) using Maximum disatance separable matrix (0x169)
	inline constexpr std::uint32_t BinaryFeedbackFormulaA = (1U << 8) + (1U << 6) + (1U << 5) + (1U << 3) + 1;

	//Primitive polynomial for Galois finite field(256) generator using Reed-Solomon code (0x14D)
	inline constexpr std::uint32_t BinaryFeedbackFormulaB = (1U << 8) + (1U << 6) + (1U << 3) + (1U << 2) + 1;

	//Linear feedback shift register 1 bit
	//@param value input bit which is a linear function of its previous state
	//@return output stream from shift register used in pseudo-random generators
	inline constexpr std::uint32_t LFSR_1Bit(std::uint32_t value)
	{
		return (value >> 1U)
		^ ( (value & 1U) ? BinaryFeedbackFormulaA / 2 : 0U );
	}

	//Linear feedback shift register 2 bit
	//@param value input bit which is a linear function of its previous state
	//@return output stream from shift register used in pseudo-random generators
	inline constexpr std::uint32_t LFSR_2Bit(std::uint32_t value)
	{
		return (value >> 2U)
		^ ( (value & 2U) ? BinaryFeedbackFormulaA / 2 : 0U )
		^ ( (value & 1U) ? BinaryFeedbackFormulaA / 4 : 0U );
	}

	//Value Exclusive-Or With Linear feedback shift register 2 bit
	//@param value input for Exclusive-Or operation
	//@return output value Exclusive-Or-ed with linear feedback shift register
	inline constexpr std::uint32_t MixFunctionX(std::uint32_t value)
	{
		//0x5B
		return value ^ LFSR_2Bit(value);
	}

	//Value Exclusive-Or With Linear feedback shift register 1 bit and 2 bit
	//@param value input for Exclusive-Or operation
	//@return output value Exclusive-Or-ed with linear feedback shift register
	inline constexpr std::uint32_t MixFunctionY(std::uint32_t value)
	{
		//0xEF
		return value ^ LFSR_1Bit(value) ^ LFSR_2Bit(value);
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	CompilerGeneration_MDS_Matrix()
	{
		std::array<std::array<std::uint32_t, 256>, 4> MDS {};

		std::array<std::uint8_t, 2> TemporaryVector {0, 0};
		std::array<std::uint8_t, 2> TemporaryVectorX {0, 0};
		std::array<std::uint8_t, 2> TemporaryVectorY {0, 0};
		
		for(std::uint32_t round = 0; round < 256; round++)
		{
			TemporaryVector[0] = PSB_Matrix_Fixed[0][round];
			TemporaryVectorX[0] = static_cast<std::uint8_t>( MixFunctionX(TemporaryVector[0]) & 255U );
			TemporaryVectorY[0] = static_cast<std::uint8_t>( MixFunctionY(TemporaryVector[0]) & 255U );

			TemporaryVector[1] = PSB_Matrix_Fixed[1][round];
			TemporaryVectorX[1] = static_cast<std::uint8_t>( MixFunctionX(TemporaryVector[1]) & 255U );
			TemporaryVectorY[1] = static_cast<std::uint8_t>( MixFunctionY(TemporaryVector[1]) & 255U );

			//PERMUTE_INDEX_00 = 1U
			MDS[0][round] = static_cast<std::uint32_t>( TemporaryVector[1] )
			| static_cast<std::uint32_t>( TemporaryVectorX[1] ) << 8U
			| static_cast<std::uint32_t>( TemporaryVectorY[1] ) << 16U
			| static_cast<std::uint32_t>( TemporaryVectorY[1] ) << 24U;

			//PERMUTE_INDEX_10 = 0U
			MDS[1][round] = static_cast<std::uint32_t>( TemporaryVectorY[0] )
			| static_cast<std::uint32_t>( TemporaryVectorY[0] ) << 8U
			| static_cast<std::uint32_t>( TemporaryVectorX[0] ) << 16U
			| static_cast<std::uint32_t>( TemporaryVector[0] ) << 24U;

			//PERMUTE_INDEX_20 = 1U
			MDS[2][round] = static_cast<std::uint32_t>( TemporaryVectorX[1] )
			| static_cast<std::uint32_t>( TemporaryVectorY[1] ) << 8U
			| static_cast<std::uint32_t>( TemporaryVector[1] ) << 16U
			| static_cast<std::uint32_t>( TemporaryVectorY[1] ) << 24U;

			//PERMUTE_INDEX_30 = 0U
			MDS[3][round] = static_cast<std::uint32_t>( TemporaryVectorX[0] )
			| static_cast<std::uint32_t>( TemporaryVector[0] ) << 8U
			| static_cast<std::uint32_t>( TemporaryVectorY[0] ) << 16U
			| static_cast<std::uint32_t>( TemporaryVectorX[0] ) << 24U;
		}

		TemporaryVector[0] = 0U;
		TemporaryVector[1] = 0U;
		TemporaryVectorX[0] = 0U;
		TemporaryVectorX[1] = 0U;
		TemporaryVectorY[0] = 0U;
		TemporaryVectorY[1] = 0U;

		return MDS;
	}

	static constexpr auto MAXIMUM_DISATANCE_SEPARABLE_MATRIX = CompilerGeneration_MDS_Matrix();
}

namespace CommonSecurity::Threefish::DefineConstants
{
	template<std::uint8_t>
	struct RotationBit;

	template<std::uint8_t>
	struct InvertibleIndices;

	template<>
    struct RotationBit<4> 
    {
        static constexpr std::uint8_t Table[8][2] =
		{
			{14, 16}, {52, 57}, {23, 40}, { 5, 37},
			{25, 33}, {46, 12}, {58, 22}, {32, 32}
        };
    };

    template<>
    struct RotationBit<8>
    {
        static constexpr std::uint8_t Table[8][4] =
		{
			{46, 36, 19, 37}, 	{33, 27, 14, 42},
			{17, 49, 36, 39},	{44,  9, 54, 56},
			{39, 30, 34, 24}, 	{13, 50, 10, 17},
			{25, 29, 39, 43}, 	{ 8, 35, 56, 22}
        };
    };

    template<>
    struct RotationBit<16>
    {
        static constexpr std::uint8_t Table[8][8] =
		{
			{24, 13,  8, 47,  8, 17, 22, 37},
			{33,  4, 51, 13, 34, 41, 59, 17},
			{ 5, 20, 48, 41, 47, 28, 16, 25},
			{41,  9, 37, 31, 12, 47, 44, 30},
			{16, 34, 56, 51,  4, 53, 42, 41},
			{31, 44, 47, 46, 19, 42, 44, 25},
			{ 9, 48, 35, 52, 23, 31, 37, 20}
        };
    };

    template<>
    struct InvertibleIndices<4>
    {
        static constexpr std::uint8_t Table[4][4] =
		{
			{0, 1, 2, 3}, {0, 3, 2, 1},
			{0, 1, 2, 3}, {0, 3, 2, 1}
        };
    };

    template<>
    struct InvertibleIndices<8>
    {
        static constexpr std::uint8_t Table[4][8] =
		{
			{0, 1, 2, 3, 4, 5, 6, 7},
			{2, 1, 4, 7, 6, 5, 0, 3},
			{4, 1, 6, 3, 0, 5, 2, 7},
			{6, 1, 0, 7, 2, 5, 4, 3}
        };
    };

    template<>
    struct InvertibleIndices<16>
    {
        static constexpr std::uint8_t Table[4][16] =
		{
			{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			{0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1},
			{0, 7, 2, 5, 4, 3, 6, 1, 12, 15, 14, 13, 8, 11, 10, 9},
			{0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7}
        };
    };
}