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
				CommonSecurity::RNG_Xorshiro::xorshiro256 PRNG;
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
			CommonSecurity::RNG_Xorshiro::xorshiro256 RandomNumberGenerator(CommonSecurity::GenerateSecureRandomNumberSeed<std::uint32_t>(RandomDevice));
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