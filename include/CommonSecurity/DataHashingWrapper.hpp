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

#ifndef HMAC_TOKEN
#define HMAC_TOKEN
#endif // !HMAC_TOKEN

#if defined(HMAC_TOKEN) && !defined(HMAC_TOKEN_BITSET_OPTERATION)
//#define HMAC_TOKEN_BITSET_OPTERATION
#endif

//数据哈希化
//Data hashing
namespace CommonSecurity::DataHashingWrapper
{
	#if defined( HMAC_TOKEN )

	#if defined( HMAC_TOKEN_BITSET_OPTERATION )

	template<std::size_t BitDigitSize>
	inline void BitSetOperation(std::vector<std::string>& sourceBinaryStrings, std::vector<std::string>& targetBinaryStrings)
	{
		using namespace UtilTools::DataFormating;

		constexpr std::size_t BitDigitSize_Half = BitDigitSize / 2;
		constexpr std::size_t BitDigitSize_OneQuarter = BitDigitSize / 4;

		for(auto binaryStrings : targetBinaryStrings)
		{
			if(!targetBinaryStrings.empty())
			{
				return;
			}
		}

		for(auto binaryStrings : sourceBinaryStrings)
		{
			if(!IsBinaryString( binaryStrings, binaryStrings.size() ))
			{
				return;
			}
		}

		std::vector<std::bitset<BitDigitSize>> binarySetGroup;
		binarySetGroup.resize( sourceBinaryStrings.size() );

		for ( std::size_t index = 0; index < sourceBinaryStrings.size(); ++index )
		{
			binarySetGroup[ index ] = std::bitset<BitDigitSize>( sourceBinaryStrings[ index ] );
		}

		std::size_t binarySetGroupSize = binarySetGroup.size();
		if ( ( binarySetGroupSize & 1 ) == 0 )
		{
			for ( auto& bits : binarySetGroup )
			{
				for( std::size_t index = 0, middleIndex = binarySetGroupSize / 2 + 1; index < binarySetGroupSize; ++index )
				{
					bool bit = bits[index];
					if ( index < middleIndex )
					{
						if ( ( bit & true ) != 0 )
						{
							Cryptograph::Bitset::BitLeftCircularShift<BitDigitSize>( binarySetGroup[ index ], (index ^ BitDigitSize_OneQuarter) & binarySetGroupSize - 1, binarySetGroup[ index ] );
						}
						else
						{
							Cryptograph::Bitset::BitLeftCircularShift<BitDigitSize>( binarySetGroup[ index ], (index ^ BitDigitSize_Half) & binarySetGroupSize - 1, binarySetGroup[ index ] );
						}
					}
					else
					{
						if ( ( bit & true ) != 0 )
						{
							Cryptograph::Bitset::BitRightCircularShift<BitDigitSize>( binarySetGroup[ index ], (index ^ BitDigitSize_Half) & binarySetGroupSize - 1, binarySetGroup[ index ] );
						}
						else
						{
							Cryptograph::Bitset::BitRightCircularShift<BitDigitSize>( binarySetGroup[ index ], (index ^ BitDigitSize_OneQuarter) & binarySetGroupSize - 1, binarySetGroup[ index ] );
						}
					}
				}
			}
		}
		else
		{
			for ( auto& bits : binarySetGroup )
			{
				for( std::size_t index = 0, middleIndex = binarySetGroupSize / 2; index < binarySetGroupSize; ++index )
				{
					bool bit = bits[index];
					if ( index < middleIndex + 1 )
					{
						if ( ( bit & true ) != 0 )
						{
							Cryptograph::Bitset::BitLeftCircularShift<BitDigitSize>( binarySetGroup[ index ], (index ^ BitDigitSize_Half) & binarySetGroupSize - 1, binarySetGroup[ index ] );
						}
						else
						{
							Cryptograph::Bitset::BitLeftCircularShift<BitDigitSize>( binarySetGroup[ index ], (index ^ BitDigitSize_OneQuarter) & binarySetGroupSize - 1, binarySetGroup[ index ] );
						}
					}
					else
					{
						if ( ( bit & true ) != 0 )
						{
							Cryptograph::Bitset::BitRightCircularShift<BitDigitSize>( binarySetGroup[ index ], (index ^ BitDigitSize_OneQuarter) & binarySetGroupSize - 1, binarySetGroup[ index ] );
						}
						else
						{
							Cryptograph::Bitset::BitRightCircularShift<BitDigitSize>( binarySetGroup[ index ], (index ^ BitDigitSize_Half) & binarySetGroupSize - 1, binarySetGroup[ index ] );
						}
					}
				}
			}
		}

		for ( std::size_t index = 0; index < binarySetGroup.size(); ++index )
		{
			targetBinaryStrings[ index ] = std::move(binarySetGroup[ index ].to_string());
		}
	}
	#endif

	//This is a class HashTokenForData of the result
	struct KeyStreamHashTokenResult
	{
		std::string HashKeyStreamToken_String {};
		std::vector<std::uint8_t> HashKeyStreamToken_Bytes {};
	};

	//This is a class HashTokenForData of the parameters
	struct HashTokenForDataParameters
	{
		HashersAssistantParameters HashersAssistantParameters_Instance = HashersAssistantParameters();
		std::vector<std::string> OriginalPasswordStrings = std::vector<std::string>();
		std::size_t NeedHashByteTokenSize = 0;
	};

	//数据的哈希令牌
	//Hash tokens for data
	class HashTokenForData
	{

	private:

		HashersAssistantParameters HashersAssistantParameters_Instance = HashersAssistantParameters();
		std::vector<std::string> OriginalPasswordStrings = std::vector<std::string>();
		std::size_t NeedHashByteTokenSize = 0;

		std::vector<std::string> PreProcessWithMultiPasswordByHasherAssistant( std::vector<std::string> MultiPasswordString )
		{
			std::vector<std::string> HashedStringFromMultiPassword;
			HashedStringFromMultiPassword.reserve( MultiPasswordString.size() );

			for ( auto beginIterator = MultiPasswordString.begin(), endIterator = MultiPasswordString.end(); beginIterator != endIterator; ++beginIterator )
			{
				//Make Original Processed Hash Message Key
				this->HashersAssistantParameters_Instance.inputDataString = *beginIterator;
				HashersAssistant::SELECT_HASH_FUNCTION( this->HashersAssistantParameters_Instance );
				std::string PasswordHashed = this->HashersAssistantParameters_Instance.outputHashedHexadecimalString;
				HashedStringFromMultiPassword.push_back( PasswordHashed );
			}

			return HashedStringFromMultiPassword;
		}

		/*
			Hash Token Computation:
			
			Input: * Password (4 count) * ----> * Concatenate passwords * ----> * Shuffle password (Number seed by PasswordsToInteger) * ----> * HASH FUNCTION *
			                                                                                                                                     |           |
																  * DataObfuscator * ----> * Argument Key *                                      |           |
			                                                                                       |                                             |           |
																					               #                                             |           |
											 Input: * Hashed Password (4 count) * ----> * ExtendedChaCha20-IETF * <---- * Argument Nonces * <----+           |
			                                                                                       |                                                         |
			                                                                                       |                                                         |
															* Argument Keys * <--------------------+                                                         |
			                                                        |                                                                                        |
			                                                        #                                                                                        |
			Ouput: Datas <---- * Concatenate hash token * <----- * HMAC * <---- * Argument Datas * <---- * Replace passwords * <---- * Split password * <----+
		*/
		void PostProcessFromHashedStringToComputationToken( std::vector<std::string>& MultiPasswordString, std::vector<std::string>& MultiPasswordHashedString,std::vector<std::string>& HashedTokenHexadecimalString )
		{
			using namespace CommonSecurity;
			using namespace UtilTools::DataFormating;
			using namespace UtilTools::DataStreamConverter;

			//Original password (Conactenate operation)
			std::string CombinedMultiPasswordString = MultiPasswordString[ 0 ] + MultiPasswordString[ 1 ] + MultiPasswordString[ 2 ] + MultiPasswordString[ 3 ];

			std::vector<MySupport_Library::Types::my_ulli_type> PasswordStringIntegers;

			for(auto& PasswordString : MultiPasswordString)
			{
				auto TemporaryPasswordStringIntegers = StringToInteger<MySupport_Library::Types::my_ulli_type>( PasswordString );
				PasswordStringIntegers.insert(PasswordStringIntegers.end(), TemporaryPasswordStringIntegers.begin(), TemporaryPasswordStringIntegers.end());

				TemporaryPasswordStringIntegers.clear();
				TemporaryPasswordStringIntegers.shrink_to_fit();
			}

			//Seed sequence of pseudo-random numbers
			std::seed_seq SeedSequence( PasswordStringIntegers.begin(), PasswordStringIntegers.end() );
			//Pseudo-random number generation engine
			CommonSecurity::RNG_Xoshiro::xoshiro256 random_generator{ SeedSequence };
			//Pseudo-random number generation engine to disrupt container ordering (Original password shuffle)
			CommonSecurity::ShuffleRangeData( CombinedMultiPasswordString.begin(), CombinedMultiPasswordString.end(), random_generator );

			//Make Original Processed Hash Message
			this->HashersAssistantParameters_Instance.inputDataString = CombinedMultiPasswordString;
			HashersAssistant::SELECT_HASH_FUNCTION( this->HashersAssistantParameters_Instance );

			std::string HashMessage = this->HashersAssistantParameters_Instance.outputHashedHexadecimalString;

			//Re-split into four passwords, then replace the original password
			MultiPasswordString.clear();
			MultiPasswordString.shrink_to_fit();

			std::size_t CombinedString_PartSize = CombinedMultiPasswordString.size() / 4;
			for(auto begin = CombinedMultiPasswordString.begin(), end = CombinedMultiPasswordString.end(); begin != end; begin += CombinedString_PartSize)
			{
				std::size_t iterator_offset = CommonToolkit::IteratorOffsetDistance(begin, end, CombinedString_PartSize);
				MultiPasswordString.push_back(std::string(begin, begin + iterator_offset));
			}

			std::vector<std::string> HashMessageKeyStrings;

			#if defined(HMAC_TOKEN_BITSET_OPTERATION)

			std::vector<std::string> sourceBinaryStrings;
			std::vector<std::string> targetBinaryStrings;

			if(MultiPasswordHashedString.size() != 0)
			{
				sourceBinaryStrings.resize( MultiPasswordHashedString.size() );
				targetBinaryStrings.resize( MultiPasswordHashedString.size() );

				for ( std::size_t index = 0; index < MultiPasswordHashedString.size(); ++index )
				{
					sourceBinaryStrings[ index ] = Hexadecimal_Binary::FromHexadecimal( MultiPasswordHashedString[ index ], AlphabetFormat::UPPER_CASE );
				}
			}

			BitSetOperation<512>(sourceBinaryStrings, targetBinaryStrings);

			hexadecimalKeyStrings.resize( targetBinaryStrings.size() );

			for ( std::size_t index = 0; index < targetBinaryStrings.size(); ++index )
			{
				HashMessageKeyStrings[ index ] = Hexadecimal_Binary::ToHexadecimal( targetBinaryStrings[ index ], AlphabetFormat::UPPER_CASE );
			}

			#else

			//WHAT TODO: The ExtendedChaCha20 stream cipher algorithm needs to be completed and the module unit tested before the block can be commented out and reduced to code
			//要做的事: 需要将 ExtendedChaCha20 流密码算法完成，并且进行模块单元测试之后，才可以把这个代码块注释还原为代码

			/*
			std::vector<unsigned char> HashMessageBytes = ASCII_Hexadecmial::hexadecimalString2ByteArray(HashMessage);

			std::deque<std::vector<unsigned char>> MultiPasswordHashedBytes;

			for( auto& PasswordHashedString : MultiPasswordHashedString )
			{
				MultiPasswordHashedBytes.push_back( ASCII_Hexadecmial::hexadecimalString2ByteArray(PasswordHashedString) );
			}

			std::vector<unsigned char> ExtendedChacha20_Key { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			for( auto& PasswordHashedBytes : MultiPasswordHashedBytes )
			{
				//Apply ExtendedChacha20-IETF
				//应用ExtendedChacha20-IETF
				std::vector<unsigned char> ExtendedChacha20_ProcessedData = CommonSecurity::ChaCha20::WorkerExtendedChaCha20::ExtendedChaCha20
				(
					PasswordHashedBytes,
					ExtendedChacha20_Key,
					HashMessageBytes,
					PasswordHashedBytes.size()
				);

				HashMessageKeyStrings.push_back( ASCII_Hexadecmial::byteArray2HexadecimalString(ExtendedChacha20_ProcessedData) );
			}
			*/

			#endif

			//512 bit / 8 bit = 64 byte
			constexpr std::size_t MessageBlockSize = ( (sizeof(std::uint32_t) * 4) * 8 * sizeof(std::uint32_t) ) / 8;

			for ( std::size_t index = 0; index < HashMessageKeyStrings.size(); ++index )
			{
				std::string HMAC_Password = HMAC_FunctionObject( this->HashersAssistantParameters_Instance, MultiPasswordString[ index ], MessageBlockSize, HashMessageKeyStrings[ index ] );
				HashedTokenHexadecimalString.push_back( HMAC_Password );
			}
		}

	public:

		//生成个性置换令牌函数（通过4个密码处理产生的哈希值）
		//生成个性逆置换令牌函数（通过4个密码处理产生的哈希值）
		template<CommonSecurity::SHA::Hasher::WORKER_MODE mode>
		std::optional<KeyStreamHashTokenResult> GenerateKeyStreamHashToken();

		HashTokenForData() = delete;

		explicit HashTokenForData(const HashTokenForDataParameters& HashTokenForDataParameters_Instance)
			:
			HashersAssistantParameters_Instance(HashTokenForDataParameters_Instance.HashersAssistantParameters_Instance),
			OriginalPasswordStrings(HashTokenForDataParameters_Instance.OriginalPasswordStrings),
			NeedHashByteTokenSize(HashTokenForDataParameters_Instance.NeedHashByteTokenSize)
		{
		
		}

		~HashTokenForData() = default;

		HashTokenForData(HashTokenForData& _object) = delete;
		HashTokenForData& operator=(const HashTokenForData& _object) = delete;
	};

	/*
		Key stream generator:
		
		Input: Password 1 ~ Password 4
		      Type: String vector
			          |
			          |
			          |
				      #
		        ? Use Argon2 ? ----> * Yes * ----> * Argon2 * ----> Output: Key streams ( hexadecimal format )
			          |
			          |
			          |
				      #
				    * No *
			          |
			          |
			          |
		      * HASH FUNCTION * ----> * XXTEA Encryption * ----> * HASH TOKEN COMPUTATION * ----> * XXTEA Decryption * ----> Output: Key streams ( hexadecimal format )
	*/
	template<CommonSecurity::SHA::Hasher::WORKER_MODE mode>
	std::optional<KeyStreamHashTokenResult> HashTokenForData::GenerateKeyStreamHashToken()
	{
		if(this->OriginalPasswordStrings.size() != 4 || this->OriginalPasswordStrings.size() == 0)
		{
			return std::nullopt;
		}
		else
		{
			KeyStreamHashTokenResult HashKeyStreamTokenResultObject;

			std::size_t GeneratePasswordStreamHashByteTokenSize = this->NeedHashByteTokenSize == 0 ? 8192 : this->NeedHashByteTokenSize;

			if(GeneratePasswordStreamHashByteTokenSize % 1024 != 0)
			{
				std::size_t QuotientCount = GeneratePasswordStreamHashByteTokenSize / 1024;
				std::size_t RemainderCount = GeneratePasswordStreamHashByteTokenSize % 1024;
				std::size_t FactorCount = QuotientCount > RemainderCount ? QuotientCount - RemainderCount : RemainderCount - QuotientCount;
				GeneratePasswordStreamHashByteTokenSize = FactorCount * 1024;
			}

			CommonSecurity::PseudoRandomNumberEngine<CommonSecurity::RNG_ISAAC::isaac<8>> PRNE;

			if constexpr (mode == CommonSecurity::SHA::Hasher::WORKER_MODE::ARGON2)
			{
				using CommonSecurity::KDF::Argon2::Argon2_Parameters;
				using CommonSecurity::KDF::Argon2::Argon2;
				using CommonSecurity::KDF::Argon2::AlgorithmVersion;
				using CommonSecurity::KDF::Argon2::HashModeTypeStringAlphabetFormat;
				using CommonSecurity::KDF::Argon2::HashModeType;

				std::vector<std::uint8_t> PasswordStreamBytes;
				std::vector<std::uint8_t> PasswordStreamSaltBytes;

				std::string ConactenatedString =
					this->OriginalPasswordStrings[0]
					+ this->OriginalPasswordStrings[1]
					+ this->OriginalPasswordStrings[2]
					+ this->OriginalPasswordStrings[3];

				for( auto& CharacterData : ConactenatedString )
				{
					PasswordStreamSaltBytes.push_back(static_cast<std::uint8_t>(CharacterData));
					PasswordStreamBytes.push_back(static_cast<std::uint8_t>(CharacterData));
				}

				ConactenatedString.clear();

				std::vector<std::uint32_t> PasswordStreamWords = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>( PasswordStreamSaltBytes.data(), PasswordStreamSaltBytes.size() );
				PasswordStreamSaltBytes.clear();
				PasswordStreamSaltBytes.shrink_to_fit();

				PRNE.InitialBySeed( PasswordStreamWords.begin(), PasswordStreamWords.end(), 0, false );

				CommonSecurity::ShuffleRangeData( PasswordStreamWords.begin(), PasswordStreamWords.end(), PRNE.random_generator );

				for (std::size_t have_counter = 0, want_counter = (PasswordStreamWords.size() * sizeof(std::uint32_t) ); have_counter != want_counter; ++have_counter )
				{
					PasswordStreamWords.push_back( PRNE.GenerateNumber( std::numeric_limits<std::uint32_t>::min(), std::numeric_limits<std::uint32_t>::max(), true ) );
				}

				CommonSecurity::ShuffleRangeData( PasswordStreamWords.begin(), PasswordStreamWords.end(), PRNE.random_generator );

				PasswordStreamSaltBytes = CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>( PasswordStreamWords.data(), PasswordStreamWords.size() );
				PasswordStreamWords.clear();
				PasswordStreamWords.shrink_to_fit();

				std::vector<std::uint8_t> PasswordStreamHashedTokenBytes( GeneratePasswordStreamHashByteTokenSize, 0 );

				std::size_t ThreadNumber = std::thread::hardware_concurrency() / 4;

				Argon2_Parameters Argon2KDF_ParameterObject
				(
					PasswordStreamHashedTokenBytes,
					GeneratePasswordStreamHashByteTokenSize,
					PasswordStreamBytes,
					PasswordStreamSaltBytes,
					GeneratePasswordStreamHashByteTokenSize / 128 * 4,
					GeneratePasswordStreamHashByteTokenSize / 16 * 4,
					ThreadNumber,
					ThreadNumber,
					true,
					true,
					true,
					true,
					HashModeTypeStringAlphabetFormat::UPPER_CASE,
					AlgorithmVersion::NUMBER_0x13,
					HashModeType::SubstitutionBox
				);

				Argon2 Argon2KDF_Object(Argon2KDF_ParameterObject);

				Argon2KDF_Object.Hash<std::vector<std::uint8_t>>(PasswordStreamHashedTokenBytes);
				PasswordStreamBytes.clear();
				PasswordStreamBytes.assign(PasswordStreamHashedTokenBytes.begin(), PasswordStreamHashedTokenBytes.end());
				PasswordStreamHashedTokenBytes.clear();

				ThreadNumber = std::thread::hardware_concurrency() / 4;

				Argon2KDF_ParameterObject = Argon2_Parameters
				(
					PasswordStreamHashedTokenBytes,
					GeneratePasswordStreamHashByteTokenSize,
					PasswordStreamBytes,
					PasswordStreamSaltBytes,
					GeneratePasswordStreamHashByteTokenSize / 64 * 2,
					GeneratePasswordStreamHashByteTokenSize / 8 * 2,
					ThreadNumber,
					ThreadNumber,
					false,
					false,
					false,
					false,
					HashModeTypeStringAlphabetFormat::UPPER_CASE,
					AlgorithmVersion::NUMBER_0x13,
					HashModeType::MixedAddressing
				);

				Argon2KDF_Object.SetParametersContext(Argon2KDF_ParameterObject);
				Argon2KDF_Object.Hash<std::vector<std::uint8_t>>(PasswordStreamHashedTokenBytes);

				for( auto& ByteData : PasswordStreamHashedTokenBytes )
				{
					HashKeyStreamTokenResultObject.HashKeyStreamToken_String.push_back( static_cast<char>(ByteData) );
				}

				HashKeyStreamTokenResultObject.HashKeyStreamToken_Bytes = std::move(PasswordStreamHashedTokenBytes);

				return HashKeyStreamTokenResultObject;
			}
			else
			{
				/*
					首先输入多个密码字符串，通过安全散列算法进行处理来生成摘要字符串，
					接着再使用密钥散列消息认证码函数，与另一个摘要字符串生成的密钥进行一次填充数据，
					然后与0x5c(92)和0x36(54)进行一次异或运算，最后输出一个被消息认证码化的哈希令牌

					First input multiple cipher strings, process them by secure hashing algorithm to generate digest strings,
					then use the key hashing message authentication code function to fill the data once with the key generated by another digest string,
					then change byte them with 0x5c(92) and 0x36(54) in an exclusive-or operation, and finally output one hash tokens coded by message authentication
				*/

				std::vector<std::string> MultiPasswordString;
				MultiPasswordString.reserve( this->OriginalPasswordStrings.size() );

				for(const auto& password : this->OriginalPasswordStrings )
				{
					MultiPasswordString.push_back(password);
				}

				//Hashing function by Standard security hash algorithm
				std::vector<std::string> MultiPasswordHashedString = this->PreProcessWithMultiPasswordByHasherAssistant( MultiPasswordString );

				//Magic number from std::cout << std::hex << *reinterpret_cast<const unsigned long long *>(&std::numbers::e) << std::endl;
				//Magic number from std::cout << std::hex << *reinterpret_cast<const unsigned long long *>(&std::numbers::pi) << std::endl;
				constexpr std::array<unsigned int, 4> MagicNumberConstantArray { 0x4005bf0a, 0x8b145769, 0x400921fb, 0x54442d18 };

				//Execute Super TEA "Encrypt" Operation
				for(auto& PasswordString : MultiPasswordString)
				{
					while (PasswordString.size() % sizeof(unsigned int) != 0)
						PasswordString.push_back(0);

					std::vector<unsigned char> classic_bytes{ PasswordString.data(), PasswordString.data() + PasswordString.size() };
					std::span<const unsigned char> classic_bytes_span { classic_bytes };
					std::vector<unsigned int> word_ascii_codes(classic_bytes_span.size() / 4);
					std::span<const unsigned int> word_ascii_codes_span { word_ascii_codes };
					
					CommonToolkit::MessagePacking(classic_bytes_span, word_ascii_codes.data());

					CommonSecurity::CorrectedBlockTEA::SuperTEA(word_ascii_codes.data(), word_ascii_codes.size(), true, MagicNumberConstantArray);

					CommonToolkit::MessageUnpacking(word_ascii_codes_span, classic_bytes.data());

					std::string ProcessedPasswordString { classic_bytes.data(), classic_bytes.data() + classic_bytes.size() };

					PasswordString.swap(ProcessedPasswordString);

					word_ascii_codes.clear();
					word_ascii_codes.shrink_to_fit();
					classic_bytes.clear();
					classic_bytes.shrink_to_fit();
					ProcessedPasswordString.clear();
				}

				std::vector<std::string> HashedTokenHexadecimalString;

				this->PostProcessFromHashedStringToComputationToken( MultiPasswordString, MultiPasswordHashedString, HashedTokenHexadecimalString );

				//Execute Super TEA "Decrypt" Operation
				for(auto& PasswordString : HashedTokenHexadecimalString)
				{
					while (PasswordString.size() % sizeof(unsigned int) != 0)
						PasswordString.push_back(0);

					std::vector<unsigned char> classic_bytes{ PasswordString.data(), PasswordString.data() + PasswordString.size() };
					std::span<const unsigned char> classic_bytes_span { classic_bytes };
					std::vector<unsigned int> word_ascii_codes( classic_bytes_span.size() / 4 );
					std::span<const unsigned int> word_ascii_codes_span { word_ascii_codes };
					
					CommonToolkit::MessagePacking( classic_bytes_span, word_ascii_codes.data() );

					CommonSecurity::CorrectedBlockTEA::SuperTEA( word_ascii_codes.data(), word_ascii_codes.size(), false, MagicNumberConstantArray );

					CommonToolkit::MessageUnpacking( word_ascii_codes_span, classic_bytes.data() );

					std::string ProcessedPasswordString { classic_bytes.data(), classic_bytes.data() + classic_bytes.size() };

					PasswordString.swap( ProcessedPasswordString );

					word_ascii_codes.clear();
					word_ascii_codes.shrink_to_fit();
					classic_bytes.clear();
					classic_bytes.shrink_to_fit();
					ProcessedPasswordString.clear();
				}

				MultiPasswordString.clear();
				MultiPasswordString.shrink_to_fit();
				MultiPasswordHashedString.clear();
				MultiPasswordHashedString.shrink_to_fit();

				std::string PasswordStreamHashedTokenString = HashedTokenHexadecimalString[0] + HashedTokenHexadecimalString[1] + HashedTokenHexadecimalString[2] + HashedTokenHexadecimalString[3];

				if(PasswordStreamHashedTokenString.size() < GeneratePasswordStreamHashByteTokenSize)
				{
					//Append byte data

					std::vector<std::uint8_t> PasswordStreamBytes;

					for( auto& CharacterData : PasswordStreamHashedTokenString )
					{
						PasswordStreamBytes.push_back(static_cast<std::uint8_t>(CharacterData));
					}

					PasswordStreamHashedTokenString.clear();

					std::vector<std::uint32_t> PasswordStreamWords = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>( PasswordStreamBytes.data(), PasswordStreamBytes.size() );
					PasswordStreamBytes.clear();
					PasswordStreamBytes.shrink_to_fit();

					PRNE.InitialBySeed( PasswordStreamWords.begin(), PasswordStreamWords.end(), 0, false );

					CommonSecurity::ShuffleRangeData( PasswordStreamWords.begin(), PasswordStreamWords.end(), PRNE.random_generator );

					for (std::size_t have_counter = PasswordStreamWords.size(), want_counter = GeneratePasswordStreamHashByteTokenSize / sizeof(std::uint32_t); have_counter < want_counter; ++have_counter )
					{
						PasswordStreamWords.push_back( PRNE.GenerateNumber( std::numeric_limits<std::uint32_t>::min(), std::numeric_limits<std::uint32_t>::max(), true ) );
					}

					CommonSecurity::ShuffleRangeData( PasswordStreamWords.begin(), PasswordStreamWords.end(), PRNE.random_generator );

					PasswordStreamBytes = CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>( PasswordStreamWords.data(), PasswordStreamWords.size() );
					PasswordStreamWords.clear();
					PasswordStreamWords.shrink_to_fit();

					for( auto& ByteData : PasswordStreamBytes )
					{
						HashKeyStreamTokenResultObject.HashKeyStreamToken_String.push_back( static_cast<char>(ByteData) );
					}

					HashKeyStreamTokenResultObject.HashKeyStreamToken_Bytes = std::move(PasswordStreamBytes);
				}
				else
				{
					//Truncation byte data

					while (PasswordStreamHashedTokenString.size() > GeneratePasswordStreamHashByteTokenSize)
					{
						PasswordStreamHashedTokenString.pop_back();
					}
				}

				if(HashKeyStreamTokenResultObject.HashKeyStreamToken_String.empty())
					HashKeyStreamTokenResultObject.HashKeyStreamToken_String = std::move(PasswordStreamHashedTokenString);

				if(HashKeyStreamTokenResultObject.HashKeyStreamToken_Bytes.empty())
				{
					for(const auto& CharacterData : HashKeyStreamTokenResultObject.HashKeyStreamToken_String)
					{
						HashKeyStreamTokenResultObject.HashKeyStreamToken_Bytes.push_back( static_cast<std::uint8_t>(CharacterData) );
					}
				}

				return HashKeyStreamTokenResultObject;
			}
		}
	}

	#endif	//! HMAC_TOKEN

}

#ifdef HMAC_TOKEN
#undef HMAC_TOKEN
#endif //! HMAC_TOKEN