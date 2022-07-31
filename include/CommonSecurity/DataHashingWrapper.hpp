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
		//FUTURE TODO:
		//Maybe here it could be an RSA(Rivest–Shamir–Adleman) algorithm based on random large prime numbers?
		//One-time one-way asymmetric "encryption" or "decryption" for key generation.
		//也许这里可以是基于随机大素数的RSA(Rivest-Shamir-Adleman)算法？
		//一次性单向非对称 "加密 "或 "解密"，用于生成密钥。

		/*** The following code is deprecated ***/

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
			using namespace CommonSecurity::SHA;

			std::vector<std::string> HashedStringFromMultiPassword;
			HashedStringFromMultiPassword.reserve( MultiPasswordString.size() );

			for ( auto beginIterator = MultiPasswordString.begin(), endIterator = MultiPasswordString.end(); beginIterator != endIterator; ++beginIterator )
			{
				if(this->HashersAssistantParameters_Instance.hash_mode == Hasher::WORKER_MODE::BLAKE3)
				{
					this->HashersAssistantParameters_Instance.hash_mode = Hasher::WORKER_MODE::BLAKE2;

					my_cpp2020_assert(this->HashersAssistantParameters_Instance.generate_hash_bit_size < 1024 * std::numeric_limits<std::uint8_t>::digits, "[The Data Size Designation Is Too Small!]\nThe data required for the Blake3 algorithm must be greater than or equal to 1024 bytes!", std::source_location::current());

					//Make Original Processed Hash Message Key
					this->HashersAssistantParameters_Instance.inputDataString = *beginIterator;
					HashersAssistant::SELECT_HASH_FUNCTION( this->HashersAssistantParameters_Instance );
					std::string PasswordHashed = this->HashersAssistantParameters_Instance.outputHashedHexadecimalString;
					*beginIterator = PasswordHashed;

					this->HashersAssistantParameters_Instance.hash_mode = Hasher::WORKER_MODE::BLAKE3;
				}

				//Make Original Processed Hash Message Key
				this->HashersAssistantParameters_Instance.inputDataString = *beginIterator;
				HashersAssistant::SELECT_HASH_FUNCTION( this->HashersAssistantParameters_Instance );
				std::string PasswordHashed = this->HashersAssistantParameters_Instance.outputHashedHexadecimalString;
				HashedStringFromMultiPassword.push_back( PasswordHashed );
			}

			return HashedStringFromMultiPassword;
		}

		//Apply data obfuscation
		//应用数据混淆
		template<bool IsCompileTime>
		CustomSecurity::DataObfuscator::CustomDataObfuscatorResult<IsCompileTime> ApplyCustomDataObfuscation
		(
			std::size_t RandomNumberSeed,
			std::size_t RandomNumberSeed2,
			std::vector<std::uint8_t>& ProcessData,
			bool IsEncodeOrDecodeMode
		)
		{
			using namespace CustomSecurity::DataObfuscator;

			CustomDataObfuscator<IsCompileTime> CustomDataObfuscatorObject(RandomNumberSeed, RandomNumberSeed2);

			CustomDataObfuscatorResult<IsCompileTime> ExportedObfuscatorResultTable = CustomDataObfuscatorObject.ExportEncodingAndDecodingTable(CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::ONE_TIME_USE);
			bool ProcessDataIsChanged = CustomDataObfuscatorObject.ImportAndEncodeOrDecode
			(
				ProcessData,
				ExportedObfuscatorResultTable,
				CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::ONE_TIME_USE,
				IsEncodeOrDecodeMode
			);

			std::destroy_at(&CustomDataObfuscatorObject);

			my_cpp2020_assert(ProcessDataIsChanged, "[This Code Data Hash Is Not Match!]\nAfter applying a custom data obfuscator to this data, it does not change the data content!", std::source_location::current());

			return ExportedObfuscatorResultTable;
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
			using namespace CommonSecurity::SHA;
			using namespace UtilTools::DataFormating;
			using namespace UtilTools::DataStreamConverter;

			//Original password (Conactenate operation)
			std::string CombinedMultiPasswordString = MultiPasswordString[ 0 ] + MultiPasswordString[ 1 ] + MultiPasswordString[ 2 ] + MultiPasswordString[ 3 ];

			std::vector<std::uint64_t> PasswordStringIntegers;

			for(auto& PasswordString : MultiPasswordString)
			{
				auto TemporaryPasswordStringIntegers = StringToInteger<std::uint64_t>( PasswordString );
				PasswordStringIntegers.insert(PasswordStringIntegers.end(), TemporaryPasswordStringIntegers.begin(), TemporaryPasswordStringIntegers.end());

				TemporaryPasswordStringIntegers.clear();
				TemporaryPasswordStringIntegers.shrink_to_fit();
			}

			//Seed sequence of pseudo-random numbers
			std::seed_seq SeedSequence( PasswordStringIntegers.begin(), PasswordStringIntegers.end() );
			//Pseudo-random number generation engine
			CommonSecurity::RNG_Xoshiro::xoshiro256 RNG_Xoshiro256{ SeedSequence };
			//Pseudo-random number generation engine to disrupt container ordering (Original password shuffle)
			CommonSecurity::ShuffleRangeData( CombinedMultiPasswordString.begin(), CombinedMultiPasswordString.end(), RNG_Xoshiro256 );

			//Make Original Processed Hash Message
			this->HashersAssistantParameters_Instance.inputDataString = CombinedMultiPasswordString;

			if(this->HashersAssistantParameters_Instance.hash_mode == Hasher::WORKER_MODE::BLAKE3)
			{
				this->HashersAssistantParameters_Instance.hash_mode = Hasher::WORKER_MODE::BLAKE2;

				my_cpp2020_assert(this->HashersAssistantParameters_Instance.generate_hash_bit_size < 1024 * std::numeric_limits<std::uint8_t>::digits, "[The Data Size Designation Is Too Small!]\nThe data required for the Blake3 algorithm must be greater than or equal to 1024 bytes!", std::source_location::current());

				//Make Original Processed Hash Message Key
				HashersAssistant::SELECT_HASH_FUNCTION( this->HashersAssistantParameters_Instance );
				std::string PasswordHashed = this->HashersAssistantParameters_Instance.outputHashedHexadecimalString;
				this->HashersAssistantParameters_Instance.inputDataString = PasswordHashed;

				this->HashersAssistantParameters_Instance.hash_mode = Hasher::WORKER_MODE::BLAKE3;
			}

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

			if(this->HashersAssistantParameters_Instance.hash_mode == Hasher::WORKER_MODE::BLAKE3)
			{
				MultiPasswordString = this->PreProcessWithMultiPasswordByHasherAssistant(MultiPasswordString);
			}

			std::vector<std::string> HashMessageStringOfKeys;

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
				HashMessageStringOfKeys[ index ] = Hexadecimal_Binary::ToHexadecimal( targetBinaryStrings[ index ], AlphabetFormat::UPPER_CASE );
			}

			#else

			std::vector<std::uint8_t> ExtendedChacha20_Message = ASCII_Hexadecmial::hexadecimalString2ByteArray(HashMessage);

			std::deque<std::vector<std::uint8_t>> ExtendedChacha20_Nonces;

			for( auto& PasswordHashedString : MultiPasswordHashedString )
			{
				ExtendedChacha20_Nonces.push_back( ASCII_Hexadecmial::hexadecimalString2ByteArray(PasswordHashedString) );
			}

			std::vector<std::uint8_t> ExtendedChacha20_Key;
			
			//Does it use a true random number generator?
			//是否使用真随机数生成器？
			if constexpr(false)
			{
				std::random_device TRNG;

				std::destroy_at(&RNG_Xoshiro256);

				ExtendedChacha20_Key.resize(64 * MultiPasswordHashedString.size());

				for( auto& ByteData : ExtendedChacha20_Key )
				{
					ByteData = TRNG() % std::numeric_limits<std::uint8_t>::max();
				}

				std::size_t CurrentRandomSeed = GenerateSecureRandomNumberSeed<std::size_t>(TRNG);
				std::size_t CurrentRandomSeed2 = GenerateSecureRandomNumberSeed<std::size_t>(TRNG);

				auto ExportedObfuscatorResultTable = this->ApplyCustomDataObfuscation<false>(CurrentRandomSeed, CurrentRandomSeed2, ExtendedChacha20_Key, true);

				CurrentRandomSeed = 0;
				CurrentRandomSeed2 = 0;

				std::destroy_at(&ExportedObfuscatorResultTable);
			}
			else
			{
				//Using my data obfuscator, Permutation and concatenation operations are performed on the source byte data before the provided data (extended-chacha20 key) is obfuscated.
				//用我的数据混淆器，对所提供的数据（extended-chacha20密钥）进行混淆之前，将源字节数据进行排列和串联操作。
				std::ranges::copy(ExtendedChacha20_Nonces[0].begin(), ExtendedChacha20_Nonces[0].end(), std::back_inserter(ExtendedChacha20_Key));
				std::ranges::copy(ExtendedChacha20_Nonces[2].begin(), ExtendedChacha20_Nonces[2].end(), std::back_inserter(ExtendedChacha20_Key));
				std::ranges::copy(ExtendedChacha20_Nonces[1].begin(), ExtendedChacha20_Nonces[1].end(), std::back_inserter(ExtendedChacha20_Key));
				std::ranges::copy(ExtendedChacha20_Nonces[3].begin(), ExtendedChacha20_Nonces[3].end(), std::back_inserter(ExtendedChacha20_Key));
				std::ranges::copy(ExtendedChacha20_Message.begin(), ExtendedChacha20_Message.end(), std::back_inserter(ExtendedChacha20_Key));

				CommonSecurity::ShuffleRangeData( ExtendedChacha20_Key.begin(), ExtendedChacha20_Key.end(), RNG_Xoshiro256 );
				std::destroy_at(&RNG_Xoshiro256);

				std::size_t X_Seed = ExtendedChacha20_Message[0] + ExtendedChacha20_Message[1] + ExtendedChacha20_Message[2] + ExtendedChacha20_Message[3];
				std::size_t Y_Seed = ExtendedChacha20_Nonces[0][0] + ExtendedChacha20_Nonces[1][0] + ExtendedChacha20_Nonces[2][0] + ExtendedChacha20_Nonces[3][0];
				CustomSecurity::DataObfuscator::CustomDataObfuscator<false> MyCustomDataObfuscator(X_Seed, Y_Seed);

				auto ExportedObfuscatorResultTable = this->ApplyCustomDataObfuscation<false>(X_Seed, Y_Seed, ExtendedChacha20_Key, true);

				X_Seed = 0;
				Y_Seed = 0;

				std::destroy_at(&ExportedObfuscatorResultTable);
			}

			std::vector<std::uint8_t> ExtendedChacha20_InitialKey(32, 0xFF);
			CommonSecurity::StreamDataCryptographic::ExtendedChaCha20 ExtendedChacha20_IETF(ExtendedChacha20_InitialKey);

			//Apply ExtendedChacha20-IETF
			//应用ExtendedChacha20-IETF

			std::vector<std::uint8_t> ThisProcessedMessage;
			for( auto& ExtendedChacha20_Nonce : ExtendedChacha20_Nonces )
			{
				std::vector<std::uint8_t> ExtendedChacha20_UsingKey = ExtendedChacha20_Key;
				std::vector<std::uint8_t> ThisProcessedMessage = CommonSecurity::StreamDataCryptographic::Helpers::Helper(ExtendedChacha20_IETF, ExtendedChacha20_Message, ExtendedChacha20_UsingKey, ExtendedChacha20_Nonce);
				HashMessageStringOfKeys.push_back( ASCII_Hexadecmial::byteArray2HexadecimalString(ThisProcessedMessage) );
				
				if(ExtendedChacha20_Message.empty())
					ThisProcessedMessage.swap(ExtendedChacha20_Message);
			}

			ExtendedChacha20_Nonces.clear();
			
			ExtendedChacha20_Key.clear();
			ExtendedChacha20_Key.shrink_to_fit();
			ExtendedChacha20_Message.clear();
			ExtendedChacha20_Message.shrink_to_fit();

			#endif

			//Apply the key hash message authentication code algorithm
			//应用 密钥散列消息认证码算法

			/*
				Note: The requirement of post-quantum cryptography for the length of the existing key must be greater than 512 bits.
				Because the performance of quantum computers in terms of processing speed, quantum computers use specific algorithms (Grover's deep search algorithm for associating large amounts of data) to calculate symmetric keys in half the time of traditional computers;
				So the original key length of 512 bits can only reach the minimum required security level proposed by post-quantum cryptography -- that is, 256 bits key length.
				
				注意：后量子密码学对于现有密钥长度的要求，必须大于512比特(bit)。
				因为从量子计算机逻辑运算的性能处理速度来讲，量子计算机它使用特定算法(Grover's 的关联大量数据的深度搜索算法)来计算对称密钥的破解时间是传统计算机的一半；
				所以原有长度为512比特的密钥，只能达到后量子密码学提出的最基本要求的安全等级——即256比特密钥长度。
			*/

			//512 bit / 8 bit = 64 byte
			constexpr std::size_t MessageBlockSize = ( (sizeof(std::uint32_t) * 4) * 8 * sizeof(std::uint32_t) ) / 8;

			for ( std::size_t index = 0, data_index = 0; index < HashMessageStringOfKeys.size(); ++index, ++data_index )
			{
				if(data_index > 4 - 1)
					data_index = 0;
				std::string HMAC_Password = HMAC_FunctionObject( this->HashersAssistantParameters_Instance, MultiPasswordString[ data_index ], MessageBlockSize, HashMessageStringOfKeys[ index ] );
				HashedTokenHexadecimalString.push_back( HMAC_Password );
			}
		}

		void AppendRandomByteData
		(
			CommonSecurity::PseudoRandomNumberEngine<CommonSecurity::RNG_ISAAC::isaac<8>>& PRNE,
			std::vector<std::uint8_t>& PasswordStreamBytes,
			std::size_t WantWordSize
		)
		{
			std::size_t ByteModulusSize = PasswordStreamBytes.size() % sizeof(std::uint32_t);
			std::size_t PaddingByteSize = sizeof(std::uint32_t) - ByteModulusSize;
			while(PaddingByteSize != 0)
			{
				PasswordStreamBytes.push_back( PRNE.GenerateNumber( std::numeric_limits<std::uint8_t>::min(), std::numeric_limits<std::uint8_t>::max(), true ) );
				--PaddingByteSize;
			}

			std::vector<std::uint32_t> PasswordStreamWords = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>( PasswordStreamBytes.data(), PasswordStreamBytes.size() );
			PasswordStreamBytes.clear();
			PasswordStreamBytes.shrink_to_fit();

			//Does it use a true random number generator?
			//是否使用真随机数生成器？
			if constexpr(false)
			{
				std::vector<std::uint32_t> RandomNumberSeedSequence = GenerateSecureRandomNumberSeedSequence<std::uint32_t>(PasswordStreamWords.size());
				PRNE.InitialBySeed<std::uint32_t, std::vector<std::uint32_t>::iterator>( RandomNumberSeedSequence.begin(), RandomNumberSeedSequence.end(), false );
			}
			else
			{
				PRNE.InitialBySeed<std::uint32_t, std::vector<std::uint32_t>::iterator>( PasswordStreamWords.begin(), PasswordStreamWords.end(), false );
			}

			CommonSecurity::ShuffleRangeData( PasswordStreamWords.begin(), PasswordStreamWords.end(), PRNE.random_generator );

			for (std::size_t have_counter = 0, want_counter = WantWordSize; have_counter != want_counter; ++have_counter )
			{
				PasswordStreamWords.push_back( PRNE.GenerateNumber( std::numeric_limits<std::uint32_t>::min(), std::numeric_limits<std::uint32_t>::max(), true ) );
			}

			CommonSecurity::ShuffleRangeData( PasswordStreamWords.begin(), PasswordStreamWords.end(), PRNE.random_generator );

			PasswordStreamBytes = CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>( PasswordStreamWords.data(), PasswordStreamWords.size() );
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(PasswordStreamWords.data(), sizeof(std::uint32_t) * PasswordStreamWords.size());
			if(CheckPointer != PasswordStreamWords.data())
			{
				throw std::runtime_error("Force Memory Fill Has Been \"Optimization\" !");
			}


			PasswordStreamWords.clear();
			PasswordStreamWords.shrink_to_fit();
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

		~HashTokenForData()
		{
			volatile void* CheckPointer = nullptr;

			for( auto& StringData : OriginalPasswordStrings )
			{
				memory_set_no_optimize_function<0x00>(StringData.data(), StringData.size());
				if(CheckPointer != StringData.data())
				{
					throw std::runtime_error("Force Memory Fill Has Been \"Optimization\" !");
				}
			}

			OriginalPasswordStrings.clear();
			OriginalPasswordStrings.shrink_to_fit();
		}

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

			auto lambda_ResetGeneratePasswordStreamHashByteTokenSize = [](std::size_t GeneratePasswordStreamHashByteTokenSize, std::size_t ThatNumber) -> std::size_t
			{
				if(ThatNumber == 0)
				{
					ThatNumber = 1;
				}

				std::size_t QuotientCount = GeneratePasswordStreamHashByteTokenSize / ThatNumber;
				std::size_t RemainderCount = GeneratePasswordStreamHashByteTokenSize % ThatNumber;
				std::size_t FactorCount = QuotientCount > RemainderCount ? QuotientCount - RemainderCount : RemainderCount - QuotientCount;
				return FactorCount * ThatNumber;
			};

			/*
				Note: The requirement of post-quantum cryptography for the length of the existing key must be greater than 512 bits.
				Because the performance of quantum computers in terms of processing speed, quantum computers use specific algorithms (Grover's deep search algorithm for associating large amounts of data) to calculate symmetric keys in half the time of traditional computers;
				So the original key length of 512 bits can only reach the minimum required security level proposed by post-quantum cryptography -- that is, 256 bits key length.
				
				注意：后量子密码学对于现有密钥长度的要求，必须大于512比特(bit)。
				因为从量子计算机逻辑运算的性能处理速度来讲，量子计算机它使用特定算法(Grover's 的关联大量数据的深度搜索算法)来计算对称密钥的破解时间是传统计算机的一半；
				所以原有长度为512比特的密钥，只能达到后量子密码学提出的最基本要求的安全等级——即256比特密钥长度。
			*/
			std::size_t GeneratePasswordStreamHashByteTokenSize = this->NeedHashByteTokenSize < 64 ? 64 : this->NeedHashByteTokenSize;

			if((GeneratePasswordStreamHashByteTokenSize > 1024) && (GeneratePasswordStreamHashByteTokenSize % 1024) != 0)
			{
				GeneratePasswordStreamHashByteTokenSize = lambda_ResetGeneratePasswordStreamHashByteTokenSize(GeneratePasswordStreamHashByteTokenSize, 1024);
			}
			else
			{
				if(GeneratePasswordStreamHashByteTokenSize % 8 != 0)
				{
					GeneratePasswordStreamHashByteTokenSize = lambda_ResetGeneratePasswordStreamHashByteTokenSize(GeneratePasswordStreamHashByteTokenSize, 8);
				}
			}

			CommonSecurity::PseudoRandomNumberEngine<CommonSecurity::RNG_ISAAC::isaac<8>> PRNE;

			if constexpr (mode == CommonSecurity::SHA::Hasher::WORKER_MODE::ARGON2)
			{
				using CommonSecurity::KDF::Argon2::Constants::WORDS_MEMORY_BLOCK_SIZE;
				using CommonSecurity::KDF::Argon2::Argon2_Parameters;
				using CommonSecurity::KDF::Argon2::Argon2;
				using CommonSecurity::KDF::Argon2::AlgorithmVersion;
				using CommonSecurity::KDF::Argon2::HashModeTypeStringAlphabetFormat;
				using CommonSecurity::KDF::Argon2::HashModeType;

				std::vector<std::uint8_t> PasswordStreamBytes;
				std::vector<std::uint8_t> PasswordStreamSaltBytes;

				std::string ConactenatedPasswordString =
					this->OriginalPasswordStrings[0]
					+ this->OriginalPasswordStrings[1]
					+ this->OriginalPasswordStrings[2]
					+ this->OriginalPasswordStrings[3];

				for( auto& CharacterData : ConactenatedPasswordString )
				{
					PasswordStreamSaltBytes.push_back(static_cast<std::uint8_t>(CharacterData));
					PasswordStreamBytes.push_back(static_cast<std::uint8_t>(CharacterData));
				}

				ConactenatedPasswordString.clear();

				this->AppendRandomByteData(PRNE, PasswordStreamSaltBytes, PasswordStreamSaltBytes.size() * sizeof(std::uint32_t));

				std::vector<std::uint8_t> PasswordStreamHashedToken_Bytes( GeneratePasswordStreamHashByteTokenSize, 0 );

				std::size_t ThreadNumber = std::thread::hardware_concurrency();

				if( GeneratePasswordStreamHashByteTokenSize / (sizeof(std::uint64_t) * WORDS_MEMORY_BLOCK_SIZE) == 0 )
				{
					GeneratePasswordStreamHashByteTokenSize *= (sizeof(std::uint64_t) * WORDS_MEMORY_BLOCK_SIZE);
				}
				std::size_t MemoryByteSize = try_allocate_temporary_memory_size(GeneratePasswordStreamHashByteTokenSize * (sizeof(std::uint64_t) * WORDS_MEMORY_BLOCK_SIZE)).value();
				std::size_t MemoryBlockSpaceNumber = MemoryByteSize / (sizeof(std::uint64_t) * WORDS_MEMORY_BLOCK_SIZE);
				std::size_t TimeIterationNumber = MemoryBlockSpaceNumber % 128 == 0 ? MemoryBlockSpaceNumber / 128 : (MemoryBlockSpaceNumber % 128) * 2;

				Argon2_Parameters Argon2KDF_ParameterObject
				(
					PasswordStreamHashedToken_Bytes,
					GeneratePasswordStreamHashByteTokenSize,
					PasswordStreamBytes,
					PasswordStreamSaltBytes,
					TimeIterationNumber,
					MemoryBlockSpaceNumber,
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

				Argon2KDF_Object.Hash<std::vector<std::uint8_t>>(PasswordStreamHashedToken_Bytes);
				PasswordStreamBytes.clear();
				PasswordStreamBytes.swap(PasswordStreamHashedToken_Bytes);

				ThreadNumber = std::thread::hardware_concurrency() / 4;
				
				Argon2KDF_ParameterObject = Argon2_Parameters
				(
					PasswordStreamHashedToken_Bytes,
					GeneratePasswordStreamHashByteTokenSize,
					PasswordStreamBytes,
					PasswordStreamSaltBytes,
					TimeIterationNumber,
					MemoryBlockSpaceNumber,
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
				Argon2KDF_Object.Hash<std::vector<std::uint8_t>>(PasswordStreamHashedToken_Bytes);

				if(PasswordStreamHashedToken_Bytes.size() < GeneratePasswordStreamHashByteTokenSize)
				{
					//Append byte data

					this->AppendRandomByteData(PRNE, PasswordStreamHashedToken_Bytes, (GeneratePasswordStreamHashByteTokenSize - PasswordStreamHashedToken_Bytes.size()) / sizeof(std::uint32_t) );

					HashKeyStreamTokenResultObject.HashKeyStreamToken_String = UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString(PasswordStreamHashedToken_Bytes);
					HashKeyStreamTokenResultObject.HashKeyStreamToken_Bytes = std::move(PasswordStreamHashedToken_Bytes);

					PasswordStreamHashedToken_Bytes.clear();
					PasswordStreamHashedToken_Bytes.shrink_to_fit();
				}
				else
				{
					//Truncation byte data

					if (PasswordStreamHashedToken_Bytes.size() > GeneratePasswordStreamHashByteTokenSize)
					{
						PasswordStreamHashedToken_Bytes.resize(GeneratePasswordStreamHashByteTokenSize);
					}

					HashKeyStreamTokenResultObject.HashKeyStreamToken_String = UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString(PasswordStreamHashedToken_Bytes);
					HashKeyStreamTokenResultObject.HashKeyStreamToken_Bytes = std::move(PasswordStreamHashedToken_Bytes);

					PasswordStreamHashedToken_Bytes.clear();
					PasswordStreamHashedToken_Bytes.shrink_to_fit();
				}

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
				constexpr std::array<std::uint32_t, 4> MagicNumberConstantArray { 0x4005bf0a, 0x8b145769, 0x400921fb, 0x54442d18 };

				//Execute Super TEA "Encrypt" Operation
				for(auto& PasswordString : MultiPasswordString)
				{
					while (PasswordString.size() % sizeof(std::uint32_t) != 0)
						PasswordString.push_back(0);

					std::vector<std::uint8_t> classic_bytes{ PasswordString.data(), PasswordString.data() + PasswordString.size() };
					std::span<const std::uint8_t> classic_bytes_span { classic_bytes };
					std::vector<std::uint32_t> word_ascii_codes(classic_bytes_span.size() / 4);
					std::span<const std::uint32_t> word_ascii_codes_span { word_ascii_codes };
					
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
					while (PasswordString.size() % sizeof(std::uint32_t) != 0)
						PasswordString.push_back(0);

					std::vector<std::uint8_t> classic_bytes{ PasswordString.data(), PasswordString.data() + PasswordString.size() };
					std::span<const std::uint8_t> classic_bytes_span { classic_bytes };
					std::vector<std::uint32_t> word_ascii_codes( classic_bytes_span.size() / 4 );
					std::span<const std::uint32_t> word_ascii_codes_span { word_ascii_codes };
					
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

				std::vector<std::uint8_t> PasswordStreamHashedToken_Bytes;

				std::string CurrentConcatenatedHashedTokenHexadecimalString =
					HashedTokenHexadecimalString[0]
					+ HashedTokenHexadecimalString[1]
					+ HashedTokenHexadecimalString[2]
					+ HashedTokenHexadecimalString[3];

				HashedTokenHexadecimalString.clear();
				HashedTokenHexadecimalString.shrink_to_fit();

				for(const auto& ClassByte : CurrentConcatenatedHashedTokenHexadecimalString)
				{
					PasswordStreamHashedToken_Bytes.push_back(static_cast<std::uint8_t>(ClassByte));
				}
				CurrentConcatenatedHashedTokenHexadecimalString.clear();
				CurrentConcatenatedHashedTokenHexadecimalString.shrink_to_fit();

				if(PasswordStreamHashedToken_Bytes.size() < GeneratePasswordStreamHashByteTokenSize)
				{
					//Append byte data

					this->AppendRandomByteData(PRNE, PasswordStreamHashedToken_Bytes, (GeneratePasswordStreamHashByteTokenSize - PasswordStreamHashedToken_Bytes.size()) / sizeof(std::uint32_t) );

					HashKeyStreamTokenResultObject.HashKeyStreamToken_String = UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString(PasswordStreamHashedToken_Bytes);
					HashKeyStreamTokenResultObject.HashKeyStreamToken_Bytes = std::move(PasswordStreamHashedToken_Bytes);

					PasswordStreamHashedToken_Bytes.clear();
					PasswordStreamHashedToken_Bytes.shrink_to_fit();
				}
				else
				{
					//Truncation byte data

					if (PasswordStreamHashedToken_Bytes.size() > GeneratePasswordStreamHashByteTokenSize)
					{
						PasswordStreamHashedToken_Bytes.resize(GeneratePasswordStreamHashByteTokenSize);
					}

					HashKeyStreamTokenResultObject.HashKeyStreamToken_String = UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString(PasswordStreamHashedToken_Bytes);
					HashKeyStreamTokenResultObject.HashKeyStreamToken_Bytes = std::move(PasswordStreamHashedToken_Bytes);

					PasswordStreamHashedToken_Bytes.clear();
					PasswordStreamHashedToken_Bytes.shrink_to_fit();
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
