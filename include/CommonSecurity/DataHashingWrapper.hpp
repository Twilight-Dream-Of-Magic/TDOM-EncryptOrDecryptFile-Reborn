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
	//哈希器助手
	//Hashers' Assistant
	struct HashersAssistant
	{

	private:
		void SHA_Version2( std::string& inputDataString, std::string& outputHashedHexadecimalString ) const;
		void SHA_Version3( std::string& inputDataString, std::string& outputHashedHexadecimalString ) const;
		void China_ShangYongMiMa3( std::string& inputDataString, std::string& outputHashedHexadecimalString ) const;

	public:
		static void SELECT_HASH_FUNCTION(const HashersAssistant& thisInstance, const CommonSecurity::SHA::Hasher::WORKER_MODE& mode, std::string& inputDataString, std::string& outputHashedHexadecimalString);
			
		HashersAssistant() = default;
		~HashersAssistant() = default;

		HashersAssistant( const HashersAssistant& _object) = delete;
	};

	//Digest hash bit 512
	void HashersAssistant::SHA_Version2( std::string& inputDataString, std::string& outputHashedHexadecimalString ) const
	{
		using namespace CommonSecurity::SHA::Version2;

		std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools> hasherClassPointer = std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools>();
		std::optional<std::string> optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512, inputDataString );
		hasherClassPointer = nullptr;

		if(optionalHashedHexadecimalString.has_value())
			optionalHashedHexadecimalString.value().swap(outputHashedHexadecimalString);
		else
			throw std::invalid_argument(" If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");
	}

	//Digest hash bit 512
	void HashersAssistant::SHA_Version3( std::string& inputDataString, std::string& outputHashedHexadecimalString ) const
	{
		using namespace CommonSecurity::SHA::Version3;

		std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools> hasherClassPointer = std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools>();
		std::optional<std::string> optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512, inputDataString );
		hasherClassPointer = nullptr;

		if(optionalHashedHexadecimalString.has_value())
			optionalHashedHexadecimalString.value().swap(outputHashedHexadecimalString);
		else
			throw std::invalid_argument(" If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");
	}

	//Digest hash bit 256
	void HashersAssistant::China_ShangYongMiMa3( std::string& inputDataString, std::string& outputHashedHexadecimalString ) const
	{
		using namespace CommonSecurity::SHA::Version2;

		std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools> hasherClassPointer = std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools>();
		std::optional<std::string> optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3, inputDataString );
		hasherClassPointer = nullptr;

		if(optionalHashedHexadecimalString.has_value())
			optionalHashedHexadecimalString.value().swap(outputHashedHexadecimalString);
		else
			throw std::invalid_argument(" If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");
	}

	void HashersAssistant::SELECT_HASH_FUNCTION(const HashersAssistant& thisInstance, const CommonSecurity::SHA::Hasher::WORKER_MODE& mode, std::string& inputDataString, std::string& outputHashedHexadecimalString)
	{
		switch (mode)
        {
			case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512:
			{
				thisInstance.SHA_Version3(inputDataString, outputHashedHexadecimalString);
				break;
			}
			case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512:
			{
				thisInstance.SHA_Version2(inputDataString, outputHashedHexadecimalString);
				break;
			}
			case CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3:
			{
				thisInstance.China_ShangYongMiMa3(inputDataString, outputHashedHexadecimalString);
				break;
			}
			default:
				break;
        }
	}

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

	/**
	*	https://zh.wikipedia.org/wiki/HMAC
	*	密钥散列消息认证码（英语：Keyed-hash message authentication code），又称散列消息认证码（Hash-based message authentication code，缩写为HMAC）
	*	是一种通过特别计算方式之后产生的消息认证码（MAC），使用密码散列函数，同时结合一个加密密钥。
	*	它可以用来保证资料的完整性，同时可以用来作某个消息的身份验证。
	*	https://en.wikipedia.org/wiki/HMAC
	*	In cryptography, an HMAC (sometimes expanded as either keyed-hash message authentication code or hash-based message authentication code)
	*	is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. 
	*	As with any MAC, it may be used to simultaneously verify both the data integrity and authenticity of a message.
	*	HMAC can provide authentication using a shared secret instead of using digital signatures with asymmetric cryptography.
	*	It trades off the need for a complex public key infrastructure by delegating the key exchange to the communicating parties, who are responsible for establishing and using a trusted channel to agree on the key prior to communication.
	*/
	class HMAC_Worker
	{

	private:
		struct AlgorithmImplementation
		{
			std::string CalculationMessageAuthenticationCode( const HashersAssistant& HashersAssistant_Instance, const CommonSecurity::SHA::Hasher::WORKER_MODE& mode, const std::string& Message, const std::size_t& MessageBlockSize, std::string Key )
			{
				// Outer padded key
				static constexpr char OuterPaddingKey = 0x5c;
				// Inner padded key
				static constexpr char InnerPaddingKey = 0x36;

				std::string KeyPaddings;
				std::string OuterPaddedKeys;
				std::string InnerPaddedKeys;
				KeyPaddings.resize( MessageBlockSize, 0x00 );
				OuterPaddedKeys.resize( MessageBlockSize, 0x00 );
				InnerPaddedKeys.resize( MessageBlockSize, 0x00 );

				// Compute the block sized key
				auto lambda_ComputeBlockSizedKey = [ & ]( std::string Key, std::size_t KeySize )
				{
					std::string KeyHashed;

					if ( KeySize > MessageBlockSize )
					{
						// Keys longer than blockSize are shortened by hashing them

						HashersAssistant::SELECT_HASH_FUNCTION( HashersAssistant_Instance, mode, Key, KeyHashed );
						Key = KeyHashed;
						KeyHashed.clear();
					}
					else if ( KeySize < MessageBlockSize )
					{
						// Keys shorter than blockSize are padded to blockSize by padding with zeros on the right

						for ( std::size_t index = 0; index < MessageBlockSize; ++index )
						{
							// Pad key with zeros to make it blockSize bytes long
							if ( index < MessageBlockSize - KeySize )
							{
								KeyPaddings[ index ] = 0x00;
							}
							else
							{
								KeyPaddings[ index ] = Key[ index - ( MessageBlockSize - KeySize ) ];
							}
						}
					}
				};

				lambda_ComputeBlockSizedKey( Key, Key.size() );

				for ( std::size_t index = 0; index < MessageBlockSize; ++index )
				{
					OuterPaddedKeys[ index ] = KeyPaddings[ index ] ^ OuterPaddingKey;
				}

				for ( std::size_t index = 0; index < MessageBlockSize; ++index )
				{
					InnerPaddedKeys[ index ] = KeyPaddings[ index ] ^ InnerPaddingKey;
				}

				std::string data = InnerPaddedKeys + Message;
				std::string dataHashed;
				HashersAssistant::SELECT_HASH_FUNCTION( HashersAssistant_Instance, mode, data, dataHashed );

				std::string data2 = OuterPaddedKeys + dataHashed;
				std::string data2Hashed;
				HashersAssistant::SELECT_HASH_FUNCTION( HashersAssistant_Instance, mode, data2, data2Hashed );
				
				data.clear();
				data2.clear();

				return data2Hashed;
			}
		};

		std::unique_ptr<AlgorithmImplementation> HMAC_Pointer = std::unique_ptr<AlgorithmImplementation>();
		std::atomic<bool> whether_occupied = false;

	public:
		std::string operator()( const HashersAssistant& HashersAssistant_Instance, const CommonSecurity::SHA::Hasher::WORKER_MODE& mode, const std::string& Message, const std::size_t& MessageBlockSize, std::string Key )
		{
			whether_occupied.wait(true, std::memory_order::seq_cst);

			whether_occupied.store(true, std::memory_order::seq_cst);
			std::string HMAC_String = HMAC_Pointer.get()->CalculationMessageAuthenticationCode( HashersAssistant_Instance, mode, Message, MessageBlockSize, Key );
			whether_occupied.store(false, std::memory_order::relaxed);
			whether_occupied.notify_all();
			return HMAC_String;
		}
	};

	HMAC_Worker HMAC_FunctionObject;

	//数据的哈希令牌
	//Hash tokens for data
	class HashTokenForData
	{

	private:
			
		static constexpr HashersAssistant HashersAssistant_Instance = HashersAssistant();

		std::vector<std::string> PreProcessWithMultiPasswordByHasherAssistant( CommonSecurity::SHA::Hasher::WORKER_MODE mode, std::vector<std::string> MultiPasswordString )
		{
			std::vector<std::string> HashedStringFromMultiPassword;
			HashedStringFromMultiPassword.reserve( MultiPasswordString.size() );
			std::string PasswordHashed;

			for ( auto beginIterator = MultiPasswordString.begin(), endIterator = MultiPasswordString.end(); beginIterator != endIterator; ++beginIterator )
			{
				//Make Original Processed Hash Message Key
				HashersAssistant::SELECT_HASH_FUNCTION( HashersAssistant_Instance, mode, *beginIterator, PasswordHashed );
				HashedStringFromMultiPassword.push_back( PasswordHashed );
			}

			return HashedStringFromMultiPassword;
		}

		void PostProcessFromHashedStringToGenerateToken( CommonSecurity::SHA::Hasher::WORKER_MODE mode, std::vector<std::string>& MultiPasswordString, std::vector<std::string>& MultiPasswordHashedString, std::string& HashedTokenHexadecimalString )
		{
			using namespace CommonSecurity;
			using namespace UtilTools::DataFormating;
			using namespace UtilTools::DataStreamConverter;
				
			//Magic number from std::cout << std::hex << *reinterpret_cast<const unsigned long long *>(&std::numbers::e) << std::endl;
			//Magic number from std::cout << std::hex << *reinterpret_cast<const unsigned long long *>(&std::numbers::pi) << std::endl;
			constexpr std::array<unsigned int, 4> MagicNumberConstantArray { 0x4005bf0a, 0x8b145769, 0x400921fb, 0x54442d18 };

			//Execute Super TEA "Encrypt" Operation
			for(auto& PasswordString : MultiPasswordString)
			{
				while (PasswordString.size() % sizeof(unsigned int) != 0)
				{
					PasswordString.push_back(0);
				}

				std::vector<unsigned char> classic_bytes{ PasswordString.data(), PasswordString.data() + PasswordString.size() };
				std::span<const unsigned char> classic_bytes_span { classic_bytes };
				std::vector<unsigned int> word_ascii_codes(classic_bytes_span.size() / 4);
				std::span<const unsigned int> word_ascii_codes_span { word_ascii_codes };
					
				CommonSecurity::MessagePacking(classic_bytes_span, word_ascii_codes.data());

				CommonSecurity::CorrectedBlockTEA::SuperTEA(word_ascii_codes.data(), word_ascii_codes.size(), true, MagicNumberConstantArray);

				CommonSecurity::MessageUnpacking(word_ascii_codes_span, classic_bytes.data());

				std::string ProcessedPasswordString { classic_bytes.data(), classic_bytes.data() + classic_bytes.size() };

				PasswordString.swap(ProcessedPasswordString);

				word_ascii_codes.clear();
				word_ascii_codes.shrink_to_fit();
				classic_bytes.clear();
				classic_bytes.shrink_to_fit();
				ProcessedPasswordString.clear();
			}

			std::string HashMessage;
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
			//Pseudo-random number generation engine to disrupt container ordering
			CommonSecurity::ShuffleRangeData( CombinedMultiPasswordString.begin(), CombinedMultiPasswordString.end(), random_generator );

			MultiPasswordString.clear();
			MultiPasswordString.shrink_to_fit();

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

			std::size_t CombinedString_PartSize = CombinedMultiPasswordString.size() / 4;
			for(auto begin = CombinedMultiPasswordString.begin(), end = CombinedMultiPasswordString.end(); begin != end; begin += CombinedString_PartSize)
			{
				std::size_t iterator_offset = CommonToolkit::IteratorOffsetDistance(begin, end, CombinedString_PartSize);
				MultiPasswordString.push_back(std::string(begin, begin + iterator_offset));
			}
				
			//Execute Super TEA "Decrypt" Operation
			for(auto& PasswordString : MultiPasswordString)
			{
				while (PasswordString.size() % sizeof(unsigned int) != 0)
				{
					PasswordString.push_back(0);
				}

				std::vector<unsigned char> classic_bytes{ PasswordString.data(), PasswordString.data() + PasswordString.size() };
				std::span<const unsigned char> classic_bytes_span { classic_bytes };
				std::vector<unsigned int> word_ascii_codes( classic_bytes_span.size() / 4 );
				std::span<const unsigned int> word_ascii_codes_span { word_ascii_codes };
					
				CommonSecurity::MessagePacking( classic_bytes_span, word_ascii_codes.data() );

				CommonSecurity::CorrectedBlockTEA::SuperTEA( word_ascii_codes.data(), word_ascii_codes.size(), false, MagicNumberConstantArray );

				CommonSecurity::MessageUnpacking( word_ascii_codes_span, classic_bytes.data() );

				std::string ProcessedPasswordString { classic_bytes.data(), classic_bytes.data() + classic_bytes.size() };

				PasswordString.swap( ProcessedPasswordString );

				word_ascii_codes.clear();
				word_ascii_codes.shrink_to_fit();
				classic_bytes.clear();
				classic_bytes.shrink_to_fit();
				ProcessedPasswordString.clear();
			}

			CombinedMultiPasswordString = MultiPasswordString[ 0 ] + MultiPasswordString[ 1 ] + MultiPasswordString[ 2 ] + MultiPasswordString[ 3 ];

			MultiPasswordString.clear();
			MultiPasswordString.shrink_to_fit();

			//Make Original Processed Hash Message
			HashersAssistant::SELECT_HASH_FUNCTION( HashersAssistant_Instance, mode, CombinedMultiPasswordString, HashMessage );

			#if defined(HMAC_TOKEN_BITSET_OPTERATION)

			BitSetOperation<512>(sourceBinaryStrings, targetBinaryStrings);

			#endif

			std::vector<std::string> hexadecimalKeyStrings;
			hexadecimalKeyStrings.resize( targetBinaryStrings.size() );

			for ( std::size_t index = 0; index < targetBinaryStrings.size(); ++index )
			{
				hexadecimalKeyStrings[ index ] = Hexadecimal_Binary::ToHexadecimal( targetBinaryStrings[ index ], AlphabetFormat::UPPER_CASE );
			}

			constexpr std::size_t MessageBlockSize = 512 / 8;

			for ( std::size_t index = 0; index < hexadecimalKeyStrings.size(); ++index )
			{
				std::string HMAC_Password = HMAC_FunctionObject( HashersAssistant_Instance, mode, HashMessage, MessageBlockSize, hexadecimalKeyStrings[ index ] );
				HashedTokenHexadecimalString.append( HMAC_Password );
			}
		}

	public:

		//生成个性置换令牌函数（通过4个密码处理产生的哈希值）
		//生成个性逆置换令牌函数（通过4个密码处理产生的哈希值）
		static std::optional<std::string> GenerateHashToken( const CommonSecurity::SHA::Hasher::WORKER_MODE& mode, const std::vector<std::string>& passwords );

		HashTokenForData() = default;
		~HashTokenForData() = default;

		HashTokenForData(HashTokenForData& _object) = delete;
		HashTokenForData& operator=(const HashTokenForData& _object) = delete;
	};

	std::optional<std::string> HashTokenForData::GenerateHashToken(const CommonSecurity::SHA::Hasher::WORKER_MODE& mode, const std::vector<std::string>& passwords )
	{
		if(passwords.size() == 0)
		{
			return std::nullopt;
		}
		else
		{
			std::unique_ptr<HashTokenForData> HashTokenHelperPointer = std::unique_ptr<HashTokenForData>();

			std::string HashedTokenHexadecimalString;

			std::vector<std::string> MultiPasswordString;
			MultiPasswordString.reserve( passwords.size() );

			std::vector<std::string> MultiPasswordHashedString;
			MultiPasswordHashedString.reserve( passwords.size() );

			for(const auto& password : passwords )
			{
				MultiPasswordString.push_back(password);
			}

			//Hashing function by Standard security hash algorithm
			MultiPasswordHashedString = HashTokenHelperPointer.get()->PreProcessWithMultiPasswordByHasherAssistant( mode, MultiPasswordString );
			HashTokenHelperPointer.get()->PostProcessFromHashedStringToGenerateToken( mode, MultiPasswordString, MultiPasswordHashedString, HashedTokenHexadecimalString );
			HashTokenHelperPointer = nullptr;

			return std::make_optional<std::string>(HashedTokenHexadecimalString);
		}
	}

	#endif	//! HMAC_TOKEN

}

#ifdef HMAC_TOKEN
#undef HMAC_TOKEN
#endif //! HMAC_TOKEN
