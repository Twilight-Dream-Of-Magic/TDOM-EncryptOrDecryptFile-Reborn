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

//#define USE_MEMORY_TRACKER_CODE
//#define PRINT_MEMORY_TRACKING_INFORATION

#include "Support+Library/Support-MyType.hpp"

#include "UtilTools/UtilTools.hpp"
#include "CommonToolkit/CommonToolkit.hpp"

#include "CommonSecurity/CommonSecurity.hpp"
#include "CommonSecurity/SecureHashProvider/Hasher.hpp"
#include "CustomSecurity/CryptionWorker.hpp"
#include "CustomSecurity/CrypticDataThreadingWrapper.hpp"
#include "CommonSecurity/BlockDataCryption.hpp"

#include "ThreadingToolkit/Pool/Version1/ThreadPool.hpp"
#include "ThreadingToolkit/Pool/Version2/ThreadPool.hpp"
#include "ThreadingToolkit/Pool/Version3/ThreadPool.hpp"
#include "ThreadingToolkit/Time/TimedThreadExecutor.hpp"
#include "ThreadingToolkit/Wrapper/AsyncTaskWrapper.hpp"

#include "FileProcessing/FileProcessing.hpp"
#include "FileProcessing/MemoryMappingByFile.hpp"

#ifndef HMAC_TOKEN
#define HMAC_TOKEN
#endif // !HMAC_TOKEN

/**
*	@file IsFor_EODF_Reborn.hpp
*
*	@brief 加密或解密文件重生版本 - 实用工具
*	@brief Encrypting or Decrypting File Reborn Versions - Utility tools
*
*	作者成员：
*	Author Members:
*
*	@author Project Owner and Module Designer: Twilight-Dream
*	@author Algorithm Designer: Spiritual-Fish
*	@author Tech Supporter : XiLiuFeng
* 
*	功能名：隐秘的奥尔德雷斯之谜
*	Function Name: OaldresPuzzle-Cryptic
*
*	@details
*	项目反馈URL (Github/GitLab/Gitee):
*	Project Feedback URL (Github/GitLab/Gitee):
*
*	联系方式:
*	Contact details:
*	
*		With by bilibili website personal space:
*		Twilight-Dream https://space.bilibili.com/21974189
*		Spiritual-Fish https://space.bilibili.com/1545018134
*		XiLiuFeng https://space.bilibili.com/4357220
*
*	All copyrights reserved from ©2021 year forward (Author Members)
*	保留所有权利，从@2021年开始 (作者成员)
*/
namespace EODF_Reborn
{
	//数据哈希化
	//Data hashing
	namespace Data_Hashing
	{
		using namespace CommonSecurity::SHA;

		//哈希器助手
		//Hashers' Assistant
		struct HashersAssistant
		{

		public:

			static void VERSION2_BIT512( std::string& inputDataString, std::string& outputHashedHexadecimalString );
			static void VERSION3_BIT512( std::string& inputDataString, std::string& outputHashedHexadecimalString );
		};

		void HashersAssistant::VERSION2_BIT512( std::string& inputDataString, std::string& outputHashedHexadecimalString )
		{
			using namespace Version2;

			Hasher::HasherTools* hasherClassPointer = new Hasher::HasherTools();
			outputHashedHexadecimalString = hasherClassPointer->GenerateHashed( Hasher::WORKER_MODE::SHA2_512, inputDataString );
			delete hasherClassPointer;
			hasherClassPointer = nullptr;
		}

		void HashersAssistant::VERSION3_BIT512( std::string& inputDataString, std::string& outputHashedHexadecimalString )
		{
			using namespace Version3;

			Hasher::HasherTools* hasherClassPointer = new Hasher::HasherTools();
			outputHashedHexadecimalString = hasherClassPointer->GenerateHashed( Hasher::WORKER_MODE::SHA3_512, inputDataString );
			delete hasherClassPointer;
			hasherClassPointer = nullptr;
		}

		#if defined( HMAC_TOKEN )

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

		//数据的哈希令牌
		//Hash tokens for data
		class HashTokenForData
		{

		private:

			void SelectHashFunction(Hasher::WORKER_MODE mode, std::string& inputDataString, std::string& outputHashedHexadecimalString)
			{
				switch (mode)
                {

					case Hasher::WORKER_MODE::SHA3_512:
					{
						HashersAssistant::VERSION3_BIT512(inputDataString, outputHashedHexadecimalString);
						break;
					}
					case Hasher::WORKER_MODE::SHA2_512:
					{
						HashersAssistant::VERSION2_BIT512(inputDataString, outputHashedHexadecimalString);
						break;
					}
					/*
					case Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3:
					{
						HashersAssistant::CHINA_SHANG_YONG_MI_MA3_BIT256(inputDataString, outputHashedHexadecimalString);
						break;
					}
					*/
					default:
						break;
                }
			}
			
			std::vector<std::string> PreProcessTokenWithMultiPasswordByHasherAssistant( Hasher::WORKER_MODE mode, std::vector<std::string> MultiPasswordString )
			{
				std::vector<std::string> HashedStringFromMultiPassword;
				HashedStringFromMultiPassword.reserve( MultiPasswordString.size() );
				std::string PasswordHashed;

				for ( auto beginIterator = MultiPasswordString.begin(), endIterator = MultiPasswordString.end(); beginIterator != endIterator; ++beginIterator )
				{
					//Make Original Processed Hash Message Key
					SelectHashFunction(mode, *beginIterator, PasswordHashed);
					HashedStringFromMultiPassword.push_back( PasswordHashed );
				}

				return HashedStringFromMultiPassword;
			}

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
			std::string HMAC_Calculation( Hasher::WORKER_MODE mode, std::string Message, const std::size_t& MessageBlockSize, std::string Key )
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

						SelectHashFunction( mode, Key, KeyHashed );
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
				SelectMode_SHA( mode, data, dataHashed );

				std::string data2 = OuterPaddedKeys + dataHashed;
				std::string data2Hashed;
				SelectMode_SHA( mode, data2, data2Hashed );

				return data2Hashed;
			}

			void ToGenerateTokenFromHashedString( Hasher::WORKER_MODE mode, std::vector<std::string>& MultiPasswordString, std::vector<std::string>& MultiPasswordHashedString, std::string& HashedTokenHexadecimalString )
			{
				using namespace CommonSecurity;
				using namespace UtilTools::DataFormating;
				using namespace UtilTools::DataStreamConverter;

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

				SelectMode_SHA( mode, CombinedMultiPasswordString, HashMessage );

				if ( mode == Hasher::WORKER_MODE::SHA2_512 || mode == Hasher::WORKER_MODE::SHA3_512)
				{
					BitSetOperation<512>(sourceBinaryStrings, targetBinaryStrings);
				}

				std::vector<std::string> hexadecimalKeyStrings;
				hexadecimalKeyStrings.resize( targetBinaryStrings.size() );

				for ( std::size_t index = 0; index < targetBinaryStrings.size(); ++index )
				{
					hexadecimalKeyStrings[ index ] = Hexadecimal_Binary::ToHexadecimal( targetBinaryStrings[ index ], AlphabetFormat::UPPER_CASE );
				}

				constexpr std::size_t MessageBlockSize = 512 / 8;

				for ( std::size_t index = 0; index < hexadecimalKeyStrings.size(); ++index )
				{
					std::string HMAC_Password = HMAC_Calculation( mode, HashMessage, MessageBlockSize, hexadecimalKeyStrings[ index ] );
					HashedTokenHexadecimalString.append( HMAC_Password );
				}
			}

		public:

			//生成个性置换令牌函数（通过4个密码处理产生的哈希值）
			//生成个性逆置换令牌函数（通过4个密码处理产生的哈希值）
			static std::optional<std::string> GenerateHashToken( Hasher::WORKER_MODE mode, const std::vector<std::string>& passwords );

			HashTokenForData() = default;
			~HashTokenForData() = default;

			HashTokenForData(HashTokenForData& _object) = delete;
			HashTokenForData& operator=(const HashTokenForData& _object) = delete;
		};

		std::optional<std::string> HashTokenForData::GenerateHashToken( Hasher::WORKER_MODE mode, const std::vector<std::string>& passwords )
		{
			if(passwords.size() == 0)
			{
				return std::nullopt;
			}
			else
			{
				HashTokenForData* HashTokenHelperPointer = new HashTokenForData();

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
				MultiPasswordHashedString = HashTokenHelperPointer->PreProcessTokenWithMultiPasswordByHasherAssistant( mode, MultiPasswordString );
				HashTokenHelperPointer->ToGenerateTokenFromHashedString( mode, MultiPasswordString, MultiPasswordHashedString, HashedTokenHexadecimalString );
				delete HashTokenHelperPointer;
				HashTokenHelperPointer = nullptr;

				return std::make_optional<std::string>(HashedTokenHexadecimalString);
			}
		}

		#endif	//! HMAC_TOKEN
	}	// namespace Data_Hashing

	// 压缩和解压缩文件数据过程处理
	// Compress and Decompress file data process handling
	namespace CompressDataProcessing
	{
		//文件数据压缩器
		//File data compressor
		class FileCompressor
		{
		};

		//文件数据解压缩器
		//File data decompressor
		class FileDecompressor
		{
		};

	}  // namespace CompressDataProcessing

	// 主程序模块实现
	// Main program module implementation
	namespace MainProgram_ModuleImplementation
	{
		//通过处理文件数据制作哈希摘要
		//Making hash digest by processing file data
		std::optional<std::string> MakeHashDigestByWithProcessingFileData(const std::filesystem::path& file_path_name)
		{
			using namespace MemoryObjectConfrontationDiskFileData;
			using namespace EODF_Reborn;
			using namespace UtilTools;
			using namespace CrypticDataThreadingWrapper;

			using namespace CommonSecurity::FNV_1a;
			using namespace MySupport_Library::ExperimentalExtensions;

			//RO is ReadOnly
			//RW is ReadAndWrite
			MIO_LibraryHelper::MemoryMapPointers ro_mmap_pointers_object = MIO_LibraryHelper::MakeDefaultMemoryMappingObject(MIO_LibraryHelper::MemoryMapTypes::SIGNED_READ_ONLY);
			auto& ro_mmap_pointer_reference  = ro_mmap_pointers_object.signed_ro();
			auto* managed_ro_mmap_pointer = ro_mmap_pointer_reference.get();

			//[packing and unpacking]
			//相关的内存映射对象数据，将会被进行打包和进行解包
			//The associated memory mapped object data will be packaged and unpacked
			
			mio::mmap_source mapped_ro_object;
			auto mmap_data_package = MIO_LibraryHelper::MappingMemoryMapObject_TryAssociateFile_ToPack(file_path_name, managed_ro_mmap_pointer);
			bool associated_mmap_data_package_status = MIO_LibraryHelper::MappedMemoryMapObject_FromUnpack(mmap_data_package, mapped_ro_object);

			if(associated_mmap_data_package_status)
			{
				std::size_t hashed_number {0};
				std::size_t hashed_number2 {0};
				std::size_t hashed_number3 {0};

				//Hashing function by FNV-1a algorithm
				Hasher::hash_combine hash_combine_object;
				constexpr std::size_t message_size = 4096;

				auto file_data_begin = mapped_ro_object.begin();
				auto file_data_end = mapped_ro_object.end();

				std::size_t	iteratorOffset;
				while (file_data_begin != file_data_end)
				{
					iteratorOffset = CommonToolkit::IteratorOffsetDistance( file_data_begin, file_data_end, message_size );
					if(iteratorOffset < message_size)
					{
						std::string temporary_string_data3 { file_data_begin, file_data_begin + iteratorOffset };
						hashed_number3 = hash_combine_object( temporary_string_data3 );

						hashed_number ^= hashed_number3;

						break;
					}
					else
					{
						auto file_part_data_begin = file_data_begin;
						auto file_part_data_end = file_data_begin + iteratorOffset;

						std::string temporary_string_data { file_part_data_begin, file_part_data_end };

						file_data_begin += iteratorOffset;

						iteratorOffset = CommonToolkit::IteratorOffsetDistance( file_data_begin, file_data_end, message_size );
						if(iteratorOffset < message_size)
						{
							continue;
						}
						else
						{
							file_part_data_begin = file_data_begin;
							file_part_data_end = file_data_begin + iteratorOffset;

							std::string temporary_string_data2 { file_part_data_begin, file_part_data_end };

							file_data_begin += iteratorOffset;

							if(!temporary_string_data.empty() && !temporary_string_data2.empty())
							{
								hashed_number = hash_combine_object( temporary_string_data );
								hashed_number2 = hash_combine_object( temporary_string_data2 );

								hashed_number ^= hashed_number2;
							}
							else
							{
								return std::nullopt;
							}
						}
					}
				}

				MIO_LibraryHelper::UnmappingMemoryMapObject(mapped_ro_object);

				std::string file_hash_string_part { std::move(DataStreamConverter::Integer2Hexadecimal(hashed_number)) };
				std::string file_hash_string_part2 { std::move(DataStreamConverter::Integer2Hexadecimal(hashed_number2)) };
				std::string file_hash_string_part3 { std::move(DataStreamConverter::Integer2Hexadecimal(hashed_number3)) };
				return file_hash_string_part + "-" + file_hash_string_part2 + "-" + file_hash_string_part3;
			}
			else
			{
				return std::nullopt;
			}
		}

		//构建密钥流
		//Building a keystream
		std::optional<std::deque<std::vector<std::byte>>> BuildingKeyStream(const std::vector<std::string>& passwords)
		{
			using namespace MemoryObjectConfrontationDiskFileData;
			using namespace EODF_Reborn;
			using namespace UtilTools;
			using namespace CrypticDataThreadingWrapper;
			using namespace CommonSecurity::SHA;

			/*
				首先输入多个密码字符串，通过安全散列算法进行处理来生成摘要字符串，
				接着再使用密钥散列消息认证码函数，与另一个摘要字符串生成的密钥进行一次填充数据，
				然后与0x5c(92)和0x36(54)进行一次异或运算加密，最后输出一个被消息认证码化的哈希令牌

				First input multiple cipher strings, process them by secure hashing algorithm to generate digest strings,
				then use the key hashing message authentication code function to fill the data once with the key generated by another digest string,
				then encrypt them with 0x5c(92) and 0x36(54) in an exclusive-or operation, and finally output one hash tokens coded by message authentication
			*/
			auto Optional_HashToken = Data_Hashing::HashTokenForData::GenerateHashToken(Hasher::WORKER_MODE::SHA3_512, passwords);

			if(Optional_HashToken.has_value())
			{
				std::string HashToken_String = Optional_HashToken.value();

				std::cout << "HashToken String:\n" <<  HashToken_String << std::endl;

				DataFormating::Base64Coder::Author2::Base64 Base64Coder;
				std::string HashToken_EncodedString = Base64Coder.base64_encode(HashToken_String, false);

				std::cout << "HashToken String Base64 Encoded:\n" <<  HashToken_EncodedString << std::endl;

				std::string HashToken_DecodedString = Base64Coder.base64_decode(HashToken_EncodedString, false);

				std::cout << "HashToken String Base64 Decoded:\n" <<  HashToken_DecodedString << std::endl;

				std::deque<std::byte> HashToken_Bytes;
				for(auto CharacterData : HashToken_EncodedString)
				{
					auto ByteData = static_cast<std::byte>(static_cast<unsigned char>(CharacterData));
					HashToken_Bytes.push_back(std::move(ByteData));
				}

				std::deque<std::vector<std::byte>> HashToken_GroupedBytes;
				CommonToolkit::ProcessingDataBlock::splitter(HashToken_Bytes, HashToken_GroupedBytes, 256, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Move);

				return HashToken_GroupedBytes;
			}
			else
			{
				return std::nullopt;
			}
		}

		class CryptographFileDataHelper
		{

		private:

			void _EncryptingData_MemoryMappcation_
			(
				std::vector<char>& file_data_part,
				Cryptograph::Implementation::Encrypter& custom_encrypter,
				std::deque<std::vector<std::byte>>& builded_key_stream,
				decltype(builded_key_stream.begin())& builded_key_stream_begin,
				decltype(builded_key_stream.end())& builded_key_stream_end
			)
			{
				std::vector<std::byte> encrypted_byte_data;

				Cryptograph::CommonModule::Adapters::characterToByte(file_data_part, encrypted_byte_data);

				file_data_part.clear();
				file_data_part.shrink_to_fit();

				//Decryption Of File Data
				if(builded_key_stream_begin != builded_key_stream_end)
				{
					custom_encrypter.Main(encrypted_byte_data, *builded_key_stream_begin);
					++builded_key_stream_begin;
				}
				else
				{
					builded_key_stream_begin = builded_key_stream.begin();
					custom_encrypter.Main(encrypted_byte_data, *builded_key_stream_begin);
					++builded_key_stream_begin;
				}

				Cryptograph::CommonModule::Adapters::characterFromByte(encrypted_byte_data, file_data_part);

				encrypted_byte_data.clear();
				encrypted_byte_data.shrink_to_fit();
			}

			void _DecryptingData_MemoryMappcation_
			(
				std::vector<char>& file_data_part,
				Cryptograph::Implementation::Decrypter& custom_decrypter,
				std::deque<std::vector<std::byte>>& builded_key_stream,
				decltype(builded_key_stream.begin())& builded_key_stream_begin,
				decltype(builded_key_stream.end())& builded_key_stream_end
			)
			{
				std::vector<std::byte> decrypted_byte_data;

				Cryptograph::CommonModule::Adapters::characterToByte(file_data_part, decrypted_byte_data);

				file_data_part.clear();
				file_data_part.shrink_to_fit();

				//Decryption Of File Data
				if(builded_key_stream_begin != builded_key_stream_end)
				{
					custom_decrypter.Main(decrypted_byte_data, *builded_key_stream_begin);
					++builded_key_stream_begin;
				}
				else
				{
					builded_key_stream_begin = builded_key_stream.begin();
					custom_decrypter.Main(decrypted_byte_data, *builded_key_stream_begin);
					++builded_key_stream_begin;
				}

				Cryptograph::CommonModule::Adapters::characterFromByte(decrypted_byte_data, file_data_part);

				decrypted_byte_data.clear();
				decrypted_byte_data.shrink_to_fit();
			}

		protected:
			std::filesystem::path EncryptionFileWithMemoryMapping
			(
				const std::filesystem::path& file_path_name,
				const std::filesystem::path& encrypted_file_name,
				std::deque<std::vector<std::byte>>& builded_key_stream,
				FileProcessing::CryptographProfileBuilder& profile_builder,
				ThreadingToolkit::Pool::Version1::ThreadPool& threadPoolVersion1
			)
			{
				using namespace MemoryObjectConfrontationDiskFileData;

				// RO is ReadOnly
				// RW is ReadAndWrite

				try
				{
					std::cout << "EncryptionFileWithMemoryMapping: Please wait, the source file is copying to the target file.\n";
					std::filesystem::copy_file(file_path_name, encrypted_file_name);
				}
				catch (const std::filesystem::filesystem_error& excecption)
				{
					std::cout << "Could not copy file "
								<< "[" << file_path_name << "]"
								<< " , Error is " << excecption.what() << '\n';
					std::cout << "Source file path is: " << "[" << excecption.path1() << "]"
								<< "Taregt file path is: " 	<< "[" << excecption.path2() << "]" << '\n';;
				}

				MIO_LibraryHelper::MemoryMapPointers rw_mmap_pointers_object = MIO_LibraryHelper::MakeDefaultMemoryMappingObject( MIO_LibraryHelper::MemoryMapTypes::SIGNED_READ_AND_WRITE );

				auto& rw_mmap_pointer_reference = rw_mmap_pointers_object.signed_rw();
				auto* managed_rw_mmap_pointer = rw_mmap_pointer_reference.get();

				Cryptograph::Implementation::Encrypter custom_encrypter;

				//[packing and unpacking]
				//相关的内存映射对象数据，将会被进行打包和进行解包
				//The associated memory mapped object data will be packaged and unpacked
                
				mio::mmap_sink mapped_rw_object;
				std::error_code error_code_object;
				auto mmap_data_package = MIO_LibraryHelper::MappingMemoryMapObject_TryAssociateFile_ToPack(encrypted_file_name, managed_rw_mmap_pointer);
				bool associated_mmap_data_package_status = MIO_LibraryHelper::MappedMemoryMapObject_FromUnpack(mmap_data_package, mapped_rw_object, error_code_object);
                
				if (associated_mmap_data_package_status)
				{
					auto file_data_begin = mapped_rw_object.begin();
					auto file_data_end = mapped_rw_object.end();

					std::size_t	iterator_offset;

					constexpr std::size_t MB_Size = 1024 * 1024;

					//每个数据块有多少MB的大小?
					//What is the size of each data block in MB?
					std::size_t file_data_block_byte_size = 64 * MB_Size;

					//多少个数据块是按照一个组来处理？
					//How many data blocks are processed as a group?
					std::size_t file_data_block_byte_count = 4;

					const std::size_t need_process_block_size = file_data_block_byte_size * file_data_block_byte_count;

					auto builded_key_stream_begin = builded_key_stream.begin();
					auto builded_key_stream_end = builded_key_stream.end();

					while (file_data_begin != file_data_end)
					{
						iterator_offset = CommonToolkit::IteratorOffsetDistance( file_data_begin, file_data_end, need_process_block_size );

						if(iterator_offset < need_process_block_size)
						{
							std::vector<char> file_data_part { file_data_begin, file_data_begin + iterator_offset };
								
							//Encryption Of File Data
							this->_EncryptingData_MemoryMappcation_(file_data_part, custom_encrypter, builded_key_stream, builded_key_stream_begin, builded_key_stream_end);

							const char* next_file_data_begin = file_data_begin + iterator_offset;

							//Change File Mapped Data
							for (std::size_t encrypted_data_offset = 0; file_data_begin != next_file_data_begin; ++encrypted_data_offset)
							{
								*file_data_begin = file_data_part.operator[](encrypted_data_offset);
								++file_data_begin;
							}

							MIO_LibraryHelper::NeedSyncDiskFile_ByManagedDataIsChanged_WithMappedObject(mapped_rw_object, error_code_object);
							AnalysisErrorCode(error_code_object);

							file_data_part.clear();
							file_data_part.shrink_to_fit();
						}
						else
						{
							std::vector<char> file_data_part { file_data_begin, file_data_begin + need_process_block_size };
							
							//Encryption Of File Data
							this->_EncryptingData_MemoryMappcation_(file_data_part, custom_encrypter, builded_key_stream, builded_key_stream_begin, builded_key_stream_end);

							const char* next_file_data_begin = file_data_begin + need_process_block_size;

							//Change File Mapped Data
							for (std::size_t encrypted_data_offset = 0; file_data_begin != next_file_data_begin; ++encrypted_data_offset)
							{
								*file_data_begin = file_data_part.operator[](encrypted_data_offset);
								++file_data_begin;
							}

							MIO_LibraryHelper::NeedSyncDiskFile_ByManagedDataIsChanged_WithMappedObject(mapped_rw_object, error_code_object);
							AnalysisErrorCode(error_code_object);

							file_data_part.clear();
							file_data_part.shrink_to_fit();
						}

						//Check the validity of the iterator (pointer) and update the memory address of the iterator (pointer)
						if(file_data_begin != file_data_end)
						{
							const std::ptrdiff_t pointer_distance = file_data_end - file_data_begin;

							if(pointer_distance > 0)
							{
								//?
								++file_data_begin;
							}
							else if(pointer_distance == 0)
							{
								continue;
							}
							else if(pointer_distance < 0)
							{
								MIO_LibraryHelper::UnmappingMemoryMapObject(mapped_rw_object);
								std::string error_message = "EncryptionFileWithMemoryMapping: A fatal logic error occurred when an iterator (pointer) was accessing a file that was already mapped to a memory block!\nThe iterator (pointer) has gone out of range of the memory block to which the file is mapped.";
								std::out_of_range iterator_access_abort(error_message);
								throw iterator_access_abort;
							}
						}
					}

					MIO_LibraryHelper::UnmappingMemoryMapObject(mapped_rw_object);
					return encrypted_file_name;
				}
				else
				{
					MIO_LibraryHelper::UnmappingMemoryMapObject(mapped_rw_object);
					AnalysisErrorCode(error_code_object);
				}
			}

			std::filesystem::path DecryptionFileWithMemoryMapping
			(
				const std::filesystem::path& file_path_name,
				const std::filesystem::path& decrypted_file_name,
				std::deque<std::vector<std::byte>>& builded_key_stream,
				FileProcessing::CryptographProfileBuilder& profile_builder,
				ThreadingToolkit::Pool::Version1::ThreadPool& threadPoolVersion1
			)
			{
				using namespace MemoryObjectConfrontationDiskFileData;

				// RO is ReadOnly
				// RW is ReadAndWrite

				try
				{
					std::cout << "DecryptionFileWithMemoryMapping: Please wait, the source file is copying to the target file.\n";
					std::filesystem::copy_file(file_path_name, decrypted_file_name);
				}
				catch (const std::filesystem::filesystem_error& excecption)
				{
					std::cout << "Could not copy file "
								<< "[" << file_path_name << "]"
								<< " , Error is " << excecption.what() << '\n';
					std::cout << "Source file path is: " << "[" << excecption.path1() << "]"
								<< "Taregt file path is: " 	<< "[" << excecption.path2() << "]" << '\n';;
				}

				MIO_LibraryHelper::MemoryMapPointers rw_mmap_pointers_object = MIO_LibraryHelper::MakeDefaultMemoryMappingObject( MIO_LibraryHelper::MemoryMapTypes::SIGNED_READ_AND_WRITE );

				auto& rw_mmap_pointer_reference = rw_mmap_pointers_object.signed_rw();
				auto* managed_rw_mmap_pointer = rw_mmap_pointer_reference.get();

				Cryptograph::Implementation::Decrypter custom_decrypter;

				//[packing and unpacking]
				//相关的内存映射对象数据，将会被进行打包和进行解包
				//The associated memory mapped object data will be packaged and unpacked
                
				mio::mmap_sink mapped_rw_object;
				std::error_code error_code_object;
				auto mmap_data_package = MIO_LibraryHelper::MappingMemoryMapObject_TryAssociateFile_ToPack(decrypted_file_name, managed_rw_mmap_pointer);
				bool associated_mmap_data_package_status = MIO_LibraryHelper::MappedMemoryMapObject_FromUnpack(mmap_data_package, mapped_rw_object, error_code_object);

				if (associated_mmap_data_package_status)
				{
					auto file_data_begin = mapped_rw_object.begin();
					auto file_data_end = mapped_rw_object.end();

					std::size_t	iterator_offset;

					constexpr std::size_t MB_Size = 1024 * 1024;

					//每个数据块有多少MB的大小?
					//What is the size of each data block in MB?
					std::size_t file_data_block_byte_size = 64 * MB_Size;

					//多少个数据块是按照一个组来处理？
					//How many data blocks are processed as a group?
					std::size_t file_data_block_byte_count = 4;

					const std::size_t need_process_block_size = file_data_block_byte_size * file_data_block_byte_count;

					auto builded_key_stream_begin = builded_key_stream.begin();
					auto builded_key_stream_end = builded_key_stream.end();

					while (file_data_begin != file_data_end)
					{
						iterator_offset = CommonToolkit::IteratorOffsetDistance( file_data_begin, file_data_end, need_process_block_size );

						if(iterator_offset < need_process_block_size)
						{
							std::vector<char> file_data_part { file_data_begin, file_data_begin + iterator_offset };
							
							//Decryption Of File Data
							this->_DecryptingData_MemoryMappcation_(file_data_part, custom_decrypter, builded_key_stream, builded_key_stream_begin, builded_key_stream_end);

							const char* next_file_data_begin = file_data_begin + iterator_offset;

							//Change File Mapped Data
							for (std::size_t decrypted_data_offset = 0; file_data_begin != next_file_data_begin; ++decrypted_data_offset)
							{
								*file_data_begin = file_data_part.operator[](decrypted_data_offset);
								++file_data_begin;
							}

							MIO_LibraryHelper::NeedSyncDiskFile_ByManagedDataIsChanged_WithMappedObject(mapped_rw_object, error_code_object);
							AnalysisErrorCode(error_code_object);

							file_data_part.clear();
							file_data_part.shrink_to_fit();
						}
						else
						{
							std::vector<char> file_data_part { file_data_begin, file_data_begin + need_process_block_size };
							
							//Decryption Of File Data
							this->_DecryptingData_MemoryMappcation_(file_data_part, custom_decrypter, builded_key_stream, builded_key_stream_begin, builded_key_stream_end);

							const char* next_file_data_begin = file_data_begin + need_process_block_size;

							//Change File Mapped Data
							for (std::size_t decrypted_data_offset = 0; file_data_begin != next_file_data_begin; ++decrypted_data_offset)
							{
								*file_data_begin = file_data_part.operator[](decrypted_data_offset);
								++file_data_begin;
							}

							MIO_LibraryHelper::NeedSyncDiskFile_ByManagedDataIsChanged_WithMappedObject(mapped_rw_object, error_code_object);
							AnalysisErrorCode(error_code_object);

							file_data_part.clear();
							file_data_part.shrink_to_fit();
						}

						//Check the validity of the iterator (pointer) and update the memory address of the iterator (pointer)
						if(file_data_begin != file_data_end)
						{
							const std::ptrdiff_t pointer_distance = file_data_end - file_data_begin;

							if(pointer_distance > 0)
							{
								//?
								++file_data_begin;
							}
							else if(pointer_distance == 0)
							{
								continue;
							}
							else if(pointer_distance < 0)
							{
								file_data_begin = file_data_end;
								MIO_LibraryHelper::UnmappingMemoryMapObject(mapped_rw_object);
								std::string error_message = "DecryptionFileWithMemoryMapping: A fatal logic error occurred when an iterator (pointer) was accessing a file that was already mapped to a memory block!\nThe iterator (pointer) has gone out of range of the memory block to which the file is mapped.";
								std::out_of_range iterator_access_abort(error_message);
								throw iterator_access_abort;
							}
						}
					}

					MIO_LibraryHelper::UnmappingMemoryMapObject(mapped_rw_object);
					return decrypted_file_name;
				}
				else
				{
					MIO_LibraryHelper::UnmappingMemoryMapObject(mapped_rw_object);
					AnalysisErrorCode(error_code_object);
				}
			}

		public:
			bool RunCustomEncryptionFile
			(
				const std::filesystem::path& profile_path_name,
				const std::filesystem::path& file_path_name,
				const std::vector<std::string>& passwords,
				bool UseMemoryMappcation = false
			)
			{
				using namespace EODF_Reborn;
				using namespace UtilTools;
				using namespace CrypticDataThreadingWrapper;
				using namespace ThreadingToolkit;

				if(profile_paths.find(profile_path_name.u8string()) != profile_paths.end())
				{
					return false;
				}
				else
				{
					profile_paths.insert(profile_path_name.u8string());

					if(file_paths.find(file_path_name.u8string()) != file_paths.end())
					{
						profile_paths.erase(file_path_name.u8string());
						return false;
					}
					else
					{
						file_paths.insert(file_path_name.u8string());
					}
				}

				FileProcessing::CryptographProfileBuilder profile_builder;

				if(!std::filesystem::exists(file_path_name))
				{
					std::stringstream error_message;
					error_message << "Error: An error occurred in the encryption operation, Because the path name "
									<< "[" << file_path_name << "] "
									<< "does not exist\n";
					std::runtime_error path_is_not_exist(error_message.str());

					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					throw path_is_not_exist;
				}
				else
				{
					if(!std::filesystem::is_regular_file(file_path_name))
					{
						std::stringstream error_message;
						error_message << "Error: file encryption failed, Because "
									  << "[" << file_path_name << "] "
									  << "is not a regular file\n";
						std::runtime_error path_is_not_regular_file(error_message.str());

						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						throw path_is_not_regular_file;
					}
				}

				if(std::filesystem::exists(profile_path_name))
				{
					std::cerr << "RunCustomEncryptionFile: Wait, what are you doing? You can't overwrite an existing file, I don't even know what it does!\nPlease use a non-existent filename as the path to the binary configuration file.\nThe operation is aborted!" << std::endl;
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				Pool::Version1::ThreadPool threadPoolVersion1(2, 4);

				threadPoolVersion1.initialize();

				std::future<std::optional<std::string>> futureTask_makeHashDigestID = threadPoolVersion1.submit(MakeHashDigestByWithProcessingFileData, std::ref(file_path_name));
				std::future<std::optional<std::deque<std::vector<std::byte>>>> futureTask2_buildingKeyStream = threadPoolVersion1.submit(BuildingKeyStream, std::ref(passwords));

				std::optional<std::string> optional_makeHashDigestID = futureTask_makeHashDigestID.get();
				std::optional<std::deque<std::vector<std::byte>>> optional_buildedKeyStream = futureTask2_buildingKeyStream.get();

				threadPoolVersion1.finished();

				std::deque<std::vector<std::byte>> buildedKeyStream;

				if(optional_makeHashDigestID.has_value())
				{
					std::cout << "RunCustomEncryptionFile: Make file hash digest id is succeed!" << std::endl;
					std::string makeHashDigestID = optional_makeHashDigestID.value();

					profile_builder.FileDataHashedID = makeHashDigestID;

					std::cout << "RunCustomDecryptionFile: The file hash data is saved." << std::endl;
				}
				else
				{
					std::cerr << "RunCustomEncryptionFile: Make file hash digest id is failed!" << std::endl;

					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				if(optional_buildedKeyStream.has_value())
				{
					std::cout << "RunCustomEncryptionFile: Build key stream is succeed!" << std::endl;
					buildedKeyStream = optional_buildedKeyStream.value();

					profile_builder.PasswordOneHashData = buildedKeyStream.operator[](0);
					profile_builder.PasswordTwoHashData = buildedKeyStream.operator[](1);
					profile_builder.PasswordThreeHashData = buildedKeyStream.operator[](2);
					profile_builder.PasswordFourHashData = buildedKeyStream.operator[](3);

					std::cout << "RunCustomDecryptionFile: The password hash data is saved." << std::endl;
				}
				else
				{
					std::cerr << "RunCustomEncryptionFile: Build key stream is failed!" << std::endl;

					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				std::cout << "Please wait for your file to be encrypted......" << std::endl;

				/*std::vector<std::byte> buildedKeyBlock;

				CommonToolkit::ProcessingDataBlock::merger(buildedKeyStream, std::back_inserter(buildedKeyBlock));
				buildedKeyStream.clear();
				CommonToolkit::ProcessingDataBlock::splitter(buildedKeyBlock, buildedKeyStream, 128, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Move);*/

				//Aligning key data
				if(buildedKeyStream.back().size() % 128 != 0)
				{
					buildedKeyStream.pop_back();
				}

				std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter> FDCM_adapter_pointer = std::make_unique<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>();
				std::unique_ptr<std::deque<std::vector<char>>> pointer_filedata_blockchain = std::make_unique<std::deque<std::vector<char>>>();
				constexpr std::size_t MB_Size = 1024 * 1024;

				//每个数据块有多少MB的大小?
				//What is the size of each data block in MB?
				std::size_t file_data_block_byte_size = 128 * MB_Size;

				//多少个数据块是按照一个组来处理？
				//How many data blocks are processed as a group?
				std::size_t file_data_block_byte_count = 64;

				profile_builder.FileSize = std::filesystem::file_size(file_path_name);

				FileProcessing::Operation::BinaryStreamReader binary_file_stream_reader;
				FileProcessing::Operation::FILE_OPERATION_STATUS file_stream_operation_status = binary_file_stream_reader.ReadFileData(profile_builder.FileDataHashedID, file_path_name, FDCM_adapter_pointer, pointer_filedata_blockchain.get(), file_data_block_byte_size, file_data_block_byte_count);

				switch (file_stream_operation_status)
				{
					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_EMPTY:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_RUNNING:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_ZERO:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
						break;
					}

					default:
						break;
				}

				std::filesystem::path encrypted_file_name;
				encrypted_file_name += file_path_name.u8string();
				encrypted_file_name += u8".opc-encrypted";

				if(file_stream_operation_status == FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_OVERLIMIT || file_stream_operation_status == FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_NOT_STANDARD_DATA_SIZE)
				{
					FDCM_adapter_pointer->ClearData();
					FDCM_adapter_pointer->ResetStatus();

					if(UseMemoryMappcation)
					{
						std::function<std::filesystem::path()> taskFunction = std::bind_front(&CryptographFileDataHelper::EncryptionFileWithMemoryMapping, this, std::ref(file_path_name), std::ref(encrypted_file_name), std::ref(buildedKeyStream), std::ref(profile_builder), std::ref(threadPoolVersion1));

						std::future<std::filesystem::path> asyncTask = std::async(std::launch::async, taskFunction);
				
						while (std::future_status::ready != asyncTask.wait_for(std::chrono::seconds(10)))
						{
							if(std::future_status::ready == asyncTask.wait_for(std::chrono::seconds(10)))
							{
								break;
							}
						}

						try
						{
							encrypted_file_name = asyncTask.get();
						}
						catch ( const std::exception& except )
						{
							std::cerr << "[Error] Exception message is" << except.what() << std::endl;
						}
					}
					else
					{
						const auto chioseWorker = Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER;

						FileDataHelper file_data_helper { buildedKeyStream, file_path_name, encrypted_file_name, profile_builder.FileSize, chioseWorker };

						file_data_helper.launch_work();
					}

					futureTask_makeHashDigestID = ThreadingToolkit::Pool::Version2::ThreadPool::get_instance( 2 ).submit( std::bind_front(MakeHashDigestByWithProcessingFileData, std::ref(encrypted_file_name)) );
					optional_makeHashDigestID = futureTask_makeHashDigestID.get();

					if(optional_makeHashDigestID.has_value())
					{
						std::cout << "EncryptionFileWithMemoryMapping: Make file hash digest id is succeed!" << std::endl;
						std::string makeHashDigestID = optional_makeHashDigestID.value();

						profile_builder.FileProceesedDataHashID = makeHashDigestID;

						std::cout << "EncryptionFileWithMemoryMapping: The processed file hash data is saved." << std::endl;
					}
					else
					{
						std::runtime_error make_hash_digest_is_invalid("EncryptionFileWithMemoryMapping: Make file hash digest id is failed!");
						throw make_hash_digest_is_invalid;
					}
				}
				else if (file_stream_operation_status == FileProcessing::Operation::FILE_OPERATION_STATUS::DONE)
				{
					/*Cryptograph::CommonModule::ConversionBufferData_Input(FDCM_adapter_pointer, pointer_filedata_blockchain.get());
					pointer_filedata_blockchain.get()->clear();
					auto* bytesPointer = std::addressof(FDCM_adapter_pointer.get()->FileDataBytes);*/
					auto& fileDataPart = *(pointer_filedata_blockchain.get());

					//Do File Encryption
					Cryptograph::Implementation::Encrypter CustomEncrypter;
					
					auto buildedKeyStreamBegin = buildedKeyStream.begin();
					auto buildedKeyStreamEnd = buildedKeyStream.end();

					for(auto begin = fileDataPart.begin(), end = fileDataPart.end(); begin != end; ++begin)
					{
						if(buildedKeyStreamBegin != buildedKeyStreamEnd)
						{
							CustomEncrypter.Main(*begin, *buildedKeyStreamBegin);
							++buildedKeyStreamBegin;
						}
						else
						{
							buildedKeyStreamBegin = buildedKeyStream.begin();
							CustomEncrypter.Main(*begin, *buildedKeyStreamBegin);
							++buildedKeyStreamBegin;
						}
					}

					/*Cryptograph::CommonModule::ConversionBufferData_Output(FDCM_adapter_pointer, bytesPointer);
					bytesPointer->clear();
					auto* charactersPointer = std::addressof(FDCM_adapter_pointer.get()->FileDataCharacters);*/

					FileProcessing::Operation::BinaryStreamWriter binary_file_stream_writer;
					binary_file_stream_writer.WriteFileData(profile_builder.FileDataHashedID, encrypted_file_name, FDCM_adapter_pointer, pointer_filedata_blockchain.get(), file_data_block_byte_size, file_data_block_byte_count);

					futureTask_makeHashDigestID = ThreadingToolkit::Pool::Version2::ThreadPool::get_instance( 2 ).submit( std::bind_front(MakeHashDigestByWithProcessingFileData, std::ref(encrypted_file_name)) );
					optional_makeHashDigestID = futureTask_makeHashDigestID.get();

					if(optional_makeHashDigestID.has_value())
					{
						std::cout << "RunCustomEncryptionFile: Make file hash digest id is succeed!" << std::endl;
						std::string makeHashDigestID = optional_makeHashDigestID.value();

						profile_builder.FileProceesedDataHashID = makeHashDigestID;

						std::cout << "RunCustomEncryptionFile: The processed file hash data is saved." << std::endl;
					}
					else
					{
						std::cerr << "RunCustomEncryptionFile: Make file hash digest id is failed!" << std::endl;

						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
					}
				}

				std::ofstream outputProfileObject;

				profile_builder.FileMainName = file_path_name.filename();
				profile_builder.FileMainName.resize(profile_builder.FileMainName.find(L".", 0));
				profile_builder.FileExtensionName = file_path_name.extension();
				profile_builder.CryptographDataEnumType = FileProcessing::CryptographDataTypePassByFile::CUSTOM_OPC;

				outputProfileObject.open(profile_path_name, std::ios::binary | std::ios::trunc);
				if(outputProfileObject.is_open())
				{
					FileProcessing::profile_serialize(outputProfileObject, profile_builder);
					std::cout << "RunCustomEncryptionFile: All data has been saved to the binary configuration file" << std::endl;
				}
				else
				{
					std::cerr << "RunCustomEncryptionFile: Access to the binary configuration file happens to be blocked, Serialization is not complete!" << std::endl;
					outputProfileObject.close();
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				outputProfileObject.close();

				std::cout << "RunCustomEncryptionFile: Your file has been completed encrypted !!!" << std::endl;
				profile_paths.erase(profile_path_name.u8string());
				file_paths.erase(file_path_name.u8string());
				return true;
			}

			bool RunCustomDecryptionFile
			(
				const std::filesystem::path& profile_path_name,
				const std::filesystem::path& file_path_name,
				const std::vector<std::string>& passwords,
				bool UseMemoryMappcation = false
			)
			{
				using namespace MemoryObjectConfrontationDiskFileData;
				using namespace EODF_Reborn;
				using namespace UtilTools;
				using namespace CrypticDataThreadingWrapper;
				using namespace ThreadingToolkit;

				if(profile_paths.find(profile_path_name.u8string()) != profile_paths.end())
				{
					return false;
				}
				else
				{
					profile_paths.insert(profile_path_name.u8string());

					if(file_paths.find(file_path_name.u8string()) != file_paths.end())
					{
						profile_paths.erase(file_path_name.u8string());
						return false;
					}
					else
					{
						file_paths.insert(file_path_name.u8string());
					}
				}

				if(!std::filesystem::exists(file_path_name))
				{
					std::stringstream error_message;
					error_message << "Error: An error occurred in the decryption operation, Because the path name "
									<< "[" << file_path_name << "] "
									<< "does not exist\n";
					std::runtime_error path_is_not_exist(error_message.str());

					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					throw path_is_not_exist;
				}
				else
				{
					if(!std::filesystem::is_regular_file(file_path_name))
					{
						std::stringstream error_message;
						error_message << "Error: file decryption failed, Because "
									  << "[" << file_path_name << "] "
									  << "is not a regular file\n";
						std::runtime_error path_is_not_regular_file(error_message.str());

						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						throw path_is_not_regular_file;
					}
				}

				if(!std::filesystem::exists(profile_path_name))
				{
					std::cerr << "RunCustomDecryptionFile: The binary profile does not exist and the operation is aborted." << std::endl;
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				FileProcessing::CryptographProfileBuilder profile_builder;
				
				std::ifstream inputProfileObject;

				inputProfileObject.open(profile_path_name, std::ios::binary);
				if(inputProfileObject.is_open())
				{
					FileProcessing::profile_deserialize(inputProfileObject, profile_builder);
					std::cout << "RunCustomDecryptionFile: All data has been loaded from the binary configuration file" << std::endl;
				}
				else
				{
					std::cerr << "RunCustomDecryptionFile: Access to the binary configuration file happens to be blocked, Deserialization is not complete!" << std::endl;
					inputProfileObject.close();
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}
				inputProfileObject.close();

				Pool::Version1::ThreadPool threadPoolVersion1(2, 4);

				threadPoolVersion1.initialize();

				std::future<std::optional<std::deque<std::vector<std::byte>>>> futureTask_buildingKeyStream = threadPoolVersion1.submit(BuildingKeyStream, std::ref(passwords));
				std::optional<std::deque<std::vector<std::byte>>> optional_buildedKeyStream = futureTask_buildingKeyStream.get();

				threadPoolVersion1.finished();
				
				std::deque<std::vector<std::byte>> buildedKeyStream;

				if(optional_buildedKeyStream.has_value())
				{
					std::cout << "RunCustomDecryptionFile: Build key stream is succeed!" << std::endl;
					buildedKeyStream = optional_buildedKeyStream.value();

					if(profile_builder.PasswordOneHashData.empty() || profile_builder.PasswordTwoHashData.empty() || profile_builder.PasswordThreeHashData.empty() || profile_builder.PasswordFourHashData.empty())
					{
						std::cerr << "RunCustomDecryptionFile: Oops, there was an error in the profile data, maybe your binary profile is corrupted?" << std::endl;
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
					}
					else
					{
						if(buildedKeyStream.operator[](0) != profile_builder.PasswordOneHashData)
						{
							std::cerr << "RunCustomDecryptionFile: Oops, the password hash data doesn't match, maybe there is something wrong with your number 1 password?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}
						if(buildedKeyStream.operator[](1) != profile_builder.PasswordTwoHashData)
						{
							std::cerr << "RunCustomDecryptionFile: Oops, the password hash data doesn't match, maybe there is something wrong with your number 2 password?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}
						if(buildedKeyStream.operator[](2) != profile_builder.PasswordThreeHashData)
						{
							std::cerr << "RunCustomDecryptionFile: Oops, the password hash data doesn't match, maybe there is something wrong with your number 3 password?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}
						if(buildedKeyStream.operator[](3) != profile_builder.PasswordFourHashData)
						{
							std::cerr << "RunCustomDecryptionFile: Oops, the password hash data doesn't match, maybe there is something wrong with your number 4 password?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}

						std::cout << "RunCustomDecryptionFile: The password hash check is complete." << std::endl;
					}
				}
				else
				{
					std::cerr << "RunCustomDecryptionFile: Build key stream is failed!" << std::endl;
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				std::cout << "Please wait for your file to be decrypted......" << std::endl; 

				/*std::vector<std::byte> buildedKeyBlock;

				CommonToolkit::ProcessingDataBlock::merger(buildedKeyStream, std::back_inserter(buildedKeyBlock));
				buildedKeyStream.clear();
				CommonToolkit::ProcessingDataBlock::splitter(buildedKeyBlock, buildedKeyStream, 128, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Move);*/

				//Aligning key data
				if(buildedKeyStream.back().size() % 128 != 0)
				{
					buildedKeyStream.pop_back();
				}

				std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter> FDCM_adapter_pointer = std::make_unique<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>();
				std::unique_ptr<std::deque<std::vector<char>>> pointer_filedata_blockchain = std::make_unique<std::deque<std::vector<char>>>();
				constexpr std::size_t MB_Size = 1024 * 1024;

				//每个数据块有多少MB的大小?
				//What is the size of each data block in MB?
				std::size_t file_data_block_byte_size = 128 * MB_Size;

				//多少个数据块是按照一个组来处理？
				//How many data blocks are processed as a group?
				std::size_t file_data_block_byte_count = 64;

				FileProcessing::Operation::BinaryStreamReader binary_file_stream_reader;
				FileProcessing::Operation::FILE_OPERATION_STATUS file_stream_operation_status = binary_file_stream_reader.ReadFileData(profile_builder.FileProceesedDataHashID, file_path_name, FDCM_adapter_pointer, pointer_filedata_blockchain.get(), file_data_block_byte_size, file_data_block_byte_count);

				switch (file_stream_operation_status)
				{
					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_EMPTY:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_RUNNING:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_ZERO:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
						break;
					}

					default:
						break;
				}

				std::filesystem::path decrypted_file_name;
				decrypted_file_name += file_path_name.parent_path();
				decrypted_file_name += u8"/";
				decrypted_file_name += profile_builder.FileMainName;
				std::u8string file_extension_name(profile_builder.FileExtensionName.begin(), profile_builder.FileExtensionName.end());
				decrypted_file_name += u8"_opc-decrypted";
				decrypted_file_name += file_extension_name;

				if(file_stream_operation_status == FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_OVERLIMIT || file_stream_operation_status == FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_NOT_STANDARD_DATA_SIZE)
				{
					FDCM_adapter_pointer->ClearData();
					FDCM_adapter_pointer->ResetStatus();

					threadPoolVersion1.initialize();

					std::future<std::optional<std::string>> futureTask_makeHashDigestID = std::async(std::launch::async, MakeHashDigestByWithProcessingFileData, std::ref(file_path_name));
					std::optional<std::string> optional_makeHashDigestID = futureTask_makeHashDigestID.get();

					threadPoolVersion1.finished();

					if(optional_makeHashDigestID.has_value())
					{
						std::cout << "DecryptionFileWithMemoryMapping: Make file hash digest id is succeed!" << std::endl;
						std::string makeHashDigestID = optional_makeHashDigestID.value();

						if(!profile_builder.FileProceesedDataHashID.empty())
						{
							if(makeHashDigestID != profile_builder.FileProceesedDataHashID)
							{
								std::runtime_error processed_file_hash_is_not_match("DecryptionFileWithMemoryMapping: Oops, the processed file hash data doesn't match, maybe your encrypted file is corrupted?");
								throw processed_file_hash_is_not_match;
							}
						}
						else
						{
							std::runtime_error profile_is_corrupted("DecryptionFileWithMemoryMapping: Oops, there was an error in the profile data, maybe your binary profile is corrupted?");
							throw profile_is_corrupted;
						}
					}
					else
					{
						std::runtime_error make_hash_digest_is_invalid("DecryptionFileWithMemoryMapping: Make file hash digest id is failed!");
						throw make_hash_digest_is_invalid;
					}

					if(UseMemoryMappcation)
					{
						std::function<std::filesystem::path()> taskFunction = std::bind_front(&CryptographFileDataHelper::DecryptionFileWithMemoryMapping, this, std::ref(file_path_name), std::ref(decrypted_file_name), std::ref(buildedKeyStream), std::ref(profile_builder), std::ref(threadPoolVersion1));
						
						std::future<std::filesystem::path> asyncTask = std::async(std::launch::async, taskFunction);
				
						while (std::future_status::ready != asyncTask.wait_for(std::chrono::seconds(10)))
						{
							if(std::future_status::ready == asyncTask.wait_for(std::chrono::seconds(10)))
							{
								break;
							}
						}

						try
						{
							decrypted_file_name = asyncTask.get();
						}
						catch ( const std::exception& except )
						{
							std::cerr << "[Error] Exception message is" << except.what() << std::endl;
						}
					}
					else
					{
						const auto chioseWorker = Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER;

						FileDataHelper file_data_helper { buildedKeyStream, file_path_name, decrypted_file_name, profile_builder.FileSize, chioseWorker };

						file_data_helper.launch_work();
					}

					futureTask_makeHashDigestID = ThreadingToolkit::Pool::Version2::ThreadPool::get_instance( 2 ).submit( std::bind_front(MakeHashDigestByWithProcessingFileData, std::ref(decrypted_file_name)) );
					optional_makeHashDigestID = futureTask_makeHashDigestID.get();

					if(optional_makeHashDigestID.has_value())
					{
						std::cout << "DecryptionFileWithMemoryMapping: Make file hash digest id is succeed!" << std::endl;
						std::string makeHashDigestID = optional_makeHashDigestID.value();

						if(!profile_builder.FileDataHashedID.empty())
						{
							if(makeHashDigestID != profile_builder.FileDataHashedID)
							{
								std::runtime_error file_hash_is_not_match("DecryptionFileWithMemoryMapping: Oops, the file hash data doesn't match, maybe your encrypted file is corrupted?");
								throw file_hash_is_not_match;
							}
						}
						else
						{
							std::runtime_error profile_is_corrupted("DecryptionFileWithMemoryMapping: Oops, there was an error in the profile data, maybe your binary profile is corrupted?");
							throw profile_is_corrupted;
						}
					}
					else
					{
						std::runtime_error make_hash_digest_is_invalid("DecryptionFileWithMemoryMapping: Make file hash digest id is failed!");
						throw make_hash_digest_is_invalid;
					}
				}
				else if (file_stream_operation_status == FileProcessing::Operation::FILE_OPERATION_STATUS::DONE)
				{
					threadPoolVersion1.initialize();

					std::future<std::optional<std::string>> futureTask_makeHashDigestID = std::async(MakeHashDigestByWithProcessingFileData, std::ref(file_path_name));
					std::optional<std::string> optional_makeHashDigestID = futureTask_makeHashDigestID.get();

					threadPoolVersion1.finished();

					if(optional_makeHashDigestID.has_value())
					{
						std::cout << "RunCustomDecryptionFile: Make file hash digest id is succeed!" << std::endl;
						std::string makeHashDigestID = optional_makeHashDigestID.value();

						if(!profile_builder.FileProceesedDataHashID.empty())
						{
							if(makeHashDigestID != profile_builder.FileProceesedDataHashID)
							{
								std::cerr << "RunCustomDecryptionFile: Oops, the processed file hash data doesn't match, maybe your encrypted file is corrupted?" << std::endl;
								profile_paths.erase(profile_path_name.u8string());
								file_paths.erase(file_path_name.u8string());
								return false;
							}
						}
						else
						{
							std::cerr << "RunCustomDecryptionFile: Oops, there was an error in the profile data, maybe your binary profile is corrupted?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}
					}
					else
					{
						std::cerr << "RunCustomDecryptionFile: Make file hash digest id is failed!" << std::endl;

						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
					}

					/*Cryptograph::CommonModule::ConversionBufferData_Input(FDCM_adapter_pointer, pointer_filedata_blockchain.get());
					pointer_filedata_blockchain.get()->clear();
					auto* bytesPointer = std::addressof(FDCM_adapter_pointer.get()->FileDataBytes);*/
					auto& fileDataPart = *(pointer_filedata_blockchain.get());

					//Do File Decryption
					Cryptograph::Implementation::Decrypter CustomDecrypter;

					auto buildedKeyStreamBegin = buildedKeyStream.begin();
					auto buildedKeyStreamEnd = buildedKeyStream.end();

					for(auto begin = fileDataPart.begin(), end = fileDataPart.end(); begin != end; ++begin)
					{
						if(buildedKeyStreamBegin != buildedKeyStreamEnd)
						{
							CustomDecrypter.Main(*begin, *buildedKeyStreamBegin);
							++buildedKeyStreamBegin;
						}
						else
						{
							buildedKeyStreamBegin = buildedKeyStream.begin();
							CustomDecrypter.Main(*begin, *buildedKeyStreamBegin);
							++buildedKeyStreamBegin;
						}
					}

					/*Cryptograph::CommonModule::ConversionBufferData_Output(FDCM_adapter_pointer, bytesPointer);
					auto* charactersPointer = std::addressof(FDCM_adapter_pointer.get()->FileDataCharacters);*/

					FileProcessing::Operation::BinaryStreamWriter binary_file_stream_writer;
					binary_file_stream_writer.WriteFileData(profile_builder.FileProceesedDataHashID, decrypted_file_name, FDCM_adapter_pointer, pointer_filedata_blockchain.get(), file_data_block_byte_size, file_data_block_byte_count);

					futureTask_makeHashDigestID = ThreadingToolkit::Pool::Version2::ThreadPool::get_instance( 2 ).submit( std::bind_front(MakeHashDigestByWithProcessingFileData, std::ref(decrypted_file_name)) );
					optional_makeHashDigestID = futureTask_makeHashDigestID.get();

					if(optional_makeHashDigestID.has_value())
					{
						std::cout << "RunCustomDecryptionFile: Make file hash digest id is succeed!" << std::endl;
						std::string makeHashDigestID = optional_makeHashDigestID.value();

						if(!profile_builder.FileDataHashedID.empty())
						{
							if(makeHashDigestID != profile_builder.FileDataHashedID)
							{
								std::runtime_error file_hash_is_not_match("RunCustomDecryptionFile: Oops, the file hash data doesn't match, maybe your encrypted file is corrupted?");
								throw file_hash_is_not_match;
							}
						}
						else
						{
							std::runtime_error profile_is_corrupted("RunCustomDecryptionFile: Oops, there was an error in the profile data, maybe your binary profile is corrupted?");
							throw profile_is_corrupted;
						}
					}
					else
					{
						std::runtime_error make_hash_digest_is_invalid("RunCustomDecryptionFile: Make file hash digest id is failed!");
						throw make_hash_digest_is_invalid;
					}
				}

				std::cout << "RunCustomDecryptionFile: Your file has been completed decrypted !!!" << std::endl;

				profile_paths.erase(profile_path_name.u8string());
				file_paths.erase(file_path_name.u8string());
				return true;
			}

		private:
			std::unordered_set<std::u8string> profile_paths;
			std::unordered_set<std::u8string> file_paths;
		};

	}  // namespace MainProgram_ModulemImplementation
}  // namespace EODF_Reborn