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

namespace Cryptograph
{
	/*
		Implementation of Custom Data Encrypting Worker
		自定义加密数据工作器的实现
		
		OaldresPuzzle-Cryptic
		隐秘的奥尔德雷斯之谜
	*/
	namespace OaldresPuzzle_Cryptic::Version1
	{
		inline void Exclusive_OR( std::byte& Data, const std::byte& Key )
		{
			Data ^= Key;
		}

		inline void Equivalence_OR( std::byte& Data, const std::byte& Key )
		{
			Data ^= Key;
			Data = ~Data;
		}

		inline void BitCirculation_Left( std::byte& Data, unsigned int move_bit )
		{
			Data = ( Data << move_bit ) | ( Data >> ( 8 - move_bit ) );
		}

		inline void BitCirculation_Right( std::byte& Data, unsigned int move_bit )
		{
			Data = ( Data >> move_bit ) | ( Data << ( 8 - move_bit ) );
		}

		inline void BitToggle( std::byte& Data, unsigned int position )
		{
			constexpr std::byte Mask{ 1 };

			Data ^= ( Mask << position );
		}

		namespace Encryption_Tools
		{
			/*
				@author Project Owner and Module Designer: Twilight-Dream
				@author Algorithm Designer: Spiritual-Fish

				@brief OaldresPuzzle-Cryptic's Core - Symmetric Encryption Algorithm Implementation
				@brief OaldresPuzzle-Cryptic的核心 - 对称加密算法实现
			*/
			class Encryption
			{

			public:
				Encryption() : choise( 0 ), move_bit( 0 ) {}

				~Encryption() {}

				Encryption( const Encryption& _object ) = delete;

				std::byte Main_Encryption( std::byte& data, const std::byte& Key );

			private:
				size_t choise;
				size_t move_bit;
			};

			inline std::byte Encryption::Main_Encryption( std::byte& data, const std::byte& Key )
			{
				constexpr std::byte ByteFlag{ 3 };
				constexpr std::byte ByteFlag2{ 7 };

				//Binary Digits 10101010
				/*
			
					Select Binary Digits
					1 0 1 0 1 0 1 0
								^ ^
			
				*/
				choise = std::to_integer<std::size_t>( Key & ByteFlag );

				/*
			
					00101010 = 10101010 >> 2
			
					Select Binary Digits
					0 0 1 0 1 0 1 0
							  ^ ^ ^
			
				*/
				move_bit = std::to_integer<std::size_t>( (Key >> 2) & ByteFlag2 );

				switch ( choise )
				{
					case 0:
					{
						Exclusive_OR( data, Key );
						break;
					}
					case 1:
					{
						Equivalence_OR( data, Key );
						break;
					}

					case 2:
					{
						BitCirculation_Left( data, move_bit );
						break;
					}
					case 3:
					{
						BitCirculation_Right( data, move_bit );
						break;
					}
					default:
						break;
				}

				//Non-linear processing - random bit switching
				//非线性处理 - 随机比特位切换
				BitToggle( data, move_bit );

				return data;
			}

		}  // namespace Encryption_Tools

		namespace Decryption_Tools
		{
			/*
				@author Project Owner and Module Designer: Twilight-Dream
				@author Algorithm Designer: Spiritual-Fish

				@brief OaldresPuzzle-Cryptic's Core - Symmetric Decryption Algorithm Implementation
				@brief OaldresPuzzle-Cryptic的核心 - 对称解密算法实现
			*/
			class Decryption
			{

			public:
				Decryption() : choise( 0 ), move_bit( 0 ) {}

				~Decryption() {}

				Decryption( const Decryption& _object ) = delete;

				std::byte Main_Decryption( std::byte& data, const std::byte& Key );

			private:
				size_t choise;
				size_t move_bit;
			};

			inline std::byte Decryption::Main_Decryption( std::byte& data, const std::byte& Key )
			{
				constexpr std::byte ByteFlag{ 3 };
				constexpr std::byte ByteFlag2{ 7 };

				//Binary Digits 10101010
				/*
			
					Select Binary Digits
					1 0 1 0 1 0 1 0
								^ ^
			
				*/
				choise = std::to_integer<std::size_t>( Key & ByteFlag );

				/*
			
					00101010 = 10101010 >> 2
			
					Select Binary Digits
					0 0 1 0 1 0 1 0
							  ^ ^ ^
			
				*/
				move_bit = std::to_integer<std::size_t>( (Key >> 2) & ByteFlag2 );

				//Non-linear processing - random bit switching
				//非线性处理 - 随机比特位切换
				BitToggle( data, move_bit );

				switch ( choise )
				{
					case 0:
					{
						Exclusive_OR( data, Key );
						break;
					}

					case 1:
					{
						Equivalence_OR( data, Key );
						break;
					}

					case 2:
					{
						BitCirculation_Right( data, move_bit );
						break;
					}

					case 3:
					{
						BitCirculation_Left( data, move_bit );
						break;
					}
					default:
						break;
				}

				return data;
			}
		}  // namespace Decryption_Tools

		class Encrypter
		{

		private:

			std::byte default_binary_key { 250 };

		protected:

			/*
				分块加密数据函数
				Split block encryption data function
			*/
			void SplitDataBlockToEncrypt(std::vector<std::byte>& PlainText, const std::vector<std::byte>& Key) const
			{
				using namespace CommonSecurity;

				if(PlainText.size() % 64 != 0)
					return;
				if(Key.size() % 128 != 0)
					return;

				std::size_t PlainText_size = PlainText.size();
				std::byte temporaryBinaryPassword { default_binary_key };

				Encryption_Tools::Encryption Algorithm;

				std::vector<unsigned int> temporaryIndexSplited = CommonToolkit::make_vector(std::make_integer_sequence<unsigned int, 64>{});

				for ( std::size_t datablock_size = 0; datablock_size < PlainText_size; datablock_size += 64 )
				{
					//第一次循环加密
					//First cycle encryption
					for ( std::size_t round = datablock_size; round < 64 + datablock_size; round++ )
					{
						std::byte temporaryKey = Algorithm.Main_Encryption( temporaryBinaryPassword, Key[ round - datablock_size ] );
						temporaryBinaryPassword = Algorithm.Main_Encryption( PlainText[ round ], temporaryKey );
					}

					PlainText.push_back( temporaryBinaryPassword );

					//随机置换
					//Random Displacement
					CommonSecurity::RNG_Xoshiro::xoshiro256 pseudoRandomGenerator { static_cast<unsigned int>( temporaryBinaryPassword ^ Key[0] ) };
					CommonSecurity::ShuffleRangeData( temporaryIndexSplited, pseudoRandomGenerator );

					//第二次循环加密
					//Second cycle encryption
					for ( std::size_t round2 = 0; round2 < 64; round2++ )
					{
						std::byte temporaryKey = Algorithm.Main_Encryption( temporaryBinaryPassword, Key[ round2 + 64 ] );
						temporaryBinaryPassword = Algorithm.Main_Encryption( PlainText[ datablock_size + temporaryIndexSplited[ round2 ] ], temporaryKey );
					}

					temporaryBinaryPassword = PlainText.back();
				}
			}

			/*
				https://en.wikipedia.org/wiki/Padding_(cryptography)

				ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.

				Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
			*/
			void PaddingData(std::vector<std::byte>& Data) const
			{
				std::byte temporaryBinaryData;

				std::size_t Remainder_64 = Data.size() & 63;
				std::size_t NeedPaddingCount = 63 - Remainder_64;

				std::random_device HardwareRandomDevice;
				std::mt19937 RandomGeneraterBySecureSeed ( CommonSecurity::GenerateSecureRandomNumberSeed<std::size_t>(HardwareRandomDevice) );
				CommonSecurity::RND::UniformIntegerDistribution UniformDistribution(0, 255);

				for (int loopCount = 0; loopCount < NeedPaddingCount; ++loopCount)
				{
					auto integer = static_cast<unsigned int>( UniformDistribution(RandomGeneraterBySecureSeed) );
					std::byte byteData{ static_cast<std::byte>(integer) };
					temporaryBinaryData = byteData;
					Data.push_back(temporaryBinaryData);
				}
				auto integer = static_cast<unsigned int>(NeedPaddingCount);
				std::byte byteData{ static_cast<std::byte>(integer) };
				temporaryBinaryData = byteData;
				Data.push_back(temporaryBinaryData);
			}

		public:

			// class CrypticDataThreadingWrapper::FileDataHelper
			// 多线程实现的专用接口，请勿使用不标准的大小数据，进行随意调用，禁止移除该函数！
			// Multi-threaded implementation of the special interface, please do not use non-standard size data, for arbitrary calls, prohibit the removal of the function!
			std::vector<char>& Main(std::vector<char>& PlainText, const std::vector<std::byte>& Key);

			/*
				The file size levels are listed here
				Small file size range: 1BYTE~4GB
				Medium file size range: 4GB~20GB
				Large file size range: 20GB~Number GB
				This function interface is for small files.
			
				这里列出文件大小等级规定
				小型文件大小范围: 1BYTE~4GB
				中型文件大小范围: 4GB~20GB
				大型文件大小范围: 20GB~Number GB
				这个函数接口是给小型文件来使用的。
			*/
			std::vector<std::byte> Main(const std::vector<std::byte>& PlainText, const std::vector<std::byte>& Key);
		
			Encrypter() = default;
			~Encrypter() = default;

			Encrypter( Encrypter& _object ) = delete;
			Encrypter& operator=( const Encrypter& _object ) = delete;
		};

		inline std::vector<char>& Encrypter::Main(std::vector<char>& PlainText, const std::vector<std::byte>& Key)
		{
			std::vector<std::byte> temporaryByteData;
			Cryptograph::CommonModule::Adapters::characterToByte(PlainText, temporaryByteData);
			PlainText.clear();
			PlainText.shrink_to_fit();
			SplitDataBlockToEncrypt(temporaryByteData, Key);
			Cryptograph::CommonModule::Adapters::characterFromByte(temporaryByteData, PlainText);
			return PlainText;
		}

		inline std::vector<std::byte> Encrypter::Main(const std::vector<std::byte>& PlainText, const std::vector<std::byte>& Key)
		{
			std::vector<std::byte> CipherText(PlainText);
			PaddingData(CipherText);
			SplitDataBlockToEncrypt(CipherText, Key);
			return CipherText;
		}


		/*
			Implementation of Custom Data Decrypting Worker
			自定义解密数据工作器的实现
		
			OaldresPuzzle-Cryptic
			隐秘的奥尔德雷斯之谜
		*/
		class Decrypter
		{
	
		private:

			std::byte default_binary_key { 250 };

		protected:

			/*
				分块解密数据函数
				Split block decryption data function
			*/
			void SplitDataBlockToDecrypt(std::vector<std::byte>& CipherText, const std::vector<std::byte>& Key) const
			{
				using namespace CommonSecurity;

				if(CipherText.size() % 65 != 0)
					return;
				if(Key.size() % 128 != 0)
					return;

				std::byte temporaryBinaryPassword{ default_binary_key };
				std::byte temporaryBinaryPassword2{ default_binary_key };

				Encryption_Tools::Encryption MakeKey;
				Decryption_Tools::Decryption Algorithm;

				std::byte temporaryBinaryData;
				std::vector<unsigned int> temporaryIndexSplited = CommonToolkit::make_vector(std::make_integer_sequence<unsigned int, 64>{});

				std::stack<std::byte> temporary_head_stack;
				std::size_t stack_size = CipherText.size() / 65;
				while ( stack_size-- )
				{
					temporary_head_stack.push( CipherText.back() );
					CipherText.pop_back();
				}

				for ( std::size_t datablock_size = 0; datablock_size < CipherText.size(); datablock_size += 64 )
				{
					temporaryBinaryPassword = temporary_head_stack.top();

					//随机置换
					//Random Displacement
					CommonSecurity::RNG_Xoshiro::xoshiro256 pseudoRandomGenerator { static_cast<unsigned int>( temporaryBinaryPassword ^ Key[0] ) };
					CommonSecurity::ShuffleRangeData( temporaryIndexSplited, pseudoRandomGenerator );

					//第一次循环解密
					//First cycle Decryption
					for ( std::size_t round = 0; round < 64; round++ )
					{
						temporaryBinaryData = CipherText[ datablock_size + temporaryIndexSplited[ round ] ];
						std::byte temporaryKey = MakeKey.Main_Encryption( temporaryBinaryPassword, Key[ round + 64 ] );
						Algorithm.Main_Decryption( CipherText[ datablock_size + temporaryIndexSplited[ round ] ], temporaryKey );
						temporaryBinaryPassword = temporaryBinaryData;
					}

					//第二次循环解密
					//Second cycle decryption
					for ( std::size_t round2 = datablock_size; round2 < 64 + datablock_size; round2++ )
					{
						temporaryBinaryData = CipherText[ round2 ];
						std::byte temporaryKey = MakeKey.Main_Encryption( temporaryBinaryPassword2, Key[ round2 - datablock_size ] );
						Algorithm.Main_Decryption( CipherText[ round2 ], temporaryKey );
						temporaryBinaryPassword2 = temporaryBinaryData;
					}

					temporaryBinaryPassword2 = temporary_head_stack.top();
					temporary_head_stack.pop();
				}
			}

			/*
				https://en.wikipedia.org/wiki/Padding_(cryptography)

				ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.

				Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
			*/
			void UnpaddingData(std::vector<std::byte>& Data) const
			{
				std::size_t count = static_cast<std::size_t>(Data.back());
				Data.pop_back();
				while (count--)
				{
					Data.pop_back();
				}
			}

		public:
		
			// class CrypticDataThreadingWrapper::FileDataHelper
			// 多线程实现的专用接口，请勿使用不标准的大小数据，进行随意调用，禁止移除该函数！
			// Multi-threaded implementation of the special interface, please do not use non-standard size data, for arbitrary calls, prohibit the removal of the function!
			std::vector<char>& Main(std::vector<char>& CipherText, const std::vector<std::byte>& Key);
		
			/*
				The file size levels are listed here
				Small file size range: 1BYTE~2GB
				Medium file size range: 2GB~20GB
				Large file size range: 20GB~Number GB
				This function interface is for small files.
			
				这里列出文件大小等级规定
				小型文件大小范围: 1BYTE~2GB
				中型文件大小范围: 2GB~20GB
				大型文件大小范围: 20GB~Number GB
				这个函数接口是给小型文件来使用的。
			*/
			std::vector<std::byte> Main(const std::vector<std::byte>& CipherText, const std::vector<std::byte>& Key);

			Decrypter() = default;
			~Decrypter() = default;

			Decrypter( Decrypter& _object ) = delete;
			Decrypter& operator=( const Decrypter& _object ) = delete;
		};

		inline std::vector<char>& Decrypter::Main(std::vector<char>& CipherText, const std::vector<std::byte>& Key)
		{
			std::vector<std::byte> temporaryByteData;
			Cryptograph::CommonModule::Adapters::characterToByte(CipherText, temporaryByteData);
			CipherText.clear();
			CipherText.shrink_to_fit();
			SplitDataBlockToDecrypt(temporaryByteData, Key);
			Cryptograph::CommonModule::Adapters::characterFromByte(temporaryByteData, CipherText);
			return CipherText;
		}

		inline std::vector<std::byte> Decrypter::Main(const std::vector<std::byte>& CipherText, const std::vector<std::byte>& Key)
		{
			std::vector<std::byte> PlainText(CipherText);
			SplitDataBlockToDecrypt(PlainText, Key);
			UnpaddingData(PlainText);
			return PlainText;
		}
	}

} // namespace Cryptograph

namespace Cryptograph
{

	/*
		Implementation of Custom Data Encrypting Worker and Decrypting Worker 
		自定义加密和解密数据工作器的实现
		
		OaldresPuzzle-Cryptic (Version 2.0)
		隐秘的奥尔德雷斯之谜 (版本 2.0)
	*/
	namespace OaldresPuzzle_Cryptic::Version2
	{
		using CommonSecurity::RNG_FeedbackShiftRegister::LinearFeedbackShiftRegister;
		using CommonSecurity::RNG_FeedbackShiftRegister::NonlinearFeedbackShiftRegister;
		using CommonSecurity::RNG_ChaoticTheory::SimulateDoublePendulum;
	
		template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
		class StateData_Worker;

		namespace ImplementationDetails
		{
			template<std::integral DataType, std::size_t ArraySize>
			class SegmentTree
			{

				/*
					std::has_single_bit(ArraySize)
					ArraySize != 0 && (ArraySize ^ (ArraySize & -ArraySize) == 0)
				*/

			private:

				static constexpr std::size_t N = std::has_single_bit(ArraySize) ? ArraySize : 0;
				std::array<DataType, N << 1> Nodes {};

			public:
				void Set(std::size_t Position)
				{
					for(std::size_t CurrentNode = N | Position; CurrentNode; CurrentNode >>= 1)
						this->Nodes[CurrentNode]++;
				}

				DataType Get(std::size_t Order)
				{
					std::size_t CurrentNode = 1;
					for(std::size_t CurrentLeftSize = N >> 1, LeftTotal = 0; CurrentLeftSize; CurrentLeftSize >>= 1)
					{
						std::size_t CurrentLeftCount = CurrentLeftSize - this->Nodes[CurrentNode << 1];
						if(LeftTotal + CurrentLeftCount > Order)
							CurrentNode = CurrentNode << 1;
						else
							CurrentNode = CurrentNode << 1 | 1, LeftTotal += CurrentLeftCount;
					}
					return static_cast<DataType>(CurrentNode ^ N);
				}

				void Clear()
				{
					volatile void* CheckPointer = nullptr;
					CheckPointer = memory_set_no_optimize_function<0x00>(this->Nodes.data(), this->Nodes.size() * sizeof(DataType));
					CheckPointer = nullptr;
				}
			
				~SegmentTree()
				{
					volatile void* CheckPointer = nullptr;
					CheckPointer = memory_set_no_optimize_function<0x00>(this->Nodes.data(), this->Nodes.size() * sizeof(DataType));
					CheckPointer = nullptr;
				}
			};

			template<std::uint64_t BITS_STATE_SIZE>
			inline constexpr std::array<std::uint32_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2>
			GenerateHashStateBufferIndices()
			{
				std::array<std::uint32_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2> StateBufferIndexes {};

				for(std::size_t Index = 0, Value = 0; Index < StateBufferIndexes.size(); ++Index )
				{
					StateBufferIndexes[Index] = Value;
					++Value;
				}

				return StateBufferIndexes;
			}

			template<std::uint64_t HashBitSize>
			/*
				https://en.wikipedia.org/wiki/Sponge_function
						
				基于海绵结构的密码学哈希函数，使用的伪随机置换函数由Twilight-Dream设计
				Cryptographic hash function based on sponge structure using a pseudo-random permutation function designed by Twilight-Dream
			*/
			class CustomSecureHash
			{

			private:

				/*
					哈希状态比特大小=比特率大小+比特容量大小
							
					例子:
					海绵函数的安全性取决于其内部状态的长度和块的长度。
					如果信息块的长度为r位，内部状态的长度为w位，那么有c = w - r位的内部状态不能被信息块所修改。
					c的值被称为海绵的容量，海绵函数所保证的安全级别是c/2。例如，要达到256位的安全与64位的消息块，内部状态应该是w=2×256+64=576位。
					当然，安全级别也取决于哈希值的长度n。因此，碰撞攻击的复杂性是2^{n/2}和2^{c/2}之间的最小值，而第二次预像攻击的复杂性是2^n和2^{c/2}之间的最小值。

					为了安全起见，排列组合P应该表现得像一个随机排列组合，没有统计上的偏差，也没有让攻击者预测输出的数学结构。
					与基于压缩函数的哈希值一样，海绵函数也会对信息进行填充，但填充更简单，因为它不需要包括信息的长度。
					最后一个信息位只是由一个1位和尽可能多的0跟在后面。
							
					Hash state bits size =  Bits rate size + Bits capacity size
							
					Example :
					The security of a sponge function depends on the length of its internal state and the length of the blocks.
					If message blocks are r-bit long and the internal state is w-bit long, then there are c = w – r bits of the internal state that can’t be modified by message blocks.
					The value of c is called a sponge’s capacity, and the security level guaranteed by the sponge function is c/2. For example, to reach 256-bit security with 64-bit message blocks, the internal state should be w = 2 × 256 + 64 = 576 bits.
					Of course, the security level also depends on the length, n, of the hash value. The complexity of a collision attack is therefore the smallest value between 2^{n/2} and 2^{c/2}, while the complexity of a second preimage attack is the smallest value between 2^n and 2^{c/2}.

					To be secure, the permutation P should behave like a random permutation, without statistical bias and without a mathematical structure that would allow an attacker to predict outputs.
					As in compression function–based hashes, sponge functions also pad messages, but the padding is simpler because it doesn’t need to include the message’s length.
					The last message bit is simply followed by a 1 bit and as many zeroes as necessary.
				*/

				static constexpr std::uint64_t BITS_STATE_SIZE = 2 * HashBitSize + std::numeric_limits<std::uint64_t>::digits;
				static constexpr std::uint64_t BITS_RATE = HashBitSize;
				static constexpr std::uint64_t BITS_CAPACITY = BITS_STATE_SIZE - BITS_RATE;

				static constexpr std::uint64_t BYTES_RATE = BITS_RATE / std::numeric_limits<std::uint8_t>::digits;
				static constexpr std::uint64_t BITWORDS_RATE = BYTES_RATE / sizeof(std::uint64_t);
				static constexpr std::uint64_t BYTES_CAPACITY = BITS_CAPACITY / std::numeric_limits<std::uint8_t>::digits;
				static constexpr std::uint64_t BITWORDS_CAPACITY = BYTES_CAPACITY / sizeof(std::uint64_t);

				static constexpr std::uint8_t PAD_BYTE_DATA = 0b00000001;
				static constexpr std::uint64_t PAD_BITSWORD_DATA = 0b0000000100000001000000010000000100000001000000010000000100000001;

				std::array<std::uint64_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits> BitsHashState {};

				static constexpr std::array<std::uint32_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2> StateBufferIndices = GenerateHashStateBufferIndices<BITS_STATE_SIZE>();
						
				const std::array<std::uint32_t, 63> MoveBitCounts {};
				const std::array<std::uint32_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits> HashStateIndices {};
				std::array<std::uint32_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2> LeftRotatedStateBufferIndices;
				std::array<std::uint32_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2> RightRotatedStateBufferIndices;

				std::size_t StateCurrentCounter = 1;

				/*
					这里的伪随机数来源，可以是大素数的立方根或者平方根所生成的比特位，也可以是无理数所生成的比特位，也可以是严格设计的比特掩码
					The source of the pseudo-random numbers here can be the bits generated by the cube root or square root of a large prime number, the bits generated by an irrational number, or a strictly designed bit mask
				*/
				static constexpr std::array<std::uint64_t, 64> HASH_ROUND_CONSTANTS
				{
					0xe02d51d52e6988abULL,0xfc48780c20090b50ULL,0xc6144c4d89151352ULL,0xb98669bb3a32a8f1ULL,0xd4786928fe033c03ULL,0xaebb38f01d73faabULL,0x936cb166f1ff8493ULL,0x60310a07294f5dc8ULL,
					0x06d5b3dbf088ae77ULL,0x7e2be74e7f525e23ULL,0xe5459a079549e2e3ULL,0x352ba71a6a95e6d6ULL,0x7b40c16d92d5e43bULL,0xa559af839ba27363ULL,0x985236a57aa17c27ULL,0xf4be83da5a08c659ULL,
					0x9ab94838ff7737c6ULL,0x718d70cd883014f9ULL,0x0bda9af50ba21d4dULL,0xd88cb07c07a814d5ULL,0xa6c8d66f9b3d8933ULL,0x80643413e011c839ULL,0x5456e69b40922372ULL,0x86a8e11d2e20eb52ULL,
					0x19224d7b455813b1ULL,0xb1dbd44f138bac7fULL,0x2ba9107bb26a6134ULL,0x48297fe2c4167b76ULL,0x776528a5edb8a68eULL,0x2381e0eb054681a8ULL,0x41a27b65af8e39bfULL,0xeda2847d88303971ULL,
					0x655f38e3d5446574ULL,0xd8093b5a1172958cULL,0x28880627fe4c014bULL,0x0459d6592d1b2b51ULL,0x2aeb8df1c83b63beULL,0xcba3ca8c513a8205ULL,0xa4967565ebf34510ULL,0x1041efcb786f9e59ULL,
					0xdf8ee44352384448ULL,0xff38527afa3b13a2ULL,0x9ff904a86c03fe22ULL,0xe81a56aef956f93fULL,0x3c13136bf0612494ULL,0xca9b0621705e9748ULL,0xe89292acf259cef1ULL,0x373480242c1c5effULL,
					0xd249f4efd3685008ULL,0xda2779c07b0e4a43ULL,0x1cc1bd402438ea81ULL,0x7b090a135f97ba29ULL,0xd25e80bc98b09e4bULL,0xeea820f2885ac1f8ULL,0x939c9063e5bdc233ULL,0x01c1b92d1ed7777bULL,
					0x75208f3a3cb244dfULL,0x20f74f61571512b4ULL,0xfd526ef256343eb7ULL,0x753082ea79791d09ULL,0x41a3a000a8c7ae30ULL,0xb2a056be3a257d27ULL,0x152a2da04d5f2393ULL,0x99dba5727ec6dabbULL
				};

				std::array<std::uint32_t, 63>
				GenerateRandomMoveBitCounts()
				{
					CommonSecurity::RNG_ISAAC::isaac64<8> CSPRNG = CommonSecurity::RNG_ISAAC::isaac64<8>(1946379852749613ULL);

					CSPRNG.discard(1024);

					std::array<std::uint32_t, 63> MoveBitCounts {};

					std::iota(MoveBitCounts.begin(), MoveBitCounts.end(), 1);

					for(std::uint64_t Index = 0; Index < MoveBitCounts.size(); ++Index)
					{
						std::swap(MoveBitCounts[Index], MoveBitCounts[(Index + CSPRNG()) % MoveBitCounts.size()]);
					}

					return MoveBitCounts;
				}

				std::array<std::uint32_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits>
				GenerateRandomHashStateIndices()
				{
					CommonSecurity::RNG_ISAAC::isaac64<8> CSPRNG = CommonSecurity::RNG_ISAAC::isaac64<8>(1946379852749613ULL);

					CSPRNG.discard(2048);

					std::array<std::uint32_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits> RandomHashStateIndices {};

					std::iota(RandomHashStateIndices.begin(), RandomHashStateIndices.end(), 0);

					for(std::uint64_t Index = 0; Index < RandomHashStateIndices.size(); ++Index)
					{
						std::swap(RandomHashStateIndices[Index], RandomHashStateIndices[(Index + CSPRNG()) % RandomHashStateIndices.size()]);
					}

					return RandomHashStateIndices;
				}

				/*
					这个对应了海绵函数结构中的数学抽象的F函数(它应该是一个安全的伪随机置换函数)。

					它有以下几个步骤:
					1.哈希状态混合
					2.应用线性函数
					3.应用比特伪随机置换 (P函数)
					4.应用非线性函数
					5.每一轮需要哈希状态和哈希使用的常量进行混合

					This corresponds to the mathematical abstraction of the F function in the structure of the sponge function (it is supposed to be a safe pseudo-random permutation function).

					It has the following steps:
					1. Hash state mixing
					2. Apply linear function
					3. Apply bit pseudo-random permutation (P function)
					4. Apply nonlinear functions
					5. Each round requires a mix of hash state and constants used by the hash
				*/
				void TransfromState(std::size_t Counter)
				{
					using CommonSecurity::Binary_LeftRotateMove;
					using CommonSecurity::Binary_RightRotateMove;

					std::array<std::uint64_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2> StateBuffer {};
					std::array<std::uint64_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2> StateBuffer2 {};
					std::array<std::uint64_t, BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits> StateBuffer3 {};

					for(std::size_t RoundIndex = BitsHashState.size() - 1 - Counter; RoundIndex < BitsHashState.size(); ++RoundIndex)
					{
						//Step 1
						while(StateCurrentCounter % BitsHashState.size() != 0)
						{
							StateBuffer[StateCurrentCounter % StateBuffer.size()] = BitsHashState[StateCurrentCounter % BitsHashState.size()] ^ BitsHashState[(StateCurrentCounter + 1) % BitsHashState.size()];
							++StateCurrentCounter;
							StateBuffer[StateCurrentCounter % StateBuffer.size()] = BitsHashState[(StateCurrentCounter + 2) % BitsHashState.size()] ^ BitsHashState[(StateCurrentCounter + 3) % BitsHashState.size()];
							++StateCurrentCounter;
						}

						//Step 2
						for(std::size_t StateBufferIndex = 0; StateBufferIndex < StateBufferIndices.size(); ++StateBufferIndex)
						{
							StateBuffer2[StateBufferIndex] = StateBuffer[RightRotatedStateBufferIndices[StateBufferIndex]] ^ Binary_RightRotateMove<std::uint64_t>(StateBuffer[LeftRotatedStateBufferIndices[StateBufferIndex]], 1);
						}

						//Step 3
						StateBuffer3[0] = BitsHashState[0] ^ StateBuffer2[0];

						for(std::size_t StateBufferIndex = 1; StateBufferIndex < StateBuffer3.size(); ++StateBufferIndex)
						{
							StateBuffer3[HashStateIndices[StateBufferIndex]] = Binary_RightRotateMove<std::uint64_t>(BitsHashState[StateBufferIndex] ^ StateBuffer2[StateBufferIndex % StateBuffer2.size()], MoveBitCounts[StateCurrentCounter % MoveBitCounts.size()]);
							++StateCurrentCounter;
						}

						//Step 4
						for(std::size_t StateBufferIndex = 0; StateBufferIndex < StateBuffer3.size(); ++StateBufferIndex)
						{
							BitsHashState[StateBufferIndex] = StateBuffer3[StateBufferIndex] ^ ( ~(StateBuffer3[(StateBufferIndex + 1) % StateBuffer3.size()]) & StateBuffer3[(StateBufferIndex + 2) % StateBuffer3.size()] );
						}

						//Step 5
						BitsHashState[0] ^= HASH_ROUND_CONSTANTS[RoundIndex % HASH_ROUND_CONSTANTS.size()];
						BitsHashState[BitsHashState.size() - 1] ^= HASH_ROUND_CONSTANTS[(HASH_ROUND_CONSTANTS.size() - 1 - RoundIndex) % HASH_ROUND_CONSTANTS.size()];
					}
				}

				void AbsorbInputData(std::span<const std::uint8_t> ByteDatas)
				{
					std::vector<std::uint64_t> BitWords(ByteDatas.size() / sizeof(std::uint64_t), 0);
							
					CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(ByteDatas, BitWords.data());
							
					for(std::uint64_t InputBytesIndex = 0, OutputBytesIndex = 0; OutputBytesIndex < BitWords.size(); ++InputBytesIndex, ++OutputBytesIndex)
					{
						if(InputBytesIndex >= BITWORDS_RATE)
							InputBytesIndex = 0;
						BitsHashState[InputBytesIndex] ^= BitWords[OutputBytesIndex];
						
						//状态排列和变换(信息熵池搅拌)
						//State permutation and transformation (stirring of information entropy pool)
						for(std::size_t BlockCounter = 0; BlockCounter < (ByteDatas.size() / sizeof(std::uint64_t)); BlockCounter++)
						{
							this->TransfromState(BlockCounter);
						}
					}

					memory_set_no_optimize_function<0x00>(BitWords.data(), BitWords.size() * sizeof(std::uint64_t));
				}

				void AbsorbInputData(std::span<const std::uint64_t> BitWordDatas)
				{
					for(std::uint64_t InputBitsIndex = 0, OutputBitsIndex = 0; OutputBitsIndex < BitWordDatas.size(); ++InputBitsIndex, ++OutputBitsIndex)
					{
						if(InputBitsIndex >= BITWORDS_RATE)
							InputBitsIndex = 0;
						BitsHashState[InputBitsIndex] ^= BitWordDatas[OutputBitsIndex];

						//状态排列和变换(信息熵池搅拌)
						//State permutation and transformation (stirring of information entropy pool)
						for(std::size_t BlockCounter = 0; BlockCounter < BitWordDatas.size(); BlockCounter++)
						{
							this->TransfromState(BlockCounter);
						}
					}
				}

				void SqueezeOutputData(std::span<std::uint8_t> ByteDatas)
				{
					std::vector<std::uint64_t> BitWords(HashBitSize / std::numeric_limits<std::uint64_t>::digits, 0);

					for(std::uint64_t BitsIndex = 0; BitsIndex < BitWords.size(); ++BitsIndex)
					{
						BitWords[BitsIndex] = BitsHashState[BitsIndex];
					}

					CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(BitWords, ByteDatas.data());
				}

				void SqueezeOutputData(std::span<std::uint64_t> WordDatas)
				{
					for(std::uint64_t BitsIndex = 0; BitsIndex < (HashBitSize / std::numeric_limits<std::uint64_t>::digits); ++BitsIndex)
					{
						WordDatas[BitsIndex] = BitsHashState[BitsIndex];
					}
				}

			public:

				void Reset()
				{
					this->StateCurrentCounter = 0;
					memory_set_no_optimize_function<0x00>(BitsHashState.data(), BitsHashState.size() * sizeof(std::uint64_t));
				}

				//不提供外部数据的测试
				//Tests that do not provide external data
				std::vector<std::uint64_t> Test()
				{
					for(std::size_t BlockCounter = 0; BlockCounter < (HashBitSize / std::numeric_limits<std::uint64_t>::digits); BlockCounter++)
					{
						this->TransfromState(BlockCounter);
					}

					std::vector<std::uint64_t> TestData(HashBitSize / std::numeric_limits<std::uint64_t>::digits, 0);
					this->SqueezeOutputData(TestData);

					this->Reset();

					return TestData;
				}

				void SecureHash
				(
					std::span<const std::uint8_t> InputData,
					std::span<std::uint8_t> OuputData
				)
				{
					std::vector<std::uint8_t> BlockDataBuffer(InputData.begin(), InputData.end());
					
					//填充数据和吸收数据阶段
					//Pad data and Absorbing data stage
					if(BlockDataBuffer.size() % BYTES_RATE != 0)
					{
						for(std::size_t PadCount = 0; PadCount < BlockDataBuffer.size() % BYTES_RATE; ++PadCount)
						{
							BlockDataBuffer.push_back(PAD_BYTE_DATA);
						}
					}
					this->AbsorbInputData(BlockDataBuffer);

					//挤压数据阶段
					//squeeze data stage
					this->SqueezeOutputData(OuputData);

					memory_set_no_optimize_function<0x00>(BlockDataBuffer.data(), BlockDataBuffer.size());

					//如果已经生成哈希摘要数据，就必须把当前状态全部重置和清理
					//如果不重置和清理，你将会影响哈希函数的质量
					//If the hash summary data has been generated, the current state must be completely reset and cleaned up.
					//If you don't reset and clean, you will affect the quality of the hash function
					this->Reset();
				}

				void SecureHash
				(
					std::span<const std::uint64_t> InputData,
					std::span<std::uint64_t> OuputData
				)
				{
					std::vector<std::uint64_t> BlockDataBuffer(InputData.begin(), InputData.end());
					
					//填充数据和吸收数据阶段
					//Pad data and Absorbing data stage
					if(BlockDataBuffer.size() % BITWORDS_RATE != 0)
					{
						for(std::size_t PadCount = 0; PadCount < BlockDataBuffer.size() % BYTES_RATE; ++PadCount)
						{
							BlockDataBuffer.push_back(PAD_BITSWORD_DATA);
						}
					}
					this->AbsorbInputData(BlockDataBuffer);
					
					//挤压数据阶段
					//squeeze data stage
					this->SqueezeOutputData(OuputData);

					memory_set_no_optimize_function<0x00>(BlockDataBuffer.data(), BlockDataBuffer.size() * sizeof(std::uint64_t));

					//如果已经生成哈希摘要数据，就必须把当前状态全部重置和清理
					//如果不重置和清理，你将会影响哈希函数的质量
					//If the hash summary data has been generated, the current state must be completely reset and cleaned up.
					//If you don't reset and clean, you will affect the quality of the hash function
					this->Reset();
				}

				CustomSecureHash() 
					:
					MoveBitCounts(GenerateRandomMoveBitCounts()), HashStateIndices(GenerateRandomHashStateIndices())
				{
					static_assert(HashBitSize >= 128 && HashBitSize % 8 == 0, "");

					std::ranges::rotate_copy(StateBufferIndices.begin(), StateBufferIndices.begin() + 1, StateBufferIndices.end(), LeftRotatedStateBufferIndices.begin());
					std::ranges::rotate_copy(StateBufferIndices.begin(), StateBufferIndices.end() - 1, StateBufferIndices.end(), RightRotatedStateBufferIndices.begin());
				}
			};

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class CommonStateDataPointer;

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class SecureSubkeyGeneratationModule;

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class SecureRoundSubkeyGeneratationModule;

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class MixTransformationUtil;

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class SubkeyMatrixOperation;

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class CommonStateData
			{

			private:

				/*
					BlockSize / KeySize (QuadWord)
				*/

				template<std::size_t, std::size_t>
				friend class CommonStateDataPointer;

				template<std::size_t, std::size_t>
				friend class SecureSubkeyGeneratationModule;

				template<std::size_t, std::size_t>
				friend class SecureRoundSubkeyGeneratationModule;

				template<std::size_t, std::size_t>
				friend class SubkeyMatrixOperation;

				template<std::size_t, std::size_t>
				friend class MixTransformationUtil;

				template<std::size_t, std::size_t>
				friend class OaldresPuzzle_Cryptic::Version2::StateData_Worker;

				static constexpr std::size_t OPC_DataBlockSize = OPC_QuadWord_DataBlockSize;
				static constexpr std::size_t OPC_KeyBlockSize = OPC_QuadWord_KeyBlockSize;

				CommonSecurity::RND::BernoulliDistribution BernoulliDistributionObject = CommonSecurity::RND::BernoulliDistribution(0.5);

				//自定义的随机数生成器
				//Customized random number generator
				std::unique_ptr<LinearFeedbackShiftRegister> LFSR_Pointer = nullptr;
				std::unique_ptr<NonlinearFeedbackShiftRegister> NLFSR_Pointer = nullptr;
				std::unique_ptr<SimulateDoublePendulum> SDP_Pointer = nullptr;

				LinearFeedbackShiftRegister* LFSR_ClassicPointer = this->LFSR_Pointer.get();
				NonlinearFeedbackShiftRegister* NLFSR_ClassicPointer = this->NLFSR_Pointer.get();
				SimulateDoublePendulum* SDP_ClassicPointer = this->SDP_Pointer.get();

				//索引数的容器(将会被乱序洗牌)
				//Containers of indices number (will be shuffled in disorder)
				//用在单向变换函数的步骤中，会根据当前乱序数作为“RandomIndex”，访问生成的子密钥(来自变换后的密钥矩阵)和生成的轮函数的子密钥
				//In the step used for the one-way transform function, the generated subkey (from the transformed key matrix) and the generated subkey of the wheel function are accessed based on the current random number as "RandomIndex".
				std::array<std::uint32_t, OPC_KeyBlockSize * 2> MatrixOffsetWithRandomIndices = CommonToolkit::make_array<std::uint32_t, OPC_QuadWord_KeyBlockSize * 2>();

				//Word(32 Bit)数据的初始向量，用于关联Word数据的密钥
				//Initial vector of Word(32 Bit) data, used to associate the key of Word data
				std::vector<std::uint32_t> WordDataInitialVector;

				static constexpr std::size_t OPC_KeyMatrix_Rows = OPC_KeyBlockSize * 2;
				static constexpr std::size_t OPC_KeyMatrix_Columns = OPC_KeyBlockSize * 2;

				//Word(64 Bit)数据的密钥向量，用于生成子密钥的材料
				//Key vector for Word (64 Bit) data, material for generating subkeys
				std::array<std::uint64_t, OPC_KeyBlockSize> WordKeyDataVector {};

				Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
				RandomQuadWordMatrix = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>::Zero();

				Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
				//变换的子密钥矩阵(来自变换的RandomQuadWordMatrix)
				//Generated subkey (from the transformed key matrix)
				TransformedSubkeyMatrix = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>::Zero();

			public:

				void LFSR_Seed(std::uint64_t LFSR_SeedNumber)
				{
					if(LFSR_SeedNumber == 0)
						LFSR_SeedNumber = 1;

					this->LFSR_ClassicPointer->seed(LFSR_SeedNumber);
				}

				void NLFSR_Seed(std::uint64_t NLFSR_SeedNumber)
				{
					if(NLFSR_SeedNumber == 0)
						NLFSR_SeedNumber = 1;

					this->NLFSR_ClassicPointer->seed(NLFSR_SeedNumber);
				}

				void SDP_Seed(std::uint64_t SDP_SeedNumber)
				{
					this->SDP_ClassicPointer->seed(SDP_SeedNumber);
				}

				CommonStateData(std::span<std::uint8_t> InitialBytes_MemorySpan, std::uint64_t LFSR_SeedNumber, std::uint64_t NLFSR_SeedNumber)
					:
					LFSR_Pointer(std::make_unique<LinearFeedbackShiftRegister>(LFSR_SeedNumber)),
					NLFSR_Pointer(std::make_unique<NonlinearFeedbackShiftRegister>(NLFSR_SeedNumber)),
					SDP_Pointer(std::make_unique<SimulateDoublePendulum>(0xB7E151628AED2A6AULL))
				{
					//OPC_DataBlockSize必须是16的倍数，而且必须不能小于2（128 Bit / 8 Bit(1 Byte) == 16 Byte = 16 Byte / 8 Byte(1 QuadWords) == 2 QuadWords）
					static_assert((OPC_DataBlockSize % 2) == 0 && OPC_DataBlockSize >= 2, "StateData_Worker(CommonStateData): OPC_DataBlockSize must be a multiple of 2 quad-words and must not be less than 2 quad-words (128Bit)");
				
					//OPC_KeyBlockSize必须是32的倍数，而且必须不能小于4 (256 Bit / 8 Bit(1 Byte) == 32 Byte = 32 Byte / 8 Byte(1 QuadWords) == 4 QuadWords），否则不符合后量子标准的数据安全性！
					static_assert((OPC_KeyBlockSize % 4) == 0 && OPC_KeyBlockSize >= 4, "StateData_Worker(CommonStateData): OPC_KeyBlockSize must be a multiple of 4 quad-words and must not be less than 4 quad-words (256Bit), otherwise it does not meet the post-quantum standard of data security!");

					//OPC_KeyBlockSize必须是OPC_DataBlockSize的任意倍数。
					static_assert(OPC_KeyBlockSize > OPC_DataBlockSize && (OPC_KeyBlockSize % OPC_DataBlockSize) == 0, "StateData_Worker(CommonStateData): OPC_KeyBlockSize must be any multiple of OPC_DataBlockSize !");

					my_cpp2020_assert
					(
						LFSR_SeedNumber != 0 && NLFSR_SeedNumber != 0,
						"OaldresPuzzle_Cryptic::Version2: Invalid custom random number generator for number seeding!",
						std::source_location::current()
					);

					if(InitialBytes_MemorySpan.size() % (OPC_DataBlockSize * sizeof(std::uint64_t)) != 0)
						my_cpp2020_assert(false, "The InitialBytes_MemorySpan size of the referenced data is not a multiple of (OPC_DataBlockSize * sizeof(std::uint64_t)) byte!", std::source_location::current());
				
					this->WordDataInitialVector = CommonToolkit::IntegerExchangeBytes::MessagePacking<std::uint32_t, std::uint8_t>(InitialBytes_MemorySpan.data(), InitialBytes_MemorySpan.size());
				}

				~CommonStateData()
				{
					volatile void* CheckPointer = nullptr;

					this->LFSR_Pointer.reset();
					this->NLFSR_Pointer.reset();
					this->SDP_Pointer.reset();
				
					CheckPointer = memory_set_no_optimize_function<0x00>(this->MatrixOffsetWithRandomIndices.data(), this->MatrixOffsetWithRandomIndices.size() * sizeof(std::uint32_t));
					my_cpp2020_assert(CheckPointer == this->MatrixOffsetWithRandomIndices.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->WordDataInitialVector.data(), this->WordDataInitialVector.size() * sizeof(std::uint32_t));
					my_cpp2020_assert(CheckPointer == this->WordDataInitialVector.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->WordKeyDataVector.data(), this->WordKeyDataVector.size() * sizeof(std::uint64_t));
					my_cpp2020_assert(CheckPointer == this->WordKeyDataVector.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;

					this->TransformedSubkeyMatrix.setZero();
				}
			};

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class CommonStateDataPointer
			{

			private:

				/*
					BlockSize / KeySize (QuadWord)
				*/

				template<std::size_t, std::size_t>
				friend class SecureSubkeyGeneratationModule;

				template<std::size_t, std::size_t>
				friend class SecureRoundSubkeyGeneratationModule;

				template<std::size_t, std::size_t>
				friend class SubkeyMatrixOperation;

				template<std::size_t, std::size_t>
				friend class MixTransformationUtil;

				template<std::size_t, std::size_t>
				friend class OaldresPuzzle_Cryptic::Version2::StateData_Worker;

				static constexpr std::size_t OPC_KeyMatrix_Rows = ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>::OPC_KeyMatrix_Rows;
				static constexpr std::size_t OPC_KeyMatrix_Columns = ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>::OPC_KeyMatrix_Columns;

				ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>* PointerData = nullptr;

				ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>&
				AccessReference()
				{
					return *PointerData;
				}

			public:

				explicit CommonStateDataPointer
				(
					ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>& CommonStateDataObject
				)
					:
					PointerData(std::addressof(CommonStateDataObject))
				{
			
				}

				~CommonStateDataPointer()
				{
					this->PointerData = nullptr;
				}

			};

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class MixTransformationUtil
			{
			
			private:

				/*
					BlockSize / KeySize (QuadWord)
				*/
				template<std::size_t, std::size_t>
				friend class SubkeyMatrixOperation;

				CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize> CommonStateDataPointerObject;

				/*
					This byte-substitution box: Strict avalanche criterion is satisfied !
					ByteDataSecurityTestData Transparency Order Is: 7.81299
					ByteDataSecurityTestData Nonlinearity Is: 94
					ByteDataSecurityTestData Propagation Characteristics Is: 8
					ByteDataSecurityTestData Delta Uniformity Is: 10
					ByteDataSecurityTestData Robustness Is: 0.960938
					ByteDataSecurityTestData Signal To Noise Ratio/Differential Power Analysis Is: 9.29288
					ByteDataSecurityTestData Absolute Value Indicatorer Is: 120
					ByteDataSecurityTestData Sum Of Square Value Indicator Is: 244160
					ByteDataSecurityTestData Algebraic Degree Is: 8
					ByteDataSecurityTestData Algebraic Immunity Degree Is: 4
				*/
				std::array<std::uint8_t, 256> MaterialSubstitutionBox0
				{
					0xF4, 0x53, 0x75, 0x96, 0xBE, 0x6F, 0x66, 0x11, 0x80, 0xC8, 0x5C, 0xDF, 0xF7, 0xAE, 0xC6, 0x93,
					0xF1, 0x2F, 0x5F, 0x47, 0xB8, 0xF2, 0x71, 0x30, 0x1E, 0x87, 0x32, 0x0A, 0xCA, 0x6E, 0x16, 0xCB,
					0x65, 0x2C, 0x35, 0x0D, 0x8C, 0x1C, 0x3A, 0xA8, 0xC4, 0x84, 0xC7, 0x46, 0x0B, 0xCE, 0xFC, 0xB1,
					0x62, 0x5A, 0x59, 0x6D, 0x42, 0x3D, 0xA9, 0xAA, 0xD6, 0x14, 0x88, 0x02, 0xE8, 0x82, 0x9A, 0x7E,
					0xF6, 0x9E, 0x43, 0x27, 0x33, 0x4C, 0x57, 0x01, 0x8B, 0x25, 0x79, 0xB0, 0x18, 0xB9, 0xB2, 0x9D,
					0xAF, 0x0E, 0xD4, 0xE1, 0x2E, 0x0C, 0xDB, 0x8E, 0x1D, 0xE2, 0x00, 0x51, 0xB3, 0xF3, 0x7F, 0x99,
					0xA5, 0xCD, 0x77, 0xB4, 0xD9, 0x61, 0x76, 0x70, 0x40, 0x9F, 0x5E, 0xFF, 0x4D, 0xF9, 0x86, 0xAB,
					0xD3, 0x41, 0xB5, 0x2B, 0xA1, 0x39, 0x63, 0xC9, 0x6C, 0x73, 0x9B, 0xBB, 0x7B, 0xD0, 0xAD, 0x7C,
					0xEE, 0xDE, 0xF8, 0xD8, 0xB6, 0xED, 0x98, 0x19, 0xFA, 0x8F, 0x92, 0xAC, 0x12, 0xC2, 0x05, 0xCF,
					0xC0, 0xEF, 0x08, 0xFE, 0xDD, 0x50, 0x23, 0x4B, 0xC3, 0x15, 0xE5, 0xD5, 0x3E, 0xE0, 0x2A, 0x52,
					0x95, 0x44, 0x72, 0x56, 0x0F, 0x1B, 0xF5, 0x90, 0xE3, 0x58, 0x69, 0x8D, 0x48, 0x26, 0xD2, 0xA2,
					0x7A, 0x38, 0x49, 0xEC, 0x13, 0x67, 0x07, 0x81, 0xE9, 0xD1, 0x34, 0x36, 0x85, 0xA3, 0x5D, 0x22,
					0x24, 0x6B, 0xBA, 0x37, 0x7D, 0xBF, 0x6A, 0x2D, 0x45, 0x3C, 0x55, 0x5B, 0x74, 0xF0, 0xDA, 0x83,
					0xDC, 0x4A, 0x91, 0x31, 0x97, 0xA4, 0xE6, 0x1A, 0x1F, 0x4F, 0xC5, 0x54, 0xFD, 0x17, 0x06, 0x89,
					0x60, 0xA6, 0xB7, 0x3B, 0xA7, 0xFB, 0x78, 0x94, 0xBD, 0xA0, 0xE7, 0xD7, 0xEB, 0x21, 0xE4, 0xEA,
					0x09, 0xC1, 0x03, 0xBC, 0xCC, 0x68, 0x20, 0x04, 0x28, 0x9C, 0x4E, 0x3F, 0x10, 0x29, 0x8A, 0x64,
				};

				/*
					This byte-substitution box: Strict avalanche criterion is satisfied !
					ByteDataSecurityTestData Transparency Order Is: 7.80907
					ByteDataSecurityTestData Nonlinearity Is: 94
					ByteDataSecurityTestData Propagation Characteristics Is: 8
					ByteDataSecurityTestData Delta Uniformity Is: 12
					ByteDataSecurityTestData Robustness Is: 0.953125
					ByteDataSecurityTestData Signal To Noise Ratio/Differential Power Analysis Is: 9.25523
					ByteDataSecurityTestData Absolute Value Indicatorer Is: 96
					ByteDataSecurityTestData Sum Of Square Value Indicator Is: 199424
					ByteDataSecurityTestData Algebraic Degree Is: 8
					ByteDataSecurityTestData Algebraic Immunity Degree Is: 4
				*/
				std::array<std::uint8_t, 256> MaterialSubstitutionBox1
				{
					0x88, 0xB4, 0x21, 0xF9, 0xC9, 0xBC, 0x7C, 0x5D, 0xAB, 0x7D, 0x04, 0x69, 0x96, 0x8E, 0x00, 0x71,
					0x94, 0xB0, 0xFB, 0xE1, 0xD6, 0xA2, 0xD5, 0xE6, 0x74, 0x6C, 0xB9, 0x31, 0xAE, 0xDD, 0x49, 0x19,
					0x02, 0x75, 0x34, 0x33, 0x46, 0x0A, 0xA9, 0x54, 0x1F, 0x5F, 0xCA, 0x56, 0xD2, 0xD8, 0x41, 0xD9,
					0x0D, 0x47, 0xF0, 0xB3, 0x62, 0x8F, 0x52, 0x08, 0x3F, 0x4C, 0x84, 0x1C, 0xA8, 0x3A, 0x7A, 0xCE,
					0x22, 0x2C, 0x1B, 0x4D, 0xFA, 0x30, 0x2F, 0x80, 0x3B, 0x55, 0x91, 0x05, 0x61, 0x03, 0x64, 0x87,
					0xFF, 0xE0, 0x26, 0xBE, 0x68, 0x0E, 0x50, 0xC3, 0x29, 0x42, 0x6F, 0x2B, 0x53, 0x79, 0xB5, 0x27,
					0x77, 0x97, 0x32, 0x38, 0x07, 0xBB, 0xF7, 0xF5, 0x28, 0x11, 0x36, 0x9B, 0x5C, 0x81, 0x65, 0x6A,
					0xEB, 0xE5, 0x17, 0xF4, 0x3C, 0xE9, 0x39, 0x58, 0xF8, 0x66, 0x15, 0xC6, 0xA4, 0xEA, 0xE2, 0xDF,
					0xCC, 0xFD, 0x3D, 0xEF, 0x1A, 0x24, 0x4A, 0xBF, 0xB6, 0x67, 0xF6, 0x45, 0xB7, 0x4B, 0xB2, 0x5E,
					0x60, 0x7F, 0x89, 0x76, 0xD4, 0x59, 0xE4, 0xAD, 0xCB, 0xA3, 0xFC, 0x7B, 0xBD, 0x35, 0x51, 0xC7,
					0xA0, 0xA1, 0x8C, 0x13, 0x83, 0xA5, 0xCF, 0x44, 0x95, 0xDE, 0x9E, 0xF3, 0x1D, 0x40, 0x2E, 0x0F,
					0x72, 0xD0, 0x6E, 0x8A, 0xAF, 0x6D, 0x16, 0xC1, 0xE7, 0x43, 0x8B, 0x9C, 0x4F, 0x82, 0x10, 0xDA,
					0x57, 0x0C, 0xCD, 0x63, 0x9F, 0xBA, 0x0B, 0x4E, 0x90, 0x93, 0xAA, 0xF2, 0xC0, 0x20, 0x14, 0x78,
					0xEE, 0xA7, 0x85, 0x3E, 0x5A, 0x2D, 0x01, 0xED, 0xC4, 0xAC, 0x25, 0x73, 0x5B, 0x98, 0x06, 0xEC,
					0xDC, 0x12, 0xB8, 0xD3, 0xD7, 0xC5, 0xE3, 0x9A, 0xF1, 0xD1, 0xE8, 0x6B, 0xB1, 0x48, 0xFE, 0x86,
					0x70, 0xA6, 0x9D, 0x18, 0xC2, 0x99, 0x1E, 0x09, 0x7E, 0x37, 0x2A, 0xDB, 0x8D, 0xC8, 0x23, 0x92,
				};

				std::array<std::uint32_t, 2> Word32Bit_StreamCipherStateRegisters {0,0};

				std::uint32_t SwapBits(std::uint32_t Word, std::uint32_t BitPosition, std::uint32_t BitPosition2)
				{
					/* Move BitPosition'th to rightmost side (Get Bit) */
					//std::uint32_t Bit1 = (Word >> BitPosition) & 1；
			
					/* Move BitPosition2'th to rightmost side (Get Bit) */
					//std::uint32_t Bit2 = (Word >> BitPosition2) & 1；

					/* Exclusive Or the two bits */
					//std::uint32_t BitMask = Bit1 ^ Bit2;

					/* Put the Exclusive or-ed bit back to their original positions */
					//BitMask = (BitMask << BitPosition) | (BitMask << BitPosition2);

					/* Exclusive or 'BitMask' with the original number so that the two sets are swapped */
					//return Word ^ BitMask;

					std::uint32_t BitMask = ( (Word >> BitPosition) & std::uint32_t{1} ) ^ ( (Word >> BitPosition2) & std::uint32_t{1} );

					//If it is two same bits, then return the word that does not change
					if(BitMask == std::uint32_t{0})
						return Word;

					BitMask = (BitMask << BitPosition) | (BitMask << BitPosition2);
					return Word ^ BitMask;
				}

				/*
					单比特的重组，混淆设计方案 (字 密钥)， 由Twilight-Dream 设计
					Single-bit restructuring, confusion design scheme (Word key), designed by Twilight-Dream

					std::uint32_t (Bit 32)
					0 0 0 0 0 0 0 0
					0 0 0 0 0 0 0 0
					0 0 0 0 0 0 0 0
					0 0 0 0 0 0 0 0

					//Green Step
					Bit 0 swap Bit 9
					Bit 1 swap Bit 18
					Bit 2 swap Bit 27

					Bit 5 swap Bit 28
					Bit 6 swap Bit 21
					Bit 7 swap Bit 14

					//Orange Step
					Bit 10 swap Bit 24
					Bit 11 swap Bit 25
					Bit 12 swap Bit 30
					Bit 13 swap Bit 31

					//Red Step
					Bit 19 swap Bit 4
					Bit 20 swap Bit 3

					//Yellow Step
					Bit 17 swap Bit 2
					Bit 22 swap Bit 5

					//Blue Step
					Bit 27 swap Bit 15
					Bit 28 swap Bit 9
				*/
				inline std::uint32_t WordBitRestruct(std::uint32_t WordKey)
				{
					WordKey = this->SwapBits(WordKey, 0, 9);
					WordKey = this->SwapBits(WordKey, 1, 18);
					WordKey = this->SwapBits(WordKey, 2, 27);

					WordKey = this->SwapBits(WordKey, 5, 28);
					WordKey = this->SwapBits(WordKey, 6, 21);
					WordKey = this->SwapBits(WordKey, 7, 14);

					WordKey = this->SwapBits(WordKey, 10, 24);
					WordKey = this->SwapBits(WordKey, 11, 25);
					WordKey = this->SwapBits(WordKey, 12, 30);
					WordKey = this->SwapBits(WordKey, 13, 31);

					WordKey = this->SwapBits(WordKey, 19, 4);
					WordKey = this->SwapBits(WordKey, 20, 3);

					WordKey = this->SwapBits(WordKey, 17, 2);
					WordKey = this->SwapBits(WordKey, 22, 5);

					WordKey = this->SwapBits(WordKey, 27, 15);
					WordKey = this->SwapBits(WordKey, 28, 8);

					return WordKey;
				}

				std::array<std::uint8_t, 256> RegenerationRandomMaterialSubstitutionBox(std::span<const std::uint8_t> OldDataBox)
				{
					volatile void* CheckPointer = nullptr;

					auto& NLFSR_Object = *(CommonStateDataPointerObject.AccessReference().NLFSR_ClassicPointer);

					const std::size_t OldDataArraySize = OldDataBox.size();
					SegmentTree<std::uint8_t, 256> SegmentTreeObject;
					
					std::array<std::uint8_t, 256> NewDataBox;
					const std::size_t NewDataArraySize = NewDataBox.size();

					for(std::size_t Index = 0, Index2 = 0; Index < OldDataArraySize && Index2 < NewDataArraySize; Index++, Index2++)
					{
						if(Index == OldDataArraySize - 1 && OldDataBox[Index] == SegmentTreeObject.Get(0))
						{
							//Need to re-operate data
							CheckPointer = memory_set_no_optimize_function<0x00>(NewDataBox.data(), NewDataBox.size());
							CheckPointer = nullptr;
							SegmentTreeObject.Clear();
							Index = 0;
							Index2 = 0;
							continue;
						}

						std::size_t Order = NLFSR_Object() % (OldDataArraySize - Index), Position = SegmentTreeObject.Get(Order);
						while (OldDataBox[Index] == Position)
							Order = NLFSR_Object() % (OldDataArraySize - Index), Position = SegmentTreeObject.Get(Order);
						NewDataBox[Index2] = Position, SegmentTreeObject.Set(Position);
					}

					return NewDataBox;
				}

				void RegenerationRandomMaterialSubstitutionBox()
				{
					//Regenerate material substitution boxes
					//重新生成材料替代箱
					MaterialSubstitutionBox0 = this->RegenerationRandomMaterialSubstitutionBox(MaterialSubstitutionBox0);
					MaterialSubstitutionBox1 = this->RegenerationRandomMaterialSubstitutionBox(MaterialSubstitutionBox1);
				}

			public:

				inline void Word32Bit_Initialize()
				{
					auto& LFSR_Object = *(CommonStateDataPointerObject.AccessReference().LFSR_ClassicPointer);
					auto& NLFSR_Object = *(CommonStateDataPointerObject.AccessReference().NLFSR_ClassicPointer);
					auto& SDP_Object = *(CommonStateDataPointerObject.AccessReference().SDP_ClassicPointer);
					
					auto& StateValue0 = this->Word32Bit_StreamCipherStateRegisters[0];
					auto& StateValue1 = this->Word32Bit_StreamCipherStateRegisters[1];

					std::uint64_t BaseNumber = NLFSR_Object() ^ SDP_Object(0ULL, 0xFFFFFFFFFFFFFFFFULL);
					volatile std::uint64_t RandomNumber = 0;

					for (size_t Count = 129; Count > 0; --Count)
					{
						BaseNumber = NLFSR_Object.unpredictable_bits(BaseNumber % 0xFFFFFFFFFFFFFFFFULL, 64) ^ LFSR_Object();
					}

					RandomNumber = NLFSR_Object() ^ ~(LFSR_Object() ^ BaseNumber);

					StateValue0 = static_cast<std::uint32_t>(RandomNumber >> 32);
					StateValue1 = static_cast<std::uint32_t>((RandomNumber << 32) >> 32);

					RandomNumber = 0;
				}

				/*
					Word数据比特的混淆和扩散，然后扩展序列的大小
					Word data bits are obfuscated and spread, and then the size of the sequence is expanded
				*/
				inline std::vector<std::uint32_t> Word32Bit_ExpandKey(std::span<const std::uint32_t> NeedHashDataWords)
				{
					std::vector<std::uint32_t> ProcessedWordKeys(NeedHashDataWords.size() * 12, 0);
				
					std::size_t NeedHashDataIndex = 0;
					while(NeedHashDataIndex < NeedHashDataWords.size())
					{

						/*
							Step 1 : Data word do bit reorganization
							数据字做比特重组
						*/

						const std::uint32_t RestructedWordKey = this->WordBitRestruct(NeedHashDataWords[NeedHashDataIndex]);

						if constexpr(std::endian::native == std::endian::big)
							RestructedWordKey = CommonToolkit::ByteSwap::byteswap(RestructedWordKey);

						/*
							Step 2 : Data words do bit splitting
							数据字做比特分割
						*/

						std::uint32_t UpPartWord = (RestructedWordKey >> 16);
						std::uint32_t DownPartWord = (RestructedWordKey << 16) >> 16;
						std::uint32_t LeftPartWord = (RestructedWordKey & 0xF000'0000U) | ( (RestructedWordKey & 0x00F0'0000U) << 4 ) | ( (RestructedWordKey & 0x0000'F000U) << 8 ) |  ( (RestructedWordKey & 0x0000'00F0U) << 12 );
						std::uint32_t RightPartWord = ( (RestructedWordKey & 0x0F00'0000U) << 4 ) | ( (RestructedWordKey & 0x000F'0000U) << 8 ) | ( (RestructedWordKey & 0x0000'0F00U) << 12 ) | ( (RestructedWordKey & 0x0000'000FU) << 14 );

						/*
							Step 3 : Data words do byte mixing and number expansions
							数据字做字节混合和数量扩展
						*/

						volatile std::uint32_t DiffusionResult0 = UpPartWord ^ DownPartWord;
						volatile std::uint32_t DiffusionResult1 = LeftPartWord ^ RightPartWord;
						volatile std::uint32_t DiffusionResult2 = UpPartWord ^ LeftPartWord;
						volatile std::uint32_t DiffusionResult3 = DownPartWord ^ RightPartWord;
						volatile std::uint32_t DiffusionResult4 = UpPartWord ^ RightPartWord;
						volatile std::uint32_t DiffusionResult5 = DownPartWord ^ LeftPartWord;

						/*
							https://bigprimes.org/
							https://www.numberempire.com/primenumbers.php

							286331173
							3676758680
							4123665948
							3193679190
							339204479
							2017551733
							3451580309
							2711043323
							645676697
							1066195267
							4172536373
							3285900997
						*/
					
						std::uint32_t KeyIndex = 0;
						while(KeyIndex < ProcessedWordKeys.size())
						{
							ProcessedWordKeys[KeyIndex] ^= (DiffusionResult0 << 8 | DiffusionResult4) + 0x11111125U;
							ProcessedWordKeys[KeyIndex + 1] ^= (DiffusionResult0 | DiffusionResult4 >> 24) - 0xDB26E298U;
							ProcessedWordKeys[KeyIndex + 2] ^= (DiffusionResult5 << 16 | DiffusionResult1) * 0xF5CA261CU;
							ProcessedWordKeys[KeyIndex + 3] = (DiffusionResult5 | DiffusionResult1 >> 16) % 0xBE5BAD56U;
							ProcessedWordKeys[KeyIndex + 4] ^= (DiffusionResult2 << 24 | DiffusionResult3) * 0x1437D97FU;
							ProcessedWordKeys[KeyIndex + 5] ^= (DiffusionResult2 | DiffusionResult3 >> 8) + 0x78416575U;
							ProcessedWordKeys[KeyIndex + 6] = (DiffusionResult0 >> 24 | DiffusionResult4) % 0xCDBAEF95U;
							ProcessedWordKeys[KeyIndex + 7] ^= (DiffusionResult0 | DiffusionResult4 << 8) - 0xA1973CFBU;
							ProcessedWordKeys[KeyIndex + 8] ^= (DiffusionResult5 >> 16 | DiffusionResult1) * 0x267C3E99U;
							ProcessedWordKeys[KeyIndex + 9] ^= (DiffusionResult5 | DiffusionResult1 << 16) - 0x3F8CD943U;
							ProcessedWordKeys[KeyIndex + 10] = (DiffusionResult2 >> 8 | DiffusionResult3) % 0xF8B3DA35U;
							ProcessedWordKeys[KeyIndex + 11] ^= (DiffusionResult2 | DiffusionResult3 << 24) + 0xC3DADEC5U;
							
							std::ranges::rotate(ProcessedWordKeys.begin(), ProcessedWordKeys.end() - 1, ProcessedWordKeys.end());

							DiffusionResult0 -= ProcessedWordKeys[KeyIndex] | ProcessedWordKeys[KeyIndex + 11];
							DiffusionResult5 += ProcessedWordKeys[KeyIndex + 1] & ProcessedWordKeys[KeyIndex + 10];
							DiffusionResult1 -= ProcessedWordKeys[KeyIndex + 2] | ProcessedWordKeys[KeyIndex + 9];
							DiffusionResult4 += ProcessedWordKeys[KeyIndex + 3] & ProcessedWordKeys[KeyIndex + 8];
							DiffusionResult2 -= ProcessedWordKeys[KeyIndex + 4] | ProcessedWordKeys[KeyIndex + 7];
							DiffusionResult3 += ProcessedWordKeys[KeyIndex + 5] & ProcessedWordKeys[KeyIndex + 6];

							std::ranges::rotate(ProcessedWordKeys.begin(), ProcessedWordKeys.end() - 1, ProcessedWordKeys.end());

							DiffusionResult0 = this->WordBitRestruct(DiffusionResult0);
							DiffusionResult1 = this->WordBitRestruct(DiffusionResult1);
							DiffusionResult2 = this->WordBitRestruct(DiffusionResult2);
							DiffusionResult3 = this->WordBitRestruct(DiffusionResult3);
							DiffusionResult4 = this->WordBitRestruct(DiffusionResult4);
							DiffusionResult5 = this->WordBitRestruct(DiffusionResult5);

							KeyIndex += 12;
						}

						//临时数据置零，防止被分析
						//Temporary data zeroing to prevent analysis

						DiffusionResult0 = 0;
						DiffusionResult1 = 0;
						DiffusionResult2 = 0;
						DiffusionResult3 = 0;
						DiffusionResult4 = 0;
						DiffusionResult5 = 0;

						UpPartWord = 0;
						DownPartWord = 0;
						LeftPartWord = 0;
						RightPartWord = 0;

						++NeedHashDataIndex;
					}

					return ProcessedWordKeys;
				}

				/*
					该算法参考了中国商用流密码，祖冲之的混合变换轮函数
					The algorithm is referenced from the Chinese commercial stream cipher, Zu Chongzhi's mix transform round function

					非线性变换和线性变换函数
					Nonlinear transformations and linear transformation functions
				*/
				inline std::uint32_t Word32Bit_KeyWithStreamCipherFunction(std::span<const std::uint32_t> RandomWordDataMaterial)
				{
					my_cpp2020_assert(RandomWordDataMaterial.size() == 4, "", std::source_location::current());

					auto& LFSR_Object = *(CommonStateDataPointerObject.AccessReference().LFSR_ClassicPointer);
					auto& NLFSR_Object = *(CommonStateDataPointerObject.AccessReference().NLFSR_ClassicPointer);

					auto& StateValue0 = this->Word32Bit_StreamCipherStateRegisters[0];
					auto& StateValue1 = this->Word32Bit_StreamCipherStateRegisters[1];

					std::uint32_t RandomWordData0 = (RandomWordDataMaterial[0] ^ StateValue0) + StateValue1;
					
					const std::uint32_t RandomWordData1 = StateValue0 + RandomWordDataMaterial[1];
					const std::uint32_t RandomWordData2 = StateValue1 ^ RandomWordDataMaterial[2];

					volatile std::uint32_t RandomWordDataA = (RandomWordData1 << 16) | (RandomWordData2 >> 16);
					volatile std::uint32_t RandomWordDataB = (RandomWordData2 << 16) | (RandomWordData1 >> 16);

					/*
						线性变换
						基于固定的二进制多项式, 伽罗瓦有限域(power(2, 32))

						Linear Transformation
						Based on a fixed binary polynomial, Galois finite field (power(2, 32))
					*/
					StateValue0 = RandomWordDataA
						^ std::rotl(RandomWordDataA, 2)
						^ std::rotl(RandomWordDataA, 10)
						^ std::rotl(RandomWordDataA, 18)
						^ std::rotl(RandomWordDataA, 24);

					StateValue1 = RandomWordDataB
						^ std::rotl(RandomWordDataB, 8)
						^ std::rotl(RandomWordDataB, 14)
						^ std::rotl(RandomWordDataB, 22)
						^ std::rotl(RandomWordDataB, 30);

					/*
						非线性变换
						基于动态生成的字节替代盒的查找和替换

						Nonlinear Transformation
						Find and replace based on dynamically generated byte substitution boxes
					*/
					StateValue0 = (MaterialSubstitutionBox0[(StateValue0 >> 24) & 0xFF]) << 24
						| (MaterialSubstitutionBox1[(StateValue0 >> 16) & 0xFF]) << 16
						| (MaterialSubstitutionBox0[(StateValue0 >> 8) & 0xFF]) << 8
						| (MaterialSubstitutionBox1[StateValue0 & 0xFF]);

					StateValue1 = (MaterialSubstitutionBox0[(StateValue1 >> 24) & 0xFF]) << 24
						| (MaterialSubstitutionBox1[(StateValue1 >> 16) & 0xFF]) << 16
						| (MaterialSubstitutionBox0[(StateValue1 >> 8) & 0xFF]) << 8
						| (MaterialSubstitutionBox1[StateValue1 & 0xFF]);

					return RandomWordData0;
				}

				MixTransformationUtil(ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>& CommonStateData)
					:
					CommonStateDataPointerObject(CommonStateData)
				{
					this->Word32Bit_Initialize();
				}

				~MixTransformationUtil()
				{
					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->MaterialSubstitutionBox0.data(), this->MaterialSubstitutionBox0.size());
					my_cpp2020_assert(CheckPointer == this->MaterialSubstitutionBox0.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->MaterialSubstitutionBox1.data(), this->MaterialSubstitutionBox1.size());
					my_cpp2020_assert(CheckPointer == this->MaterialSubstitutionBox1.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->Word32Bit_StreamCipherStateRegisters.data(), this->Word32Bit_StreamCipherStateRegisters.size() * sizeof(std::uint32_t));
					my_cpp2020_assert(CheckPointer == this->Word32Bit_StreamCipherStateRegisters.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;
				}

			};

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			class SubkeyMatrixOperation
			{

			private:

				static constexpr std::size_t OPC_KeyMatrix_Rows = ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>::OPC_KeyMatrix_Rows;
				static constexpr std::size_t OPC_KeyMatrix_Columns = ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>::OPC_KeyMatrix_Columns;

				CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>
				CommonStateDataPointerObject;

				MixTransformationUtil<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>
				MixTransformationUtilObject;

				void ApplyWordDataInitialVector(std::span<const std::uint32_t> WordDataInitialVector)
				{
					auto& RandomQuadWordMatrix = CommonStateDataPointerObject.AccessReference().RandomQuadWordMatrix;
				
					//初始采样Word数据 (使用32Bit字 - 数据初始向量)
					//Initial sampling of Word data (Use 32Bit Word Data - Initial Vector)

					std::vector<std::uint32_t> Word32Bit_ExpandedInitialVector = MixTransformationUtilObject.Word32Bit_ExpandKey(WordDataInitialVector);

					volatile std::size_t Index = Word32Bit_ExpandedInitialVector.size();

					std::size_t MatrixRow = RandomQuadWordMatrix.rows();
					std::size_t MatrixColumn = RandomQuadWordMatrix.cols();
				
					Use32BitData:

					while(MatrixRow > 0)
					{
						while(MatrixColumn > 0)
						{
							if(Index == 0)
								break;

							volatile std::uint64_t RandomValue = static_cast<std::uint64_t>( Word32Bit_ExpandedInitialVector[Index - 1] );
							auto&& RotatedBits = (RandomValue << 7) | (RandomValue >> 1);

							auto& MatrixValue = RandomQuadWordMatrix(MatrixRow - 1, MatrixColumn - 1);

							//Random bits
							MatrixValue = RandomValue ^ (RandomValue & RotatedBits);

							//Switch bit
							MatrixValue ^= (static_cast<std::uint64_t>(1) << (RandomValue & std::numeric_limits<std::uint64_t>::digits - 1));

							RandomValue += MatrixValue;
							MatrixValue += RandomValue * 2 + MatrixValue;
							
							--Index;

							--MatrixColumn;
						}
						--MatrixRow;

						MatrixColumn = RandomQuadWordMatrix.cols();
					}

					if(MatrixRow == 0 && MatrixColumn == 0 && Index > 0)
					{
						MatrixRow = RandomQuadWordMatrix.rows();
						MatrixColumn = RandomQuadWordMatrix.cols();

						goto Use32BitData;
					}

					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(Word32Bit_ExpandedInitialVector.data(), Word32Bit_ExpandedInitialVector.size() * sizeof(std::uint32_t));
					CheckPointer = nullptr;
				}

			public:

				//About TransformedSubkeyMatrix - initialization state - key substitution, sampling and random data generation
				//关于TransformedSubkeyMatrix - 初始化状态 - 密钥替换、采样和生成随机数据
				void InitializationState(std::span<const std::uint64_t> Key)
				{
					volatile void* CheckPointer = nullptr;

					auto& BernoulliDistribution = CommonStateDataPointerObject.AccessReference().BernoulliDistributionObject;
					auto& RandomQuadWordMatrix = CommonStateDataPointerObject.AccessReference().RandomQuadWordMatrix;
					auto& LFSR_Object = *(CommonStateDataPointerObject.AccessReference().LFSR_ClassicPointer);

					std::vector<std::uint8_t> ByteKeys = CommonToolkit::IntegerExchangeBytes::MessageUnpacking<std::uint64_t, std::uint8_t>(Key.data(), Key.size());

					//通过材料置换框0进行字节数据置换操作
					//Byte data substitution operation via material substitution box 0
					std::ranges::transform
					(
						ByteKeys.begin(), 
						ByteKeys.end(), 
						ByteKeys.begin(),
						[this](const std::uint8_t& byte) -> std::uint8_t
						{ 
							return MixTransformationUtilObject.MaterialSubstitutionBox0[ MixTransformationUtilObject.MaterialSubstitutionBox0[byte] ];
						}
					);

					std::vector<std::uint32_t> Word32Bit_Key = CommonToolkit::IntegerExchangeBytes::MessagePacking<std::uint32_t, std::uint8_t>(ByteKeys.data(), ByteKeys.size());

					CheckPointer = memory_set_no_optimize_function<0x00>(ByteKeys.data(), ByteKeys.size());
					CheckPointer = nullptr;
					ByteKeys.resize(0);

					//初始采样Word数据 (使用32Bit字 - 密钥向量)
					//Initial sampling of Word data (Use 32Bit Word - Key Vector)
					std::vector<std::uint32_t> Word32Bit_ExpandedKey = MixTransformationUtilObject.Word32Bit_ExpandKey(Word32Bit_Key);

					std::span<std::uint32_t> Word32Bit_ExpandedKeySpan(Word32Bit_ExpandedKey.begin(), Word32Bit_ExpandedKey.end());

					std::vector<std::uint32_t> Word32Bit_Random(Word32Bit_ExpandedKey.size() / 4, 0);

					//处理采样Word数据
					//Processing Sampled Word Data
					for
					(
						std::size_t Index = 0, OffsetIndex_WordsMemorySpan = 0;
						OffsetIndex_WordsMemorySpan + 4 < Word32Bit_ExpandedKeySpan.size() && Index < Word32Bit_Random.size();
						OffsetIndex_WordsMemorySpan += 4, ++Index
					)
					{
						std::span<std::uint32_t> Word32Bit_ExpandedKeySubSpan = Word32Bit_ExpandedKeySpan.subspan(OffsetIndex_WordsMemorySpan, 4);
						std::uint32_t RandomWord = MixTransformationUtilObject.Word32Bit_KeyWithStreamCipherFunction(Word32Bit_ExpandedKeySubSpan) ^ Word32Bit_ExpandedKeySubSpan[3];
						Word32Bit_Random[Index] = RandomWord;
						RandomWord = 0;
					}

					ByteKeys = CommonToolkit::IntegerExchangeBytes::MessageUnpacking<std::uint32_t, std::uint8_t>(Word32Bit_Random.data(), Word32Bit_Random.size());
					
					CheckPointer = memory_set_no_optimize_function<0x00>(Word32Bit_ExpandedKey.data(), Word32Bit_ExpandedKey.size() * sizeof(std::uint32_t));
					CheckPointer = nullptr;
					Word32Bit_ExpandedKey.resize(0);
					CheckPointer = memory_set_no_optimize_function<0x00>(Word32Bit_Random.data(), Word32Bit_Random.size() * sizeof(std::uint32_t));
					CheckPointer = nullptr;
					Word32Bit_Random.resize(0);
					CheckPointer = memory_set_no_optimize_function<0x00>(Word32Bit_Key.data(), Word32Bit_Key.size() * sizeof(std::uint32_t));
					CheckPointer = nullptr;
					Word32Bit_Key.resize(0);

					//通过材料置换框1进行字节数据置换操作
					//Byte data substitution operation via material substitution box 1
					std::ranges::transform
					(
						ByteKeys.begin(), 
						ByteKeys.end(), 
						ByteKeys.begin(),
						[this](const std::uint8_t &byte) -> std::uint8_t
						{ 
							return MixTransformationUtilObject.MaterialSubstitutionBox1[ MixTransformationUtilObject.MaterialSubstitutionBox1[byte] ];
						}
					);

					std::vector<std::uint64_t> Word64Bit_ProcessedKey = CommonToolkit::IntegerExchangeBytes::MessagePacking<std::uint64_t, std::uint8_t>(ByteKeys.data(), ByteKeys.size());

					CheckPointer = memory_set_no_optimize_function<0x00>(ByteKeys.data(), ByteKeys.size());
					CheckPointer = nullptr;
					ByteKeys.resize(0);

					volatile bool Word64Bit_KeyUsed = false;
					std::array<bool, std::numeric_limits<std::uint64_t>::digits> RandomBitsArray {};
					for(std::size_t row = 0; row < RandomQuadWordMatrix.rows(); ++row)
					{
						for(std::size_t column = 0; column < RandomQuadWordMatrix.cols(); ++column)
						{
							if(column + 1 == Word64Bit_ProcessedKey.size() || column + 1 == RandomQuadWordMatrix.cols())
								Word64Bit_KeyUsed = true;

							if(Word64Bit_KeyUsed == false)
								RandomQuadWordMatrix(row, column) -= Word64Bit_ProcessedKey[column];
							else
							{
								while (column < RandomQuadWordMatrix.cols())
								{
									volatile std::uint64_t RandomNumber = 0;

									for(auto& RandomBit : RandomBitsArray)
									{
										RandomNumber = static_cast<std::uint64_t>(BernoulliDistribution(LFSR_Object)) ^ LFSR_Object();
										RandomBit = static_cast<bool>(RandomNumber & 1);
									}

									for(std::size_t BitIndex = 0; BitIndex < std::numeric_limits<std::uint64_t>::digits; BitIndex++)
									{
										if(RandomBitsArray[BitIndex])
											RandomNumber |= (static_cast<std::uint64_t>(RandomBitsArray[BitIndex]) << BitIndex);
										else
											BitIndex++;
									}

									RandomQuadWordMatrix(row, column) += RandomNumber;

									RandomNumber = 0;

									++column;
								}

								if(column + 1 < Word64Bit_ProcessedKey.size())
								{
									Word64Bit_KeyUsed = false;
								}
							}
						}
					}

					CheckPointer = memory_set_no_optimize_function<0x00>(RandomBitsArray.data(), RandomBitsArray.size());
					CheckPointer = nullptr;

					MixTransformationUtilObject.RegenerationRandomMaterialSubstitutionBox();
				}

				//About TransformedSubkeyMatrix - Update State
				//关于TransformedSubkeyMatrix - 更新状态
				void UpdateState()
				{
					//http://eigen.tuxfamily.org/dox/group__TutorialReductionsVisitorsBroadcasting.html

					ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>& 
					CommonStateDataReference = CommonStateDataPointerObject.AccessReference();

					auto& RandomQuadWordMatrix = CommonStateDataReference.RandomQuadWordMatrix;
					auto& TransformedSubkeyMatrix = CommonStateDataReference.TransformedSubkeyMatrix;
					auto& NLFSR_Object = *(CommonStateDataReference.NLFSR_ClassicPointer);
					auto& SDP_Object = *(CommonStateDataReference.SDP_ClassicPointer);

					Eigen::Matrix<std::uint64_t, 1, OPC_KeyMatrix_Columns>
					RandomWordVector = Eigen::Matrix<std::uint64_t, 1, OPC_KeyMatrix_Columns>::Zero();

					Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>
					RandomWordVector2 = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>::Zero();

					//Vector[index] = RandomNumber......
					//Vector2[index] = RandomNumber......

					volatile std::size_t BaseNumber = 0;

					for(auto Rows : RandomWordVector.rowwise())
					{
						for(auto& RoundSubkeyMatrixValue : Rows)
						{
							RoundSubkeyMatrixValue = NLFSR_Object.unpredictable_bits(BaseNumber & 1, 64);
							++BaseNumber;
						}
					}

					for(auto Columns : RandomWordVector2.colwise())
					{
						for(auto& RoundSubkeyMatrixValue : Columns)
						{
							RoundSubkeyMatrixValue = NLFSR_Object.unpredictable_bits(BaseNumber & 1, 63);
							++BaseNumber;
						}
					}

					BaseNumber = 0;

					//Affine Transformation
					//https://en.wikipedia.org/wiki/Affine_transformation
					//仿射变换
					//https://zh.wikipedia.org/zh-cn/%E4%BB%BF%E5%B0%84%E5%8F%98%E6%8D%A2
					//LeftMatrix = <Matrix, Vector>(row wise) + Vector2
					//RightMatrix = <Matrix, Vector2>(column wise) - Vector

					Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
					LeftMatrix = RandomQuadWordMatrix.array().rowwise() * RandomWordVector.array();
					LeftMatrix.colwise() += RandomWordVector2;

					Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
					RightMatrix = RandomQuadWordMatrix.array().colwise() * RandomWordVector2.array();
					RightMatrix.rowwise() -= RandomWordVector;

					//TransformedSubkeyMatrix = TransformedSubkeyMatrix ⊕ (LeftMatrix ⊕ RightMatrix)

					for(std::size_t MatrixRow = 0; MatrixRow < LeftMatrix.rows() && MatrixRow < RightMatrix.rows(); ++MatrixRow)
					{
						for(std::size_t MatrixColumn = 0; MatrixColumn < LeftMatrix.cols() && MatrixColumn < RightMatrix.cols(); ++MatrixColumn)
						{
							RandomQuadWordMatrix(MatrixRow, MatrixColumn) ^= LeftMatrix(MatrixRow, MatrixColumn) ^ RightMatrix(MatrixRow, MatrixColumn);
						}
					}

					RandomWordVector.setZero();
					RandomWordVector2.setZero();
					LeftMatrix.setZero();
					RightMatrix.setZero();

					for(auto Rows : RandomWordVector.rowwise())
					{
						for(auto& RoundSubkeyMatrixValue : Rows)
						{
							RoundSubkeyMatrixValue = SDP_Object(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
						}
					}

					for(auto Columns : RandomWordVector2.colwise())
					{
						for(auto& RoundSubkeyMatrixValue : Columns)
						{
							RoundSubkeyMatrixValue = SDP_Object(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
						}
					}

					//Tensor product
					//https://en.wikipedia.org/wiki/Tensor_product
					//张量积
					//https://zh.wikipedia.org/zh/%E5%BC%A0%E9%87%8F%E7%A7%AF
					//张量积通常不符合交换律
					//Tensor products usually do not conform to the exchange law
					//<VectorA, VectorB> ≠ <VectorB, VectorA>

					//克罗内克积
					//https://zh.wikipedia.org/wiki/%E5%85%8B%E7%BD%97%E5%86%85%E5%85%8B%E7%A7%AF
					//Kronecker product
					//https://en.wikipedia.org/wiki/Kronecker_product
					Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
					KroneckerProductMatrix = Eigen::kroneckerProduct(RandomWordVector, RandomWordVector2).eval();
					std::uint64_t DotProduct = RandomWordVector2.dot(RandomWordVector);

					TransformedSubkeyMatrix = RandomQuadWordMatrix * (KroneckerProductMatrix * DotProduct);
					
					KroneckerProductMatrix.setZero();
					DotProduct = 0;
					RandomWordVector.setZero();
					RandomWordVector2.setZero();

					auto& MatrixOffsetWithRandomIndices = CommonStateDataPointerObject.AccessReference().MatrixOffsetWithRandomIndices;
					CommonSecurity::ShuffleRangeData(MatrixOffsetWithRandomIndices.begin(), MatrixOffsetWithRandomIndices.end(), NLFSR_Object);
				}

				SubkeyMatrixOperation(ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>& CommonStateData)
					:
					CommonStateDataPointerObject(CommonStateData),
					MixTransformationUtilObject(CommonStateData)
				{
					this->ApplyWordDataInitialVector(CommonStateDataPointerObject.AccessReference().WordDataInitialVector);
				}

				~SubkeyMatrixOperation() = default;
			};

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			//模块A: 安全的生成子密钥
			//Module A: Secure generation of subkeys
			class SecureSubkeyGeneratationModule
			{
		
			private:

				ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>
				CommonStateDataPointerObject;

				static constexpr std::size_t OPC_KeyMatrix_Rows = ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>::OPC_KeyMatrix_Rows;
				static constexpr std::size_t OPC_KeyMatrix_Columns = ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>::OPC_KeyMatrix_Columns;

				SubkeyMatrixOperation<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>
				SubkeyMatrixOperationObject;

				struct TDOM_HashModule
				{

				public:

					//This is sponge bit hash!
					CustomSecureHash<(OPC_KeyMatrix_Rows * 64) / 2> CustomSecureHashObject;

					static constexpr std::uint64_t LargePrimeNumber = 18446744073709551557ULL;

					/*
						@details
						https://en.wikipedia.org/wiki/Short_integer_solution_problem
						Short integer solution (SIS) and ring-SIS problems are two average-case problems that are used in lattice-based cryptography constructions.
						短整数解（SIS）和环形SIS问题是两个平均案例问题，被用于基于格子的密码学构建。
						
						使用短矢量查找Ajtais哈希函数中的碰撞问题
						https://crypto.stackexchange.com/questions/34400/find-collision-in-ajtais-hash-function-using-short-vector
						
						高效算术-哈希函数
						https://crypto.stackexchange.com/questions/61687/efficient-arithmetic-hash-function/
						
						什么时候开始，SIS的短整数解格子问题变得容易了？
						https://crypto.stackexchange.com/questions/71591/when-does-the-sis-short-integer-solution-lattice-problem-start-becoming-easy
						
						Ajtais Hash Function:
						Ajtais哈希函数:
						Hash(MassageVector) = <RandomNumberMatrixA, MassageVector> mod LargePrimeNumbers
						The largest prime number is that will fit into a 64-bit unsigned variable: 18446744073709551557
						GeneratedRoundSubkeyMatrix = GeneratedRoundSubkeyMatrix * array(RandomQuadWordMatrix) % 18446744073709551557;

						@return EigenLibrary column vector
					*/
					Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>
					SecureHash
					(
						const Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>& RandomQuadWordMatrix,
						const Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>& IntegerVector
					)
					{
						Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
						RandomQuadWordMatrixA = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>::Zero();
						Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1> 
						IntegerVectorA = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>::Zero();
						Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
						RandomQuadWordMatrixB = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>::Zero();
						Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>
						IntegerVectorB = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>::Zero();
						
						//Element is 64 bits data, split into high and low 32 bits Data and stored as 64 bits data
						//元素为64位数据，拆分为高低32位数据，存储为64位数据
						for (std::size_t Index = 0; Index < OPC_KeyMatrix_Rows * OPC_KeyMatrix_Columns; ++Index)
						{
							std::uint64_t value = RandomQuadWordMatrix.array()(Index);
							RandomQuadWordMatrixA.array()(Index) = value >> 32;
							RandomQuadWordMatrixB.array()(Index) = value & 0xFFFFFFFF;
						}

						for (std::size_t Index = 0; Index < OPC_KeyMatrix_Rows; ++Index)
						{
							std::uint64_t value = IntegerVector(Index);
							IntegerVectorA.array()(Index) = value >> 32;
							IntegerVectorB.array()(Index) = value & 0xFFFFFFFF;
						}

						//Matrix-vector multiplication using split 32-bit data in stored 64-bit data without any computational overflow
						//在存储的 64 位数据中使用拆分的 32 位数据进行矩阵-向量乘法，没有任何计算溢出
						Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>
						ResultA = RandomQuadWordMatrixA * IntegerVectorA;
						Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>
						ResultB = RandomQuadWordMatrixB * IntegerVectorB;

						std::span<std::uint64_t> SpanVectorA(ResultA.data(), ResultA.data() + ResultA.size());
						std::span<std::uint64_t> SpanVectorB(ResultB.data(), ResultB.data() + ResultB.size());

						std::array<std::uint64_t, OPC_KeyMatrix_Rows> CustomHashed {};
						std::span<std::uint64_t> SpanCustomHashed {CustomHashed};
						Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>
						Hashed = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>::Zero();

						CustomSecureHashObject.SecureHash(SpanVectorA, SpanCustomHashed.subspan(0, OPC_KeyMatrix_Rows / 2));
						CustomSecureHashObject.SecureHash(SpanVectorB, SpanCustomHashed.subspan(OPC_KeyMatrix_Rows / 2, OPC_KeyMatrix_Rows / 2));

						std::uint64_t HashedValue = 0;
						//After splitting, the matrix-vector multiplication results on both sides are combined using this addition. 
						//If there is a calculation overflow, it is guaranteed to use a large prime number for modulo, and the result will not overflow.
						//拆分后，把两边矩阵-向量的乘法结果，使用这个加法合并。
						//如果有计算溢出，保证使用大素数进行取模，则结果不会溢出。
						for(std::size_t row = 0; row < OPC_KeyMatrix_Rows; ++row)
						{
							//(A + B) mod PrimeNumber = ((A mod PrimeNumber) + (B mod PrimeNumber)) mod PrimeNumber
							HashedValue = ( ResultA( row ) % LargePrimeNumber ) + ( ResultB( row ) % LargePrimeNumber ) % LargePrimeNumber;
							Hashed( row ) = ( CustomHashed[ row ] % LargePrimeNumber ) + ( HashedValue % LargePrimeNumber ) % LargePrimeNumber;
						}

						//确保状态矩阵和向量被安全的清理
						//Ensure that the status matrix and vector is securely cleaned
						RandomQuadWordMatrixA.setZero();
						RandomQuadWordMatrixB.setZero();
						IntegerVectorA.setZero();
						IntegerVectorB.setZero();
						ResultA.setZero();
						ResultB.setZero();
						return Hashed;
					}

					TDOM_HashModule() = default;
					~TDOM_HashModule() = default;
				};

				TDOM_HashModule HashObject;

				void LatticeCryptographyAndHash
				(
					std::span<const std::uint64_t> Input,
					std::span<std::uint64_t> Output
				)
				{
					auto& SDP_Object = *(CommonStateDataPointerObject.AccessReference().SDP_ClassicPointer);

					//被哈希过的向量
					//A vector hashed with the result of the hash function
					Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>
					HashMixedIntegerVector = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, 1>::Zero();

					std::memcpy(HashMixedIntegerVector.data(), Input.data(), Input.size() * sizeof(std::uint64_t));

					Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
					PseudoRandomNumberMatrix = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>::Zero();
					
					//计算哈希过的向量数据替换原向量数据
					//Compute hashed vector data to replace original vector data
					for(std::size_t Index = 0; Index < OPC_KeyMatrix_Rows * OPC_KeyMatrix_Columns; ++Index)
						PseudoRandomNumberMatrix.array()(Index) = SDP_Object(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());

					HashMixedIntegerVector.noalias() = HashObject.SecureHash( PseudoRandomNumberMatrix, HashMixedIntegerVector ).eval();

					//原向量数据和哈希过的向量数据做具有大模数的大整数的加法，然后变成一个被哈希混合过的向量
					//The original vector data and the hashed vector data are added with a large integer with a large modulus, and then become a hash-mixed vector
					for ( std::size_t index = 0; index < HashMixedIntegerVector.size(); index++ )
					{
						const std::uint64_t& a = Input[index % Input.size()];
						const std::uint64_t& b = HashMixedIntegerVector( index );
						std::uint64_t& c = Output[index];

						if ( c == 0 )
							c = ( a + b >= TDOM_HashModule::LargePrimeNumber ) ? a + b - TDOM_HashModule::LargePrimeNumber : a + b;
						else
						{
							std::uint64_t d = ( a + b >= TDOM_HashModule::LargePrimeNumber ) ? a + b - TDOM_HashModule::LargePrimeNumber : a + b;
							c = ( c + d >= TDOM_HashModule::LargePrimeNumber ) ? c + d - TDOM_HashModule::LargePrimeNumber : c + d;
						}
					}

					//确保状态向量被安全的清理
					//Ensure that the status vector is securely cleaned
					HashMixedIntegerVector.setZero();
				}

			public:

				/*
					使用说明：
					
					字64位Word64Bit_MasterKey，一个临时存储的主密钥，是在StateData_Worker类的函数里;
					WordKeyDataVector在CommonStateData类里，大小为OPC_QuadWord_KeyBlockSize；
					
					主密钥未使用时，应该更新WordKeyDataVector
					
					如果主密钥的长度大于OPC_QuadWord_KeyBlockSize
					那么第一次从Word64Bit_MasterKey里面，直接复制这个长度的主密钥给这个WordKeyDataVector，之后记录这个偏移在主密钥(Word64Bit_MasterKey[index])，index偏移重置为0在WordKeyDataVector[index]，使用ExclusiveOr(异或)操作把主密钥应用到WordKeyDataVector。
					重复以上步骤，就可以把主密钥(Word64Bit_MasterKey)给使用完毕。
					
					主密钥使用完毕之后，无需更新WordKeyDataVector，直接使用这个函数
					
					如果主密钥的长度小于OPC_QuadWord_KeyBlockSize
					应该填充伪随机数到主密钥，直到主密钥的长度等于OPC_QuadWord_KeyBlockSize
					
					这个函数执行完毕之后，将会更新"变换的子密钥矩阵"

					Usage Notes.
					
					Word64Bit_MasterKey, a temporary storage of the master key, is in the function of the StateData_Worker class;
					WordKeyDataVector in the CommonStateData class, of size OPC_QuadWord_KeyBlockSize.

					The WordKeyDataVector should be updated when the master key is not used

					If the length of the master key is greater than OPC_QuadWord_KeyBlockSize
					then the first time from Word64Bit_MasterKey inside, directly copy this length of the master key to this WordKeyDataVector, after recording this offset in the master key (Word64Bit_MasterKey[index]), index offset reset to 0 in WordKeyDataVector[index], use exclusive-or operation to apply the master key to the WordKeyDataVector.
					Repeat the above steps, you can the master key (Word64Bit_MasterKey) to complete used.
					
					After the used of the master key, no need to update the WordKeyDataVector, directly using this function
					
					If the length of the master key is less than OPC_QuadWord_KeyBlockSize
					it should be filled with pseudo-random numbers until the length of the master key equals OPC_QuadWord_KeyBlockSize
					
					After this function is executed, the "transformed subkey matrix" will be updated
				*/
				void GenerationSubkeys(std::span<const std::uint64_t> WordKeyDataVector)
				{
					/*
						比特数据混淆层
						Bits Data Confusion Layer
					*/
					if(!WordKeyDataVector.empty())
					{
						my_cpp2020_assert(WordKeyDataVector.size() % OPC_QuadWord_KeyBlockSize == 0, "", std::source_location::current());
						std::vector<std::uint64_t> WordKeyResistQC(OPC_KeyMatrix_Rows, 0);
						this->LatticeCryptographyAndHash(WordKeyDataVector, WordKeyResistQC);
						this->SubkeyMatrixOperationObject.InitializationState(WordKeyResistQC);
					}

					this->SubkeyMatrixOperationObject.UpdateState();
				}

				SecureSubkeyGeneratationModule(ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>& CommonStateData)
					:
					CommonStateDataPointerObject(CommonStateData),
					SubkeyMatrixOperationObject(CommonStateData)
				{
				
				}

				~SecureSubkeyGeneratationModule() = default;
			
			};

			template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
			//模块B: 安全的生成每轮混合子密钥
			//Module B: Securely generate mixed subkeys for each round
			class SecureRoundSubkeyGeneratationModule
			{

			private:

				/*
					BlockSize / KeySize (QuadWord)
				*/

				template<std::size_t, std::size_t>
				friend class StateData_Worker;

				ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>
				CommonStateDataPointerObject;

				static constexpr std::size_t OPC_KeyMatrix_Rows = ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>::OPC_KeyMatrix_Rows;
				static constexpr std::size_t OPC_KeyMatrix_Columns = ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>::OPC_KeyMatrix_Columns;

				std::unique_ptr<Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>>
				//生成的轮函数的子密钥的矩阵(来自变换后的子密钥矩阵)
				//The subkey of the generated round function (from the transformed subkey matrix)
				GeneratedRoundSubkeyMatrixPointer = std::make_unique<Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>>();

				std::unique_ptr<std::array<std::uint64_t, OPC_KeyMatrix_Rows * OPC_KeyMatrix_Columns>>
				//生成的轮函数的子密钥向量(来自生成的轮函数的子密钥的矩阵)
				//Generated subkey (from the transformed key matrix)
				GeneratedRoundSubkeyVectorPointer = std::make_unique<std::array<std::uint64_t, OPC_KeyMatrix_Rows * OPC_KeyMatrix_Columns>>();

				std::uint64_t MatrixTransformationCounter = 0;

				#if 0

				template<typename ThisMatrixType> 
				ThisMatrixType EigenMatrixPseudoInverse
				(
					const ThisMatrixType& matrix,
					const double float_epsilon = std::numeric_limits<double>::epsilon()
				)
				{
					//Matrix for svd decomposition
					Eigen::JacobiSVD<ThisMatrixType> svd_holder(matrix, Eigen::ComputeFullU | Eigen::ComputeFullV);  
					
					auto&& D = svd_holder.singularValues().array();

					//Choose your tolerance wisely
					double tolerance = float_epsilon * std::max(matrix.cols(), matrix.rows()) * D.abs()(0); 

					ThisMatrixType V = svd_holder.matrixV();
					ThisMatrixType S = (D.abs() > tolerance).select(D.inverse(), 0.0).matrix().asDiagonal();
					ThisMatrixType U = svd_holder.matrixU().adjoint();

					//MatrixPseudoInverse(A) = V * S * transpose(U)
					return V * S * U;
				}

				#endif

				//奥尔德雷斯之谜 - 不可预测的矩阵变换
				//OaldresPuzzle-Cryptic - Unpredictable matrix transformation
				void OPC_MatrixTransformation()
				{
					//https://eigen.tuxfamily.org/dox/group__TutorialSTL.html

					auto& RandomQuadWordMatrix = CommonStateDataPointerObject.AccessReference().RandomQuadWordMatrix;
					auto& TransformedSubkeyMatrix = CommonStateDataPointerObject.AccessReference().TransformedSubkeyMatrix;
					auto& GeneratedRoundSubkeyMatrix = *(this->GeneratedRoundSubkeyMatrixPointer.get());

					Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>
					TemporaryIntegerMartix = Eigen::Matrix<std::uint64_t, OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns>::Zero();

					//TemporaryIntegerMartix = ( RandomQuadWordMatrix + transpose(TransformedSubkeyMatrix) ) * ( TransformedSubkeyMatrix - transpose(RandomQuadWordMatrix) ) -> adjoint()
					TemporaryIntegerMartix.noalias() = ( ( RandomQuadWordMatrix + TransformedSubkeyMatrix.transpose() ) * ( TransformedSubkeyMatrix - RandomQuadWordMatrix.transpose() ) ).adjoint();
					GeneratedRoundSubkeyMatrix.noalias() += TemporaryIntegerMartix * RandomQuadWordMatrix * TransformedSubkeyMatrix;
					
					/*
						注意，如果这段代码被注释掉，虽然可以显著提高OaldresPuzzle-Cryptic算法的运行速度。
						但是，它有可能被外部破解者用汇编调试器分析出来，所以为了安全起见，请仔细考虑之后再选择修改！!
						Note that if this code is commented out, it can significantly improve the running speed of the OaldresPuzzle-Cryptic algorithm though.
						However, it could be analyzed by an external cracker with an assembly debugger, so please consider carefully before choosing to modify it for safety reasons!!!
					*/
					//确保状态矩阵被安全的清理
					//Ensure that the status matrix is securely cleaned
					TemporaryIntegerMartix.setZero();

					//std::cout << GeneratedRoundSubkeyMatrix << std::endl;
					//std::cout << std::endl;
				}

			public:

				#if 0

				void GenerateDiffusionLayerPermuteIndices()
				{
					std::array<std::unordered_set<std::uint32_t>, 16> DiffusionLayerMatrixIndex
					{
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
						std::unordered_set<std::uint32_t>{},
					};

					std::array<std::uint32_t, 32> ArrayIndexData
					{
						//0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
						25,9,27,18,11,2,26,7,12,24,5,17,6,1,10,3,21,30,8,20,0,29,4,13,19,14,23,16,22,31,28,15
					};

					std::vector<std::uint32_t> VectorIndexData(ArrayIndexData.begin(), ArrayIndexData.end());

					CommonSecurity::RNG_ISAAC::isaac64<8> CSPRNG;
					CommonSecurity::RND::UniformIntegerDistribution<std::uint32_t> UniformDistribution;

					for(std::size_t Round = 0; Round < 10223; ++Round)
					{
						for(std::size_t X = 0; X < DiffusionLayerMatrixIndex.size(); ++X )
						{
							std::unordered_set<std::uint32_t> HashSet;
							while(HashSet.size() != 16)
							{
								std::uint32_t RandomIndex = UniformDistribution(CSPRNG) % 32;
								while (RandomIndex >= VectorIndexData.size())
								{
									RandomIndex = UniformDistribution(CSPRNG) % 32;
								}
								HashSet.insert(VectorIndexData[RandomIndex]);
								VectorIndexData.erase(VectorIndexData.begin() + RandomIndex);

								if(VectorIndexData.empty())
								{
									CommonSecurity::ShuffleRangeData(ArrayIndexData.begin(), ArrayIndexData.end(), CSPRNG);
									VectorIndexData = std::vector<std::uint32_t>(ArrayIndexData.begin(), ArrayIndexData.end());
								}
							}
							DiffusionLayerMatrixIndex[X] = HashSet;

							if(VectorIndexData.empty())
							{
								CommonSecurity::ShuffleRangeData(ArrayIndexData.begin(), ArrayIndexData.end(), CSPRNG);
								VectorIndexData = std::vector<std::uint32_t>(ArrayIndexData.begin(), ArrayIndexData.end());
							}
						}
					}

					for( std::size_t X = DiffusionLayerMatrixIndex.size(); X > 0; --X )
					{
						for(const auto& Value : DiffusionLayerMatrixIndex[X - 1] )
							std::cout << "KeyStateX" << "[" << Value << "]" << ", ";

						std::cout << "\n";
					}

					std::cout << std::endl;

					for(std::size_t Round = 0; Round < 10223; ++Round)
					{
						for(std::size_t X = DiffusionLayerMatrixIndex.size(); X > 0; --X )
						{
							std::unordered_set<std::uint32_t> HashSet;
							while(HashSet.size() != 16)
							{
								std::uint32_t RandomIndex = UniformDistribution(CSPRNG) % 32;
								while (RandomIndex >= VectorIndexData.size())
								{
									RandomIndex = UniformDistribution(CSPRNG) % 32;
								}
								HashSet.insert(VectorIndexData[RandomIndex]);
								VectorIndexData.erase(VectorIndexData.begin() + RandomIndex);

								if(VectorIndexData.empty())
								{
									CommonSecurity::ShuffleRangeData(ArrayIndexData.begin(), ArrayIndexData.end(), CSPRNG);
									VectorIndexData = std::vector<std::uint32_t>(ArrayIndexData.begin(), ArrayIndexData.end());
								}
							}
							DiffusionLayerMatrixIndex[X - 1] = HashSet;

							if(VectorIndexData.empty())
							{
								CommonSecurity::ShuffleRangeData(ArrayIndexData.begin(), ArrayIndexData.end(), CSPRNG);
								VectorIndexData = std::vector<std::uint32_t>(ArrayIndexData.begin(), ArrayIndexData.end());
							}
						}
					}

					for( std::size_t X = 0; X < DiffusionLayerMatrixIndex.size(); ++X )
					{
						for(const auto& Value : DiffusionLayerMatrixIndex[X] )
							std::cout << "KeyStateX" << "[" << Value << "]" << ", ";

						std::cout << "\n";
					}

					std::cout << std::endl;
				}

				#endif

				//将旧的QuadWord子密钥矩阵以及用于轮函数的QuadWord子密钥矩阵，进行单向变换和运算，并生成新的QuadWord子密钥矩阵和子密钥向量，并作为轮函数的RoundSubkey使用
				//Take the old QuadWord subkey matrix and the QuadWord subkey matrix used for the round function, perform one-way transformation and operation, and generate a new QuadWord subkey matrix and subkey vector, and use them as the RoundSubkey of the round function
				void GenerationRoundSubkeys()
				{
					volatile void* CheckPointer = nullptr;
					
					auto& GeneratedRoundSubkeyMatrix = *(this->GeneratedRoundSubkeyMatrixPointer.get());
					auto& GeneratedRoundSubkeyVector = *(this->GeneratedRoundSubkeyVectorPointer.get());

					if(this->MatrixTransformationCounter == 0)
					{
						volatile void* CheckPointer = nullptr;

						CheckPointer = memory_set_no_optimize_function<0x00>(GeneratedRoundSubkeyVector.data(), GeneratedRoundSubkeyVector.size() * sizeof(std::uint64_t));
						CheckPointer = nullptr;

						GeneratedRoundSubkeyMatrix.setZero();
					}

					this->OPC_MatrixTransformation();

					//密钥白化
					//Key whitening
					//https://en.wikipedia.org/wiki/Key_whitening

					std::size_t KeyVectorIndex = 0;
					while(KeyVectorIndex < GeneratedRoundSubkeyVector.size())
					{
						GeneratedRoundSubkeyVector[KeyVectorIndex] ^= GeneratedRoundSubkeyMatrix.array()(KeyVectorIndex);
						++KeyVectorIndex;
					}

					std::unique_ptr<std::array<std::uint64_t, OPC_KeyMatrix_Rows * OPC_KeyMatrix_Columns>>
					TransformedRoundSubkeyVectorPointer = std::make_unique<std::array<std::uint64_t, OPC_KeyMatrix_Rows * OPC_KeyMatrix_Columns>>();
					auto& TransformedRoundSubkeyVector = *(TransformedRoundSubkeyVectorPointer.get());

					std::span<std::uint64_t> NewRoundSubkeyVectorSpan(TransformedRoundSubkeyVector.begin(), TransformedRoundSubkeyVector.end());
					std::span<const std::uint64_t> RoundSubkeyVectorSpan(GeneratedRoundSubkeyVector.begin(), GeneratedRoundSubkeyVector.end());

					/*
						比特数据扩散层
						Bits data diffusion layer

						数据雪崩效应进行扩散
						Data avalanche effect for diffusion
					*/
					for(std::size_t Index = 0; Index < RoundSubkeyVectorSpan.size(); Index += 32)
					{
						std::span<const std::uint64_t> KeyStateX = RoundSubkeyVectorSpan.subspan(Index ,32);
						std::span<std::uint64_t> KeyStateY = NewRoundSubkeyVectorSpan.subspan(Index, 32);

						/*

						该排列的常数Index来源于,上面注释的GenerateDiffusionLayerPermuteIndices(函数/算法).
						The constant Index of this alignment comes from, the (function/algorithm) annotated above.

						伪代码:
						Pseudocode:

						MatrixA, MatrixB from KeyStateX
						VectorA, VectorB from KeyStateY
						VectorA is KeyStateY[0] ... KeyStateY[15]
						VectorB is KeyStateY[16] ... KeyStateY[31]

						//把长向量当成一个矩阵的视图来看
						//View the long vector as a matrix
						KeyStateMatrixX = ViewRangeMatrix(KeyStateX)
						KeyStateMatrixY = ViewRangeMatrix(KeyStateY)

						VectorA, VectorB = Split(KeyStateMatrixY)
						MatrixA, MatrixB = Split(KeyStateMatrixX)
						StateMatrixY[Index] = BinaryDiffusion(MatrixA, MatrixB, VectorA, VectorB)
							Vectorα = BinaryMultiplicationWithGaloisFiniteField(VectorA, MatrixA)
							Vectorβ = BinaryMultiplicationWithGaloisFiniteField(VectorB, MatrixB)
							Vectorα, Vectorβ ∈ GaloisFiniteField(power(2, 64))
							return Concat(Vectorα, Vectorβ)

						*/

						KeyStateY[0] = KeyStateX[24] ^ KeyStateX[8] ^ KeyStateX[6] ^ KeyStateX[1] ^ KeyStateX[9] ^ KeyStateX[4] ^ KeyStateX[10] ^ KeyStateX[3] ^ KeyStateX[26] ^ KeyStateX[2] ^ KeyStateX[5] ^ KeyStateX[15] ^ KeyStateX[17] ^ KeyStateX[13] ^ KeyStateX[23] ^ KeyStateX[12];
						KeyStateY[1] = KeyStateX[19] ^ KeyStateX[11] ^ KeyStateX[22] ^ KeyStateX[14] ^ KeyStateX[25] ^ KeyStateX[31] ^ KeyStateX[7] ^ KeyStateX[0] ^ KeyStateX[30] ^ KeyStateX[21] ^ KeyStateX[28] ^ KeyStateX[20] ^ KeyStateX[18] ^ KeyStateX[27] ^ KeyStateX[29] ^ KeyStateX[16];
						KeyStateY[2] = KeyStateX[4] ^ KeyStateX[18] ^ KeyStateX[10] ^ KeyStateX[26] ^ KeyStateX[1] ^ KeyStateX[22] ^ KeyStateX[30] ^ KeyStateX[21] ^ KeyStateX[20] ^ KeyStateX[5] ^ KeyStateX[23] ^ KeyStateX[12] ^ KeyStateX[17] ^ KeyStateX[6] ^ KeyStateX[3] ^ KeyStateX[25];
						KeyStateY[3] = KeyStateX[11] ^ KeyStateX[19] ^ KeyStateX[24] ^ KeyStateX[16] ^ KeyStateX[0] ^ KeyStateX[7] ^ KeyStateX[28] ^ KeyStateX[13] ^ KeyStateX[29] ^ KeyStateX[14] ^ KeyStateX[2] ^ KeyStateX[15] ^ KeyStateX[27] ^ KeyStateX[8] ^ KeyStateX[31] ^ KeyStateX[9];
						KeyStateY[4] = KeyStateX[21] ^ KeyStateX[13] ^ KeyStateX[28] ^ KeyStateX[4] ^ KeyStateX[7] ^ KeyStateX[24] ^ KeyStateX[25] ^ KeyStateX[9] ^ KeyStateX[16] ^ KeyStateX[5] ^ KeyStateX[6] ^ KeyStateX[19] ^ KeyStateX[23] ^ KeyStateX[31] ^ KeyStateX[27] ^ KeyStateX[1];
						KeyStateY[5] = KeyStateX[15] ^ KeyStateX[3] ^ KeyStateX[11] ^ KeyStateX[2] ^ KeyStateX[12] ^ KeyStateX[20] ^ KeyStateX[17] ^ KeyStateX[30] ^ KeyStateX[10] ^ KeyStateX[22] ^ KeyStateX[8] ^ KeyStateX[0] ^ KeyStateX[18] ^ KeyStateX[26] ^ KeyStateX[29] ^ KeyStateX[14];
						KeyStateY[6] = KeyStateX[16] ^ KeyStateX[24] ^ KeyStateX[21] ^ KeyStateX[25] ^ KeyStateX[18] ^ KeyStateX[10] ^ KeyStateX[30] ^ KeyStateX[22] ^ KeyStateX[0] ^ KeyStateX[6] ^ KeyStateX[27] ^ KeyStateX[1] ^ KeyStateX[23] ^ KeyStateX[4] ^ KeyStateX[28] ^ KeyStateX[3];
						KeyStateY[7] = KeyStateX[12] ^ KeyStateX[20] ^ KeyStateX[14] ^ KeyStateX[31] ^ KeyStateX[15] ^ KeyStateX[2] ^ KeyStateX[9] ^ KeyStateX[8] ^ KeyStateX[29] ^ KeyStateX[11] ^ KeyStateX[5] ^ KeyStateX[19] ^ KeyStateX[26] ^ KeyStateX[13] ^ KeyStateX[17] ^ KeyStateX[7];
						KeyStateY[8] = KeyStateX[7] ^ KeyStateX[31] ^ KeyStateX[8] ^ KeyStateX[24] ^ KeyStateX[2] ^ KeyStateX[9] ^ KeyStateX[3] ^ KeyStateX[22] ^ KeyStateX[14] ^ KeyStateX[6] ^ KeyStateX[4] ^ KeyStateX[20] ^ KeyStateX[27] ^ KeyStateX[17] ^ KeyStateX[26] ^ KeyStateX[21];
						KeyStateY[9] = KeyStateX[19] ^ KeyStateX[23] ^ KeyStateX[15] ^ KeyStateX[28] ^ KeyStateX[5] ^ KeyStateX[0] ^ KeyStateX[1] ^ KeyStateX[10] ^ KeyStateX[25] ^ KeyStateX[30] ^ KeyStateX[13] ^ KeyStateX[12] ^ KeyStateX[18] ^ KeyStateX[16] ^ KeyStateX[29] ^ KeyStateX[11];
						KeyStateY[10] = KeyStateX[25] ^ KeyStateX[9] ^ KeyStateX[30] ^ KeyStateX[22] ^ KeyStateX[14] ^ KeyStateX[3] ^ KeyStateX[10] ^ KeyStateX[18] ^ KeyStateX[12] ^ KeyStateX[4] ^ KeyStateX[26] ^ KeyStateX[21] ^ KeyStateX[27] ^ KeyStateX[24] ^ KeyStateX[8] ^ KeyStateX[28];
						KeyStateY[11] = KeyStateX[0] ^ KeyStateX[17] ^ KeyStateX[1] ^ KeyStateX[19] ^ KeyStateX[11] ^ KeyStateX[13] ^ KeyStateX[5] ^ KeyStateX[7] ^ KeyStateX[29] ^ KeyStateX[15] ^ KeyStateX[6] ^ KeyStateX[20] ^ KeyStateX[16] ^ KeyStateX[31] ^ KeyStateX[23] ^ KeyStateX[2];
						KeyStateY[12] = KeyStateX[9] ^ KeyStateX[17] ^ KeyStateX[13] ^ KeyStateX[5] ^ KeyStateX[7] ^ KeyStateX[2] ^ KeyStateX[28] ^ KeyStateX[30] ^ KeyStateX[11] ^ KeyStateX[4] ^ KeyStateX[24] ^ KeyStateX[0] ^ KeyStateX[26] ^ KeyStateX[23] ^ KeyStateX[16] ^ KeyStateX[22];
						KeyStateY[13] = KeyStateX[12] ^ KeyStateX[20] ^ KeyStateX[27] ^ KeyStateX[19] ^ KeyStateX[8] ^ KeyStateX[6] ^ KeyStateX[21] ^ KeyStateX[25] ^ KeyStateX[3] ^ KeyStateX[10] ^ KeyStateX[31] ^ KeyStateX[1] ^ KeyStateX[18] ^ KeyStateX[14] ^ KeyStateX[29] ^ KeyStateX[15];
						KeyStateY[14] = KeyStateX[7] ^ KeyStateX[3] ^ KeyStateX[11] ^ KeyStateX[30] ^ KeyStateX[28] ^ KeyStateX[18] ^ KeyStateX[10] ^ KeyStateX[25] ^ KeyStateX[1] ^ KeyStateX[24] ^ KeyStateX[16] ^ KeyStateX[22] ^ KeyStateX[26] ^ KeyStateX[9] ^ KeyStateX[13] ^ KeyStateX[8];
						KeyStateY[15] = KeyStateX[20] ^ KeyStateX[12] ^ KeyStateX[21] ^ KeyStateX[23] ^ KeyStateX[31] ^ KeyStateX[15] ^ KeyStateX[6] ^ KeyStateX[2] ^ KeyStateX[29] ^ KeyStateX[19] ^ KeyStateX[4] ^ KeyStateX[0] ^ KeyStateX[14] ^ KeyStateX[17] ^ KeyStateX[27] ^ KeyStateX[5];

						KeyStateY[16] = KeyStateX[7] ^ KeyStateX[31] ^ KeyStateX[8] ^ KeyStateX[24] ^ KeyStateX[2] ^ KeyStateX[9] ^ KeyStateX[3] ^ KeyStateX[22] ^ KeyStateX[14] ^ KeyStateX[6] ^ KeyStateX[4] ^ KeyStateX[20] ^ KeyStateX[27] ^ KeyStateX[17] ^ KeyStateX[26] ^ KeyStateX[21];
						KeyStateY[17] = KeyStateX[19] ^ KeyStateX[23] ^ KeyStateX[15] ^ KeyStateX[28] ^ KeyStateX[5] ^ KeyStateX[0] ^ KeyStateX[1] ^ KeyStateX[10] ^ KeyStateX[25] ^ KeyStateX[30] ^ KeyStateX[13] ^ KeyStateX[12] ^ KeyStateX[18] ^ KeyStateX[16] ^ KeyStateX[29] ^ KeyStateX[11];
						KeyStateY[18] = KeyStateX[25] ^ KeyStateX[9] ^ KeyStateX[30] ^ KeyStateX[22] ^ KeyStateX[14] ^ KeyStateX[3] ^ KeyStateX[10] ^ KeyStateX[18] ^ KeyStateX[12] ^ KeyStateX[4] ^ KeyStateX[26] ^ KeyStateX[21] ^ KeyStateX[27] ^ KeyStateX[24] ^ KeyStateX[8] ^ KeyStateX[28];
						KeyStateY[19] = KeyStateX[0] ^ KeyStateX[17] ^ KeyStateX[1] ^ KeyStateX[19] ^ KeyStateX[11] ^ KeyStateX[13] ^ KeyStateX[5] ^ KeyStateX[7] ^ KeyStateX[29] ^ KeyStateX[15] ^ KeyStateX[6] ^ KeyStateX[20] ^ KeyStateX[16] ^ KeyStateX[31] ^ KeyStateX[23] ^ KeyStateX[2];
						KeyStateY[20] = KeyStateX[9] ^ KeyStateX[17] ^ KeyStateX[13] ^ KeyStateX[5] ^ KeyStateX[7] ^ KeyStateX[2] ^ KeyStateX[28] ^ KeyStateX[30] ^ KeyStateX[11] ^ KeyStateX[4] ^ KeyStateX[24] ^ KeyStateX[0] ^ KeyStateX[26] ^ KeyStateX[23] ^ KeyStateX[16] ^ KeyStateX[22];
						KeyStateY[21] = KeyStateX[12] ^ KeyStateX[20] ^ KeyStateX[27] ^ KeyStateX[19] ^ KeyStateX[8] ^ KeyStateX[6] ^ KeyStateX[21] ^ KeyStateX[25] ^ KeyStateX[3] ^ KeyStateX[10] ^ KeyStateX[31] ^ KeyStateX[1] ^ KeyStateX[18] ^ KeyStateX[14] ^ KeyStateX[29] ^ KeyStateX[15];
						KeyStateY[22] = KeyStateX[7] ^ KeyStateX[3] ^ KeyStateX[11] ^ KeyStateX[30] ^ KeyStateX[28] ^ KeyStateX[18] ^ KeyStateX[10] ^ KeyStateX[25] ^ KeyStateX[1] ^ KeyStateX[24] ^ KeyStateX[16] ^ KeyStateX[22] ^ KeyStateX[26] ^ KeyStateX[9] ^ KeyStateX[13] ^ KeyStateX[8];
						KeyStateY[23] = KeyStateX[20] ^ KeyStateX[12] ^ KeyStateX[21] ^ KeyStateX[23] ^ KeyStateX[31] ^ KeyStateX[15] ^ KeyStateX[6] ^ KeyStateX[2] ^ KeyStateX[29] ^ KeyStateX[19] ^ KeyStateX[4] ^ KeyStateX[0] ^ KeyStateX[14] ^ KeyStateX[17] ^ KeyStateX[27] ^ KeyStateX[5];
						KeyStateY[24] = KeyStateX[31] ^ KeyStateX[7] ^ KeyStateX[23] ^ KeyStateX[6] ^ KeyStateX[10] ^ KeyStateX[2] ^ KeyStateX[5] ^ KeyStateX[8] ^ KeyStateX[15] ^ KeyStateX[24] ^ KeyStateX[9] ^ KeyStateX[12] ^ KeyStateX[16] ^ KeyStateX[27] ^ KeyStateX[14] ^ KeyStateX[30];
						KeyStateY[25] = KeyStateX[0] ^ KeyStateX[4] ^ KeyStateX[20] ^ KeyStateX[13] ^ KeyStateX[1] ^ KeyStateX[22] ^ KeyStateX[26] ^ KeyStateX[3] ^ KeyStateX[28] ^ KeyStateX[25] ^ KeyStateX[17] ^ KeyStateX[21] ^ KeyStateX[18] ^ KeyStateX[11] ^ KeyStateX[29] ^ KeyStateX[19];
						KeyStateY[26] = KeyStateX[18] ^ KeyStateX[10] ^ KeyStateX[2] ^ KeyStateX[15] ^ KeyStateX[8] ^ KeyStateX[28] ^ KeyStateX[25] ^ KeyStateX[3] ^ KeyStateX[21] ^ KeyStateX[9] ^ KeyStateX[14] ^ KeyStateX[30] ^ KeyStateX[16] ^ KeyStateX[7] ^ KeyStateX[31] ^ KeyStateX[13];
						KeyStateY[27] = KeyStateX[17] ^ KeyStateX[1] ^ KeyStateX[22] ^ KeyStateX[27] ^ KeyStateX[19] ^ KeyStateX[0] ^ KeyStateX[4] ^ KeyStateX[5] ^ KeyStateX[29] ^ KeyStateX[20] ^ KeyStateX[24] ^ KeyStateX[12] ^ KeyStateX[11] ^ KeyStateX[23] ^ KeyStateX[26] ^ KeyStateX[6];
						KeyStateY[28] = KeyStateX[27] ^ KeyStateX[2] ^ KeyStateX[4] ^ KeyStateX[13] ^ KeyStateX[5] ^ KeyStateX[6] ^ KeyStateX[17] ^ KeyStateX[25] ^ KeyStateX[19] ^ KeyStateX[9] ^ KeyStateX[7] ^ KeyStateX[1] ^ KeyStateX[14] ^ KeyStateX[26] ^ KeyStateX[11] ^ KeyStateX[10];
						KeyStateY[29] = KeyStateX[28] ^ KeyStateX[12] ^ KeyStateX[16] ^ KeyStateX[24] ^ KeyStateX[0] ^ KeyStateX[31] ^ KeyStateX[21] ^ KeyStateX[30] ^ KeyStateX[8] ^ KeyStateX[3] ^ KeyStateX[23] ^ KeyStateX[22] ^ KeyStateX[18] ^ KeyStateX[15] ^ KeyStateX[29] ^ KeyStateX[20];
						KeyStateY[30] = KeyStateX[13] ^ KeyStateX[5] ^ KeyStateX[3] ^ KeyStateX[19] ^ KeyStateX[25] ^ KeyStateX[8] ^ KeyStateX[18] ^ KeyStateX[28] ^ KeyStateX[22] ^ KeyStateX[7] ^ KeyStateX[11] ^ KeyStateX[10] ^ KeyStateX[14] ^ KeyStateX[2] ^ KeyStateX[17] ^ KeyStateX[31];
						KeyStateY[31] = KeyStateX[21] ^ KeyStateX[6] ^ KeyStateX[30] ^ KeyStateX[12] ^ KeyStateX[20] ^ KeyStateX[24] ^ KeyStateX[23] ^ KeyStateX[26] ^ KeyStateX[29] ^ KeyStateX[0] ^ KeyStateX[9] ^ KeyStateX[1] ^ KeyStateX[15] ^ KeyStateX[27] ^ KeyStateX[16] ^ KeyStateX[4];
					}

					GeneratedRoundSubkeyVector = TransformedRoundSubkeyVector;

					CheckPointer = memory_set_no_optimize_function<0x00>(TransformedRoundSubkeyVector.data(), TransformedRoundSubkeyVector.size() * sizeof(std::uint64_t));
					CheckPointer = nullptr;

					++(this->MatrixTransformationCounter);
				}

				std::array<std::uint32_t, 2> ForwardTransform
				(
					std::uint32_t LeftWordData,
					std::uint32_t RightWordData
				)
				{
					//Pseudo-Hadamard Transformation (Forward)
					auto A = LeftWordData + RightWordData;
					auto B = LeftWordData + RightWordData * 2;

					B ^= std::rotl(A, 1);
					A ^= std::rotr(B, 63);

					return {A, B};
				}

				std::array<std::uint32_t, 2> BackwardTransform
				(
					std::uint32_t LeftWordData,
					std::uint32_t RightWordData
				)
				{
					LeftWordData ^= std::rotr(RightWordData, 63);
					RightWordData ^= std::rotl(LeftWordData, 1);
				
					//Pseudo-Hadamard Transformation (Backward)
					auto B = RightWordData - LeftWordData;
					auto A = 2 * LeftWordData - RightWordData;

					return {A, B};
				}

				/*
					使用生成的伪随机数序列对相关(字)进行疯狂比特变换
					Crazy bit transformation of the correlation (word) using the generated pseudo-random number sequence
				*/
				std::uint32_t CrazyTransformAssociatedWord
				(
					std::uint32_t AssociatedWordData,
					const std::uint64_t WordKeyMaterial
				)
				{
					std::array<std::uint32_t, 2> BitReorganizationWord { 0, 0 };

					auto& [WordA, WordB] = BitReorganizationWord;

					//将64位（字）的密钥材料的左右两半应用于2个32位（字）的数据
					//Apply the left and right halves of the 64-bit (word) key material to the 2 32-bit (word) data
					const std::uint32_t LeftWordKey = static_cast<std::uint32_t>( static_cast<std::uint64_t>(WordKeyMaterial & 0xFFFFFFFF00000000ULL) >> static_cast<std::uint64_t>(32) );
					const std::uint32_t RightWordKey = static_cast<std::uint32_t>( static_cast<std::uint64_t>(WordKeyMaterial & 0x00000000FFFFFFFFULL) );

					//Unidirectional function（单射函数）
					//2个内存字的非线性单射变换函数（相当于应用不可逆元的字节替换盒?）
					//根据每一轮的数据和密钥，会产生不同的结果
					//Non-linear one-shot transformation function for 2 memory words (equivalent to applying a byte substitution box of irreversible elements?)
					//Depending on the data and key of each round, different results are produced
					WordA = LeftWordKey
						^ std::rotr( 1U, AssociatedWordData % 32 )
						| std::rotr( RightWordKey, WordKeyMaterial % 32 );

					WordB = RightWordKey
						^ std::rotr( 1U, AssociatedWordData % 32 )
						| std::rotr( LeftWordKey, WordKeyMaterial % 32 );

					WordA -= WordB;
					WordB -= WordA;

					WordB = WordA
						^ std::rotl( 1U, (AssociatedWordData ^ ~RightWordKey) % 32 )
						& std::rotl( WordB, (WordKeyMaterial ^ WordA) % 32);

					WordA = WordB
						^ std::rotl( 1U, (AssociatedWordData ^ ~LeftWordKey) % 32 )
						& std::rotl( WordA, (WordKeyMaterial ^ WordB) % 32 );

					WordA += WordB;
					WordB += WordA;

					auto& MatrixOffsetWithRandomIndices = CommonStateDataPointerObject.AccessReference().MatrixOffsetWithRandomIndices;
					auto& TransformedRoundSubkeyMatrix = *(GeneratedRoundSubkeyMatrixPointer.get());

					const std::uint32_t& Row = MatrixOffsetWithRandomIndices[ WordA % MatrixOffsetWithRandomIndices.size() ];
					const std::uint32_t& Column = MatrixOffsetWithRandomIndices[ WordB % MatrixOffsetWithRandomIndices.size() ];

					//const std::uint32_t& Row = WordA % TransformedRoundSubkeyMatrix.rows();
					//const std::uint32_t& Column = WordB % TransformedRoundSubkeyMatrix.cols();

					const std::uint64_t RoundSubkey = TransformedRoundSubkeyMatrix(Row, Column);

					//将64位（字）的密钥材料的左右两半应用于2个32位（字）的数据
					//Apply the left and right halves of the 64-bit (word) key material to the 2 32-bit (word) data
					WordA ^= static_cast<std::uint32_t>( static_cast<std::uint64_t>(RoundSubkey & 0xFFFFFFFF00000000ULL) >> static_cast<std::uint64_t>(32) );
					WordB ^= static_cast<std::uint32_t>( static_cast<std::uint64_t>(RoundSubkey & 0x00000000FFFFFFFFULL) );

					AssociatedWordData ^= (WordA ^ WordB);

					return AssociatedWordData;
				}

				auto& UseRoundSubkeyVectorReference()
				{
					return *(this->GeneratedRoundSubkeyVectorPointer.get());
				}

				SecureRoundSubkeyGeneratationModule(ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>& CommonStateData)
					:
					CommonStateDataPointerObject(CommonStateData)
				{
				
				}

				~SecureRoundSubkeyGeneratationModule()
				{
					volatile void* CheckPointer = nullptr;

					auto& GeneratedRoundSubkeyMatrix = *(this->GeneratedRoundSubkeyMatrixPointer.get());
					auto& GeneratedRoundSubkeyVector = *(this->GeneratedRoundSubkeyVectorPointer.get());

					CheckPointer = memory_set_no_optimize_function<0x00>(GeneratedRoundSubkeyVector.data(), GeneratedRoundSubkeyVector.size() * sizeof(std::uint64_t));
					CheckPointer = nullptr;

					GeneratedRoundSubkeyMatrix.setZero();
				}
			};
		}

		template<std::size_t OPC_QuadWord_DataBlockSize, std::size_t OPC_QuadWord_KeyBlockSize>
		class StateData_Worker
		{

		private:

			ImplementationDetails::CommonStateDataPointer<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize> CommonStateDataPointerObject;
			ImplementationDetails::SecureSubkeyGeneratationModule<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize> SecureSubkeyGeneratationModuleObject;
			ImplementationDetails::SecureRoundSubkeyGeneratationModule<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize> SecureRoundSubkeyGeneratationModuleObject;

			//检查本轮子密钥已经生成的次数的计数器
			//Counter to check the number of times the current round of subkeys has been generated
			volatile std::uint64_t RoundSubkeysCounter = 0;

			//China Pediy BBS: https://bbs.pediy.com/thread-253916.htm
			//AES Forward SubstitutionBox Modified
			//Primitive polynomial degree is 8
			//x^8 + x^7 + x^6 + x^5 + x^4 + x^3 + 1
			static constexpr std::array<std::uint8_t, 256> ForwardSubstitutionBox0
			{
				0x7F, 0x84, 0x01, 0x2B, 0xC3, 0x4E, 0x55, 0x58, 0x21, 0x62, 0x64, 0xF1, 0xE9, 0x81, 0x6F, 0x6D,
				0x50, 0x71, 0x72, 0x61, 0xF2, 0xA9, 0xBB, 0xD7, 0xB7, 0xF8, 0x00, 0x74, 0xF4, 0x05, 0x76, 0x6E,
				0xE8, 0x8F, 0x78, 0x34, 0xF9, 0x28, 0xF3, 0x54, 0x3A, 0x6C, 0x14, 0x02, 0x1D, 0x7B, 0xA8, 0x5E,
				0x98, 0x25, 0x3F, 0x87, 0xC0, 0x8A, 0x79, 0xE2, 0xBA, 0xE5, 0xC1, 0x24, 0xFB, 0x13, 0xF7, 0xCF,
				0xB4, 0x12, 0x07, 0x95, 0xFC, 0x8D, 0xDA, 0x5B, 0x3C, 0x53, 0xD4, 0x09, 0x39, 0x4B, 0xEA, 0x27,
				0xDD, 0xB9, 0x75, 0xB6, 0x49, 0xD5, 0x42, 0x3E, 0xCD, 0xF6, 0x7D, 0x5F, 0x17, 0xA1, 0xEF, 0xD3,
				0x0F, 0x0B, 0x52, 0x2F, 0xDC, 0x46, 0x80, 0x30, 0xA0, 0x99, 0x06, 0x56, 0xFF, 0xE0, 0xB1, 0xB0,
				0x1E, 0x60, 0x32, 0x8E, 0xA3, 0x67, 0x51, 0x7E, 0xBE, 0x15, 0xCA, 0x8C, 0x3B, 0xAB, 0xA4, 0x16,
				0x19, 0xA7, 0xC9, 0x4D, 0x43, 0x94, 0x89, 0xCC, 0x3D, 0x70, 0x85, 0x59, 0x2E, 0xD1, 0xEE, 0x9E,
				0x5D, 0x8B, 0x69, 0x77, 0x29, 0xD2, 0x44, 0x63, 0x5C, 0x82, 0x65, 0x45, 0x36, 0x1A, 0xD0, 0x88,
				0xAD, 0xD6, 0x9F, 0xAC, 0x7A, 0x4F, 0x9B, 0x41, 0xE7, 0x47, 0x2A, 0xB2, 0xE1, 0x0D, 0xDF, 0x97,
				0x26, 0xC5, 0x38, 0x6B, 0xFD, 0x2D, 0xEC, 0xF5, 0xC8, 0x10, 0x93, 0x20, 0x37, 0x9A, 0xAA, 0xA2,
				0xC4, 0xB3, 0xC6, 0xA6, 0x6A, 0xDB, 0x57, 0x0A, 0xAE, 0x9C, 0xE3, 0x08, 0x03, 0x1F, 0xD8, 0x2C,
				0x90, 0xB5, 0x0C, 0x83, 0x40, 0x23, 0x68, 0x91, 0xBC, 0x22, 0x33, 0x66, 0x18, 0xAF, 0x1B, 0xCE,
				0x4C, 0xE4, 0xF0, 0xFE, 0x5A, 0x0E, 0x04, 0x35, 0x11, 0xBD, 0x73, 0xFA, 0xEB, 0x9D, 0x7C, 0x48,
				0x1C, 0xD9, 0x4A, 0xC2, 0xA5, 0xC7, 0x86, 0xED, 0xDE, 0xBF, 0x96, 0xB8, 0x92, 0x31, 0xCB, 0xE6,
			};

			//China Pediy BBS: https://bbs.pediy.com/thread-253916.htm
			//AES Backward SubstitutionBox Modified
			//Primitive polynomial degree is 8
			//x^8 + x^7 + x^6 + x^5 + x^4 + x^3 + 1
			static constexpr std::array<std::uint8_t, 256> BackwardSubstitutionBox0
			{
				0x1A, 0x02, 0x2B, 0xCC, 0xE6, 0x1D, 0x6A, 0x42, 0xCB, 0x4B, 0xC7, 0x61, 0xD2, 0xAD, 0xE5, 0x60,
				0xB9, 0xE8, 0x41, 0x3D, 0x2A, 0x79, 0x7F, 0x5C, 0xDC, 0x80, 0x9D, 0xDE, 0xF0, 0x2C, 0x70, 0xCD,
				0xBB, 0x08, 0xD9, 0xD5, 0x3B, 0x31, 0xB0, 0x4F, 0x25, 0x94, 0xAA, 0x03, 0xCF, 0xB5, 0x8C, 0x63,
				0x67, 0xFD, 0x72, 0xDA, 0x23, 0xE7, 0x9C, 0xBC, 0xB2, 0x4C, 0x28, 0x7C, 0x48, 0x88, 0x57, 0x32,
				0xD4, 0xA7, 0x56, 0x84, 0x96, 0x9B, 0x65, 0xA9, 0xEF, 0x54, 0xF2, 0x4D, 0xE0, 0x83, 0x05, 0xA5,
				0x10, 0x76, 0x62, 0x49, 0x27, 0x06, 0x6B, 0xC6, 0x07, 0x8B, 0xE4, 0x47, 0x98, 0x90, 0x2F, 0x5B,
				0x71, 0x13, 0x09, 0x97, 0x0A, 0x9A, 0xDB, 0x75, 0xD6, 0x92, 0xC4, 0xB3, 0x29, 0x0F, 0x1F, 0x0E,
				0x89, 0x11, 0x12, 0xEA, 0x1B, 0x52, 0x1E, 0x93, 0x22, 0x36, 0xA4, 0x2D, 0xEE, 0x5A, 0x77, 0x00,
				0x66, 0x0D, 0x99, 0xD3, 0x01, 0x8A, 0xF6, 0x33, 0x9F, 0x86, 0x35, 0x91, 0x7B, 0x45, 0x73, 0x21,
				0xD0, 0xD7, 0xFC, 0xBA, 0x85, 0x43, 0xFA, 0xAF, 0x30, 0x69, 0xBD, 0xA6, 0xC9, 0xED, 0x8F, 0xA2,
				0x68, 0x5D, 0xBF, 0x74, 0x7E, 0xF4, 0xC3, 0x81, 0x2E, 0x15, 0xBE, 0x7D, 0xA3, 0xA0, 0xC8, 0xDD,
				0x6F, 0x6E, 0xAB, 0xC1, 0x40, 0xD1, 0x53, 0x18, 0xFB, 0x51, 0x38, 0x16, 0xD8, 0xE9, 0x78, 0xF9,
				0x34, 0x3A, 0xF3, 0x04, 0xC0, 0xB1, 0xC2, 0xF5, 0xB8, 0x82, 0x7A, 0xFE, 0x87, 0x58, 0xDF, 0x3F,
				0x9E, 0x8D, 0x95, 0x5F, 0x4A, 0x55, 0xA1, 0x17, 0xCE, 0xF1, 0x46, 0xC5, 0x64, 0x50, 0xF8, 0xAE,
				0x6D, 0xAC, 0x37, 0xCA, 0xE1, 0x39, 0xFF, 0xA8, 0x20, 0x0C, 0x4E, 0xEC, 0xB6, 0xF7, 0x8E, 0x5E,
				0xE2, 0x0B, 0x14, 0x26, 0x1C, 0xB7, 0x59, 0x3E, 0x19, 0x24, 0xEB, 0x3C, 0x44, 0xB4, 0xE3, 0x6C
			};

			//China ZUC Cipher Forward SubstitutionBox
			static constexpr std::array<std::uint8_t, 256> ForwardSubstitutionBox1
			{
				0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
				0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42,
				0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1,
				0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48,
				0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87,
				0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB,
				0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09,
				0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9,
				0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9,
				0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89,
				0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4,
				0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE,
				0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21,
				0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34,
				0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
				0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2,
			};

			//China ZUC Cipher Backward SubstitutionBox
			static constexpr std::array<std::uint8_t, 256> BackwardSubstitutionBox1
			{
				0x17, 0xA0, 0xBB, 0xFD, 0xEE, 0x37, 0x43, 0xDA, 0x6E, 0x6F, 0xDB, 0x3C, 0x13, 0x85, 0xDE, 0xB5,
				0x28, 0x42, 0xFC, 0x16, 0x65, 0xAA, 0x1A, 0x66, 0xC6, 0x76, 0x15, 0xC8, 0x9B, 0x8B, 0xD3, 0xEB,
				0x41, 0xCF, 0x38, 0x68, 0xA4, 0xF9, 0x21, 0x49, 0xEF, 0x0C, 0x33, 0x60, 0xC9, 0x88, 0x83, 0xF4,
				0x6B, 0xD5, 0xEC, 0xD9, 0xDF, 0xD7, 0x44, 0x91, 0xA7, 0x2D, 0x30, 0x04, 0x09, 0xE5, 0x27, 0x73,
				0x1C, 0xD4, 0x1F, 0x2E, 0x20, 0x26, 0x89, 0x06, 0x3F, 0x9E, 0xBC, 0x7A, 0x52, 0x90, 0x78, 0x58,
				0xAC, 0xC3, 0x4A, 0x61, 0xD2, 0x00, 0x32, 0x55, 0xA3, 0xF5, 0xD0, 0x0B, 0x63, 0x7D, 0x94, 0xA6,
				0xE6, 0x74, 0x3E, 0x02, 0xF0, 0xED, 0x39, 0x6C, 0x22, 0x4C, 0xD1, 0xC5, 0xE7, 0x35, 0x8A, 0xB7,
				0x72, 0x03, 0x1B, 0x6D, 0xCC, 0x93, 0x29, 0x0F, 0xA8, 0xBD, 0x5E, 0xE8, 0xE3, 0x6A, 0xDD, 0x50,
				0xCA, 0x24, 0x98, 0x95, 0x51, 0xF2, 0x07, 0x4F, 0xE0, 0x9F, 0xF6, 0x2C, 0x10, 0x5D, 0x77, 0x7C,
				0xAB, 0xB1, 0xD6, 0x7B, 0x12, 0xAE, 0x23, 0x8C, 0xE2, 0xA9, 0x59, 0xF3, 0x54, 0x99, 0x96, 0x08,
				0xB8, 0x64, 0xA5, 0xC0, 0x56, 0x92, 0x14, 0x2B, 0x19, 0x7F, 0x0D, 0x97, 0xFA, 0x80, 0x82, 0xFB,
				0xF8, 0xE1, 0x75, 0x36, 0xB6, 0x31, 0xA1, 0x71, 0xAD, 0x9A, 0xDC, 0x4B, 0x57, 0xA2, 0xF1, 0x3A,
				0x34, 0x46, 0x01, 0xBE, 0xD8, 0x11, 0x2A, 0xB2, 0x05, 0x45, 0xE9, 0x84, 0xB9, 0x9D, 0xB3, 0x47,
				0xB0, 0x8E, 0x53, 0xEA, 0x4E, 0x69, 0x5C, 0xF7, 0x62, 0x25, 0x0A, 0x7E, 0x3B, 0x40, 0xBF, 0x5A,
				0x9C, 0x2F, 0xFE, 0x18, 0xAF, 0x79, 0xC4, 0xCD, 0x8D, 0x8F, 0xC2, 0x5F, 0xC7, 0xB4, 0x70, 0xC1,
				0xBA, 0x81, 0xFF, 0xE4, 0x87, 0x4D, 0x48, 0xCB, 0x1E, 0x1D, 0x3D, 0x67, 0x86, 0x0E, 0x5B, 0xCE,
			};

			template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ThisExecuteMode>
			void ByteSubstitution(std::span<std::uint8_t> EachRoundDatas)
			{
				if((EachRoundDatas.size() & 7) != 0)
					return;

				/*
					字节数据置换层
					Byte Data Substitution Layer
				*/
				if constexpr(ThisExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					for(std::uint64_t Index = 0; Index < EachRoundDatas.size(); Index += 8)
					{
						EachRoundDatas[Index] = ForwardSubstitutionBox1[EachRoundDatas[Index]];
						EachRoundDatas[Index + 1] = ForwardSubstitutionBox0[EachRoundDatas[Index + 1]];
						EachRoundDatas[Index + 2] = BackwardSubstitutionBox1[EachRoundDatas[Index + 2]];
						EachRoundDatas[Index + 3] = BackwardSubstitutionBox0[EachRoundDatas[Index + 3]];

						EachRoundDatas[Index + 4] = ForwardSubstitutionBox0[EachRoundDatas[Index + 4]];
						EachRoundDatas[Index + 5] = BackwardSubstitutionBox1[EachRoundDatas[Index + 5]];
						EachRoundDatas[Index + 6] = ForwardSubstitutionBox0[EachRoundDatas[Index + 6]];
						EachRoundDatas[Index + 7] = BackwardSubstitutionBox1[EachRoundDatas[Index + 7]];
					}
				}
				else if constexpr(ThisExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					for(std::uint64_t Index = 0; Index < EachRoundDatas.size(); Index += 8)
					{
						EachRoundDatas[Index] = BackwardSubstitutionBox1[EachRoundDatas[Index]];
						EachRoundDatas[Index + 1] = BackwardSubstitutionBox0[EachRoundDatas[Index + 1]];
						EachRoundDatas[Index + 2] = ForwardSubstitutionBox1[EachRoundDatas[Index + 2]];
						EachRoundDatas[Index + 3] = ForwardSubstitutionBox0[EachRoundDatas[Index + 3]];

						EachRoundDatas[Index + 4] = BackwardSubstitutionBox0[EachRoundDatas[Index + 4]];
						EachRoundDatas[Index + 5] = ForwardSubstitutionBox1[EachRoundDatas[Index + 5]];
						EachRoundDatas[Index + 6] = BackwardSubstitutionBox0[EachRoundDatas[Index + 6]];
						EachRoundDatas[Index + 7] = ForwardSubstitutionBox1[EachRoundDatas[Index + 7]];
					}
				}
				else
				{
					static_assert(CommonToolkit::Dependent_Always_Failed<ThisExecuteMode>, "");
				}
			}

			/*
				https://en.wikipedia.org/wiki/Lai%E2%80%93Massey_scheme

				The Lai–Massey scheme is a cryptographic structure used in the design of block ciphers.
				It is used in IDEA and IDEA NXT. 
				The scheme was originally introduced by Xuejia Lai with the assistance of James L. Massey, hence the scheme's name, Lai-Massey.
		 
				The Lai-Massey Scheme is similar to a Feistel Network in design, using a round function and a half-round function.
				The round function is a function which takes two inputs, a sub-key and a Data block, and which returns one output of equal length to the Data block.
				The half-round function takes two inputs and transforms them into two outputs. 
				For any given round, the input is split into two halves, left and right.
				Initially, the inputs are passed through the half-round function.
				In each round, the difference between the inputs is passed to the round function along with a sub-key, and the result from the round function is then added to each input.
				The input is then passed to the half-round function, which is repeated a fixed number of times, and the final output is the encrypted data.
				Due to its design, it has an advantage over a Substitution-permutation network since the round-function does not need to be inverted
				just the half-round - enabling it to be more easily inverted, and enabling the round-function to be arbitrarily complex.
				The encryption and decryption processes are fairly similar, decryption instead requiring a reversal of the key schedule, an inverted half-round function, and that the round function's output be "subtracted" instead of "added".

				Lai-Massey方案是一种用于设计分块密码的密码器结构
				它被用于IDEA和IDEA NXT。
 
				该方案最初是由Xuejia Lai在James L. Massey的协助下提出的，因此该方案的名称为Lai-Massey
		 
				Lai-Massey方案在设计上类似于Feistel网络，使用一个轮函数和一个半轮函数
				轮函数是一个需要两个输入的函数，一个子密钥和一个数据块，并返回一个与数据块等长的输出
				半轮函数接受两个输入，并将其转化为两个输出。对于任何给定的回合，输入被分成两半，即左和右
				最初，输入被传递给半轮函数。
				在每一轮中，输入之间的差异与一个子密钥一起被传递给轮函数，然后轮函数的结果被增加到每个输入
				然后，输入被传递到半轮函数中，重复固定的次数，最后的输出是加密的数据。
				由于它的设计，它比置换-排列网络更有优势，因为轮函数不需要被反转-只需要半轮函数被反转--使它更容易被反转，并使轮函数可以任意地复杂
				加密和解密过程相当相似，解密则需要颠倒密钥计划，倒置半轮函数，以及轮函数的输出被"减去"而不是"增加"

			*/
			template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ThisExecuteMode>
			inline std::uint64_t LaiMasseyFramework
			(
				std::uint64_t WordData,
				std::uint64_t WordKeyMaterial
			)
			{
				/*
					L' = H-Forward(L ⊕ F(L ⊕ R, K[++n]))
					R' = R ⊕ F(L ⊕ R, K[++n])

					L = H-Backward(L') ⊕ F(H-Backward(L') ⊕ R', K[--n])
					R = R' ⊕ F(H-Backward(L') ⊕ R', K[--n])

					H-Backward(L') = L ⊕ F(L ⊕ R, K[--n])
					H-Backward(L') ⊕ R' = L ⊕ F(L ⊕ R, K[--n]) ⊕ R ⊕ F(L ⊕ R, K[--n]) = L ⊕ R
				*/

				if constexpr(ThisExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					if constexpr(std::endian::native == std::endian::big)
					{
						WordData = CommonToolkit::ByteSwap::byteswap(WordData);
					}

					//L,R = PlainText
					std::uint32_t LeftWordData = static_cast<std::uint32_t>( static_cast<std::uint64_t>(WordData & 0xFFFFFFFF00000000ULL) >> static_cast<std::uint64_t>(32) );
					std::uint32_t RightWordData = static_cast<std::uint32_t>( static_cast<std::uint64_t>(WordData & 0x00000000FFFFFFFFULL) );

					const std::uint32_t TransformKey = SecureRoundSubkeyGeneratationModuleObject.CrazyTransformAssociatedWord(LeftWordData ^ RightWordData, WordKeyMaterial);

					//L'' = L' ⊕ TK
					LeftWordData ^= TransformKey;
					//R'' = R' ⊕ TK
					RightWordData ^= TransformKey;

					std::array<std::uint32_t, 2> HalfRoundDataArray = SecureRoundSubkeyGeneratationModuleObject.ForwardTransform(LeftWordData, RightWordData);

					//HalfRoundDataArray[0] ^= ( std::rotl((RightWordData ^ LeftWordKey), (RightWordData & 31)) ) & RightWordKey;
					//HalfRoundDataArray[1] ^= LeftWordKey | std::rotr(LeftWordData ^ RightWordKey, (LeftWordData & 31));

					//CipherText = L, R
					std::uint64_t ProcessedWordData = static_cast<std::uint64_t>( static_cast<std::uint64_t>(HalfRoundDataArray[0]) << static_cast<std::uint64_t>(32) | static_cast<std::uint64_t>(HalfRoundDataArray[1]) );

					if constexpr(std::endian::native == std::endian::big)
					{
						ProcessedWordData = CommonToolkit::ByteSwap::byteswap(ProcessedWordData);
					}

					LeftWordData = 0;
					RightWordData = 0;
					HalfRoundDataArray.fill(0);

					return ProcessedWordData;
				}
				else if constexpr(ThisExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					if constexpr(std::endian::native == std::endian::big)
					{
						WordData = CommonToolkit::ByteSwap::byteswap(WordData);
					}

					//L,R = CipherText
					std::uint32_t LeftWordData = static_cast<std::uint32_t>( static_cast<std::uint64_t>(WordData & 0xFFFFFFFF00000000ULL) >> static_cast<std::uint64_t>(32) );
					std::uint32_t RightWordData = static_cast<std::uint32_t>( static_cast<std::uint64_t>(WordData & 0x00000000FFFFFFFFULL) );

					std::array<std::uint32_t, 2> HalfRoundDataArray = SecureRoundSubkeyGeneratationModuleObject.BackwardTransform(LeftWordData, RightWordData);

					const std::uint32_t TransformKey = SecureRoundSubkeyGeneratationModuleObject.CrazyTransformAssociatedWord(HalfRoundDataArray[0] ^ HalfRoundDataArray[1], WordKeyMaterial);
				
					//R' = R'' ⊕ TK
					HalfRoundDataArray[1] ^= TransformKey;
					//L' = L'' ⊕ TK
					HalfRoundDataArray[0] ^= TransformKey;

					//HalfRoundDataArray[1] ^= LeftWordKey | std::rotr(LeftWordData ^ RightWordKey, (LeftWordData & 31));
					//HalfRoundDataArray[0] ^= std::rotl((RightWordData ^ LeftWordKey), (RightWordData & 31)) & RightWordKey;

					//PlainText = L, R
					std::uint64_t ProcessedWordData = static_cast<std::uint64_t>( static_cast<std::uint64_t>(HalfRoundDataArray[0]) << static_cast<std::uint64_t>(32) | static_cast<std::uint64_t>(HalfRoundDataArray[1]) );

					if constexpr(std::endian::native == std::endian::big)
					{
						ProcessedWordData = CommonToolkit::ByteSwap::byteswap(ProcessedWordData);
					}

					LeftWordData = 0;
					RightWordData = 0;
					HalfRoundDataArray.fill(0);
					
					return ProcessedWordData;
				}
				else
				{
					static_assert(CommonToolkit::Dependent_Always_Failed<ThisExecuteMode>,"");
				}
			}

			template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ThisExecuteMode>
			//每一轮过程的函数
			//The function of each round process
			void RoundFunction(std::span<std::uint64_t> EachRoundDatas)
			{
				if(EachRoundDatas.size() != OPC_QuadWord_DataBlockSize)
					return;

				/*
					每轮数据的数据变换函数
					Data transformation function for each round data
				*/
				if constexpr(ThisExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					auto& GeneratedRoundSubkeyVector = this->SecureRoundSubkeyGeneratationModuleObject.UseRoundSubkeyVectorReference();

					std::vector<std::uint8_t> BytesData(EachRoundDatas.size() * sizeof(std::uint64_t), 0);

					volatile std::size_t KeyIndex = 0;

					//生成用于轮函数的子密钥(不是原来子密钥！)
					//Generate a subkey for the round function (not the original subkey!)

					SecureRoundSubkeyGeneratationModuleObject.GenerationRoundSubkeys();

					for ( std::size_t RoundCounter = 0; RoundCounter < 16; ++RoundCounter )
					{
						DoEncryptionDataBlock:

						//L[0], R[0] --> L[N + 1], R[N + 1]
						//K[0] --> K[N]
						//正向应用RoundIndex (Index, KeyIndex) 和加密函数
						//Forward apply RoundIndex (Index, KeyIndex) and the encryption function
						for ( std::uint64_t Index = 0; Index < EachRoundDatas.size(); Index++ )
						{
							EachRoundDatas[Index] = this->LaiMasseyFramework<ThisExecuteMode>(EachRoundDatas[Index], GeneratedRoundSubkeyVector[KeyIndex]);

							if(KeyIndex < GeneratedRoundSubkeyVector.size())
								++KeyIndex;
						}

						if(KeyIndex < GeneratedRoundSubkeyVector.size())
						{
							goto DoEncryptionDataBlock;
						}
						else
						{
							KeyIndex = 0;
						}
					
						//非线性字节数据代换(编码函数)
						//Nonlinear byte data substitution (encoding function)

						CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(EachRoundDatas, BytesData.data());

						this->ByteSubstitution<ThisExecuteMode>(BytesData);

						CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(BytesData, EachRoundDatas.data());

						//向右循环移动元素
						//Circularly move elements to the right
						//std::ranges::rotate(EachRoundDatas.begin(), EachRoundDatas.begin() + 1, EachRoundDatas.end());
					}

					KeyIndex = 0;

					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(BytesData.data(), BytesData.size());
					if(CheckPointer != BytesData.data())
					{
						std::cout << "Force Memory Fill Has Been \"Optimization\" !" << std::endl;
						throw std::runtime_error("");
					}
					CheckPointer = nullptr;
				}
				else if constexpr(ThisExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					auto& GeneratedRoundSubkeyVector = this->SecureRoundSubkeyGeneratationModuleObject.UseRoundSubkeyVectorReference();

					std::vector<std::uint8_t> BytesData(EachRoundDatas.size() * sizeof(std::uint64_t), 0);

					volatile std::size_t KeyIndex = GeneratedRoundSubkeyVector.size();

					//生成用于轮函数的子密钥(不是原来子密钥！)
					//Generate a subkey for the round function (not the original subkey!)

					SecureRoundSubkeyGeneratationModuleObject.GenerationRoundSubkeys();

					for ( std::size_t RoundCounter = 0; RoundCounter < 16; ++RoundCounter )
					{
						//向左循环移动元素
						//Circularly move elements to the left
						//std::ranges::rotate(EachRoundDatas.begin(), EachRoundDatas.end() - 1, EachRoundDatas.end());
					
						//非线性字节数据代换(解码函数)
						//Nonlinear byte data substitution (decoding function)

						CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(EachRoundDatas, BytesData.data());

						this->ByteSubstitution<ThisExecuteMode>(BytesData);

						CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(BytesData, EachRoundDatas.data());

						DoDecryptionDataBlock:

						//L[N + 1], R[N + 1] --> L[0], R[0]
						//K[N] --> K[0]
						//反向应用RoundIndex (Index, KeyIndex) 和解密函数
						//Backward apply RoundIndex (Index, KeyIndex) and the decryption function
						for ( std::uint64_t Index = EachRoundDatas.size(); Index > 0; Index-- )
						{
							EachRoundDatas[Index - 1] = this->LaiMasseyFramework<ThisExecuteMode>(EachRoundDatas[Index - 1], GeneratedRoundSubkeyVector[KeyIndex - 1]);

							if(KeyIndex - 1 > 0)
								--KeyIndex;
						}

						if(KeyIndex - 1 > 0)
						{
							goto DoDecryptionDataBlock;
						}
						else
						{
							KeyIndex = GeneratedRoundSubkeyVector.size();
						}
					
					}

					KeyIndex = 0;

					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(BytesData.data(), BytesData.size());
					if(CheckPointer != BytesData.data())
					{
						std::cout << "Force Memory Fill Has Been \"Optimization\" !" << std::endl;
						throw std::runtime_error("");
					}
					CheckPointer = nullptr;
				}
				else
				{
					static_assert(CommonToolkit::Dependent_Always_Failed<ThisExecuteMode>, "");
				}
			}

			//#define NEED_OPC_VERSION1_FUNCTIONS
			#if defined(NEED_OPC_VERSION1_FUNCTIONS)

			template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ExecuteMode>
			void CustomizationTransformKeyOrDataBits(std::span<std::uint64_t> WordsDataA, std::span<const std::uint64_t> WordsDataB)
			{
				if(WordsDataA.size() != WordsDataB.size())
					return;

				auto DataBegin = WordsDataA.begin();
				auto DataEnd = WordsDataA.end();
				auto KeyBegin = WordsDataB.begin();
				auto KeyEnd = WordsDataB.end();

				constexpr std::uint64_t FlagModuloByFour = 3;
				constexpr std::uint64_t FlagModuloBySixtyFour = std::numeric_limits<std::uint64_t>::digits - 1;

				while
				(
					DataBegin != DataEnd && KeyBegin != KeyEnd
				)
				{
					std::uint8_t ChoiseBinaryBit = *DataBegin & FlagModuloByFour;
					std::uint8_t ChoiseBitPosition = (*DataBegin >> 2) & FlagModuloBySixtyFour;

					if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
					{
						*DataBegin ^= (static_cast<std::uint64_t>(1) << ChoiseBitPosition);

						switch (ChoiseBinaryBit)
						{
							case 0:
							{
								*DataBegin = std::rotr(*DataBegin, ChoiseBitPosition);
								break;
							}
							case 1:
							{
								*DataBegin = std::rotl(*DataBegin, ChoiseBitPosition);
								break;
							}
							case 2:
							{
								*DataBegin ^= *KeyBegin;
								*DataBegin = ~(*DataBegin);
								break;
							}
							case 3:
							{
								*DataBegin ^= *KeyBegin;
								break;
							}

							default:
								break;
						}
					}

					if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
					{
						switch (ChoiseBinaryBit)
						{
							case 0:
							{
								*DataBegin = std::rotl(*DataBegin, ChoiseBitPosition);
								break;
							}
							case 1:
							{
								*DataBegin = std::rotr(*DataBegin, ChoiseBitPosition);
								break;
							}
							case 2:
							{
								*DataBegin ^= *KeyBegin;
								*DataBegin = ~(*DataBegin);
								break;
							}
							case 3:
							{
								*DataBegin ^= *KeyBegin;
								break;
							}

							default:
								break;
						}

						*DataBegin ^= (static_cast<std::uint64_t>(1) << ChoiseBitPosition);
					}

					++DataBegin, ++KeyBegin;
				}
			}

			void PreEncryption(std::span<std::uint64_t> PlainText, std::span<const std::uint64_t> RoundSubkey)
			{
				if(!PlainText.empty() && PlainText.size() % OPC_QuadWord_DataBlockSize == 0)
					return;
				if(!RoundSubkey.empty() && RoundSubkey.size() % OPC_QuadWord_KeyBlockSize == 0)
					return;
				if(PlainText.size() != RoundSubkey.size())
					return;

				auto& NLFSR_Object = *(CommonStateDataPointerObject.AccessReference().NLFSR_ClassicPointer);

				std::vector<std::uint64_t> RoundSubkeyCopy(RoundSubkey.begin(), RoundSubkey.end());
				std::span<std::uint64_t> RoundSubkeyCopySpan(RoundSubkey.begin(), RoundSubkey.end());

				//通过自定义处理功能进行事先加密
				//Pre-encryption by custom processing function
				for ( std::size_t RoundDataIndex = 0; RoundDataIndex < PlainText.size(); RoundDataIndex += OPC_QuadWord_KeyBlockSize)
				{
					auto DataSpan = PlainText.subspan(RoundDataIndex, OPC_QuadWord_KeyBlockSize);
					auto KeySpan = RoundSubkeyCopySpan.subspan(RoundDataIndex, OPC_QuadWord_KeyBlockSize);

					this->CustomizationTransformKeyOrDataBits(DataSpan, KeySpan, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER);

					if(RoundDataIndex % OPC_QuadWord_KeyBlockSize == 0)
					{
						NLFSR_Object.seed(NLFSR_Object.unpredictable_bits(0, 63) & (RoundSubkey.size() - 1));
						CommonSecurity::ShuffleRangeData(KeySpan.begin(), KeySpan.end(), NLFSR_Object);
					}
				}
			}

			void PostDecryption(std::span<std::uint64_t> CipherText, std::span<const std::uint64_t> RoundSubkey)
			{
				if(!CipherText.size() && CipherText.size() % OPC_QuadWord_DataBlockSize == 0)
					return;
				if(!RoundSubkey.size() && RoundSubkey.size() % OPC_QuadWord_KeyBlockSize == 0)
					return;
				if(CipherText.size() != RoundSubkey.size())
					return;

				auto& NLFSR_Object = *(CommonStateDataPointerObject.AccessReference().NLFSR_ClassicPointer);

				std::vector<std::uint64_t> RoundSubkeyCopy(RoundSubkey.begin(), RoundSubkey.end());
				std::span<std::uint64_t> RoundSubkeyCopySpan(RoundSubkey.begin(), RoundSubkey.end());

				//通过自定义处理功能进行事后解密
				//Post-decryption by custom processing function
				for ( std::size_t RoundDataIndex = 0; RoundDataIndex < CipherText.size(); RoundDataIndex += OPC_QuadWord_KeyBlockSize)
				{
					auto DataSpan = CipherText.subspan(RoundDataIndex, OPC_QuadWord_KeyBlockSize);
					auto KeySpan = RoundSubkeyCopySpan.subspan(RoundDataIndex, OPC_QuadWord_KeyBlockSize);

					this->CustomizationTransformKeyOrDataBits(DataSpan, KeySpan, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER);

					if(RoundDataIndex % OPC_QuadWord_KeyBlockSize == 0)
					{
						NLFSR_Object.seed(NLFSR_Object.unpredictable_bits(0, 63) & (RoundSubkey.size() - 1));
						CommonSecurity::ShuffleRangeData(KeySpan.begin(), KeySpan.end(), NLFSR_Object);
					}
				}
			}

			#endif

			#undef NEED_OPC_VERSION1_FUNCTIONS

			/*
				https://en.wikipedia.org/wiki/Padding_(cryptography)

				ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.

				Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
			*/
			void PaddingData(std::vector<std::uint8_t>& Data) const
			{
				std::size_t NumberRemainder = Data.size() & (OPC_QuadWord_DataBlockSize * sizeof(std::uint64_t)) - 1;

				std::size_t NeedPaddingCount = (OPC_QuadWord_DataBlockSize * sizeof(std::uint64_t)) - NumberRemainder;

				std::random_device HardwareRandomDevice;
				std::mt19937 RandomNumericalGeneratorBySecureSeed ( CommonSecurity::GenerateSecureRandomNumberSeed<std::size_t>(HardwareRandomDevice) );
				CommonSecurity::RND::UniformIntegerDistribution UniformDistribution(0, 255);

				for (std::size_t loopCount = 0; loopCount < NeedPaddingCount; ++loopCount)
				{
					auto integer = static_cast<std::uint32_t>( UniformDistribution(RandomNumericalGeneratorBySecureSeed) );
					std::uint8_t byteData{ static_cast<std::uint8_t>(integer) };
					Data.push_back(byteData);
				}
				auto integer = static_cast<std::uint32_t>(NeedPaddingCount);
				std::uint8_t byteData{ static_cast<std::uint8_t>(integer) };
				Data[Data.size() - 1] = byteData;
			}

			/*
				https://en.wikipedia.org/wiki/Padding_(cryptography)

				ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.

				Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
			*/
			void UnpaddingData(std::vector<std::uint8_t>& Data) const
			{
				std::size_t count = static_cast<std::size_t>(Data.back());
				while (count--)
				{
					Data.pop_back();
				}
			}

			/*
				分块加密数据函数
				Split block encryption data function
			*/
			void SplitDataBlockToEncrypt(std::span<std::uint64_t> PlainText, std::span<const std::uint64_t> Keys)
			{
				/*
					Tips 提示
					对于二进制计算机来说，一个数字a是modulo b，这相当于用b减1然后和a做比特AND运算 (b 应该是2的幂)。
					For a binary computer, a number a is modulo b, which is equivalent to subtracting 1 from b and then doing a bitwise AND operation with a (b should be a power of 2)
				*/

				if( ( PlainText.size() & (OPC_QuadWord_DataBlockSize - 1) ) != 0)
					my_cpp2020_assert(false, "StateData_Worker: The size of PlainText is not a multiple of OPC_QuadWord_DataBlockSize!", std::source_location::current());
				if( ( Keys.size() & (OPC_QuadWord_KeyBlockSize - 1) ) != 0)
					my_cpp2020_assert(false, "StateData_Worker: The size of (Encryption)Keys is not a multiple of OPC_QuadWord_KeyBlockSize!", std::source_location::current());
				
				volatile void* CheckPointer = nullptr;

				volatile std::size_t Word64Bit_Key_OffsetIndex = 0;

				auto& WordKeyDataVector = CommonStateDataPointerObject.AccessReference().WordKeyDataVector;
				std::ranges::copy(Keys.begin(), Keys.begin() + WordKeyDataVector.size(), WordKeyDataVector.begin());
				Word64Bit_Key_OffsetIndex += OPC_QuadWord_KeyBlockSize;

				std::array<std::uint64_t, OPC_QuadWord_KeyBlockSize * 2> RandomWordKeyDataVector {};

				volatile bool ConditionControlFlag = true;
				volatile bool ConditionControlFlag2 = false;

				//生成代表"盐渍"的伪随机数
				//Generate a pseudo-random number representing "salted"
				std::mt19937_64 MersenneTwister64Bit;

				const std::size_t PlainTextSize = PlainText.size();
				for ( std::size_t DataBlockOffset = 0; DataBlockOffset < PlainTextSize; DataBlockOffset += OPC_QuadWord_DataBlockSize )
				{
					if(Word64Bit_Key_OffsetIndex < Keys.size())
					{
						std::span<const std::uint64_t> KeyByteSpan { Keys.begin() + Word64Bit_Key_OffsetIndex, Keys.begin() + Word64Bit_Key_OffsetIndex + OPC_QuadWord_KeyBlockSize };
						
						//使用你的主密钥数据
						//Use your master key data
						std::ranges::transform
						(
							KeyByteSpan.begin(),
							KeyByteSpan.end(),
							WordKeyDataVector.begin(),
							WordKeyDataVector.end(),
							WordKeyDataVector.begin(),
							[](const std::uint64_t& left, const std::uint64_t& right)
							{
								if(left == right)
									return ~(left + right);
								else
									return left ^ right;
							}
						);
						
						Word64Bit_Key_OffsetIndex += OPC_QuadWord_KeyBlockSize;

						//主密钥未使用时，应该更新WordKeyDataVector
						//The WordKeyDataVector should be updated when the master key is not used
						this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys(WordKeyDataVector);

						++(this->RoundSubkeysCounter);
					}
					else
					{
						//主密钥使用完毕之后，无需更新WordKeyDataVector，直接使用这个函数
						//After the used of the master key, no need to update the WordKeyDataVector, directly using this function
						
						if(ConditionControlFlag == true && ConditionControlFlag2 == false)
						{
							//使用默认的零数据，而不使用主密钥数据
							//Use the default zero data without the master key data
							const std::array<std::uint64_t, OPC_QuadWord_KeyBlockSize> ZeroWordKeyDataVector {};

							this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys(ZeroWordKeyDataVector);

							ConditionControlFlag = false;
						}
						
						if((this->RoundSubkeysCounter % 2048ULL) == 0)
						{
							using CommonSecurity::KDF::Scrypt::Algorithm;
							using CommonToolkit::MessagePacking;
							using CommonToolkit::MessageUnpacking;

							if((this->RoundSubkeysCounter % (2048ULL * 3ULL)) == 0)
							{
								ConditionControlFlag = false;
								ConditionControlFlag2 = false;
							}
							else if((this->RoundSubkeysCounter % (2048ULL * 2ULL)) == 0)
							{
								ConditionControlFlag2 = true;
							} 
							else if(this->RoundSubkeysCounter == 2048ULL)
							{
								ConditionControlFlag = true;
							}

							std::array<std::uint64_t, 16> SaltWordData {};
							std::ranges::generate_n( SaltWordData.begin(), SaltWordData.size(), MersenneTwister64Bit );

							if ( ConditionControlFlag == true )
							{
								std::array<std::uint8_t, 16 * sizeof( std::uint64_t )> SaltData {};
								MessageUnpacking<std::uint64_t, std::uint8_t>( SaltWordData, SaltData.data() );

								std::vector<std::uint8_t> MaterialKeys = MessageUnpacking<std::uint64_t, std::uint8_t>( RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() );
								Algorithm				  ScryptKeyDerivationFunctionObject;
								std::vector<std::uint8_t> GeneratedSecureKeys = ScryptKeyDerivationFunctionObject.GenerateKeys( MaterialKeys, SaltData, RandomWordKeyDataVector.size() * sizeof( std::uint64_t ), 1024, 8, 16 );
								MessagePacking<std::uint64_t, std::uint8_t>( GeneratedSecureKeys, RandomWordKeyDataVector.data() );

								//使用通过密钥派生函数的生成的数据，而不使用主密钥数据
								//Use the data generated by the key derivation function without using the master key data
								this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( RandomWordKeyDataVector );

								CheckPointer = memory_set_no_optimize_function<0x00>( SaltWordData.data(), SaltWordData.size() * sizeof( std::uint64_t ) );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( SaltData.data(), SaltData.size() );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( MaterialKeys.data(), MaterialKeys.size() );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedSecureKeys.data(), GeneratedSecureKeys.size() );
								CheckPointer = nullptr;
								GeneratedSecureKeys.clear();
								GeneratedSecureKeys.shrink_to_fit();

								ConditionControlFlag = false;
							}
							else if ( ConditionControlFlag2 == true )
							{
								std::array<std::uint8_t, 16 * sizeof( std::uint64_t )> SaltData {};
								MessageUnpacking<std::uint64_t, std::uint8_t>( SaltWordData, SaltData.data() );

								std::vector<std::uint8_t> MaterialKeys = MessageUnpacking<std::uint64_t, std::uint8_t>( RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() );
								Algorithm				  ScryptKeyDerivationFunctionObject;
								std::vector<std::uint8_t> GeneratedSecureKeys = ScryptKeyDerivationFunctionObject.GenerateKeys( MaterialKeys, SaltData, RandomWordKeyDataVector.size() * sizeof( std::uint64_t ), 1024, 8, 16 );
								MessagePacking<std::uint64_t, std::uint8_t>( GeneratedSecureKeys, RandomWordKeyDataVector.data() );

								//使用通过密钥派生函数的生成的数据，而不使用主密钥数据
								//Use the data generated by the key derivation function without using the master key data
								this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( RandomWordKeyDataVector );
								std::seed_seq Seeds = std::seed_seq( RandomWordKeyDataVector.begin(), RandomWordKeyDataVector.end() );
								MersenneTwister64Bit.seed( Seeds );

								CheckPointer = memory_set_no_optimize_function<0x00>( SaltWordData.data(), SaltWordData.size() * sizeof( std::uint64_t ) );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( SaltData.data(), SaltData.size() );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( MaterialKeys.data(), MaterialKeys.size() );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedSecureKeys.data(), GeneratedSecureKeys.size() );
								CheckPointer = nullptr;
								GeneratedSecureKeys.clear();
								GeneratedSecureKeys.shrink_to_fit();

								ConditionControlFlag2 = false;
							}

							const std::vector<std::uint64_t> EmptyData {};
							this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( EmptyData );
						}

						++(this->RoundSubkeysCounter);
					}

					std::span<std::uint64_t> DataByteSpan { PlainText.begin() + DataBlockOffset, PlainText.begin() + DataBlockOffset + OPC_QuadWord_DataBlockSize };

					this->RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(DataByteSpan);
				}

				this->RoundSubkeysCounter = 0;
				CheckPointer = memory_set_no_optimize_function<0x00>(RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
			}

			/*
				分块解密数据函数
				Split block decryption data function
			*/
			void SplitDataBlockToDecrypt(std::span<std::uint64_t> CipherText, std::span<const std::uint64_t> Keys)
			{
				/*
					Tips 提示
					对于二进制计算机来说，一个数字a是modulo b，这相当于用b减1然后和a做比特AND运算 (b 应该是2的幂)。
					For a binary computer, a number a is modulo b, which is equivalent to subtracting 1 from b and then doing a bitwise AND operation with a (b should be a power of 2)
				*/

				if( ( CipherText.size() & (OPC_QuadWord_DataBlockSize - 1) ) != 0)
					my_cpp2020_assert(false, "StateData_Worker: The size of CipherText is not a multiple of OPC_QuadWord_DataBlockSize!", std::source_location::current());
				if( ( Keys.size() & (OPC_QuadWord_KeyBlockSize - 1) ) != 0)
					my_cpp2020_assert(false, "StateData_Worker: The size of (Decryption)Keys is not a multiple of OPC_QuadWord_KeyBlockSize!", std::source_location::current());
				
				volatile void* CheckPointer = nullptr;

				volatile std::size_t Word64Bit_Key_OffsetIndex = 0;

				auto& WordKeyDataVector = CommonStateDataPointerObject.AccessReference().WordKeyDataVector;
				std::ranges::copy(Keys.begin(), Keys.begin() + WordKeyDataVector.size(), WordKeyDataVector.begin());
				Word64Bit_Key_OffsetIndex += OPC_QuadWord_KeyBlockSize;

				std::array<std::uint64_t, OPC_QuadWord_KeyBlockSize * 2> RandomWordKeyDataVector {};

				volatile bool ConditionControlFlag = true;
				volatile bool ConditionControlFlag2 = false;

				//生成代表"盐渍"的伪随机数
				//Generate a pseudo-random number representing "salted"
				std::mt19937_64 MersenneTwister64Bit;

				const std::size_t CipherTextSize = CipherText.size();
				for ( std::size_t DataBlockOffset = 0; DataBlockOffset < CipherTextSize; DataBlockOffset += OPC_QuadWord_DataBlockSize )
				{
					if(Word64Bit_Key_OffsetIndex < Keys.size())
					{
						std::span<const std::uint64_t> KeyByteSpan { Keys.begin() + Word64Bit_Key_OffsetIndex, Keys.begin() + Word64Bit_Key_OffsetIndex + OPC_QuadWord_KeyBlockSize };
						
						//使用你的主密钥数据
						//Use your master key data
						std::ranges::transform
						(
							KeyByteSpan.begin(),
							KeyByteSpan.end(),
							WordKeyDataVector.begin(),
							WordKeyDataVector.end(),
							WordKeyDataVector.begin(),
							[](const std::uint64_t& left, const std::uint64_t& right)
							{
								if(left == right)
									return ~(left + right);
								else
									return left ^ right;
							}
						);
						
						Word64Bit_Key_OffsetIndex += OPC_QuadWord_KeyBlockSize;

						//主密钥未使用时，应该更新WordKeyDataVector
						//The WordKeyDataVector should be updated when the master key is not used
						this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys(WordKeyDataVector);

						++(this->RoundSubkeysCounter);
					}
					else
					{
						//主密钥使用完毕之后，无需更新WordKeyDataVector，直接使用这个函数
						//After the used of the master key, no need to update the WordKeyDataVector, directly using this function
						
						if(ConditionControlFlag == true && ConditionControlFlag2 == false)
						{
							//使用默认的零数据，而不使用主密钥数据
							//Use the default zero data without the master key data
							const std::array<std::uint64_t, OPC_QuadWord_KeyBlockSize> ZeroWordKeyDataVector {};

							this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys(ZeroWordKeyDataVector);

							ConditionControlFlag = false;
						}
						
						if((this->RoundSubkeysCounter % 2048ULL) == 0)
						{
							using CommonSecurity::KDF::Scrypt::Algorithm;
							using CommonToolkit::MessagePacking;
							using CommonToolkit::MessageUnpacking;

							if((this->RoundSubkeysCounter % (2048ULL * 3ULL)) == 0)
							{
								ConditionControlFlag = false;
								ConditionControlFlag2 = false;
							}
							else if((this->RoundSubkeysCounter % (2048ULL * 2ULL)) == 0)
							{
								ConditionControlFlag2 = true;
							} 
							else if(this->RoundSubkeysCounter == 2048ULL)
							{
								ConditionControlFlag = true;
							}

							std::array<std::uint64_t, 16> SaltWordData {};
							std::ranges::generate_n( SaltWordData.begin(), SaltWordData.size(), MersenneTwister64Bit );

							if ( ConditionControlFlag == true )
							{
								std::array<std::uint8_t, 16 * sizeof( std::uint64_t )> SaltData {};
								MessageUnpacking<std::uint64_t, std::uint8_t>( SaltWordData, SaltData.data() );

								std::vector<std::uint8_t> MaterialKeys = MessageUnpacking<std::uint64_t, std::uint8_t>( RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() );
								Algorithm				  ScryptKeyDerivationFunctionObject;
								std::vector<std::uint8_t> GeneratedSecureKeys = ScryptKeyDerivationFunctionObject.GenerateKeys( MaterialKeys, SaltData, RandomWordKeyDataVector.size() * sizeof( std::uint64_t ), 1024, 8, 16 );
								MessagePacking<std::uint64_t, std::uint8_t>( GeneratedSecureKeys, RandomWordKeyDataVector.data() );

								//使用通过密钥派生函数的生成的数据，而不使用主密钥数据
								//Use the data generated by the key derivation function without using the master key data
								this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( RandomWordKeyDataVector );

								CheckPointer = memory_set_no_optimize_function<0x00>( SaltWordData.data(), SaltWordData.size() * sizeof( std::uint64_t ) );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( SaltData.data(), SaltData.size() );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( MaterialKeys.data(), MaterialKeys.size() );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedSecureKeys.data(), GeneratedSecureKeys.size() );
								CheckPointer = nullptr;
								GeneratedSecureKeys.clear();
								GeneratedSecureKeys.shrink_to_fit();

								ConditionControlFlag = false;
							}
							else if ( ConditionControlFlag2 == true )
							{
								std::array<std::uint8_t, 16 * sizeof( std::uint64_t )> SaltData {};
								MessageUnpacking<std::uint64_t, std::uint8_t>( SaltWordData, SaltData.data() );

								std::vector<std::uint8_t> MaterialKeys = MessageUnpacking<std::uint64_t, std::uint8_t>( RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() );
								Algorithm				  ScryptKeyDerivationFunctionObject;
								std::vector<std::uint8_t> GeneratedSecureKeys = ScryptKeyDerivationFunctionObject.GenerateKeys( MaterialKeys, SaltData, RandomWordKeyDataVector.size() * sizeof( std::uint64_t ), 1024, 8, 16 );
								MessagePacking<std::uint64_t, std::uint8_t>( GeneratedSecureKeys, RandomWordKeyDataVector.data() );

								//使用通过密钥派生函数的生成的数据，而不使用主密钥数据
								//Use the data generated by the key derivation function without using the master key data
								this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( RandomWordKeyDataVector );
								std::seed_seq Seeds = std::seed_seq( RandomWordKeyDataVector.begin(), RandomWordKeyDataVector.end() );
								MersenneTwister64Bit.seed( Seeds );

								CheckPointer = memory_set_no_optimize_function<0x00>( SaltWordData.data(), SaltWordData.size() * sizeof( std::uint64_t ) );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( SaltData.data(), SaltData.size() );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( MaterialKeys.data(), MaterialKeys.size() );
								CheckPointer = nullptr;
								CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedSecureKeys.data(), GeneratedSecureKeys.size() );
								CheckPointer = nullptr;
								GeneratedSecureKeys.clear();
								GeneratedSecureKeys.shrink_to_fit();

								ConditionControlFlag2 = false;
							}

							const std::vector<std::uint64_t> EmptyData {};
							this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( EmptyData );
						}

						++(this->RoundSubkeysCounter);
					}

					std::span<std::uint64_t> DataByteSpan { CipherText.begin() + DataBlockOffset, CipherText.begin() + DataBlockOffset + OPC_QuadWord_DataBlockSize };

					this->RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(DataByteSpan);
				}

				this->RoundSubkeysCounter = 0;
				CheckPointer = memory_set_no_optimize_function<0x00>(RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
			}

		public:

			void LaiMasseyFrameworkTest()
			{
				std::array<std::uint64_t, 2> TestDataArray { 112233445566778899ULL, 998877665544332211ULL };
				std::array<std::uint64_t, 2> TestKeyArray { 147852369369852147ULL, 987456321123654789ULL };

				this->SecureSubkeyGeneratationModuleObject.GenerationSubkeys();
				this->SecureRoundSubkeyGeneratationModuleObject.GenerationRoundSubkeys();

				auto TestDataArray2 = this->SecureRoundSubkeyGeneratationModuleObject.ForwardTransform(123456789U, 987654321U);
				TestDataArray2 = this->SecureRoundSubkeyGeneratationModuleObject.BackwardTransform(TestDataArray2[0], TestDataArray2[1]);

				TestDataArray[0] = this->LaiMasseyFramework<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(TestDataArray[0], TestKeyArray[0]);
				TestDataArray[1] = this->LaiMasseyFramework<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(TestDataArray[1], TestKeyArray[1]);
			
				TestDataArray[1] = this->LaiMasseyFramework<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(TestDataArray[1], TestKeyArray[1]);
				TestDataArray[0] = this->LaiMasseyFramework<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(TestDataArray[0], TestKeyArray[0]);

				if(TestDataArray[0] != 112233445566778899ULL || TestDataArray[1] != 998877665544332211ULL)
				{
					std::cout << "Data does not match, LaiMasseyFramework function is incorrect!" << std::endl;
				}
			}

			inline std::vector<std::uint8_t> EncrypterMain(const std::vector<std::uint8_t>& PlainText, const std::vector<std::uint8_t>& Keys)
			{
				volatile void* CheckPointer = nullptr;

				std::vector<std::uint8_t> CipherText(PlainText);
				this->PaddingData(CipherText);

				auto Word64Bit_MasterKey = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(Keys.data(), Keys.size());
				auto Word64Bit_Data = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(CipherText.data(), CipherText.size());

				CheckPointer = memory_set_no_optimize_function<0x00>(CipherText.data(), CipherText.size());
				CheckPointer = nullptr;
				CipherText.clear();
				CipherText.shrink_to_fit();

				this->SplitDataBlockToEncrypt(Word64Bit_Data, Word64Bit_MasterKey);
			
				CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_MasterKey.data(), Word64Bit_MasterKey.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
				Word64Bit_MasterKey.clear();
				Word64Bit_MasterKey.shrink_to_fit();

				CipherText = CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(Word64Bit_Data.data(), Word64Bit_Data.size());

				CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_Data.data(), Word64Bit_Data.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
				Word64Bit_Data.clear();
				Word64Bit_Data.shrink_to_fit();

				return CipherText;
			}

			inline std::vector<std::uint8_t> DecrypterMain(const std::vector<std::uint8_t>& CipherText, const std::vector<std::uint8_t>& Keys)
			{
				volatile void* CheckPointer = nullptr;

				std::vector<std::uint8_t> PlainText(CipherText);
			
				auto Word64Bit_MasterKey = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(Keys.data(), Keys.size());
				auto Word64Bit_Data = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(PlainText.data(), PlainText.size());

				CheckPointer = memory_set_no_optimize_function<0x00>(PlainText.data(), PlainText.size());
				CheckPointer = nullptr;
				PlainText.clear();
				PlainText.shrink_to_fit();

				this->SplitDataBlockToDecrypt(Word64Bit_Data, Word64Bit_MasterKey);

				CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_MasterKey.data(), Word64Bit_MasterKey.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
				Word64Bit_MasterKey.clear();
				Word64Bit_MasterKey.shrink_to_fit();

				PlainText = CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(Word64Bit_Data.data(), Word64Bit_Data.size());

				CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_Data.data(), Word64Bit_Data.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
				Word64Bit_Data.clear();
				Word64Bit_Data.shrink_to_fit();

				this->UnpaddingData(PlainText);
			
				return PlainText;
			}

			inline std::vector<std::uint8_t> EncrypterMainWithoutPadding(const std::vector<std::uint8_t>& PlainText, const std::vector<std::uint8_t>& Keys)
			{
				volatile void* CheckPointer = nullptr;

				std::vector<std::uint8_t> CipherText(PlainText);

				auto Word64Bit_MasterKey = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(Keys.data(), Keys.size());
				auto Word64Bit_Data = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(CipherText.data(), CipherText.size());

				CheckPointer = memory_set_no_optimize_function<0x00>(CipherText.data(), CipherText.size());
				CheckPointer = nullptr;
				CipherText.clear();
				CipherText.shrink_to_fit();

				this->SplitDataBlockToEncrypt(Word64Bit_Data, Word64Bit_MasterKey);
			
				CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_MasterKey.data(), Word64Bit_MasterKey.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
				Word64Bit_MasterKey.clear();
				Word64Bit_MasterKey.shrink_to_fit();

				CipherText = CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(Word64Bit_Data.data(), Word64Bit_Data.size());

				CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_Data.data(), Word64Bit_Data.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
				Word64Bit_Data.clear();
				Word64Bit_Data.shrink_to_fit();

				return CipherText;
			}

			inline std::vector<std::uint8_t> DecrypterMainWithoutUnpadding(const std::vector<std::uint8_t>& CipherText, const std::vector<std::uint8_t>& Keys)
			{
				volatile void* CheckPointer = nullptr;

				std::vector<std::uint8_t> PlainText(CipherText);
			
				auto Word64Bit_MasterKey = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(Keys.data(), Keys.size());
				auto Word64Bit_Data = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(PlainText.data(), PlainText.size());

				CheckPointer = memory_set_no_optimize_function<0x00>(PlainText.data(), PlainText.size());
				CheckPointer = nullptr;
				PlainText.clear();
				PlainText.shrink_to_fit();

				this->SplitDataBlockToDecrypt(Word64Bit_Data, Word64Bit_MasterKey);

				CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_MasterKey.data(), Word64Bit_MasterKey.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
				Word64Bit_MasterKey.clear();
				Word64Bit_MasterKey.shrink_to_fit();

				PlainText = CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(Word64Bit_Data.data(), Word64Bit_Data.size());

				CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_Data.data(), Word64Bit_Data.size() * sizeof(std::uint64_t));
				CheckPointer = nullptr;
				Word64Bit_Data.clear();
				Word64Bit_Data.shrink_to_fit();
			
				return PlainText;
			}

			explicit StateData_Worker
			(
				ImplementationDetails::CommonStateData<OPC_QuadWord_DataBlockSize, OPC_QuadWord_KeyBlockSize>& CommonStateDataObject
			)
				:
				CommonStateDataPointerObject(CommonStateDataObject),
				SecureSubkeyGeneratationModuleObject(CommonStateDataObject),
				SecureRoundSubkeyGeneratationModuleObject(CommonStateDataObject)
			{
				
			}

			~StateData_Worker() = default;
		};
	}

} // namespace Cryptograph
