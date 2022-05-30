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

namespace CommonSecurity::Blake2
{

	/*
	
		BLAKE is a cryptographic hash function based on Daniel J. Bernstein's ChaCha stream cipher, but a permuted copy of the input block, XOR-ed with round constants, is added before each ChaCha round. Like SHA-2, there are two variants differing in the word size.
		ChaCha operates on a 4×4 array of words.
		BLAKE repeatedly combines an 8-word hash value with 16 message words, truncating the ChaCha result to obtain the next hash value.
		BLAKE-256 and BLAKE-224 use 32-bit words and produce digest sizes of 256 bits and 224 bits, respectively, while BLAKE-512 and BLAKE-384 use 64-bit words and produce digest sizes of 512 bits and 384 bits, respectively.

		The BLAKE2 hash function, based on BLAKE, was announced in 2012. The BLAKE3 hash function, based on BLAKE2, was announced in 2020.

		BLAKE是一个基于Daniel J. Bernstein的ChaCha流密码的加密散列函数，但在每一轮ChaCha之前，会添加一个输入块的混合副本，与轮回常数进行XOR。与SHA-2一样，有两种不同的字大小的变体。
		ChaCha在一个4×4的字阵列上操作。
		BLAKE重复地将一个8个字的哈希值与16个信息字相结合，截断ChaCha的结果以获得下一个哈希值。
		BLAKE-256和BLAKE-224使用32位字，产生的摘要大小分别为256比特和224比特，而BLAKE-512和BLAKE-384使用64位字，产生的摘要大小分别为512比特和384比特。

		基于BLAKE的BLAKE2散列函数于2012年公布。基于BLAKE2的BLAKE3哈希函数于2020年宣布。

		BLAKE2 is a cryptographic hash function based on BLAKE, created by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein. The design goal was to replace the widely used, but broken, MD5 and SHA-1 algorithms in applications requiring high performance in software.
		BLAKE2 was announced on December 21, 2012.
		A reference implementation is available under CC0, the OpenSSL License, and the Apache Public License 2.0.
		BLAKE2b is faster than MD5, SHA-1, SHA-2, and SHA-3, on 64-bit x86-64 and ARM architectures.
		BLAKE2 provides better security than SHA-2 and similar to that of SHA-3: immunity to length extension, indifferentiability from a random oracle, etc.
		BLAKE2 removes addition of constants to message words from BLAKE round function, changes two rotation constants, simplifies padding, adds parameter block that is XOR'ed with initialization vectors, and reduces the number of rounds from 16 to 12 for BLAKE2b (successor of BLAKE-512), and from 14 to 10 for BLAKE2s (successor of BLAKE-256).

		BLAKE2 supports keying, salting, personalization, and hash tree modes, and can output digests from 1 up to 64 bytes for BLAKE2b, or up to 32 bytes for BLAKE2s.
		There are also parallel versions designed for increased performance on multi-core processors; BLAKE2bp (4-way parallel) and BLAKE2sp (8-way parallel).
		BLAKE2X is a family of extensible-output functions (XOFs).
		Whereas BLAKE2 is limited to 64-byte digests, BLAKE2X allows for digests of up to 256 GiB. 
		BLAKE2X is itself not an instance of a hash function, and must be based on an actual BLAKE2 instance.
		An example of a BLAKE2X instance could be BLAKE2Xb16MiB, which would be a BLAKE2X version based on BLAKE2b producing 16,777,216-byte digests (or exactly 16 MiB, hence the name of such an instance).
		BLAKE2b and BLAKE2s are specified in RFC 7693. Optional features using the parameter block (salting, personalized hashes, tree hashing, et cetera), are not specified, and thus neither is support for BLAKE2bp, BLAKE2sp, or BLAKE2X.
		BLAKE2sp is the BLAKE2 version used by 7zip file compressor signature in context menu "CRC SHA"


		BLAKE2是一个基于BLAKE的加密哈希函数，由Jean-Philippe Aumasson、Samuel Neves、Zooko Wilcox-O'Hearn和Christian Winnerlein创建。其设计目标是在需要高性能的软件应用中取代广泛使用但已损坏的MD5和SHA-1算法。
		BLAKE2于2012年12月21日公布。
		在CC0、OpenSSL许可证和Apache公共许可证2.0下有一个参考实现。
		BLAKE2b在64位x86-64和ARM架构上比MD5、SHA-1、SHA-2和SHA-3都快。
		BLAKE2提供了比SHA-2更好的安全性，并与SHA-3相似：对长度扩展的免疫力，对随机神谕的不可控性等。
		BLAKE2从BLAKE轮函数中删除了对消息字的添加常数，改变了两个旋转常数，简化了填充，增加了与初始化向量XOR的参数块，并将BLAKE2b（BLAKE-512的继承者）的轮数从16个减少到12个，BLAKE2s（BLAKE-256的继承者）从14个减少到10个。

		BLAKE2支持加密钥、加盐、个性化和哈希树模式，对于BLAKE2b可以输出从1到64字节的摘要，对于BLAKE2s可以输出到32字节的摘要。
		还有为提高多核处理器性能而设计的并行版本；BLAKE2bp（4路并行）和BLAKE2sp（8路并行）。
		BLAKE2X是一个可扩展输出函数（XOFs）系列。
		BLAKE2仅限于64字节的摘要，而BLAKE2X允许高达256GiB的摘要。 
		BLAKE2X本身不是一个哈希函数的实例，它必须基于一个实际的BLAKE2实例。
		一个BLAKE2X实例的例子是BLAKE2Xb16MiB，这将是一个基于BLAKE2b的BLAKE2X版本，产生16,777,216字节的摘要（或正好是16 MiB，因此这样的实例的名字）。
		BLAKE2b和BLAKE2s在RFC 7693中被指定。使用参数块的可选功能（加盐、个性化散列、树形散列等）没有被指定，因此也不支持BLAKE2bp、BLAKE2sp或BLAKE2X。
		BLAKE2sp是7zip文件压缩器签名在上下文菜单 "CRC SHA "中使用的BLAKE2版本。
	*/

	namespace Core
	{
		using WordType = std::conditional_t<CURRENT_SYSTEM_BITS == 32, CommonToolkit::FourByte, CommonToolkit::EightByte>;

		enum class HashModeType
		{
			Ordinary = 0,
			Extension = 1,
			ExtensionAndOuput = 2
		};

		//For each round of hashing execution, the permute table of the message data index
		//对于每一轮散列的执行，信息数据索引的permute表
		inline constexpr std::array<std::array<CommonToolkit::FourByte, 16>, 12> SIGMA_VECTOR
		{
			{
				{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
				{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
				{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
				{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
				{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
				{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
				{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
				{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
				{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
				{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
				{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
				{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
			},
		};

		template<typename Type>
		struct HashConstants;

		template<>
		struct HashConstants<CommonToolkit::EightByte>
		{
			static constexpr std::array<CommonToolkit::EightByte, 8> INITIAL_VECTOR
			{
				0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
				0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6BULL, 0x5be0cd19137e2179ULL
			};
		};
		

		template<>
		struct HashConstants<CommonToolkit::FourByte>
		{
			static constexpr std::array<CommonToolkit::FourByte, 8> INITIAL_VECTOR
			{
				0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
				0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
			};
		};

		namespace Functions
		{
			template<typename Type> requires std::same_as<Type, WordType>
			using ThisWordArray16Type = std::array<Type, 16>;

			/*
				The G primitive function mixes two input words, "x" and "y", into four words indexed by "a", "b", "c", and "d" in the working vector working_vector[0..15].
				The full modified vector is returned.
			*/
			static inline void HashValueMixer(std::size_t RoundNumber, std::size_t SigmaVectorIndex, WordType& ValueA, WordType& ValueB, WordType& ValueC, WordType& ValueD, const ThisWordArray16Type<WordType>& Message)
			{
				if constexpr(CURRENT_SYSTEM_BITS == 64)
				{
					ValueA = ValueA + ValueB + Message[SIGMA_VECTOR[RoundNumber][2 * SigmaVectorIndex]];
					ValueD = CommonSecurity::Binary_RightRotateMove<WordType>(ValueD ^ ValueA, 32);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove<WordType>(ValueB ^ ValueC, 24);

					ValueA = ValueA + ValueB + Message[SIGMA_VECTOR[RoundNumber][2 * SigmaVectorIndex + 1]];
					ValueD = CommonSecurity::Binary_RightRotateMove<WordType>(ValueD ^ ValueA, 16);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove<WordType>(ValueB ^ ValueC, 63);
				}
				else
				{
					ValueA = ValueA + ValueB + Message[SIGMA_VECTOR[RoundNumber][2 * SigmaVectorIndex]];
					ValueD = CommonSecurity::Binary_RightRotateMove<WordType>(ValueD ^ ValueA, 16);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove<WordType>(ValueB ^ ValueC, 12);

					ValueA = ValueA + ValueB + Message[SIGMA_VECTOR[RoundNumber][2 * SigmaVectorIndex + 1]];
					ValueD = CommonSecurity::Binary_RightRotateMove<WordType>(ValueD ^ ValueA, 8);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove<WordType>(ValueB ^ ValueC, 7);
				}
			}

			/*
				//Message word selection permutation for this round.
				s[0..15] := SIGMA_VECTOR[index modulo 10][0..15]
			*/
			static inline void HashValueRound(std::size_t RoundNumber, const ThisWordArray16Type<WordType>& Message, ThisWordArray16Type<WordType>& CurrentInitialVector)
			{
				auto&
				[
					StateValue, StateValue2, StateValue3, StateValue4,
					StateValue5, StateValue6, StateValue7, StateValue8,
					StateValue9, StateValue10, StateValue11, StateValue12,
					StateValue13, StateValue14, StateValue15, StateValue16
				] = CurrentInitialVector;

				// For the current state of the round mix transformation data applied to the row
				// 对于当前状态的轮变换数据应用到行

				HashValueMixer(RoundNumber, 0, StateValue, StateValue5, StateValue9, StateValue13, Message);
				HashValueMixer(RoundNumber, 1, StateValue2, StateValue6, StateValue10, StateValue14, Message);
				HashValueMixer(RoundNumber, 2, StateValue3, StateValue7, StateValue11, StateValue15, Message);
				HashValueMixer(RoundNumber, 3, StateValue4, StateValue8, StateValue12, StateValue16, Message);

				// For the current state of the round mix transformation data applied to the diagonal
				// 对于当前状态的轮变换数据应用到对角线

				HashValueMixer(RoundNumber, 4, StateValue, StateValue6, StateValue11, StateValue16, Message);
				HashValueMixer(RoundNumber, 5, StateValue2, StateValue7, StateValue12, StateValue13, Message);
				HashValueMixer(RoundNumber, 6, StateValue3, StateValue8, StateValue9, StateValue14, Message);
				HashValueMixer(RoundNumber, 7, StateValue4, StateValue5, StateValue10, StateValue15, Message);
			}

			inline WordType LookupInitialVectorValue(std::size_t index)
			{
				return HashConstants<WordType>::INITIAL_VECTOR[index];
			}

			inline void AssignHashStateArrayData(std::array<WordType, 8>& HashStateArray)
			{
				if constexpr(CURRENT_SYSTEM_BITS == 64)
				{
					std::memcpy(HashStateArray.data(), HashConstants<WordType>::INITIAL_VECTOR.data(), 64);
					HashStateArray[0] ^= 0x0000000001010000ULL;
				}
				else
				{
					std::memcpy(HashStateArray.data(), HashConstants<WordType>::INITIAL_VECTOR.data(), 32);
					HashStateArray[0] ^= 0x01010000U;
				}
			}

			inline void ExtensionHashStateArrayData(std::array<WordType, 8>& HashStateArray, std::size_t LeftHashSize, std::size_t ProcessedMessageSize, std::size_t ExtensionOffset, std::size_t RightHashSize)
			{
				if constexpr(CURRENT_SYSTEM_BITS == 64)
				{
					std::memcpy(HashStateArray.data(), HashConstants<WordType>::INITIAL_VECTOR.data(), 64);
					HashStateArray[0] ^= std::min(LeftHashSize - ProcessedMessageSize, static_cast<size_t>(64));
					HashStateArray[0] ^= 0x0000004000000000ULL;
					HashStateArray[1] ^= ExtensionOffset;
					HashStateArray[1] ^= RightHashSize << 32;
					HashStateArray[2] ^= 0x0000000000004000ULL;
				}
				else
				{
					std::memcpy(HashStateArray.data(), HashConstants<WordType>::INITIAL_VECTOR.data(), 32);
					HashStateArray[0] ^= std::min(LeftHashSize - ProcessedMessageSize, static_cast<size_t>(32));
					HashStateArray[1] ^= 0x00000020U;
					HashStateArray[2] ^= ExtensionOffset;
					HashStateArray[3] ^= 0x20000000U;
					HashStateArray[3] ^= static_cast<CommonToolkit::TwoByte>(RightHashSize);
				}
			}
		}

	}

	template<Core::HashModeType ModeType>
	class HashProvider : public CommonSecurity::HashProviderBaseTools::InterfaceHashProvider
	{

	private:
		std::array<Core::WordType, 8> _HashStateArrayData;
		static constexpr std::size_t HASH_BIT_SIZE = CURRENT_SYSTEM_BITS == 64 
			? 512 
			: 256;
		static constexpr std::size_t HASH_SALT_PERSONALZTION_BYTE_SIZE = HASH_BIT_SIZE / 32;
		std::array<CommonToolkit::OneByte, HASH_BIT_SIZE / 4> _BufferMessageMemory;
		std::array<Core::WordType, 2> _HashSaltValueArray;
		std::array<Core::WordType, 2> _HashPersonalizationValueArray;
		std::string _OriginKey;
		std::size_t _byte_position;
		CommonToolkit::EightByte _total_bit;
		std::size_t _hash_size;
		std::size_t _extension_offset;
		bool _whether_compressing;

		inline void absorb_key()
		{
			if(_OriginKey.empty())
			{
				return;
			}
			else
			{
				std::array<CommonToolkit::OneByte, HASH_BIT_SIZE / 4> _HashKey;
				std::memcpy(_HashKey.data(), _OriginKey.data(), _OriginKey.size());
				if(_OriginKey.size() != HASH_BIT_SIZE / 4)
					std::memset(_HashKey.data() + _OriginKey.size(), 0, HASH_BIT_SIZE / 4 - _OriginKey.size());
				this->StepUpdate( _HashKey );
			}
		}

		inline void hash_transform( const CommonToolkit::OneByte* data, size_t data_number_blocks, bool whether_padding )
		{
			//Local message block vector (last block is padded with zeros to full block size, if required)
			std::array<Core::WordType, 16> TemporaryMessages = std::array<Core::WordType, 16>();

			//Local work vector used in processing
			std::array<Core::WordType, 16> TemporaryHashStateBlockVector = std::array<Core::WordType, 16>();

			for(std::size_t data_block_index = 0; data_block_index < data_number_blocks; ++data_block_index)
			{
				for(std::size_t OriginMessageIndex = 0; OriginMessageIndex < 16; ++OriginMessageIndex)
				{
					Core::WordType DataWord = std::bit_cast<const Core::WordType*>(data)[data_block_index * 16 + OriginMessageIndex];

					if constexpr(std::endian::native != std::endian::little)
					{
						DataWord = CommonToolkit::ByteSwap::byteswap(DataWord);
					}

					TemporaryMessages[OriginMessageIndex] = DataWord;
				}

				CommonToolkit::EightByte TotalBytes = _total_bit / 8 + ( whether_padding ? 0 : ( data_block_index + 1 ) * HASH_BIT_SIZE ) / 4;

				//2 word-bit offset counter
				Core::WordType WordBitOffsetCounter_VaribaleT = static_cast<Core::WordType>(TotalBytes);
				Core::WordType WordBitOffsetCounter_VaribaleT2 = HASH_BIT_SIZE == 512 
					? 0 
					: static_cast<Core::WordType>(TotalBytes >> 32);

				//final block indicator flag
				Core::WordType FinalBlockIndicatorFlag_VaribaleF = 0, FinalBlockIndicatorFlag_VaribaleF2 = 0;

				if(whether_padding)
				{
					FinalBlockIndicatorFlag_VaribaleF = static_cast<Core::WordType>(-1);
					FinalBlockIndicatorFlag_VaribaleF2 = 0;
				}

				/*
				
					// First half from state.
					work_vector[0..7] := hash_state[0..7]

					// Second half from IV.
					work_vector[8..15] := InitialVector[0..7]

				*/
				std::memcpy(TemporaryHashStateBlockVector.data(), _HashStateArrayData.data(), sizeof(Core::WordType) * 8);
				for(std::size_t index = 0; index < 4; ++index)
				{
					TemporaryHashStateBlockVector[8 + index] = Core::Functions::LookupInitialVectorValue(index);
				}

				//A collection of temporary word bit offset counter and block indicator flag states
				std::array<Core::WordType, 4> TemporaryCollection { WordBitOffsetCounter_VaribaleT, WordBitOffsetCounter_VaribaleT2, FinalBlockIndicatorFlag_VaribaleF, FinalBlockIndicatorFlag_VaribaleF2 };

				/*
				
					// Low word of the offset.
					work_vector[12] := work_vector[12] ^ (t modulo power(2, word_size))

					// High word.
					work_vector[13] := work_vector[13] ^ (t >> word_size)
				*/
				for(std::size_t index = 4, index2 = 0; index < 8 && index2 < 4; ++index, ++index2)
				{
					TemporaryHashStateBlockVector[8 + index] = TemporaryCollection[index2] ^ Core::Functions::LookupInitialVectorValue(index);
				}

				std::memset(TemporaryCollection.data(), 0, TemporaryCollection.size());

				//Cryptographic hash value state mixing
				//The number of rounds (12 for BLAKE2b and 10 for BLAKE2s)
				if constexpr(HASH_BIT_SIZE == 512)
				{
					for(std::size_t rounds_number = 0; rounds_number < 12; ++rounds_number)
					{
						Core::Functions::HashValueRound(rounds_number, TemporaryMessages, TemporaryHashStateBlockVector);
					}
				}
				else
				{
					for(std::size_t rounds_number = 0; rounds_number < 10; ++rounds_number)
					{
						Core::Functions::HashValueRound(rounds_number, TemporaryMessages, TemporaryHashStateBlockVector);
					}
				}

				//ExclusiveOR the two halves
				for(std::size_t index = 0; index < 4; ++index)
				{
					_HashStateArrayData[index] = _HashStateArrayData[index] ^ TemporaryHashStateBlockVector[index] ^ TemporaryHashStateBlockVector[index + 8];
					_HashStateArrayData[index + 4] = _HashStateArrayData[index + 4] ^ TemporaryHashStateBlockVector[index + 4] ^ TemporaryHashStateBlockVector[index + 8 + 4];
				}
			}
		}

	public:
		//Is extendable-output function
		static const bool is_Extendable_OF = ModeType == Core::HashModeType::ExtensionAndOuput;

		inline void UpdateStringKey(const std::string& Key)
		{
			if( Key.size() > HASH_BIT_SIZE / 8 )
			{
				std::cout << "The string key you given is an invalid size!" << std::endl;
				return;
			}
			_OriginKey = std::move(Key);
		}

		inline void UpdateSaltBytes(const std::span<std::uint8_t>& SaltBytes)
		{
			if(SaltBytes.size() != 0 && SaltBytes.size() != HASH_SALT_PERSONALZTION_BYTE_SIZE)
			{
				std::cout << "The string salt bytes you given is an invalid size!" << std::endl;
				return;
			}
			
			//std::memcpy(_HashSaltValueArray.data(), Key.data(), Key.size());

			if constexpr(CURRENT_SYSTEM_BITS == 32)
				CommonToolkit::BitConverters::le32_copy(SaltBytes.data(), 0, _HashSaltValueArray.data(), 0, SaltBytes.size());
			else
				CommonToolkit::BitConverters::le64_copy(SaltBytes.data(), 0, _HashSaltValueArray.data(), 0, SaltBytes.size());
		}

		inline void UpdatePersonalizationBytes(const std::span<std::uint8_t> PersonalizationBytes)
		{
			if(PersonalizationBytes.size() != 0 && PersonalizationBytes.size() != HASH_SALT_PERSONALZTION_BYTE_SIZE)
			{
				std::cout << "The string personalization bytes you given is an invalid size!" << std::endl;
				return;
			}

			//std::memcpy(_HashPersonalizationValueArray.data(), PersonalizationBytes, PersonalizationBytesSize);

			if constexpr(CURRENT_SYSTEM_BITS == 32)
				CommonToolkit::BitConverters::le32_copy(PersonalizationBytes.data(), 0, _HashPersonalizationValueArray.data(), 0, PersonalizationBytes.size());
			else
				CommonToolkit::BitConverters::le64_copy(PersonalizationBytes.data(), 0, _HashPersonalizationValueArray.data(), 0, PersonalizationBytes.size());
		}

		inline void ComprssionHashData(std::uint8_t* hash_array, std::size_t hash_byte_size)
		{
			std::size_t ProcessedMessageByteSize = 0;
			if(_whether_compressing == false)
			{
				if constexpr( ModeType == Core::HashModeType::ExtensionAndOuput )
				{
					_total_bit += _byte_position * 8;
				}
				_whether_compressing = true;
				_extension_offset = 0;
				if( HASH_BIT_SIZE / 4 != _byte_position)
				{
					std::memset( std::addressof(_BufferMessageMemory[_byte_position]), 0, HASH_BIT_SIZE / 4 - _byte_position );
				}
				this->hash_transform( _BufferMessageMemory.data(), 1, true );
				
				//std::memcpy( _BufferMessageMemory.data(), _HashStateArrayData.data(), HASH_BIT_SIZE / 8 );

				if constexpr(CURRENT_SYSTEM_BITS == 32)
					CommonToolkit::BitConverters::le32_copy(_HashStateArrayData.data(), 0, _BufferMessageMemory.data(), 0, HASH_BIT_SIZE / 8);
				else
					CommonToolkit::BitConverters::le64_copy(_HashStateArrayData.data(), 0, _BufferMessageMemory.data(), 0, HASH_BIT_SIZE / 8);
			}
			else if( _byte_position < HASH_BIT_SIZE / 8 )
			{
				std::size_t CopySize = std::min(_hash_size, HASH_BIT_SIZE / 8 - _byte_position);

				//std::memcpy( hash_array, reinterpret_cast<std::uint8_t*>( _HashStateArrayData.data()) + _byte_position, CopySize	);

				if constexpr(CURRENT_SYSTEM_BITS == 32)
					CommonToolkit::BitConverters::le32_copy(_HashStateArrayData.data(), _byte_position, hash_array, 0, CopySize);
				else
					CommonToolkit::BitConverters::le64_copy(_HashStateArrayData.data(), _byte_position, hash_array, 0, CopySize);
				
				ProcessedMessageByteSize += CopySize;
				_byte_position += CopySize;
			}

			Core::WordType RightHashSize = static_cast<Core::WordType>( _hash_size );
			if constexpr(ModeType == Core::HashModeType::ExtensionAndOuput)
			{
				RightHashSize = static_cast<Core::WordType>( -1 );
			}

			while ( ProcessedMessageByteSize < hash_byte_size )
			{
				Core::Functions::ExtensionHashStateArrayData( _HashStateArrayData, _hash_size, ProcessedMessageByteSize, ++_extension_offset, RightHashSize );
				
				_HashStateArrayData[4] ^= _HashSaltValueArray[0];
				_HashStateArrayData[5] ^= _HashSaltValueArray[1];

				_HashStateArrayData[6] ^= _HashPersonalizationValueArray[0];
				_HashStateArrayData[7] ^= _HashPersonalizationValueArray[1];

				_total_bit = HASH_BIT_SIZE;

				std::memset( std::addressof(_BufferMessageMemory[HASH_BIT_SIZE / 8]), 0, _BufferMessageMemory.size() - HASH_BIT_SIZE / 8 );
				this->hash_transform( _BufferMessageMemory.data(), 1, true );
				_byte_position = std::min( hash_byte_size - ProcessedMessageByteSize, HASH_BIT_SIZE / 8 );

				//std::memcpy( hash_array + ProcessedMessageSize, _HashStateArrayData.data(), _byte_position );

				if constexpr(CURRENT_SYSTEM_BITS == 32)
					CommonToolkit::BitConverters::le32_copy(_HashStateArrayData.data(), 0, hash_array, ProcessedMessageByteSize, _byte_position);
				else
					CommonToolkit::BitConverters::le64_copy(_HashStateArrayData.data(), 0, hash_array, ProcessedMessageByteSize, _byte_position);

				ProcessedMessageByteSize += _byte_position;
			}
		}

		inline void StepInitialize() override
		{
			_byte_position = 0;
			_total_bit = 0;
			_extension_offset = 0;
			_whether_compressing = false;

			Core::Functions::AssignHashStateArrayData(_HashStateArrayData);

			if constexpr(ModeType == CommonSecurity::Blake2::Core::HashModeType::Ordinary)
			{
				_HashStateArrayData[0] ^= _hash_size / 8;
			}
			else
			{
				_HashStateArrayData[0] ^= HASH_BIT_SIZE / 8;
				Core::WordType RightHashSize = ModeType == CommonSecurity::Blake2::Core::HashModeType::Extension 
					? static_cast<Core::WordType>( _hash_size / 8 ) 
					: ( static_cast<Core::WordType>( -1 ) >> static_cast<Core::WordType>(sizeof(Core::WordType) * 4) );

				if constexpr(HASH_BIT_SIZE == 512)
					_HashStateArrayData[1] ^= (RightHashSize << ( HASH_BIT_SIZE / 16 ));
				else
					_HashStateArrayData[3] ^= RightHashSize;

				_HashStateArrayData[0] ^= ( _OriginKey.size() << 8 );
				_HashStateArrayData[4] ^= _HashSaltValueArray[0];
				_HashStateArrayData[5] ^= _HashSaltValueArray[1];
				_HashStateArrayData[6] ^= _HashPersonalizationValueArray[0];
				_HashStateArrayData[7] ^= _HashPersonalizationValueArray[1];

				this->absorb_key();
			}
		}

		inline void StepUpdate( const std::span<const std::uint8_t> data_value_vector ) override
		{
			const auto* data_pointer = data_value_vector.data();
			auto data_size = data_value_vector.size();

			if(data_pointer == nullptr)
				return;

			auto lambda_Transform = [ this ]( const std::uint8_t* data, std::size_t data_size )
			{
				this->hash_transform( data, data_size, false );
			};

			HashProviderBaseTools::absorb_bytes( data_pointer, data_size, HASH_BIT_SIZE / 4, HASH_BIT_SIZE / 4, _BufferMessageMemory.data(), _byte_position, _total_bit, lambda_Transform );
		}

		inline void StepFinal( std::span<std::uint8_t> hash_value_vector ) override
		{
			if(hash_value_vector.data() == nullptr)
				return;

			_total_bit += _byte_position * 8;
			if constexpr(ModeType == CommonSecurity::Blake2::Core::HashModeType::Ordinary)
			{
				if (HASH_BIT_SIZE / 4 != _byte_position)
					std::memset( std::addressof(_BufferMessageMemory[_byte_position]), 0, HASH_BIT_SIZE / 4 - _byte_position );
				this->hash_transform( _BufferMessageMemory.data(), 1, true);

				//std::memcpy( hash_value_vector.data(), _HashStateArrayData.data(), _hash_size / 8 );

				if constexpr(CURRENT_SYSTEM_BITS == 32)
					CommonToolkit::BitConverters::le32_copy(_HashStateArrayData.data(), 0, hash_value_vector.data(), 0, _hash_size / 8);
				else
					CommonToolkit::BitConverters::le64_copy(_HashStateArrayData.data(), 0, hash_value_vector.data(), 0, _hash_size / 8);
			}
			else
				this->ComprssionHashData(hash_value_vector.data(), _hash_size / 8);

			StepInitialize();
		}

		inline std::size_t HashSize() const override
		{
			return _hash_size;
		}

		inline void Clear() override
		{
			HashProviderBaseTools::zero_memory(_HashStateArrayData);
			HashProviderBaseTools::zero_memory(_BufferMessageMemory);
			HashProviderBaseTools::zero_memory(_OriginKey);
			HashProviderBaseTools::zero_memory(_HashSaltValueArray);
			HashProviderBaseTools::zero_memory(_HashPersonalizationValueArray);
		}

		HashProvider( std::size_t hashsize ) : _hash_size( hashsize ), _whether_compressing(false)
		{
			switch (ModeType)
			{
				case CommonSecurity::Blake2::Core::HashModeType::Ordinary:
					HashProviderBaseTools::HashSize::validate( hashsize, HASH_BIT_SIZE );
					break;
				case CommonSecurity::Blake2::Core::HashModeType::Extension:
					HashProviderBaseTools::HashSize::validate( hashsize, HASH_BIT_SIZE * sizeof(Core::WordType) * 4 - 16 );
					break;
				case CommonSecurity::Blake2::Core::HashModeType::ExtensionAndOuput:
					break;
				default:
					break;
			}
			
			HashProviderBaseTools::zero_memory(_HashSaltValueArray);
			HashProviderBaseTools::zero_memory(_HashPersonalizationValueArray);
		}

		~HashProvider()
		{
			this->Clear();
		}

		HashProvider() = delete;
	};
}