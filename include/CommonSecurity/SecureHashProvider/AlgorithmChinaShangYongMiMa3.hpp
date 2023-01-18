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

namespace CommonSecurity::ChinaShangYongMiMa3
{
	/*
		SM3 is a cryptographic hash function used in the Chinese National Standard.
		It was published by the National Cryptography Administration (Chinese: 国家密码管理局) on 2010-12-17 as "GM/T 0004-2012: SM3 cryptographic hash algorithm".
		SM3 is mainly used in digital signatures, message authentication codes, and pseudorandom number generators. 
		The algorithm is public and is considered similar to SHA-256 in security and efficiency.

		SM3是中华人民共和国政府采用的一种密码散列函数标准，前身为SCH4杂凑算法，由国家密码管理局于2010年12月17日发布，相关标准为“GM/T 0004-2012 《SM3密码杂凑算法》”。
		2016年，成为中国国家密码标准（GB/T 32905-2016。
		在商用密码体系中，SM3主要用于数字签名及验证、消息认证码生成及验证、随机数生成等，其算法公开，安全性及效率与SHA-256相当。
	*/

	namespace Core
	{
		static inline CommonToolkit::FourByte exclusiveOR_Multi(CommonToolkit::FourByte a, CommonToolkit::FourByte b, CommonToolkit::FourByte c)
		{
			return a ^ b ^ c;
		}

		static inline CommonToolkit::FourByte ff_ChinaVersionHashCodeMajority(CommonToolkit::FourByte a, CommonToolkit::FourByte b, CommonToolkit::FourByte c)
		{
			return (a & b) ^ (a & c) ^ (b & c);
		}

		static inline CommonToolkit::FourByte gg_ChinaVersionChooseHashCode(CommonToolkit::FourByte a, CommonToolkit::FourByte b, CommonToolkit::FourByte c)
		{
			return (a & b) ^ (~a & c);
		}

		static inline CommonToolkit::FourByte p0_ChinaVersionHashCode(CommonToolkit::FourByte HashCode)
		{
			return HashCode ^ CommonSecurity::Binary_LeftRotateMove(HashCode, static_cast<CommonToolkit::FourByte>(9)) ^ CommonSecurity::Binary_LeftRotateMove(HashCode, static_cast<CommonToolkit::FourByte>(17));
		}

		static inline CommonToolkit::FourByte p1_ChinaVersionHashCode(CommonToolkit::FourByte HashCode)
		{
			return HashCode ^ CommonSecurity::Binary_LeftRotateMove(HashCode, static_cast<CommonToolkit::FourByte>(15)) ^ CommonSecurity::Binary_LeftRotateMove(HashCode, static_cast<CommonToolkit::FourByte>(23));
		}
	}

	class HashProvider : public CommonSecurity::HashProviderBaseTools::InterfaceHashProvider
	{
		
	private:
		std::array<CommonToolkit::FourByte, 8> _HashStateArrayData;
		std::array<CommonToolkit::OneByte, 64> _BufferMessageMemory;
		std::size_t _byte_position;
		CommonToolkit::EightByte _total_bit;

		inline void hash_transform( const CommonToolkit::OneByte* data, std::size_t data_number_blocks )
		{
			for(std::size_t data_block_index = 0; data_block_index < data_number_blocks; ++data_block_index)
			{
				//Step 0: Adaptation of data storage methods for big or little endian
				//第0步: 数据存储方式的大或小端序适配

				std::array<CommonToolkit::FourByte, 16> OriginMessageArray = std::array<CommonToolkit::FourByte, 16>();
				for (std::size_t OriginMessageIndex = 0; OriginMessageIndex < 64 / 4; ++OriginMessageIndex)
				{
					CommonToolkit::FourByte DataWord = std::bit_cast<const CommonToolkit::FourByte*>(data)[data_block_index * 16 + OriginMessageIndex];

					if constexpr(std::endian::native == std::endian::big)
					{
						OriginMessageArray[OriginMessageIndex] = DataWord;
					}
					else
					{
						OriginMessageArray[OriginMessageIndex] = CommonToolkit::ByteSwap::byteswap(DataWord);
					}
				}

				//Step 1: Expansion of message data blocks
				//第1步: 消息数据块的扩展

				std::array<CommonToolkit::FourByte, 68> HashWordStateArray {};
				std::array<CommonToolkit::FourByte, 64> HashWordStateArray2 {};

				for(std::size_t index = 0; index <= 15; ++index)
					HashWordStateArray[index] = OriginMessageArray[index];

				for(std::size_t index = 16; index <= 67; ++index)
				{
					CommonToolkit::FourByte HashValue0 = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashWordStateArray[index - 3], 15);
					CommonToolkit::FourByte HashValue1 = HashWordStateArray[index - 16] ^ HashWordStateArray[index - 9] ^ HashValue0;
					CommonToolkit::FourByte HashValue2 = Core::p1_ChinaVersionHashCode( HashValue1 );
					CommonToolkit::FourByte HashValue3 = HashValue2 ^ CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashWordStateArray[index - 13], 7);
					CommonToolkit::FourByte HashValue4 = HashValue3 ^ HashWordStateArray[index - 6];
					HashWordStateArray[index] = HashValue4;
				}

				for(std::size_t index = 0; index <= 63; ++index)
					HashWordStateArray2[index] = HashWordStateArray[index] ^ HashWordStateArray[index + 4];

				//Step 2: Apply compression functions to message data
				//第2步: 对消息数据应用压缩函数

				auto
				[
					HashValueA, HashValueB, HashValueC, HashValueD,
					HashValueE, HashValueF, HashValueG, HashValueH
				] = _HashStateArrayData;

				for(std::size_t index = 0; index <= 15; ++index)
				{
					CommonToolkit::FourByte HashValue5 = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValueA, 12) + HashValueE + CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(0x79cc4519U, index);
					
					//Paper Variables SS1
					CommonToolkit::FourByte HashValue6 = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValue5, 7);
					
					//Paper Variables SS2
					CommonToolkit::FourByte HashValue7 = HashValue6 ^ CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValueA, 12);
					
					//Paper Variables TT1
					CommonToolkit::FourByte HashValue8 = Core::exclusiveOR_Multi(HashValueA, HashValueB, HashValueC) + HashValueD + HashValue7 + HashWordStateArray2[index];
					
					//Paper Variables TT2
					CommonToolkit::FourByte HashValue9 = Core::exclusiveOR_Multi(HashValueE, HashValueF, HashValueG) + HashValueH + HashValue6 + HashWordStateArray[index];

					HashValueD = HashValueC;
					HashValueC = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValueB, 9);
					HashValueB = HashValueA;
					HashValueA = HashValue8;
					HashValueH = HashValueG;
					HashValueG = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValueF, 19);
					HashValueF = HashValueE;
					HashValueE = Core::p0_ChinaVersionHashCode(HashValue9);
				}

				for(std::size_t index = 16; index <= 63; ++index)
				{
					CommonToolkit::FourByte HashValue5 = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValueA, 12) + HashValueE + CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(0x7a879d8aU, index);
					
					//Paper Variables SS1
					CommonToolkit::FourByte HashValue6 = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValue5, 7);
					
					//Paper Variables SS2
					CommonToolkit::FourByte HashValue7 = HashValue6 ^ CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValueA, 12);
					
					//Paper Variables TT1
					CommonToolkit::FourByte HashValue8 = Core::ff_ChinaVersionHashCodeMajority(HashValueA, HashValueB, HashValueC) + HashValueD + HashValue7 + HashWordStateArray2[index];
					
					//Paper Variables TT2
					CommonToolkit::FourByte HashValue9 = Core::gg_ChinaVersionChooseHashCode(HashValueE, HashValueF, HashValueG) + HashValueH + HashValue6 + HashWordStateArray[index];

					HashValueD = HashValueC;
					HashValueC = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValueB, 9);
					HashValueB = HashValueA;
					HashValueA = HashValue8;
					HashValueH = HashValueG;
					HashValueG = CommonSecurity::Binary_LeftRotateMove<CommonToolkit::FourByte>(HashValueF, 19);
					HashValueF = HashValueE;
					HashValueE = Core::p0_ChinaVersionHashCode(HashValue9);
				}

				//Step 3: Update the hash state array
				//第3步: 更新哈希状态数组

				_HashStateArrayData[0] ^= HashValueA;
				_HashStateArrayData[1] ^= HashValueB;
				_HashStateArrayData[2] ^= HashValueC;
				_HashStateArrayData[3] ^= HashValueD;
				_HashStateArrayData[4] ^= HashValueE;
				_HashStateArrayData[5] ^= HashValueF;
				_HashStateArrayData[6] ^= HashValueG;
				_HashStateArrayData[7] ^= HashValueH;
			}
		}

	public:
		//Is extendable-output function
		static const bool is_Extendable_OF = false;

		inline void StepInitialize() override
		{
			_HashStateArrayData[0] = 0x7380166fU;
			_HashStateArrayData[1] = 0x4914b2b9U;
			_HashStateArrayData[2] = 0x172442d7U;
			_HashStateArrayData[3] = 0xda8a0600U;
			_HashStateArrayData[4] = 0xa96f30bcU;
			_HashStateArrayData[5] = 0x163138aaU;
			_HashStateArrayData[6] = 0xe38dee4dU;
			_HashStateArrayData[7] = 0xb0fb0e4eU;

			_byte_position = 0;
			_total_bit = 0;
		}

		inline void StepUpdate( const std::span<const std::uint8_t> data_value_vector ) override
		{
			const auto* data_pointer = data_value_vector.data();
			auto data_size = data_value_vector.size();

			if(data_pointer == nullptr)
				return;

			auto lambda_Transform = [ this ]( const std::uint8_t* data_pointer, std::size_t data_size )
			{
				this->hash_transform( data_pointer, data_size );
			};

			HashProviderBaseTools::absorb_bytes(data_pointer, data_size, 64, 64, _BufferMessageMemory.data(), _byte_position, _total_bit, lambda_Transform);
		}

		inline void StepFinal( std::span<std::uint8_t> hash_value_vector ) override
		{
			if(hash_value_vector.data() == nullptr)
				return;

			_total_bit += _byte_position * 8;

			_BufferMessageMemory[_byte_position++] = 0x80;

			if (_byte_position > 56)
			{
				if (_byte_position != 64)
				{
					std::memset(_BufferMessageMemory.data() + _byte_position, 0, 64 - _byte_position);
				}

				this->hash_transform(_BufferMessageMemory.data(), 1);
				_byte_position = 0;
			}
		
			std::memset(std::addressof(_BufferMessageMemory[_byte_position]), 0, 56 - _byte_position);

			CommonToolkit::EightByte _Message_Size = CommonToolkit::ByteSwap::byteswap(_total_bit);

			//std::memcpy(std::addressof(_BufferMessageMemory[64 - 8]), &_Message_Size, 64 / 8);

			if constexpr(CURRENT_SYSTEM_BITS == 32)
				CommonToolkit::BitConverters::le32_copy(&_Message_Size, 0, std::addressof(_BufferMessageMemory[64 - 8]), 0, 64 / 8);
			else
				CommonToolkit::BitConverters::le64_copy(&_Message_Size, 0, std::addressof(_BufferMessageMemory[64 - 8]), 0, 64 / 8);
		
			this->hash_transform(_BufferMessageMemory.data(), 1);
		
			for (std::size_t index = 0; index < 8; index++)
			{
				_HashStateArrayData[index] = CommonToolkit::ByteSwap::byteswap(_HashStateArrayData[index]);
			}

			//std::memcpy(hash_value_vector.data(), _HashStateArrayData.data(), _HashStateArrayData.size() * sizeof(CommonToolkit::FourByte));

			if constexpr(CURRENT_SYSTEM_BITS == 32)
				CommonToolkit::BitConverters::le32_copy(_HashStateArrayData.data(), 0, hash_value_vector.data(), 0, _HashStateArrayData.size() * sizeof(CommonToolkit::FourByte));
			else
				CommonToolkit::BitConverters::le64_copy(_HashStateArrayData.data(), 0, hash_value_vector.data(), 0, _HashStateArrayData.size() * sizeof(CommonToolkit::FourByte));

			StepInitialize();
		}

		inline std::size_t HashSize() const override
		{
			return 256;
		}

		inline void Clear() override
		{
			HashProviderBaseTools::zero_memory( _HashStateArrayData );
			HashProviderBaseTools::zero_memory( _BufferMessageMemory );
		}

		HashProvider() = default;

		~HashProvider()
		{
			this->Clear();
		}
	};
}