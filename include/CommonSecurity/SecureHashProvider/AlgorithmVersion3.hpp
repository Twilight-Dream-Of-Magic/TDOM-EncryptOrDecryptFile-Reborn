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

namespace CommonSecurity::SHA
{
	//Chinese: 第三代安全散列算法，之前名为Keccak算法
	//English: Secure Hash Algorithm Version 3 (Keccak)
	//Paper: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
	namespace Version3
	{
		using namespace CommonSecurity::HashProviderBaseTools;
		/*
			state_constant[16] = {random_bit()...} // random number or random bit mask

			state[4][4] = {{0,0,0,0}, {0,0,0,0}...} //element is 64 bit

			SPRP(state, rounds):

				a[4] = {0,0,0,0}
				b[4] = {0,0,0,0}
				c[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

				nonlinear_function(c):
					for(i = 0, j = 0; i < rows && j < columns, i = i + 1, j = j + 1)
						state[j][i] = c[i % 16] bitwise_xor (bitwise_not(c[(i + 1) % 16]) bitwise_and c[(i + 2) % 16]))

				linear_function(a, b):
					b[0] = a[3] bitwise_xor bit_loop_right_shift(a[1], 1)
					b[1] = a[0] bitwise_xor bit_loop_right_shift(a[2], 1)
					b[2] = a[1] bitwise_xor bit_loop_right_shift(a[3], 1)
					b[3] = a[2] bitwise_xor bit_loop_right_shift(a[0], 1)

				pseudo_random_permutation(state, b):
					c[i + random_number() mod 16] = bit_loop_right_shift(state[0][0] bitwise_xor b[0], fixed_bit_count)
					c[i + random_number() mod 16] = bit_loop_right_shift(state[0][1] bitwise_xor b[1], fixed_bit_count)
					c[i + random_number() mod 16] = bit_loop_right_shift(state[0][2] bitwise_xor b[2], fixed_bit_count)
					c[i + random_number() mod 16] = bit_loop_right_shift(state[0][3] bitwise_xor b[3], fixed_bit_count)
					
					for(i = 0, j = 0; i < rows && j < columns, i = i + 1, j = j + 1)
						value = bit_loop_right_shift(state[j][i] bitwise_xor b[i mod 4], fixed_bit_count)
						if(c[i + random_number()] != value)
							c[i + random_number() mod 16] = value

				for i in 1 to rounds:
					//State mix
					a[0] = state[0][0] bitwise_xor state[1][0] bitwise_xor state[2][0] bitwise_xor state[3][0]
					a[1] = state[0][1] bitwise_xor state[1][1] bitwise_xor state[2][1] bitwise_xor state[3][1]
					a[2] = state[0][2] bitwise_xor state[1][2] bitwise_xor state[2][2] bitwise_xor state[3][2]
					a[3] = state[0][3] bitwise_xor state[1][3] bitwise_xor state[2][3] bitwise_xor state[3][3]
					
					linear_function(a, b)
					pseudo_random_permutation(state, b)
					nonlinear_function(c)
					state[0][0] = state[0][0] bitwise_xor random_constant[i]

				return state
		*/
		namespace Core
		{
			using CommonSecurity::Binary_LeftRotateMove;
			using CommonSecurity::Binary_RightRotateMove;

			constexpr std::array<CommonToolkit::EightByte, 24> HASH_ROUND_CONSTANTS
			{
				0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
				0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
				0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
				0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
				0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
				0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
			};

			namespace Functions
			{
				template <std::size_t ROUND>
				static inline void hash_transform( CommonToolkit::EightByte* _ArrayHashStateData )
				{
					for ( std::size_t round = 24 - ROUND; round < 24; round++ )
					{
						CommonToolkit::EightByte _ArrayDataBuffer[ 5 ], _ArrayDataBuffer2[ 5 ];
						_ArrayDataBuffer[ 0 ] = _ArrayHashStateData[ 0 * 5 + 0 ] ^ _ArrayHashStateData[ 1 * 5 + 0 ] ^ _ArrayHashStateData[ 2 * 5 + 0 ] ^ _ArrayHashStateData[ 3 * 5 + 0 ] ^ _ArrayHashStateData[ 4 * 5 + 0 ];
						_ArrayDataBuffer[ 1 ] = _ArrayHashStateData[ 0 * 5 + 1 ] ^ _ArrayHashStateData[ 1 * 5 + 1 ] ^ _ArrayHashStateData[ 2 * 5 + 1 ] ^ _ArrayHashStateData[ 3 * 5 + 1 ] ^ _ArrayHashStateData[ 4 * 5 + 1 ];
						_ArrayDataBuffer[ 2 ] = _ArrayHashStateData[ 0 * 5 + 2 ] ^ _ArrayHashStateData[ 1 * 5 + 2 ] ^ _ArrayHashStateData[ 2 * 5 + 2 ] ^ _ArrayHashStateData[ 3 * 5 + 2 ] ^ _ArrayHashStateData[ 4 * 5 + 2 ];
						_ArrayDataBuffer[ 3 ] = _ArrayHashStateData[ 0 * 5 + 3 ] ^ _ArrayHashStateData[ 1 * 5 + 3 ] ^ _ArrayHashStateData[ 2 * 5 + 3 ] ^ _ArrayHashStateData[ 3 * 5 + 3 ] ^ _ArrayHashStateData[ 4 * 5 + 3 ];
						_ArrayDataBuffer[ 4 ] = _ArrayHashStateData[ 0 * 5 + 4 ] ^ _ArrayHashStateData[ 1 * 5 + 4 ] ^ _ArrayHashStateData[ 2 * 5 + 4 ] ^ _ArrayHashStateData[ 3 * 5 + 4 ] ^ _ArrayHashStateData[ 4 * 5 + 4 ];

						_ArrayDataBuffer2[ 0 ] = _ArrayDataBuffer[ 4 ] ^ Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayDataBuffer[ 1 ], 1 );
						_ArrayDataBuffer2[ 1 ] = _ArrayDataBuffer[ 0 ] ^ Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayDataBuffer[ 2 ], 1 );
						_ArrayDataBuffer2[ 2 ] = _ArrayDataBuffer[ 1 ] ^ Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayDataBuffer[ 3 ], 1 );
						_ArrayDataBuffer2[ 3 ] = _ArrayDataBuffer[ 2 ] ^ Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayDataBuffer[ 4 ], 1 );
						_ArrayDataBuffer2[ 4 ] = _ArrayDataBuffer[ 3 ] ^ Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayDataBuffer[ 0 ], 1 );

						CommonToolkit::EightByte B00 = _ArrayHashStateData[ 0 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ];
						CommonToolkit::EightByte B10 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 0 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 1 );
						CommonToolkit::EightByte B20 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 0 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 62 );
						CommonToolkit::EightByte B05 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 0 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 28 );
						CommonToolkit::EightByte B15 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 0 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 27 );

						CommonToolkit::EightByte B16 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 1 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ], 36 );
						CommonToolkit::EightByte B01 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 1 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 44 );
						CommonToolkit::EightByte B11 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 1 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 6 );
						CommonToolkit::EightByte B21 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 1 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 55 );
						CommonToolkit::EightByte B06 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 1 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 20 );

						CommonToolkit::EightByte B07 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 2 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ], 3 );
						CommonToolkit::EightByte B17 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 2 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 10 );
						CommonToolkit::EightByte B02 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 2 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 43 );
						CommonToolkit::EightByte B12 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 2 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 25 );
						CommonToolkit::EightByte B22 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 2 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 39 );

						CommonToolkit::EightByte B23 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 3 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ], 41 );
						CommonToolkit::EightByte B08 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 3 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 45 );
						CommonToolkit::EightByte B18 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 3 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 15 );
						CommonToolkit::EightByte B03 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 3 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 21 );
						CommonToolkit::EightByte B13 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 3 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 8 );

						CommonToolkit::EightByte B14 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 4 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ], 18 );
						CommonToolkit::EightByte B24 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 4 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 2 );
						CommonToolkit::EightByte B09 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 4 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 61 );
						CommonToolkit::EightByte B19 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 4 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 56 );
						CommonToolkit::EightByte B04 = Binary_LeftRotateMove<CommonToolkit::EightByte>( _ArrayHashStateData[ 4 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 14 );

						_ArrayHashStateData[ 0 * 5 + 0 ] = B00 ^ ( ( ~B01 ) & B02 );
						_ArrayHashStateData[ 0 * 5 + 1 ] = B01 ^ ( ( ~B02 ) & B03 );
						_ArrayHashStateData[ 0 * 5 + 2 ] = B02 ^ ( ( ~B03 ) & B04 );
						_ArrayHashStateData[ 0 * 5 + 3 ] = B03 ^ ( ( ~B04 ) & B00 );
						_ArrayHashStateData[ 0 * 5 + 4 ] = B04 ^ ( ( ~B00 ) & B01 );

						_ArrayHashStateData[ 1 * 5 + 0 ] = B05 ^ ( ( ~B06 ) & B07 );
						_ArrayHashStateData[ 1 * 5 + 1 ] = B06 ^ ( ( ~B07 ) & B08 );
						_ArrayHashStateData[ 1 * 5 + 2 ] = B07 ^ ( ( ~B08 ) & B09 );
						_ArrayHashStateData[ 1 * 5 + 3 ] = B08 ^ ( ( ~B09 ) & B05 );
						_ArrayHashStateData[ 1 * 5 + 4 ] = B09 ^ ( ( ~B05 ) & B06 );

						_ArrayHashStateData[ 2 * 5 + 0 ] = B10 ^ ( ( ~B11 ) & B12 );
						_ArrayHashStateData[ 2 * 5 + 1 ] = B11 ^ ( ( ~B12 ) & B13 );
						_ArrayHashStateData[ 2 * 5 + 2 ] = B12 ^ ( ( ~B13 ) & B14 );
						_ArrayHashStateData[ 2 * 5 + 3 ] = B13 ^ ( ( ~B14 ) & B10 );
						_ArrayHashStateData[ 2 * 5 + 4 ] = B14 ^ ( ( ~B10 ) & B11 );

						_ArrayHashStateData[ 3 * 5 + 0 ] = B15 ^ ( ( ~B16 ) & B17 );
						_ArrayHashStateData[ 3 * 5 + 1 ] = B16 ^ ( ( ~B17 ) & B18 );
						_ArrayHashStateData[ 3 * 5 + 2 ] = B17 ^ ( ( ~B18 ) & B19 );
						_ArrayHashStateData[ 3 * 5 + 3 ] = B18 ^ ( ( ~B19 ) & B15 );
						_ArrayHashStateData[ 3 * 5 + 4 ] = B19 ^ ( ( ~B15 ) & B16 );

						_ArrayHashStateData[ 4 * 5 + 0 ] = B20 ^ ( ( ~B21 ) & B22 );
						_ArrayHashStateData[ 4 * 5 + 1 ] = B21 ^ ( ( ~B22 ) & B23 );
						_ArrayHashStateData[ 4 * 5 + 2 ] = B22 ^ ( ( ~B23 ) & B24 );
						_ArrayHashStateData[ 4 * 5 + 3 ] = B23 ^ ( ( ~B24 ) & B20 );
						_ArrayHashStateData[ 4 * 5 + 4 ] = B24 ^ ( ( ~B20 ) & B21 );

						_ArrayHashStateData[ 0 ] ^= HASH_ROUND_CONSTANTS[ round ];
					}
				}
			}  // namespace Functions
		}	   // namespace Core

		// SHA3-512 Reference Source Code
		// https://github.com/kerukuro/digestpp
		// Modified by Twilight-Dream
		class HashProvider : public CommonSecurity::HashProviderBaseTools::InterfaceHashProvider
		{

		private:
			std::array<CommonToolkit::EightByte, 25> _HashStateArrayData;
			std::array<CommonToolkit::OneByte, 144>  _BufferMessageMemory;
			std::size_t				  _byte_position;
			std::size_t				  _hash_size;
			std::size_t				  _rate;
			CommonToolkit::EightByte _total_bit;

			template <std::size_t ROUND>
			inline void hash_transform( const CommonToolkit::OneByte* data, CommonToolkit::EightByte number_blocks, CommonToolkit:: EightByte* _ArrayHashStateData, std::size_t _rate )
			{
				std::size_t rate8 = _rate / 8;
				std::size_t rate64 = _rate / 64;
				for ( std::size_t block = 0; block < number_blocks; block++ )
				{
					for ( std::size_t index = 0; index < rate64; index++ )
					{
						CommonToolkit::EightByte data_word = std::bit_cast<const CommonToolkit::EightByte*>( data + block * rate8 )[ index ];
						if constexpr(std::endian::native != std::endian::little)
						{
							data_word = CommonToolkit::ByteSwap::byteswap(data_word);
						}
						_ArrayHashStateData[ index ] ^= data_word;
					}

					Core::Functions::hash_transform<ROUND>( _ArrayHashStateData );
				}
			}

		public:
			//Is extendable-output function
			static const bool is_Extendable_OF = false;

			inline void StepInitialize() override
			{
				HashProviderBaseTools::zero_memory( _HashStateArrayData );
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
					this->hash_transform<24>( data_pointer, data_size, _HashStateArrayData.data(), _rate );
				};

				HashProviderBaseTools::absorb_bytes( data_pointer, data_size, _rate / 8, _rate / 8, _BufferMessageMemory.data(), _byte_position, _total_bit, lambda_Transform );
			}

			inline void StepFinal( std::span<std::uint8_t> hash_value_vector ) override
			{
				if(hash_value_vector.data() == nullptr)
					return;

				std::size_t rate8 = _rate / 8;

				_BufferMessageMemory[ _byte_position++ ] = 0x06;

				if ( rate8 != _byte_position )
				{
					std::memset( _BufferMessageMemory.data() + _byte_position, 0, rate8 - _byte_position );
				}

				_BufferMessageMemory[ rate8 - 1 ] |= 0x80;

				this->hash_transform<24>( _BufferMessageMemory.data(), 1, _HashStateArrayData.data(), _rate );

				//::memcpy( hash_value_vector.data(), _HashStateArrayData.data(), _hash_size / 8 );

				if constexpr(CURRENT_SYSTEM_BITS == 32)
					CommonToolkit::BitConverters::le32_copy(_HashStateArrayData.data(), 0, hash_value_vector.data(), 0, _hash_size / 8);
				else
					CommonToolkit::BitConverters::le64_copy(_HashStateArrayData.data(), 0, hash_value_vector.data(), 0, _hash_size / 8);

				StepInitialize();
			}

			inline std::size_t HashSize() const override
			{
				return _hash_size;
			}

			inline void Clear() override
			{
				HashProviderBaseTools::zero_memory( _HashStateArrayData );
				HashProviderBaseTools::zero_memory( _BufferMessageMemory );
			}

			HashProvider( std::size_t hashsize ) : _hash_size( hashsize )
			{
				HashProviderBaseTools::HashSize::validate( hashsize, { 224, 256, 384, 512 } );
				_rate = 1600U - _hash_size * 2;
			}

			~HashProvider()
			{
				this->Clear();
			}
		};
	}  // namespace Version3
}

