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
		using namespace CommonSecurity::SHA::BaseTools;

		namespace Core
		{
			using CommonSecurity::Binary_LeftRotateMove;
			using CommonSecurity::Binary_RightRotateMove;

			constexpr std::array<EightByte, 24> HASH_ROUND_CONSTANTS{ 0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808Aull, 0x8000000080008000ull, 0x000000000000808Bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull, 0x000000000000008Aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000Aull, 0x000000008000808Bull, 0x800000000000008Bull, 0x8000000000008089ull, 0x8000000000008003ull, 0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800Aull, 0x800000008000000Aull, 0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull };

			namespace Functions
			{
				template <std::size_t ROUND>
				static inline void transform( EightByte* _ArrayHashStateData )
				{
					for ( std::size_t round = 24 - ROUND; round < 24; round++ )
					{
						EightByte _ArrayDataBuffer[ 5 ], _ArrayDataBuffer2[ 5 ];
						_ArrayDataBuffer[ 0 ] = _ArrayHashStateData[ 0 * 5 + 0 ] ^ _ArrayHashStateData[ 1 * 5 + 0 ] ^ _ArrayHashStateData[ 2 * 5 + 0 ] ^ _ArrayHashStateData[ 3 * 5 + 0 ] ^ _ArrayHashStateData[ 4 * 5 + 0 ];
						_ArrayDataBuffer[ 1 ] = _ArrayHashStateData[ 0 * 5 + 1 ] ^ _ArrayHashStateData[ 1 * 5 + 1 ] ^ _ArrayHashStateData[ 2 * 5 + 1 ] ^ _ArrayHashStateData[ 3 * 5 + 1 ] ^ _ArrayHashStateData[ 4 * 5 + 1 ];
						_ArrayDataBuffer[ 2 ] = _ArrayHashStateData[ 0 * 5 + 2 ] ^ _ArrayHashStateData[ 1 * 5 + 2 ] ^ _ArrayHashStateData[ 2 * 5 + 2 ] ^ _ArrayHashStateData[ 3 * 5 + 2 ] ^ _ArrayHashStateData[ 4 * 5 + 2 ];
						_ArrayDataBuffer[ 3 ] = _ArrayHashStateData[ 0 * 5 + 3 ] ^ _ArrayHashStateData[ 1 * 5 + 3 ] ^ _ArrayHashStateData[ 2 * 5 + 3 ] ^ _ArrayHashStateData[ 3 * 5 + 3 ] ^ _ArrayHashStateData[ 4 * 5 + 3 ];
						_ArrayDataBuffer[ 4 ] = _ArrayHashStateData[ 0 * 5 + 4 ] ^ _ArrayHashStateData[ 1 * 5 + 4 ] ^ _ArrayHashStateData[ 2 * 5 + 4 ] ^ _ArrayHashStateData[ 3 * 5 + 4 ] ^ _ArrayHashStateData[ 4 * 5 + 4 ];

						_ArrayDataBuffer2[ 0 ] = _ArrayDataBuffer[ 4 ] ^ Binary_LeftRotateMove<EightByte>( _ArrayDataBuffer[ 1 ], 1 );
						_ArrayDataBuffer2[ 1 ] = _ArrayDataBuffer[ 0 ] ^ Binary_LeftRotateMove<EightByte>( _ArrayDataBuffer[ 2 ], 1 );
						_ArrayDataBuffer2[ 2 ] = _ArrayDataBuffer[ 1 ] ^ Binary_LeftRotateMove<EightByte>( _ArrayDataBuffer[ 3 ], 1 );
						_ArrayDataBuffer2[ 3 ] = _ArrayDataBuffer[ 2 ] ^ Binary_LeftRotateMove<EightByte>( _ArrayDataBuffer[ 4 ], 1 );
						_ArrayDataBuffer2[ 4 ] = _ArrayDataBuffer[ 3 ] ^ Binary_LeftRotateMove<EightByte>( _ArrayDataBuffer[ 0 ], 1 );

						EightByte B00 = _ArrayHashStateData[ 0 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ];
						EightByte B10 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 0 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 1 );
						EightByte B20 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 0 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 62 );
						EightByte B05 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 0 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 28 );
						EightByte B15 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 0 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 27 );

						EightByte B16 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 1 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ], 36 );
						EightByte B01 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 1 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 44 );
						EightByte B11 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 1 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 6 );
						EightByte B21 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 1 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 55 );
						EightByte B06 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 1 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 20 );

						EightByte B07 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 2 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ], 3 );
						EightByte B17 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 2 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 10 );
						EightByte B02 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 2 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 43 );
						EightByte B12 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 2 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 25 );
						EightByte B22 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 2 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 39 );

						EightByte B23 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 3 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ], 41 );
						EightByte B08 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 3 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 45 );
						EightByte B18 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 3 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 15 );
						EightByte B03 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 3 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 21 );
						EightByte B13 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 3 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 8 );

						EightByte B14 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 4 * 5 + 0 ] ^ _ArrayDataBuffer2[ 0 ], 18 );
						EightByte B24 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 4 * 5 + 1 ] ^ _ArrayDataBuffer2[ 1 ], 2 );
						EightByte B09 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 4 * 5 + 2 ] ^ _ArrayDataBuffer2[ 2 ], 61 );
						EightByte B19 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 4 * 5 + 3 ] ^ _ArrayDataBuffer2[ 3 ], 56 );
						EightByte B04 = Binary_LeftRotateMove<EightByte>( _ArrayHashStateData[ 4 * 5 + 4 ] ^ _ArrayDataBuffer2[ 4 ], 14 );

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

				template <std::size_t ROUND>
				static inline void transform( const uint8_t* data, EightByte number_blocks, EightByte* _ArrayHashStateData, std::size_t _rate )
				{
					std::size_t rate8 = _rate / 8;
					std::size_t rate64 = _rate / 64;
					for ( std::size_t block = 0; block < number_blocks; block++ )
					{
						for ( std::size_t index = 0; index < rate64; index++ )
						{
							_ArrayHashStateData[ index ] ^= reinterpret_cast<const EightByte*>( data + block * rate8 )[ index ];
						}

						transform<ROUND>( _ArrayHashStateData );
					}
				}
			}  // namespace Functions
		}	   // namespace Core

		// SHA3-512 Code Source
		// https://github.com/kerukuro/digestpp
		// Modified by Twilight-Dream
		class HashProvider
		{

		private:
			//A is State Arrays
			std::array<EightByte, 25> _ArrayHashStateData;
			std::array<uint8_t, 144>  _BufferMemory;
			std::size_t				  _position;
			std::size_t				  _hash_size;
			std::size_t				  _rate;
			CommonSecurity::EightByte _total;

		public:
			//Is extendable-output function
			static const bool is_Extendable_OF = false;

			HashProvider( std::size_t hashsize ) : _hash_size( hashsize )
			{
				BaseTools::HashSize::validate( hashsize, { 224, 256, 384, 512 } );
				_rate = 1600U - _hash_size * 2;
			}

			~HashProvider()
			{
				Clear();
			}

			inline void StepInitialize();

			inline void StepUpdate( const uint8_t* data, std::size_t data_size );

			inline void StepFinal( uint8_t* hash );

			inline std::size_t HashSize() const;

			inline void Clear();
		};

		inline void HashProvider::StepInitialize()
		{
			BaseTools::zero_memory( _ArrayHashStateData );
			_position = 0;
			_total = 0;
		}

		inline void HashProvider::StepUpdate( const uint8_t* data, std::size_t data_size )
		{
			auto lambda_Transform = [ this ]( const uint8_t* data, std::size_t data_size ) {
				Core::Functions::transform<24>( data, data_size, _ArrayHashStateData.data(), _rate );
			};

			BaseTools::absorb_bytes( data, data_size, _rate / 8, _rate / 8, _BufferMemory.data(), _position, _total, lambda_Transform );
		}

		inline void HashProvider::StepFinal( uint8_t* hash )
		{
			std::size_t rate8 = _rate / 8;
			_BufferMemory[ _position++ ] = 0x06;
			if ( rate8 != _position )
			{
				std::memset( &_BufferMemory[ _position ], 0, rate8 - _position );
			}
			_BufferMemory[ rate8 - 1 ] |= 0x80;
			Core::Functions::transform<24>( _BufferMemory.data(), 1, _ArrayHashStateData.data(), _rate );
			std::memcpy( hash, _ArrayHashStateData.data(), HashSize() / 8 );
		}

		inline std::size_t HashProvider::HashSize() const
		{
			return _hash_size;
		}

		inline void HashProvider::Clear()
		{
			BaseTools::zero_memory( _ArrayHashStateData );
			BaseTools::zero_memory( _BufferMemory );
		}
	}  // namespace Version3
}

