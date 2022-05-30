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
	namespace HashProviderBaseTools
	{
		class InterfaceHashProvider
		{

		protected:
			//初始化哈希器的状态数据
			//Initialize the state data of the hashers
			virtual inline void StepInitialize() = 0;
			
			//如果源字节数据大小大于或者等于一个即将哈希的分块字节数据大小，那么就更新哈希器的状态数据：使用HashTransform私有函数来处理 【分块字节大小】*【分块字节数量】的字节数据
			//If the source byte data size is greater than or equal to the size of a chunk byte data to be hashed, then update the hasher state data: use the HashTransform private function to process the byte data of [chunk byte size] * [chunk byte count]
			virtual inline void StepUpdate( const std::span<const std::uint8_t> data_value_vector ) = 0;
			
			//否则源字节数据小于一个即将哈希的分块字节数据大小，那么就直接使用一次HashTransform私有函数
			//Otherwise, if the source byte data is smaller than the size of a chunk byte data to be hashed, then use the HashTransform private function directly once
			virtual inline void StepFinal( std::span<std::uint8_t> hash_value_vector ) = 0;
			
			//散列信息的比特大小
			//Bit size of hashed message
			virtual inline std::size_t HashSize() const = 0;

			//清除内存中的哈希器的状态数据
			//Clear the state data of the hashers in memory
			virtual inline void Clear() = 0;

		public:

			virtual ~InterfaceHashProvider() = default;
		};

		template <typename Type, size_t N>
		struct stream_width_fixer
		{
			stream_width_fixer( Type value ) : _value( value ) {}
			Type _value;
		};

		template <typename Type, size_t N>
		std::ostream& operator<<( std::ostream& os, const stream_width_fixer<Type, N>& swf )
		{
			return os << std::setw( N ) << swf._value;
		}

		inline std::string Bytes2HexadecimalString( std::span<std::byte> in )
		{
			constexpr static std::array<char, 16> transArray{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

			std::string out;
			out.resize( in.size() * 2 );
			std::byte highMask{ 0xF0 };
			std::byte lowMask{ 0x0F };

			for ( size_t input_index = 0, output_index = 0; input_index < in.size(); ++input_index, output_index += 2 )
			{
				out[ output_index ] = transArray[ static_cast<size_t>( ( in[ input_index ] & highMask ) >> 4 ) ];
				out[ output_index + 1 ] = transArray[ static_cast<size_t>( ( in[ input_index ] & lowMask ) ) ];
			}
			return out;
		}

		// Accumulate data and call the transformation function for full blocks.
		template <typename Type, typename TransformFunctionType>
		requires std::is_invocable_r_v<void, TransformFunctionType, std::uint8_t*, std::size_t>
		inline void absorb_bytes
		(
			const uint8_t* data,
			std::size_t data_size,
			std::size_t block_byte_size,
			std::size_t block_byte_size_check,
			CommonToolkit::OneByte* _BufferMessageMemory,
			std::size_t& byte_position,
			Type& _total_bit,
			TransformFunctionType transform_function
		)
		{
			/*if ( byte_position && byte_position + data_size >= block_byte_size_check )
			{
				std::memcpy( _BufferMessageMemory + byte_position, data, block_byte_size - byte_position );
				transform_function( _BufferMessageMemory, 1 );
				data_size -= block_byte_size - byte_position;
				data += block_byte_size - byte_position;
				_total_bit += block_byte_size * 8;
				byte_position = 0;
			}
			if ( data_size >= block_byte_size_check )
			{
				std::size_t blocks = ( data_size + block_byte_size - block_byte_size_check ) / block_byte_size;
				std::size_t bytes = blocks * block_byte_size;
				transform_function( data, blocks );
				data_size -= bytes;
				data += bytes;
				_total_bit += ( bytes ) * 8;
			}
			std::memcpy( _BufferMessageMemory + byte_position, data, data_size );
			byte_position += data_size;*/

			bool data_container_all_element_is_zero = false;

			if ( byte_position != 0 && byte_position + data_size >= block_byte_size_check )
			{
				std::memcpy( _BufferMessageMemory + byte_position, data, block_byte_size - byte_position );
				transform_function( _BufferMessageMemory, 1 );
				data_size -= block_byte_size - byte_position;
				data += block_byte_size - byte_position;
				_total_bit += block_byte_size * 8;
				byte_position = 0;
			}

			if ( data_size >= block_byte_size_check )
			{
				std::size_t loop_blocks = ( data_size + block_byte_size - block_byte_size_check ) / block_byte_size;
				std::size_t hashed_bytes = loop_blocks * block_byte_size;
				transform_function( data, loop_blocks );

				std::span<const CommonToolkit::OneByte> data_span(data, data + data_size);

				data_container_all_element_is_zero = std::ranges::all_of
				(
					data_span.begin(),
					data_span.end(),
					[](unsigned char value) -> bool
					{
						return value == static_cast<unsigned char>(0);
					}
				);

				data_size -= hashed_bytes;
				data += hashed_bytes;
				_total_bit += ( hashed_bytes ) * 8;
			}

			if(!data_container_all_element_is_zero)
			{
				std::memcpy( _BufferMessageMemory + byte_position, data, data_size );
				byte_position += data_size;
			}
		}

		/*
			Clear memory, suppressing compiler optimizations.
			
			@brief Sets each element of an array to 0
			@param BufferDataType; is class or type
			@param buffer; an array of elements
			@param size; the number of elements in the array
			@details The operation performs a wipe or zeroization.
			The function attempts to survive optimizations and dead code removal.
		*/
		template<typename BufferDataType>
		requires std::integral<BufferDataType>
		inline void zero_memory( BufferDataType* variable_pointer, std::size_t size )
		{
			#if 1

				#if 1
					
					memory_set_no_optimize_function(variable_pointer, 0, size);
				
				#else
				
					// GCC 4.3.2 on Cygwin optimizes away the first store if this
					// loop is done in the forward direction
					volatile BufferDataType* data_pointer = static_cast<volatile BufferDataType*>( variable_pointer + size );
					while ( size-- )
					{
						volatile BufferDataType& reference_value = *data_pointer;
						reference_value = static_cast<BufferDataType>(0);
						--data_pointer;
					}

				#endif

			#else

			memset_s(data_pointer, 0, size);

			#endif
		}

		// Clear memory occupied by an array, suppressing compiler optimizations.
		template <typename Type, size_t N>
		inline void zero_memory( std::array<Type, N>& array_data )
		{
			zero_memory( array_data.data(), array_data.size() * sizeof( Type ) );
		}

		// Clear memory occupied by std::string
		inline void zero_memory( std::string& string_data )
		{
			if ( !string_data.empty() )
				zero_memory( &string_data[ 0 ], string_data.size() );
		}

	}  // namespace HashProviderBaseTools

	namespace HashProviderBaseTools::HashSize
	{
		// Validate that variable hash is within the list of allowed sizes
		inline void validate( std::size_t HashSize, std::initializer_list<std::size_t> initializer_list )
		{
			if ( !HashSize )
			{
				throw std::invalid_argument( std::string( "Hash size can't be zero." ) );
			}

			if ( std::find( initializer_list.begin(), initializer_list.end(), HashSize ) )
			{
				return;
			}

			throw std::runtime_error( "Invalid hash size." );
		}

		// Validate variable hash size up to max bits
		inline void validate( size_t HashSize, size_t max_hash_size )
		{
			if ( !HashSize )
			{
				throw std::invalid_argument( std::string( "Hash size can't be zero." ) );
			}

			if ( HashSize % 8 )
			{
				throw std::runtime_error( "Non-byte hash sizes are not supported." );
			}

			if ( HashSize > max_hash_size )
			{
				throw std::runtime_error( "Invalid hash size." );
			}
		}
	}  // namespace HashProviderBaseTools::HashSize

	namespace HashProviderBaseTools::Traits
	{
		//Is extendable-output function
		template <typename Type>
		struct is_Extendable_OF
		{
			static const bool value = Type::is_Extendable_OF;
		};

		template <typename Type>
		inline constexpr bool is_Extendable_OF_v = is_Extendable_OF<Type>::value;

		//Is byte function
		template <typename Type>
		struct is_byte
		{
			static const bool value = std::is_same_v<Type, char>::value || std::is_same_v<Type, signed char>::value ||
			#if ( defined( _HAS_STD_BYTE ) && _HAS_STD_BYTE ) || ( defined( __cpp_lib_byte ) && __cpp_lib_byte >= 201603 )
				std::is_same_v<Type, std::byte>::value ||
			#endif
				std::is_same_v<Type, unsigned char>::value || std::is_same_v<Type, CommonToolkit::OneByte>::value;
		};

		template <typename Type>
		inline constexpr bool is_byte_v = is_byte<Type>::value;
	}  // namespace HashProviderBaseTools::Traits
	
	namespace HashProviderBaseTools::Blake
	{
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
	}
}
