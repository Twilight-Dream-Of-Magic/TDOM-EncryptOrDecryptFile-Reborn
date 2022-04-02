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

#ifndef BYTE_SWAP_FUNCTON
#define BYTE_SWAP_FUNCTON
#endif	// !BYTE_SWAP_FUNCTON

#ifndef INTEGER_PACKCATION_OLD
//#define INTEGER_PACKCATION_OLD
#endif	// !INTEGER_PACKCATION_OLD

#ifndef INTEGER_UNPACKCATION_OLD
//#define INTEGER_UNPACKCATION_OLD
#endif	// !INTEGER_UNPACKCATION_OLD

//通用安全工具
//Common Security Tools
namespace CommonSecurity
{
	using namespace UtilTools::DataFormating;

	using OneByte = unsigned char;
	using TwoByte = unsigned short int;
	using FourByte = unsigned int;
	using EightByte = unsigned long long int;

	using SpanOneByte = std::span<std::byte, 1>;
	using SpanTwoByte = std::span<std::byte, 2>;
	using SpanFourByte = std::span<std::byte, 4>;
	using SpanEightByte = std::span<std::byte, 8>;

	// unpackInteger convert unsigned long long int to array<byte, 8>
	// packInteger convert array of byte to specific integer type
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	constexpr auto unpackInteger( IntegerType data )
	{
		constexpr auto					 byteCount = std::numeric_limits<IntegerType>::digits / 8;
		std::array<std::byte, byteCount> answer;
		for ( int index = byteCount - 1; index >= 0; --index )
		{
			answer[ index ] = static_cast<std::byte>( data & 0xFF );
			data >>= 8;
		}
		return answer;
	}
	constexpr TwoByte packInteger( SpanTwoByte data )
	{
		return ( static_cast<TwoByte>( data[ 0 ] ) << 8 ) | ( static_cast<TwoByte>( data[ 1 ] ) );
	}
	constexpr FourByte packInteger( SpanFourByte data )
	{
		return ( static_cast<FourByte>( data[ 0 ] ) << 24 ) | ( static_cast<FourByte>( data[ 1 ] ) << 16 ) | ( static_cast<FourByte>( data[ 2 ] ) << 8 ) | ( static_cast<FourByte>( data[ 3 ] ) );
	}
	constexpr EightByte packInteger( SpanEightByte data )
	{
		return ( static_cast<EightByte>( packInteger( SpanFourByte{ data.begin(), 4u } ) ) << 32 ) | static_cast<EightByte>( packInteger( SpanFourByte{ data.begin() + 4, 4u } ) );
	}

	namespace SHA::BaseTools
	{
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
		template <typename Type, typename TF>
		requires std::is_invocable_r_v<void, TF, uint8_t*, size_t>
		inline void absorb_bytes( const uint8_t* data, std::size_t data_size, std::size_t block_size, std::size_t block_size_check, OneByte* _BufferMemory, std::size_t& position, Type& _total, TF transform )
		{
			if ( position && position + data_size >= block_size_check )
			{
				memcpy( _BufferMemory + position, data, block_size - position );
				transform( _BufferMemory, 1 );
				data_size -= block_size - position;
				data += block_size - position;
				_total += block_size * 8;
				position = 0;
			}
			if ( data_size >= block_size_check )
			{
				std::size_t blocks = ( data_size + block_size - block_size_check ) / block_size;
				std::size_t bytes = blocks * block_size;
				transform( data, blocks );
				data_size -= bytes;
				data += bytes;
				_total += ( bytes )*8;
			}
			memcpy( _BufferMemory + position, data, data_size );
			position += data_size;
		}

		// Clear memory, suppressing compiler optimizations.
		inline void zero_memory( void* variable, std::size_t size )
		{
			volatile OneByte* data_pointer = static_cast<volatile OneByte*>( variable );
			while ( size-- )
			{
				*data_pointer++ = 0;
			}
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
	}  // namespace SHA::BaseTools

	namespace SHA::BaseTools::HashSize
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
	}  // namespace SHA::BaseTools::HashSize

	namespace SHA::BaseTools::Traits
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
				std::is_same_v<Type, unsigned char>::value || std::is_same_v<Type, OneByte>::value;
		};

		template <typename Type>
		inline constexpr bool is_byte_v = is_byte<Type>::value;
	}  // namespace SHA::BaseTools::Traits

	#if defined( BYTE_SWAP_FUNCTON ) && __cplusplus >= 202002L
	
	/*
		Reference source code: https://gist.github.com/raidoz/4163b8ec6672aabb0656b96692af5e33
		cross-platform / cross-compiler standalone endianness conversion
	*/
	namespace ByteSwap
	{
		namespace Implementation
		{
			/* C */
			extern "C" unsigned short __cdecl _builtin_byteswap_uint16(const unsigned short value)
			{
				unsigned short other_value = 0;
				other_value =  (value << 8);
				other_value += (value >> 8);
				return other_value;
			}

			/* C */
			extern "C" unsigned int __cdecl _builtin_byteswap_uint32(const unsigned int value)
			{
				unsigned int other_value = 0;
				other_value =  (value << 24);
				other_value += (value <<  8) & 0x00FF0000;
				other_value += (value >>  8) & 0x0000FF00;
				other_value += (value >> 24);
				return other_value;
			}

			/* C */
			extern "C" unsigned long long __cdecl _builtin_byteswap_uint64(const unsigned long long value)
			{
				unsigned long long other_value = 0;
				other_value =  (value << 56);
				other_value += (value << 40) & 0x00FF000000000000;
				other_value += (value << 24) & 0x0000FF0000000000;
				other_value += (value <<  8) & 0x000000FF00000000;
				other_value += (value >>  8) & 0x00000000FF000000;
				other_value += (value >> 24) & 0x0000000000FF0000;
				other_value += (value >> 40) & 0x000000000000FF00;
				other_value += (value >> 56);
				return other_value;
			}

			//! C++ Byte-swap 16-bit unsigned short
			[[nodiscard]] static inline constexpr unsigned short Byteswap(const unsigned short ByteValue) noexcept
			{
				if (std::is_constant_evaluated())
				{
					#if defined(_MSC_VER)

					return static_cast<unsigned short>((ByteValue << 8) | (ByteValue >> 8));

					#else

					return ((( ByteValue  >> 8 ) & 0xffu ) | (( ByteValue  & 0xffu ) << 8 ));

					#endif
				}
				else
				{
					return _builtin_byteswap_uint16(ByteValue);
				}
			}

			//Type unsigned long equal to type unsigned int 
			//! C++ Byte-swap 32-bit unsigned int
			[[nodiscard]] static inline constexpr unsigned int Byteswap(const unsigned int ByteValue) noexcept
			{
				if (std::is_constant_evaluated())
				{
					#if defined(_MSC_VER)

					return (ByteValue << 24) | ((ByteValue << 8) & 0x00FF'0000) | ((ByteValue >> 8) & 0x0000'FF00) | (ByteValue >> 24);

					#else

					return ((( ByteValue & 0xff000000u ) >> 24 ) |
							(( ByteValue & 0x00ff0000u ) >> 8  ) |
							(( ByteValue & 0x0000ff00u ) << 8  ) |
							(( ByteValue & 0x000000ffu ) << 24 ));

					#endif
				}
				else
				{
					return _builtin_byteswap_uint32(ByteValue);
				}
			}

			//! C++ Byte-swap 64-bit unsigned long long
			[[nodiscard]] static inline constexpr unsigned long long Byteswap(const unsigned long long ByteValue) noexcept
			{
				if (std::is_constant_evaluated())
				{
					#if defined(_MSC_VER)

					return (ByteValue << 56) | ((ByteValue << 40) & 0x00FF'0000'0000'0000) | ((ByteValue << 24) & 0x0000'FF00'0000'0000) |
						   ((ByteValue << 8) & 0x0000'00FF'0000'0000) | ((ByteValue >> 8) & 0x0000'0000'FF00'0000) |
						   ((ByteValue >> 24) & 0x0000'0000'00FF'0000) | ((ByteValue >> 40) & 0x0000'0000'0000'FF00) | (ByteValue >> 56);

					#else

					return ((( ByteValue & 0xff00000000000000ull ) >> 56 ) |
							(( ByteValue & 0x00ff000000000000ull ) >> 40 ) |
							(( ByteValue & 0x0000ff0000000000ull ) >> 24 ) |
							(( ByteValue & 0x000000ff00000000ull ) >> 8  ) |
							(( ByteValue & 0x00000000ff000000ull ) << 8  ) |
							(( ByteValue & 0x0000000000ff0000ull ) << 24 ) |
							(( ByteValue & 0x000000000000ff00ull ) << 40 ) |
							(( ByteValue & 0x00000000000000ffull ) << 56 ));

					#endif
				}
				else
				{
					return _builtin_byteswap_uint64(ByteValue);
				}
			}

			//! C++ Byte-swap 32-bit float
			static inline float Byteswap(float ByteValue)
			{
				#ifdef __cplusplus
					static_assert(sizeof(float) == sizeof(uint32_t), "Unexpected float format");
					/* Problem: de-referencing float pointer as uint32_t breaks strict-aliasing rules for C++ and C, even if it normally works
					 *   uint32_t val = bswap32(*(reinterpret_cast<const uint32_t *>(&f)));
					 *   return *(reinterpret_cast<float *>(&val));
					 */
					// memcpy approach is guaranteed to work in C & C++ and fn calls should be optimized out:
					uint32_t asInt;
					std::memcpy(&asInt, reinterpret_cast<const void *>(&ByteValue), sizeof(uint32_t));
					asInt = Byteswap(asInt);
					std::memcpy(&ByteValue, reinterpret_cast<void *>(&asInt), sizeof(float));
					return ByteValue;
				#else
					_Static_assert(sizeof(float) == sizeof(uint32_t), "Unexpected float format");
					// union approach is guaranteed to work in C99 and later (but not in C++, though in practice it normally will):
					union { uint32_t asInt; float asFloat; } conversion_union;
					conversion_union.asFloat = ByteValue;
					conversion_union.asInt = Byteswap(conversion_union.asInt);
					return conversion_union.asFloat;
				#endif
			}

			//! C++ Byte-swap 64-bit double
			static inline double Byteswap(double ByteValue)
			{
				#ifdef __cplusplus
					static_assert(sizeof(double) == sizeof(uint64_t), "Unexpected double format");
					uint64_t asInt;
					std::memcpy(&asInt, reinterpret_cast<const void *>(&ByteValue), sizeof(uint64_t));
					asInt = Byteswap(asInt);
					std::memcpy(&ByteValue, reinterpret_cast<void *>(&asInt), sizeof(double));
					return ByteValue;
				#else
					_Static_assert(sizeof(double) == sizeof(uint64_t), "Unexpected double format");
					union { uint64_t asInt; double asDouble; } conversion_union;
					conversion_union.asDouble = ByteValue;
					conversion_union.asInt = Byteswap(conversion_union.asInt);
					return conversion_union.asDouble;
				#endif
			}
		}
		
		template <class Type> requires std::is_integral_v<Type>
		[[nodiscard]] constexpr Type byteswap(const Type ByteValue) noexcept
		{
			using ThisType = std::remove_cvref_t<Type>;

			if constexpr (sizeof(ThisType) == 1)
			{
				return ByteValue;
			}
			else if constexpr (sizeof(ThisType) == 2)
			{
				return static_cast<ThisType>(Implementation::Byteswap(static_cast<unsigned short>(ByteValue)));
			}
			else if constexpr (sizeof(ThisType) == 4)
			{
				return static_cast<Type>(Implementation::Byteswap(static_cast<unsigned int>(ByteValue)));
			}
			else if constexpr (sizeof(ThisType) == 8)
			{
				return static_cast<ThisType>(Implementation::Byteswap(static_cast<unsigned long long>(ByteValue)));
			}
			else if constexpr (std::same_as<ThisType, float>)
			{
				return static_cast<Type>(Implementation::Byteswap(static_cast<float>(ByteValue)));
			}
			else if constexpr (std::same_as<ThisType, double>)
			{
				return static_cast<Type>(Implementation::Byteswap(static_cast<double>(ByteValue)));
			}
			else
			{
				static_assert(CommonToolkit::Dependent_Always_Failed<ThisType>, "Unexpected integer size");
			}
		}
	}

	#endif

	#if defined( INTEGER_PACKCATION_OLD ) && __cplusplus <= 202002L

	inline int32_t ByteArrayToInteger32Bit( const std::vector<unsigned char>& temporaryBytes )
	{
		auto& ValueA = temporaryBytes.operator[](0);
		auto& ValueB = temporaryBytes.operator[](1);
		auto& ValueC = temporaryBytes.operator[](2);
		auto& ValueD = temporaryBytes.operator[](3);

		int32_t number = ValueA & 0xFF;
		number |= ((static_cast<int32_t>(ValueB) << 8) & 0xFF00);
		number |= ((static_cast<int32_t>(ValueC) << 16) & 0xFF0000);
		number |= ((static_cast<int32_t>(ValueD) << 24) & 0xFF000000);
		return number;
	}

	inline int64_t ByteArrayToInteger64Bit( const std::vector<unsigned char>& temporaryBytes )
	{
		auto& ValueA = temporaryBytes.operator[](0);
		auto& ValueB = temporaryBytes.operator[](1);
		auto& ValueC = temporaryBytes.operator[](2);
		auto& ValueD = temporaryBytes.operator[](3);
		auto& ValueE = temporaryBytes.operator[](4);
		auto& ValueF = temporaryBytes.operator[](5);
		auto& ValueG = temporaryBytes.operator[](6);
		auto& ValueH = temporaryBytes.operator[](7);

		int64_t number = ValueA & 0xFF;
		number |= ((static_cast<int64_t>(ValueB) << 8) & 0xFF00);
		number |= ((static_cast<int64_t>(ValueC) << 16) & 0xFF0000);
		number |= ((static_cast<int64_t>(ValueD) << 24) & 0xFF000000);
		number |= ((static_cast<int64_t>(ValueE) << 32) & 0xFF00000000);
		number |= ((static_cast<int64_t>(ValueF) << 40) & 0xFF0000000000);
		number |= ((static_cast<int64_t>(ValueG) << 48) & 0xFF000000000000);
		number |= ((static_cast<int64_t>(ValueH) << 56) & 0xFF00000000000000);
		return number;
	}

	//Turn byte 8bit array to integer 32bit
	inline void MessagePacking32Bit( const std::vector<uint8_t>& input, std::vector<uint32_t>& output )
	{
		std::vector<unsigned char> temporaryBytes = std::vector<unsigned char>();

		auto begin = input.begin(), end = input.end();
		while(begin != end)
		{
			std::size_t iteratorMoveOffset = 0;
			std::size_t dataBlockDistanceDiffercnce = static_cast<std::size_t>( std::ranges::distance( begin, end ) );
			iteratorMoveOffset = std::min( static_cast<std::size_t>(4), dataBlockDistanceDiffercnce );

			temporaryBytes.insert(temporaryBytes.begin(), begin, begin + iteratorMoveOffset);
			int32_t value = ByteArrayToInteger32Bit(temporaryBytes);
			output.push_back(static_cast<uint32_t>(value));

			temporaryBytes.clear();

			begin += iteratorMoveOffset;
		}
	}

	//Turn byte 8bit array to integer 64bit
	inline void MessagePacking64Bit( const std::vector<uint8_t>& input, std::vector<uint64_t>& output )
	{
		std::vector<unsigned char> temporaryBytes = std::vector<unsigned char>();

		auto begin = input.begin(), end = input.end();
		while(begin != end)
		{
			std::size_t iteratorMoveOffset = 0;
			std::size_t dataBlockDistanceDiffercnce = static_cast<std::size_t>( std::ranges::distance( begin, end ) );
			iteratorMoveOffset = std::min( static_cast<std::size_t>(8), dataBlockDistanceDiffercnce );

			temporaryBytes.insert(temporaryBytes.begin(), begin, begin + iteratorMoveOffset);
			int64_t value = ByteArrayToInteger64Bit(temporaryBytes);
			output.push_back(static_cast<uint64_t>(value));

			temporaryBytes.clear();

			begin += iteratorMoveOffset;
		}
	}

	#else

	/*
	
		Example Code:
			
			std::deque<unsigned char> Word;

			unsigned int InputWord = 0;
			unsigned int OutputWord = 0;
			std::vector<std::byte> bytes
			{  
				static_cast<std::byte>(Word.operator[](0)),
				static_cast<std::byte>(Word.operator[](1)),
				static_cast<std::byte>(Word.operator[](2)),
				static_cast<std::byte>(Word.operator[](3))
			};

			std::span<std::byte> byteSpan{ bytes.begin(), bytes.end() };
			CommonSecurity::MessagePacking<unsigned int>(byteSpan, &InputWord);

			OutputWord = (InputWord << 8) | (InputWord >> 24);

			std::vector<unsigned int> words
			{
				OutputWord
			};
			std::span<unsigned int> wordSpan{ words };
			CommonSecurity::MessageUnpacking<unsigned int>(wordSpan, bytes.data());

			Word.operator[](0) = static_cast<unsigned char>(bytes.operator[](0));
			Word.operator[](1) = static_cast<unsigned char>(bytes.operator[](1));
			Word.operator[](2) = static_cast<unsigned char>(bytes.operator[](2));
			Word.operator[](3) = static_cast<unsigned char>(bytes.operator[](3));

			bytes.clear();
			words.clear();
	
	*/
	template<typename IntegerType> requires std::is_integral_v<std::remove_cvref_t<IntegerType>>
	void MessagePacking(const std::span<const std::byte>& input, IntegerType* output)
    {
        if(input.size() % sizeof(IntegerType) != 0)
		{
			throw std::length_error("The size of the data must be aligned with the size of the type!");
		}

        if constexpr (std::endian::native == std::endian::little)
        {
            std::memcpy(output, input.data(), input.size());
        }
        else if constexpr (std::endian::native == std::endian::big)
        {
            auto begin = input.data();
            auto end = input.data() + input.size();
            for (auto iterator = begin; iterator != end; iterator += sizeof(IntegerType))
            {
                IntegerType value;
                std::memcpy(&value, iterator, sizeof(IntegerType));

				#if __cpp_lib_byteswap

                *output++ = std::byteswap(value);

				#else

				*output++ = CommonSecurity::ByteSwap::byteswap(value);

				#endif		
            }
        }
        else
        {
            throw std::runtime_error("");
        }
    }

	template<typename IntegerType> requires std::is_integral_v<std::remove_cvref_t<IntegerType>>
	void MessagePacking(const std::span<const unsigned char>& input, IntegerType* output)
    {
        if(input.size() % sizeof(IntegerType) != 0)
		{
			throw std::length_error("The size of the data must be aligned with the size of the type!");
		}

        if constexpr (std::endian::native == std::endian::little)
        {
            std::memcpy(output, input.data(), input.size());
        }
        else if constexpr (std::endian::native == std::endian::big)
        {
            auto begin = input.data();
            auto end = input.data() + input.size();
            for (auto iterator = begin; iterator != end; iterator += sizeof(IntegerType))
            {
                IntegerType value;
                std::memcpy(&value, iterator, sizeof(IntegerType));

				#if __cpp_lib_byteswap

                *output++ = std::byteswap(value);

				#else

				*output++ = CommonSecurity::ByteSwap::byteswap(value);

				#endif		
            }
        }
        else
        {
            throw std::runtime_error("");
        }
    }

	#endif

	#if defined( INTEGER_UNPACKCATION_OLD ) && __cplusplus <= 202002L

	inline std::vector<unsigned char> ByteArrayFromInteger32Bit( const int32_t& number, std::vector<unsigned char>& temporaryBytes )
	{
		temporaryBytes.operator[](0) = number;
		temporaryBytes.operator[](1) = number >> 8;
		temporaryBytes.operator[](2) = number >> 16;
		temporaryBytes.operator[](3) = number >> 24;

		return temporaryBytes;
	}

	inline std::vector<unsigned char> ByteArrayFromInteger64Bit( const int64_t& number, std::vector<unsigned char>& temporaryBytes )
	{
		temporaryBytes.operator[](0) = number;
		temporaryBytes.operator[](1) = number >> 8;
		temporaryBytes.operator[](2) = number >> 16;
		temporaryBytes.operator[](3) = number >> 24;
		temporaryBytes.operator[](4) = number >> 32;
		temporaryBytes.operator[](5) = number >> 40;
		temporaryBytes.operator[](6) = number >> 48;
		temporaryBytes.operator[](7) = number >> 56;

		return temporaryBytes;
	}

	//Turn integer 32bit to byte 8bit array
	inline void MessageUnpacking32Bit( std::vector<uint32_t>& input, std::vector<uint8_t>& output )
	{
		std::vector<unsigned char> temporaryBytes = std::vector<unsigned char>();

		for(auto begin = input.begin(), end = input.end(); begin != end; ++begin)
		{
			int32_t number = static_cast<int32_t>(*begin);

			temporaryBytes.resize(4);
			std::vector<unsigned char> input = ByteArrayFromInteger32Bit(number, temporaryBytes);

			for(auto& value : input)
			{
				output.push_back(value);
			}

			temporaryBytes.clear();
		}
	}

	//Turn integer 64bit to byte 8bit array
	inline void MessageUnpacking64Bit( std::vector<uint64_t>& input, std::vector<uint8_t>& output )
	{
		std::vector<unsigned char> temporaryBytes = std::vector<unsigned char>();

		for(auto begin = input.begin(), end = input.end(); begin != end; ++begin)
		{
			int64_t number = static_cast<int64_t>(*begin);

			temporaryBytes.resize(8);
			std::vector<unsigned char> input = ByteArrayFromInteger64Bit(number, temporaryBytes);

			for(auto& value : input)
			{
				output.push_back(value);
			}

			temporaryBytes.clear();
		}
	}

	#else
	
	/*
	
		Example Code:

			std::deque<unsigned char> Word;

			unsigned int InputWord = 0;
			unsigned int OutputWord = 0;
			std::vector<std::byte> bytes
			{  
				static_cast<std::byte>(Word.operator[](0)),
				static_cast<std::byte>(Word.operator[](1)),
				static_cast<std::byte>(Word.operator[](2)),
				static_cast<std::byte>(Word.operator[](3))
			};

			std::span<std::byte> byteSpan{ bytes.begin(), bytes.end() };
			CommonSecurity::MessagePacking<unsigned int>(byteSpan, &InputWord);

			OutputWord = (InputWord << 8) | (InputWord >> 24);

			std::vector<unsigned int> words
			{
				OutputWord
			};
			std::span<unsigned int> wordSpan{ words };
			CommonSecurity::MessageUnpacking<unsigned int>(wordSpan, bytes.data());

			Word.operator[](0) = static_cast<unsigned char>(bytes.operator[](0));
			Word.operator[](1) = static_cast<unsigned char>(bytes.operator[](1));
			Word.operator[](2) = static_cast<unsigned char>(bytes.operator[](2));
			Word.operator[](3) = static_cast<unsigned char>(bytes.operator[](3));

			bytes.clear();
			words.clear();
	
	*/
	template<typename IntegerType> requires std::is_integral_v<std::remove_cvref_t<IntegerType>>
	void MessageUnpacking(const std::span<const IntegerType>& input, std::byte *output)
    {
        if constexpr (std::endian::native == std::endian::little)
        {
            std::memcpy(output, input.data(), input.size() * sizeof(IntegerType));
        }
        else if constexpr (std::endian::native == std::endian::big)
        {
			// intentional copy
            for (IntegerType value : input)
			{	
				#if __cpp_lib_byteswap

				value = std::byteswap(value);

				#else

                value = CommonSecurity::ByteSwap::byteswap(value);

				#endif

				std::memcpy(output, &value, sizeof(IntegerType));
                output += sizeof(IntegerType);
            }
        }
        else
        {
            throw std::runtime_error("");
        }
    }

	template<typename IntegerType> requires std::is_integral_v<std::remove_cvref_t<IntegerType>>
	void MessageUnpacking(const std::span<const IntegerType>& input, unsigned char *output)
    {
        if constexpr (std::endian::native == std::endian::little)
        {
            std::memcpy(output, input.data(), input.size() * sizeof(IntegerType));
        }
        else if constexpr (std::endian::native == std::endian::big)
        {
			// intentional copy
            for (IntegerType value : input)
			{	
				#if __cpp_lib_byteswap

				value = std::byteswap(value);

				#else

                value = CommonSecurity::ByteSwap::byteswap(value);

				#endif

				std::memcpy(output, &value, sizeof(IntegerType));
                output += sizeof(IntegerType);
            }
        }
        else
        {
            throw std::runtime_error("");
        }
    }

	#endif

	//Function to left rotate (number) by (count) bits
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	inline IntegerType Binary_LeftRotateMove( IntegerType NumberValue, IntegerType RotationCount )
	{
		constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;
		const auto	   MoveFromRemainder = RotationCount % BitDigits;
		if ( MoveFromRemainder > 0 )
		{
			return static_cast<IntegerType>( static_cast<IntegerType>( NumberValue << MoveFromRemainder ) | static_cast<IntegerType>( NumberValue >> ( BitDigits - MoveFromRemainder ) ) );
		}
		else if ( MoveFromRemainder == 0 )
		{
			return NumberValue;
		}
		else
		{
			return std::rotl( NumberValue, MoveFromRemainder );
		}
	}

	//Function to right rotate (number) by (count) bits
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	inline IntegerType Binary_RightRotateMove( IntegerType NumberValue, IntegerType RotationCount )
	{
		constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;
		const auto	   MoveFromRemainder = RotationCount % BitDigits;
		if ( MoveFromRemainder > 0 )
		{
			return static_cast<IntegerType>( static_cast<IntegerType>( NumberValue >> MoveFromRemainder ) | static_cast<IntegerType>( NumberValue << ( BitDigits - MoveFromRemainder ) ) );
		}
		else if ( MoveFromRemainder == 0 )
		{
			return NumberValue;
		}
		else
		{
			return std::rotr( NumberValue, MoveFromRemainder );
		}
	}

	//Function to left shift (number) by (count) bits
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	inline IntegerType Binary_LeftShift( IntegerType NumberValue, IntegerType MoveShiftCount, bool AllowOverBitwise = false )
	{
		constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;

		if ( MoveShiftCount == 0 )
		{
			return NumberValue;
		}
		else if ( MoveShiftCount < 0 )
		{
			return Binary_LeftShift<IntegerType>( NumberValue, ~MoveShiftCount + 1 );
		}
		else if ( MoveShiftCount > 0 )
		{
			if ( MoveShiftCount > BitDigits && AllowOverBitwise == false )
			{
				MoveShiftCount = BitDigits;
			}
			return static_cast<IntegerType>( NumberValue << MoveShiftCount );
		}
	}

	//Function to right shift (number) by (count) bits
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	inline IntegerType Binary_RightShift( IntegerType NumberValue, IntegerType MoveShiftCount, bool AllowOverBitwise = false )
	{
		constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;

		if ( MoveShiftCount == 0 )
		{
			return NumberValue;
		}
		else if ( MoveShiftCount < 0 )
		{
			return Binary_LeftShift<IntegerType>( NumberValue, ~MoveShiftCount + 1 );
		}
		else if ( MoveShiftCount > 0 )
		{
			if ( MoveShiftCount > BitDigits && AllowOverBitwise == false )
			{
				MoveShiftCount = BitDigits;
			}
			return static_cast<IntegerType>( NumberValue >> MoveShiftCount );
		}
	}

	template <size_t BitDigits>
	inline void BinarySet_LeftRotateMove( std::bitset<BitDigits>& binaryData, size_t RotationCount )
	{
		const size_t MoveFromRemainder = RotationCount % BitDigits;
		( ( binaryData << RotationCount ) | ( binaryData >> ( BitDigits - MoveFromRemainder ) ) );
	}

	template <size_t BitDigits>
	inline void BinarySet_RightRotateMove( std::bitset<BitDigits>& binaryData, size_t RotationCount )
	{
		const size_t MoveFromRemainder = RotationCount % BitDigits;
		( ( binaryData >> RotationCount ) | ( binaryData << ( BitDigits - MoveFromRemainder ) ) );
	}

	/*
		Reference source code: https://github.com/Reputeless/Xoshiro-cpp/
		https://gist.github.com/wreien/442e6f89f125f9b4a9919299a7536fd5
		Rudimentary C++20 xoshiro256** uniform random bit generator implementation
	*/
	namespace RNG_Xoshiro
	{
		// An implementation of xoshiro256** (https://vigna.di.unimi.it/xorshift/)
		// wrapped to fit the C++11 RandomNumberGenerator requirements.
		// This allows us to use it with all the other facilities in <random>.
		//
		// Credits go to David Blackman and Sebastiano Vigna.
		//
		// TODO: make generic? (parameterise scrambler/width/hyperparameters/etc.)
		// Not as easy to do nicely as it might sound,
		// and this as it is is good enough for my purposes.
		struct xoshiro256
		{
			static constexpr int num_state_words = 4;
			using state_type = std::uint64_t[ num_state_words ];
			using result_type = std::uint64_t;

			// cannot initialize with an all-zero state
			constexpr xoshiro256() noexcept : state { 12, 34, 56, 78 } {}

			// using SplitMix64 generator to initialize the state;
			// using a different generator helps prevent seed correlation
			explicit constexpr xoshiro256( result_type s ) noexcept
			{
				auto splitmix64 = [ x = s ]() mutable {
					auto z = ( x += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;
					return z ^ ( z >> 31 );
				};
				std::ranges::generate( state, splitmix64 );
			}

			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> ) explicit constexpr xoshiro256( SeedSeq& q )
			{
				std::uint32_t temp_state[ num_state_words * 2 ];
				q.generate( std::begin( temp_state ), std::end( temp_state ) );
				for ( int i = 0; i < num_state_words; ++i )
				{
					state[ i ] = temp_state[ i * 2 ];
					state[ i ] <<= 32;
					state[ i ] |= temp_state[ i * 2 + 1 ];
				}
			}

			constexpr void seed() noexcept
			{
				*this = xoshiro256();
			}
			constexpr void seed( result_type s ) noexcept
			{
				*this = xoshiro256( s );
			}
			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> ) constexpr void seed( SeedSeq& q )
			{
				*this = xoshiro256( q );
			}

			static constexpr result_type min() noexcept
			{
				return std::numeric_limits<result_type>::min();
			}
			static constexpr result_type max() noexcept
			{
				return std::numeric_limits<result_type>::max();
			}

			constexpr result_type operator()() noexcept
			{
				// xorshiro256+:
				// const auto result = state[0] + state[3];\
				// xorshiro256++:
				// const auto result = std::rotl(state[0] + state[3], 23) + state[0];

				// xorshiro256**:
				const auto result = std::rotl( state[ 1 ] * 5, 7 ) * 9;
				const auto t = state[ 1 ] << 17;

				state[ 2 ] ^= state[ 0 ];
				state[ 3 ] ^= state[ 1 ];
				state[ 1 ] ^= state[ 2 ];
				state[ 0 ] ^= state[ 3 ];

				state[ 2 ] ^= t;
				state[ 3 ] = std::rotl( state[ 3 ], 45 );

				return result;
			}

			constexpr void discard( unsigned long long z ) noexcept
			{
				while ( z-- )
					operator()();
			}

			// jump 2^128 steps;
			// use it to create 2^128 non-overlapping sequences for parallel computations
			constexpr void jump() noexcept
			{
				constexpr std::uint64_t jump_table[] = {
					0x180ec6d33cfd0aba,
					0xd5a61266f0c9392c,
					0xa9582618e03fc9aa,
					0x39abdc4529b1661c,
				};

				state_type s {};
				for ( int i = 0; i < std::ssize( jump_table ); i++ )
				{
					for ( int b = 0; b < 64; b++ )
					{
						if ( jump_table[ i ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							s[ 0 ] ^= state[ 0 ];
							s[ 1 ] ^= state[ 1 ];
							s[ 2 ] ^= state[ 2 ];
							s[ 3 ] ^= state[ 3 ];
						}
						operator()();
					}
				}

				state[ 0 ] = s[ 0 ];
				state[ 1 ] = s[ 1 ];
				state[ 2 ] = s[ 2 ];
				state[ 3 ] = s[ 3 ];
			}

			// jump 2^192 steps;
			// use it to create 2^64 starting points,
			// from which jump() can create 2^64 non-overlapping sequences
			constexpr void long_jump() noexcept
			{
				constexpr std::uint64_t long_jump_table[] = {
					0x76e15d3efefdcbbf,
					0xc5004e441c522fb3,
					0x77710069854ee241,
					0x39109bb02acbe635,
				};

				state_type s {};
				for ( int i = 0; i < std::ssize( long_jump_table ); i++ )
				{
					for ( int b = 0; b < 64; b++ )
					{
						if ( long_jump_table[ i ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							s[ 0 ] ^= state[ 0 ];
							s[ 1 ] ^= state[ 1 ];
							s[ 2 ] ^= state[ 2 ];
							s[ 3 ] ^= state[ 3 ];
						}
						operator()();
					}
				}

				state[ 0 ] = s[ 0 ];
				state[ 1 ] = s[ 1 ];
				state[ 2 ] = s[ 2 ];
				state[ 3 ] = s[ 3 ];
			}

			constexpr bool operator==( const xoshiro256& ) const noexcept = default;

			template <typename CharT, typename Traits>
			friend std::basic_ostream<CharT, Traits>& operator<<( std::basic_ostream<CharT, Traits>& os, const xoshiro256& e )
			{
				os << e.state[ 0 ];
				for ( int i = 1; i < num_state_words; ++i )
				{
					os.put( os.widen( ' ' ) );
					os << e.state[ i ];
				}
				return os;
			}

			template <typename CharT, typename Traits>
			friend std::basic_istream<CharT, Traits&> operator>>( std::basic_istream<CharT, Traits>& is, xoshiro256& e )
			{
				xoshiro256 r;
				// TODO: what if ' ' is not considered whitespace?
				// Maybe more appropriate is to `.get` each space
				for ( auto& s : r.state )
					is >> s;
				if ( is )
					e = r;
				return is;
			}

		private:
			state_type state;
		};

	}  // namespace RNG_Xoshiro

	namespace ShufflingRangeDataDetails
	{
		//将一个统一的随机数发生器包装成一个随机数发生器
		//Wrap a Uniform random number generator as an Random number generator
		template <class DifferenceType, class URNG_Type>
		requires std::uniform_random_bit_generator<std::remove_reference_t<URNG_Type>>
		class WARP_URNG_AS_AN_RNG
		{

		public:

			using Type0 = std::make_unsigned_t<DifferenceType>;
			using Type1 = typename URNG_Type::result_type;

			using UnsignedDifferenceType = std::conditional_t<sizeof( Type1 ) < sizeof( Type0 ), Type0, Type1>;

			explicit WARP_URNG_AS_AN_RNG( URNG_Type& _Func ) : URNG_TypeReference( _Func ), RandomBits( CHAR_BIT * sizeof( UnsignedDifferenceType ) ), RandomBitMask( UnsignedDifferenceType( -1 ) )
			{
				for ( ; ( URNG_Type::max )() - ( URNG_Type::min )() < RandomBitMask; RandomBitMask >>= 1 )
				{
					--RandomBits;
				}
			}

			// adapt URNG_Type closed range to [0, DifferenceTypeIndex)
			DifferenceType operator()( DifferenceType DifferenceTypeIndex )
			{
				for ( ;; )
				{											  // try a sample random value
					UnsignedDifferenceType ResultObject = 0;  // random bits
					UnsignedDifferenceType MaskInRange = 0;	  // 2^N - 1, ResultObject is within [0, MaskInRange]

					while ( MaskInRange < UnsignedDifferenceType( DifferenceTypeIndex - 1 ) )
					{									  // need more random bits
						ResultObject <<= RandomBits - 1;  // avoid full shift
						ResultObject <<= 1;
						ResultObject |= FindBits();
						MaskInRange <<= RandomBits - 1;	 // avoid full shift
						MaskInRange <<= 1;
						MaskInRange |= RandomBitMask;
					}

					// ResultObject is [0, MaskInRange], DifferenceTypeIndex - 1 <= MaskInRange, return if unbiased
					if ( ResultObject / DifferenceTypeIndex < MaskInRange / DifferenceTypeIndex || MaskInRange % DifferenceTypeIndex == UnsignedDifferenceType( DifferenceTypeIndex - 1 ) )
					{
						return static_cast<DifferenceType>( ResultObject % DifferenceTypeIndex );
					}
				}
			}

			UnsignedDifferenceType FindAllBits()
			{
				UnsignedDifferenceType ResultObject = 0;

				for ( size_t NumberIndex = 0; NumberIndex < CHAR_BIT * sizeof( UnsignedDifferenceType ); NumberIndex += RandomBits )
				{									  // don't mask away any bits
					ResultObject <<= RandomBits - 1;  // avoid full shift
					ResultObject <<= 1;
					ResultObject |= FindBits();
				}

				return ResultObject;
			}

			WARP_URNG_AS_AN_RNG( const WARP_URNG_AS_AN_RNG& ) = delete;
			WARP_URNG_AS_AN_RNG& operator=( const WARP_URNG_AS_AN_RNG& ) = delete;

		private:

			// return a random value within [0, RandomBitMask]
			UnsignedDifferenceType FindBits()
			{
				for ( ;; )
				{  // repeat until random value is in range
					UnsignedDifferenceType _Val = URNG_TypeReference() - ( URNG_Type::min )();

					if ( _Val <= RandomBitMask )
					{
						return _Val;
					}
				}
			}

			URNG_Type&			   URNG_TypeReference;	// reference to URNG
			size_t				   RandomBits;			// number of random bits generated by _Get_bits()
			UnsignedDifferenceType RandomBitMask;		// 2^RandomBits - 1
		};

		// uniform integer distribution
		template <class IntegerType>
		requires std::is_integral_v<IntegerType>
		class UniformInteger
		{
		public:
			using result_type = IntegerType;

			// parameter package
			struct param_type
			{
				using distribution_type = UniformInteger;

				param_type()
				{
					InitialParamType( 0, 9 );
				}

				explicit param_type( result_type MinimumValue0, result_type MaximumValue0 = 9 )
				{
					InitialParamType( MinimumValue0, MaximumValue0 );
				}

				[[nodiscard]] bool operator==( const param_type& _Right ) const
				{
					return MinimumValue == _Right.MinimumValue && MaximumValue == _Right.MaximumValue;
				}

				[[nodiscard]] bool operator!=( const param_type& _Right ) const
				{
					return !( *this == _Right );
				}

				[[nodiscard]] result_type a() const
				{
					return MinimumValue;
				}

				[[nodiscard]] result_type b() const
				{
					return MaximumValue;
				}

				void InitialParamType( IntegerType MinimumValue0, IntegerType MaximumValue0 )
				{	// set internal state

					my_cpp2020_assert( MinimumValue0 <= MaximumValue0, "invalid min and max arguments for uniform_int", std::source_location::current() );

					MinimumValue = MinimumValue0;
					MaximumValue = MaximumValue0;
				}

				result_type MinimumValue;
				result_type MaximumValue;
			};

			UniformInteger() : _ParamObject_( 0, 9 ) {}

			explicit UniformInteger( IntegerType MinimumValue0, IntegerType MaximumValue0 = 9 ) : _ParamObject_( MinimumValue0, MaximumValue0 ) {}

			explicit UniformInteger( const param_type& _ParamObject_0 ) : _ParamObject_( _ParamObject_0 ) {}

			[[nodiscard]] result_type a() const
			{
				return _ParamObject_.a();
			}

			[[nodiscard]] result_type b() const
			{
				return _ParamObject_.b();
			}

			[[nodiscard]] param_type param() const
			{
				return _ParamObject_;
			}

			void param( const param_type& _ParamObject_0 )
			{  // set parameter package
				_ParamObject_ = _ParamObject_0;
			}

			[[nodiscard]] result_type( min )() const
			{
				return _ParamObject_.MinimumValue;
			}

			[[nodiscard]] result_type( max )() const
			{
				return _ParamObject_.MaximumValue;
			}

			void reset() {}	 // clear internal state

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject ) const
			{
				return RND_CalculationValue( RNG_EngineObject, _ParamObject_.MinimumValue, _ParamObject_.MaximumValue );
			}

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject, const param_type& _ParamObject_0 ) const
			{
				return RND_CalculationValue( RNG_EngineObject, _ParamObject_0.MinimumValue, _ParamObject_0.MaximumValue );
			}

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject, result_type _Nx ) const
			{
				return RND_CalculationValue( RNG_EngineObject, 0, _Nx - 1 );
			}

			template <class _Elem, class _Traits>
			std::basic_istream<_Elem, _Traits>& Read( std::basic_istream<_Elem, _Traits>& Istr )
			{  // read state from Istr
				IntegerType MinimumValue0;
				IntegerType MaximumValue0;
				Istr >> MinimumValue0 >> MaximumValue0;
				_ParamObject_.InitialParamType( MinimumValue0, MaximumValue0 );
				return Istr;
			}

			// write state to Ostr
			template <class _Elem, class _Traits>
			std::basic_ostream<_Elem, _Traits>& Write( std::basic_ostream<_Elem, _Traits>& Ostr ) const
			{
				return Ostr << _ParamObject_.MinimumValue << ' ' << _ParamObject_.MaximumValue;
			}

		private:

			using UnsignedIntegerType = std::make_unsigned_t<IntegerType>;

			// compute next value in range [MinimumValue, MaximumValue]
			template <class RandomNumberGenerator_EngineType>
			result_type RND_CalculationValue( RandomNumberGenerator_EngineType& RNG_EngineObject, IntegerType MinimumValue, IntegerType MaximumValue ) const
			{
				WARP_URNG_AS_AN_RNG<UnsignedIntegerType, RandomNumberGenerator_EngineType> _Generator( RNG_EngineObject );

				const UnsignedIntegerType _UnsignedMinimunValue_ = AdjustNumber( static_cast<UnsignedIntegerType>( MinimumValue ) );
				const UnsignedIntegerType _UnsignedMaximunValue_ = AdjustNumber( static_cast<UnsignedIntegerType>( MaximumValue ) );

				UnsignedIntegerType UnsignedIntegerResult;

				if ( _UnsignedMaximunValue_ - _UnsignedMinimunValue_ == static_cast<UnsignedIntegerType>( -1 ) )
				{
					UnsignedIntegerResult = static_cast<UnsignedIntegerType>( _Generator.FindAllBits() );
				}
				else
				{
					UnsignedIntegerResult = static_cast<UnsignedIntegerType>( _Generator( static_cast<UnsignedIntegerType>( _UnsignedMaximunValue_ - _UnsignedMinimunValue_ + 1 ) ) );
				}

				return static_cast<IntegerType>( AdjustNumber( static_cast<UnsignedIntegerType>( UnsignedIntegerResult + _UnsignedMinimunValue_ ) ) );
			}

			// convert signed ranges to unsigned ranges and vice versa
			static UnsignedIntegerType AdjustNumber( UnsignedIntegerType UnsignedInegerValue )
			{
				if constexpr ( std::is_signed_v<IntegerType> )
				{
					const UnsignedIntegerType NumberAdjuster = ( static_cast<UnsignedIntegerType>( -1 ) >> 1 ) + 1;	 // 2^(N-1)

					if ( UnsignedInegerValue < NumberAdjuster )
					{
						return static_cast<UnsignedIntegerType>( UnsignedInegerValue + NumberAdjuster );
					}
					else
					{
						return static_cast<UnsignedIntegerType>( UnsignedInegerValue - NumberAdjuster );
					}
				}
				else
				{  // IntegerType is already unsigned, do nothing
					return UnsignedInegerValue;
				}
			}

			param_type _ParamObject_;
		};

		// read state from _Istr
		template <class _Elem, class _Traits, class Type>
		std::basic_istream<_Elem, _Traits>& operator>>(std::basic_istream<_Elem, _Traits>& _Istr, UniformInteger<Type>& _Dist)
		{
			return _Dist.Read(_Istr);
		}

		// write state to _Ostr
		template <class _Elem, class _Traits, class Type>
		std::basic_ostream<_Elem, _Traits>& operator<<(std::basic_ostream<_Elem, _Traits>& _Ostr, const UniformInteger<Type>& _Dist)
		{
			return _Dist.Write(_Ostr);
		}

		// uniform integer distribution
		template <class IntegerType>
		class UniformIntegerDistribution : public UniformInteger<IntegerType>
		{

		public:

			using _BaseType = UniformInteger<IntegerType>;
			using _ParamBaseType = typename _BaseType::param_type;
			using result_type = typename _BaseType::result_type;

			// parameter package
			struct param_type : _ParamBaseType
			{
				using distribution_type = UniformIntegerDistribution;

				param_type() : _ParamBaseType(0, (std::numeric_limits<IntegerType>::max)()) {}

				explicit param_type(result_type _Min0, result_type _Max0 = (std::numeric_limits<IntegerType>::max)()) : _ParamBaseType(_Min0, _Max0) {}

				param_type(const _ParamBaseType& _Right) : _ParamBaseType(_Right) {}
			};

			UniformIntegerDistribution() : _BaseType(0, (std::numeric_limits<IntegerType>::max)()) {}

			explicit UniformIntegerDistribution(IntegerType _Min0, IntegerType _Max0 = (std::numeric_limits<IntegerType>::max)()) : _BaseType(_Min0, _Max0) {}

			explicit UniformIntegerDistribution(const param_type& _ParamObject) : _BaseType(_ParamObject) {}
		};
	}

	template<typename RNG_Type>
	requires std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
	struct PseudoRandomNumberEngine
	{
		class SimpleGenerator
		{

		private:

			static FourByte _seedNumber;
	
		public:

			explicit SimpleGenerator()
			{
				_seedNumber = 1;
			}

			SimpleGenerator( int seedNumber )
			{
				_seedNumber = seedNumber;
			}

			~SimpleGenerator()
			{
				_seedNumber = 0;
			}

			void seed( int seedNumber )
			{
				_seedNumber = static_cast<FourByte>( seedNumber & 0x7fffffffU );
			}

			int number( void )
			{
				//1103515245 is magic number
				_seedNumber = ( _seedNumber * 1103515245U + 12345U ) & 0x7fffffffU;
				return static_cast<signed int>( _seedNumber );
			}

			SimpleGenerator(SimpleGenerator& _object) = delete;
			SimpleGenerator& operator=(const SimpleGenerator& _object) = delete;
		};

		//Whether the pseudo-random is initialized by seed
		inline static bool PseudoRandomIsInitialBySeed = false;
		inline static RNG_Type random_generator;

		//C++ 初始化伪随机数的种子
		//C++ Initialize the seed of the pseudo-random number
		template <typename IntegerType>
		requires std::is_integral_v<IntegerType>
		void InitialBySeed( IntegerType seedNumber, bool ResetFlag = false )
		{
			if ( ResetFlag == true )
			{
				PseudoRandomIsInitialBySeed = false;
			}

			if ( PseudoRandomIsInitialBySeed == false )
			{
				random_generator.seed( seedNumber );
				PseudoRandomIsInitialBySeed = true;
			}
		}

		//C++ 初始化伪随机数的种子
		//C++ Initialize the seed of the pseudo-random number
		void InitialBySeed( std::seed_seq seedNumberSequence, bool ResetFlag = false )
		{
			if ( ResetFlag == true )
			{
				PseudoRandomIsInitialBySeed = false;
			}

			if ( PseudoRandomIsInitialBySeed == false )
			{
				random_generator.seed( seedNumberSequence );
				PseudoRandomIsInitialBySeed = true;
			}
		}


		//C++ 生成伪随机数
		//C++ generates random numbers
		template <typename IntegerType>
		requires std::is_integral_v<IntegerType>
		IntegerType GenerateNumber( IntegerType minimum, IntegerType maximum )
		{
			if ( PseudoRandomIsInitialBySeed == true )
			{
				static UniformIntegerDistribution<IntegerType> number_distribution( minimum, maximum );
				return number_distribution( random_generator );
			}
		}
	};

	//针对容器内容进行洗牌
	//Shuffling against container content
	struct UnifromShuffleRangeImplement
	{
		//RNG is random number generator
		template<std::random_access_iterator RandomAccessIteratorType, std::sentinel_for<RandomAccessIteratorType> SentinelIteratorType, typename RNG_Type>
		requires std::permutable<RandomAccessIteratorType> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		RandomAccessIteratorType operator()(RandomAccessIteratorType first, SentinelIteratorType last, RNG_Type&& functionRNG)
		{
			using iterator_difference_t = std::iter_difference_t<RandomAccessIteratorType>;
			using number_distribution_t = ShufflingRangeDataDetails::UniformIntegerDistribution<iterator_difference_t>;
			using number_distribution_param_t = typename number_distribution_t::param_type;

			number_distribution_t number_distribution_object;
			const auto distance { last - first };

			for(iterator_difference_t index{1}; index < distance; ++index)
			{
				std::ranges::iter_swap(first + index, first + number_distribution_object(functionRNG, number_distribution_param_t(0, index)));
			}
			return std::ranges::next(first, last);
		}

		template <std::ranges::random_access_range RandomAccessRangeType, typename RNG_Type>
		requires std::permutable<std::ranges::iterator_t<RandomAccessRangeType>> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		std::ranges::borrowed_iterator_t<RandomAccessRangeType> operator()( RandomAccessRangeType&& range, RNG_Type&& functionRNG )
		{
			return this->operator()( std::ranges::begin( range ), std::ranges::end( range ), std::forward<RNG_Type>( functionRNG ) );
		}

		template<std::random_access_iterator RandomAccessIteratorType, typename RNG_Type>
		requires std::permutable<RandomAccessIteratorType> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		void KnuthShuffle(RandomAccessIteratorType begin, RandomAccessIteratorType end, RNG_Type&& functionRNG)
		{
			for ( std::iter_difference_t<RandomAccessIteratorType> difference_value = end - begin - 1; difference_value >= 1; --difference_value )
			{
				std::size_t iterator_offset = functionRNG() % ( difference_value + 1 );
				if ( iterator_offset != difference_value )
				{
					std::iter_swap( begin + iterator_offset, begin + difference_value );
				}
			}
		}

		template<std::ranges::random_access_range RandomAccessRangeType, typename RNG_Type>
		requires std::permutable<std::ranges::iterator_t<RandomAccessRangeType>> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		void KnuthShuffle(RandomAccessRangeType&& range, RNG_Type&& functionRNG)
		{
			return (*this).KnuthShuffle(std::ranges::begin(range), std::ranges::end( range ), std::forward<RNG_Type>( functionRNG ));
		}
	};

	inline UnifromShuffleRangeImplement ShuffleRangeData;

	template < typename IntegerType >
	requires std::is_integral_v<IntegerType>
	std::vector<IntegerType> VectorContainerDataWithRandomAccess( IntegerType randomSeed, const IntegerType needAccessCount, const std::vector<IntegerType>& inputDataContainer )
	{
		IntegerType container_size = inputDataContainer.size();

		if ( container_size == 0 )
		{
			return std::vector<IntegerType>{};
		}
		else
		{
			//复制过的容器
			//Copied containers
			std::vector<IntegerType> copiedContainer;

			//对源容器的内容进行复制一次，然后三次插入原容器的内容到复制的容器
			//The contents of the source container are copied once and then the contents of the original container are inserted three times into the copied container
			std::copy( inputDataContainer.begin(), inputDataContainer.end(), std::back_inserter( copiedContainer ) );
			copiedContainer.insert( copiedContainer.end(), inputDataContainer.begin(), inputDataContainer.end() );
			copiedContainer.insert( copiedContainer.end(), inputDataContainer.begin(), inputDataContainer.end() );
			copiedContainer.insert( copiedContainer.end(), inputDataContainer.begin(), inputDataContainer.end() );

			IntegerType copied_container_size = copiedContainer.size();

			//copied_container_size == container.size() * 4
			IntegerType firstIndex = 0;
			IntegerType lastIndex = container_size * 4 - 1;

			//copied_container_size * 4 / 2  == container.size() * 2
			IntegerType middleIndex = container_size * 2;
			IntegerType middleIndex2 = container_size * 2;

			//生成的乱序的容器数据
			//Generated disordered container data
			std::vector<IntegerType> outputRandomDataContainer;

			//伪随机数
			//Pseudo random number
			IntegerType				 pseudoRandomNumber = 0;
			std::vector<IntegerType> pseudoRandomNumbers;

			PseudoRandomNumberEngine<std::mt19937> PRNE;
			PRNE.InitialBySeed<IntegerType>( randomSeed, false );

			std::mt19937 random_number_generator { randomSeed };

			ShuffleRangeData(copiedContainer, random_number_generator);

			for ( IntegerType index = 0; index < copied_container_size; index++ )
			{
				pseudoRandomNumber = PRNE.GenerateNumber<IntegerType>( firstIndex, lastIndex );
				pseudoRandomNumbers.push_back( pseudoRandomNumber );
			}

			//运行循环次数
			//RTNOC (Run The Number Of Cycles)
			const IntegerType RTONC = std::numeric_limits<IntegerType>::max();

			//被访问的数据
			//Accessed data
			IntegerType accessedData = 0;

			//需要减少几倍的容器访问次数
			//Need to reduce the number of container accesses by a factor of several
			IntegerType OxO = 1;

			//这一轮进行容器访问的剩余次数
			//Remaining number of container accesses performed this round
			IntegerType accessRemaining = needAccessCount;

			//进入无限循环
			//Enter the infinite loop
			for ( IntegerType loopCount = 0; loopCount < RTONC; ++loopCount )
			{
				IntegerType currentElement = copiedContainer.at( middleIndex );
				IntegerType currentElement2 = copiedContainer.at( middleIndex2 );

				if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
				{
					pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] < pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex ] : pseudoRandomNumbers[ middleIndex2 ];

					if ( pseudoRandomNumber % 13 == 0 )
					{
						random_number_generator.seed(pseudoRandomNumbers[ middleIndex ]);
						ShuffleRangeData(copiedContainer.begin(), copiedContainer.end(), random_number_generator);
					}
					else if ( pseudoRandomNumber % 15 == 0 )
					{
						random_number_generator.seed(pseudoRandomNumbers[ middleIndex2 ]);
						ShuffleRangeData(copiedContainer.begin(), copiedContainer.end(), random_number_generator);
					}
				}

				//当前已经访问到容器数据尾部
				//The tail of the container data is currently being accessed
				if ( middleIndex == firstIndex )
				{
					outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement );
					middleIndex = copied_container_size / 2;
				}

				if ( middleIndex2 == firstIndex )
				{
					outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement2 );
					middleIndex2 = copied_container_size / 2;
				}

				//当前已经访问到容器数据首部
				//The container data head is currently being accessed
				if ( middleIndex == lastIndex )
				{
					outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement );
					middleIndex = copied_container_size / 2;
				}

				if ( middleIndex2 == lastIndex )
				{
					outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement2 );
					middleIndex2 = copied_container_size / 2;
				}

				//当前的这一轮容器的访问次数已使用完毕
				//The current round of container accesses has been used up
				if ( accessRemaining == 0 )
				{
					//继续下一轮容器访问
					//Continue to next round of container access
					if ( OxO == 1 )
					{
						accessRemaining = needAccessCount;
					}
					OxO *= 2;
					accessRemaining /= OxO;

					//输出容器的元素数量是否等于输入容器的元素数量的四倍？
					//Is the number of elements of the output container equal to four times the number of elements of the input container?
					if ( outputRandomDataContainer.size() == inputDataContainer.size() * 4 )
					{
						//退出无限循环
						//Exit the infinite loop
						break;
					}

					if ( accessRemaining == 0 )
					{
						continue;
					}
				}
				else
				{
					//输出容器的元素数量是否不等于输入容器的元素数量的两倍？
					//Is the number of elements of the output container not equal to twice the number of elements of the input container?
					if ( outputRandomDataContainer.size() != inputDataContainer.size() * 4 || outputRandomDataContainer.size() < inputDataContainer.size() * 4 )
					{
						outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement );
					}
					if ( outputRandomDataContainer.size() != inputDataContainer.size() * 4 || outputRandomDataContainer.size() < inputDataContainer.size() * 4 )
					{
						outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement2 );
					}
				}

				//当前这个数是奇数还是偶数
				//Is the current number odd or is it even?
				if ( ( currentElement & 1 ) != 0 )
				{
					if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
					{
						pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] > pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex2 ] : pseudoRandomNumbers[ middleIndex ];
						middleIndex -= pseudoRandomNumber;
					}

					//当前访问超出范围
					//The current access is out of range?
					if ( ( middleIndex > pseudoRandomNumbers.size() ) || 0 < middleIndex )
					{
						middleIndex = PRNE.GenerateNumber<IntegerType>( firstIndex, lastIndex );
					}
					else
					{
						if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
						{
							accessRemaining = 0;
							continue;
						}
						currentElement = copiedContainer[ middleIndex ];
						accessedData = currentElement;
						outputRandomDataContainer.insert( outputRandomDataContainer.begin(), accessedData );
					}

					//当前这个数是奇数还是偶数
					//Is the current number odd or is it even?
					if ( ( accessRemaining & 1 ) != 0 )
					{
						accessRemaining--;

						if ( pseudoRandomNumber % 7 == 0 )
						{
							//向左旋转容器中的元素位置
							//Rotate the position of the elements in the container to the left (C++ 2020)
							std::ranges::rotate( copiedContainer, copiedContainer.begin() + accessedData );

							if ( pseudoRandomNumber % 5 == 0 )
							{
								random_number_generator.seed(randomSeed);
								ShuffleRangeData(copiedContainer.begin(), copiedContainer.end(), random_number_generator);
							}
						}
					}
					else
					{
						if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
						{
							pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] == pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex2 ] : pseudoRandomNumbers[ middleIndex ];
							middleIndex += pseudoRandomNumber;
						}

						//当前访问超出范围
						//The current access is out of range?
						if ( ( middleIndex > pseudoRandomNumbers.size() ) || 0 < middleIndex )
						{
							middleIndex = ShuffleRangeData<IntegerType>( firstIndex, lastIndex );
						}
						else
						{
							if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
							{
								accessRemaining = 0;
								continue;
							}
							currentElement = copiedContainer[ middleIndex ];
							accessedData = currentElement;
							outputRandomDataContainer.insert( outputRandomDataContainer.begin(), accessedData );
						}

						if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
						{
							accessRemaining = 0;
							continue;
						}

						accessRemaining--;

						if ( pseudoRandomNumber % 1 == 0 )
						{
							//向右旋转容器中的元素位置
							//Rotate the position of the elements in the container to the right (C++ 2020)
							std::ranges::rotate( copiedContainer, copiedContainer.end() - accessedData );

							if ( pseudoRandomNumber % 3 == 0 )
							{
								random_number_generator.seed(randomSeed);
								ShuffleRangeData(copiedContainer.begin(), copiedContainer.end(), random_number_generator);
							}
						}
					}
				}
				else
				{
					middleIndex = pseudoRandomNumber;
				}

				//当前这个数是偶数还是奇数
				//Is the current number even or odd?
				if ( ( currentElement2 & 1 ) == 0 )
				{
					if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
					{
						pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] == pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex ] : pseudoRandomNumbers[ middleIndex2 ];
						middleIndex2 += pseudoRandomNumber;
					}

					//当前访问超出范围
					//The current access is out of range?
					if ( ( middleIndex2 > pseudoRandomNumbers.size() ) || 0 < middleIndex2 )
					{
						middleIndex2 = PRNE.GenerateNumber<IntegerType>( firstIndex, lastIndex );
					}
					else
					{
						if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
						{
							accessRemaining = 0;
							continue;
						}
						currentElement2 = copiedContainer[ middleIndex2 ];
						accessedData = currentElement2;
						outputRandomDataContainer.insert( outputRandomDataContainer.begin(), accessedData );
					}

					//当前这个数是偶数还是奇数
					//Is the current number even or odd?
					if ( ( accessRemaining & 1 ) == 0 )
					{
						accessRemaining--;

						if ( pseudoRandomNumber % 2 == 0 )
						{
							//向右旋转容器中的元素位置
							//Rotate the position of the elements in the container to the right (C++ 2020)
							std::ranges::rotate( copiedContainer, copiedContainer.end() - accessedData );

							if ( pseudoRandomNumber % 8 == 0 )
							{
								ShuffleRangeData<IntegerType, IntegerType>( randomSeed, copiedContainer );
							}
						}
					}
					else
					{
						if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
						{
							pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] < pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex2 ] : pseudoRandomNumbers[ middleIndex ];
							middleIndex2 -= pseudoRandomNumber;
						}

						//当前访问超出范围
						//The current access is out of range?
						if ( ( middleIndex2 > pseudoRandomNumbers.size() ) || 0 < middleIndex2 )
						{
							middleIndex2 = PRNE.GenerateNumber<IntegerType>( firstIndex, lastIndex );
						}
						else
						{
							if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
							{
								accessRemaining = 0;
								continue;
							}
							currentElement2 = copiedContainer[ middleIndex2 ];
							accessedData = currentElement2;
							outputRandomDataContainer.insert( outputRandomDataContainer.begin(), accessedData );
						}

						accessRemaining--;

						if ( pseudoRandomNumber % 4 == 0 )
						{
							//向左旋转容器中的元素位置
							//Rotate the position of the elements in the container to the left (C++ 2020)
							std::ranges::rotate( copiedContainer, copiedContainer.begin() + accessedData );

							if ( pseudoRandomNumber % 6 == 0 )
							{
								ShuffleRangeData<IntegerType, IntegerType>( randomSeed, copiedContainer );
							}
						}
					}
				}
				else
				{
					middleIndex2 = pseudoRandomNumber;
				}

				pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] > pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex ] : pseudoRandomNumbers[ middleIndex2 ];

				if ( pseudoRandomNumber % 10 == 0 )
				{
					//反转容器中的元素位置
					//Reverses the position of the elements in the container (C++ 2020)
					std::ranges::reverse( copiedContainer.begin(), copiedContainer.end() );

					if ( pseudoRandomNumber % 12 == 0 )
					{
						ShuffleRangeData<IntegerType, IntegerType>( randomSeed, copiedContainer );
					}
				}
			}

			return outputRandomDataContainer;
		}
	}
}  // namespace CommonSecurity

namespace Cryptograph
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

	inline void BitCirculation_Left( std::byte& Data, const std::byte& Key, unsigned int move_bit )
	{
		Data = ( Data << move_bit ) | ( Data >> ( 8 - move_bit ) );
		//Key = ( Key << move_bit ) | ( Key >> ( 8 - move_bit ) );
	}

	inline void BitCirculation_Right( std::byte& Data, const std::byte& Key, unsigned int move_bit )
	{
		Data = ( Data >> move_bit ) | ( Data << ( 8 - move_bit ) );
		//Key = ( Key >> move_bit ) | ( Key << ( 8 - move_bit ) );
	}

	inline void BitToggle( std::byte& Data, unsigned int position )
	{
		constexpr std::byte Mask{ 1 };

		Data ^= ( Mask << position );
	}
}  // namespace Cryptograph

namespace Cryptograph::Bitset
{
	template<std::size_t BitsetSize>
	inline void Exclusive_OR(std::bitset<BitsetSize>& bits, const std::bitset<BitsetSize>& other_bits)
	{
		bits ^= other_bits;
	}

	template<std::size_t BitsetSize>
	inline void Equivalence_OR(std::bitset<BitsetSize>& bits, const std::bitset<BitsetSize>& other_bits)
	{
		bits ^= other_bits;
		bits = ~bits;
	}

	template<size_t BitsetSize>
	inline void BitLeftCircularShift(const std::bitset<BitsetSize>& bits, std::size_t shift_count, std::bitset<BitsetSize>& result_bits)
	{
					shift_count %= BitsetSize;  // Limit count to range [0,N)
					auto part_bits = bits << shift_count;
					auto part2_bits = bits >> (BitsetSize - shift_count);
					result_bits = part_bits | part2_bits;
		/*
			  result_bits = (bits << count | bits >> (BitsetSize - count));
			The shifted bits ^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^ The wrapped bits
		*/
	}

	template<size_t BitsetSize>
	inline void BitRightCircularShift(const std::bitset<BitsetSize>& bits, std::size_t shift_count, std::bitset<BitsetSize>& result_bits )
	{
					shift_count %= BitsetSize;  // Limit count to range [0,N)
					auto part_bits = bits >> shift_count;
					auto part2_bits = bits << (BitsetSize - shift_count);
					result_bits = part_bits | part2_bits;
		/*
			  result_bits = (bits >> count | bits << (BitsetSize - count));
			The shifted bits ^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^ The wrapped bits
		*/
	}

	template<size_t BitsetSize>
	inline void BitToggle( std::bitset<BitsetSize>& bits, std::size_t index )
	{
		constexpr std::bitset<BitsetSize> Mask{ 1 };

		index %= BitsetSize;  // Limit count to range [0,N)
		bits ^= ( Mask << index );
	}

	template<std::size_t SIZE>
	struct bitset_size
	{
		bitset_size(const std::bitset<SIZE>&)
		{
		}
		static constexpr std::size_t BITSET_SIZE = SIZE;
	};

	template<std::size_t BinaryDataCopySize, std::size_t SplitPosition_OnePartSize, std::size_t SplitPosition_TwoPartSize = BinaryDataCopySize - SplitPosition_OnePartSize>
	inline std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> SplitBitset(const std::bitset<BinaryDataCopySize>& BinaryData)
	{
		constexpr std::size_t BinaryDataSize = decltype(bitset_size{ BinaryData })::BITSET_SIZE;

		//invalied_split_binary
		static_assert(BinaryDataCopySize != 0 && BinaryDataSize != 0, "Unexpected logic error: Binary data size BinaryData.size() must not be 0!\n源二进制数据大小BinaryData.size()不得为0");

		//invalied_split_binary
		static_assert(BinaryDataSize == BinaryDataCopySize,"Unexpected logic error: The source data size BinaryData.size() does not match the template parameter BitsetCopySize \n源数据大小BinaryData.size()与模板参数BinaryDataCopySize不一致");

		if constexpr(SplitPosition_OnePartSize + SplitPosition_TwoPartSize != BinaryDataSize)
		{
			//invalied_split_binary
			static_assert(CommonToolkit::Dependent_Always_Failed<decltype(BinaryDataCopySize)>,"Unexpected logic error: The size of the two target binary data comes from the total size of the source binary data after the split is completed, where one or both of the subsizes are not and range complementary. \n两个目标二进制数据的大小，来自于分割完成之后源二进制数据的总大小，其中有一个或者两个的子大小是不和范围互补的");
		}
		else if constexpr(SplitPosition_OnePartSize >= BinaryDataSize || SplitPosition_TwoPartSize >= BinaryDataSize)
		{
			//invalied_split_binary
			static_assert(CommonToolkit::Dependent_Always_Failed<decltype(SplitPosition_OnePartSize)>, "Unexpected logic error: Binary data split point position out of range!\n二进制数据分割点位置超出范围");
		}
		else
		{
			using WordType = std::conditional_t<BinaryDataSize <= std::numeric_limits<unsigned long>::digits, unsigned long, unsigned long long>;

			if constexpr(SplitPosition_OnePartSize <= std::numeric_limits<unsigned long long>::digits && SplitPosition_TwoPartSize <= std::numeric_limits<unsigned long long>::digits)
			{
				//Example binary data:
				//A is: 0001'1010'0110'0111'0011'0010'0100(Digits size is 26 bit)
				//B is: 13
				//A with B split to C and D:
				//C is: 0001'101'0011'0011
				//D is: 0010'011'0010'0100
			
				/*
					The process of implementation:
						High Digit Binary data calculation:
							Step 1: 0000'0000'0000'0000'1101'0011'0011 = 0001'1010'0110'0111'0011'0010'0100 >> 13 (Bit Right Shift)
							Step 2: 0000'1101'0011'0011 and 0000'0000'0000'0000'1101'0011'0011 It's actually the same!
						Low Digit Binary data calculation:
							Step 1: SelectedBinaryDigit = ~(1 << index)
							If index is 14, Then 0000'0000'0000'0010'0000'0000'0000 = 0000'0000'0000'0000'0000'0000'0001 << 14 (Bit Left Shift)
							Step 2: SelectedBinaryDigit = 1111'1111'1111'1101'1111'1111'1111 = ~0000'0000'0000'0010'0000'0000'0000 (Bit Not)
							Step 3: 0001'1010'0110'0101'0011'0010'0100 = 0001'1010'0110'0111'0011'0010'0100 & 1111'1111'1111'1101'1111'1111'1111 (Bit And)
							Step 4: Repeat the above steps until all binary data high bit 1s are changed to data bit 0
				*/

				/*
				//Reset binary HighDigitPart bit
				//复位二进制高位部分位
				for(unsigned long long index = BitsetCopySize; index != 0 && index != SplitPosition_TwoPartSize; --index )
				{
					unsigned long long BitsetDataPosition = 1 << index;
					unsigned long long BitsetDataPositionMask = ~BitsetDataPosition;
					LowDigitPartDataWithInteger = LowDigitPartDataWithInteger & BitsetDataPositionMask;
				}

				//Reset binary LowDigitPart bit
				//复位二进制低位部分位
				for(unsigned long long index = SplitPosition_OnePartSize; index != 0 && index != BitsetCopySize + 1; ++index )
				{
					unsigned long long BitsetDataPosition = 1 << index;
					unsigned long long BitsetDataPositionMask = ~BitsetDataPosition;
					HighDigitPartDataWithInteger = HighDigitPartDataWithInteger & BitsetDataPositionMask;
				}
				*/

				std::bitset<BinaryDataCopySize> BitsetDataCopy { BinaryData };

				if constexpr(SplitPosition_OnePartSize == SplitPosition_TwoPartSize)
				{
					WordType BitsetDataWithInteger;

					if constexpr(std::same_as<WordType, unsigned long long>)
						BitsetDataWithInteger = BitsetDataCopy.to_ullong();
					else
						BitsetDataWithInteger = BitsetDataCopy.to_ulong();

					//Discard binary LowDigitPart bits
					//丢弃二进制低位部分位数
					WordType HighDigitPartDataWithInteger = BitsetDataWithInteger >> SplitPosition_OnePartSize;

					//Discard binary HighDigitPart bits
					//丢弃二进制高位部分位数
					WordType LowDigitPartDataWithInteger = BitsetDataWithInteger << SplitPosition_TwoPartSize;
					LowDigitPartDataWithInteger = LowDigitPartDataWithInteger >> SplitPosition_TwoPartSize;

					std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ HighDigitPartDataWithInteger };
					std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ LowDigitPartDataWithInteger };
					return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
				}
				else
				{
					/*
					
						10 <-> 1010
						11 <-> 1011

						Source Binary Data:
						0000 0000 0001 0100 1110 0011 1001 1100

						1010011100
						01110011100

						Bit Right Shift (Logic):
						0000 0000 0000 0000 0000 0010 1001 1100 = 0000 0000 0001 0100 1110 0011 1001 1100 >> 11

						Bits Right Rotate:
						0111 0011 1000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0010 1001 1100 = (0000 0000 0001 0100 1110 0011 1001 1100  >> 11) | (0000 0000 0001 0100 1110 0011 1001 1100 << 32 - 11)

						Bit Right Shift (Logic):
						0001 1100 1110 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 = 0111 0011 1000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0010 1001 1100 >> 10

						Bits Left Rotate:
						0000 0000 0000 0000 0000 0011 1001 1100 = (0001 1100 1110 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  << (10 + 11)) | (0001 1100 1110 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 >> 32 - (10 + 11))

						0000000000000-01010011100

						Target Binary Pair:
						1010011100
						01110011100
					
					*/

					if constexpr(SplitPosition_OnePartSize < SplitPosition_TwoPartSize)
					{
						WordType BitsetDataWithInteger = 0;
						WordType HighDigitPartDataWithInteger = 0;
						WordType LowDigitPartDataWithInteger = 0;

						if constexpr(std::same_as<WordType, unsigned long long>)
							BitsetDataWithInteger = BitsetDataCopy.to_ullong();
						else
							BitsetDataWithInteger = BitsetDataCopy.to_ulong();

						//Discard binary LowDigitPart bits
						//丢弃二进制低位部分位数
						HighDigitPartDataWithInteger = BitsetDataWithInteger >> SplitPosition_TwoPartSize;

						//By right (circular shift) rotation, the low bits of binary data are moved to the high bits (and reversed)
						//Facilitates discarding the original high bits of data
						//通过右(循环移位)旋转，将二进制的低位比特的数据，移动至高位(并且反向)
						//便于丢弃原高位比特的数据
						LowDigitPartDataWithInteger = std::rotr(BitsetDataWithInteger, SplitPosition_TwoPartSize);

						//Discard the original high bits of data
						//丢弃原高位比特的数据
						LowDigitPartDataWithInteger = LowDigitPartDataWithInteger >> SplitPosition_OnePartSize;
						
						//By left (circular shift) rotation, the high bits of the binary data are moved to the low bits (and reversed)
						//Used to recover the original low bits of data
						//通过左(循环移位)旋转，将二进制的高位比特的数据，移动至低位(并且反向)
						//用于恢复原低位比特的数据
						LowDigitPartDataWithInteger = std::rotl(LowDigitPartDataWithInteger, SplitPosition_OnePartSize + SplitPosition_TwoPartSize);

						std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ HighDigitPartDataWithInteger };
						std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ LowDigitPartDataWithInteger };
						return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
					}
					if constexpr(SplitPosition_OnePartSize > SplitPosition_TwoPartSize)
					{
						WordType BitsetDataWithInteger = 0;
						WordType HighDigitPartDataWithInteger = 0;
						WordType LowDigitPartDataWithInteger = 0;

						if constexpr(std::same_as<WordType, unsigned long long>)
							BitsetDataWithInteger = BitsetDataCopy.to_ullong();
						else
							BitsetDataWithInteger = BitsetDataCopy.to_ulong();

						//Discard binary LowDigitPart bits
						//丢弃二进制低位部分位数
						HighDigitPartDataWithInteger = BitsetDataWithInteger >> SplitPosition_TwoPartSize;

						//By right (circular shift) rotation, the low bits of binary data are moved to the high bits (and reversed)
						//Facilitates discarding the original high bits of data
						//通过右(循环移位)旋转，将二进制的低位比特的数据，移动至高位(并且反向)
						//便于丢弃原高位比特的数据
						LowDigitPartDataWithInteger = std::rotr(BitsetDataWithInteger, SplitPosition_TwoPartSize);

						//Discard the original high bits of data
						//丢弃原高位比特的数据
						LowDigitPartDataWithInteger = LowDigitPartDataWithInteger >> SplitPosition_OnePartSize;
						
						//By left (circular shift) rotation, the high bits of the binary data are moved to the low bits (and reversed)
						//Used to recover the original low bits of data
						//通过左(循环移位)旋转，将二进制的高位比特的数据，移动至低位(并且反向)
						//用于恢复原低位比特的数据
						LowDigitPartDataWithInteger = std::rotl(LowDigitPartDataWithInteger, SplitPosition_OnePartSize + SplitPosition_TwoPartSize);

						std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ HighDigitPartDataWithInteger };
						std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ LowDigitPartDataWithInteger };
						return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
					}
				}
			}
			else
			{
				std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData;
				std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData;

				for(std::size_t index = 0; index != BinaryData.size(); ++index)
				{
					if(index < SplitPosition_OnePartSize)
					{
						if(BinaryData.operator[](index))
						{
							LowDigitPartBitsetData.operator[](index) = BinaryData.operator[](index);
						}
					}
					else
					{
						if(BinaryData.operator[](index))
						{
							HighDigitPartBitsetData.operator[](index - SplitPosition_OnePartSize) = BinaryData.operator[](index);
						}
					}
				}
			}
		}
	}

	template <std::size_t BitsetSize, std::size_t BitsetSize2 >
	inline std::bitset <BitsetSize + BitsetSize2> ConcatenateBitset( const std::bitset<BitsetSize>& leftBinaryData, const std::bitset<BitsetSize2>& rightBinaryData, bool isNeedSwapTwoPart )
	{
		constexpr unsigned long long ConcatenateBinarySize = BitsetSize + BitsetSize2;

		//invalied_concat_binary
		static_assert(decltype(bitset_size{ leftBinaryData })::BITSET_SIZE != 0 && decltype(bitset_size{ rightBinaryData })::BITSET_SIZE != 0, "Unexpected logic error: The size of the two parts of the binary data that need to be concatenated, the size of their bits, cannot have either one of them be 0 or both of them be 0!\n需要的串接的两个部分的二进制数据，它们的位数的大小，不能有任意一个是0或者两个都是0");

		constexpr unsigned long long ConcatenateBinarySize2 = decltype(bitset_size{ leftBinaryData })::BITSET_SIZE + decltype(bitset_size{ rightBinaryData })::BITSET_SIZE;

		//invalied_concat_binary
		static_assert(ConcatenateBinarySize == ConcatenateBinarySize2, "Unexpected logic error: The source data size leftBinaryData.size() + rightBinaryData.size() does not match the result of the template parameter BitsetSize + BitsetSize2!\n源数据大小 leftBinaryData.size() + rightBinaryData.size() 与模板参数 BitsetSize + BitsetSize2 的结果不一致");

		using WordType = std::conditional_t<ConcatenateBinarySize <= std::numeric_limits<unsigned long>::digits, unsigned long, unsigned long long>;

		if constexpr(ConcatenateBinarySize <= std::numeric_limits<unsigned long long>::digits)
		{
			//Example binary data:
			//A is: 0000'1101'0011'0011(Digits size is 13 bit)
			//B is: 0001'0011'0010'0100(Digits size is 13 bit)

			//C from A concate B: 0001'1010'0110'0111'0011'0010'0100

			/*
			The process of implementation:
				Binary data calculation:
					Step 1: 0001'1010'0110'0110'0000'0000'0000 = 0000'1101'0011'0011 << 13 (Bit Left Shift)
					Step 2: 0001'0011'0010'0100 and 0000'0000'0000'0001'0011'0010'0100, It's actually the same!
					Step 3: 0001'1010'0110'0111'0011'0010'0100 = 0001'1010'0110'0110'0000'0000'0000 | 0000'0000'0000'0001'0011'0010'0100 (Bit Or)
			*/

			//Discard binary HighDigitPart bit and Reset binary LowDigitPart bit, then Set binary LowDigitPart bit.
			//丢弃二进制高位部分的位数并重置二进制低位部分的位数，然后设置二进制低位部分的位数。

			if(!isNeedSwapTwoPart)
			{
				WordType ConcatenatedBinaryDataWithInteger = leftBinaryData.to_ullong() << leftBinaryData.size() | rightBinaryData.to_ullong();

				std::bitset<ConcatenateBinarySize> ConcatenatedBitset( ConcatenatedBinaryDataWithInteger );
				return ConcatenatedBitset;
			}
			else
			{
				WordType ConcatenatedBinaryDataWithInteger = rightBinaryData.to_ullong() << rightBinaryData.size() | leftBinaryData.to_ullong();

				std::bitset<ConcatenateBinarySize> ConcatenatedBitset( ConcatenatedBinaryDataWithInteger );
				return ConcatenatedBitset;
			}
		}
		else
		{
			if(!isNeedSwapTwoPart)
			{
				//Binary string concat
				return std::bitset<ConcatenateBinarySize>( leftBinaryData.to_string() + rightBinaryData.to_string() );
			}
			else
			{
				//Binary string concat
				return std::bitset<ConcatenateBinarySize>( rightBinaryData.to_string() + leftBinaryData.to_string() );
			}
		}
	}

	inline std::bitset<64> ClassicByteArrayToBitset64Bit(const std::vector<unsigned char>& ByteArray)
	{
		unsigned long long TemporaryInteger = 0;
		if(ByteArray.size() != sizeof(TemporaryInteger))
		{
			std::length_error conversion_type_data_is_undefined_behaviour("This object CharacterArray size is not equal 8 !");
			throw conversion_type_data_is_undefined_behaviour;
		}
		std::memcpy(&TemporaryInteger, ByteArray.data(), sizeof(TemporaryInteger));
		std::bitset<64> Bitset64Object(TemporaryInteger);
		return Bitset64Object;
	}

	inline std::vector<unsigned char> ClassicByteArrayFromBitset64Bit(const std::bitset<64>& Bitset64Object)
	{
		unsigned long long TemporaryInteger { Bitset64Object.to_ullong() };
		std::vector<unsigned char> ByteArray { reinterpret_cast<unsigned char *>( &TemporaryInteger ), reinterpret_cast<unsigned char *>( &TemporaryInteger + 1 ) };
		return ByteArray;
	}
}