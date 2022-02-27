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
//#define BYTE_SWAP_FUNCTON
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
		template <typename T, typename TF>
		requires std::is_invocable_r_v<void, TF, uint8_t*, size_t>
		inline void absorb_bytes( const uint8_t* data, std::size_t data_size, std::size_t block_size, std::size_t block_size_check, OneByte* _BufferMemory, std::size_t& position, T& _total, TF transform )
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
		template <typename T, size_t N>
		inline void zero_memory( std::array<T, N>& array_data )
		{
			zero_memory( array_data.data(), array_data.size() * sizeof( T ) );
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

	#if defined( BYTE_SWAP_FUNCTON )

	// Byte-swap a 16-bit uint32_teger.
	inline uint16_t byteswap( uint16_t val )
	{
		return ( ( val & 0xff ) << 8 ) | ( ( val & 0xff00 ) >> 8 );
	}

	// Byte-swap a 32-bit uint32_teger.
	inline uint32_t byteswap( uint32_t val )
	{
		return ( ( ( val & 0xff000000 ) >> 24 ) | ( ( val & 0x00ff0000 ) >> 8 ) | ( ( val & 0x0000ff00 ) << 8 ) | ( ( val & 0x000000ff ) << 24 ) );
	}

	// Byte-swap a 64-bit uint32_teger.
	inline uint64_t byteswap( uint64_t val )
	{
		return ( ( ( val & 0xff00000000000000ULL ) >> 56 ) | ( ( val & 0x00ff000000000000ULL ) >> 40 ) | ( ( val & 0x0000ff0000000000ULL ) >> 24 ) | ( ( val & 0x000000ff00000000ULL ) >> 8 ) | ( ( val & 0x00000000ff000000ULL ) << 8 ) | ( ( val & 0x0000000000ff0000ULL ) << 24 ) | ( ( val & 0x000000000000ff00ULL ) << 40 ) | ( ( val & 0x00000000000000ffULL ) << 56 ) );
	}

	#endif

	#if defined( INTEGER_PACKCATION_OLD )

	//Turn byte 8bit array to integer 32bit
	inline void MessagePacking32Bit( std::vector<uint8_t>& input, std::vector<uint64_t>& output, uint64_t size )
	{
		uint64_t index_input = 0, index_output = 0;
		while ( index_input < size )
		{
			output[ index_output ] = ( static_cast<uint64_t>( input[ index_input + 3 ] ) ) | ( static_cast<uint64_t>( input[ index_input + 2 ] ) << 8 ) | ( static_cast<uint64_t>( input[ index_input + 1 ] ) << 16 ) | ( static_cast<uint64_t>( input[ index_input + 0 ] ) << 24 );

			++index_output;
			index_input += 8;
		}
	}

	//Turn byte 8bit array to integer 64bit
	inline void MessagePacking64Bit( std::vector<uint8_t>& input, std::vector<uint64_t>& output, uint64_t size )
	{
		uint64_t index_input = 0, index_output = 0;
		while ( index_input < size )
		{
			output[ index_output ] = ( static_cast<uint64_t>( input[ index_input + 7 ] ) ) | ( static_cast<uint64_t>( input[ index_input + 6 ] ) << 8 ) | ( static_cast<uint64_t>( input[ index_input + 5 ] ) << 16 ) | ( static_cast<uint64_t>( input[ index_input + 4 ] ) << 24 ) | ( static_cast<uint64_t>( input[ index_input + 3 ] ) << 32 ) | ( static_cast<uint64_t>( input[ index_input + 2 ] ) << 40 ) | ( static_cast<uint64_t>( input[ index_input + 1 ] ) << 48 ) | ( static_cast<uint64_t>( input[ index_input + 0 ] ) << 56 );

			++index_output;
			index_input += 8;
		}
	}

	#endif

	#if defined( INTEGER_UNPACKCATION_OLD )

	//Turn integer 32bit to byte 8bit array
	inline void MessageUnpacking32Bit( std::vector<uint64_t>& input, std::vector<uint8_t>& output, uint64_t size )
	{
		uint64_t index_input = 0, index_output = 0;

		while ( index_output < size )
		{
			output[ index_output + 3 ] = static_cast<uint8_t>( input[ index_input ] & 0xFF );
			output[ index_output + 2 ] = static_cast<uint8_t>( ( input[ index_input ] >> 8 ) & 0xFF00 );
			output[ index_output + 1 ] = static_cast<uint8_t>( ( input[ index_input ] >> 16 ) & 0xFF0000 );
			output[ index_output + 0 ] = static_cast<uint8_t>( ( input[ index_input ] >> 24 ) & 0xFF000000 );

			++index_input;
			index_output += 8;
		}
	}

	//Turn integer 64bit to byte 8bit array
	inline void MessageUnpacking64Bit( std::vector<uint64_t>& input, std::vector<uint8_t>& output, uint64_t size )
	{
		uint64_t index_input = 0, index_output = 0;

		while ( index_output < size )
		{
			output[ index_output + 7 ] = static_cast<uint8_t>( input[ index_input ] & 0xFF );
			output[ index_output + 6 ] = static_cast<uint8_t>( ( input[ index_input ] >> 8 ) & 0xFF00 );
			output[ index_output + 5 ] = static_cast<uint8_t>( ( input[ index_input ] >> 16 ) & 0xFF0000 );
			output[ index_output + 4 ] = static_cast<uint8_t>( ( input[ index_input ] >> 24 ) & 0xFF000000 );
			output[ index_output + 3 ] = static_cast<uint8_t>( ( input[ index_input ] >> 32 ) & 0xFF00000000 );
			output[ index_output + 2 ] = static_cast<uint8_t>( ( input[ index_input ] >> 40 ) & 0xFF0000000000 );
			output[ index_output + 1 ] = static_cast<uint8_t>( ( input[ index_input ] >> 48 ) & 0xFF000000000000 );
			output[ index_output + 0 ] = static_cast<uint8_t>( ( input[ index_input ] >> 56 ) & 0xFF00000000000000 );

			++index_input;
			index_output += 8;
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
				{  // set internal state
					_STL_ASSERT( MinimumValue0 <= MaximumValue0, "invalid min and max arguments for uniform_int" );
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
		template <class _Elem, class _Traits, class _Ty>
		std::basic_istream<_Elem, _Traits>& operator>>(std::basic_istream<_Elem, _Traits>& _Istr, UniformInteger<_Ty>& _Dist)
		{
			return _Dist.Read(_Istr);
		}

		// write state to _Ostr
		template <class _Elem, class _Traits, class _Ty>
		std::basic_ostream<_Elem, _Traits>& operator<<(std::basic_ostream<_Elem, _Traits>& _Ostr, const UniformInteger<_Ty>& _Dist)
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

#include "SecureHashProvider/Hasher.hpp"