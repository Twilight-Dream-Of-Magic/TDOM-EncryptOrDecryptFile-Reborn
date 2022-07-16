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

namespace CommonToolkit
{

	inline namespace MemoryBits
	{
		struct BitOperations
		{
		public:
			static void ReverseByteArray(const void *Source, void * Destination, std::size_t size)
			{
				std::uint8_t *source_pointer = const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(Source));
				std::uint8_t *destination_pointer = reinterpret_cast<std::uint8_t*>(Destination);

				destination_pointer = destination_pointer + (size - 1);
				for (std::size_t counter = 0; counter < size; ++counter)
				{
					*destination_pointer = *source_pointer;
					source_pointer += 1;
					destination_pointer -= 1;
				} // end for
			} // end function ReverseByteArray

			static std::int32_t ReverseBytesInt32(const std::int32_t value)
			{
				auto integer_a = value & 0xFF;
				auto integer_b = Asr32(value, 8) & 0xFF;
				auto integer_c = Asr32(value, 16) & 0xFF;
				auto integer_d = Asr32(value, 24) & 0xFF;

				return (integer_a << 24) | (integer_b << 16) | (integer_c << 8) | (integer_d << 0);
			} // end function ReverseBytesInt32

			static std::uint8_t ReverseBitsUInt8(const std::uint8_t value)
			{
				std::uint8_t result = ((value >> 1) & 0x55) | ((value << 1) & 0xAA);
				result = ((result >> 2) & 0x33) | ((result << 2) & 0xCC);
				return ((result >> 4) & 0x0F) | ((result << 4) & 0xF0);
			} // end function ReverseBitsUInt8

			static std::uint16_t ReverseBytesUInt16(const std::uint16_t value)
			{
				return ((value & std::uint32_t(0xFF)) << 8 | (value & std::uint32_t(0xFF00)) >> 8);
			} // end function ReverseBytesUInt16

			static std::uint32_t ReverseBytesUInt32(const std::uint32_t value)
			{
				return (value & std::uint32_t(0x000000FF)) << 24 |
					(value & std::uint32_t(0x0000FF00)) << 8 |
					(value & std::uint32_t(0x00FF0000)) >> 8 |
					(value & std::uint32_t(0xFF000000)) >> 24;
			} // end function ReverseBytesUInt32

			static std::uint64_t ReverseBytesUInt64(const std::uint64_t value)
			{
				return (value & std::uint64_t(0x00000000000000FF)) << 56 |
					(value & std::uint64_t(0x000000000000FF00)) << 40 |
					(value & std::uint64_t(0x0000000000FF0000)) << 24 |
					(value & std::uint64_t(0x00000000FF000000)) << 8 |
					(value & std::uint64_t(0x000000FF00000000)) >> 8 |
					(value & std::uint64_t(0x0000FF0000000000)) >> 24 |
					(value & std::uint64_t(0x00FF000000000000)) >> 40 |
					(value & std::uint64_t(0xFF00000000000000)) >> 56;
			} // end function ReverseBytesUInt64

			//Arithmetic bit-shift 32
			static std::int32_t Asr32(const std::int32_t value, const std::int32_t ShiftBits)
			{
				return std::int32_t(std::uint32_t(std::uint32_t(std::uint32_t(value) >> (ShiftBits & 31)) |
					(std::uint32_t(std::int32_t(std::uint32_t(0 - std::uint32_t(std::uint32_t(value) >> 31)) &
						std::uint32_t(std::int32_t(0 - (bool((ShiftBits & 31) != 0)))))) << (32 - (ShiftBits & 31)))));
			} // end function Asr32

			//Arithmetic bit-shift 64
			static std::int64_t Asr64(const std::int64_t value, const std::int32_t ShiftBits)
			{
				return std::int64_t(std::uint64_t(std::uint64_t(std::uint64_t(value) >> (ShiftBits & 63)) |
					(std::uint64_t(std::int64_t(std::uint64_t(0 - std::uint64_t(std::uint64_t(value) >> 63)) &
						std::uint64_t(std::int64_t(size_t(0) - (bool((ShiftBits & 63) != 0)))))) << (64 - (ShiftBits & 63)))));
			} // end function Asr64

		}; // end class Bits

		struct BitConverters
		{
			static void swap_copy_to_u32
			(
				const void* source_pointer,
				const std::int32_t source_pointer_index,
				void* destination_pointer,
				std::int32_t destination_pointer_index,
				const std::int32_t data_size
			)
			{
				std::uint32_t* lbegin, *ldestination, *lend;
				std::uint8_t* lsource_block;
				std::int32_t ldata_size;

				// if all pointers and length are 32-bits aligned
				if
				(
					((std::int32_t((std::uint8_t*)(destination_pointer)-(std::uint8_t*)(0))
					| ((std::uint8_t*)(source_pointer)-(std::uint8_t*)(0))
					| source_pointer_index
					| destination_pointer_index | data_size) & 3) == 0
				)
				{
					// copy memory as 32-bit words
					lbegin = (std::uint32_t*)const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index);
					lend = (std::uint32_t*)const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index);
					ldestination = (std::uint32_t*)reinterpret_cast<std::uint8_t*>(destination_pointer) + destination_pointer_index;
					while (lbegin < lend)
					{
						*ldestination = BitOperations::ReverseBytesUInt32(*lbegin);
						ldestination += 1;
						lbegin += 1;
					} // end while
				} // end if
				else
				{
					lsource_block = const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index);

					ldata_size = data_size + destination_pointer_index;
					while (destination_pointer_index < ldata_size)
					{
						reinterpret_cast<std::uint8_t*>(destination_pointer)[destination_pointer_index ^ 3] = *lsource_block;

						lsource_block += 1;
						destination_pointer_index += 1;
					} // end while
				} // end else

			} // end function swap_copy_to_u32

			static void swap_copy_to_u64
			(
				const void* source_pointer,
				const std::int32_t source_pointer_index,
				void* destination_pointer,
				std::int32_t destination_pointer_index,
				const std::int32_t data_size
			)
			{
				std::uint64_t* lbegin, * ldestination, * lend;
				std::uint8_t* lsource_block;
				std::int32_t ldata_size;

				// if all pointers and length are 64-bits aligned
				if
				(
					((std::int32_t((std::uint8_t*)(destination_pointer)-(std::uint8_t*)(0))
					| ((std::uint8_t*)(source_pointer)-(std::uint8_t*)(0))
					| source_pointer_index
					| destination_pointer_index
					| data_size) & 7) == 0
				)
				{
					// copy aligned memory block as 64-bit integers
					lbegin = (std::uint64_t*)const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index);
					lend = (std::uint64_t*)const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index) + data_size;
					ldestination = (std::uint64_t*)reinterpret_cast<std::uint8_t*>(destination_pointer) + destination_pointer_index;
					while (lbegin < lend)
					{
						*ldestination = BitOperations::ReverseBytesUInt64(*lbegin);
						ldestination += 1;
						lbegin += 1;
					} // end while
				} // end if
				else
				{
					lsource_block = const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index);

					ldata_size = data_size + destination_pointer_index;
					while (destination_pointer_index < ldata_size)
					{
						reinterpret_cast<std::uint8_t*>(destination_pointer)[destination_pointer_index ^ 7] = *lsource_block;

						lsource_block += 1;
						destination_pointer_index += 1;
					} // end while
				} // end else
			} // end function swap_copy_to_u64

			static std::uint32_t be2me_32(const std::uint32_t number)
			{
				if constexpr(std::endian::native == std::endian::little)
				{
					return BitOperations::ReverseBytesUInt32(number);
				} // end if

				return number;
			} // end function be2me_32

			static std::uint64_t be2me_64(const std::uint64_t number)
			{
				if constexpr(std::endian::native == std::endian::little)
				{
					return BitOperations::ReverseBytesUInt64(number);
				} // end if

				return number;
			} // end function be2me_64

			static std::uint32_t le2me_32(const std::uint32_t number)
			{
				if constexpr(std::endian::native != std::endian::little)
				{
					return BitOperations::ReverseBytesUInt32(number);
				} // end if

				return number;
			} // end function le2me_32

			static std::uint64_t le2me_64(const std::uint64_t number)
			{
				if constexpr(std::endian::native != std::endian::little)
				{
					return BitOperations::ReverseBytesUInt64(number);
				} // end if

				return number;
			} // end function le2me_64

			//Big endian 32bit(copy memory)
			static void be32_copy
			(
				const void* source_pointer,
				const std::int32_t source_pointer_index,
				void* destination_pointer,
				const std::int32_t destination_pointer_index,
				const std::int32_t data_size
			)
			{
				if constexpr(std::endian::native != std::endian::big)
				{
					BitConverters::swap_copy_to_u32
					(
						source_pointer,
						source_pointer_index,
						destination_pointer,
						destination_pointer_index,
						data_size
					);
				} // end if
				else
				{
					if(destination_pointer == nullptr || source_pointer == nullptr)
						my_cpp2020_assert(false, "", std::source_location::current());

					if(data_size == 0)
						return;

					std::memmove
					(
						reinterpret_cast<std::uint8_t*>(destination_pointer) + destination_pointer_index,
						reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index,
						data_size
					);
				} // end else
			} // end function be32_copy

			//Big endian 64bit(copy memory)
			static void be64_copy
			(
				const void* source_pointer,
				const std::int32_t source_pointer_index,
				void* destination_pointer,
				const std::int32_t destination_pointer_index,
				const std::int32_t data_size
			)
			{
				if constexpr(std::endian::native != std::endian::big)
				{
					BitConverters::swap_copy_to_u64
					(
						source_pointer,
						source_pointer_index,
						destination_pointer,
						destination_pointer_index,
						data_size
					);
				} // end if
				else
				{

					if(destination_pointer == nullptr || source_pointer == nullptr)
						my_cpp2020_assert(false, "", std::source_location::current());

					if(data_size == 0)
						return;

					std::memmove
					(
						reinterpret_cast<std::uint8_t*>(destination_pointer) + destination_pointer_index,
						reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index,
						data_size
					);
				} // end else
			} // end function be64_copy

			//Liitle endian 32bit(copy memory)
			static void le32_copy
			(
				const void* source_pointer,
				const std::int32_t source_pointer_index,
				void* destination_pointer,
				const std::int32_t destination_pointer_index,
				const std::int32_t data_size
			)
			{
				if constexpr(std::endian::native != std::endian::little)
				{
					BitConverters::swap_copy_to_u32
					(
						source_pointer,
						source_pointer_index,
						destination_pointer,
						destination_pointer_index,
						data_size
					);
				} // end if
				else
				{
					if(destination_pointer == nullptr || source_pointer == nullptr)
						my_cpp2020_assert(false, "", std::source_location::current());

					if(data_size == 0)
						return;

					std::memmove
					(
						reinterpret_cast<std::uint8_t*>(destination_pointer) + destination_pointer_index,
						reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index,
						data_size
					);
				} // end else
			} // end function be64_copy

			//Liitle endian 64bit(copy memory)
			static void le64_copy
			(
				const void* source_pointer,
				const std::int32_t source_pointer_index,
				void* destination_pointer,
				const std::int32_t destination_pointer_index,
				const std::int32_t data_size
			)
			{
				if constexpr(std::endian::native != std::endian::little)
				{
					BitConverters::swap_copy_to_u64
					(
						source_pointer,
						source_pointer_index,
						destination_pointer,
						destination_pointer_index,
						data_size
					);
				} // end if
				else
				{
					if(destination_pointer == nullptr || source_pointer == nullptr)
						my_cpp2020_assert(false, "", std::source_location::current());

					if(data_size == 0)
						return;

					std::memmove
					(
						reinterpret_cast<std::uint8_t*>(destination_pointer) + destination_pointer_index,
						reinterpret_cast<const std::uint8_t*>(source_pointer) + source_pointer_index,
						data_size
					);
				} // end else
			} // end function be64_copy

		};
	}

	inline namespace IntegerExchangeBytes
	{
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
		inline constexpr TwoByte packInteger( SpanTwoByte data )
		{
			return ( static_cast<TwoByte>( data[ 0 ] ) << 8 ) | ( static_cast<TwoByte>( data[ 1 ] ) );
		}
		inline constexpr FourByte packInteger( SpanFourByte data )
		{
			return ( static_cast<FourByte>( data[ 0 ] ) << 24 ) | ( static_cast<FourByte>( data[ 1 ] ) << 16 ) | ( static_cast<FourByte>( data[ 2 ] ) << 8 ) | ( static_cast<FourByte>( data[ 3 ] ) );
		}
		inline constexpr EightByte packInteger( SpanEightByte data )
		{
			return ( static_cast<EightByte>( packInteger( SpanFourByte{ data.begin(), 4u } ) ) << 32 ) | static_cast<EightByte>( packInteger( SpanFourByte{ data.begin() + 4, 4u } ) );
		}

		#if defined( BYTE_SWAP_FUNCTON ) && __cplusplus >= 202002L

		/*
			Reference source code: https://gist.github.com/raidoz/4163b8ec6672aabb0656b96692af5e33
			cross-platform / cross-compiler standalone endianness conversion
		*/
		namespace ByteSwap
		{
			namespace Implementation
			{
				inline std::uint16_t _builtin_byteswap_uint16(const std::uint16_t& value)
				{
					unsigned short other_value = 0;
					other_value =  (value << 8);
					other_value += (value >> 8);
					return other_value;
				}

				inline std::uint32_t _builtin_byteswap_uint32(const std::uint32_t& value)
				{
					unsigned int other_value = 0;
					other_value =  (value << 24);
					other_value += (value <<  8) & 0x00FF0000;
					other_value += (value >>  8) & 0x0000FF00;
					other_value += (value >> 24);
					return other_value;
				}

				inline std::uint64_t _builtin_byteswap_uint64(const std::uint64_t& value)
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
				[[nodiscard]] static inline constexpr std::uint16_t Byteswap(const std::uint16_t& ByteValue) noexcept
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
				[[nodiscard]] static inline constexpr std::uint32_t Byteswap(const std::uint32_t& ByteValue) noexcept
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
				[[nodiscard]] static inline constexpr std::uint64_t Byteswap(const std::uint64_t& ByteValue) noexcept
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
					return static_cast<ThisType>(Implementation::Byteswap(static_cast<std::uint16_t>(ByteValue)));
				}
				else if constexpr (sizeof(ThisType) == 4)
				{
					return static_cast<Type>(Implementation::Byteswap(static_cast<std::uint32_t>(ByteValue)));
				}
				else if constexpr (sizeof(ThisType) == 8)
				{
					return static_cast<ThisType>(Implementation::Byteswap(static_cast<std::uint64_t>(ByteValue)));
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

		template<typename IntegerType, typename ByteType>
		concept BytesExchangeIntegersConecpt = std::is_integral_v<std::remove_cvref_t<IntegerType>> && std::is_same_v<std::remove_cvref_t<ByteType>, unsigned char> || std::is_same_v<std::remove_cvref_t<ByteType>, std::byte>;

		class MemoryDataFormatExchange
		{

		private:
			std::array<std::uint8_t, 2> twobyte_array { 0, 0 };
			std::array<std::uint8_t, 4> fourbyte_array { 0, 0, 0, 0 };
			std::array<std::uint8_t, 8> eightbyte_array { 0, 0, 0, 0, 0, 0, 0, 0 };

		public:
			std::uint16_t Packer_2Byte(std::span<const std::uint8_t> bytes)
			{
				my_cpp2020_assert(bytes.size() == 2, "The required byte array size is 2", std::source_location::current());

				auto ValueA = bytes.operator[](0);
				auto ValueB = bytes.operator[](1);

				std::uint16_t integer = ValueA & 0xFF;
				integer |= ((static_cast<std::uint16_t>(ValueB) << 8) & 0xFF00);

				if constexpr(std::endian::native == std::endian::big)
				{
					#if __cpp_lib_byteswap

					integer = std::byteswap(integer);

					#else

					integer = ByteSwap::byteswap(integer);

					#endif
				}

				return integer;
			}

			std::span<std::uint8_t> Unpacker_2Byte(std::uint16_t integer)
			{
				if constexpr(std::endian::native == std::endian::big)
				{
					#if __cpp_lib_byteswap

					integer = std::byteswap(integer);

					#else

					integer = ByteSwap::byteswap(integer);

					#endif
				}

				twobyte_array.fill(0);
				std::span<std::uint8_t> bytes { twobyte_array };
				bytes.operator[](0) = (integer & 0x000000FF);
				bytes.operator[](1) = (integer & 0x0000FF00) >> 8;

				return bytes;
			}

			std::uint32_t Packer_4Byte(std::span<const std::uint8_t> bytes)
			{
				my_cpp2020_assert(bytes.size() == 4, "The required byte array size is 4", std::source_location::current());

				auto ValueA = bytes.operator[](0);
				auto ValueB = bytes.operator[](1);
				auto ValueC = bytes.operator[](2);
				auto ValueD = bytes.operator[](3);

				std::uint32_t integer = ValueA & 0xFF;
				integer |= ((static_cast<std::uint32_t>(ValueB) << 8) & 0xFF00);
				integer |= ((static_cast<std::uint32_t>(ValueC) << 16) & 0xFF0000);
				integer |= ((static_cast<std::uint32_t>(ValueD) << 24) & 0xFF000000);

				if constexpr(std::endian::native == std::endian::big)
				{
					#if __cpp_lib_byteswap

					integer = std::byteswap(integer);

					#else

					integer = ByteSwap::byteswap(integer);

					#endif
				}

				return integer;
			}

			std::span<std::uint8_t> Unpacker_4Byte(std::uint32_t integer)
			{
				if constexpr(std::endian::native == std::endian::big)
				{
					#if __cpp_lib_byteswap

					integer = std::byteswap(integer);

					#else

					integer = ByteSwap::byteswap(integer);

					#endif
				}

				fourbyte_array.fill(0);
				std::span<std::uint8_t> bytes { fourbyte_array };
				bytes.operator[](0) = (integer & 0x000000FF);
				bytes.operator[](1) = (integer & 0x0000FF00) >> 8;
				bytes.operator[](2) = (integer & 0x00FF0000) >> 16;
				bytes.operator[](3) = (integer & 0xFF000000) >> 24;

				return bytes;
			}

			std::uint64_t Packer_8Byte(std::span<const std::uint8_t> bytes)
			{
				my_cpp2020_assert(bytes.size() == 8, "The required byte array size is 8", std::source_location::current());

				auto ValueA = bytes.operator[](0);
				auto ValueB = bytes.operator[](1);
				auto ValueC = bytes.operator[](2);
				auto ValueD = bytes.operator[](3);
				auto ValueE = bytes.operator[](4);
				auto ValueF = bytes.operator[](5);
				auto ValueG = bytes.operator[](6);
				auto ValueH = bytes.operator[](7);

				std::uint64_t integer = ValueA & 0xFF;
				integer |= ((static_cast<std::uint64_t>(ValueB) << 8) & 0xFF00);
				integer |= ((static_cast<std::uint64_t>(ValueC) << 16) & 0xFF0000);
				integer |= ((static_cast<std::uint64_t>(ValueD) << 24) & 0xFF000000);
				integer |= ((static_cast<std::uint64_t>(ValueE) << 32) & 0xFF00000000);
				integer |= ((static_cast<std::uint64_t>(ValueF) << 40) & 0xFF0000000000);
				integer |= ((static_cast<std::uint64_t>(ValueG) << 48) & 0xFF000000000000);
				integer |= ((static_cast<std::uint64_t>(ValueH) << 56) & 0xFF00000000000000);

				if constexpr(std::endian::native == std::endian::big)
				{
					#if __cpp_lib_byteswap

					integer = std::byteswap(integer);

					#else

					integer = ByteSwap::byteswap(integer);

					#endif
				}

				return integer;
			}

			std::span<std::uint8_t> Unpacker_8Byte(std::uint64_t integer)
			{
				if constexpr(std::endian::native == std::endian::big)
				{
					#if __cpp_lib_byteswap

					integer = std::byteswap(integer);

					#else

					integer = ByteSwap::byteswap(integer);

					#endif
				}

				eightbyte_array.fill(0);
				std::span<std::uint8_t> bytes { eightbyte_array };
				bytes.operator[](0) = (integer & 0x00000000000000FF);
				bytes.operator[](1) = (integer & 0x000000000000FF00) >> 8;
				bytes.operator[](2) = (integer & 0x0000000000FF0000) >> 16;
				bytes.operator[](3) = (integer & 0x00000000FF000000) >> 24;
				bytes.operator[](4) = (integer & 0x000000FF00000000) >> 32;
				bytes.operator[](5) = (integer & 0x0000FF0000000000) >> 40;
				bytes.operator[](6) = (integer & 0x00FF000000000000) >> 48;
				bytes.operator[](7) = (integer & 0xFF00000000000000) >> 56;

				return bytes;
			}

			MemoryDataFormatExchange() = default;
			~MemoryDataFormatExchange() = default;

		};

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
				CommonToolkit::MessagePacking<unsigned int>(byteSpan, &InputWord);

				OutputWord = (InputWord << 8) | (InputWord >> 24);

				std::vector<unsigned int> words
				{
					OutputWord
				};
				std::span<unsigned int> wordSpan{ words };
				CommonToolkit::MessageUnpacking<unsigned int>(wordSpan, bytes.data());

				Word.operator[](0) = static_cast<unsigned char>(bytes.operator[](0));
				Word.operator[](1) = static_cast<unsigned char>(bytes.operator[](1));
				Word.operator[](2) = static_cast<unsigned char>(bytes.operator[](2));
				Word.operator[](3) = static_cast<unsigned char>(bytes.operator[](3));

				bytes.clear();
				words.clear();

		*/

		template<typename IntegerType, typename ByteType>
		requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
		void MessagePacking(const std::span<const ByteType>& input, IntegerType* output)
		{
			if(input.size() % sizeof(IntegerType) != 0)
			{
				throw std::length_error("The size of the data must be aligned with the size of the type!");
			}

			if(output == nullptr)
			{
				throw std::logic_error("The target of the copied byte must not be a null pointer!");
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

					*output++ = ByteSwap::byteswap(value);

					#endif
				}
			}
			else
			{
				throw std::runtime_error("");
			}
		}

		template<typename IntegerType, typename ByteType>
		requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
		std::vector<IntegerType> MessagePacking(const ByteType* input_pointer, std::size_t input_size)
		{
			if(input_pointer == nullptr)
				throw std::logic_error("The source of the copied byte must not be a null pointer!");

			if(input_size == 0)
				throw std::logic_error("The source size of the copied bytes cannot be 0!");
			else if (input_size % sizeof(IntegerType) != 0)
				throw std::length_error("The size of the data must be aligned with the size of the type!");
			else
			{
				std::vector<IntegerType> output_vector(input_size / sizeof(IntegerType), 0);

				std::memcpy(output_vector.data(), input_pointer, input_size);

				bool whether_need_byteswap = false;
				//whether_need_byteswap is true
				if constexpr (std::endian::native == std::endian::big)
				{
					whether_need_byteswap = true;
				}
				//whether_need_byteswap is false
				else if constexpr (std::endian::native == std::endian::little)
				{
					whether_need_byteswap = false;
				}

				if(whether_need_byteswap)
				{
					std::span<IntegerType> temporary_span { output_vector.data(), output_vector.size() };

					for(auto& temporary_value : temporary_span )
					{
						#if __cpp_lib_byteswap

						input_value = std::byteswap(value);

						#else

						temporary_value = ByteSwap::byteswap(temporary_value);

						#endif
					}
				}

				return output_vector;
			}
		}

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
				CommonToolkit::MessagePacking<unsigned int>(byteSpan, &InputWord);

				OutputWord = (InputWord << 8) | (InputWord >> 24);

				std::vector<unsigned int> words
				{
					OutputWord
				};
				std::span<unsigned int> wordSpan{ words };
				CommonToolkit::MessageUnpacking<unsigned int>(wordSpan, bytes.data());

				Word.operator[](0) = static_cast<unsigned char>(bytes.operator[](0));
				Word.operator[](1) = static_cast<unsigned char>(bytes.operator[](1));
				Word.operator[](2) = static_cast<unsigned char>(bytes.operator[](2));
				Word.operator[](3) = static_cast<unsigned char>(bytes.operator[](3));

				bytes.clear();
				words.clear();

		*/

		template<typename IntegerType, typename ByteType>
		requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
		void MessageUnpacking(const std::span<const IntegerType>& input, ByteType* output)
		{
			if(output == nullptr)
			{
				throw std::logic_error("The target of the copied byte must not be a null pointer!");
			}

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

					value = ByteSwap::byteswap(value);

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

		template<typename IntegerType, typename ByteType>
		requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
		std::vector<ByteType> MessageUnpacking(const IntegerType* input_pointer, std::size_t input_size)
		{
			if(input_pointer == nullptr)
				throw std::logic_error("The source of the copied byte must not be a null pointer!");

			if(input_size == 0)
				throw std::logic_error("The source size of the copied bytes cannot be 0!");
			else
			{
				std::vector<IntegerType> temporary_vector(input_pointer, input_pointer + input_size);

				bool whether_need_byteswap = false;
				//whether_need_byteswap is true
				if constexpr (std::endian::native == std::endian::big)
				{
					whether_need_byteswap = true;
				}
				//whether_need_byteswap is false
				else if constexpr (std::endian::native == std::endian::little)
				{
					whether_need_byteswap = false;
				}

				if(whether_need_byteswap)
				{
					std::span<IntegerType> temporary_span { temporary_vector.begin(), temporary_vector.end() };

					for(auto& temporary_value : temporary_span )
					{
						#if __cpp_lib_byteswap

						input_value = std::byteswap(value);

						#else

						temporary_value = ByteSwap::byteswap(temporary_value);

						#endif
					}

					std::vector<ByteType> output_vector(input_size * sizeof(IntegerType), 0);

					std::memcpy(output_vector.data(), temporary_vector.data(), output_vector.size());

					return output_vector;
				}
				else
				{
					std::vector<ByteType> output_vector(input_size * sizeof(IntegerType), 0);

					std::memcpy(output_vector.data(), input_pointer, output_vector.size());

					return output_vector;
				}
			}
		}

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

		#endif

		#if defined( INTEGER_UNPACKCATION_OLD ) && __cplusplus <= 202002L

		inline std::vector<unsigned char> ByteArrayFromInteger32Bit( const int32_t& number, std::vector<unsigned char>& temporaryBytes )
		{
			temporaryBytes.operator[](0) = (number & 0x000000FF);
			temporaryBytes.operator[](1) = (number & 0x0000FF00) >> 8;
			temporaryBytes.operator[](2) = (number & 0x00FF0000) >> 16;
			temporaryBytes.operator[](3) = (number & 0xFF000000) >> 24;

			return temporaryBytes;
		}

		inline std::vector<unsigned char> ByteArrayFromInteger64Bit( const int64_t& number, std::vector<unsigned char>& temporaryBytes )
		{
			temporaryBytes.operator[](0) = (number & 0x00000000000000FF);
			temporaryBytes.operator[](1) = (number & 0x000000000000FF00) >> 8;
			temporaryBytes.operator[](2) = (number & 0x0000000000FF0000) >> 16;
			temporaryBytes.operator[](3) = (number & 0x00000000FF000000) >> 24;
			temporaryBytes.operator[](4) = (number & 0x000000FF00000000) >> 32;
			temporaryBytes.operator[](5) = (number & 0x0000FF0000000000) >> 40;
			temporaryBytes.operator[](6) = (number & 0x00FF000000000000) >> 48;
			temporaryBytes.operator[](7) = (number & 0xFF00000000000000) >> 56;

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

	#endif
	}
}
