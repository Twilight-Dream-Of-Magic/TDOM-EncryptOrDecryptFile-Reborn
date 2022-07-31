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

#include "./CPP2020_Concept.hpp"

#ifndef COMMON_TOOLKIT_HPP
#define COMMON_TOOLKIT_HPP

#if __cplusplus >= 201103L && __cplusplus <= 201703L
inline std::wstring cpp2017_string2wstring(const std::string &_string)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(_string);
}

inline std::string cpp2017_wstring2string(const std::wstring &_wstring)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(_wstring);
}
#endif

inline std::wstring string2wstring(const std::string& _string)
{
	::setlocale(LC_ALL, "");
	std::vector<wchar_t> wide_character_buffer;
	std::size_t source_string_count = 1;
	std::size_t found_not_ascii_count = 0;
	for(auto begin = _string.begin(), end = _string.end(); begin != end; begin++)
	{
		if(static_cast<const long long>(*begin) > 0)
		{
			++source_string_count;
		}
		else if (static_cast<const long long>(*begin) < 0)
		{
			++found_not_ascii_count;
		}
	}

	std::size_t target_wstring_count = source_string_count + (found_not_ascii_count / 2);

	wide_character_buffer.resize(target_wstring_count);

	#if defined(_MSC_VER)
	std::size_t _converted_count = 0;
	::mbstowcs_s(&_converted_count, &wide_character_buffer[0], target_wstring_count, _string.c_str(), ((size_t)-1));
	#else
	::mbstowcs(&wide_character_buffer[0], _string.c_str(), target_wstring_count);
	#endif

	std::size_t _target_wstring_size = 0;
	for(auto begin = wide_character_buffer.begin(), end = wide_character_buffer.end(); begin != end && *begin != L'\0'; begin++)
	{
		++_target_wstring_size;
	}
	std::wstring _wstring{ wide_character_buffer.data(),  _target_wstring_size };

	#if defined(_MSC_VER)
	if(_converted_count == 0)
	{
		throw std::runtime_error("The function string2wstring is not work !");
	}
	#endif

	if(found_not_ascii_count > 0)
	{
		//Need Contains character('\0') then check size
		if(((_target_wstring_size + 1) - source_string_count) != (found_not_ascii_count / 2))
		{
			throw std::runtime_error("The function string2wstring, An error occurs during conversion !");
		}
		else
		{
			return _wstring;
		}
	}
	else
	{
		//Need Contains character('\0') then check size
		if((_target_wstring_size + 1) != source_string_count)
		{
			 throw std::runtime_error("The function string2wstring, An error occurs during conversion !");
		}
		else
		{
			return _wstring;
		}
	}

}

inline std::string wstring2string(const std::wstring& _wstring)
{
	::setlocale(LC_ALL, "");
	std::vector<char> character_buffer;
	std::size_t source_wstring_count = 1;
	std::size_t found_not_ascii_count = 0;
	for(auto begin = _wstring.begin(), end = _wstring.end(); begin != end; begin++)
	{
		if(static_cast<const long long>(*begin) < 256)
		{
			++source_wstring_count;
		}
		else if (static_cast<const long long>(*begin) >= 256)
		{
			++found_not_ascii_count;
		}
	}
	std::size_t target_string_count = source_wstring_count + found_not_ascii_count * 2;

	character_buffer.resize(target_string_count);

	#if defined(_MSC_VER)
	std::size_t _converted_count = 0;
	::wcstombs_s(&_converted_count, &character_buffer[0], target_string_count, _wstring.c_str(), ((size_t)-1));
	#else
	::wcstombs(&character_buffer[0], _wstring.c_str(), target_string_count);
	#endif

	std::size_t _target_string_size = 0;
	for(auto begin = character_buffer.begin(), end = character_buffer.end(); begin != end && *begin != '\0'; begin++)
	{
		++_target_string_size;
	}
	std::string _string{ character_buffer.data(),  _target_string_size };

	#if defined(_MSC_VER)
	if(_converted_count == 0)
	{
		throw std::runtime_error("The function wstring2string is not work !");
	}
	#endif

	if(found_not_ascii_count > 0)
	{
		if(((_target_string_size + 1) - source_wstring_count) != (found_not_ascii_count * 2))
		{
			throw std::runtime_error("The function wstring2string, An error occurs during conversion !");
		}
		else
		{
			return _string;
		}
	}
	else
	{
		if((_target_string_size + 1) != source_wstring_count)
		{
			throw std::runtime_error("The function wstring2string, An error occurs during conversion !");
		}
		else
		{
			return _string;
		}
	}
}

#if __cplusplus >= 202002L

namespace CommonToolkit
{
	using namespace EODF_Reborn_CommonToolkit::CPP2020_Concepts;

	namespace MakeArrayImplement
	{
		template<typename Type, std::size_t N, std::size_t... I>
		constexpr auto make_array(std::index_sequence<I...>)
		{
			return std::array<Type, N>{ {I...} };
		}

		template<typename Type, typename FunctionType, std::size_t... Is>
		requires std::invocable<FunctionType>
		constexpr auto generate_array(FunctionType& function, std::index_sequence<Is...>) -> std::array<Type, sizeof...(Is)>
		{
			return {{ function(std::integral_constant<std::size_t, Is>{})... }};
		}
	}

	template<typename Type, std::size_t N>
	constexpr auto make_array()
	{
		static_assert(N >= Type{}, "no negative sizes");
		return MakeArrayImplement::make_array<Type, N>(std::make_index_sequence<N>{});
	}

	template<typename Type, std::size_t N, typename FunctionType>
	requires std::invocable<FunctionType>
	constexpr auto generate_array(FunctionType function)
	{
		return MakeArrayImplement::generate_array<Type>(function, std::make_index_sequence<N>{});
	}

	namespace MakeVectorImplement
	{
		template <typename Type, Type... VALUES>
		constexpr std::vector<Type> make_vector()
		{
			return std::vector<Type> { VALUES... };
		}
	}

	template <typename Type, Type... VALUES>
	constexpr std::vector<Type> make_vector( std::integer_sequence<Type, VALUES...> )
	{
		return MakeVectorImplement::make_vector<Type, VALUES...>();
	}

	//https://vladris.com/blog/2018/10/13/arithmetic-overflow-and-underflow.html
	//https://zh.cppreference.com/w/cpp/algorithm/iota
	template<bool is_increment_or_decrement, std::input_or_output_iterator IteratorType, typename IteratorSentinelType, typename NumericalType>
	requires std::sentinel_for<IteratorSentinelType, IteratorType>
	&& std::signed_integral<NumericalType>
	|| std::unsigned_integral<NumericalType>
	void numbers_sequence_generator(IteratorType first, IteratorSentinelType last, NumericalType value)
	{
		while (first != last)
		{
			*first++ = value;

			if constexpr(is_increment_or_decrement)
			{
				if(value + 1 == std::numeric_limits<NumericalType>::min())
					break;
				++value;
			}
			else if constexpr(is_increment_or_decrement)
			{
				if(value - 1 == std::numeric_limits<NumericalType>::max())
					break;
				--value;
			}
		}
	}

	template<bool is_increment_or_decrement, std::bidirectional_iterator IteratorType, typename IteratorSentinelType, typename NumericalType>
	requires std::integral<NumericalType>
	&& std::sentinel_for<IteratorSentinelType, IteratorType>
	void numbers_sequence_generator(IteratorType first, IteratorSentinelType last, NumericalType value, NumericalType other_value)
	{
		std::iter_difference_t<IteratorType> ranges_size = std::ranges::distance(first, last);

		if(ranges_size > 0)
		{
			while (first != last)
			{
				/*
					Equivalence Code:

					*first = value;
					first++;

				*/
				*first++ = value;

				if constexpr(is_increment_or_decrement)
				{
					//AdditionOverflows
					if( (other_value >= 0) && (value > std::numeric_limits<NumericalType>::max() - other_value) )
						break;
					//AdditionUnderflows
					else if( (other_value < 0) && (value < std::numeric_limits<NumericalType>::min() - other_value) )
						break;
					value += other_value;
				}
				else if constexpr(!is_increment_or_decrement)
				{
					//SubtractionOverflows
					if( (other_value < 0) && (value > std::numeric_limits<NumericalType>::max() + other_value) )
						break;
					//SubtractionOverflows
					else if( (other_value >= 0) && (value < std::numeric_limits<NumericalType>::min() + other_value) )
						break;
					value -= other_value;
				}
			}
		}
		else if (ranges_size < 0)
		{
			while (last != first)
			{
				/*
					Equivalence Code:

					*first = value;
					first--;

				*/
				*first-- = value;

				if constexpr(is_increment_or_decrement)
				{
					//AdditionOverflows
					if( (other_value >= 0) && (value > std::numeric_limits<NumericalType>::max() - other_value) )
						break;
					//AdditionUnderflows
					else if( (other_value < 0) && (value < std::numeric_limits<NumericalType>::min() - other_value) )
						break;
					value += other_value;
				}
				else if constexpr(!is_increment_or_decrement)
				{
					//SubtractionOverflows
					if( (other_value < 0) && (value > std::numeric_limits<NumericalType>::max() + other_value) )
						break;
					//SubtractionOverflows
					else if( (other_value >= 0) && (value < std::numeric_limits<NumericalType>::min() + other_value) )
						break;
					value -= other_value;
				}
			}
		}
		else
		{
			return;
		}
	}

	namespace ClassObjectComparer
	{
		template <typename Type>
		requires IsArithmeticDifferencesComparableType<Type>
		class LessThanOrder
		{
		public:
			bool operator()( Type leftObject, Type rightObject )
			{
				return leftObject > rightObject;
			}
		};

		template <typename Type>
		requires IsArithmeticDifferencesComparableType<Type>
		class GreaterThanOrder
		{
		public:
			bool operator()( Type leftObject, Type rightObject )
			{
				return leftObject < rightObject;
			}
		};

		template <typename Type>
		requires IsEqualityComparableType<Type>
		class EqualComparer
		{
		public:
			bool operator()( Type leftObject, Type rightObject )
			{
				return leftObject == rightObject;
			}
		};

		template <typename Type>
		requires IsEqualityComparableType<Type>
		class NotEqualComparer
		{
		public:
			bool operator()( Type leftObject, Type rightObject )
			{
				return leftObject != rightObject;
			}
		};
	}  // namespace ClassObjectComparer

	template <typename OtherType, typename DataObjectType>
	concept _Half_part_of_class_object_comparer = IsTwoSameType<CommonToolkit::ClassObjectComparer::template LessThanOrder<DataObjectType>, OtherType> || IsTwoSameType<CommonToolkit::ClassObjectComparer::template GreaterThanOrder<DataObjectType>, OtherType>;

	template <typename OtherType, typename DataObjectType>
	concept IsClassObjectComparerType = _Half_part_of_class_object_comparer<OtherType, DataObjectType> && IsArithmeticDifferencesComparableType<DataObjectType>;

	#if defined(__cpp_lib_char8_t)

	inline std::string from_u8string(const char8_t* utf8_string_data, std::size_t size)
	{
		std::u8string value = std::u8string(utf8_string_data, size);

		#if __cplusplus >= 202002L
		return std::string(std::bit_cast<char*>(&value), size);
		#else
		return std::string(reinterpret_cast<char*>(&value), size);
		#endif
	}

	inline std::string from_u8string(const std::u8string& utf8_string_data)
	{
		std::string string_data;

		for(auto& utf8_character : utf8_string_data)
		{
			const char const_utf8_character = static_cast<const char>(utf8_character);
			string_data.push_back( const_utf8_character );
		}

		return string_data;
	}

	inline std::string from_u8string(std::u8string&& utf8_string_data)
	{
		return std::move(std::string(utf8_string_data.begin(), utf8_string_data.end()));
	}

	#endif

	inline std::string from_wstring(const wchar_t* wstring_data)
	{
		std::wstring value = std::wstring(wstring_data, wcslen(wstring_data));

		return std::string(value.begin(), value.end());
	}

	inline std::string from_wstring(const std::wstring& wstring_data)
	{
		return wstring2string(wstring_data);
	}

	inline std::string from_wstring(std::wstring&& wstring_data)
	{
		return std::move(std::string(wstring_data.begin(), wstring_data.end()));
	}

	template <typename IteratorType>
	requires std::input_or_output_iterator<IteratorType>
	std::size_t IteratorOffsetDistance( IteratorType iteratorA, IteratorType iteratorB, std::size_t needOffsetCount )
	{
		//这里是指迭代器（泛型指针）偏移量，是否还有可以移动的距离
		//Here is the iterator (generic pointer) offset, whether there is still a distance that can be moved

		std::size_t iteratorMoveOffset = 0;
		if ( iteratorA != iteratorB )
		{
			std::size_t dataBlockDistanceDiffercnce = static_cast<std::size_t>( std::ranges::distance( iteratorA, iteratorB ) );
			iteratorMoveOffset = std::min( needOffsetCount, dataBlockDistanceDiffercnce );
		}
		return iteratorMoveOffset;
	}

	template <typename RangeType, typename IteratorType>
	requires std::input_or_output_iterator<IteratorType>
	RangeType ImplementationMakeSubrangeContent(IteratorType& iterator, std::size_t dataBlockDistanceDiffercnce, std::size_t& needOffsetCount, bool needUpdateaIterator)
	{
		RecheckRangeSize:

		if (needOffsetCount <= dataBlockDistanceDiffercnce)
		{
			// Sub-ranges are in of range
			//子范围是在范围内的
			RangeType subrange {iterator, iterator + needOffsetCount};

			if (needUpdateaIterator)
			{
				std::ranges::advance(iterator, needOffsetCount);
			}
			return subrange;
		}
		else
		{
			// Sub-ranges are out of range
			//子范围不在范围内
			while (needOffsetCount > dataBlockDistanceDiffercnce)
			{
				--needOffsetCount;
			}

			goto RecheckRangeSize;
		}
	}

	template <typename RangeType, typename IteratorType>
	requires std::input_or_output_iterator<IteratorType>
	RangeType MakeSubrangeContent( IteratorType& iteratorA, IteratorType iteratorB, std::size_t& needOffsetCount, bool needUpdateaIteratorA )
	{
		using RangeValueType = std::ranges::range_value_t<std::remove_cvref_t<RangeType>>;

		if constexpr(std::ranges::range<RangeType>)
		{
			// Sub-range has size
			//子范围有大小
			if (iteratorA != iteratorB)
			{
				std::size_t dataBlockDistanceDiffercnce = static_cast<std::size_t>(std::ranges::distance(iteratorA, iteratorB));
				return ImplementationMakeSubrangeContent<RangeType, IteratorType>(iteratorA, dataBlockDistanceDiffercnce, needOffsetCount, needUpdateaIteratorA);
			}
			else
			{
				return RangeType();
			}
		}
		else
		{
			static_assert(Dependent_Always_Failed<RangeType>, "RangeType is not a ranged container type!");
		}
	}

	//数据块的处理
	//Handling of data blocks
	namespace ProcessingDataBlock
	{
		template<typename Type>
		inline static constexpr bool IsArrayClassType()
		{
			return is_array_class_type<std::remove_cvref_t<Type>>;
		}

		template<typename Type, std::size_t N>
		inline static constexpr bool IsArrayClassType()
		{
			return is_array_class_type<std::remove_cvref_t<Type>>;
		}

		//文件数据拆分与结合
		//File data splitting and merging

		template <typename Range>
		concept DataBlockRangeBase = std::ranges::range<Range> && std::ranges::random_access_range<Range> || std::ranges::contiguous_range<Range>;

		template <typename Range>
		concept DataBlockRange = std::ranges::input_range<Range> || std::ranges::output_range<Range, std::ranges::range_value_t<Range>> || std::input_or_output_iterator<std::ranges::iterator_t<Range>>;

		/*
			Input_Range = std::deque<std::vector<int>>
			InpuOutput_IteratorType = std::back_insert_iterator< std::vector<int> >
			std::ranges::range_value_t<Input_Range> = std::vector<int>
			Type = std::ranges::range_value_t<std::ranges::range_value_t<Input_Range>> = int
			std::output_iterator<Output_IteratorType, Type>
			 => *out++ = an_int
		*/
		template <typename Input_Range, typename Output_IteratorType>
		concept MergerRanges = DataBlockRangeBase<Input_Range> && std::input_iterator<std::ranges::iterator_t<Input_Range>> && std::output_iterator<Output_IteratorType, std::ranges::range_value_t<std::ranges::range_value_t<Input_Range>>>;


		/*
			Input_Range = std::vector<int>
			InpuOutput_IteratorType = std::back_insert_iterator< std::deque<std::vector<int>> >
			std::output_iterator<Output_IteratorType, Input_Range>
			  => *out++ = a_vector_int (Input_Range)
		*/
		template <typename Input_Range, typename Output_IteratorType>
		concept SplitterRanges = DataBlockRangeBase<Input_Range> && std::input_iterator<std::ranges::iterator_t<Input_Range>> && std::output_iterator<Output_IteratorType, Input_Range>;

		//数据块拆分器类
		//Data block splitter class
		struct Splitter
		{
			enum class WorkMode
			{
				Copy,
				Move,
			};

			template <typename Input_Range, typename Output_Range>
			requires DataBlockRange<Input_Range> && DataBlockRange<Output_Range>
			void operator()
			(
				Input_Range&& this_input_range,
				Output_Range&& this_output_range,
				const std::size_t& partition_size,
				WorkMode mode
			)
			{
				using input_range_t = std::remove_cvref_t<Input_Range>;
				using input_range_value_t = std::ranges::range_value_t<input_range_t>;
				using output_range_t = std::remove_cvref_t<Output_Range>;
				using output_subrange_value_t = std::ranges::range_value_t<output_range_t>;

				if ( partition_size <= 0 )
				{
					return;
				}

				auto range_beginIterator = std::ranges::begin( this_input_range );
				auto range_endIterator = std::ranges::end( this_input_range );

				constexpr bool is_key_value_range = std::same_as<std::set<input_range_value_t>, input_range_t> || EODF_Reborn_CommonToolkit::CPP2020_Concepts::IsKeyValueMapType<input_range_t>;
				constexpr bool is_contiguous_range = std::ranges::contiguous_range<output_range_t>;
				constexpr bool is_random_access_range = std::ranges::random_access_range<output_range_t>;

				constexpr bool input_range_is_array_class_type = IsArrayClassType<input_range_t>();
				//constexpr bool input_sub_range_is_array_class_type = IsArrayClassType<input_range_value_t>();

				constexpr bool output_range_is_array_class_type = IsArrayClassType<output_range_t>();
				constexpr bool output_sub_range_is_array_class_type = IsArrayClassType<output_subrange_value_t>();

				if constexpr( input_range_is_array_class_type || output_range_is_array_class_type || output_sub_range_is_array_class_type && ( !is_key_value_range ) )
				{
					auto beginIterator = std::ranges::begin( this_output_range );
					auto endIterator = std::ranges::end( this_output_range );

					while ( range_beginIterator != range_endIterator )
					{
						auto offsetCount = std::min( partition_size, static_cast<std::size_t>( std::ranges::distance( range_beginIterator, range_endIterator ) ) );
						std::vector<input_range_value_t> input_data_buffer(range_beginIterator, std::ranges::next( range_beginIterator, offsetCount ));
						output_subrange_value_t& output_data_buffer = *beginIterator;

						auto* byte_data_pointer = &(*input_data_buffer.begin());
						auto byte_data_size = input_data_buffer.size() * sizeof(input_range_value_t);
						auto* byte_data_pointer2 = &(*output_data_buffer.begin());
						std::memcpy(byte_data_pointer2, byte_data_pointer, byte_data_size);

						/*for(std::size_t index = 0; index < input_data_buffer.size() && index < output_data_buffer.size(); ++index)
						{
							output_data_buffer[index] = input_data_buffer[index];
						}*/

						std::ranges::advance( range_beginIterator, offsetCount );

						if( beginIterator != endIterator )
							std::ranges::advance( beginIterator, 1 );
					}

					if ( mode == WorkMode::Move )
					{
						if constexpr(std::destructible<input_range_value_t>)
						{
							for ( auto&& sub_range_container : this_input_range )
							{
								std::destroy_at(std::addressof(sub_range_container));
							}
						}
						else if(std::integral<input_range_value_t> || std::is_pointer_v<input_range_value_t>)
						{
							const input_range_value_t value = 0;
							std::ranges::fill(this_input_range.begin(), this_input_range.end(), value);
						}
					}

					return;
				}
				else
				{
					while ( range_beginIterator != range_endIterator )
					{
						auto offsetCount = std::min( partition_size, static_cast<std::size_t>( std::ranges::distance( range_beginIterator, range_endIterator ) ) );
						output_subrange_value_t sub_range_container( range_beginIterator, range_beginIterator + offsetCount );

						if constexpr ( is_key_value_range )
						{
							this_output_range.emplace_hint( this_output_range.end(), std::move( sub_range_container ) );
							sub_range_container.clear();

							while ( offsetCount != 0 )
							{
								range_beginIterator++;
								--offsetCount;
							}

							continue;
						}
						else if constexpr ( is_random_access_range )
						{
							this_output_range.emplace( this_output_range.end(), std::move( sub_range_container ) );

							sub_range_container.clear();
							range_beginIterator += offsetCount;
						}
						else if constexpr ( is_contiguous_range )
						{
							std::ranges::copy( std::make_move_iterator( sub_range_container.begin() ), std::make_move_iterator( sub_range_container.end() ), this_output_range.end() );
						}
					}

					if ( mode == WorkMode::Move )
					{
						this_input_range.clear();
					}

					return;
				}
			}

			/*
			Use:
			std::deque<std::vector<int>> target;
			std::vector<int> source;

			split(source, std::back_inserter(target), 24);

			*/

			template <typename Input_Range, typename Output_IteratorType>
			requires SplitterRanges<Input_Range, Output_IteratorType>
			void operator()
			(
				Input_Range&& one_input_range,
				Output_IteratorType many_output_range,
				const size_t partition_size
			)
			{
				if ( partition_size <= 0 )
				{
					return;
				}

				auto range_beginIterator = std::ranges::begin( one_input_range );
				auto range_endIterator = std::ranges::end( one_input_range );

				while ( range_beginIterator != range_endIterator )
				{
					auto offsetCount = std::min( partition_size, static_cast<std::size_t>( std::ranges::distance( range_beginIterator, range_endIterator ) ) );
					*many_output_range++ = { range_beginIterator, std::ranges::next( range_beginIterator, offsetCount ) };;
					std::ranges::advance( range_beginIterator, offsetCount );
				}
			}
		};

		inline Splitter splitter;

		//数据块结合器类
		//Data block merger class
		struct Merger
		{
			enum class WorkMode
			{
				Copy,
				Move,
			};

			template <typename Input_Range, typename Output_Range>
			requires DataBlockRange<Input_Range> && DataBlockRange<Output_Range>
			void operator()
			(
				Input_Range&& this_input_range,
				Output_Range&& this_output_range,
				WorkMode mode
			)
			{
				using input_range_t = std::remove_cvref_t<Input_Range>;
				using input_subrange_value_t = std::ranges::range_value_t<input_range_t>;
				using output_range_t = std::remove_cvref_t<Output_Range>;
				using output_range_value_t = std::ranges::range_value_t<output_range_t>;

				constexpr bool input_range_is_array_class_type = IsArrayClassType<input_range_t>();
				constexpr bool input_sub_range_is_array_class_type = IsArrayClassType<input_subrange_value_t>();

				constexpr bool output_range_is_array_class_type = IsArrayClassType<output_range_t>();
				//constexpr bool output_sub_range_is_array_class_type = IsArrayClassType<output_subrange_value_t>();

				if constexpr( input_range_is_array_class_type || input_sub_range_is_array_class_type || output_range_is_array_class_type )
				{
					std::size_t byte_pointer_offset = 0;
					for ( auto&& sub_range_container : this_input_range )
					{
						auto* byte_data_pointer = &(*sub_range_container.begin());
						auto byte_data_size = sub_range_container.size() * sizeof(output_range_value_t);
						auto* byte_data_pointer2 = &(*this_output_range.begin());
						std::memcpy(byte_data_pointer2 + byte_pointer_offset, byte_data_pointer, byte_data_size);
						byte_pointer_offset += byte_data_size;
					}
				}
				else
				{
					for ( auto&& sub_range_container : this_input_range )
					{
						std::ranges::copy(sub_range_container.begin(), sub_range_container.end(), this_output_range.rbegin());
					}
				}

				if ( mode == WorkMode::Move )
				{
					if constexpr(std::destructible<input_subrange_value_t>)
					{
						for ( auto&& sub_range_container : this_input_range )
						{
							std::destroy_at(std::addressof(sub_range_container));
						}
					}
					else if(std::integral<input_subrange_value_t> || std::is_pointer_v<input_subrange_value_t>)
					{
						const input_subrange_value_t value = 0;
						std::ranges::fill(this_input_range.begin(), this_input_range.end(), value);
					}
				}
			}

			/*
			Use:
			std::deque<std::vector<int>> source;
			std::vector<int> target;

			merge(source, std::back_inserter(target));

			*/

			template <typename Input_Range, typename Output_IteratorType>
			requires MergerRanges<Input_Range, Output_IteratorType>
			void operator()( Input_Range&& many, Output_IteratorType one )
			{
				for ( auto&& sub_range : many )
				{
					for ( auto&& value : sub_range )
					{
						*one++ = value;
					}
				}
			}
		};

		inline Merger merger;

	}  // namespace ProcessingDataBlock

	#if defined( TEST_CPP2020_RANGE_MODIFIER )

	void TestCPP2020RangesModifier()
	{
		std::deque<std::vector<int>> source { { 1, 2, 3 }, { 4, 5, 6 } };
		std::vector<int>			 target1;

		ProcessingDataBlock::merger( source, std::back_inserter( target1 ) );
		for ( auto v : target1 )
			std::cout << v << ' ';

		std::cout << '\n';

		std::deque<std::vector<int>> target2;
		ProcessingDataBlock::splitter( target1, std::back_inserter( target2 ), 2 );

		for ( const auto& sub : target2 )
		{
			for ( auto v : sub )
			{
				std::cout << v << ' ';
			}
			std::cout << '\n';
		}
	}

	#endif

	#if 0

	namespace ModularArithmetic
	{
		template<typename IntegerType>
		requires std::integral<IntegerType> && std::unsigned_integral<IntegerType> || std::signed_integral<IntegerType>
		class SafeRangedInteger
		{

		private:
			IntegerType result_value = 0;
			IntegerType modulus_value = 0;

			/*
				https://vladris.com/blog/2018/10/13/arithmetic-overflow-and-underflow.html
			*/

			template <typename IntegerType>
			constexpr bool AdditionOverflows(const IntegerType& a, const IntegerType& b)
			{
				return (b >= 0) && (a > std::numeric_limits<IntegerType>::max() - b);
			}

			template <typename IntegerType>
			constexpr bool AdditionUnderflows(const IntegerType& a, const IntegerType& b)
			{
				return (b < 0) && (a < std::numeric_limits<IntegerType>::min() - b);
			}

			template <typename IntegerType>
			constexpr bool SubtractionOverflows(const IntegerType& a, const IntegerType& b)
			{
				return (b < 0) && (a > std::numeric_limits<IntegerType>::max() + b);
			}

			template <typename IntegerType>
			constexpr bool SubtractionUnderflows(const IntegerType& a, const IntegerType& b)
			{
				return (b >= 0) && (a < std::numeric_limits<IntegerType>::min() + b);
			}

			template <typename IntegerType>
			constexpr bool MultiplicationOverflows(const IntegerType& a, const IntegerType& b)
			{
				if (b == 0) return false; // Avoid division by 0
				return ((b > 0) && (a > 0) && (a > std::numeric_limits<IntegerType>::max() / b))
					|| ((b < 0) && (a < 0) && (a < std::numeric_limits<IntegerType>::max() / b));
			}

			template <typename IntegerType>
			constexpr bool MultiplicationUnderflows(const IntegerType& a, const IntegerType& b)
			{
				if (b == 0) return false; // Avoid division by 0
				return ((b > 0) && (a < 0) && (a < std::numeric_limits<IntegerType>::min() / b))
					|| ((b < 0) && (a > 0) && (a > std::numeric_limits<IntegerType>::min() / b));
			}

			template <typename IntegerType>
			constexpr bool DivisionOverflows(const IntegerType& a, const IntegerType& b)
			{
				return (a == std::numeric_limits<IntegerType>::min()) && (b == -1)
					&& (a != 0);
			}

			/*
				算术(Arithmetic)Overflow的意思是：计算的结果大于最大值，并且多余的值从最小值再次向着最大值的方向溢出
				算术(Arithmetic)Underflow的意思是：计算的结果小于最小值，并且多余的值从最大值再次向着到最小值的方向溢出

				Arithmetic Overflow means that the result of the calculation is greater than the maximum value, and the excess value overflows from the minimum value to the maximum value direction again.
				Arithmetic Underflow means that the result of the calculation is less than the minimum value and the excess value overflows from the maximum value to the minimum value direction again.
			*/

			IntegerType DoAddition(IntegerType a, IntegerType b)
			{
				if(AdditionOverflows(a,b))
				{
					IntegerType c = a + b;

					if( std::abs((long long)std::numeric_limits<IntegerType>::min() - c) > std::abs((long long)std::numeric_limits<IntegerType>::max() - c) )
						return std::numeric_limits<IntegerType>::max() - std::abs((long long)b) - std::abs((long long)b);
					else if( std::abs((long long)std::numeric_limits<IntegerType>::min() - c) < std::abs((long long)std::numeric_limits<IntegerType>::max() - c) )
						return std::numeric_limits<IntegerType>::min() + std::abs((long long)b) + std::abs((long long)b);

					c = 0;
				}

				if(AdditionUnderflows(a,b))
				{
					IntegerType c = a + b;

					if( std::abs((long long)std::numeric_limits<IntegerType>::max - c) > std::abs((long long)c - std::numeric_limits<IntegerType>::min()) )
						return std::numeric_limits<IntegerType>::max() + std::abs((long long)b) + std::abs((long long)b);
					else if( std::abs((long long)std::numeric_limits<IntegerType>::max - c) < std::abs((long long)c - std::numeric_limits<IntegerType>::min()) )
						return std::numeric_limits<IntegerType>::min() - std::abs((long long)b) - std::abs((long long)b);

					c = 0;
				}

				if(this->modulus_value != static_cast<IntegerType>(0))
					return (a + b) % this->modulus_value;
				else
					return (a + b);
			}

			IntegerType DoSubtraction(IntegerType a, IntegerType b)
			{
				if(SubtractionOverflows(a,b))
				{
					IntegerType c = a - b;

					if( std::abs((long long)std::numeric_limits<IntegerType>::min() - c) > std::abs((long long)std::numeric_limits<IntegerType>::max() - c) )
						return std::numeric_limits<IntegerType>::max() + std::abs((long long)b) + std::abs((long long)b);
					else if( std::abs((long long)std::numeric_limits<IntegerType>::min() - c) < std::abs((long long)std::numeric_limits<IntegerType>::max() - c) )
						return std::numeric_limits<IntegerType>::min() - std::abs((long long)b) - std::abs((long long)b);

					c = 0;
				}

				if(SubtractionUnderflows(a,b))
				{
					IntegerType c = a - b;

					if( std::abs((long long)std::numeric_limits<IntegerType>::max() - c) > std::abs((long long)c - std::numeric_limits<IntegerType>::min()) )
						return std::numeric_limits<IntegerType>::max() - std::abs((long long)b) - std::abs((long long)b);
					else if( std::abs((long long)std::numeric_limits<IntegerType>::max()  - c) < std::abs((long long)c - std::numeric_limits<IntegerType>::min()) )
						return std::numeric_limits<IntegerType>::min() + std::abs((long long)b) + std::abs((long long)b);

					c = 0;
				}

				if(this->modulus_value != static_cast<IntegerType>(0))
					return (a - b) % this->modulus_value;
				else
					return (a - b);
			}

			IntegerType DoMultiplication(IntegerType a, IntegerType b)
			{
				if(MultiplicationOverflows(a,b))
				{
					return (a * (b - static_cast<IntegerType>(1)));
				}

				if(MultiplicationUnderflows(a,b))
				{
					return (a * (b - static_cast<IntegerType>(1)));
				}

				if(this->modulus_value != static_cast<IntegerType>(0))
					return (a * b) % this->modulus_value;
				else
					return (a * b);
			}

			IntegerType DoDivision(IntegerType a, IntegerType b)
			{
				if(DivisionOverflows(a,b))
				{
					return (a * (1 / b) ) + b;
				}

				if(a == static_cast<IntegerType>(0))
					return b;

				if(b == static_cast<IntegerType>(0))
					return a;

				if(this->modulus_value != static_cast<IntegerType>(0))
					return (a * (1 / b) ) % this->modulus_value;
				else
					return (a * (1 / b) );
			}

		public:
			IntegerType AccessValue() const
			{
				return result_value;
			}

			void UpdateModulusValue(IntegerType modulus_value_argument)
			{
				modulus_value = modulus_value_argument;
			}

			friend bool operator==(SafeRangedInteger left, SafeRangedInteger right)
			{
				if(left.result_value == right.result_value && left.modulus_value == right.modulus_value)
				{
					return true;
				}
				return false;
			}

			friend bool operator!=(SafeRangedInteger left, SafeRangedInteger right)
			{
				return !(left == right);
			}

			friend SafeRangedInteger operator+(SafeRangedInteger& safe_integer_object, IntegerType value)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoAddition(safe_integer_object.result_value, value);
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator+(IntegerType value, SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoAddition(value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator-(SafeRangedInteger& safe_integer_object, IntegerType value)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoSubtraction(safe_integer_object.result_value, value);
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator-(IntegerType value, SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoSubtraction(value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator*(SafeRangedInteger& safe_integer_object, IntegerType value)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoMultiplication(safe_integer_object.result_value, value);
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator*(IntegerType value, SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoMultiplication(value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator/(SafeRangedInteger& safe_integer_object, IntegerType value)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoDivision(safe_integer_object.result_value, value);
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator/(IntegerType value, SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoDivision(value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator^(SafeRangedInteger& safe_integer_object, IntegerType value)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = safe_integer_object.result_value ^ value;
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator^(IntegerType value, SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = value ^ safe_integer_object.result_value;
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator|(SafeRangedInteger& safe_integer_object, IntegerType value)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = safe_integer_object.result_value | value;
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator|(IntegerType value, SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = value | safe_integer_object.result_value;
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator&(SafeRangedInteger& safe_integer_object, IntegerType value)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = safe_integer_object.result_value & value;
				return copied_safe_integer;
			}

			friend SafeRangedInteger operator&(IntegerType value, SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = value & safe_integer_object.result_value;
				return copied_safe_integer;
			}

			SafeRangedInteger operator+(SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoAddition(result_value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			SafeRangedInteger operator+(SafeRangedInteger&& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoAddition(result_value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			SafeRangedInteger& operator+=(SafeRangedInteger& safe_integer_object)
			{
				result_value = this->DoAddition(result_value, safe_integer_object.result_value);
				return *this;
			}

			SafeRangedInteger& operator+=(SafeRangedInteger&& safe_integer_object)
			{
				result_value = this->DoAddition(result_value, safe_integer_object.result_value);
				return *this;
			}

			SafeRangedInteger operator-(SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoSubtraction(result_value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			SafeRangedInteger operator-(SafeRangedInteger&& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoSubtraction(result_value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			SafeRangedInteger& operator-=(SafeRangedInteger& safe_integer_object)
			{
				result_value = this->DoSubtraction(result_value, safe_integer_object.result_value);
				return *this;
			}

			SafeRangedInteger& operator-=(SafeRangedInteger&& safe_integer_object)
			{
				result_value = this->DoSubtraction(result_value, safe_integer_object.result_value);
				return *this;
			}

			SafeRangedInteger operator*(SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoMultiplication(result_value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			SafeRangedInteger operator*(SafeRangedInteger&& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoMultiplication(result_value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			SafeRangedInteger& operator*=(SafeRangedInteger& safe_integer_object)
			{
				result_value = this->DoMultiplication(result_value, safe_integer_object.result_value);
				return *this;
			}

			SafeRangedInteger& operator*=(SafeRangedInteger&& safe_integer_object)
			{
				result_value = this->DoMultiplication(result_value, safe_integer_object.result_value);
				return *this;
			}

			SafeRangedInteger operator/(SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoDivision(result_value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			SafeRangedInteger operator/(SafeRangedInteger&& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = this->DoDivision(result_value, safe_integer_object.result_value);
				return copied_safe_integer;
			}

			SafeRangedInteger& operator/=(SafeRangedInteger& safe_integer_object)
			{
				result_value = this->DoDivision(result_value, safe_integer_object.result_value);
				return *this;
			}

			SafeRangedInteger& operator/=(SafeRangedInteger&& safe_integer_object)
			{
				result_value = this->DoDivision(result_value, safe_integer_object.result_value);
				return *this;
			}

			SafeRangedInteger operator^(SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = result_value ^ safe_integer_object.result_value;
				return copied_safe_integer;
			}

			SafeRangedInteger operator^(SafeRangedInteger&& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = result_value ^ safe_integer_object.result_value;
				return copied_safe_integer;
			}

			SafeRangedInteger operator^=(SafeRangedInteger& safe_integer_object)
			{
				result_value ^= safe_integer_object.result_value;
				return *this;
			}

			SafeRangedInteger operator^=(SafeRangedInteger&& safe_integer_object)
			{
				result_value ^= safe_integer_object.result_value;
				return *this;
			}

			SafeRangedInteger operator|(SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = result_value | safe_integer_object.result_value;
				return copied_safe_integer;
			}

			SafeRangedInteger operator|(SafeRangedInteger&& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = result_value | safe_integer_object.result_value;
				return copied_safe_integer;
			}

			SafeRangedInteger& operator|=(SafeRangedInteger& safe_integer_object)
			{
				result_value |= safe_integer_object.result_value;
				return *this;
			}

			SafeRangedInteger& operator|=(SafeRangedInteger&& safe_integer_object)
			{
				result_value |= safe_integer_object.result_value;
				return *this;
			}

			SafeRangedInteger operator&(SafeRangedInteger& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = result_value & safe_integer_object.result_value;
				return copied_safe_integer;
			}

			SafeRangedInteger operator&(SafeRangedInteger&& safe_integer_object)
			{
				SafeRangedInteger copied_safe_integer(0);
				copied_safe_integer = result_value & safe_integer_object.result_value;
				return copied_safe_integer;
			}

			SafeRangedInteger& operator&=(SafeRangedInteger& safe_integer_object)
			{
				result_value &= safe_integer_object.result_value;
				return *this;
			}

			SafeRangedInteger& operator&=(SafeRangedInteger&& safe_integer_object)
			{
				result_value &= safe_integer_object.result_value;
				return *this;
			}

			SafeRangedInteger& operator~()
			{
				return ~result_value;
			}

			SafeRangedInteger& operator=(const IntegerType update_value)
			{
				this->result_value = update_value;

				return *this;
			}

			SafeRangedInteger& operator=(const SafeRangedInteger& safe_integer_object)
			{
				if(this == std::addressof(safe_integer_object))
					return;

				*this = SafeRangedInteger(safe_integer_object);

				if(modulus_value == static_cast<IntegerType>(0))
					modulus_value = static_cast<IntegerType>(1);

				return *this;
			}

			SafeRangedInteger& operator=(SafeRangedInteger&& safe_integer_object)
			{
				if(this == std::addressof(safe_integer_object))
					return *this;

				std::destroy_at(this);

				std::construct_at(this, safe_integer_object);

				return *this;
			}

			SafeRangedInteger(const SafeRangedInteger& safe_integer_object)
			{
				this->result_value = safe_integer_object.result_value;
				this->modulus_value = safe_integer_object.modulus_value;
			}

			SafeRangedInteger(SafeRangedInteger&& safe_integer_object)
			{
				this->result_value = safe_integer_object.result_value;
				this->modulus_value = safe_integer_object.modulus_value;
			}

			explicit SafeRangedInteger(IntegerType result_value_argument)
				: result_value(result_value_argument)
			{
				
			}

			explicit SafeRangedInteger(IntegerType result_value_argument, IntegerType modulus_value_argument)
				: result_value(result_value_argument), modulus_value(modulus_value_argument)
			{

			}

			~SafeRangedInteger()
			{
				result_value = 0;
				modulus_value = 0;
			}

		};
	}

	#endif

}  // namespace CommonToolkit

#endif	// __cplusplus

inline int CatchErrorCode( const std::error_code& error_code_object );

inline void AnalysisErrorCode( const std::error_code& error_code_object );

inline int CatchErrorCode( const std::error_code& error_code_object )
{
	const int error_code_number = error_code_object.value();
	if(error_code_number != 0)
	{
		return error_code_number;
	}
	else
	{
		return 0;
	}
}

inline void AnalysisErrorCode( const std::error_code& error_code_object )
{
	const int error_code_number = error_code_object.value();

	#if 0

		if(error_code_number != 0)
		{
			const std::string& error_message = error_code_object.message();
			std::cout << CommonToolkit::from_u8string(u8"发生错误，已获得标准系统错误代码，代码为：") << error_code_number << ", 中止..." << std::endl;
			std::cout << "Error occurred, Standard system error codes have been obtained, code is: " << error_code_number << ", aborting..." << std::endl;
			std::cout << CommonToolkit::from_u8string(u8"The error message is(错误消息是): ") << error_message << std::endl;

			throw std::system_error(error_code_object);
		}

	#else

		if(error_code_number != 0)
		{
			const std::string& error_message = error_code_object.message();
			std::cout << CommonToolkit::from_wstring(L"发生错误，已获得标准系统错误代码，代码为：") << error_code_number << CommonToolkit::from_wstring(L", 中止...") << std::endl;
			std::cout << "Error occurred, Standard system error codes have been obtained, code is: " << error_code_number << ", aborting..." << std::endl;
			std::cout << CommonToolkit::from_wstring(L"The error message is(错误消息是): ") << error_message << std::endl;

			throw std::system_error(error_code_object);
		}

	#endif
}

#endif	// !COMMON_TOOLKIT_HPP
