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

#if defined(_WIN32) || defined(_WIN64)

#if __cplusplus >= 201103L && __cplusplus <= 201703L
std::wstring cpp2017_string2wstring(const std::string &_string)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.from_bytes(_string);
}

std::string cpp2017_wstring2string(const std::wstring &_wstring)
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
    std::size_t _converted_count = 0;
    ::mbstowcs_s(&_converted_count, &wide_character_buffer[0], target_wstring_count, _string.c_str(), ((size_t)-1));

    std::size_t _target_wstring_size = 0;
    for(auto begin = wide_character_buffer.begin(), end = wide_character_buffer.end(); begin != end && *begin != L'\0'; begin++)
    {
        ++_target_wstring_size;
    }
    std::wstring _wstring{ wide_character_buffer.data(),  _target_wstring_size };

    if(_converted_count == 0)
    {
        throw std::runtime_error("The function string2wstring is not work !");
    }
    else
    {
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
    ::size_t _converted_count = 0;
    ::wcstombs_s(&_converted_count, &character_buffer[0], target_string_count, _wstring.c_str(), ((size_t)-1));

    std::size_t _target_string_size = 0;
    for(auto begin = character_buffer.begin(), end = character_buffer.end(); begin != end, *begin != '\0'; begin++)
    {
        ++_target_string_size;
    }
    std::string _string{ character_buffer.data(),  _target_string_size };

    if(_converted_count == 0)
    {
        throw std::runtime_error("The function wstring2string is not work !");
    }
    else
    {
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
}
#endif

#if __cplusplus >= 202002L

namespace CommonToolkit
{
	// false value attached to a dependent name (for static_assert)
	template <class>
	inline constexpr bool Dependent_Always_Failed = false;
	// true value attached to a dependent name (for static_assert)
	template <class>
	inline constexpr bool Dependent_Always_Succeed = true;

	template<class T> struct dependent_always_true : std::true_type {};
	template<class T> struct dependent_always_false : std::false_type {};

	using namespace EODF_Reborn_CommonToolkit::CPP2020_Concepts;

	template <typename Type, Type... VALUES>
	std::vector<Type> make_vector()
	{
		return std::vector<Type> { VALUES... };
	}

	template <typename Type, Type... VALUES>
	std::vector<Type> make_vector( std::integer_sequence<Type, VALUES...> )
	{
		return make_vector<Type, VALUES...>();
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

				RecheckRangeSize:

                if (needOffsetCount <= dataBlockDistanceDiffercnce)
                {
                    // Sub-ranges are in of range
                    //子范围是在范围内的
					RangeType subrange {iteratorA, iteratorA + needOffsetCount};

                    if (needUpdateaIteratorA)
                    {
                        std::ranges::advance(iteratorA, needOffsetCount);
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
			void operator()( Input_Range& input_range, Output_Range& output_range, const std::size_t& partition_size, WorkMode mode )
			{
				using input_range_t = std::remove_cvref_t<Input_Range>;
				using input_range_value_t = std::ranges::range_value_t<input_range_t>;
				using output_range_t = std::remove_cvref_t<Output_Range>;
				using output_subrange_t = std::ranges::range_value_t<output_range_t>;

				if ( partition_size <= 0 )
				{
					return;
				}

				auto range_beginIterator = input_range.begin();
				auto range_endIterator = input_range.end();

				constexpr bool is_key_value_range = std::same_as<std::set<input_range_value_t>, input_range_t> || EODF_Reborn_CommonToolkit::CPP2020_Concepts::IsKeyValueMapType<input_range_t>;
				constexpr bool is_contiguous_range = std::ranges::contiguous_range<output_range_t>;
				constexpr bool is_random_access_range = std::ranges::random_access_range<output_range_t>;

				while ( range_beginIterator != range_endIterator )
				{
					auto offsetCount = std::min( partition_size, static_cast<std::size_t>( std::ranges::distance( range_beginIterator, range_endIterator ) ) );
					if ( mode == WorkMode::Copy || mode == WorkMode::Move )
					{
						output_subrange_t subRange_container( range_beginIterator, range_beginIterator + offsetCount );
						
						if constexpr ( is_random_access_range )
						{
							if constexpr ( is_key_value_range )
							{
								output_range.emplace_hint( output_range.end(), std::move( subRange_container ) );
								subRange_container.clear();

								while ( offsetCount != 0 )
								{
									range_beginIterator++;
									--offsetCount;
								}

								continue;
							}

							output_range.emplace( output_range.end(), std::move( subRange_container ) );

							subRange_container.clear();
							range_beginIterator += offsetCount;
						}
						else if constexpr ( is_contiguous_range )
						{
							if constexpr ( is_key_value_range )
							{
								output_range.emplace_hint( output_range.end(), std::move( subRange_container ) );
								subRange_container.clear();

								while ( offsetCount != 0 )
								{
									range_beginIterator++;
									--offsetCount;
								}

								continue;
							}

							std::ranges::copy( std::make_move_iterator( subRange_container.begin() ), std::make_move_iterator( subRange_container.end() ), output_range.end() );
						}
					}
					else
					{
						return;
					}
				}

				if ( mode == WorkMode::Move )
				{
					input_range.clear();
					Input_Range().swap( input_range );
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
			void operator()( Input_Range&& one_input_range, Output_IteratorType many_output_range, const size_t partition_size )
			{
				if ( partition_size <= 0 )
				{
					return;
				}

				auto beginIterator = std::ranges::begin( one_input_range );
				auto endIterator = std::ranges::end( one_input_range );

				while ( beginIterator != endIterator )
				{
					auto offsetCount = std::min( partition_size, static_cast<std::size_t>( std::ranges::distance( beginIterator, endIterator ) ) );
					*many_output_range++ = { beginIterator, std::ranges::next( beginIterator, offsetCount ) };
					std::ranges::advance( beginIterator, offsetCount );
				}
			}
		};

		Splitter splitter;

		//数据块结合器类
		//Data block merger class
		struct Merger
		{
			enum class WorkMode
			{
				Copy,
				Move,
			};

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

		Merger merger;
	}  // namespace ProcessingDataBlock

	#if defined( TEST_CPP2020_RANGE_MODIFIER )

	int main()
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