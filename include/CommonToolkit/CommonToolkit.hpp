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

#include "CPP2020_Concept.hpp"

#ifndef COMMON_TOOLKIT_HPP
#define COMMON_TOOLKIT_HPP

#if __cplusplus >= 202002L

namespace CommonToolkit
{
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

	template <std::input_or_output_iterator Type>
	std::size_t IteratorOffsetDistance( Type iteratorA, Type iteratorB, std::size_t needOffsetCount )
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

#endif	// !COMMON_TOOLKIT_HPP
