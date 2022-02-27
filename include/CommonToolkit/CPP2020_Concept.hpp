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

#include "Support+Library/Support-MyType.hpp"

#if __cplusplus >= 202002L

#include <concepts>

namespace EODF_Reborn_CommonToolkit
{
	namespace CPP2020_Concepts
	{
		template < typename Other, template < typename... > class Self >
		struct is_specialization_class_of : std::false_type
		{
		};

		template < typename... Args, template < typename... > class Self >
		struct is_specialization_class_of< Self< Args... >, Self > : std::true_type
		{
		};

		template < typename Other, template < typename... > class Self >
		inline constexpr bool is_specialization_class_of_v = is_specialization_class_of< Other, Self >::value;

		template < typename Other, template < typename... > class Self >
		concept IsSpecializesClassType = is_specialization_class_of_v< Other, Self >;

		namespace IsIterable
		{
			template < typename IterableType, typename = void >
			struct implementation : std::false_type
			{
			};

			// this gets used only when we can call std::begin() and std::end() on that type
			template < typename IterableType >
			struct implementation< IterableType, std::void_t< decltype( std::begin( std::declval< IterableType >() ) ), decltype( std::end( std::declval< IterableType >() ) ) > > : std::true_type
			{
			};

			//std::cout << std::boolalpha;
			//std::cout << is_iterable_v<std::vector<double>> << '\n';
			//std::cout << is_iterable_v<std::map<int, double>> << '\n';
			//std::cout << is_iterable_v<double> << '\n';
			//struct A;
			//std::cout << is_iterable_v<A> << '\n';
			template < typename IterableType >
			inline constexpr bool is_iterable_v = implementation< IterableType >::value;

			// To allow ADL with custom begin/end
			using std::begin;
			using std::end;

			template < typename Type >
			concept IsIterable = requires
			{
				std::begin( std::declval< Type& >() ) == std::end( std::declval< Type& >() );  // begin/end and operator ==
				std::begin( std::declval< Type& >() ) != std::end( std::declval< Type& >() );  // begin/end and operator !=
				++std::declval< decltype( std::begin( std::declval< Type& >() ) )& >();		   // operator ++
				--std::declval< decltype( std::begin( std::declval< Type& >() ) )& >();
				*std::begin( std::declval< Type& >() );	 // operator*
			};
		}  // namespace IsIterable

		namespace WithRanges
		{
			template < typename IterableType >
			concept IsElementIterableLevel1Type = std::ranges::range< IterableType >;

			template < typename IterableType >
			concept IsElementIterableLevel2Type = std::ranges::input_range< IterableType > || std::ranges::output_range< IterableType, std::ranges::range_value_t< IterableType > >;

			template < typename IterableType >
			concept IsElementIterableWithRangeType = std::ranges::contiguous_range< IterableType > && requires( std::ranges::range_value_t< IterableType > container )
			{
				std::ranges::begin( container );
				std::ranges::end( container );
			};

			template < typename IterableType >
			concept IsElementIterableWithRangeType2 = std::ranges::random_access_range< IterableType > && requires( std::ranges::range_value_t< IterableType > container )
			{
				std::ranges::begin( container );
				std::ranges::end( container );
			};
		}  // namespace WithRanges

		template < typename LeftType, typename RightType >
		concept IsTwoSameType = std::same_as< LeftType, RightType >;

		template < typename Type >
		concept IsArithmeticDifferencesComparableType = std::totally_ordered< Type >;

		template < typename Type >
		concept IsEqualityComparableType = std::equality_comparable< Type >;

		template < typename Type >
		concept IsClassType = std::is_class_v< Type >;

		template < typename BaseClassType, typename DerivedClassType >
		concept IsTypeFromBaseClass = std::is_base_of_v< BaseClassType, DerivedClassType >;

		template < typename DataType >
		concept IsSimpleType = std::is_arithmetic_v< DataType > || std::is_enum_v< DataType > || std::is_class_v< DataType > || std::is_union_v< DataType > || std::is_reference_v< DataType > && !std::is_null_pointer_v< DataType > && !std::is_array_v< DataType >;

		template < typename DataType, typename ReferenceType, typename PointerType >
		concept IsCustomIteratorType = IsSimpleType< DataType > && std::is_reference_v< ReferenceType > &&( std::is_pointer_v< PointerType > || std::is_member_pointer_v< PointerType > && !std::is_null_pointer_v< PointerType > );

		template<class KeyValueMapType>
		concept IsKeyValueMapType = std::same_as<typename KeyValueMapType::value_type, std::pair<const typename KeyValueMapType::key_type, typename KeyValueMapType::mapped_type>>;

	}  // namespace CPP2020_Concepts
}  // namespace EODF_Reborn_CommonToolkit

#endif
