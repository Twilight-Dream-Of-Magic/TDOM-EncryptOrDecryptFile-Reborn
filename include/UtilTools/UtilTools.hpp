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

#include "Base64Coder.hpp"
#include "DataFormating.hpp"
#include "CompressDataProcessing.hpp"

//通用实用工具
//General and Utility Tools
namespace UtilTools
{
	template <typename ArrayType> requires std::is_array_v<ArrayType>
	static size_t getArraySize(ArrayType& _array_pointer_value)
	{
		size_t index = 0;
		while (_array_pointer_value[index] != '\0')
		{
			index++;
		}
		return index;
	}

	template <typename ArrayType, size_t Array_Size> requires std::is_array_v<ArrayType>
	constexpr size_t getArraySizeNew(const ArrayType(&)[Array_Size])
	{
		return Array_Size;
	}

	template <typename RangesType> requires std::ranges::sized_range<RangesType>
	static size_t getArraySizeWithCppRanges(RangesType rangesContainer)
	{
		size_t Array_Size = std::ranges::size(rangesContainer);
	}

	template <typename ReturnType, typename ArrayType, typename ElementValueType, size_t ArraySizeType> requires std::is_array_v<ArrayType>
	static ReturnType searchArrayElement(ArrayType(&array_checking)[ArraySizeType], ElementValueType seek_value)
	{
		size_t		position = 0;
		ReturnType index_result = -1;
		bool		FindedElementFlag = false;
		auto		Array_Size = ArraySizeType;

		std::cout << "Array size is = " << Array_Size << std::endl;

		for (position = 0; position <= Array_Size; position++)
		{
			// cout << "DATA CHECKPOINT" << endl;
			// cout << "Function searchArrayElement() Current index decimal value from position : " << position << endl;
			// cout << "Function searchArrayElement() Current byte hexadecimal value from value : " << seek_value << endl;

			if (array_checking[position] == seek_value)
			{
				index_result = position;
				// cout << "ARRAY ELEMENT FOUNDED" << endl;
				// cout << "Function searchArrayElement() Current index decimal value from position : " << index_result << endl; cout << "Function
				// searchArrayElement() Current index decimal value from position : " << position << endl; cout << "Function searchArrayElement() Now byte hexadecimal value from value : " << seek_value << endl;
				FindedElementFlag = true;
				// break;
				return index_result;
			}

			if (FindedElementFlag == false)
			{
				std::cout << "ARRAY ELEMENT NOT FOUNDED" << std::endl;
				std::cout << "Function searchArrayElement() Current index decimal value from position : " << index_result << std::endl;
				std::cout << "Function searchArrayElement() Current index decimal value from position : " << position << std::endl;
				std::cout << "Function searchArrayElement() Con not search and finded to byte hexadecimal value " << seek_value << " from array." << std::endl;
				index_result = -1;
				return index_result;
			}
		}
	}

	//内存数据流的类型转换
	//Type conversion of in-memory data streams
	namespace DataStreamConverter
	{

	}

	//数据编码器和解码器，数据格式化器
	//Data encoders and decoders, data formatters
	namespace DataFormating
	{

	}
}
