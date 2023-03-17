#pragma once

namespace CommonSecurity::TripleDES::DefineConstants
{
	template<bool Experimental>
	struct SubstitutionBox;

	//For the generation of FeistelBox
	//用于生成Feistel盒子
	inline constexpr std::uint64_t
	PermuteBlock(std::uint64_t data, std::array<std::uint8_t, 32> permuteation_table)
	{
		constexpr std::uint64_t bit_mask = 1;

		std::uint64_t permuted_data = 0;

		for(std::size_t index = 0; index < permuteation_table.size(); index++)
		{
			std::uint64_t bit = (data >> permuteation_table[index]) & bit_mask;
			permuted_data |= (bit << static_cast<std::uint32_t>( (permuteation_table.size() - 1) - index) );
		}

		return permuted_data;
	}

	//For the generation of subkeys, you need to use the Key Parity Choice table
	//对于子密钥的生成，你需要使用密钥奇偶性选择表
	inline constexpr std::uint64_t
	PermuteBlock(std::uint64_t data, std::array<std::uint8_t, 48> permuteation_table)
	{
		constexpr std::uint64_t bit_mask = 1;

		std::uint64_t permuted_data = 0;

		for(std::size_t index = 0; index < permuteation_table.size(); index++)
		{
			std::uint64_t bit = (data >> permuteation_table[index]) & bit_mask;
			permuted_data |= (bit << static_cast<std::uint32_t>( (permuteation_table.size() - 1) - index) );
		}

		return permuted_data;
	}

	//For the generation of subkeys, you need to use the selection table (representing the permutation function and the compression function) uses
	//对于子密钥的生成，你需要使用（代表排列组合函数和压缩函数）用途的选择表
	inline constexpr std::uint64_t
	PermuteBlock(std::uint64_t data, std::array<std::uint8_t, 56> permuteation_table)
	{
		constexpr std::uint64_t bit_mask = 1;

		std::uint64_t permuted_data = 0;

		for(std::size_t index = 0; index < permuteation_table.size(); index++)
		{
			std::uint64_t bit = (data >> permuteation_table[index]) & bit_mask;
			permuted_data |= (bit << static_cast<std::uint32_t>( (permuteation_table.size() - 1) - index) );
		}

		return permuted_data;
	}

	inline constexpr std::array<std::array<std::uint32_t, 64>, 8>
	GenerateFeistelBox();

	template<>
	struct SubstitutionBox<true>
	{
		static constexpr std::array<std::array<char, 64>, 8> PlaneData
		{{
			{{
				14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
				0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
				4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
				15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
			}},
			{{
				15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
				3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
				0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
				13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
			}},
			{{
				10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
				13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
				13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
				1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
			}},
			{{
				7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
				13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
				10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
				3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
			}},
			{{
				2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
				14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
				4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
				11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
			}},
			{{
				12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
				10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
				9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
				4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
			}},
			{{
				4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
				13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
				1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
				6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
			}},
			{{
				13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
				1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
				7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
				2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
			}}
		}};
	};

	template<>
	struct SubstitutionBox<false>
	{
		//Byte Data Substitution Box
		//字节数据代换盒
		//Here it means that each S-box is a 4x16 permutation table, 6 bits -> 4 bits, 8 S-boxes
		//在这里表示每个S盒是4x16的置换表，6位 -> 4位，8个S盒
		static constexpr std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> CubeData
		{{
			{{
				/* Box 0 */
				{{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 }},
				{{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 }},
				{{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 }},
				{{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }}
			}},

			{{
				/* Box 1 */
				{{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 }},
				{{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 }},
				{{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 }},
				{{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }}
			}},

			{{
				/* Box 2 */
				{{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 }},
				{{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 }},
				{{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 }},
				{{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }}
			}},

			{{
				/* Box 3 */
				{{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 }},
				{{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 }},
				{{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 }},
				{{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }}
			}},

			{{
				/* Box 4 */
				{{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 }},
				{{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 }},
				{{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 }},
				{{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }}
			}},
		
			{{
				/* Box 5 */
				{{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 }},
				{{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 }},
				{{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 }},
				{{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }}
			}},

			{{
				/* Box 6 */
				{{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 }},
				{{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 }},
				{{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 }},
				{{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }}
			}},

			{{
				/* Box 7 */
				{{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 }},
				{{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 }},
				{{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 }},
				{{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }}
			}}
		}};
	};

	inline constexpr std::array<std::array<std::uint32_t, 64>, 8>
	GenerateFeistelBox()
	{
		std::array<std::array<std::uint32_t, 64>, 8> FeistelBox{};

		constexpr std::array<std::uint8_t, 32> permutation_function_box_data
		{
			16, 25, 12, 11, 3, 20, 4, 15,
			31, 17, 9, 6, 27, 14, 1, 22,
			30, 24, 8, 18, 0, 5, 29, 23,
			13, 19, 2, 26, 10, 21, 28, 7,
		};

		for(std::uint32_t box_index = 0; box_index < SubstitutionBox<false>::CubeData.size(); box_index++)
		{
			for(std::uint32_t group_index = 0; group_index < SubstitutionBox<false>::CubeData[0].size(); group_index++)
			{
				for(std::uint32_t index = 0; index < SubstitutionBox<false>::CubeData[0][0].size(); index++)
				{
					std::uint64_t feistel_value = static_cast<std::uint64_t>(SubstitutionBox<false>::CubeData[box_index][group_index][index]) << (4U * (7U - box_index));
					feistel_value = PermuteBlock(feistel_value, permutation_function_box_data);

					// Row is determined by the 1st and 6th bit.
					// Column is the middle four bits.
					// 行是由第1比特位和第6比特位决定的。
					// 列是中间的4个比特位。
					std::uint8_t row = static_cast<std::uint8_t>( ( (group_index & 2U) << 4U ) | group_index & 1U );
					std::uint8_t column = static_cast<std::uint8_t>(index << 1U);
					std::uint32_t table_index = row | column;

					// The rotation was performed in the feistel rounds, being factored out and now mixed into the feistel-box.
					// 旋转是在feistel轮中进行的，被因子化了，现在混在feistel-box中。
					feistel_value = (feistel_value << 1U) | (feistel_value >> 31U);

					FeistelBox[box_index][table_index] = static_cast<std::uint32_t>(feistel_value);
				}
			}
		}

		return FeistelBox;
	}

	// Contains the SubstitutionBox and PermutationFunctionBox, then use PermutationBlock function to generate the XOR Table
	// 包含SubstitutionBox和PermutationFunctionBox，然后使用PermutationBlock函数来生成XOR表
	// FeistelBox[box_index][16 * group_index + index]
	// for SubstitutionBox<true>::CubeData[box_index][group_index][index] << 4 * (7-box_index)
	inline constexpr std::array<std::array<std::uint32_t, 64>, 8> FeistelBox = GenerateFeistelBox();
}

namespace CommonSecurity::TripleDES::ProcedureFunctions
{
	template<bool Experimental>
	class DataWorker;

	template<>
	class DataWorker<true>
	{

	private:

		//First Step (Used to perform an initial permutation)
		//第一个步骤
		//Forward Permutation Table
		static constexpr std::array<std::uint8_t, 64> InitialPermutationTable
		{
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17,  9, 1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7
		};

		//Last Step (Used to perform a final permutation) This is the inverse of InitialPermutationTable
		//最后一步
		//Backward Permutation Table
		static constexpr std::array<std::uint8_t, 64> FinalPermutationTable
		{
			40,  8, 48, 16, 56, 24, 64, 32,
			39,  7, 47, 15, 55, 23, 63, 31,
			38,  6, 46, 14, 54, 22, 62, 30,
			37,  5, 45, 13, 53, 21, 61, 29,
			36,  4, 44, 12, 52, 20, 60, 28,
			35,  3, 43, 11, 51, 19, 59, 27,
			34,  2, 42, 10, 50, 18, 58, 26,
			33,  1, 41,  9, 49, 17, 57, 25
		};

		//Transform:(Results like data compression), Used in the key schedule to select 56 bits from a 64-bit input
		//变换:（结果类似于数据压缩），在密钥计划中用于从64位输入中选择56位
		static constexpr std::array<std::uint8_t, 56> KeyParityChoiceTable
		{
			57, 49, 41, 33, 25, 17, 9,  1,
			58, 50, 42, 34, 26, 18, 10, 2,
			59, 51, 43, 35, 27, 19, 11, 3,
			60, 52, 44, 36, 63, 55, 47, 39, 
			31, 23, 15, 7, 62, 54, 46, 38,
			30, 22, 14, 6, 61, 53, 45, 37,
			29, 21, 13, 5, 28, 20, 12, 4
		};

		//Transform:(Results like data compression), Used in the key schedule to produce each subkey by selecting 48 bits from the 56-bit input
		//变换：（结果类似于数据压缩），在密钥计划中使用，通过从56位输入中选择48位来产生每个子密钥
		static constexpr std::array<std::uint8_t, 48> KeyPermutationCompressionChoiceTable
		{
			14, 17, 11, 24, 1,  5,  3,  28,
			15, 6,  21, 10, 23, 19, 12, 4, 
			26, 8,  16, 7,  27, 20, 13, 2,
			41, 52, 31, 37, 47, 55, 30, 40,
			51, 45, 33, 48, 44, 49, 39, 56,
			34, 53, 46, 42, 50, 36, 29, 32
		};

		//Used to expand an input block of 32 bits, producing extension an output block of 48 bits.
		//32位数据扩展为48位数据
		static constexpr std::array<std::uint8_t, 48> DataExtensionPermutationTable
		{
			32, 1,  2,  3,  4,  5,  4,  5, 
			6,  7,  8,  9,  8,  9,  10, 11,
			12, 13, 12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21, 20, 21,
			22, 23, 24, 25, 24, 25, 26, 27,
			28, 29, 28, 29, 30, 31, 32, 1
		};

		//Byte Data Permutation Function Box (Yields a 32-bit output from a 32-bit input)
		//字节数据置换方法盒
		static constexpr std::array<std::uint8_t, 32> PermutationFunctionBox
		{
			16, 7,  20, 21,
			29, 12, 28, 17,
			1,  15, 23, 26,
			5,  18, 31, 10,
			2,  8,  24, 14,
			32, 27, 3,  9,
			19, 13, 30, 6,
			22, 11, 4,  25
		};
		
		static constexpr std::uint32_t LOW_BIT32_ONE_MASK = 0x00000001;
		static constexpr std::uint64_t LOW_BIT64_ONE_MASK = 0x0000000000000001;
		static constexpr std::uint64_t LOW_BIT64_MASK  = 0x00000000FFFFFFFF;

		//缓存的主密钥 (64位)
		//Cached original master key (64-bit)
		std::uint64_t OriginalKey;
		std::uint64_t RecordOriginalKey;

		//缓存的16轮子密钥（48位）
		//Cached 16 rounds of subkeys (48 bit)
		std::array<std::uint64_t, 16> SubKeyArray;

		template<typename InputType, typename OutputType>
		void PermuteDataBlocks(InputType&& Data, OutputType&& PermutedData, std::size_t DataTableSize, const std::uint8_t* PermutationTable, auto PermutationTableSize, auto BitMask)
		{
			for (decltype(PermutationTableSize) index = 0; index < PermutationTableSize; index++)
			{
				PermutedData <<= 1;
				PermutedData |= (Data >> ( DataTableSize - PermutationTable[index]) ) & BitMask;
			}
		}

		std::uint32_t RoundFeistelFunction(const std::uint32_t CurrentRoundDataBlock, std::uint64_t CurrentRoundKey)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;
			
			/* 48 Bits */
			std::uint64_t SubstitutionBoxInput = 0;
			
			/* 32 Bits */
			std::uint32_t SubstitutionBoxOutput = 0;

			//Extend the data block and then re-permute the operation
			//对数据块进行扩展，然后重新置换操作
			this->PermuteDataBlocks(CurrentRoundDataBlock, SubstitutionBoxInput, 32, DataExtensionPermutationTable.data(), DataExtensionPermutationTable.size(), LOW_BIT32_ONE_MASK);

			//Use the key's data (48 Bits) for exclusive-or operation with the original data (48 Bits)
			//使用密钥的数据与原始数据进行异或操作
			SubstitutionBoxInput ^= CurrentRoundKey;

			//The 48-bit extended replacement key, divided into eight groups of six bits each
			//48位扩展置换后的密钥，分成8组，每组6位
			for(std::size_t Counter = 0; Counter < 8; ++Counter)
			{
				// 00 00 RCCC CR00 00 00 00 00 00 s_input
				// 00 00 1000 0100 00 00 00 00 00 row mask
				// 00 00 0111 1000 00 00 00 00 00 column mask

				char row = 0, column = 0;

				row = static_cast<char>( (SubstitutionBoxInput & (0x0000840000000000 >> (6 * Counter))) >> (42 - 6 * Counter) );
				row = (row >> 4) | row & 0x01;

				column = static_cast<char>( (SubstitutionBoxInput & (0x0000780000000000 >> (6 * Counter))) >> (43 - 6 * Counter) );

				SubstitutionBoxOutput <<= 4;
				SubstitutionBoxOutput |= static_cast<std::uint32_t>( SubstitutionBox<true>::PlaneData[Counter][16 * row + column] & 0x0f );
			}

			//The value of PermutationFunctionBox is accessed through the index inside the loop, and then given to Transformed_S_Box
			//The index is 32 subtracted from the value of PermutationFunctionBox already accessed, and the data can be transformed
			//通过循环内部的索引访问P_Box的值，然后给Transformed_S_Box
			//索引是32减去已经访问P_Box的值，就可以对数据进行变换

			std::uint32_t ProcessedCurrentRoundData = 0;
			this->PermuteDataBlocks(SubstitutionBoxOutput, ProcessedCurrentRoundData, 32, PermutationFunctionBox.data(), PermutationFunctionBox.size(), LOW_BIT32_ONE_MASK);

			return ProcessedCurrentRoundData;
		}

		void GenerateSubKeys()
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			//Generate the number of bits to be circular left-shift or circular right-shift for each (16) key rounds
			//Size of left rotation or right rotation per round in each half of the key schedule
			//生成每一轮(16个)密钥要循环左移或循环右移的比特数
			//在密钥计划的每一半中，每轮左旋或右旋的大小

			constexpr std::array<std::uint8_t, 16> BitRotateLeftWithRound
			{
				1, 1, 2, 2, 2, 2, 2, 2,
				1, 2, 2, 2, 2, 2, 2, 1
			};

			constexpr std::array<std::uint8_t, 16> BitRotateRightWithRound
			{
				1, 2, 2, 2, 2, 2, 2, 1,
				2, 2, 2, 2, 2, 2, 1, 1
			};
			
			/* 56 Bits */
			std::uint64_t BinaryKeyNotParityMarker = 0;
			
			/* 48 Bits */
			std::uint64_t GenerateCompressedBinaryKey = 0;

			//通过访问置换选择表1，去掉奇偶标记位，将64位密钥变成56位
			//Select Table 1 by accessing the permutation, removing the parity marker bits and turning the 64-bit key into a 56-bit
			this->PermuteDataBlocks(OriginalKey, BinaryKeyNotParityMarker, 64, KeyParityChoiceTable.data(), KeyParityChoiceTable.size(), LOW_BIT64_ONE_MASK);

			//Split the 56-bit key into the first 28 bits and the last 28 bits
			//将56位密钥分解成为前28位和后28位
			std::uint32_t BinaryKeyHighDigitPart = static_cast<std::uint32_t>( (BinaryKeyNotParityMarker >> 28) & 0x000000000FFFFFFF );
			std::uint32_t BinaryKeyLowDigitPart = static_cast<std::uint32_t>(BinaryKeyNotParityMarker & 0x000000000FFFFFFF);

			/* Calculate the key schedule for 16 rounds */
			/* 计算16个轮回的密钥日程表 */
			for (std::uint32_t RoundNumber = 0; RoundNumber < 16; RoundNumber++)
			{
				/*
					//Circular left shifting
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart << 1) | 0x00000001 & (BinaryKeyHighDigitPart >> 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart << 1) | 0x00000001 & (BinaryKeyLowDigitPart >> 27);

					//Circular right shifting
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart >> 1) | 0x00000001 & (BinaryKeyHighDigitPart << 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart >> 1) | 0x00000001 & (BinaryKeyLowDigitPart << 27);
				*/

				//Perform circular left-shift and circular right-shift for the front and back parts of the 56-bit key (The original version for the key operation are circular left shift, maybe for the key operation are circular right shift?)
				//对56位密钥的前后部分，进行循环左移和循环右移（原版对于密钥的操作都是循环左移，也许可以对于密钥的操作都是循环右移？）
				for(std::uint32_t RoundNumber2 = 0; RoundNumber2 < BitRotateLeftWithRound[RoundNumber]; RoundNumber2++)
				{
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart << 1) | 0x00000001 & (BinaryKeyHighDigitPart >> 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart >> 1) | 0x00000001 & (BinaryKeyLowDigitPart << 27);
				}

				//Concatenation into a 56-bit key
				//组合成56比特位密钥
				BinaryKeyNotParityMarker = ( static_cast<std::uint64_t>(BinaryKeyHighDigitPart) << 28 ) | static_cast<std::uint64_t>(BinaryKeyLowDigitPart);

				this->SubKeyArray.operator[](RoundNumber) = 0;

				//Turn a 56-bit key into a 48-bit key by accessing permutation selection table 2
				//通过访问置换选择表2，将56位密钥变成48位
				this->PermuteDataBlocks(BinaryKeyNotParityMarker, GenerateCompressedBinaryKey, 56, KeyPermutationCompressionChoiceTable.data(), KeyPermutationCompressionChoiceTable.size(), LOW_BIT64_ONE_MASK);

				this->SubKeyArray.operator[](RoundNumber) = GenerateCompressedBinaryKey;
			}
		}

		std::uint64_t Encryption(const std::uint64_t PlainBits)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::uint64_t CurrentBits;

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			this->PermuteDataBlocks(PlainBits, CurrentBits, 64, InitialPermutationTable.data(), InitialPermutationTable.size(), LOW_BIT64_ONE_MASK);

			//Step 2: PlainBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			std::uint32_t BinaryData_LeftBits = static_cast<std::uint32_t>( CurrentBits >> 32 ) & LOW_BIT64_MASK;
			std::uint32_t BinaryData_RightBits = CurrentBits & LOW_BIT64_MASK;

			//Step 3: Total 16 rounds of iterations (Sub-key forward sequential application)
			//共16轮迭代（子密钥正向顺序应用）
			
			for (auto& SubKey : this->SubKeyArray)
			{
				std::uint32_t TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = static_cast<std::uint64_t>(BinaryData_RightBits) << 32 | static_cast<std::uint64_t>(BinaryData_LeftBits);

			std::uint64_t CipherBits;

			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			this->PermuteDataBlocks(CurrentBits, CipherBits, 64, FinalPermutationTable.data(), FinalPermutationTable.size(), LOW_BIT64_ONE_MASK);

			return CipherBits;
		}

		std::uint64_t Decryption(const std::uint64_t CipherBits)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::uint64_t CurrentBits;

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			this->PermuteDataBlocks(CipherBits, CurrentBits, 64, InitialPermutationTable.data(), InitialPermutationTable.size(), LOW_BIT64_ONE_MASK);

			//Step 2: CipherBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			std::uint32_t BinaryData_LeftBits = static_cast<std::uint32_t>( CurrentBits >> 32 ) & LOW_BIT64_MASK;
			std::uint32_t BinaryData_RightBits = CurrentBits & LOW_BIT64_MASK;

			//Step 3: Total 16 rounds of iterations (Sub-key backward sequential application)
			//共16轮迭代（子密钥反向顺序应用）
			for (auto& SubKey : std::ranges::subrange(this->SubKeyArray.rbegin(), this->SubKeyArray.rend()))
			{
				std::uint32_t TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = static_cast<std::uint64_t>(BinaryData_RightBits) << 32 | static_cast<std::uint64_t>(BinaryData_LeftBits);

			std::uint64_t PlainBits;

			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			this->PermuteDataBlocks(CurrentBits, PlainBits, 64, FinalPermutationTable.data(), FinalPermutationTable.size(), LOW_BIT64_ONE_MASK);

			return PlainBits;
		}

	public:

		void UpadateMainKeyOnly(std::uint64_t& Key)
		{
			if(Key != this->RecordOriginalKey)
			{
				this->OriginalKey = Key;
				this->RecordOriginalKey = Key;
			}
		}

		void UpadateSubKeyOnly()
		{
			this->GenerateSubKeys();
		}

		//The update sub-round key by the main-round key
		//通过主轮密钥更新子轮密钥 
		void UpadateMainKeyAndSubKey(std::uint64_t& Key)
		{
			this->UpadateMainKeyOnly(Key);
			this->UpadateSubKeyOnly();
		}

		std::vector<std::uint8_t> DES_Executor
		(
			Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
			const std::vector<std::uint8_t>& dataBlock,
			bool updateSubKey
		)
		{
			std::size_t dataBlockByteSize = dataBlock.size();

			/*
				Data buffer
			*/

			std::uint64_t Bitset64Object_Plain;
			std::uint64_t Bitset64Object_Cipher;

			if(updateSubKey)
			{
				this->UpadateSubKeyOnly();
			}

			my_cpp2020_assert(dataBlockByteSize != 0 && dataBlockByteSize % 8 == 0, "The size of the input data must be a multiple of eight to ensure that the output data is properly sized! ", std::source_location::current());

			CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange memoryDataFormatExchanger;

			if(dataBlockByteSize == std::numeric_limits<std::uint8_t>::digits)
			{
				//Byte array data container size is 64 bits
				if(executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte(dataBlock);
					Bitset64Object_Cipher = this->Encryption(Bitset64Object_Plain);
					auto spanData = memoryDataFormatExchanger.Unpacker_8Byte(Bitset64Object_Cipher);
					return std::vector<std::uint8_t>(spanData.begin(), spanData.end());
				}
				else if (executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					Bitset64Object_Cipher = memoryDataFormatExchanger.Packer_8Byte(dataBlock);
					Bitset64Object_Plain = this->Decryption(Bitset64Object_Cipher);
					auto spanData = memoryDataFormatExchanger.Unpacker_8Byte(Bitset64Object_Plain);
					return std::vector<std::uint8_t>(spanData.begin(), spanData.end());
				}
				else
				{
					std::cout << "Wrong DES DataWorker worker is selected" << std::endl;
					abort();
				}
			}
			else
			{
				//Byte array data container size is not 64 bits

				std::vector<std::uint8_t> processedDataBlock(dataBlock.size(), 0x00);

				my_cpp2020_assert(dataBlock.size() % sizeof(std::uint64_t) == 0, "This data vector size a in't right !", std::source_location::current());

				switch (executeMode)
				{
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
					{
						//For each 8-byte size of data to be processed
						for(std::size_t DataIndex = 0; DataIndex != dataBlock.size(); DataIndex += sizeof(std::uint64_t))
						{
							std::span<const std::uint8_t> byteSpanData0 ( dataBlock.begin() + DataIndex, dataBlock.begin() + DataIndex + sizeof(std::uint64_t) );
							Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte( byteSpanData0 );
							Bitset64Object_Cipher = this->Encryption( Bitset64Object_Plain );
							auto byteSpanData = memoryDataFormatExchanger.Unpacker_8Byte( Bitset64Object_Cipher );
							
							std::ranges::move(byteSpanData.begin(), byteSpanData.end(), processedDataBlock.begin() + DataIndex);
						}

						break;
					}
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
					{
						//For each 8-byte size of data to be processed
						for(std::size_t DataIndex = 0; DataIndex != dataBlock.size(); DataIndex += sizeof(std::uint64_t))
						{
							std::span<const std::uint8_t> byteSpanData0( dataBlock.begin() + DataIndex, dataBlock.begin() + DataIndex + sizeof(std::uint64_t) );
							Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte( byteSpanData0 );
							Bitset64Object_Cipher = this->Decryption( Bitset64Object_Plain );
							auto byteSpanData = memoryDataFormatExchanger.Unpacker_8Byte( Bitset64Object_Cipher );
							
							std::ranges::move(byteSpanData.begin(), byteSpanData.end(), processedDataBlock.begin() + DataIndex);
						}

						break;
					}
					default:
					{
						std::cout << "Wrong DES DataWorker worker is selected" << std::endl;
						abort();
					}
				}

				return processedDataBlock;
			}
		}
	};

	template<>
	class DataWorker<false>
	{

	private:

		#define DES_ALGORITHM_ROL32(word, n)   (((word) << (n)) | ((word) >> (32U - (n))))
		#define DES_ALGORITHM_ROR32(word, n)   (((word) >> (n)) | ((word) << (32U - (n))))
		#define DES_ALGORITHM_ROL28(word, n) ((((word) << (n)) | ((word) >> (28U - (n)))) & 0x0FFFFFFF)
		#define DES_ALGORITHM_ROR28(word, n) ((((word) >> (n)) | ((word) << (28U - (n)))) & 0x0FFFFFFF)

		std::array<std::uint32_t, 32> Subkeys
		{ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };

		//Permutation of bit fields between words (Eric Young's technique)
		//字与字之间的位域互换（Eric Young的技术）
		void CipherDataSwapAndMove
		(
			std::uint32_t& left_data,
			std::uint32_t& right_data,
			const std::uint32_t shift_count,
			const std::uint32_t permutation_constant
		)
		{
			std::uint32_t temporary_value = ( (left_data >> shift_count) ^ right_data ) & permutation_constant;
			right_data ^= temporary_value;
			left_data ^= temporary_value << shift_count;
			temporary_value = 0U;
		}

		//Permuted choice 1
		void KeyParityChoice(std::uint32_t& left_key, std::uint32_t& right_key)
		{
			std::uint32_t temporary_value = 0U;
			this->CipherDataSwapAndMove(left_key, right_key, 4, 0x0F0F0F0F);
			this->CipherDataSwapAndMove(left_key, right_key, 16, 0x0000FFFF);
			this->CipherDataSwapAndMove(right_key, left_key, 2, 0x33333333);
			this->CipherDataSwapAndMove(right_key, left_key, 8, 0x00FF00FF);
			this->CipherDataSwapAndMove(left_key, right_key, 1, 0x55555555);
			this->CipherDataSwapAndMove(right_key, left_key, 8, 0x00FF00FF);
			this->CipherDataSwapAndMove(left_key, right_key, 16, 0x0000FFFF);
			temporary_value = (left_key << 4) & 0x0FFFFFF0;
			temporary_value |= (right_key >> 24) & 0x0000000F;
			left_key = (right_key << 20) & 0x0FF00000;
			left_key |= (right_key << 4) & 0x000FF000;
			left_key |= (right_key >> 12) & 0x00000FF0;
			left_key |= (right_key >> 28) & 0x0000000F;
			right_key = temporary_value;
		}
		
		//Permuted choice 2 (first half)
		std::uint32_t KeyPermutationCompressionChoiceLeft(std::uint32_t left_key, std::uint32_t right_key)
		{
			return ( ( ( left_key << 4 ) & 0x24000000 )
				| ( ( left_key << 28 ) & 0x10000000 )
				| ( ( left_key << 14 ) & 0x08000000 )
				| ( ( left_key << 18 ) & 0x02080000 )
				| ( ( left_key << 6 ) & 0x01000000 )
				| ( ( left_key << 9 ) & 0x00200000 )
				| ( ( left_key >> 1 ) & 0x00100000 )
				| ( ( left_key << 10 ) & 0x00040000 )
				| ( ( left_key << 2 ) & 0x00020000 )
				| ( ( left_key >> 10 ) & 0x00010000 )
				| ( ( right_key >> 13 ) & 0x00002000 )
				| ( ( right_key >> 4 ) & 0x00001000 )
				| ( ( right_key << 6 ) & 0x00000800 )
				| ( ( right_key >> 1 ) & 0x00000400 )
				| ( ( right_key >> 14 ) & 0x00000200 )
				| ( ( right_key >> 0 ) & 0x00000100 )
				| ( ( right_key >> 5 ) & 0x00000020 )
				| ( ( right_key >> 10 ) & 0x00000010 )
				| ( ( right_key >> 3 ) & 0x00000008 )
				| ( ( right_key >> 18 ) & 0x00000004 )
				| ( ( right_key >> 26 ) & 0x00000002 )
				| ( ( right_key >> 24 ) & 0x00000001 ) );
		}

		//Permuted choice 2 (second half)
		std::uint32_t KeyPermutationCompressionChoiceRight(std::uint32_t left_key, std::uint32_t right_key)
		{
			return ( ( ( left_key << 15 ) & 0x20000000 )
				| ( ( left_key << 17 ) & 0x10000000 )
				| ( ( left_key << 10 ) & 0x08000000 )
				| ( ( left_key << 22 ) & 0x04000000 )
				| ( ( left_key >> 2 ) & 0x02000000 )
				| ( ( left_key << 1 ) & 0x01000000 )
				| ( ( left_key << 16 ) & 0x00200000 )
				| ( ( left_key << 11 ) & 0x00100000 )
				| ( ( left_key << 3 ) & 0x00080000 )
				| ( ( left_key >> 6 ) & 0x00040000 )
				| ( ( left_key << 15 ) & 0x00020000 )
				| ( ( left_key >> 4 ) & 0x00010000 )
				| ( ( right_key >> 2 ) & 0x00002000 )
				| ( ( right_key << 8 ) & 0x00001000 )
				| ( ( right_key >> 14 ) & 0x00000808 )
				| ( ( right_key >> 9 ) & 0x00000400 )
				| ( ( right_key >> 0 ) & 0x00000200 )
				| ( ( right_key << 7 ) & 0x00000100 )
				| ( ( right_key >> 7 ) & 0x00000020 )
				| ( ( right_key >> 3 ) & 0x00000011 )
				| ( ( right_key << 2 ) & 0x00000004 )
				| ( ( right_key >> 21 ) & 0x00000002 ) );
		}

		// This is equivalent to the permutation defined by InitialPermutationTable
		void PermuteInitialBlock(std::uint32_t& left_data, std::uint32_t& right_data)
		{
			this->CipherDataSwapAndMove(left_data, right_data, 4U, 0x0f0f0f0fU);
			this->CipherDataSwapAndMove(left_data, right_data, 16U, 0x0000ffffU);
			this->CipherDataSwapAndMove(right_data, left_data, 2U, 0x33333333U);
			this->CipherDataSwapAndMove(right_data, left_data, 8U, 0x00ff00ffU);
			this->CipherDataSwapAndMove(left_data, right_data, 1U, 0x55555555U);
			left_data = DES_ALGORITHM_ROL32(left_data, 1U);
			right_data = DES_ALGORITHM_ROL32(right_data, 1U);
		}

		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ProcessMode>
		/*
			In cryptography, a Feistel cipher (also known as Luby–Rackoff block cipher) is a symmetric structure used in the construction of block ciphers,
			named after the German-born physicist and cryptographer Horst Feistel,
			who did pioneering research while working for IBM; it is also commonly known as a Feistel network.

			A large proportion of block ciphers use the scheme, including the US Data Encryption Standard,the Soviet/Russian GOST and the more recent Blowfish and Twofish ciphers.
				
			In a Feistel cipher, encryption and decryption are very similar operations,
			and both consist of iteratively running a function called a "round function" a fixed number of times.
			https://en.wikipedia.org/wiki/Feistel_cipher

			K[0],K[1],K[2]...,K[n] represent the subkeys, which are used as the input for each round.

			The original data is divided into equal parts on the left and right side, (L[0],R[0])

			The following operation is performed in each round.

			L[i+1] = R[i] 

			R[i+1] = L[i] ⊕ F(R[i] ,K[i])

			The final result of encryption is (R[i+1],L[i+1])

			The decryption process is the reverse order of the encryption process, where each round of decryption performs the following operation.

			R[i] = L[i+1]

			L[i] = R[i+1] ⊕ F(L[i+1],K[i])

			Finally we get our original data (R[0],L[0])

			Theoretical study of Feistel networks:
			Michael Luby and Charles Rackoff proved that if the round function is a cryptographically secure pseudorandom function using Ki as the seed
			Then after three rounds, the generated grouped passwords are already pseudo-randomly arranged.
			A "strong" pseudo-random permutation can be generated after four rounds

			Other uses:
			The Feistel construction is also used in cryptographic algorithms other than block ciphers. 
			For example, the optimal asymmetric encryption padding (OAEP) scheme uses a simple Feistel network to randomize ciphertexts in certain asymmetric-key encryption schemes.

			A generalized Feistel algorithm can be used to create strong permutations on small domains of size not a power of two (see format-preserving encryption).
			https://en.wikipedia.org/wiki/Format-preserving_encryption

			在密码学中，费斯特尔密码（也被称为卢比-拉科夫区块密码）是一种用于构建区块密码的对称结构。
			以德国出生的物理学家和密码学家Horst Feistel命名。
			他在为IBM工作时做了开创性的研究；它也通常被称为Feistel网络。

			很大一部分区块密码都使用该方案，包括美国的数据加密标准、苏联/俄罗斯的GOST以及最近的Blowfish和Twofish密码器。
				
			在费斯特尔密码中，加密和解密是非常相似的操作。
			两者都是由一个被称为 "圆形函数 "的函数迭代运行固定次数组成的。
			
			K[0],K[1],K[2]…,K[n]表示的是子密钥，分别作为各轮的输入。

			原始数据被分成了左右两边相等的部分，(L[0],R[0])

			每一轮都会进行下面的操作：

			L[i+1] = R[i] 

			R[i+1] = L[i]  ⊕ F(R[i] ,K[i])

			最后的加密出的结果就是(R[i+1],L[i+1])

			解密的过程是加密过程的逆序，每一轮解密都会进行下面的操作：

			R[i] = L[i+1]

			L[i] = R[i+1] ⊕ F(L[i+1],K[i])

			最终得到我们的原始数据(R[0],L[0])

			Feistel网络的理论研究:
			Michael Luby 和 Charles Rackoff 证明了如果轮函数是使用Ki为种子的密码安全的伪随机函数
			那么经过三轮操作之后，生成的分组密码就已经是伪随机排列了。
			经过四轮操作可以生成“强”伪随机排列。

			其他用途
			Feistel结构也被用于除区块密码之外的加密算法中。 
			例如，最佳非对称加密填充（OAEP）方案使用一个简单的Feistel网络来随机化某些非对称密钥加密方案中的密码文本。

			一个广义的Feistel算法可以用来在大小不是二的幂的小域上创建强的互换（见格式保护加密）。
		*/
		void FeistelTransform
		(
			std::uint32_t& left_data, std::uint32_t& right_data
		)
		{
			// DES Feistel Structure Transform Function
			
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;
			using CommonSecurity::TripleDES::DefineConstants::FeistelBox;

			//16 rounds of computation are needed

			if constexpr(ProcessMode == CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
			{
				std::uint32_t _left_data_ = left_data;
				std::uint32_t _right_data_ = right_data;

				std::uint32_t temporary_value = 0U;

				//For encryption, keys in the key schedule must be applied in Positive index order
				for(std::uint32_t subkey_index = 0; subkey_index < 32; subkey_index += 4U)
				{
					//Apply odd round function
					temporary_value = _right_data_ ^ this->Subkeys[subkey_index + 0U];
					_left_data_ ^= FeistelBox[1][(temporary_value >> 24U) & 0x3f];
					_left_data_ ^= FeistelBox[3][(temporary_value >> 16U) & 0x3f];
					_left_data_ ^= FeistelBox[5][(temporary_value >> 8U) & 0x3f];
					_left_data_ ^= FeistelBox[7][(temporary_value) & 0x3f];

					temporary_value = DES_ALGORITHM_ROR32(_right_data_, 4U) ^ this->Subkeys[subkey_index + 1U];
					_left_data_ ^= FeistelBox[0][(temporary_value >> 24U) & 0x3f];
					_left_data_ ^= FeistelBox[2][(temporary_value >> 16U) & 0x3f];
					_left_data_ ^= FeistelBox[4][(temporary_value >> 8U) & 0x3f];
					_left_data_ ^= FeistelBox[6][(temporary_value) & 0x3f];

					//Apply even round function
					temporary_value = _left_data_ ^ this->Subkeys[subkey_index + 2U];
					_right_data_ ^= FeistelBox[1][(temporary_value >> 24U) & 0x3f];
					_right_data_ ^= FeistelBox[3][(temporary_value >> 16U) & 0x3f];
					_right_data_ ^= FeistelBox[5][(temporary_value >> 8U) & 0x3f];
					_right_data_ ^= FeistelBox[7][(temporary_value) & 0x3f];

					temporary_value = DES_ALGORITHM_ROR32(_left_data_, 4U) ^ this->Subkeys[subkey_index + 3U];
					_right_data_ ^= FeistelBox[0][(temporary_value >> 24U) & 0x3f];
					_right_data_ ^= FeistelBox[2][(temporary_value >> 16U) & 0x3f];
					_right_data_ ^= FeistelBox[4][(temporary_value >> 8U) & 0x3f];
					_right_data_ ^= FeistelBox[6][(temporary_value) & 0x3f];
				}

				left_data = _left_data_;
				right_data = _right_data_;

				temporary_value = 0U;
				_left_data_ = 0U;
				_right_data_ = 0U;
			}
			else if constexpr(ProcessMode == CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
			{
				std::uint32_t _left_data_ = left_data;
				std::uint32_t _right_data_ = right_data;

				std::uint32_t temporary_value = 0U;

				//For decryption, keys in the key schedule must be applied in Inverse index order
				for(std::uint32_t subkey_index = 32; subkey_index > 0; subkey_index -= 4U)
				{
					//Apply even round function
					temporary_value = DES_ALGORITHM_ROR32(_left_data_, 4U) ^ this->Subkeys[subkey_index - 1U];
					_right_data_ ^= FeistelBox[6][(temporary_value) & 0x3f];
					_right_data_ ^= FeistelBox[4][(temporary_value >> 8U) & 0x3f];
					_right_data_ ^= FeistelBox[2][(temporary_value >> 16U) & 0x3f];
					_right_data_ ^= FeistelBox[0][(temporary_value >> 24U) & 0x3f];

					temporary_value = _left_data_ ^ this->Subkeys[subkey_index - 2U];
					_right_data_ ^= FeistelBox[7][(temporary_value) & 0x3f];
					_right_data_ ^= FeistelBox[5][(temporary_value >> 8U) & 0x3f];
					_right_data_ ^= FeistelBox[3][(temporary_value >> 16U) & 0x3f];
					_right_data_ ^= FeistelBox[1][(temporary_value >> 24U) & 0x3f];

					//Apply odd round function
					temporary_value = DES_ALGORITHM_ROR32(_right_data_, 4U) ^ this->Subkeys[subkey_index - 3U];
					_left_data_ ^= FeistelBox[6][(temporary_value) & 0x3f];
					_left_data_ ^= FeistelBox[4][(temporary_value >> 8U) & 0x3f];
					_left_data_ ^= FeistelBox[2][(temporary_value >> 16U) & 0x3f];
					_left_data_ ^= FeistelBox[0][(temporary_value >> 24U) & 0x3f];

					temporary_value = _right_data_ ^ this->Subkeys[subkey_index - 4U];
					_left_data_ ^= FeistelBox[7][(temporary_value) & 0x3f];
					_left_data_ ^= FeistelBox[5][(temporary_value >> 8U) & 0x3f];
					_left_data_ ^= FeistelBox[3][(temporary_value >> 16U) & 0x3f];
					_left_data_ ^= FeistelBox[1][(temporary_value >> 24U) & 0x3f];
				}

				left_data = _left_data_;
				right_data = _right_data_;

				temporary_value = 0U;
				_left_data_ = 0U;
				_right_data_ = 0U;
			}
			else
			{
				static_assert(CommonToolkit::Dependent_Always_Failed<ProcessMode>,"");
			}
		}

		// This is equivalent to the permutation defined by FinalPermutationTable
		void PermuteFinalBlock(std::uint32_t& left_data, std::uint32_t& right_data)
		{
			left_data = DES_ALGORITHM_ROR32(left_data, 1U);
			right_data = DES_ALGORITHM_ROR32(right_data, 1U);
			this->CipherDataSwapAndMove(left_data, right_data, 1U, 0x55555555U);
			this->CipherDataSwapAndMove(right_data, left_data, 8U, 0x00ff00ffU);
			this->CipherDataSwapAndMove(right_data, left_data, 2U, 0x33333333U);
			this->CipherDataSwapAndMove(left_data, right_data, 16U, 0x0000ffffU);
			this->CipherDataSwapAndMove(left_data, right_data, 4U, 0x0f0f0f0fU);
		}

	public:

		static constexpr std::uint32_t BlockByteSize = 8;

		// Generate 16 subkeys of 56 bit words from the original byte key
		// 从原始字节密钥中生成16个56位的子密钥
		void GenerateSubkeys(std::span<const std::uint8_t> bytes_key)
		{
			using CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange;
			using CommonSecurity::TripleDES::DefineConstants::PermuteBlock;

			my_cpp2020_assert(bytes_key.size() == BlockByteSize, "CommonSecurity::TripleDES::TripleDES : The size of the bytes key is not valid!", std::source_location::current());

			MemoryDataFormatExchange memory_data_format_exchanger;
			std::uint32_t left_key = memory_data_format_exchanger.Packer_4Byte(bytes_key.subspan(0, sizeof(std::uint32_t)));
			std::uint32_t right_key = memory_data_format_exchanger.Packer_4Byte(bytes_key.subspan(4, sizeof(std::uint32_t)));

			// Apply PC1 permutation table to key
			this->KeyParityChoice(left_key, right_key);

			// Generate subkeys using the key schedule
			// 用密钥计划安排生成子密钥
			for (std::uint32_t round = 0; round < 16; round++)
			{
				if(round == 0 || round == 1 || round == 8 || round == 15)
				{
					#if 1

					// 28-bit circular left shift
					left_key = DES_ALGORITHM_ROL28(left_key, 1);
					right_key = DES_ALGORITHM_ROL28(right_key, 1);

					#else

					// 28-bit circular right shift
			
					left_key = DES_ALGORITHM_ROR28(left_key, 1);
					right_key = DES_ALGORITHM_ROR28(right_key, 1);

					#endif
				}
				else
				{
					#if 1

					// 28-bit circular left shift
					left_key = DES_ALGORITHM_ROL28(left_key, 2);
					right_key = DES_ALGORITHM_ROL28(right_key, 2);

					#else

					// 28-bit circular right shift
			
					left_key = DES_ALGORITHM_ROR28(left_key, 2);
					right_key = DES_ALGORITHM_ROR28(right_key, 2);

					#endif
				}

				// Apply PC2 permutation table to subkey
				this->Subkeys[2 * round] = this->KeyPermutationCompressionChoiceLeft(left_key, right_key);
				this->Subkeys[2 * round + 1] = this->KeyPermutationCompressionChoiceRight(left_key, right_key);
			}
		}

		// Process one data chunk at a time (The size is 8 bytes)
		// 每次处理一个数据分块(大小为8个字节)
		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ProcessMode>
		void ProcessDataBlock
		(
			std::span<const std::uint8_t> source_bytes_data,
			std::span<std::uint8_t> destination_byte_data
		)
		{
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;
			using CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange;

			my_cpp2020_assert(source_bytes_data.size() == BlockByteSize, "CommonSecurity::TripleDES::DataWorker : The size of the bytes source data is not valid!", std::source_location::current());
			my_cpp2020_assert(destination_byte_data.size() == BlockByteSize, "CommonSecurity::TripleDES::DataWorker : The size of the bytes destination data is not valid!", std::source_location::current());

			MemoryDataFormatExchange memory_data_format_exchanger;

			if constexpr(ProcessMode == CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
			{
				std::uint32_t left_data_block = memory_data_format_exchanger.Packer_4Byte(source_bytes_data.subspan(0, sizeof(std::uint32_t)));
				std::uint32_t right_data_block = memory_data_format_exchanger.Packer_4Byte(source_bytes_data.subspan(4, sizeof(std::uint32_t)));

				//Initial permutation
				this->PermuteInitialBlock(left_data_block, right_data_block);

				//When calling this FeistelTransform function, use the two 32-bit word data, please do not arbitrarily swap the order of their function parameters, because which can cause a huge data change.
				//当调用这个FeistelTransform函数时，使用两个32位字的数据，请不要任意调换其函数参数的顺序，因为这样会造成巨大的数据变化。
				this->FeistelTransform<ProcessMode>(left_data_block, right_data_block);

				//Inverse of initial permutation
				this->PermuteFinalBlock(right_data_block, left_data_block);

				auto processed_bytes_span = memory_data_format_exchanger.Unpacker_4Byte(right_data_block);
				::memmove(destination_byte_data.data(), processed_bytes_span.data(), processed_bytes_span.size());
				auto processed_bytes_span2 = memory_data_format_exchanger.Unpacker_4Byte(left_data_block);
				::memmove(destination_byte_data.data() + 4, processed_bytes_span2.data(), processed_bytes_span2.size());
			}
			else if constexpr(ProcessMode == CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
			{
				std::uint32_t right_data_block = memory_data_format_exchanger.Packer_4Byte(source_bytes_data.subspan(0, sizeof(std::uint32_t)));
				std::uint32_t left_data_block = memory_data_format_exchanger.Packer_4Byte(source_bytes_data.subspan(4, sizeof(std::uint32_t)));

				//Initial permutation
				this->PermuteInitialBlock(right_data_block, left_data_block);
				
				//When calling this FeistelTransform function, use the two 32-bit word data, please do not arbitrarily swap the order of their function parameters, because which can cause a huge data change.
				//当调用这个FeistelTransform函数时，使用两个32位字的数据，请不要任意调换其函数参数的顺序，因为这样会造成巨大的数据变化。
				this->FeistelTransform<ProcessMode>(left_data_block, right_data_block);

				//Inverse of initial permutation
				this->PermuteFinalBlock(left_data_block, right_data_block);

				auto processed_bytes_span = memory_data_format_exchanger.Unpacker_4Byte(left_data_block);
				::memmove(destination_byte_data.data(), processed_bytes_span.data(), processed_bytes_span.size());
				auto processed_bytes_span2 = memory_data_format_exchanger.Unpacker_4Byte(right_data_block);
				::memmove(destination_byte_data.data() + 4, processed_bytes_span2.data(), processed_bytes_span2.size());
			}
			else
			{
				static_assert(CommonToolkit::Dependent_Always_Failed<ProcessMode>,"");
			}
		}

		DataWorker() = default;

		~DataWorker()
		{
			memory_set_no_optimize_function<0x00>(this->Subkeys.data(), this->Subkeys.size() * sizeof(std::uint32_t));
		}

		#undef DES_ALGORITHM_ROL32
		#undef DES_ALGORITHM_ROR32
		#undef DES_ALGORITHM_ROL28
		#undef DES_ALGORITHM_ROR28
	};

	template<bool Experimental>
	struct TripleDES;

	template<>
	struct TripleDES<true>
	{
		DataWorker<true> DES_Worker, DES_Worker2, DES_Worker3;
	};

	template<>
	struct TripleDES<false>
	{
		DataWorker<false> DES_Worker, DES_Worker2, DES_Worker3;

		void GenerateSubkeys(std::span<const std::uint8_t> bytes_key)
		{
			//Check key length
			if(bytes_key.size() == 8)
			{
				//This option provides backward compatibility with DES, because the
				//first and second DES operations cancel out
				DES_Worker.GenerateSubkeys( bytes_key );
				DES_Worker2.GenerateSubkeys( bytes_key );
				DES_Worker3.GenerateSubkeys( bytes_key );
			}
			else if(bytes_key.size() == 16)
			{
				//If the key length is 128 bits including parity, the first 8 bytes of the
				//encoding represent the key used for the two outer DES operations, and
				//the second 8 bytes represent the key used for the inner DES operation
				DES_Worker.GenerateSubkeys( bytes_key.subspan(0, sizeof(std::uint64_t)) );
				DES_Worker2.GenerateSubkeys( bytes_key.subspan(8, sizeof(std::uint64_t)) );
				DES_Worker3.GenerateSubkeys( bytes_key.subspan(0, sizeof(std::uint64_t)) );
			}
			else if(bytes_key.size() == 24)
			{
				//If the key length is 192 bits including parity, then 3 independent DES
				//keys are represented, in the order in which they are used for encryption
				DES_Worker.GenerateSubkeys( bytes_key.subspan(0, sizeof(std::uint64_t)) );
				DES_Worker2.GenerateSubkeys( bytes_key.subspan(8, sizeof(std::uint64_t)) );
				DES_Worker3.GenerateSubkeys( bytes_key.subspan(16, sizeof(std::uint64_t)) );
			}
			else
			{
			   my_cpp2020_assert(false, "CommonSecurity::TripleDES::TripleDES : The size of the bytes key is not valid!", std::source_location::current());
			}
		}

		void BlockEncryption
		(
			std::span<const std::uint8_t> source_bytes_data,
			std::span<std::uint8_t> destination_byte_data
		)
		{
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

			//The first pass is a DES encryption
			DES_Worker.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(source_bytes_data, destination_byte_data);
			//The second pass is a DES decryption of the first ciphertext result
			DES_Worker2.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(destination_byte_data, destination_byte_data);
			//The third pass is a DES encryption of the second pass result
			DES_Worker3.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(destination_byte_data, destination_byte_data);
		}

		void BlockDecryption
		(
			std::span<const std::uint8_t> source_bytes_data,
			std::span<std::uint8_t> destination_byte_data
		)
		{
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

			//The first pass is a DES decryption
			DES_Worker3.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(source_bytes_data, destination_byte_data);
			//The second pass is a DES encryption of the first pass result
			DES_Worker2.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(destination_byte_data, destination_byte_data);
			//The third pass is a DES decryption of the second ciphertext result
			DES_Worker.ProcessDataBlock<CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(destination_byte_data, destination_byte_data);
		}
	};
}

/*
	
	Paper: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf
	
*/
namespace CommonSecurity::TripleDES
{
	using ExperimentalWorker = CommonSecurity::TripleDES::ProcedureFunctions::TripleDES<true>;
	using OfficialWorker = CommonSecurity::TripleDES::ProcedureFunctions::TripleDES<false>;
	
	inline void TripleDES_Executor
	(
		ProcedureFunctions::TripleDES<true>& TripleDES_Object,
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
		const std::vector<std::uint8_t>& inputDataBlock,
		std::deque<std::vector<std::uint8_t>>& keyBlockChain,
		std::vector<std::uint8_t>& outputDataBlock,
		bool forceAssert = true
	)
	{
		CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange MemoryDataFormatExchanger;
		std::vector<std::uint64_t> Bit64_Keys;

		std::mt19937 pseudoRandomGenerator { static_cast<std::uint32_t>( keyBlockChain.front().operator[](0) ) };
		CommonSecurity::RND::UniformIntegerDistribution number_distribution(0, 255);

		if(inputDataBlock.empty())
		{
			throw std::length_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the input data cannot be zero!");
		}

		if(forceAssert)
		{
			my_cpp2020_assert(keyBlockChain.size() % 3 == 0, "CommonSecurity::TripleDES::TripleDES_Executor() The Triple DES algorithm requires the number of keys to be modulo 3 to work!", std::source_location::current());

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : keyBlockChain)
			{
				while(keyBlock.size() % sizeof(std::uint64_t) != 0)
				{
					std::uint8_t randomByte = static_cast<std::uint8_t>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bit64_Keys.push_back( MemoryDataFormatExchanger.Packer_8Byte(keyBlock) );
			}
		}
		else
		{
			std::deque<std::vector<std::uint8_t>> copiedKeyBlockChain = keyBlockChain;

			std::size_t KeyBlockTruncationCount = copiedKeyBlockChain.size() % 3;
			while (KeyBlockTruncationCount > 0)
			{
				copiedKeyBlockChain.back().clear();
				copiedKeyBlockChain.back().shrink_to_fit();
				copiedKeyBlockChain.pop_back();
				--KeyBlockTruncationCount;
			}

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : copiedKeyBlockChain)
			{
				while(keyBlock.size() % sizeof(std::uint64_t) != 0)
				{
					std::uint8_t randomByte = static_cast<std::uint8_t>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bit64_Keys.push_back( MemoryDataFormatExchanger.Packer_8Byte(keyBlock) );
			}
		}

		std::vector<std::uint8_t> temporaryDataBlock { inputDataBlock };
		
		std::size_t dataBlockByteSize = inputDataBlock.size();

		CommonSecurity::ChunkedDataPadders<CommonSecurity::ChunkedDataPaddingMode::PKCS7> ChunkedDataPadManager;

		using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

		switch (executeMode)
		{
			//CipherText = Encryption(Decryption(Encryption(PlainText, Key), Key2), Key3);
			case CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				ChunkedDataPadManager.Pad(temporaryDataBlock, sizeof(std::uint64_t));

				std::cout << "TripleDES Encryption Start !" << std::endl;

				for(std::size_t index = 0; index < Bit64_Keys.size(); index += 3)
				{
					//Use Encryption Main Round Key 1
					TripleDES_Object.DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index));
					temporaryDataBlock = TripleDES_Object.DES_Worker.DES_Executor(CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				
					//Use Encryption Main Round Key 2
					TripleDES_Object.DES_Worker2.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index + 1));
					temporaryDataBlock = TripleDES_Object.DES_Worker2.DES_Executor(CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);

					//Use Encryption Main Round Key 3
					TripleDES_Object.DES_Worker3.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index + 2));
					temporaryDataBlock = TripleDES_Object.DES_Worker3.DES_Executor(CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				}

				std::cout << "TripleDES Encryption End !" << std::endl;

				outputDataBlock.resize(temporaryDataBlock.size());

				std::ranges::copy(temporaryDataBlock.begin(), temporaryDataBlock.end(), outputDataBlock.begin());
				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				break;
			}
			//PlainText = Decryption(Encryption(Decryption(CipherText, Key3), Key2), Key);
			case CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				std::cout << "TripleDES Decryption Start !" << std::endl;

				for(std::size_t index = Bit64_Keys.size() - 1; index > 0;)
				{
					//Use Decryption Main Round Key 1
					TripleDES_Object.DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index));
					temporaryDataBlock = TripleDES_Object.DES_Worker.DES_Executor(CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);
				
					//Use Decryption Main Round Key 2
					TripleDES_Object.DES_Worker2.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index - 1));
					temporaryDataBlock = TripleDES_Object.DES_Worker2.DES_Executor(CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);

					//Use Decryption Main Round Key 3
					TripleDES_Object.DES_Worker3.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index - 2));
					temporaryDataBlock = TripleDES_Object.DES_Worker3.DES_Executor(CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);

					if(index - 3 > index)
					{
						break;
					}
					else
					{
						index -= 3;
					}
				}

				std::cout << "TripleDES Decryption End !" << std::endl;

				outputDataBlock.resize(temporaryDataBlock.size());

				std::ranges::copy(temporaryDataBlock.begin(), temporaryDataBlock.end(), outputDataBlock.begin());
				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				ChunkedDataPadManager.Unpad(outputDataBlock, sizeof(std::uint64_t));

				break;
			}
			default:
			{
				std::cout << "Wrong TripleDES DataWorker worker is selected" << std::endl;
				abort();
			}
		}
	}

	inline void TripleDES_Executor
	(
		ProcedureFunctions::TripleDES<false>& TripleDES_Object,
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
		const std::vector<std::uint8_t>& inputDataBlock,
		const std::deque<std::vector<std::uint8_t>>& keyBlockChain,
		std::vector<std::uint8_t>& outputDataBlock,
		bool forceAssert = true
	)
	{
		std::deque<std::vector<std::uint8_t>> copiedKeyBlockChain {keyBlockChain.begin(), keyBlockChain.end()};

		if(inputDataBlock.empty())
		{
			throw std::length_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the input data cannot be zero!");
		}

		if(forceAssert)
		{
			my_cpp2020_assert(keyBlockChain.size() % 3 == 0, "CommonSecurity::TripleDES::TripleDES_Executor() The Triple DES algorithm requires the number of keys to be modulo 3 to work!", std::source_location::current());

			CommonSecurity::RNG_Xorshiro::xorshiro256 pseudoRandomGenerator { static_cast<std::uint32_t>( keyBlockChain.front().operator[](0) ) };
			CommonSecurity::RND::UniformIntegerDistribution number_distribution(0, 255);

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : copiedKeyBlockChain)
			{
				while(keyBlock.size() < sizeof(std::uint64_t) * 3)
				{
					std::uint8_t randomByte = static_cast<std::uint8_t>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				if(keyBlock.size() > sizeof(std::uint64_t) * 3)
					keyBlock.resize(sizeof(std::uint64_t) * 3);
			}
		}
		else
		{
			std::size_t KeyBlockTruncationCount = copiedKeyBlockChain.size() % 3;
			while (KeyBlockTruncationCount > 0)
			{
				copiedKeyBlockChain.back().clear();
				copiedKeyBlockChain.back().shrink_to_fit();
				copiedKeyBlockChain.pop_back();
				--KeyBlockTruncationCount;
			}

			CommonSecurity::RNG_Xorshiro::xorshiro256 pseudoRandomGenerator { static_cast<std::uint32_t>( keyBlockChain.front().operator[](0) ) };
			CommonSecurity::RND::UniformIntegerDistribution number_distribution(0, 255);

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : copiedKeyBlockChain)
			{
				while(keyBlock.size() < sizeof(std::uint64_t) * 3)
				{
					std::uint8_t randomByte = static_cast<std::uint8_t>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				if(keyBlock.size() > sizeof(std::uint64_t) * 3)
					keyBlock.resize(sizeof(std::uint64_t) * 3);
			}
		}

		std::vector<std::uint8_t> temporaryDataBlock { inputDataBlock };

		std::size_t dataBlockByteSize = inputDataBlock.size();

		CommonSecurity::ChunkedDataPadders<CommonSecurity::ChunkedDataPaddingMode::PKCS7> ChunkedDataPadManager;

		using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

		switch (executeMode)
		{
			//CipherText = Encryption(Decryption(Encryption(PlainText, Key), Key2), Key3);
			case CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				//Padding Data

				ChunkedDataPadManager.Pad(temporaryDataBlock, sizeof(std::uint64_t));
				outputDataBlock.resize(temporaryDataBlock.size(), 0);

				my_cpp2020_assert
				(
					outputDataBlock.size() % sizeof(std::uint64_t) == 0,
					"CommonSecurity::TripleDES::TripleDES_Executor() The encryption of the triple DES algorithm requires a data number of modulo 8 to work!",
					std::source_location::current()
				);

				std::span<std::uint8_t> inputDataBlockSpan { temporaryDataBlock };
				std::span<std::uint8_t> outputDataBlockSpan { outputDataBlock };

				auto inputDataBlockSubSpan = inputDataBlockSpan.subspan(0, sizeof(std::uint64_t));
				auto outputDataBlockSubSpan = outputDataBlockSpan.subspan(0, sizeof(std::uint64_t));

				std::span<std::uint8_t> PadedBlock = inputDataBlockSpan.subspan
				(
					temporaryDataBlock.size() - sizeof(std::uint64_t),
					sizeof(std::uint64_t)
				);

				for(std::uint32_t Index = 0U; Index < sizeof(std::uint64_t) - 1; ++Index)
				{
					PadedBlock[Index] ^= copiedKeyBlockChain[0U][Index];
				}

				std::cout << "TripleDES Encryption Start !" << std::endl;

				for
				(
					std::size_t keyblock_index = 0, datablock_index = 0;
					datablock_index < temporaryDataBlock.size() - sizeof(std::uint64_t);
				)
				{
					TripleDES_Object.GenerateSubkeys(copiedKeyBlockChain.operator[](keyblock_index));
					TripleDES_Object.BlockEncryption(inputDataBlockSubSpan, outputDataBlockSubSpan);

					datablock_index += sizeof(std::uint64_t);
					
					if(datablock_index + sizeof(std::uint64_t) >= temporaryDataBlock.size())
						break;

					inputDataBlockSubSpan = inputDataBlockSpan.subspan(datablock_index, sizeof(std::uint64_t));
					outputDataBlockSubSpan = outputDataBlockSpan.subspan(datablock_index, sizeof(std::uint64_t));

					if(keyblock_index + 1 >= copiedKeyBlockChain.size())
						keyblock_index = 0U;
					else
						++keyblock_index;
				}

				std::cout << "TripleDES Encryption End !" << std::endl;

				std::span<std::uint8_t> PadedBlock2 = outputDataBlockSpan.subspan
				(
					outputDataBlock.size() - sizeof(std::uint64_t),
					sizeof(std::uint64_t)
				);

				std::ranges::copy(PadedBlock.begin(), PadedBlock.end(), PadedBlock2.begin());

				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				break;
			}
			//PlainText = Decryption(Encryption(Decryption(CipherText, Key3), Key2), Key);
			case CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				my_cpp2020_assert
				(
					temporaryDataBlock.size() % sizeof(std::uint64_t) == 0,
					"CommonSecurity::TripleDES::TripleDES_Executor() The decryption of the triple DES algorithm requires a data number of modulo 8 to work!",
					std::source_location::current()
				);

				std::cout << "TripleDES Decryption Start !" << std::endl;

				outputDataBlock.resize(temporaryDataBlock.size(), 0);

				std::span<std::uint8_t> inputDataBlockSpan { temporaryDataBlock };
				std::span<std::uint8_t> outputDataBlockSpan { outputDataBlock };

				auto inputDataBlockSubSpan = inputDataBlockSpan.subspan(0, sizeof(std::uint64_t));
				auto outputDataBlockSubSpan = outputDataBlockSpan.subspan(0, sizeof(std::uint64_t));

				std::uint32_t PadedBlockSize = temporaryDataBlock.back();

				std::span<std::uint8_t> PadedBlock = inputDataBlockSpan.subspan
				(
					temporaryDataBlock.size() - sizeof(std::uint64_t),
					sizeof(std::uint64_t)
				);

				for(std::uint32_t Index = 0U; Index < sizeof(std::uint64_t) - 1; ++Index)
				{
					PadedBlock[Index] ^= copiedKeyBlockChain[0U][Index];
				}				

				for
				(
					std::size_t keyblock_index = 0, datablock_index = 0;
					datablock_index < temporaryDataBlock.size() - sizeof(std::uint64_t);
				)
				{
					TripleDES_Object.GenerateSubkeys(copiedKeyBlockChain.operator[](keyblock_index));
					TripleDES_Object.BlockDecryption(inputDataBlockSubSpan, outputDataBlockSubSpan);

					datablock_index += sizeof(std::uint64_t);

					if(datablock_index + sizeof(std::uint64_t) >= temporaryDataBlock.size())
						break;

					inputDataBlockSubSpan = inputDataBlockSpan.subspan(datablock_index, sizeof(std::uint64_t));
					outputDataBlockSubSpan = outputDataBlockSpan.subspan(datablock_index, sizeof(std::uint64_t));

					if(keyblock_index + 1 >= copiedKeyBlockChain.size())
						keyblock_index = 0U;
					else
						++keyblock_index;
				}

				std::cout << "TripleDES Decryption End !" << std::endl;

				std::span<std::uint8_t> PadedBlock2 = outputDataBlockSpan.subspan
				(
					outputDataBlock.size() - sizeof(std::uint64_t),
					sizeof(std::uint64_t)
				);

				std::ranges::copy(PadedBlock.begin(), PadedBlock.end(), PadedBlock2.begin());

				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				ChunkedDataPadManager.Unpad(outputDataBlock, sizeof(std::uint64_t));

				break;
			}
			default:
			{
				std::cout << "Wrong TripleDES DataWorker worker is selected" << std::endl;
				abort();
			}
		}
	}
}
