#pragma once

namespace CommonSecurity::Threefish::DefineConstants
{
	template<std::uint8_t>
	struct RotationBit;

	template<std::uint8_t>
	struct InvertibleIndices;

	template<>
	struct RotationBit<4> 
	{
		static constexpr std::uint8_t Table[8][2] =
		{
			{14, 16}, {52, 57}, {23, 40}, { 5, 37},
			{25, 33}, {46, 12}, {58, 22}, {32, 32}
		};
	};

	template<>
	struct RotationBit<8>
	{
		static constexpr std::uint8_t Table[8][4] =
		{
			{46, 36, 19, 37}, {33, 27, 14, 42},
			{17, 49, 36, 39}, {44,  9, 54, 56},
			{39, 30, 34, 24}, {13, 50, 10, 17},
			{25, 29, 39, 43}, { 8, 35, 56, 22}
		};
	};

	template<>
	struct RotationBit<16>
	{
		static constexpr std::uint8_t Table[8][8] =
		{
			{24, 13,  8, 47,  8, 17, 22, 37},
			{33,  4, 51, 13, 34, 41, 59, 17},
			{ 5, 20, 48, 41, 47, 28, 16, 25},
			{41,  9, 37, 31, 12, 47, 44, 30},
			{16, 34, 56, 51,  4, 53, 42, 41},
			{31, 44, 47, 46, 19, 42, 44, 25},
			{ 9, 48, 35, 52, 23, 31, 37, 20}
		};
	};

	template<>
	struct InvertibleIndices<4>
	{
		static constexpr std::uint8_t Table[4][4] =
		{
			{0, 1, 2, 3}, {0, 3, 2, 1},
			{0, 1, 2, 3}, {0, 3, 2, 1}
		};
	};

	template<>
	struct InvertibleIndices<8>
	{
		static constexpr std::uint8_t Table[4][8] =
		{
			{0, 1, 2, 3, 4, 5, 6, 7},
			{2, 1, 4, 7, 6, 5, 0, 3},
			{4, 1, 6, 3, 0, 5, 2, 7},
			{6, 1, 0, 7, 2, 5, 4, 3}
		};
	};

	template<>
	struct InvertibleIndices<16>
	{
		static constexpr std::uint8_t Table[4][16] =
		{
			{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			{0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1},
			{0, 7, 2, 5, 4, 3, 6, 1, 12, 15, 14, 13, 8, 11, 10, 9},
			{0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7}
		};
	};
}

/*
	https://en.wikipedia.org/wiki/Threefish

	Reference code:
	https://github.dev/dvolkow/threefish/blob/master/include/threefish.hpp
	https://github.dev/nitrocaster/SkeinFish/blob/master/src/SkeinFish/Threefish.cs
*/
namespace CommonSecurity::Threefish
{
	/**
	 * Only 4, 8 or 16 DWords size value may be parameters (SIZE_BLOCK)
	 */
	template <std::uint8_t SIZE_BLOCK>
	class Algorithm
	{
		
	private:
		using RotationBitType = CommonSecurity::Threefish::DefineConstants::RotationBit<SIZE_BLOCK>;
		using InvertibleIndicesType = CommonSecurity::Threefish::DefineConstants::InvertibleIndices<SIZE_BLOCK>;

		static constexpr std::uint8_t												 Word_Count = SIZE_BLOCK;
		static constexpr std::uint8_t												 Word_ExecuteRound = Word_Count < 16 ? 72 : 80;
		static constexpr std::uint64_t												 KeyScheduleConstant_240 = 0x1BD11BDAA9FC1A22;
		RotationBitType																 RotationBitObject;
		InvertibleIndicesType														 InvertibleIndicesObject;
		std::array<std::array<std::uint64_t, Word_Count>, Word_ExecuteRound / 4 + 1> Words_Subkey {};
		std::array<std::uint64_t, 3>												 Words_Tweak { 0, 0, 0 };

		inline void KeyExpansion( std::span<const std::uint64_t> Keys )
		{
			volatile void* CheckPointer = nullptr;

			std::array<std::uint64_t, Word_Count + 1> ExpandDataKeys {};
			CheckPointer = memory_set_no_optimize_function<0x00>( ExpandDataKeys.data(), ExpandDataKeys.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == ExpandDataKeys.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			ExpandDataKeys[ Word_Count ] = KeyScheduleConstant_240;

			for ( std::uint8_t Index = 0; Index < Word_Count; ++Index )
				ExpandDataKeys[ Index ] = Keys[ Index ], ExpandDataKeys[ Word_Count ] ^= Keys[ Index ];

			for ( std::uint8_t Index = 0; Index < Words_Subkey.size(); ++Index )
			{
				for ( std::uint8_t Index2 = 0; Index2 < Word_Count; ++Index2 )
					Words_Subkey[ Index ][ Index2 ] = ExpandDataKeys[ ( Index + Index2 ) % ( Word_Count + 1 ) ];

				Words_Subkey[ Index ][ Word_Count - 3 ] += Words_Tweak[ Index % 3 ];
				Words_Subkey[ Index ][ Word_Count - 2 ] += Words_Tweak[ ( Index + 1 ) % 3 ];
				Words_Subkey[ Index ][ Word_Count - 1 ] += Index;
			}

			CheckPointer = memory_set_no_optimize_function<0x00>( ExpandDataKeys.data(), ExpandDataKeys.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == ExpandDataKeys.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			
		}

		inline void MixFunction( std::uint64_t Input, std::uint64_t Input2, std::uint64_t& Output, std::uint64_t& Output2, std::uint64_t BitShiftCount )
		{
			Output = Input + Input2;
			Output2 = CommonSecurity::Binary_LeftRotateMove<std::uint64_t>( Input2, BitShiftCount ) ^ Output;
		}

		inline void UnMixFunction( std::uint64_t Input, std::uint64_t Input2, std::uint64_t& Output, std::uint64_t& Output2, std::uint64_t BitShiftCount )
		{
			Output2 = CommonSecurity::Binary_RightRotateMove<std::uint64_t>( ( Input ^ Input2 ), BitShiftCount );
			Output = Input - Output2;
		}

		inline void RoundEncryption( std::span<std::uint64_t> Words_Data, std::span<const std::uint8_t> RotationBitTable, std::span<const std::uint8_t> InvertibleIndicesTable )
		{
			for ( std::uint8_t Index = 0; Index < Word_Count; Index += 2U )
			{
				this->MixFunction
				(
					Words_Data[ InvertibleIndicesTable[ Index ] ],
					Words_Data[ InvertibleIndicesTable[ Index + 1 ] ],
					Words_Data[ InvertibleIndicesTable[ Index ] ],
					Words_Data[ InvertibleIndicesTable[ Index + 1 ] ],
					RotationBitTable[ Index / 2U ]
				);
			}
		}

		inline void RoundDecryption( std::span<std::uint64_t> Words_Data, std::span<const std::uint8_t> RotationBitTable, std::span<const std::uint8_t> InvertibleIndicesTable )
		{
			for ( std::uint8_t Index = 0; Index < Word_Count; Index += 2U )
			{
				this->UnMixFunction
				(
					Words_Data[ InvertibleIndicesTable[ Index ] ],
					Words_Data[ InvertibleIndicesTable[ Index + 1 ] ],
					Words_Data[ InvertibleIndicesTable[ Index ] ],
					Words_Data[ InvertibleIndicesTable[ Index + 1 ] ],
					RotationBitTable[ Index / 2U ]
				);
			}
		}

		inline void ProcessBlockEncryption( std::span<const std::uint64_t> InputData, std::span<std::uint64_t> OutputData )
		{
			volatile void* CheckPointer = nullptr;

			std::array<std::uint64_t, Word_Count> DataBuffer;
			std::ranges::copy( InputData.begin(), InputData.end(), DataBuffer.begin() );

			std::uint8_t ExecuteRound = 0;
			while ( ExecuteRound < Word_ExecuteRound )
			{
				for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
					DataBuffer[ ProcessIndex ] += Words_Subkey[ ExecuteRound / 4 ][ ProcessIndex ];

				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 0 ) % 8 ], InvertibleIndicesObject.Table[ 0 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 1 ) % 8 ], InvertibleIndicesObject.Table[ 1 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 2 ) % 8 ], InvertibleIndicesObject.Table[ 2 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 3 ) % 8 ], InvertibleIndicesObject.Table[ 3 ] );

				for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
					DataBuffer[ ProcessIndex ] += Words_Subkey[ ExecuteRound / 4 + 1 ][ ProcessIndex ];

				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 4 ) % 8 ], InvertibleIndicesObject.Table[ 0 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 5 ) % 8 ], InvertibleIndicesObject.Table[ 1 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 6 ) % 8 ], InvertibleIndicesObject.Table[ 2 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 7 ) % 8 ], InvertibleIndicesObject.Table[ 3 ] );

				ExecuteRound += 8U;
			}
			ExecuteRound = 0;

			for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
				OutputData[ ProcessIndex ] = DataBuffer[ ProcessIndex ] + Words_Subkey[ Word_ExecuteRound / 4 ][ ProcessIndex ];

			CheckPointer = memory_set_no_optimize_function<0x00>( DataBuffer.data(), DataBuffer.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == DataBuffer.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		inline void ProcessBlockDecryption( std::span<const std::uint64_t> InputData, std::span<std::uint64_t> OutputData )
		{
			volatile void* CheckPointer = nullptr;

			std::array<std::uint64_t, Word_Count> DataBuffer;

			for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
				DataBuffer[ ProcessIndex ] = InputData[ ProcessIndex ] - Words_Subkey[ Word_ExecuteRound / 4 ][ ProcessIndex ];

			std::uint8_t ExecuteRound = Word_ExecuteRound;
			while ( ExecuteRound > 0 )
			{
				ExecuteRound -= 8U;

				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 7 ) % 8 ], InvertibleIndicesObject.Table[ 3 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 6 ) % 8 ], InvertibleIndicesObject.Table[ 2 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 5 ) % 8 ], InvertibleIndicesObject.Table[ 1 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 4 ) % 8 ], InvertibleIndicesObject.Table[ 0 ] );

				for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
					DataBuffer[ ProcessIndex ] -= Words_Subkey[ ExecuteRound / 4 + 1 ][ ProcessIndex ];

				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 3 ) % 8 ], InvertibleIndicesObject.Table[ 3 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 2 ) % 8 ], InvertibleIndicesObject.Table[ 2 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 1 ) % 8 ], InvertibleIndicesObject.Table[ 1 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 0 ) % 8 ], InvertibleIndicesObject.Table[ 0 ] );

				for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
					DataBuffer[ ProcessIndex ] -= Words_Subkey[ ExecuteRound / 4 ][ ProcessIndex ];
			}
			ExecuteRound = 0;

			std::ranges::copy( DataBuffer.begin(), DataBuffer.end(), OutputData.begin() );

			CheckPointer = memory_set_no_optimize_function<0x00>( DataBuffer.data(), DataBuffer.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == DataBuffer.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

	public:
		void EncryptionWithECB( const std::size_t WordSize, std::span<const std::uint64_t> InputData, std::span<std::uint64_t> OutputData )
		{
			for ( std::size_t BlockIndex = 0; BlockIndex < ( WordSize / SIZE_BLOCK ); ++BlockIndex )
			{
				this->ProcessBlockEncryption( InputData.subspan( BlockIndex, SIZE_BLOCK ), OutputData.subspan( BlockIndex, SIZE_BLOCK ) );
			}
		}

		void DecryptionWithECB( const std::size_t WordSize, std::span<const std::uint64_t> InputData, std::span<std::uint64_t> OutputData )
		{
			for ( std::size_t BlockIndex = 0; BlockIndex < ( WordSize / SIZE_BLOCK ); ++BlockIndex )
			{
				this->ProcessBlockDecryption( InputData.subspan( BlockIndex, SIZE_BLOCK ), OutputData.subspan( BlockIndex, SIZE_BLOCK ) );
			}
		}

		void UpdateKey( std::span<const std::uint64_t> Keys, std::span<const std::uint64_t> TweakWords )
		{
			if ( TweakWords.size() != 3 )
				return;
			else
				std::ranges::copy( TweakWords.begin(), TweakWords.end(), Words_Tweak.begin() );
			this->KeyExpansion( Keys );
		}

		void UpdateKey( std::span<const std::uint64_t> Keys )
		{
			if ( Keys.size() != SIZE_BLOCK )
				return;
			this->KeyExpansion( Keys );
		}

		explicit Algorithm( std::span<const std::uint64_t> Keys )
		{
			constexpr std::uint64_t BitSize = std::numeric_limits<std::uint64_t>::digits;
			static_assert( ( 256U / SIZE_BLOCK ) == BitSize || ( 512U / SIZE_BLOCK ) == BitSize || ( 1024U / SIZE_BLOCK ) == BitSize, "Threefish DataWorker: SIZE_BLOCK is invalid!" );

			my_cpp2020_assert( Keys.size() == SIZE_BLOCK, "", std::source_location::current() );

			volatile void* CheckPointer = nullptr;

			for ( auto& ArrayData : Words_Subkey )
			{
				CheckPointer = memory_set_no_optimize_function<0x00>( ArrayData.data(), ArrayData.size() * sizeof( std::uint64_t ) );
				my_cpp2020_assert(CheckPointer == ArrayData.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			this->KeyExpansion( Keys );
		}

		~Algorithm()
		{
			volatile void* CheckPointer = nullptr;

			for ( auto& ArrayData : Words_Subkey )
			{
				CheckPointer = memory_set_no_optimize_function<0x00>( ArrayData.data(), ArrayData.size() * sizeof( std::uint64_t ) );
				my_cpp2020_assert(CheckPointer == ArrayData.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}

			CheckPointer = memory_set_no_optimize_function<0x00>( Words_Tweak.data(), Words_Tweak.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == Words_Tweak.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}
	};
}