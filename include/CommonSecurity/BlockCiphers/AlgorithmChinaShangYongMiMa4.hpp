#pragma once

namespace CommonSecurity::ChinaShangYongMiMa4::DefineConstants
{
	inline constexpr std::array<std::uint8_t, 256> Subtitute_ByteBox
	{
		0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
		0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
		0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
		0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
		0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
		0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
		0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
		0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
		0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
		0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
		0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
		0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
		0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
		0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
		0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
		0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
	};

	//用于支持每轮密钥生成的常量字
	//Constant words used to support each round of key generation
	inline constexpr std::array<std::uint32_t, 32> ConstentWords
	{
		0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
		0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
		0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
		0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
		0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
		0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
		0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
		0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
	};

	//用于支持密钥生成的系统功能参数字
	//System function argument words used to support key generation
	inline constexpr std::array<std::uint32_t, 4> SystemWords
	{
		0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
	};

	//Reference chinese paper: http://html.rhhz.net/ZGKXYDXXB/20180205.htm
	//Reference source code: https://github.com/Jemtaly/CryptoXX/blob/main/Cipher/sm4.hpp

	#if 0

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateMixDataTransformedWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		for(std::uint32_t Index = 0, Round = 0; Index < 256 && Round < 256; Index++, ++Round)
		{
			//Tau_NonlinearTransform Function

			std::uint32_t ByteA = Subtitute_ByteBox[Index];
			std::uint32_t ByteB = Subtitute_ByteBox[Index];
			std::uint32_t ByteC = Subtitute_ByteBox[Index];
			std::uint32_t ByteD = Subtitute_ByteBox[Index];
			
			std::uint32_t WordA = ByteA << 24;
			std::uint32_t WordB = ByteB << 16;
			std::uint32_t WordC = ByteC << 8;
			std::uint32_t WordD = ByteD;

			//T0 - LinearTransform0 Function
			WordA = WordA
				^ std::rotl(WordA, static_cast<std::uint32_t>(2))
				^ std::rotl(WordA, static_cast<std::uint32_t>(10))
				^ std::rotl(WordA, static_cast<std::uint32_t>(18))
				^ std::rotl(WordA, static_cast<std::uint32_t>(24));

			//T1 - LinearTransform0 Function
			WordB = WordB
				^ std::rotl(WordB, static_cast<std::uint32_t>(2))
				^ std::rotl(WordB, static_cast<std::uint32_t>(10))
				^ std::rotl(WordB, static_cast<std::uint32_t>(18))
				^ std::rotl(WordB, static_cast<std::uint32_t>(24));

			//T2 - LinearTransform0 Function
			WordC = WordC
				^ std::rotl(WordC, static_cast<std::uint32_t>(2))
				^ std::rotl(WordC, static_cast<std::uint32_t>(10))
				^ std::rotl(WordC, static_cast<std::uint32_t>(18))
				^ std::rotl(WordC, static_cast<std::uint32_t>(24));

			//T3 - LinearTransform0 Function
			WordD = WordD
				^ std::rotl(WordD, static_cast<std::uint32_t>(2))
				^ std::rotl(WordD, static_cast<std::uint32_t>(10))
				^ std::rotl(WordD, static_cast<std::uint32_t>(18))
				^ std::rotl(WordD, static_cast<std::uint32_t>(24));

			if(ProcessBlockTable[3][Round] != WordA)
				ProcessBlockTable[3][Round] = WordA;

			if(ProcessBlockTable[2][Round] != WordB)
				ProcessBlockTable[2][Round] = WordB;

			if(ProcessBlockTable[1][Round] != WordC)
				ProcessBlockTable[1][Round] = WordC;

			if(ProcessBlockTable[0][Round] != WordD)
				ProcessBlockTable[0][Round] = WordD;
		}

		return ProcessBlockTable;
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateMixKeyTransformedWordTable()
	{
		for(std::uint32_t Index = 0, Round = 0; Index < 256 && Round < 256; Index++, ++Round)
		{
			//Tau_NonlinearTransform Function

			std::uint32_t ByteA = Subtitute_ByteBox[Index];
			std::uint32_t ByteB = Subtitute_ByteBox[Index];
			std::uint32_t ByteC = Subtitute_ByteBox[Index];
			std::uint32_t ByteD = Subtitute_ByteBox[Index];
			
			std::uint32_t WordA = ByteA << 24;
			std::uint32_t WordB = ByteB << 16;
			std::uint32_t WordC = ByteC << 8;
			std::uint32_t WordD = ByteD;

			//T0 - LinearTransform1 Function
			WordA = WordA
				^ std::rotl(WordA, static_cast<std::uint32_t>(13))
				^ std::rotl(WordA, static_cast<std::uint32_t>(23));

			//T1 - LinearTransform1 Function
			WordB = WordB
				^ std::rotl(WordB, static_cast<std::uint32_t>(13))
				^ std::rotl(WordB, static_cast<std::uint32_t>(23));

			//T2 - LinearTransform1 Function
			WordC = WordC
				^ std::rotl(WordC, static_cast<std::uint32_t>(13))
				^ std::rotl(WordC, static_cast<std::uint32_t>(23));

			//T3 - LinearTransform1 Function
			WordD = WordD
				^ std::rotl(WordD, static_cast<std::uint32_t>(13))
				^ std::rotl(WordD, static_cast<std::uint32_t>(23));

			if(ProcessBlockTable[3][Round] != WordA)
				ProcessBlockTable[3][Round] = WordA;

			if(ProcessBlockTable[2][Round] != WordB)
				ProcessBlockTable[2][Round] = WordB;

			if(ProcessBlockTable[1][Round] != WordC)
				ProcessBlockTable[1][Round] = WordC;

			if(ProcessBlockTable[0][Round] != WordD)
				ProcessBlockTable[0][Round] = WordD;
		}
	}

	#else

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateMixDataTransformedWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		std::uint32_t Round = 0;

		constexpr std::uint32_t ByteBits = std::numeric_limits<std::uint8_t>::digits;
		constexpr std::uint32_t WordBits = std::numeric_limits<std::uint32_t>::digits;
		
		//T3
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform1 Function

			std::uint32_t Word = Byte ^ Byte << 2 ^ Byte << 10 ^ Byte << 18 ^ Byte << 24;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T2
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform1 Function

			std::uint32_t Word = Byte ^ Byte << 2 ^ Byte << 10 ^ Byte << 18 ^ Byte << 24;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T1
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform1 Function

			std::uint32_t Word = Byte ^ Byte << 2 ^ Byte << 10 ^ Byte << 18 ^ Byte << 24;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T0
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform1 Function

			std::uint32_t Word = Byte ^ Byte << 2 ^ Byte << 10 ^ Byte << 18 ^ Byte << 24;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		return ProcessBlockTable;
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateMixKeyTransformedWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		std::uint32_t Round = 0;

		constexpr std::uint32_t ByteBits = std::numeric_limits<std::uint8_t>::digits;
		constexpr std::uint32_t WordBits = std::numeric_limits<std::uint32_t>::digits;

		//T3
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform0 Function

			std::uint32_t Word = Byte ^ Byte << 13 ^ Byte << 23;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T2
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform0 Function

			std::uint32_t Word = Byte ^ Byte << 13 ^ Byte << 23;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T1
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform0 Function

			std::uint32_t Word = Byte ^ Byte << 13 ^ Byte << 23;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		++Round;

		//T0
		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];

			//LinearTransform0 Function

			std::uint32_t Word = Byte ^ Byte << 13 ^ Byte << 23;
			ProcessBlockTable[Round][Index] = Word << ByteBits * Round | Word >> (WordBits - ByteBits * Round) % WordBits;
		}

		return ProcessBlockTable;
	}

	#endif
}

namespace CommonSecurity::ChinaShangYongMiMa4::ProcedureFunctions
{
	class ExperimentalAlgorithm
	{
	
	private:

		std::array<std::uint32_t, 32> EachRoundKeyWords {};

		static constexpr std::array<std::array<std::uint8_t, 16>, 16> Subtitute_ByteBoxMatrix
		{
			{
				{0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
				{0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
				{0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
				{0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
				{0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
				{0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
				{0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
				{0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
				{0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
				{0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
				{0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
				{0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
				{0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
				{0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
				{0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
				{0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
			}
		};

		std::uint32_t Tau_NonlinearFunction(std::uint32_t Word)
		{
			std::array<std::uint8_t, 4> Bytes{ 0, 0, 0, 0 };
			std::uint32_t ChangedWord = 0;

			for (std::uint32_t Index = 0; Index < 4; Index++)
			{
				Bytes[Index] = Word >> (24 - Index * std::numeric_limits<std::uint8_t>::digits);
				Bytes[Index] = Subtitute_ByteBoxMatrix[Bytes[Index] >> 4][Bytes[Index] & 0x0f];
				ChangedWord |= Bytes[Index] << (24 - Index * std::numeric_limits<std::uint8_t>::digits);
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(Bytes.data(), sizeof(std::uint32_t));
			my_cpp2020_assert(CheckPointer == Bytes.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			return ChangedWord;
		}

		//For Data Round Function
		std::uint32_t LinearFunction0(std::uint32_t Word)
		{
			return Word
				^ std::rotl(Word, static_cast<std::uint32_t>(2))
				^ std::rotl(Word, static_cast<std::uint32_t>(10))
				^ std::rotl(Word, static_cast<std::uint32_t>(18))
				^ std::rotl(Word, static_cast<std::uint32_t>(24));
		}

		//For Key Expansion Function
		std::uint32_t LinearFunction1(std::uint32_t Word)
		{
			return Word
				^ std::rotl(Word, static_cast<std::uint32_t>(13))
				^ std::rotl(Word, static_cast<std::uint32_t>(23));
		}

		std::uint32_t MixerTransform0(std::uint32_t Word)
		{
			return LinearFunction0( Tau_NonlinearFunction(Word) );
		}

		std::uint32_t MixerTransform1(std::uint32_t Word)
		{
			return LinearFunction1( Tau_NonlinearFunction(Word) );
		}

		std::uint32_t EndianConvert(std::uint32_t Word)
		{
			return ((Word << 24) & 0xff000000)
				| ((Word << 8) & 0x00ff0000)
				| ((Word >> 8) & 0x0000ff00)
				| ((Word >> 24) & 0x000000ff);
		}

	public:

		static constexpr std::uint32_t Number_Block_Data_Byte_Size = 16;

		void KeySchedule
		(
			std::span<const std::uint8_t> KeyByteData
		)
		{
			using DefineConstants::ConstentWords;
			using DefineConstants::SystemWords;

			my_cpp2020_assert(KeyByteData.size() == Number_Block_Data_Byte_Size, "CommonSecurity::ChinaShangYongMiMa4::DataWorker : The size of the key byte array is invalid!", std::source_location::current());

			std::array<std::uint32_t, 4> MasterKeyWords {};
			std::array<std::uint32_t, 36> TemporaryIterationKeyWords {};

			MasterKeyWords[0] = static_cast<std::uint32_t>(KeyByteData[0] << 24)
				| static_cast<std::uint32_t>(KeyByteData[1] << 16)
				| static_cast<std::uint32_t>(KeyByteData[2] << 8)
				| static_cast<std::uint32_t>(KeyByteData[3]);
			MasterKeyWords[1] = static_cast<std::uint32_t>(KeyByteData[4] << 24)
				| static_cast<std::uint32_t>(KeyByteData[5] << 16)
				| static_cast<std::uint32_t>(KeyByteData[6] << 8)
				| static_cast<std::uint32_t>(KeyByteData[7]);
			MasterKeyWords[2] = static_cast<std::uint32_t>(KeyByteData[8] << 24)
				| static_cast<std::uint32_t>(KeyByteData[9] << 16)
				| static_cast<std::uint32_t>(KeyByteData[10] << 8)
				| static_cast<std::uint32_t>(KeyByteData[11]);
			MasterKeyWords[3] = static_cast<std::uint32_t>(KeyByteData[12] << 24)
				| static_cast<std::uint32_t>(KeyByteData[13] << 16)
				| static_cast<std::uint32_t>(KeyByteData[14] << 8)
				| static_cast<std::uint32_t>(KeyByteData[15]);

			TemporaryIterationKeyWords[0] = MasterKeyWords[0] ^ SystemWords[0];
			TemporaryIterationKeyWords[1] = MasterKeyWords[1] ^ SystemWords[1];
			TemporaryIterationKeyWords[2] = MasterKeyWords[2] ^ SystemWords[2];
			TemporaryIterationKeyWords[3] = MasterKeyWords[3] ^ SystemWords[3];

			for(std::size_t Index = 0; Index < 32; ++Index)
			{
				//Apply SM4 Key Expand Core Function And Update Round Key
				EachRoundKeyWords[Index] = TemporaryIterationKeyWords[Index + 4] = TemporaryIterationKeyWords[Index]
					^ MixerTransform1( TemporaryIterationKeyWords[Index + 1] ^ TemporaryIterationKeyWords[Index + 2] ^ TemporaryIterationKeyWords[Index + 3] ^ ConstentWords[Index] );
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(MasterKeyWords.data(), sizeof(std::uint32_t) * MasterKeyWords.size());
			my_cpp2020_assert(CheckPointer == MasterKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(TemporaryIterationKeyWords.data(), sizeof(std::uint32_t) * TemporaryIterationKeyWords.size());
			my_cpp2020_assert(CheckPointer == TemporaryIterationKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ExecuteMode>
		void RoundFunction
		(
			std::span<std::uint8_t> ByteData
		)
		{
			my_cpp2020_assert(ByteData.size_bytes() == Number_Block_Data_Byte_Size, "CommonSecurity::ChinaShangYongMiMa4::DataWorker : The size of the data byte array is invalid!", std::source_location::current());

			std::array<std::uint32_t, 36> TemporaryIterationDataWords {};
			std::array<std::uint32_t, 4> ProcessBuffer {};

			::memmove(ProcessBuffer.data(), ByteData.data(), Number_Block_Data_Byte_Size);

			TemporaryIterationDataWords[0] = this->EndianConvert(ProcessBuffer[0]);
			TemporaryIterationDataWords[1] = this->EndianConvert(ProcessBuffer[1]);
			TemporaryIterationDataWords[2] = this->EndianConvert(ProcessBuffer[2]);
			TemporaryIterationDataWords[3] = this->EndianConvert(ProcessBuffer[3]);

			for(std::uint32_t Index = 0, KeyIndex = 0; Index < 32; ++Index)
			{
				if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
					KeyIndex = Index;
				else if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
					KeyIndex = 31 - Index;
				else
					break;

				//Apply SM4 Data Process Core Function And Update Round Data
				TemporaryIterationDataWords[Index + 4] = TemporaryIterationDataWords[Index]
					^ MixerTransform0(TemporaryIterationDataWords[Index + 1] ^ TemporaryIterationDataWords[Index + 2] ^ TemporaryIterationDataWords[Index + 3] ^ this->EachRoundKeyWords[KeyIndex]);
			}

			ProcessBuffer[0] = this->EndianConvert(TemporaryIterationDataWords[35]);
			ProcessBuffer[1] = this->EndianConvert(TemporaryIterationDataWords[34]);
			ProcessBuffer[2] = this->EndianConvert(TemporaryIterationDataWords[33]);
			ProcessBuffer[3] = this->EndianConvert(TemporaryIterationDataWords[32]);

			::memmove(ByteData.data(), ProcessBuffer.data(), Number_Block_Data_Byte_Size);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(TemporaryIterationDataWords.data(), sizeof(std::uint32_t) * TemporaryIterationDataWords.size());
			my_cpp2020_assert(CheckPointer == TemporaryIterationDataWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(ProcessBuffer.data(), sizeof(std::uint32_t) * ProcessBuffer.size());
			my_cpp2020_assert(CheckPointer == ProcessBuffer.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		ExperimentalAlgorithm() = default;

		~ExperimentalAlgorithm()
		{
			volatile void* CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>(EachRoundKeyWords.data(), sizeof(std::uint32_t) * EachRoundKeyWords.size());
			my_cpp2020_assert(CheckPointer == EachRoundKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}
	};

	class OfficialAlgorithm
	{
		
	private:

		std::array<std::uint32_t, 32> EachRoundKeyWords {};

		//For Data Round Function
		static constexpr std::array<std::array<std::uint32_t, 256>, 4> MixDataTransformedWordTable = DefineConstants::GenerateMixDataTransformedWordTable();

		//For Key Expansion Function
		static constexpr std::array<std::array<std::uint32_t, 256>, 4> MixKeyTransformedWordTable = DefineConstants::GenerateMixKeyTransformedWordTable();

		std::uint32_t EndianConvert(std::uint32_t Word)
		{
			return ((Word << 24) & 0xff000000)
				| ((Word << 8) & 0x00ff0000)
				| ((Word >> 8) & 0x0000ff00)
				| ((Word >> 24) & 0x000000ff);
		}

	public:

		static constexpr std::uint32_t Number_Block_Data_Byte_Size = 16;

		void KeySchedule
		(
			std::span<const std::uint8_t> KeyByteData
		)
		{
			using DefineConstants::ConstentWords;
			using DefineConstants::SystemWords;

			my_cpp2020_assert(KeyByteData.size() == Number_Block_Data_Byte_Size, "CommonSecurity::ChinaShangYongMiMa4::DataWorker : The size of the key byte array is invalid!", std::source_location::current());

			std::array<std::uint32_t, 4> MasterKeyWords {};
			std::array<std::uint32_t, 36> TemporaryIterationKeyWords {};

			MasterKeyWords[0] = static_cast<std::uint32_t>(KeyByteData[0] << 24)
				| static_cast<std::uint32_t>(KeyByteData[1] << 16)
				| static_cast<std::uint32_t>(KeyByteData[2] << 8)
				| static_cast<std::uint32_t>(KeyByteData[3]);
			MasterKeyWords[1] = static_cast<std::uint32_t>(KeyByteData[4] << 24)
				| static_cast<std::uint32_t>(KeyByteData[5] << 16)
				| static_cast<std::uint32_t>(KeyByteData[6] << 8)
				| static_cast<std::uint32_t>(KeyByteData[7]);
			MasterKeyWords[2] = static_cast<std::uint32_t>(KeyByteData[8] << 24)
				| static_cast<std::uint32_t>(KeyByteData[9] << 16)
				| static_cast<std::uint32_t>(KeyByteData[10] << 8)
				| static_cast<std::uint32_t>(KeyByteData[11]);
			MasterKeyWords[3] = static_cast<std::uint32_t>(KeyByteData[12] << 24)
				| static_cast<std::uint32_t>(KeyByteData[13] << 16)
				| static_cast<std::uint32_t>(KeyByteData[14] << 8)
				| static_cast<std::uint32_t>(KeyByteData[15]);

			TemporaryIterationKeyWords[0] = MasterKeyWords[0] ^ SystemWords[0];
			TemporaryIterationKeyWords[1] = MasterKeyWords[1] ^ SystemWords[1];
			TemporaryIterationKeyWords[2] = MasterKeyWords[2] ^ SystemWords[2];
			TemporaryIterationKeyWords[3] = MasterKeyWords[3] ^ SystemWords[3];

			std::uint32_t TemporaryKeyWord = 0;

			for(std::size_t Index = 0; Index < 32; ++Index)
			{
				//Apply SM4 Key Expand Core Function
				TemporaryKeyWord = TemporaryIterationKeyWords[Index + 1] ^ TemporaryIterationKeyWords[Index + 2] ^ TemporaryIterationKeyWords[Index + 3] ^ ConstentWords[Index];
				TemporaryIterationKeyWords[Index + 4] = TemporaryIterationKeyWords[Index]
					^ MixKeyTransformedWordTable[0][TemporaryKeyWord & 0xff]
					^ MixKeyTransformedWordTable[1][TemporaryKeyWord >> 8 & 0xff]
					^ MixKeyTransformedWordTable[2][TemporaryKeyWord >> 16 & 0xff]
					^ MixKeyTransformedWordTable[3][TemporaryKeyWord >> 24];
				
				//Update Round Key
				EachRoundKeyWords[Index] = TemporaryIterationKeyWords[Index + 4];
			}

			TemporaryKeyWord = 0;

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(MasterKeyWords.data(), sizeof(std::uint32_t) * MasterKeyWords.size());
			my_cpp2020_assert(CheckPointer == MasterKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(TemporaryIterationKeyWords.data(), sizeof(std::uint32_t) * TemporaryIterationKeyWords.size());
			my_cpp2020_assert(CheckPointer == TemporaryIterationKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW ExecuteMode>
		void RoundFunction
		(
			std::span<std::uint8_t> OriginalByteData
		)
		{
			my_cpp2020_assert(OriginalByteData.size_bytes() == Number_Block_Data_Byte_Size, "CommonSecurity::ChinaShangYongMiMa4::DataWorker : The size of the data byte array is invalid!", std::source_location::current());

			std::array<std::uint32_t, 36> TemporaryIterationDataWords {};
			std::array<std::uint32_t, 4> ProcessBuffer {};

			::memmove(ProcessBuffer.data(), OriginalByteData.data(), Number_Block_Data_Byte_Size);

			TemporaryIterationDataWords[0] = this->EndianConvert(ProcessBuffer[0]);
			TemporaryIterationDataWords[1] = this->EndianConvert(ProcessBuffer[1]);
			TemporaryIterationDataWords[2] = this->EndianConvert(ProcessBuffer[2]);
			TemporaryIterationDataWords[3] = this->EndianConvert(ProcessBuffer[3]);

			std::uint32_t TemporaryDataWord = 0;

			for(std::uint32_t Index = 0, KeyIndex = 0; Index < 32; ++Index)
			{
				if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
					KeyIndex = Index;
				else if constexpr(ExecuteMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
					KeyIndex = 31 - Index;
				else
					break;

				//Apply SM4 Data Process Core Function
				TemporaryDataWord = TemporaryIterationDataWords[Index + 1] ^ TemporaryIterationDataWords[Index + 2] ^ TemporaryIterationDataWords[Index + 3] ^ this->EachRoundKeyWords[KeyIndex];

				//Update Round Data
				TemporaryIterationDataWords[Index + 4] = TemporaryIterationDataWords[Index]
					^ MixDataTransformedWordTable[0][TemporaryDataWord & 0xff]
					^ MixDataTransformedWordTable[1][TemporaryDataWord >> 8 & 0xff]
					^ MixDataTransformedWordTable[2][TemporaryDataWord >> 16 & 0xff]
					^ MixDataTransformedWordTable[3][TemporaryDataWord >> 24];
			}

			TemporaryDataWord = 0;

			ProcessBuffer[0] = this->EndianConvert(TemporaryIterationDataWords[35]);
			ProcessBuffer[1] = this->EndianConvert(TemporaryIterationDataWords[34]);
			ProcessBuffer[2] = this->EndianConvert(TemporaryIterationDataWords[33]);
			ProcessBuffer[3] = this->EndianConvert(TemporaryIterationDataWords[32]);

			::memmove(OriginalByteData.data(), ProcessBuffer.data(), Number_Block_Data_Byte_Size);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(TemporaryIterationDataWords.data(), sizeof(std::uint32_t) * TemporaryIterationDataWords.size());
			my_cpp2020_assert(CheckPointer == TemporaryIterationDataWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(ProcessBuffer.data(), sizeof(std::uint32_t) * ProcessBuffer.size());
			my_cpp2020_assert(CheckPointer == ProcessBuffer.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		OfficialAlgorithm() = default;

		~OfficialAlgorithm()
		{
			volatile void* CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>(EachRoundKeyWords.data(), sizeof(std::uint32_t) * EachRoundKeyWords.size());
			my_cpp2020_assert(CheckPointer == EachRoundKeyWords.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}
	};
}

namespace CommonSecurity::ChinaShangYongMiMa4
{
	using ProcedureFunctions::ExperimentalAlgorithm;
	using ProcedureFunctions::OfficialAlgorithm;

	class DataWorker128 : public CommonSecurity::BlockCipher128_128
	{

	private:

		OfficialAlgorithm AlgorithmObject;
	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(Output);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(Output);
		}

		DataWorker128() = default;
		virtual ~DataWorker128() = default;

		DataWorker128(DataWorker128& _object) = delete;
		DataWorker128& operator=(const DataWorker128& _object) = delete;
	};

	class DataWorker256 : public CommonSecurity::BlockCipher128_256
	{

	private:

		OfficialAlgorithm AlgorithmObject;
		std::array<std::uint8_t, 32> KeyArray {};
	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			if(BytesKey.size() == 32)
				::memcpy(KeyArray.data(), BytesKey.data(), 32);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			if ( ( Input.data() != Output.data() ) && ( ( Input.size() == DataBlockByteSize ) && ( Output.size() == DataBlockByteSize ) ) )
				::memcpy( Output.data(), Input.data(), DataBlockByteSize );
			AlgorithmObject.KeySchedule({KeyArray.begin(), KeyArray.begin() + 16});
			AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(Output);
			AlgorithmObject.KeySchedule({KeyArray.begin() + 16, KeyArray.end()});
			AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(Output);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			if ( ( Input.data() != Output.data() ) && ( ( Input.size() == DataBlockByteSize ) && ( Output.size() == DataBlockByteSize ) ) )
				::memcpy( Output.data(), Input.data(), DataBlockByteSize );
			AlgorithmObject.KeySchedule({KeyArray.begin() + 16, KeyArray.end()});
			AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(Output);
			AlgorithmObject.KeySchedule({KeyArray.begin(), KeyArray.begin() + 16});
			AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(Output);
		}

		DataWorker256() = default;
		virtual ~DataWorker256() = default;

		DataWorker256(DataWorker256& _object) = delete;
		DataWorker256& operator=(const DataWorker256& _object) = delete;
	};
}