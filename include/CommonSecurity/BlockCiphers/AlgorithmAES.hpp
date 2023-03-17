#pragma once

namespace CommonSecurity::AES
{
	inline constexpr std::array<std::uint8_t, 256> Subtitute_ByteBox
	{
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};

	inline constexpr std::array<std::uint8_t, 256> InverseSubtitute_ByteBox
	{
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	};

	constexpr std::uint32_t Binary_Polynomial_Data = (1U << 8) ^ (1U << 4) ^ (1U << 3) ^ (1U << 1) ^ (1U << 0);

	inline constexpr std::array<std::uint32_t, 16>
	GeneratePowerXTimeTable()
	{
		std::array<std::uint32_t, 16> PowerXTimeTable
		{ 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 };

		std::uint32_t Poly = 1;

		for(std::uint32_t Index = 0; Index < PowerXTimeTable.size(); Index++)
		{
			if(PowerXTimeTable[Index] != Poly)
				PowerXTimeTable[Index] = Poly;

			Poly <<= 1;
			if( (Poly & 256U) != 0 )
			{
				Poly ^= Binary_Polynomial_Data;
			}
		}

		return PowerXTimeTable;
	}

	// Multiply value and constant-value as GF(2) polynomials modulo poly
	inline constexpr std::uint32_t
	MultiplicationOfWordWithGaloisField(std::uint32_t Multiplied, std::uint32_t Multiplier)
	{
		std::uint32_t A = Multiplied;
		std::uint32_t B = Multiplier;
		std::uint32_t C = 0U;

		for(std::uint32_t Index = 1; Index < 256 && B != 0; Index <<= 1)
		{
			// Invariant: k == 1<<n, i == b * xⁿ
			if ((B & Index) != 0U)
			{
				// C += A in GF(2); xor in binary
				C ^= A;
				B ^= Index; // turn off bit to end loop early
			}

			// A *= x in GF(2) modulo the polynomial
			A <<= 1;
			if((A & 256) != 0U)
			{
				A ^= Binary_Polynomial_Data;
			}
		}

		return C;
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateEncryptionWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = Subtitute_ByteBox[Index];
			std::uint32_t Byte2 = MultiplicationOfWordWithGaloisField(Byte, 0x2U);
			std::uint32_t Byte3 = MultiplicationOfWordWithGaloisField(Byte, 0x3U);

			std::uint32_t Word = Byte2 << 24 | Byte << 16 | Byte << 8 | Byte3;
			for(std::uint32_t Index2 = 0; Index2 < 4; Index2++)
			{
				if(ProcessBlockTable[Index2][Index] != Word)
					ProcessBlockTable[Index2][Index] = Word;

				Word = Word << 24 | Word >> 8;
			}
		}

		return ProcessBlockTable;
	}

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	GenerateDecryptionWordTable()
	{
		std::array<std::array<std::uint32_t, 256>, 4> ProcessBlockTable{};

		for(std::uint32_t Index = 0; Index < 256; Index++)
		{
			std::uint32_t Byte = InverseSubtitute_ByteBox[Index];
			std::uint32_t Byte2 = MultiplicationOfWordWithGaloisField(Byte, 0x9U);
			std::uint32_t Byte3 = MultiplicationOfWordWithGaloisField(Byte, 0xBU);
			std::uint32_t Byte4 = MultiplicationOfWordWithGaloisField(Byte, 0xDU);
			std::uint32_t Byte5 = MultiplicationOfWordWithGaloisField(Byte, 0xEU);

			std::uint32_t Word = Byte5 << 24 | Byte2 << 16 | Byte4 << 8 | Byte3;
			for(std::uint32_t Index2 = 0; Index2 < 4; Index2++)
			{
				if(ProcessBlockTable[Index2][Index] != Word)
					ProcessBlockTable[Index2][Index] = Word;

				Word = Word << 24 | Word >> 8;
			}
		}

		return ProcessBlockTable;
	}

	enum class AES_SecurityLevel
	{
		//128 bit
		ZERO = 0,
		//192 bit
		ONE = 1,
		//256 bit
		TWO = 2
	};

	template<AES_SecurityLevel SecurityLevel>
	constexpr std::array<std::size_t, 2>
	AES_SecurityLevelInforamtion()
	{
		//The number of 32-bit words comprising the cipher key in this AES cipher.
		//Paper content: Number of 32-bit words comprising the Cipher Key. 
		//For this standard, Nk = 4, 6, or 8. (Also see Sec. 6.3.) 
		//Nk is key word size
		std::size_t Number_Key_Data_Block_Size = 0;

		//The number of rounds in this AES cipher.
		//Paper content: Number of rounds, which is a function of Nk and Nb (which is fixed).
		//For this standard, Nr = 10, 12, or 14. (Also see Sec. 6.3.) 
		//Nr is * of rounds
		std::size_t Number_Execute_Round_Count = 0;

		if constexpr(SecurityLevel == CommonSecurity::AES::AES_SecurityLevel::ZERO)
		{
			Number_Key_Data_Block_Size = 4;
			Number_Execute_Round_Count = 10;

			return { Number_Key_Data_Block_Size, Number_Execute_Round_Count };
		}
		else if constexpr(SecurityLevel == CommonSecurity::AES::AES_SecurityLevel::ONE)
		{
			Number_Key_Data_Block_Size = 6;
			Number_Execute_Round_Count = 12;

			return { Number_Key_Data_Block_Size, Number_Execute_Round_Count };
		}
		else if constexpr(SecurityLevel == CommonSecurity::AES::AES_SecurityLevel::TWO)
		{
			Number_Key_Data_Block_Size = 8;
			Number_Execute_Round_Count = 14;

			return { Number_Key_Data_Block_Size, Number_Execute_Round_Count };
		}
		else
		{
			static_assert(CommonToolkit::Dependent_Always_Failed<SecurityLevel>, "Wrong AES DataWorker security level is selected !");
		}
	}

	template<AES_SecurityLevel SecurityLevel>
	class OfficialAlgorithm
	{

	private:
		std::vector<std::uint32_t> EncryptionKey = std::vector<std::uint32_t>(this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1), 0);
		std::vector<std::uint32_t> DecryptionKey = std::vector<std::uint32_t>(this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1), 0);

	public:
		static constexpr std::size_t ONE_WORD_BYTE_SIZE = sizeof(std::uint32_t);
		
		//The number of 32-bit words comprising the plaintext and columns comprising the state matrix of an AES cipher.
		//Paper content: Number of columns (32-bit words) comprising the State. For this standard, Nb = 4. (Also see Sec. 6.3.)
		//Nb is block word size
		static constexpr std::size_t NUMBER_DATA_BLOCK_COUNT = 4;
		
		static constexpr auto AES_CONFIG_INFORMATION = AES_SecurityLevelInforamtion<SecurityLevel>();

		static constexpr std::size_t Number_Key_Data_Block_Size = AES_CONFIG_INFORMATION[0];

		static constexpr std::size_t Number_Execute_Round_Count = AES_CONFIG_INFORMATION[1];
		
		static constexpr std::uint8_t Number_Block_Data_Byte_Size = ONE_WORD_BYTE_SIZE * NUMBER_DATA_BLOCK_COUNT * sizeof(std::uint8_t);

		static constexpr std::array<std::uint32_t, 16> PowerXTimeTable = AES::GeneratePowerXTimeTable();

		static constexpr std::array<std::array<std::uint32_t, 256>, 4> EncryptionWordTable = AES::GenerateEncryptionWordTable();

		static constexpr std::array<std::array<std::uint32_t, 256>, 4> DecryptionWordTable = AES::GenerateDecryptionWordTable();

		void EncryptBlockData(std::span<const std::uint8_t> InputBlock, std::span<std::uint8_t> OuputBlock)
		{
			if(InputBlock.size() == GetBlockSize_DataByte())
			{
				auto wordDataBlock = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(InputBlock.data(), InputBlock.size());

				auto& WordA = wordDataBlock[0];
				auto& WordB = wordDataBlock[1];
				auto& WordC = wordDataBlock[2];
				auto& WordD = wordDataBlock[3];

				// First round just XORs input with key.
				WordA ^= EncryptionKey[0];
				WordB ^= EncryptionKey[1];
				WordC ^= EncryptionKey[2];
				WordD ^= EncryptionKey[3];

				// Middle rounds shuffle using tables.
				// Number of rounds is set by length of expanded key.
				std::size_t WordKeyOffest = 4;
				std::uint32_t T0 = 0U, T1 = 0U, T2 = 0U, T3 = 0U;
				for(std::size_t round = 0U; round < EncryptionKey.size() / 4 - 2; ++round)
				{
					T0 = EncryptionKey[ WordKeyOffest + 0 ]
						^ EncryptionWordTable[0][ static_cast<std::uint8_t>( WordA >> 24 ) ]
						^ EncryptionWordTable[1][ static_cast<std::uint8_t>( WordB >> 16 ) ]
						^ EncryptionWordTable[2][ static_cast<std::uint8_t>( WordC >> 8 ) ]
						^ EncryptionWordTable[3][ static_cast<std::uint8_t>( WordD ) ];

					T1 = EncryptionKey[ WordKeyOffest + 1 ]
						^ EncryptionWordTable[0][ static_cast<std::uint8_t>( WordB >> 24 ) ]
						^ EncryptionWordTable[1][ static_cast<std::uint8_t>( WordC >> 16 ) ]
						^ EncryptionWordTable[2][ static_cast<std::uint8_t>( WordD >> 8 ) ]
						^ EncryptionWordTable[3][ static_cast<std::uint8_t>( WordA ) ];

					T2 = EncryptionKey[ WordKeyOffest + 2 ]
						^ EncryptionWordTable[0][ static_cast<std::uint8_t>( WordC >> 24 ) ]
						^ EncryptionWordTable[1][ static_cast<std::uint8_t>( WordD >> 16 ) ]
						^ EncryptionWordTable[2][ static_cast<std::uint8_t>( WordA >> 8 ) ]
						^ EncryptionWordTable[3][ static_cast<std::uint8_t>( WordB ) ];

					T3 = EncryptionKey[ WordKeyOffest + 3 ]
						^ EncryptionWordTable[0][ static_cast<std::uint8_t>( WordD >> 24 ) ]
						^ EncryptionWordTable[1][ static_cast<std::uint8_t>( WordA >> 16 ) ]
						^ EncryptionWordTable[2][ static_cast<std::uint8_t>( WordB >> 8 ) ]
						^ EncryptionWordTable[3][ static_cast<std::uint8_t>( WordC ) ];

					WordKeyOffest += 4;

					WordA = T0, WordB = T1, WordC = T2, WordD = T3;
				}

				// Last round uses s-box directly and XORs to produce output.
				WordA = static_cast<std::uint32_t>( Subtitute_ByteBox[ T0 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T1 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T2 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T3 & 0xff ] );

				WordB = static_cast<std::uint32_t>( Subtitute_ByteBox[ T1 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T2 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T3 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T0 & 0xff ] );

				WordC = static_cast<std::uint32_t>( Subtitute_ByteBox[ T2 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T3 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T0 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T1 & 0xff ] );

				WordD = static_cast<std::uint32_t>( Subtitute_ByteBox[ T3 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T0 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T1 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ T2 & 0xff ] );
				
				WordA ^= EncryptionKey[WordKeyOffest + 0];
				WordB ^= EncryptionKey[WordKeyOffest + 1];
				WordC ^= EncryptionKey[WordKeyOffest + 2];
				WordD ^= EncryptionKey[WordKeyOffest + 3];

				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(wordDataBlock, OuputBlock.data());
			}
			else
			{
				throw std::length_error("");
			}
		}

		void DecryptBlockData(std::span<const std::uint8_t>& InputBlock, std::span<std::uint8_t> OutputBlock)
		{
			if(InputBlock.size() == GetBlockSize_DataByte())
			{
				auto wordDataBlock = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(InputBlock.data(), InputBlock.size());
				
				auto& WordA = wordDataBlock[0];
				auto& WordB = wordDataBlock[1];
				auto& WordC = wordDataBlock[2];
				auto& WordD = wordDataBlock[3];

				// First round just XORs input with key.
				WordA ^= DecryptionKey[0];
				WordB ^= DecryptionKey[1];
				WordC ^= DecryptionKey[2];
				WordD ^= DecryptionKey[3];

				// Middle rounds shuffle using tables.
				// Number of rounds is set by length of expanded key.
				std::size_t WordKeyOffest = 4;
				std::uint32_t T0 = 0U, T1 = 0U, T2 = 0U, T3 = 0U;
				for(std::size_t round = 0U; round < DecryptionKey.size() / 4 - 2; ++round)
				{
					T0 = DecryptionKey[ WordKeyOffest + 0 ]
						^ DecryptionWordTable[0][ static_cast<std::uint8_t>( WordA >> 24 ) ]
						^ DecryptionWordTable[1][ static_cast<std::uint8_t>( WordD >> 16 ) ]
						^ DecryptionWordTable[2][ static_cast<std::uint8_t>( WordC >> 8 ) ]
						^ DecryptionWordTable[3][ static_cast<std::uint8_t>( WordB ) ];

					T1 = DecryptionKey[ WordKeyOffest + 1 ]
						^ DecryptionWordTable[0][ static_cast<std::uint8_t>( WordB >> 24 ) ]
						^ DecryptionWordTable[1][ static_cast<std::uint8_t>( WordA >> 16 ) ]
						^ DecryptionWordTable[2][ static_cast<std::uint8_t>( WordD >> 8 ) ]
						^ DecryptionWordTable[3][ static_cast<std::uint8_t>( WordC ) ];

					T2 = DecryptionKey[ WordKeyOffest + 2 ]
						^ DecryptionWordTable[0][ static_cast<std::uint8_t>( WordC >> 24 ) ]
						^ DecryptionWordTable[1][ static_cast<std::uint8_t>( WordB >> 16 ) ]
						^ DecryptionWordTable[2][ static_cast<std::uint8_t>( WordA >> 8 ) ]
						^ DecryptionWordTable[3][ static_cast<std::uint8_t>( WordD ) ];

					T3 = DecryptionKey[ WordKeyOffest + 3 ]
						^ DecryptionWordTable[0][ static_cast<std::uint8_t>( WordD >> 24 ) ]
						^ DecryptionWordTable[1][ static_cast<std::uint8_t>( WordC >> 16 ) ]
						^ DecryptionWordTable[2][ static_cast<std::uint8_t>( WordB >> 8 ) ]
						^ DecryptionWordTable[3][ static_cast<std::uint8_t>( WordA ) ];

					WordKeyOffest += 4;

					WordA = T0, WordB = T1, WordC = T2, WordD = T3;
				}

				// Last round uses s-box directly and XORs to produce output.
				WordA = static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T0 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T3 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T2 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T1 & 0xff ] );

				WordB = static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T1 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T0 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T3 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T2 & 0xff ] );

				WordC = static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T2 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T1 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T0 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T3 & 0xff ] );

				WordD = static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T3 >> 24 ] ) << 24
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T2 >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T1 >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( InverseSubtitute_ByteBox[ T0 & 0xff ] );
				
				WordA ^= DecryptionKey[WordKeyOffest + 0];
				WordB ^= DecryptionKey[WordKeyOffest + 1];
				WordC ^= DecryptionKey[WordKeyOffest + 2];
				WordD ^= DecryptionKey[WordKeyOffest + 3];

				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(wordDataBlock, OutputBlock.data());
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			KEY SCHEDULING
			https://en.wikipedia.org/wiki/AES_key_schedule
			https://autonome-antifa.org/IMG/pdf/Rijndael.pdf
		*/
		void KeySchedule(std::span<const std::uint8_t> byteKeys)
		{
			//Key schedule round : The size of the key schedule depends on the number of rounds
			constexpr std::uint32_t KeyScheduleRound = this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
			
			//Determine the number of 32-bit words in the key
			std::size_t WordKeysSize = byteKeys.size() / sizeof(std::uint32_t);

			//Copy the original key
			::memmove(EncryptionKey.data(), byteKeys.data(), WordKeysSize * sizeof(std::uint32_t));
			if constexpr(std::endian::native == std::endian::big)
			{
				for(auto& Word : EncryptionKey)
				{
					Word = CommonToolkit::ByteSwap::byteswap(Word);
				}
			}

			//Generate the key schedule (encryption)
			for(std::size_t Index = WordKeysSize; Index < KeyScheduleRound; Index++)
			{
				std::uint32_t Word = EncryptionKey[Index - 1];
				if(Index % WordKeysSize == 0)
				{
					//Left rotate word data
					//Word = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(Word, 4);
					Word = ( Word << 8 ) | ( Word >> 24 );

					//Substitute word data
					Word = static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word & 0xff ] );

					Word = Word ^ (static_cast<std::uint32_t>( this->PowerXTimeTable[Index / this->Number_Key_Data_Block_Size - 1] ) << 24);
				}
				else if((WordKeysSize > 6) && (Index % WordKeysSize) == 4)
				{
					//Substitute word data
					Word = static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 24 ] ) << 24
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 16 & 0xff ] ) << 16
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word >> 8 & 0xff ] ) << 8
					| static_cast<std::uint32_t>( Subtitute_ByteBox[ Word & 0xff ] );
				}
				EncryptionKey[Index] = EncryptionKey[Index - WordKeysSize] ^ Word;
			}

			//Generate the key schedule (decryption)
			for(std::size_t Index = 0; Index < KeyScheduleRound; Index += 4)
			{
				std::size_t KeyOffset = KeyScheduleRound - Index - 4;
				for(std::size_t Index2 = 0; Index2 < 4; Index2++)
				{
					std::uint32_t Word = EncryptionKey[KeyOffset + Index2];
					if((Index > 0) && (Index + 4) < KeyScheduleRound)
					{
						Word = DecryptionWordTable[0][ Subtitute_ByteBox[ Word >> 24 ] ]
							^ DecryptionWordTable[1][ Subtitute_ByteBox[ Word >> 16 & 0xff ] ]
							^ DecryptionWordTable[2][ Subtitute_ByteBox[ Word >> 8 & 0xff ] ]
							^ DecryptionWordTable[3][ Subtitute_ByteBox[ Word & 0xff ] ];
					}
					DecryptionKey[Index + Index2] = Word;
				}
			}
		}

		constexpr std::uint8_t GetBlockSize_DataByte() const
		{
			return this->Number_Block_Data_Byte_Size;
		}

		constexpr std::size_t GetBlockSize_KeyByte() const
		{
			return this->Number_Key_Data_Block_Size * this->ONE_WORD_BYTE_SIZE;
		}

		constexpr std::size_t GetBlockSize_ExpandedKeyByte()
		{
			return this->ONE_WORD_BYTE_SIZE * this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
		}
	};
}

/*
	https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
	https://zh.wikipedia.org/wiki/%E9%AB%98%E7%BA%A7%E5%8A%A0%E5%AF%86%E6%A0%87%E5%87%86
	
	The Advanced Encryption Standard (AES), also known by its original name Rijndael (Dutch pronunciation: [ˈrɛindaːl]),[3]
	is a specification for the encryption of electronic data established by the U.S.
	National Institute of Standards and Technology (NIST) in 2001.[4]

	AES is a variant of the Rijndael block cipher[3] developed by two Belgian cryptographers, Joan Daemen and Vincent Rijmen, who submitted a proposal[5]
	to NIST during the AES selection process.[6] Rijndael is a family of ciphers with different key and block sizes.
	For AES, NIST selected three members of the Rijndael family, each with a block size of 128 bits, but three different key lengths: 128, 192 and 256 bits.

	AES has been adopted by the U.S. government. It supersedes the Data Encryption Standard (DES),[7]
	which was published in 1977. 
	The algorithm described by AES is a symmetric-key algorithm, meaning the same key is used for both encrypting and decrypting the data.

	In the United States, AES was announced by the NIST as U.S.FIPS PUB 197 (FIPS 197) on November 26, 2001.[4]
	This announcement followed a five-year standardization process in which fifteen competing designs were presented and evaluated, before the Rijndael cipher was selected as the most suitable (see Advanced Encryption Standard process for more details).

	AES is included in the ISO/IEC 18033-3 standard.
	AES became effective as a U.S. federal government standard on May 26, 2002, after approval by the U.S. Secretary of Commerce.
	AES is available in many different encryption packages, and is the first (and only) publicly accessible cipher approved by the U.S.
	National Security Agency (NSA) for top secret information when used in an NSA approved cryptographic module (see Security of AES, below).
	
	高级加密标准（英语：Advanced Encryption Standard，缩写：AES），又称Rijndael加密法（荷兰语发音： [ˈrɛindaːl]，音似英文的“Rhine doll”），是美国联邦政府采用的一种区块加密标准
	这个标准用来替代原先的DES，已经被多方分析且广为全世界所使用。
	经过五年的甄选流程，高级加密标准由美国国家标准与技术研究院（NIST）于2001年11月26日发布于FIPS PUB 197，并在2002年5月26日成为有效的标准
	现在，高级加密标准已然成为对称密钥加密中最流行的算法之一

	该算法为比利时密码学家Joan Daemen和Vincent Rijmen所设计，结合两位作者的名字，以Rijndael为名投稿高级加密标准的甄选流程
*/
namespace CommonSecurity::AES
{
	class DataWorker128 : public CommonSecurity::BlockCipher128_128
	{

	private:
		
		OfficialAlgorithm<AES_SecurityLevel::ZERO> AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			if ( ( Input.data() != Output.data() ) && ( ( Input.size() == DataBlockByteSize ) && ( Output.size() == DataBlockByteSize ) ) )
				::memcpy( Output.data(), Input.data(), DataBlockByteSize );
			AlgorithmObject.EncryptBlockData(Input, Output);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			AlgorithmObject.DecryptBlockData(Input, Output);
		}

		DataWorker128() = default;
		virtual ~DataWorker128() = default;

		DataWorker128(DataWorker128& _object) = delete;
		DataWorker128& operator=(const DataWorker128& _object) = delete;
	};

	class DataWorker192 : public CommonSecurity::BlockCipher128_192
	{

	private:
		
		OfficialAlgorithm<AES_SecurityLevel::ONE> AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			if ( ( Input.data() != Output.data() ) && ( ( Input.size() == DataBlockByteSize ) && ( Output.size() == DataBlockByteSize ) ) )
				::memcpy( Output.data(), Input.data(), DataBlockByteSize );
			AlgorithmObject.EncryptBlockData(Input, Output);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			if ( ( Input.data() != Output.data() ) && ( ( Input.size() == DataBlockByteSize ) && ( Output.size() == DataBlockByteSize ) ) )
				::memcpy( Output.data(), Input.data(), DataBlockByteSize );
			AlgorithmObject.DecryptBlockData(Input, Output);
		}

		DataWorker192() = default;
		virtual ~DataWorker192() = default;

		DataWorker192(DataWorker192& _object) = delete;
		DataWorker192& operator=(const DataWorker192& _object) = delete;
	};

	class DataWorker256 : public CommonSecurity::BlockCipher128_256
	{

	private:
		
		OfficialAlgorithm<AES_SecurityLevel::TWO> AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			AlgorithmObject.EncryptBlockData(Input, Output);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			AlgorithmObject.DecryptBlockData(Input, Output);
		}

		DataWorker256() = default;
		virtual ~DataWorker256() = default;

		DataWorker256(DataWorker256& _object) = delete;
		DataWorker256& operator=(const DataWorker256& _object) = delete;
	};
}

namespace CommonSecurity::AES::Experimental
{
	//For Key Schedule

	/**
		In computing, the modulo operation returns the remainder or signed remainder of a division, after one number is divided by another (called the modulus of the operation).
		Given two positive numbers a and n, a modulo n (abbreviated as a mod n) is the remainder of the Euclidean division of a by n, where a is the dividend and n is the divisor.
		The modulo operation is to be distinguished from the symbol mod, which refers to the modulus[1] (or divisor) one is operating from.
		For example, the expression "5 mod 2" would evaluate to 1, because 5 divided by 2 has a quotient of 2 and a remainder of 1, while "9 mod 3" would evaluate to 0
		Because the division of 9 by 3 has a quotient of 3 and a remainder of 0; there is nothing to subtract from 9 after multiplying 3 times 3.
		Although typically performed with a and n both being integers, many computing systems now allow other types of numeric operands.
		The range of values for an integer modulo operation of n is 0 to n − 1 inclusive (a mod 1 is always 0; a mod 0 is undefined, possibly resulting in a division by zero error in some programming languages).
		See Modular arithmetic for an older and related convention applied in number theory.
		When exactly one of a or n is negative, the naive definition breaks down, and programming languages differ in how these values are defined.

		模除（又称模数、取模操作、取模运算等，英语：modulo 有时也称作 modulus
		得到的是一个数除以另一个数的余数。
		给定两个正整数：被除数 a 和除数 n，a modulo n (缩写为 a mod n)
		得到的是使用欧几里德除法时 a/n 的余数。
		举个例子：计算表达式 "5 mod 2" 得到 1，因为 5÷2=2...1（5 除以 2 商 2 余1）；而 "9 mod 3" 得到 0，因为 9÷3=3...0；
		注意：如果使用计算器做除法，不能整除时，你不会得到商，而是会得到一个小数，如：5÷2=2.5。
		虽然通常情况下 a 和 n 都是整数，但许多计算系统允许其他类型的数字操作，如：对浮点数取模。
		一个整数对 n 取模的结果范围为： 0 到 n − 1（a mod 1 恒等于 0；a mod 0 则是未定义的，在编程语言里可能会导致除零错误）。
		有关概念在数论中的应用请参阅模算数。
		当 a 和 n 均为负数时，通常的定义就不适用了，不同的编程语言对结果有不同的处理。

		GF is Galois field
			在数学中，有限域（英语：finite field）或伽罗瓦域（英语：Galois field，为纪念埃瓦里斯特·伽罗瓦命名）是包含有限个元素的域。
			与其他域一样，有限域是进行加减乘除运算都有定义并且满足特定规则的集合。
			有限域最常见的例子是当 p 为素数时，整数对 p 取模。
			有限域的元素个数称为它的阶。
			有限域在许多数学和计算机科学领域的基础，包括数论、代数几何、伽罗瓦理论、有限几何学、密码学和编码理论。
			In mathematics, a finite field or Galois field (so-named in honor of Évariste Galois) is a field that contains a finite number of elements.
			As with any field, a finite field is a set on which the operations of multiplication, addition, subtraction and division are defined and satisfy certain basic rules.
			The most common examples of finite fields are given by the integers mod p when p is a prime number.
			The order of a finite field is its number of elements, which is either a prime number or a prime power.
			For every prime number p and every positive integer k there are fields of order p^k, all of which are isomorphic.
			Finite fields are fundamental in a number of areas of mathematics and computer science, including number theory, algebraic geometry, Galois theory, finite geometry, cryptography and coding theory.

		Paper 3.2 Bytes (Part)
			
			All byte values in the AES algorithm will be presented as the concatenation of its individual bit
			values (0 or 1) between braces in the order
			Byte {bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0}.
			These bytes are
			interpreted as finite field elements using a polynomial representation:

			Mathematical equations 3.1
			bit7*x^7 + bit6*x^6 + bit5*x^5 + bit4*x^4 + bit3*x^3 + bit2*x^2 + bit1*x + bit0

			For example, {01100011} identifies the specific finite field element x
			x^6 + x^5 + x +1.

		Paper 3.2 字节 (部分)

			在AES算法中，所有的字节值都将以其单独的比特值（0或1）的串联形式出现在大括号中。
			值（0或1）在大括号之间的连接，顺序为
			字节{bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0}。
			这些字节被
			被解释为使用多项式表示的有限场元素。

			数学方程式 3.1
			bit7*x^7 + bit6*x^6 + bit5*x^5 + bit4*x^4 + bit3*x^3 + bit2*x^2 + bit1*x + bit0

			例如，{01100011}确定了具体的有限场元素x
			x^6 + x^5 + x +1

		Paper 4. Mathematical Preliminaries
			All bytes in the AES algorithm are interpreted as finite field elements using the notation introduced in Sec. 3.2.
			Finite field elements can be added and multiplied, but these operations are different from those used for numbers.
			The following subsections introduce the basic mathematical concepts needed for Sec. 5.

		论文 4. 数学预演
			在AES算法中，所有的字节都被解释为有限场元素，使用的符号是 3.2节中介绍的符号。
			有限场元素可以被添加和相乘，但这些操作 与用于数字的操作不同。
			下面几个小节介绍了 第5章所需的基本数学概念。

		Parer 4.1 Addition

			The addition of two elements in a finite field is achieved by "adding" the coefficients for the corresponding powers in the polynomials for the two elements.
			The addition is performed with the XOR operation (denoted by (Exclusive-OR) ) - i.e., modulo 2 - so that 1 Exclusive-OR 1 = 0 , 1 Exclusive-OR  0 = 1, and 0 Exclusive-OR 0 = 0 .
			Consequently, subtraction of polynomials is identical to addition of polynomials.

			Alternatively, addition of finite field elements can be described as the modulo 2 addition of corresponding bits in the byte.
			For two bytes {bit_a7,bit_a6,bit_a5,bit_a4,bit_a3,bit_a2,bit_a1,bit_a0} and {bit_b7,bit_b6,bit_b5,bit_b4,bit_b3,bit_b2,bit_b1,bit_b0}, the sum is {bit_c7,bit_c6,bit_c5,bit_c4,bit_c3,bit_c2,bit_c1,bit_c0}
			Where each bit_ci = bit_ai (+) bit_bi (i.e., bit_c7 = bit_a7 (+) bit_b7, bit_c6 = bit_a6 (+) bit_b6, ...... bit_c0 = bit_a0 (+) bit_b0).

			For example, the following expressions are equivalent to one another:
			(x^6 + x^4 + x^2 + x + 1) + (x^7 + x + 1) = x^7 + x^6 + x^4 + x^2 (polynomial notation)
			{01010111} (+) {10000011} = {11010100} (binary notation);
			{57} (+) {83} = {d4} (hexadecimal notation).

		论文 4.1 加法
			有限域中两个元素的相加是通过 "添加 "这两个元素的多项式中的相应幂的系数来实现的。
			加法是通过XOR操作（用(Exclusive-OR)表示）进行的。- 即模数2--因此，1 Exclusive-OR 1 = 0 ，1 Exclusive-OR 0 = 1，0 Exclusive-OR 0 = 0。
			因此，多项式的减法与多项式的加法是相同的。

			另外，有限场元素的加法可以描述为字节中相应位的模2加法。
			对于两个字节{bit_a7,bit_a6,bit_a5,bit_a4,bit_a3,bit_a2,bit_a1,bit_a0}和{bit_b7,bit_b6,bit_b5, bit_b4,bit_b3,bit_b2,bit_b1,bit_b0}，其总和为{bit_c7,bit_c6,bit_c5,bit_c4,bit_c3,bit_c2,bit_c1,bit_c0}。
			其中每个bit_ci = bit_ai (+) bit_bi（即bit_c7 = bit_a7 (+) bit_b7, bit_c6 = bit_a6 (+) bit_b6, ...... bit_c0 = bit_a0 (+) bit_b0）。

			例如，下面的表达式是相互等价的。
			(x^6 + x^4 + x^2 + x + 1) + (x^7 + x + 1) = x^7 + x^6 + x^4 + x^2 (多项式记号)
			{01010111} (+) {10000011} = {11010100}（二进制记法）
			{57}（+）{83}={d4}（十六进制记法）

		Paper 4.2 Multiplication
			In the polynomial representation, multiplication in GF(2^8) (denoted by •) corresponds with the multiplication of polynomials modulo an irreducible polynomial of degree 8.
			A polynomial is irreducible if its only divisors are one and itself.
			
			For the AES algorithm, this irreducible polynomial is

			Mathematical equations 4.1
			m(x) = x^8 + x^4 + x^3 + x + 1 (4.1)

			Or {01}{1b} in hexadecimal notation.

			For example, {57} • {83} = {c1}

			(x^6 + x^4 + x^2 + x + 1)*(x^7 + x + 1)
			= x^13 + x^11 + x^9 + x^8 + x^7 + x^7 + x^5 + x^3 + x^2 + x + x^6 + x^4 + x^2 + x + 1
			= x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1
			
			and x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1 modulo (x^8 + x^4 + x^3 + x + 1)
			= x^7 + x^6 + 1

			The modular reduction by m(x) ensures that the result will be a binary polynomial of degree less than 8, and thus can be represented by a byte.
			Unlike addition, there is no simple operation at the byte level that corresponds to this multiplication.
			The multiplication defined above is associative, and the element {01} is the multiplicative identity.
			For any non-zero binary polynomial b(x) of degree less than 8, the multiplicative inverse of b(x), denoted b^-1(x), can be found as follows: the extended Euclidean algorithm [7]
			is used to compute polynomials a(x) and c(x) such that
			
			Mathematical equations 4.2
			b(x)*a(x) + m(x)*c(x) = 1
			
			Hence, a(x) • b(x) mod(m(x)) = 1
			which means

			Mathematical equations 4.3
			b^-1 (x) = a(x) mod m(x)
			Moreover, for any a(x), b(x) and c(x) in the field, it holds that
			a(x) • (b(x) + c(x)) = a(x) • b(x) + a(x) • c(x).
			It follows that the set of 256 possible byte values, with (Exclusive-OR operation) used as addition and the multiplication defined as above, has the structure of the finite field GF(2^8).


		论文 4.2 乘法
			在多项式表示中，GF(2^8)中的乘法（用•表示）对应于多项式与8度的不可还原多项式的乘法。
			如果一个多项式的除数只有一个和它本身，那么它就是不可还原的。
			
			对于AES算法，这个不可还原的多项式是

			数学方程式 4.1
			m(x) = x^8 + x^4 + x^3 + x + 1 (4.1)

			或者是十六进制的{01}{1b}
			例如，{57}•{83}={c1}
			Because (因为):

			(x^6 + x^4 + x^2 + x + 1)*(x^7 + x + 1)
			= x^13 + x^11 + x^9 + x^8 + x^7 + x^7 + x^5 + x^3 + x^2 + x + x^6 + x^4 + x^2 + x + 1
			= x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1
			
			and x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1 modulo (x^8 + x^4 + x^3 + x + 1)
			= x^7 + x^6 + 1

			m(x)的模块化还原保证了结果将是一个小于8度的二进制多项式，因此可以用一个字节来表示。
			与加法不同的是，在字节级没有对应于这种乘法的简单操作。
			上面定义的乘法是关联性的，元素{01}是乘法的身份。
			对于任何小于8度的非零二元多项式b(x)，b(x)的乘法逆数，表示为b^-1(x)，可以按如下方法找到：扩展的欧几里得算法[7] 。
			用来计算多项式a(x)和c(x)，以便于
			数学方程式 4.2
			b(x)*a(x)+m(x)*c(x)=1
			因此，a（x）• b（x）mod（m（x））= 1
			这意味着
			数学方程式 4.3
			b^-1 (x) = a(x) mod m(x)
			此外，对于场中的任何a(x), b(x)和c(x)，可以看出
			a(x) - (b(x) + c(x)) = a(x) - b(x) + a(x) - c(x)。
			由此可见，256个可能的字节值的集合，用（Exclusive-OR操作）作为加法，乘法定义如上，具有有限域GF(2^8)的结构。

		Paper 4.2.1 Multiplication by x

			Multiplying the binary polynomial defined in equation (3.1) with the polynomial x results in

			Mathematical equations 4.4
			bit7*x^8 + bit6*x^7 + bit5*x^6 + bit4*x^5 + bit3*x^4 + bit2*x^3 + bit1*x^2 + bit0*x

			The result x • b(x) is obtained by reducing the above result modulo m(x), as defined in math equation (4.1)
			If bit7 = 0, the result is already in reduced form.
			Else bit7 = 1, the reduction is accomplished by subtracting (i.e., (Exclusive-OR operation)ing) the polynomial m(x).
			It follows that multiplication by x (i.e., {00000010} or {02}) can be implemented at the byte level as a left shift and a subsequent conditional bitwise (+) with {1b}.
			
			This operation on bytes is denoted by xtime().
			Multiplication by higher powers of x can be implemented by repeated application of xtime().
			By adding intermediate results, multiplication by any constant can be implemented.

		论文 4.2.1 乘以x

			将数学方程式（3.1）中定义的二元多项式与多项式x相乘的结果是

			数学方程式4.4
			bit7*x^8 + bit6*x^7 + bit5*x^6 + bit4*x^5 + bit3*x^4 + bit2*x^3 + bit1*x^2 + bit0*x

			结果x-b(x)是通过减少上述结果的模数m(x)得到的，如数学方程(4.1)所定义的那样
			如果binray bit7 = 0，结果已经是还原形式。
			否则binray bit7 = 1, 减少是通过减去（即（Exclusive-OR操作））多项式m(x)来完成的。
			由此可见，x的乘法（即{00000010}或{02}）可以在字节级实现为左移和随后与{1b}的条件性位操作（+）。
			
			这种对字节的操作用xtime()来表示。
			x的高次幂乘法可以通过重复应用xtime()来实现。
			通过添加中间结果，可以实现与任何常数的乘法。
	*/
	inline std::uint8_t XTime(std::uint8_t Xbyte)
	{
		std::uint8_t bitMask = 0x80, moduloInnumerableMask = 0x1b;
		std::uint8_t highBit = Xbyte & bitMask;
		
		// Rotate ByteA left (multiply by (?) in GF(2^8))
		Xbyte <<= 1;
		//Xbyte = Xbyte << 1;

		// If LSB is active (equivalent to a '1' in the polynomial of ByteB)
		/* If the polynomial for ByteB has a constant term, add the corresponding ByteA to Result */
		if(highBit)
		{
			// result += ByteA in GF(2^8)
			/* Addition in GF(2^m) is an XOR of the polynomial coefficients */
			Xbyte ^= moduloInnumerableMask;
			//Xbyte = Xbyte ^ moduloInnumerableMask
		}
		return Xbyte;
	}

	/***********************************************************************************************
	* This function implements GF(2^8) mulitplication using a variation of peasent multiplication.
	* This algo takes advantage of multiplication's distributive property.
	*
	* e.g. 4 * 9 = 4 * (1* 2^0 + 0 * 2^1 + 0 * 2^2 + 1 * 2^3)
	* by the modulo polynomial relation x^8 + x^4 + x^3 + x + 1 = 0
	* (the other way being to do carryless multiplication followed by a modular reduction)
	*
	* Algorithm described in...
	* https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	***********************************************************************************************/
	inline std::uint8_t MultiplicationOfByteWithGaloisField(std::uint8_t ByteA, std::uint8_t ByteB)
	{
		// Taken and documented from https://en.wikipedia.org/wiki/Rijndael_MixColumns

		/* Accumulator for the product of the multiplication */
		std::uint8_t result = 0x00;
		const std::uint8_t BitMask = 0x01;

		for (int counter = 0; counter < 8; ++counter)
		{
			//ByteA is LeftByteData
			//ByteB is RightByteData

			// ByteA >= 128 = 0b0100'0000
			/* GF modulo: if a has a nonzero term x^7, then must be reduced when it becomes x^8 */
			std::uint8_t Bit = (ByteB & BitMask);
			
			if (Bit != static_cast<std::uint8_t>(0x00))
			{
				std::uint8_t XByte = ByteA; 

				for (int counter2 = 0; counter2 < counter; ++counter2)
				{
					XByte = XTime(XByte);
				}

				// Must reduce
				// ByteA -= 00011011 == modulo(x^8 + x^4 + x^3 + x + 1) = AES irreducible
				/* Subtract (XOR) the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1'0001'1011) – you can change it but it must be irreducible */
				result ^= XByte;
				//result = result ^ Xbyte
			}
			// Rotate ByteB right (divide by (?) in GF(2^8))
			ByteB >>= 1;
			//ByteB = ByteB >> 1;
		}

		return result;
	}

	//The generate round constant word from array index
	//从数组索引生成每轮常数字
	inline void RCON(std::array<std::uint8_t, 4>& Word, int roundCount)
	{
		//Byte data

		std::uint8_t constantByteForThisRound { 1 };

		for(signed int indexCount = 0; indexCount < roundCount - 1; ++indexCount)
		{
			constantByteForThisRound = XTime(constantByteForThisRound);
		}

		Word[0] = constantByteForThisRound;
		Word[1] = Word[2] = Word[3] = 0;
	}

	template<std::size_t SIZE_OF_WORD>
	std::array<std::uint8_t, SIZE_OF_WORD> ExclusiveOR_Words
	(
		const std::array<std::uint8_t, SIZE_OF_WORD> &lhs,
		const std::array<std::uint8_t, SIZE_OF_WORD> &rhs
	)
	{
		std::array<std::uint8_t, SIZE_OF_WORD> result;
		std::ranges::transform
		(
			rhs.begin(),
			rhs.end(),
			lhs.begin(),
			result.begin(),
			[](const std::uint8_t &rhs_byte, const std::uint8_t &lhs_byte) -> std::uint8_t
			{
				return rhs_byte ^ lhs_byte;
			}
		);
		return result;
	}

	//在密钥扩展例程中使用的函数，它接收一个四字节的输入字，并对四个字节中的每个字节应用一个S-box，以产生一个输出字。
	//Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word.
	inline void KeyWordAES_Subtitute(std::array<std::uint8_t, 4>& Word)
	{
		constexpr std::array<std::array<std::uint8_t, 16>, 16> Forward_S_Box
		{
			{
				{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
				{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
				{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
				{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
				{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
				{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
				{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
				{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
				{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
				{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
				{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
				{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
				{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
				{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
				{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
				{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
			},
		};

		std::ranges::transform
		(
			Word.begin(),
			Word.end(),
			Word.begin(),
			[&Forward_S_Box](const std::uint8_t &byte) -> std::uint8_t
			{
				return Forward_S_Box[byte / 16][byte % 16];
			}
		);
	}

	inline void KeyWordAES_LeftRotate(std::uint32_t& Word)
	{
		//Double Word
		Word = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(Word, 4);
	}

	inline void KeyWordAES_LeftRotate(std::array<std::uint8_t, 4>& Word)
	{
		/*
			Example Code:
			for (int k{}; k != 5; ++k) {
				std::iota(s.begin(), s.end(), 'A');
				std::ranges::rotate(s, s.begin() + k);
				std::cout << "Rotate left (" << k << "): " << s << '\n';
			}
			
			std::cout << '\n';
			
			for (int k{}; k != 5; ++k) {
				std::iota(s.begin(), s.end(), 'A');
				std::ranges::rotate(s, s.end() - k);
				std::cout << "Rotate right (" << k << "): " << s << '\n';
			}
		*/

		//std::ranges::rotate(Word, Word.begin() + 1);
		std::ranges::rotate(Word.begin(), Word.begin() + 1, Word.end());
	}

	/*
		The MixColumns() transformation operates on the State column-by-column, treating each column as a four-term polynomial as described in Sec. 4.3.
		The columns are considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a fixed polynomial a(x), given by

		Mathematical equations 5.5
		a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

		Mathematical equations 5.6
		As described in Sec. 4.3, this can be written as a matrix multiplication.
		state' = a(x) (*) state(x):

		As a result of this multiplication, the four bytes in a column are replaced by the following:
		state'[0][column] = ({02} • state[0][column]) (+) ({03} • state[1][column]) (+) state[2][column] (+) state[3][column]
		state'[1][column] = state[0][column] (+) ({02} • state[1][column]) (+) ({03} • state[2][column]) (+) state[3][column]
		state'[2][column] = state[0][column] (+) state[1][column] (+) ({02} • state[2][column]) (+) ({03} • state[3][column])
		state'[3][column] = ({03} • state[0][column]) (+) state[1][column] (+) state[2][column] (+) ({02} • state[3][column])

		MixColumns()转换对状态逐列操作，如第4.3节所述，将每一列作为一个四项多项式处理。
		这些列被视为GF(2^8)上的多项式，并与固定的多项式a(x)相乘以x^4+1，给出如下

		数学公式5.5
		a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

		数学方程5.6
		如第4.3节所述，这可以写成一个矩阵乘法。
		state' = a(x) (*) state(x)

		作为这个乘法的结果，一列中的四个字节被替换成以下内容:
		state'[0][column] = ({02} • state[0][column]) (+) ({03} • state[1][column]) (+) state[2][column] (+) state[3][column]
		state'[1][column] = state[0][column] (+) ({02} • state[1][column]) (+) ({03} • state[2][column]) (+) state[3][column]
		state'[2][column] = state[0][column] (+) state[1][column] (+) ({02} • state[2][column]) (+) ({03} • state[3][column])
		state'[3][column] = ({03} • state[0][column]) (+) state[1][column] (+) state[2][column] (+) ({02} • state[3][column])
		
		In the MixColumns step, the four bytes of each column of the state are combined using an invertible linear transformation.
		The MixColumns function takes four bytes as input and outputs four bytes, where each input byte affects all four output bytes.
		Together with ShiftRows, MixColumns provides diffusion in the cryptographs.

		在MixColumns步骤中，状态的每一列的四个字节用一个可逆的线性变换进行组合。
		MixColumns函数将四个字节作为输入，并输出四个字节，其中每个输入字节会影响所有四个输出字节。
		与ShiftRows一起，MixColumns在密码器中提供了扩散性。
	*/
	inline void MixColumns(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		// AES_BLOCK_SIDE is 4
		#if 0

		std::deque<std::vector<std::uint8_t>> _stateByteDataBlock
		{
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0}
		};

		// matrix multiplication in GF(2^8)
		// * => galoisMul, + => ^

		for(std::uint32_t row = 0; row < 4; ++row)
		{
			for(std::uint32_t column = 0; column < 4; ++column)
			{
				_stateByteDataBlock.operator[](row).operator[](column) = 0x00;
				
				// Dot product of row (r) of the MixColumns and the column (c) of the state
				// MixColumns的r行与状态的c列的点积
				_stateByteDataBlock.operator[](row).operator[](column) ^= MultiplicationOfByteWithGaloisField(CMDS.operator[](row).operator[](column), stateByteDataBlock.operator[](row).operator[](column));
			}
		}

		stateByteDataBlock.swap(_stateByteDataBlock);

		_stateByteDataBlock.clear();

		#else

		std::uint8_t rowDatas[4], columnDatas[4];
		for (int column = 0; column < 4; ++column)
		{
			for (int row = 0; row < 4; ++row)
			{
				rowDatas[row] = stateByteDataBlock[row][column];
			}
			columnDatas[0] = MultiplicationOfByteWithGaloisField(0x02, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[1]) ^ rowDatas[2] ^ rowDatas[3];
			columnDatas[1] = rowDatas[0] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[2]) ^ rowDatas[3];
			columnDatas[2] = rowDatas[0] ^ rowDatas[1] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[3]);
			columnDatas[3] = MultiplicationOfByteWithGaloisField(0x03, rowDatas[0]) ^ rowDatas[1] ^ rowDatas[2] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[3]);
			for (int row = 0; row < 4; ++row)
			{
				stateByteDataBlock[row][column] = columnDatas[row];
			}
		}

		#endif

	}

	/*
		
		InvMixColumns() is the inverse of the MixColumns() transformation.
		InvMixColumns() operates on the State column-by-column, treating each column as a fourterm polynomial as described in Sec. 4.3.
		The columns are considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a fixed polynomial a^-1*(x), given by
		Mathematical equations 5.9

		a^-1*x = {0b}*x^3 + {0d}*x^2 + {09}*x + {0e}

		Mathematical equations 5.10
		As described in Sec. 4.3, this can be written as a matrix multiplication.
		state'[x] = a^-1*x (*) state[x]

		As a result of this multiplication, the four bytes in a column are replaced by the following:

		state'[0][column] = ({0e} • state[0][column]) (+) ({0b} • state[1][column]) (+) ({0d} • state[2][column]) (+) ({09} • state[3][column])
		state'[1][column] = ({09} • state[0][column]) (+) ({0e} • state[1][column]) (+) ({0b} • state[2][column]) (+) ({0d} • state[3][column])
		state'[2][column] = ({0d} • state[0][column]) (+) ({09} • state[1][column]) (+) ({0e} • state[2][column]) (+) ({0b} • state[3][column])
		state'[3][column] = ({0b} • state[0][column]) (+) ({0d} • state[1][column]) (+) ({09} • state[2][column]) (+) ({0e} • state[3][column])

		InvMixColumns()是MixColumns()的逆向转换。
		InvMixColumns()对状态逐列操作，如第4.3节所述，将每一列作为一个四项式多项式处理。
		这些列被视为GF(2^8)上的多项式，并与固定的多项式a^-1*(x)相乘以x^4+1，给出如下
		数学方程式 5.9

		a^-1*x = {0b}*x^3 + {0d}*x^2 + {09}*x + {0e}

		数学方程式5.10
		如第4.3节所述，这可以写成一个矩阵乘法。
		state'[x] = a^-1*x (*) state[x]

		作为这个乘法的结果，一列中的四个字节被替换成以下内容:

		state'[0][column] = ({0e} • state[0][column]) (+) ({0b} • state[1][column]) (+) ({0d} • state[2][column]) (+) ({09} • state[3][column])
		state'[1][column] = ({09} • state[0][column]) (+) ({0e} • state[1][column]) (+) ({0b} • state[2][column]) (+) ({0d} • state[3][column])
		state'[2][column] = ({0d} • state[0][column]) (+) ({09} • state[1][column]) (+) ({0e} • state[2][column]) (+) ({0b} • state[3][column])
		state'[3][column] = ({0b} • state[0][column]) (+) ({0d} • state[1][column]) (+) ({09} • state[2][column]) (+) ({0e} • state[3][column])

	*/
	inline void InverseMixColumns(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		// AES_BLOCK_SIDE is 4
		#if 0

		std::deque<std::vector<std::uint8_t>> _stateByteDataBlock
		{
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0}
		};

		// matrix multiplication in GF(2^8)
		// * => galoisMul, + => ^

		for(std::uint32_t row = 0; row < 4; ++row)
		{
			for(std::uint32_t column = 0; column < 4; ++column)
			{
				_stateByteDataBlock.operator[](row).operator[](column) = 0x00;
				
				// Dot product of row (r) of the InverseMixColumns and the column (c) of the state
				// InverseMixColumns的r行与状态的c列的点积
				_stateByteDataBlock.operator[](row).operator[](column) ^= MultiplicationOfByteWithGaloisField(INVERSE_CMDS.operator[](row).operator[](column), stateByteDataBlock.operator[](row).operator[](column));
			}
		}

		stateByteDataBlock.swap(_stateByteDataBlock);

		_stateByteDataBlock.clear();

		#else

		std::uint8_t rowDatas[4], columnDatas[4];
		for (int column = 0; column < 4; ++column)
		{
			for (int row = 0; row < 4; ++row)
			{
				rowDatas[row] = stateByteDataBlock[row][column];
			}
			columnDatas[0] = MultiplicationOfByteWithGaloisField(0x0e, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[3]);
			columnDatas[1] = MultiplicationOfByteWithGaloisField(0x09, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[3]);
			columnDatas[2] = MultiplicationOfByteWithGaloisField(0x0d, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[3]);
			columnDatas[3] = MultiplicationOfByteWithGaloisField(0x0b, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[3]);
			for (int row = 0; row < 4; ++row)
			{
				stateByteDataBlock[row][column] = columnDatas[row];
			}
		}

		#endif
	}

	
	//Transformation in the Cipher that processes the State by cyclically shifting the last three rows of the State by different offsets.
	//密码中的转换，通过循环处理状态 将状态的最后三行按不同的偏移量进行移位。

	/*
		In the ShiftRows() transformation, the bytes in the last three rows of the State are cyclically shifted over different numbers of bytes (offsets).
		The first row, r = 0, is not shifted.
		Specifically, the ShiftRows() transformation proceeds as follows:
		
		Mathematical equations 5.3
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)

		where the shift value shift(row,Nb) depends on the row number, row, as follows (recall that Nb = 4):
		
		Mathematical equations 5.4
		shift(1,4) = 1;
		shift(2,4) = 2;
		shift(3,4) = 3;
			
		This has the effect of moving bytes to "lower" positions in the row (i.e., lower values of column in a given row),
		While the "lowest "bytes wrap around into the "top" of the row (i.e., higher values of column in a given row).

		在ShiftRows()转换中，State最后三行的字节在不同的字节数（偏移量）上被循环移位
		第一行，r = 0，不被移位。
		具体来说，ShiftRows()转换的过程如下。
			
		数学公式5.3
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)

		其中移位值shift(row,Nb)取决于行数row，如下所示（记得Nb=4）
		
		数学公式5.4
		shift(1,4) = 1;
		shift(2,4) = 2;
		shift(3,4) = 3。
		
		这样做的效果是将字节移到行中的 "较低 "位置（即在给定行中列的低值）
		而 "最低的 "字节则环绕到行的 "顶部"（即某一行中列的数值较高）
		
		The ShiftRows step operates on the rows of the state;
		It cyclically shifts the bytes in each row by a certain offset.
		In this way, each column of the output state of the ShiftRows step is composed of bytes from each column of the input state.
		The importance of this step is to avoid the columns being encrypted independently, in which case AES would degenerate into four independent block ciphers.

		ShiftRows步骤对状态的行进行操作。
		它循环地将每一行的字节按一定的偏移量移动。
		这样，ShiftRows步骤的输出状态的每一列都是由输入状态的每一列的字节组成。
		这一步的重要性在于避免各列被独立加密，在这种情况下，AES将退化为四个独立的块密码。
	*/
	inline void ShiftRows(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		std::size_t counter = 0;
		for (auto &row : stateByteDataBlock)
		{
			std::ranges::rotate(row.begin(), row.begin() + counter, row.end());
			++counter;
		}
	}

	/*
		This is the inverse of the ShiftRows() transformation.
		The bytes in the last three rows of the State are cyclically shifted over different numbers of bytes (offsets).
		The first row, r = 0, is not shifted.
		The bottom three rows are cyclically shifted by Nb - shift(r, Nb) bytes, where the shift value shift(r,Nb) depends on the row number, and is given in equation (5.4)
		(see Sec. 5.1.2).

		Specifically, the InvShiftRows() transformation proceeds as follows:
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)
		Conditions for variables: 0 < row < 4 and 0 <= column < Nb

		这是ShiftRows()转换的逆运算。
		最后三行的字节在不同的字节数（偏移量）上被循环移位。
		第一行，row = 0，不被移位。
		最下面的三行被循环移位Nb-shift(r,Nb)字节，其中shift(r,Nb)的值取决于行数，在公式(5.4)中给出
		(见第5.1.2节)。

		具体来说，InvShiftRows()转换的过程如下。
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)
		变量的条件：0 < row < 4 和 0 <= column < Nb
	*/
	inline void InverseShiftRows(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		std::size_t counter = 0;
		for (auto &row : stateByteDataBlock)
		{
			std::ranges::rotate(row.rbegin(), row.rbegin() + counter, row.rend());
			++counter;
		}
	}

	/*
		The SubBytes() transformation is a non-linear byte substitution that operates independently on each byte of the State using a substitution table (S-box).
		This S-box which is invertible, is constructed by composing two transformations:
		1. Take the multiplicative inverse in the finite field GF(2^8), described in Sec. 4.2;
		the element {00} is mapped to itself.
		2. Apply the following affine transformation (over GF(2) ):
		Mathematical equations 5.1
		bit[index] = bit[index] (+) bit[index + 4 mod 8] (+) bit[index + 5 mod 8] (+) bit[index + 6 mod 8] (+) bit[index + 7 mod 8] (+) c[index]

		for 0 <= index < 8 , where bit[index] is the index ^ the bit of the byte, and c[index] is the index ^ the bit of a byte c with the value {63} or {01100011}.
		Here and elsewhere, a prime on a variable (e.g., bit' ) indicates that the variable is to be updated with the value on the right.

		SubBytes()转换是一种非线性的字节替换，它使用一个替换表（S-box）对State的每个字节独立操作。
		这个S-box是可反转的，它是由两个转换组成的。
		1. 在有限域GF(2^8)中进行乘法逆运算，在第4.2节中描述。
		元素{00}被映射到它自己。
		2. 应用下面的仿射变换（在GF(2)上）。
		数学公式5.1
		bit[index] = bit[index] (+) bit[index + 4 mod 8] (+) bit[index + 5 mod 8] (+) bit[index + 6 mod 8] (+) bit[index + 7 mod 8] (+) c[index]
		for 0 <= index < 8 , 其中bit[index]是字节的index ^ the位，c[index]是字节c的index ^ the位，值为{63}或{01100011}。
		在这里和其他地方，变量上的素数（例如，bit'）表示该变量要用右边的值来更新。

		In the SubBytes step, each byte arrays[i][j] in the state array is replaced with a SubByte S-box[arrays[i][j]] using an 8-bit substitution box.
		Note that before round 0, the state array is simply the plaintext/input.
		This operation provides the non-linearity in the cipher.
		The S-box used is derived from the multiplicative inverse over GF(2^8), known to have good non-linearity properties.
		To avoid attacks based on simple algebraic properties, the S-box is constructed by combining the inverse function with an invertible affine transformation.
		The S-box is also chosen to avoid any fixed points (and so is a derangement), i.e., S-box[arrays[i][j]] != arrays[i][j] , and also any opposite fixed points, i.e., S-box[arrays[i][j]] (+) arrays[i][j] != FF16.
		While performing the decryption, the InvSubBytes step (the inverse of SubBytes) is used, which requires first taking the inverse of the affine transformation and then finding the multiplicative inverse.

		在SubBytes步骤中，状态数组中的每个字节arrays[i][j]被替换为SubByte S-box[arrays[i][j]]，使用一个8位替换框。
		注意，在第0轮之前，状态数组只是明文/输入。
		这个操作提供了密码中的非线性。
		所用的S-box是由GF(2^8)上的乘法逆推而来，已知其具有良好的非线性特性。
		为了避免基于简单代数特性的攻击，S-box是通过将反函数与可反转的仿射变换相结合而构建的。
		S-box的选择也是为了避免任何固定点（因此是一个脱轨），即S-box[arrays[i][j]] != arrays[i][j] ，以及任何相反的固定点，即S-box[ arrays[i][j] ] (+) arrays[i][j] != FF16。
		在进行解密时，使用了InvSubBytes步骤（SubBytes的逆），这需要先取仿射变换的逆，然后找到乘法的逆。
	*/

	//在密钥扩展例程中使用的函数，它接收一个四字节的输入字，并对四个字节中的每个字节应用一个S-box，以产生一个输出字。
	//Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word.
	inline void SubtituteBytes(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		//
		//Row is 0x?0
		//Column is 0x0?
		//Example: 0x00 <-> 0x63
		//1. Search Forward_S_Box, the row is 0 and the column is 0, then find the data 0x63
		//2. Search Backward_S_Box, the row is 6 and the column is 3, then find the data 0x00
		//
		//例子：0x00 <-> 0x63
		//1.搜索Forward_S_Box，行是0和列是0，然后找到数据0x63
		//2.搜索Backward_S_Box，行是6和列是3，然后找到数据0x00
		constexpr std::array<std::array<std::uint8_t, 16>, 16> Forward_S_Box
		{
			{
				{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
				{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
				{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
				{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
				{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
				{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
				{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
				{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
				{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
				{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
				{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
				{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
				{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
				{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
				{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
				{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
			},
		};

		for(auto& row : stateByteDataBlock)
		{
			std::ranges::transform
			(
				row.begin(),
				row.end(),
				row.begin(),
				[&Forward_S_Box](const std::uint8_t &byte) -> std::uint8_t
				{
					return Forward_S_Box[byte / 16][byte % 16];
				}
			);
		}
	}

	/*
		InvSubBytes() is the inverse of the byte substitution transformation, in which the inverse S-box is applied to each byte of the State.
		This is obtained by applying the inverse of the affine transformation (5.1) followed by taking the multiplicative inverse in GF(2^8).

		InvSubBytes()是字节替换变换的逆运算，其中逆S-box被应用于状态的每个字节。
		这是由应用仿射变换的逆（5.1），然后在GF(2^8)中取乘法逆得到的。
	*/
	inline void InverseSubtituteBytes(std::array<std::array<std::uint8_t, 4>, 4>& stateByteDataBlock)
	{
		//
		//Row is 0x?0
		//Column is 0x0?
		//Example: 0x00 <-> 0x52
		//1. Search Forward_S_Box, the row is 0 and the column is 0, then find the data 0x52
		//2. Search Backward_S_Box, the row is 5 and the column is 2, then find the data 0x00
		//
		//例子：0x00 <-> 0x52
		//1.搜索Forward_S_Box，行是0和列是0，然后找到数据0x52
		//2.搜索Backward_S_Box，行是5和列是2，然后找到数据0x00
		constexpr std::array<std::array<std::uint8_t, 16>, 16> Backward_S_Box
		{
			{
				{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
				{0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
				{0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
				{0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
				{0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
				{0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
				{0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
				{0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
				{0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
				{0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
				{0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
				{0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
				{0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
				{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
				{0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
				{0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
			},
		};

		for(auto& row : stateByteDataBlock)
		{
			std::ranges::transform
			(
				row.begin(),
				row.end(),
				row.begin(),
				[&Backward_S_Box](const std::uint8_t &byte) -> std::uint8_t
				{
					return Backward_S_Box[byte / 16][byte % 16];
				}
			);
		}
	}

	/*
		In the AddRoundKey step, the subkey is combined with the state.
		For each round, a subkey is derived from the main key using Rijndael's key schedule; each subkey is the same size as the state.
		The subkey is added by combining each byte of the state with the corresponding byte of the subkey using bitwise (+).

		在AddRoundKey步骤中，子密钥与状态相结合。
		对于每一轮，使用Rijndael的密钥计划从主密钥中导出一个子密钥；每个子密钥的大小与状态相同。
		子密钥的添加是通过将状态的每个字节与子密钥的相应字节用位法（+）结合起来。

		Transformation in the Cipher and Inverse Cipher in which a Round Key is added to the State using an XOR operation.
		The length of a Round Key equals the size of the State data block (i.e., for Nb = 4, the Round Key length equals 128 bits/16 bytes).

		在密码器和反密码器中的转换，其中一个轮密钥是使用XOR操作添加到状态数据中
		轮密钥的长度等于状态数据块的大小（例如，对于Nb=4，轮密钥的长度等于128比特/16字节）
	*/
	inline void AddRoundKey(std::array<std::array<std::uint8_t, 4>, 4>& blockByteState, const std::vector<std::uint8_t>::const_iterator blockKeyIterator)
	{
		// AES_BLOCK_SIDE is 4
		// Add in GF(2^8) corresponding bytes of the subkey and state
		for(std::size_t row = 0; row < 4; ++row)
		{
			for(std::size_t column = 0; column < 4; ++column)
			{
				blockByteState.operator[](row).operator[](column) = blockByteState.operator[](row).operator[](column) ^ blockKeyIterator.operator[](row + 4 * column);
			}
		}
	}
	
	/*
		Description of the Cryptographs(密码器的说明):

			AES is based on a design principle known as a substitution–permutation network, and is efficient in both software and hardware.
			Unlike its predecessor DES, AES does not use a Feistel network. AES is a variant of Rijndael, with a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
			By contrast, Rijndael per se is specified with block and key sizes that may be any multiple of 32 bits, with a minimum of 128 and a maximum of 256 bits.

			AES是基于一种被称为替换-互斥网络的设计原理，在软件和硬件上都很高效。 
			与其前身DES不同，AES不使用Feistel网络。
			AES是Rijndael的一个变种，其固定块大小为128比特，密钥大小为128、192或256比特。
			相比之下，Rijndael本身规定的块和密钥大小可以是32位的任何倍数，最小为128位，最大为256位。

			AES operates on a 4 × 4 column-major order array of bytes, termed the state.
			Most AES calculations are done in a particular finite field.
			AES在一个4×4列主序的字节数组上操作，称为状态。
			大多数AES的计算是在一个特定的有限域中进行的。
			For instance, 16 bytes, {byte0,byte1,......,btye15} are represented as this two-dimensional array:
			例如，16个字节，{byte0,byte1,......,btye15}被表示为这个二维阵列。
		
			(Byte data has been represented in hexadecimal 字节数据已用16进制表示)
			Byte two_dimensional_array
			{
				{0x00, 0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06, 0x07},
				{0x08, 0x09, 0x0F, 0x10},
				{0x11, 0x12, 0x13, 0x14},
			}

			The key size used for an AES cipher specifies the number of transformation rounds that convert the input, called the plaintext, into the final output, called the ciphertext. 
			The number of rounds are as follows:
			10 rounds for 128-bit keys.
			12 rounds for 192-bit keys.
			14 rounds for 256-bit keys.

			用于AES密码的密钥大小规定了将输入（称为明文）转换成最终输出（称为密文）的转换轮数。 
			轮数如下。
			128位密钥为10轮。
			192位密钥的12轮。
			256位密钥的14轮。

		Paper: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

		High-level description of the algorithm(密码器算法的高级说明):

			1.Key Expansion (密钥的扩展):
			Round keys are derived from the cipher key using the AES key schedule.
			AES requires a separate 128-bit round key block for each round plus one more.
			每一轮的子密钥都是使用AES的密钥计划从主密码密钥衍生出来的
			AES要求每一轮都有一个单独的128位比特的每轮密钥块，再加一个。

			2.Initial(1) round key addition (添加首轮密钥):

				2-1.AddRoundKey:
				Each byte of the state is combined with a byte of the round key using bitwise exclusive-OR operation.
				状态的每一个字节都与圆周率密钥的一个字节用按比特单位的异或运算结合起来。

			3.9,11 or 13 rounds (9、11或13轮):

				3-1.SubBytes:
				A non-linear substitution step where each byte is replaced with another according to a lookup table.
				一个非线性替换步骤，每个字节根据一个查找表被替换成另一个字节。

				3-2 ShiftRows:
				A transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
				转位步骤，状态的最后三行被循环地移位一定的步数。

				3-3: MixColumns:
				A linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
				一个线性混合操作，对状态的列进行操作，将每一列中的四个字节合并。

				3-4: 
					Execute 2-1 operation
					执行2-1 操作
			4.Final round (making 10, 12 or 14 rounds in total) 最后一轮（总共有10轮、12轮或14轮）:
				4-1: 
					Execute 3-1 operation
					执行3-1 操作
				4-2: 
					Execute 3-2 operation
					执行3-2 操作
				4-3: 
					Execute 2-1 operation
					执行2-1 操作
	*/
	
	template<AES_SecurityLevel SecurityLevel>
	class ExperimentalAlgorithm
	{

	private:

		template <AES_SecurityLevel>
		friend class DataWorker;

		static constexpr std::size_t ONE_WORD_BYTE_SIZE = sizeof(std::uint32_t);
		
		//The number of 32-bit words comprising the plaintext and columns comprising the state matrix of an AES cipher.
		//Paper content: Number of columns (32-bit words) comprising the State. For this standard, Nb = 4. (Also see Sec. 6.3.)
		//Nb is block word size
		static constexpr std::size_t NUMBER_DATA_BLOCK_COUNT = 4;
		
		static constexpr auto AES_CONFIG_INFORMATION = AES::AES_SecurityLevelInforamtion<SecurityLevel>();

		static constexpr std::size_t Number_Key_Data_Block_Size = AES_CONFIG_INFORMATION[0];

		static constexpr std::size_t Number_Execute_Round_Count = AES_CONFIG_INFORMATION[1];
		
		static constexpr std::uint8_t Number_Block_Data_Byte_Size = ONE_WORD_BYTE_SIZE * NUMBER_DATA_BLOCK_COUNT * sizeof(std::uint8_t);
		
		std::vector<std::uint8_t> EncryptBlockData(const std::vector<std::uint8_t>& byteData, const std::vector<std::uint8_t>& expandedByteRoundKeyBlock)
		{
			if(byteData.size() == GetBlockSize_DataByte() && expandedByteRoundKeyBlock.size() == GetBlockSize_ExpandedKeyByte())
			{
				std::vector<std::uint8_t> encryptedByteDataBlock(byteData.size());
				
				std::array<std::array<std::uint8_t, 4>, 4> currentStateBlock
				{
					{
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 }
					},
				};
				
				std::uint32_t row = 0, column = 0;
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						stateBlockContent.operator[](column) = byteData.operator[](row + 4 * column);
					}
					++row;
				}
				row = 0, column = 0;
				
				// ROUND: 0
				AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin());
				
				// ROUNDS: 1 ~ NRound-1
				for (std::uint32_t round = 1; round <= this->Number_Execute_Round_Count - 1; ++round)
				{
					SubtituteBytes(currentStateBlock);
					ShiftRows(currentStateBlock);
					MixColumns(currentStateBlock);
					
					AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin() + round * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				}
				
				// ROUND: NRound
				SubtituteBytes(currentStateBlock);
				ShiftRows(currentStateBlock);
				
				AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin() + this->Number_Execute_Round_Count * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						encryptedByteDataBlock.operator[](row + 4 * column) = stateBlockContent.operator[](column);
					}
					++row;
				}
				row = 0, column = 0;
				
				return encryptedByteDataBlock;
			}
			else
			{
				throw std::length_error("");
			}
		}

		std::vector<std::uint8_t> DecryptBlockData(const std::vector<std::uint8_t>& byteData, const std::vector<std::uint8_t>& expandedByteRoundKeyBlock)
		{
			if(byteData.size() == GetBlockSize_DataByte() && expandedByteRoundKeyBlock.size() == GetBlockSize_ExpandedKeyByte())
			{
				std::vector<std::uint8_t> decryptedByteDataBlock(byteData.size());
				
				std::array<std::array<std::uint8_t, 4>, 4> currentStateBlock
				{
					{
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 }
					},
				};
				
				std::uint32_t row = 0, column = 0;
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						stateBlockContent.operator[](column) = byteData.operator[](row + 4 * column);
					}
					++row;
				}
				row = 0, column = 0;
				
				// INVERSE ROUND: NRound
				AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin() + this->Number_Execute_Round_Count * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				
				// INVERSE ROUNDS: NRound-1 ~ 1
				for (std::uint32_t round = this->Number_Execute_Round_Count - 1; round >= 1; --round)
				{
					InverseSubtituteBytes(currentStateBlock);
					InverseShiftRows(currentStateBlock);
					
					AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin() + round * 4 * this->NUMBER_DATA_BLOCK_COUNT);
					
					InverseMixColumns(currentStateBlock);
				}
				
				// INVERSE ROUND: 0
				InverseSubtituteBytes(currentStateBlock);
				InverseShiftRows(currentStateBlock);
				
				AddRoundKey(currentStateBlock, expandedByteRoundKeyBlock.begin());
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						decryptedByteDataBlock.operator[](row + 4 * column) = stateBlockContent.operator[](column);
					}
					++row;
				}
				row = 0, column = 0;
				
				return decryptedByteDataBlock;
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			KEY SCHEDULING
			https://en.wikipedia.org/wiki/AES_key_schedule
			https://autonome-antifa.org/IMG/pdf/Rijndael.pdf
		*/
		void KeySchedule(const std::vector<std::uint8_t>& byteKeys, std::vector<std::vector<std::uint8_t>>& expandedRoundKeys)
		{
			//Key schedule round : The size of the key schedule depends on the number of rounds
			constexpr std::uint32_t KeyScheduleRound = this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
			
			expandedRoundKeys.resize( byteKeys.size() / (this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size), std::vector<std::uint8_t>{});
			for(std::size_t blockIndex = 0; blockIndex < expandedRoundKeys.size(); ++blockIndex)
			{
				expandedRoundKeys[blockIndex].resize(this->ONE_WORD_BYTE_SIZE * KeyScheduleRound);

				for(std::uint32_t index = 0; index < this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size; ++index)
				{
					expandedRoundKeys[blockIndex][index] = byteKeys[index];
				}
			}
			
			using ByteArray4 = std::array<std::uint8_t, 4>;
			
			ByteArray4 temporaryWord { 0, 0, 0, 0 };
			//Round constants
			ByteArray4 RCON_Word_Data { 0, 0, 0, 0 };
			
			// 同余式
			// congruent exprssion
			// a ≡ b (mod m)
			
			// Definition of congruence theorem
			// An important concept in number theory.
			// Given a positive integer c
			// Two integers a and b are said to be congruent to mod c if they satisfy that a-b is divisible by m, i.e., (a-b)/c yields an integer.
			// congruence of modulo c is an equivalence of integers
			
			// 同余定理的定义
			// 数论中的重要概念。
			// 给定一个正整数c
			// 如果两个整数a和b满足a-b能够被m整除，即(a-b)/c得到一个整数，那么就称整数a与b对模c同余。
			// 对模c同余是整数的一个等价关系
			
			//N是论文内容中的变量Nk（KeyWordSize）。
			//N is the variable Nk (KeyWordSize) from the paper content.
			
			//Index_Round是密钥安排轮次的索引
			//Index_Round is the index of the key schedule round
			
			for(std::size_t blockIndex = 0; blockIndex < expandedRoundKeys.size(); ++blockIndex)
			{
				for(std::size_t roundIndex = this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size; roundIndex < this->ONE_WORD_BYTE_SIZE * KeyScheduleRound; roundIndex += 4)
				{
					temporaryWord[0] = expandedRoundKeys[blockIndex][roundIndex - sizeof(std::uint32_t) + 0];
					temporaryWord[1] = expandedRoundKeys[blockIndex][roundIndex - sizeof(std::uint32_t) + 1];
					temporaryWord[2] = expandedRoundKeys[blockIndex][roundIndex - sizeof(std::uint32_t) + 2];
					temporaryWord[3] = expandedRoundKeys[blockIndex][roundIndex - sizeof(std::uint32_t) + 3];
				
					//Condition 1: N ≤ 6
					//Code: this->NKeyWordSize <= 6
					//Condition 2: index ≡ 0 ( modulo N )
					//Condition 1 And Condition 2
					//Code: roundIndex % this->NKeyWordSize == 0
					if(roundIndex / 4 % this->Number_Key_Data_Block_Size == 0)
					{
						KeyWordAES_LeftRotate(temporaryWord);
						KeyWordAES_Subtitute(temporaryWord);
						RCON(RCON_Word_Data, roundIndex / (this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size));
					
						ByteArray4 temporaryWord2 { 0, 0, 0, 0 };
					
						for (int indexByte = 0; indexByte < 4; ++indexByte)
						{
							temporaryWord2[indexByte] = temporaryWord[indexByte] ^ RCON_Word_Data[indexByte];
						}
					
						temporaryWord = temporaryWord2;
					}
				
					//Condition 1: N ＞ 6
					//Code: this->NKeyWordSize > 6
					//Condition 2: index ≡ 4 ( modulo N )
					//Condition 1 Or Condition 2
					//Code: ((roundIndex - 4) % this->NKeyWordSize) == 0
					else if(this->Number_Key_Data_Block_Size > 6 && roundIndex / 4 % this->Number_Key_Data_Block_Size == 4)
					{
						KeyWordAES_Subtitute(temporaryWord);
					}
				
					expandedRoundKeys[blockIndex][roundIndex + 0] = expandedRoundKeys[blockIndex][roundIndex + 0 - sizeof(std::uint32_t) * this->Number_Key_Data_Block_Size] ^ temporaryWord[0];
					expandedRoundKeys[blockIndex][roundIndex + 1] = expandedRoundKeys[blockIndex][roundIndex + 1 - sizeof(std::uint32_t) * this->Number_Key_Data_Block_Size] ^ temporaryWord[1];
					expandedRoundKeys[blockIndex][roundIndex + 2] = expandedRoundKeys[blockIndex][roundIndex + 2 - sizeof(std::uint32_t) * this->Number_Key_Data_Block_Size] ^ temporaryWord[2];
					expandedRoundKeys[blockIndex][roundIndex + 3] = expandedRoundKeys[blockIndex][roundIndex + 3 - sizeof(std::uint32_t) * this->Number_Key_Data_Block_Size] ^ temporaryWord[3];
				}
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(temporaryWord.data(), temporaryWord.size());
			my_cpp2020_assert(CheckPointer == temporaryWord.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(RCON_Word_Data.data(), RCON_Word_Data.size());
			my_cpp2020_assert(CheckPointer == RCON_Word_Data.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		constexpr std::uint8_t GetBlockSize_DataByte() const
		{
			return this->Number_Block_Data_Byte_Size;
		}

		constexpr std::size_t GetBlockSize_KeyByte() const
		{
			return this->Number_Key_Data_Block_Size * this->ONE_WORD_BYTE_SIZE;
		}

		constexpr std::size_t GetBlockSize_ExpandedKeyByte()
		{
			return this->ONE_WORD_BYTE_SIZE * this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
		}
	};
}