#pragma once

namespace CommonSecurity::Twofish::DefineConstants
{
	//Constants and variables

	/*
		how many rounds of encryption/decryption (number 16/24/32 of rounds for 128/192/256-bit keys, default round is 16)
	*/
	inline constexpr std::uint32_t Constant_MinCipherRounds = 16U;
	inline constexpr std::uint32_t Constant_MaxCipherRounds = 32U;

	inline constexpr std::uint32_t Constant_MinKeySize = 128U; // minimum number of bits of each key data block
	inline constexpr std::uint32_t Constant_MaxKeySize = 256U; // maximum number of bits of each key data block

	inline constexpr std::uint32_t Constant_DataBlockSize = 128U; // how many bits for each data block (128)
	inline constexpr std::uint32_t Constant_StepKeyBit = (Constant_MaxKeySize - Constant_DataBlockSize) / 2U;

	//Constants and variables - Subkey array indices

	inline constexpr std::uint32_t Constant_InputWhitenIndex = 0;
	inline constexpr std::uint32_t Constant_OutputWhitenIndex = Constant_InputWhitenIndex + Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits;
	inline constexpr std::uint32_t Constant_SubkeyRounds = Constant_OutputWhitenIndex + Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits;
	inline constexpr std::uint32_t Constant_TotalSubkeys = Constant_SubkeyRounds + 2 * Constant_MaxCipherRounds;

	//Constants and variables - Subkey array operation

	inline constexpr std::uint32_t Constant_SubkeysStep = 0x02020202U; //a fixed constant used to generate even subkeys
	inline constexpr std::uint32_t Constant_SubkeysBump = 0x01010101U; //a fixed constant used to generate odd subkeys
	inline constexpr std::uint32_t Constant_SubkeyRotateLeft = 9U; //fixed number determining bit shift in keys generator

	//Fixed 8x8 permutation substitution box
	inline constexpr std::array<std::array<std::uint8_t, 256>, 2> PSB_Matrix_Fixed
	{{
		{{
			0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
			0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
			0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
			0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
			0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
			0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
			0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
			0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
			0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
			0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
			0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
			0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
			0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
			0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
			0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
			0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
			0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
			0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
			0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
			0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
			0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
			0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
			0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
			0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
			0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
			0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
			0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
			0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
			0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
			0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
			0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
			0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
		}},
		{{
			0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
			0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
			0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
			0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
			0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
			0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
			0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
			0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
			0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
			0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
			0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
			0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
			0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
			0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
			0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
			0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
			0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
			0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
			0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
			0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
			0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
			0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
			0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
			0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
			0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
			0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
			0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
			0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
			0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
			0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
			0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
			0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
		}}
	}};

	//Primitive polynomial for Galois finite field(256) using Maximum disatance separable matrix (0x169)
	inline constexpr std::uint32_t BinaryFeedbackFormulaA = (1U << 8) ^ (1U << 6) ^ (1U << 5) ^ (1U << 3) ^ 1;

	//Primitive polynomial for Galois finite field(256) generator using Reed-Solomon code (0x14D)
	inline constexpr std::uint32_t BinaryFeedbackFormulaB = (1U << 8) ^ (1U << 6) ^ (1U << 3) ^ (1U << 2) ^ 1;

	//Linear feedback shift register 1 bit
	//@param value input bit which is a linear function of its previous state
	//@return output stream from shift register used in pseudo-random generators
	inline constexpr std::uint32_t LFSR_1Bit(std::uint32_t value)
	{
		return (value >> 1U)
		^ ( (value & 1U) ? BinaryFeedbackFormulaA / 2 : 0U );
	}

	//Linear feedback shift register 2 bit
	//@param value input bit which is a linear function of its previous state
	//@return output stream from shift register used in pseudo-random generators
	inline constexpr std::uint32_t LFSR_2Bit(std::uint32_t value)
	{
		return (value >> 2U)
		^ ( (value & 2U) ? BinaryFeedbackFormulaA / 2 : 0U )
		^ ( (value & 1U) ? BinaryFeedbackFormulaA / 4 : 0U );
	}

	//Value Exclusive-Or With Linear feedback shift register 2 bit
	//@param value input for Exclusive-Or operation
	//@return output value Exclusive-Or-ed with linear feedback shift register
	inline constexpr std::uint32_t MixFunctionX(std::uint32_t value)
	{
		//0x5B
		return value ^ LFSR_2Bit(value);
	}

	//Value Exclusive-Or With Linear feedback shift register 1 bit and 2 bit
	//@param value input for Exclusive-Or operation
	//@return output value Exclusive-Or-ed with linear feedback shift register
	inline constexpr std::uint32_t MixFunctionY(std::uint32_t value)
	{
		//0xEF
		return value ^ LFSR_1Bit(value) ^ LFSR_2Bit(value);
	}

	/*
		Define the fixed p0/p1 permutations used in keyed S-box lookup.  
		By changing the following constant definitions for P_ij,
		the S-boxes will automatically get changed in all the Twofish source code.
		Note that P_i0 is the "outermost" 8x8 permutation applied. 
		See the f32() function : ProcessFunction32Bit, to see how these constants are to be used.
	*/

	inline constexpr std::uint8_t PermuteIndex_00 = 1U; /* "outermost" permutation */
	inline constexpr std::uint8_t PermuteIndex_01 = 0U; 
	inline constexpr std::uint8_t PermuteIndex_02 = 0U;
	inline constexpr std::uint8_t PermuteIndex_03 = PermuteIndex_01 ^ 1U;
	inline constexpr std::uint8_t PermuteIndex_04 = 1U;

	inline constexpr std::uint8_t PermuteIndex_10 = 0U;
	inline constexpr std::uint8_t PermuteIndex_11 = 0U;
	inline constexpr std::uint8_t PermuteIndex_12 = 1U;
	inline constexpr std::uint8_t PermuteIndex_13 = PermuteIndex_11 ^ 1U;
	inline constexpr std::uint8_t PermuteIndex_14 = 0U;

	inline constexpr std::uint8_t PermuteIndex_20 = 1U;
	inline constexpr std::uint8_t PermuteIndex_21 = 1U;
	inline constexpr std::uint8_t PermuteIndex_22 = 0U;
	inline constexpr std::uint8_t PermuteIndex_23 = PermuteIndex_21 ^ 1U;
	inline constexpr std::uint8_t PermuteIndex_24 = 0U;

	inline constexpr std::uint8_t PermuteIndex_30 = 0U;
	inline constexpr std::uint8_t PermuteIndex_31 = 1U;
	inline constexpr std::uint8_t PermuteIndex_32 = 1U;
	inline constexpr std::uint8_t PermuteIndex_33 = PermuteIndex_31 ^ 1U;
	inline constexpr std::uint8_t PermuteIndex_34 = 1U;

	inline constexpr std::array<std::array<std::uint32_t, 256>, 4>
	CompilerGeneration_MDS_Matrix()
	{
		std::array<std::array<std::uint32_t, 256>, 4> MDS {};

		std::array<std::uint8_t, 2> TemporaryVector {0, 0};
		std::array<std::uint8_t, 2> TemporaryVectorX {0, 0};
		std::array<std::uint8_t, 2> TemporaryVectorY {0, 0};
		
		for(std::uint32_t round = 0; round < 256; round++)
		{
			TemporaryVector[0] = PSB_Matrix_Fixed[0][round];
			TemporaryVectorX[0] = static_cast<std::uint8_t>( MixFunctionX(TemporaryVector[0]) & 255U );
			TemporaryVectorY[0] = static_cast<std::uint8_t>( MixFunctionY(TemporaryVector[0]) & 255U );

			TemporaryVector[1] = PSB_Matrix_Fixed[1][round];
			TemporaryVectorX[1] = static_cast<std::uint8_t>( MixFunctionX(TemporaryVector[1]) & 255U );
			TemporaryVectorY[1] = static_cast<std::uint8_t>( MixFunctionY(TemporaryVector[1]) & 255U );

			//PERMUTE_INDEX_00 = 1U
			MDS[0][round] = static_cast<std::uint32_t>( TemporaryVector[PermuteIndex_00] )
			| static_cast<std::uint32_t>( TemporaryVectorX[PermuteIndex_00] ) << 8U
			| static_cast<std::uint32_t>( TemporaryVectorY[PermuteIndex_00] ) << 16U
			| static_cast<std::uint32_t>( TemporaryVectorY[PermuteIndex_00] ) << 24U;

			//PERMUTE_INDEX_10 = 0U
			MDS[1][round] = static_cast<std::uint32_t>( TemporaryVectorY[PermuteIndex_10] )
			| static_cast<std::uint32_t>( TemporaryVectorY[PermuteIndex_10] ) << 8U
			| static_cast<std::uint32_t>( TemporaryVectorX[PermuteIndex_10] ) << 16U
			| static_cast<std::uint32_t>( TemporaryVector[PermuteIndex_10] ) << 24U;

			//PERMUTE_INDEX_20 = 1U
			MDS[2][round] = static_cast<std::uint32_t>( TemporaryVectorX[PermuteIndex_20] )
			| static_cast<std::uint32_t>( TemporaryVectorY[PermuteIndex_20] ) << 8U
			| static_cast<std::uint32_t>( TemporaryVector[PermuteIndex_20] ) << 16U
			| static_cast<std::uint32_t>( TemporaryVectorY[PermuteIndex_20] ) << 24U;

			//PERMUTE_INDEX_30 = 0U
			MDS[3][round] = static_cast<std::uint32_t>( TemporaryVectorX[PermuteIndex_30] )
			| static_cast<std::uint32_t>( TemporaryVector[PermuteIndex_30] ) << 8U
			| static_cast<std::uint32_t>( TemporaryVectorY[PermuteIndex_30] ) << 16U
			| static_cast<std::uint32_t>( TemporaryVectorX[PermuteIndex_30] ) << 24U;
		}

		TemporaryVector[0] = 0U;
		TemporaryVector[1] = 0U;
		TemporaryVectorX[0] = 0U;
		TemporaryVectorX[1] = 0U;
		TemporaryVectorY[0] = 0U;
		TemporaryVectorY[1] = 0U;

		return MDS;
	}

	static constexpr auto MAXIMUM_DISATANCE_SEPARABLE_MATRIX = CompilerGeneration_MDS_Matrix();
}

/*
	https://en.wikipedia.org/wiki/Twofish
	
	Reference code:
	https://github.dev/mycielski/twofish-in-java
	https://github.dev/Incr3dible/Twofish/blob/master/src/Twofish/DWord.cs
	https://github.dev/Incr3dible/Twofish/blob/master/src/Twofish/TwofishImplementation.cs
	https://www.schneier.com/
*/
namespace CommonSecurity::Twofish
{
	#if __cplusplus >= 202002L
	
	#define	TWOFISH_BIT_ROTATE_LEFT(word, n) ( std::rotl(word, n) )
	#define	TWOFISH_BIT_ROTATE_RIGHT(word, n) ( std::rotr(word, n) )

	#elif __cplusplus >= 201103L

	#define	TWOFISH_BIT_ROTATE_LEFT(word, n) ( CommonSecurity::Binary_LeftRotateMove(word, n) )
	#define	TWOFISH_BIT_ROTATE_RIGHT(word, n) ( CommonSecurity::Binary_RightRotateMove(word, n) )

	#else

	#define TWOFISH_BIT_ROTATE_LEFT(word, n) ( ( ( word ) << ( ( n ) & 0x1F ) ) | ( ( word ) >> ( 32 - ( ( n ) & 0x1F ) ) ) )
	#define TWOFISH_BIT_ROTATE_RIGHT(word, n) ( ( ( word ) >> ( ( n ) & 0x1F ) ) | ( ( word ) << ( 32 - ( ( n ) & 0x1F ) ) ) )

	#endif

	#if __cplusplus >= 202002L

	inline constexpr bool CHECK_IS_BIG_ENDIAN_ORDER = std::endian::native == std::endian::big;

		#if CHECK_IS_BIG_ENDIAN_ORDER == false
			#define		TWOFISH_IS_LITTLE_ENDIAN_MACHINES true
		#else
			#define		TWOFISH_IS_LITTLE_ENDIAN_MACHINES false
		#endif

	#else

		#ifndef _M_IX86
			#ifdef	__BORLANDC__
			#define	_M_IX86	300		/* make sure this is defined for Intel CPUs */
			#endif
		#endif

		#if defined(__i386__) || defined(_M_IX86) || defined(_M_IX64)
			#define		TWOFISH_IS_LITTLE_ENDIAN_MACHINES true /* e.g., 1 for Pentium, 0 for 68K */
			#define		TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32	0 /* need dword alignment? (no for Pentium) */
		#else	/* non-Intel platforms */
			#define		TWOFISH_IS_LITTLE_ENDIAN_MACHINES false /* (assume big-endian machines) */
			#define		TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32	1 /* (assume need alignment for non-Intel) */
		#endif

	#endif

	#if TWOFISH_IS_LITTLE_ENDIAN_MACHINES
		#define		TWOFISH_BYTE_SWAP(word) (word) /* NOP for little-endian machines */
		#define		TWOFISH_ADDRESS_XOR 0 /* NOP for little-endian machines */
	#else
		#define		TWOFISH_BYTE_SWAP(word) ((TWOFISH_BIT_ROTATE_RIGHT(word, 8) & 0xFF00FF00) | (TWOFISH_BIT_ROTATE_LEFT(word, 8) & 0x00FF00FF))
		#define		TWOFISH_ADDRESS_XOR 3 /* convert byte address in dword */
	#endif
	
	/* nonzero --> use Feistel version (slow) */
	#define TWOFISH_FEISTEL_DESIGN_ARCHITECTURE_VERSION 0

	/*
		Reference code:
		https://github.com/Steppenwolfe65/CEX-NET/blob/master/CEX%20Library/Test/Tests/BCiphers/TwofishEngine.cs
	*/
	class OfficialAlgorithm
	{
		/*
			Key Instance
		*/

	private:

		/* Actual key bits, in dwords */
		std::array<std::uint32_t, DefineConstants::Constant_MaxKeySize / std::numeric_limits<std::uint32_t>::digits> CipherKey32Bit {};

		/* Key bits used for S-boxes */
		std::array<std::uint32_t, DefineConstants::Constant_MaxKeySize / std::numeric_limits<std::uint64_t>::digits> SubstituteBoxKeys {};

		/* Key-dependent byte substitution box */
		std::array<std::uint32_t, 4 * DefineConstants::Constant_MaxKeySize> SubstituteBox {};

		/* Round subkeys, input/output whitening bits */
		std::array<std::uint32_t, DefineConstants::Constant_TotalSubkeys> SubKeys {};

	public:

		/* number of rounds in cipher */
		std::int32_t NumberRounds = 0U;

		static constexpr auto& MDS0 = DefineConstants::MAXIMUM_DISATANCE_SEPARABLE_MATRIX[0];
		static constexpr auto& MDS1 = DefineConstants::MAXIMUM_DISATANCE_SEPARABLE_MATRIX[1];
		static constexpr auto& MDS2 = DefineConstants::MAXIMUM_DISATANCE_SEPARABLE_MATRIX[2];
		static constexpr auto& MDS3 = DefineConstants::MAXIMUM_DISATANCE_SEPARABLE_MATRIX[3];

		/*
		+*****************************************************************************
		*
		* Function Name:	ReedSolomon (Encode)
		*
		* Function:			Use (12,8) Reed-Solomon code over GF(256) to produce a key S-box dword from two key material dwords.
		*
		* Arguments:		key0	=	1st dword
		*					key1	=	2nd dword
		*
		* Return:			Remainder polynomial generated using RS code
		*
		* Notes:
		*	Since this computation is done only once per reKey per 64 bits of key,
		*	the performance impact of this routine is imperceptible.
		*	The RS code chosen has "simple" coefficients to allow smartcard/hardware implementation without lookup tables.
		*
		+***************************************************************************
		*/
		static std::uint32_t ReedSolomon(std::uint32_t key_data0, std::uint32_t key_data1)
		{
			using DefineConstants::BinaryFeedbackFormulaB;
			
			std::uint32_t result_word_data = 0;

			for (std::uint8_t i=0; i<2; i++)
			{
				/* Merge in 32 more key bits */
				result_word_data ^= (i) ? key_data1 : key_data0;

				/* Shift one byte at a time */
				for (std::uint8_t j=0; j<4; j++)
				{
					//Reed-Solomon_rem
					//G(x) = x^4 + (a+1/a)x^3 + ax^2 + (a+1/a)x + 1
					//a = primitive root of field generator 0x14D
					std::uint8_t current_byte = std::uint8_t(result_word_data >> 24);
					std::uint32_t g2 = (std::uint32_t(current_byte << 1) ^ (std::uint32_t(current_byte & 0x80) ? BinaryFeedbackFormulaB : 0 )) & 0xFF;		
					std::uint32_t g3 = (std::uint32_t(current_byte >> 1) & 0x7F) ^ (std::uint32_t(current_byte & 1) ? BinaryFeedbackFormulaB >> 1 : 0 ) ^ g2 ;
					result_word_data = (result_word_data << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ std::uint32_t(current_byte);
				}
			}
			return result_word_data;
		}

		/*
		+*****************************************************************************
		*
		* Function Name:	f32
		*
		* Function:			Run four bytes through keyed S-boxes and apply MDS matrix
		*
		* Arguments:		data = input to f function
		*					key_32_bit_data	= pointer to key dwords
		*					key_bit_size = total key length (key_32_bit_data --> key_bit_size / 2 bits)
		*
		* Return:			The output of the keyed permutation applied to x.
		*
		* Notes:
		*   This function is a keyed 32-bit permutation.
		*   It is the major building block for the Twofish round function,
		*   including the four keyed 8x8 permutations and the 4x4 MDS matrix multiply.
		*   This function is used both for generating round subkeys and within the round function on the block being encrypted.  
		*
		*	This version is fairly slow and pedagogical,
		*   although a smartcard would probably perform the operation exactly this way in firmware.
		*   For ultimate performance, the entire operation can be completed with four lookups into four 256x32-bit tables, with three dword xors.
		*
		*	The MDS matrix is defined in CommonSecurity::Twofish::DefineConstants::MAXIMUM_DISATANCE_SEPARABLE_MATRIX.
		*
		+***************************************************************************
		*/
		static std::uint32_t ProcessFunction32Bit(std::uint32_t data, const std::uint32_t* key_32_bit_data, std::uint32_t key_bit_size)
		{
			/* Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. */
			/* Note that each byte goes through a different combination of S-boxes.*/

			using DefineConstants::PSB_Matrix_Fixed;
			using DefineConstants::PermuteIndex_00;
			using DefineConstants::PermuteIndex_01;
			using DefineConstants::PermuteIndex_02;
			using DefineConstants::PermuteIndex_03;
			using DefineConstants::PermuteIndex_04;

			using DefineConstants::PermuteIndex_10;
			using DefineConstants::PermuteIndex_11;
			using DefineConstants::PermuteIndex_12;
			using DefineConstants::PermuteIndex_13;
			using DefineConstants::PermuteIndex_14;

			using DefineConstants::PermuteIndex_20;
			using DefineConstants::PermuteIndex_21;
			using DefineConstants::PermuteIndex_22;
			using DefineConstants::PermuteIndex_23;
			using DefineConstants::PermuteIndex_24;

			using DefineConstants::PermuteIndex_30;
			using DefineConstants::PermuteIndex_31;
			using DefineConstants::PermuteIndex_32;
			using DefineConstants::PermuteIndex_33;
			using DefineConstants::PermuteIndex_34;

			std::array<std::uint32_t, 4U> state_bytes_data
			{
				(data) & 0xFF,
				(data >> 8) & 0xFF,
				(data >> 16) & 0xFF,
				(data >> 24) & 0xFF
			};

			/* make state_bytes_data[0] = LSB, state_bytes_data[3] = MSB */
			
			std::uint32_t& data0 = state_bytes_data[0];
			std::uint32_t& data1 = state_bytes_data[1];
			std::uint32_t& data2 = state_bytes_data[2];
			std::uint32_t& data3 = state_bytes_data[3];

			const std::uint32_t& key0 = key_32_bit_data[0];
			const std::uint32_t& key1 = key_32_bit_data[1];
			const std::uint32_t& key2 = key_32_bit_data[2];
			const std::uint32_t& key3 = key_32_bit_data[3];

			std::uint32_t result = 0;

			/* H Funtion */

			//由于不需要设置break语句，switch分支语句继续执行
			//Since there is no need to set a break statement, the switch branch statement continues to be executed
			switch ( ( (key_bit_size + 63) / 64 ) & 3 )
			{
				case 1:
				{
					data0 = PSB_Matrix_Fixed[PermuteIndex_01][data0] ^ ((key0) & 0xFF);
					data1 = PSB_Matrix_Fixed[PermuteIndex_11][data1] ^ ((key0 >> 8) & 0xFF);
					data2 = PSB_Matrix_Fixed[PermuteIndex_21][data2] ^ ((key0 >> 16) & 0xFF);
					data3 = PSB_Matrix_Fixed[PermuteIndex_31][data3] ^ ((key0 >> 24) & 0xFF);

					/* G Funtion */
					result = MDS0[data0] ^ MDS1[data1] ^ MDS2[data2] ^ MDS3[data3];

					break;
				}
				/* 256 bits of key */
				case 0:
				{
					data0 = PSB_Matrix_Fixed[PermuteIndex_04][data0] ^ ((key3) & 0xFF);
					data1 = PSB_Matrix_Fixed[PermuteIndex_14][data1] ^ ((key3 >> 8) & 0xFF);
					data2 = PSB_Matrix_Fixed[PermuteIndex_24][data2] ^ ((key3 >> 16) & 0xFF);
					data3 = PSB_Matrix_Fixed[PermuteIndex_34][data3] ^ ((key3 >> 24) & 0xFF);

					[[fallthrough]];
				}
				/* having pre-processed bytes[0]..bytes[3] with k32[3] */
				
				/* 192 bits of key */
				case 3:
				{
					data0 = PSB_Matrix_Fixed[PermuteIndex_03][data0] ^ ((key2) & 0xFF);
					data1 = PSB_Matrix_Fixed[PermuteIndex_13][data1] ^ ((key2 >> 8) & 0xFF);
					data2 = PSB_Matrix_Fixed[PermuteIndex_23][data2] ^ ((key2 >> 16) & 0xFF);
					data3 = PSB_Matrix_Fixed[PermuteIndex_33][data3] ^ ((key2 >> 24) & 0xFF);
				
					[[fallthrough]];
				}
				/* having pre-processed bytes[0]..bytes[3] with k32[2] */
				
				/* 128 bits of key */
				case 2:
				{
					data0 = (PSB_Matrix_Fixed[PermuteIndex_01][ (PSB_Matrix_Fixed[PermuteIndex_02][data0] & 0xFF) ^ ((key1) & 0xFF) ] & 0xFF) ^ ((key0) & 0xFF);
					data1 = (PSB_Matrix_Fixed[PermuteIndex_11][ (PSB_Matrix_Fixed[PermuteIndex_12][data0] & 0xFF) ^ ((key1) & 0xFF) ] & 0xFF) ^ ((key0) & 0xFF);
					data2 = (PSB_Matrix_Fixed[PermuteIndex_21][ (PSB_Matrix_Fixed[PermuteIndex_22][data0] & 0xFF) ^ ((key1) & 0xFF) ] & 0xFF) ^ ((key0) & 0xFF);
					data3 = (PSB_Matrix_Fixed[PermuteIndex_31][ (PSB_Matrix_Fixed[PermuteIndex_32][data0] & 0xFF) ^ ((key1) & 0xFF) ] & 0xFF) ^ ((key0) & 0xFF);

					/* G Funtion */
					result = MDS0[data0] ^ MDS1[data1] ^ MDS2[data2] ^ MDS3[data3];

					break;
				}
				/* having pre-processed bytes[0]..bytes[3] with k32[1] xor k32[0] */
			}

			return result;
		}

		/*
		* Function:			Initialize the Twofish key schedule from key32
		*
		* Arguments:		ThisInstance = Reference Algorithm object to be initialized
		*
		* Return:			void
		*
		* Notes:
		*	Here we precompute all the round subkeys, although that is not actually required. 
		*	For example, on a smartcard, the round subkeys can be generated on-the-fly using f32()
		*/
		void KeySchedule(std::span<const std::uint8_t> BytesKey)
		{
			using CommonSecurity::Twofish::DefineConstants::Constant_SubkeyRounds;
			using CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize;
			using CommonSecurity::Twofish::DefineConstants::Constant_SubkeysStep;
			using CommonSecurity::Twofish::DefineConstants::Constant_SubkeysBump;
			using CommonSecurity::Twofish::DefineConstants::Constant_SubkeyRotateLeft;
			using CommonSecurity::Twofish::DefineConstants::Constant_TotalSubkeys;

			/* Cipher round */
			std::uint32_t byte_key_bit_size = BytesKey.size() * std::numeric_limits<std::uint8_t>::digits;
			this->NumberRounds = byte_key_bit_size / std::numeric_limits<std::uint8_t>::digits;

			const std::uint32_t key_64_bit_count = ( byte_key_bit_size + 63 ) / 64;
			const std::uint32_t subkey_count = Constant_SubkeyRounds + 2 * this->NumberRounds;

			if(subkey_count > Constant_TotalSubkeys)
				my_cpp2020_assert(false, "The subkeys size for this key instance reference is invalid!", std::source_location::current());

			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(BytesKey, this->CipherKey32Bit.data());

			std::uint32_t A = 0U, B = 0U;

			/* even/odd key dwords */
			std::uint32_t key_32_bit_even[ Constant_MaxKeySize / 64 ], key_32_bit_odd[ Constant_MaxKeySize / 64 ];

			for ( std::uint32_t keys_index = 0; keys_index < key_64_bit_count; keys_index++ )
			{
				/* split into even/odd key dwords */
				key_32_bit_even[ keys_index ] = this->CipherKey32Bit[ 2 * keys_index ];
				key_32_bit_odd[ keys_index ] = this->CipherKey32Bit[ 2 * keys_index + 1 ];

				/* compute S-box keys using (12,8) Reed-Solomon code over GF(256) */
				/* reverse order */
				this->SubstituteBoxKeys[ key_64_bit_count - 1 - keys_index ] = ReedSolomon( key_32_bit_even[ keys_index ], key_32_bit_odd[ keys_index ] );
			}

			/* Compute round subkeys for Pseudo-Hadamard Transform  */
			for ( std::uint32_t subkeys_index = 0; subkeys_index < subkey_count / 2; subkeys_index++ )
			{
				/* A uses even key dwords */
				A = ProcessFunction32Bit( subkeys_index * Constant_SubkeysStep, key_32_bit_even, byte_key_bit_size );
				/* B uses odd  key dwords */
				B = ProcessFunction32Bit( subkeys_index * Constant_SubkeysStep + Constant_SubkeysBump, key_32_bit_odd, byte_key_bit_size );
				B = TWOFISH_BIT_ROTATE_LEFT( B, 8 );

				/* combine with a Pseudo-Hadamard Transform */
				this->SubKeys[ 2 * subkeys_index ] = A + B;
				this->SubKeys[ 2 * subkeys_index + 1 ] = TWOFISH_BIT_ROTATE_LEFT( A + 2 * B, Constant_SubkeyRotateLeft );
			}

			/* fully expand the table for speed */

			/* Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. */
			/* Note that each byte goes through a different combination of S-boxes.*/

			using DefineConstants::PSB_Matrix_Fixed;
			using DefineConstants::PermuteIndex_00;
			using DefineConstants::PermuteIndex_01;
			using DefineConstants::PermuteIndex_02;
			using DefineConstants::PermuteIndex_03;
			using DefineConstants::PermuteIndex_04;

			using DefineConstants::PermuteIndex_10;
			using DefineConstants::PermuteIndex_11;
			using DefineConstants::PermuteIndex_12;
			using DefineConstants::PermuteIndex_13;
			using DefineConstants::PermuteIndex_14;

			using DefineConstants::PermuteIndex_20;
			using DefineConstants::PermuteIndex_21;
			using DefineConstants::PermuteIndex_22;
			using DefineConstants::PermuteIndex_23;
			using DefineConstants::PermuteIndex_24;

			using DefineConstants::PermuteIndex_30;
			using DefineConstants::PermuteIndex_31;
			using DefineConstants::PermuteIndex_32;
			using DefineConstants::PermuteIndex_33;
			using DefineConstants::PermuteIndex_34;

			std::array<std::uint32_t, 4U> state_bytes_data { 0, 0, 0, 0 };

			/* make state_bytes_data[0] = LSB, state_bytes_data[3] = MSB */
			
			std::uint32_t& data0 = state_bytes_data[0];
			std::uint32_t& data1 = state_bytes_data[1];
			std::uint32_t& data2 = state_bytes_data[2];
			std::uint32_t& data3 = state_bytes_data[3];

			const std::uint32_t& key0 = this->SubstituteBoxKeys[0];
			const std::uint32_t& key1 = this->SubstituteBoxKeys[1];
			const std::uint32_t& key2 = this->SubstituteBoxKeys[2];
			const std::uint32_t& key3 = this->SubstituteBoxKeys[3];

			for(std::uint64_t i = 0; i < Constant_MaxKeySize; i++)
			{
				data0 = data1 = data2 = data3 = i;

				//由于不需要设置break语句，switch分支语句继续执行
				//Since there is no need to set a break statement, the switch branch statement continues to be executed
				switch ( ( (key_64_bit_count + 63) / 64 ) & 3 )
				{
					case 1:
					{
						auto a = PSB_Matrix_Fixed[PermuteIndex_01][data0] ^ ((key0) & 0xFF);
						auto b = PSB_Matrix_Fixed[PermuteIndex_11][data1] ^ ((key0 >> 8) & 0xFF);
						auto c = PSB_Matrix_Fixed[PermuteIndex_21][data2] ^ ((key0 >> 16) & 0xFF);
						auto d = PSB_Matrix_Fixed[PermuteIndex_31][data3] ^ ((key0 >> 24) & 0xFF);

						this->SubstituteBox[i * 2] = MDS0[a];
						this->SubstituteBox[i * 2 + 1] = MDS1[b];
						this->SubstituteBox[i * 2 + 0x200] = MDS2[c];
						this->SubstituteBox[i * 2 + 0x201] = MDS3[d];

						break;
					}
					/* 256 bits of key */
					case 0:
					{
						data0 = PSB_Matrix_Fixed[PermuteIndex_04][data0] ^ ((key3) & 0xFF);
						data1 = PSB_Matrix_Fixed[PermuteIndex_14][data1] ^ ((key3 >> 8) & 0xFF);
						data2 = PSB_Matrix_Fixed[PermuteIndex_24][data2] ^ ((key3 >> 16) & 0xFF);
						data3 = PSB_Matrix_Fixed[PermuteIndex_34][data3] ^ ((key3 >> 24) & 0xFF);

						[[fallthrough]];
					}
					/* having pre-processed bytes[0]..bytes[3] with k32[3] */
				
					/* 192 bits of key */
					case 3:
					{
						data0 = PSB_Matrix_Fixed[PermuteIndex_03][data0] ^ ((key2) & 0xFF);
						data1 = PSB_Matrix_Fixed[PermuteIndex_13][data1] ^ ((key2 >> 8) & 0xFF);
						data2 = PSB_Matrix_Fixed[PermuteIndex_23][data2] ^ ((key2 >> 16) & 0xFF);
						data3 = PSB_Matrix_Fixed[PermuteIndex_33][data3] ^ ((key2 >> 24) & 0xFF);
				
						[[fallthrough]];
					}
					/* having pre-processed bytes[0]..bytes[3] with k32[2] */
				
					/* 128 bits of key */
					case 2:
					{
						auto a = (PSB_Matrix_Fixed[PermuteIndex_01][ (PSB_Matrix_Fixed[PermuteIndex_02][data0] & 0xFF) ^ ((key1) & 0xFF) ] & 0xFF) ^ ((key0) & 0xFF);
						auto b = (PSB_Matrix_Fixed[PermuteIndex_11][ (PSB_Matrix_Fixed[PermuteIndex_12][data0] & 0xFF) ^ ((key1) & 0xFF) ] & 0xFF) ^ ((key0) & 0xFF);
						auto c = (PSB_Matrix_Fixed[PermuteIndex_21][ (PSB_Matrix_Fixed[PermuteIndex_22][data0] & 0xFF) ^ ((key1) & 0xFF) ] & 0xFF) ^ ((key0) & 0xFF);
						auto d = (PSB_Matrix_Fixed[PermuteIndex_31][ (PSB_Matrix_Fixed[PermuteIndex_32][data0] & 0xFF) ^ ((key1) & 0xFF) ] & 0xFF) ^ ((key0) & 0xFF);

						this->SubstituteBox[i * 2] = MDS0[a];
						this->SubstituteBox[i * 2 + 1] = MDS1[b];
						this->SubstituteBox[i * 2 + 0x200] = MDS2[c];
						this->SubstituteBox[i * 2 + 0x201] = MDS3[d];

						break;
					}
				}
			}
		}

		/*
			Cipher Instance
		*/

		std::uint32_t ApplySubstituteBoxA(std::uint32_t data)
		{
			return SubstituteBox[0x000 + 2 * ((data) & 0xff)] ^
			SubstituteBox[0x001 + 2 * ((data >> 8) & 0xff)] ^
			SubstituteBox[0x200 + 2 * ((data >> 16) & 0xff)] ^
			SubstituteBox[0x201 + 2 * ((data >> 24) & 0xff)];
		}

		std::uint32_t ApplySubstituteBoxB(std::uint32_t data)
		{
			return SubstituteBox[0x000 + 2 * ((data >> 24) & 0xff)] ^
			SubstituteBox[0x001 + 2 * ((data) & 0xff)] ^
			SubstituteBox[0x200 + 2 * ((data >> 8) & 0xff)] ^
			SubstituteBox[0x201 + 2 * ((data >> 16) & 0xff)];
		}

		void EncryptBlock(std::span<const std::uint8_t> InputBlock, std::span<std::uint8_t> OutputBlock)
		{
			using DefineConstants::Constant_InputWhitenIndex;
			using DefineConstants::Constant_OutputWhitenIndex;
			using DefineConstants::Constant_SubkeyRounds;
			using DefineConstants::Constant_MinCipherRounds;

			const std::uint32_t a = CommonToolkit::value_from_bytes<std::uint32_t, std::uint8_t>(InputBlock.subspan(0, 4));
			const std::uint32_t b = CommonToolkit::value_from_bytes<std::uint32_t, std::uint8_t>(InputBlock.subspan(4, 4));
			const std::uint32_t c = CommonToolkit::value_from_bytes<std::uint32_t, std::uint8_t>(InputBlock.subspan(8, 4));
			const std::uint32_t d = CommonToolkit::value_from_bytes<std::uint32_t, std::uint8_t>(InputBlock.subspan(12, 4));

			//INPUT WHITEN
			std::uint32_t iw0 = a ^ this->SubKeys[Constant_InputWhitenIndex];
			std::uint32_t iw1 = b ^ this->SubKeys[Constant_InputWhitenIndex + 1];
			std::uint32_t iw2 = c ^ this->SubKeys[Constant_InputWhitenIndex + 2];
			std::uint32_t iw3 = d ^ this->SubKeys[Constant_InputWhitenIndex + 3];

			std::int64_t key_index = Constant_SubkeyRounds;
			std::uint32_t t0 = 0, t1 = 0;
			for(std::uint32_t round = 0; round < Constant_MinCipherRounds; round += 2)
			{
				t0 = this->ApplySubstituteBoxA(iw0);
				t1 = this->ApplySubstituteBoxB(iw1);
				iw2 ^= t0 + t1 + this->SubKeys[key_index++];
				iw2 = TWOFISH_BIT_ROTATE_RIGHT(iw2, 1);
				iw3 = TWOFISH_BIT_ROTATE_LEFT(iw3, 1) ^ (t0 + 2 * t1 + this->SubKeys[key_index++]);

				t0 = this->ApplySubstituteBoxA(iw2);
				t1 = this->ApplySubstituteBoxB(iw3);
				iw0 ^= t0 + t1 + this->SubKeys[key_index++];
				iw0 = TWOFISH_BIT_ROTATE_RIGHT(iw0, 1);
				iw1 = TWOFISH_BIT_ROTATE_LEFT(iw1, 1) ^ (t0 + 2 * t1 + this->SubKeys[key_index++]);
			}

			//OUTPUT WHITEN
			const std::uint32_t ow0 = iw2 ^ this->SubKeys[Constant_OutputWhitenIndex];
			const std::uint32_t ow1 = iw3 ^ this->SubKeys[Constant_OutputWhitenIndex + 1];
			const std::uint32_t ow2 = iw0 ^ this->SubKeys[Constant_OutputWhitenIndex + 2];
			const std::uint32_t ow3 = iw1 ^ this->SubKeys[Constant_OutputWhitenIndex + 3];

			std::array<std::uint8_t, 4> Bytes {0,0,0,0};
			Bytes = CommonToolkit::value_to_bytes<std::uint32_t, std::uint8_t>(ow0);
			::memcpy(OutputBlock.data(), Bytes.data(), Bytes.size());
			Bytes = CommonToolkit::value_to_bytes<std::uint32_t, std::uint8_t>(ow1);
			::memcpy(OutputBlock.data() + Bytes.size(), Bytes.data(), Bytes.size());
			Bytes = CommonToolkit::value_to_bytes<std::uint32_t, std::uint8_t>(ow2);
			::memcpy(OutputBlock.data() + Bytes.size() * 2, Bytes.data(), Bytes.size());
			Bytes = CommonToolkit::value_to_bytes<std::uint32_t, std::uint8_t>(ow3);
			::memcpy(OutputBlock.data() + Bytes.size() * 3, Bytes.data(), Bytes.size());
		}

		void DecryptBlock(std::span<const std::uint8_t> InputBlock, std::span<std::uint8_t> OutputBlock)
		{
			using DefineConstants::Constant_InputWhitenIndex;
			using DefineConstants::Constant_OutputWhitenIndex;
			using DefineConstants::Constant_SubkeyRounds;
			using DefineConstants::Constant_MinCipherRounds;

			const std::uint32_t a = CommonToolkit::value_from_bytes<std::uint32_t, std::uint8_t>(InputBlock.subspan(0, 4));
			const std::uint32_t b = CommonToolkit::value_from_bytes<std::uint32_t, std::uint8_t>(InputBlock.subspan(4, 4));
			const std::uint32_t c = CommonToolkit::value_from_bytes<std::uint32_t, std::uint8_t>(InputBlock.subspan(8, 4));
			const std::uint32_t d = CommonToolkit::value_from_bytes<std::uint32_t, std::uint8_t>(InputBlock.subspan(12, 4));

			//OUTPUT WHITEN
			std::uint32_t ow2 = a ^ this->SubKeys[Constant_OutputWhitenIndex];
			std::uint32_t ow3 = b ^ this->SubKeys[Constant_OutputWhitenIndex + 1];
			std::uint32_t ow0 = c ^ this->SubKeys[Constant_OutputWhitenIndex + 2];
			std::uint32_t ow1 = d ^ this->SubKeys[Constant_OutputWhitenIndex + 3];

			std::int64_t key_index = Constant_SubkeyRounds + 2 * Constant_MinCipherRounds - 1;
			std::uint32_t t0 = 0, t1 = 0;
			for(std::uint32_t round = 0; round < Constant_MinCipherRounds; round += 2)
			{
				t0 = this->ApplySubstituteBoxA(ow2);
				t1 = this->ApplySubstituteBoxB(ow3);
				ow1 ^= t0 + 2 * t1 + this->SubKeys[key_index--];
				ow0 = TWOFISH_BIT_ROTATE_LEFT(ow0, 1) ^ (t0 + t1 + this->SubKeys[key_index--]);
				ow1 = TWOFISH_BIT_ROTATE_RIGHT(ow1, 1);
				
				t0 = this->ApplySubstituteBoxA(ow0);
				t1 = this->ApplySubstituteBoxB(ow1);
				ow3 ^= t0 + 2 * t1 + this->SubKeys[key_index--];
				ow2 = TWOFISH_BIT_ROTATE_LEFT(ow2, 1) ^ (t0 + t1 + this->SubKeys[key_index--]);
				ow3 = TWOFISH_BIT_ROTATE_RIGHT(ow3, 1);
			}

			//INPUT WHITEN
			const std::uint32_t iw0 = ow0 ^ this->SubKeys[Constant_InputWhitenIndex];
			const std::uint32_t iw1 = ow1 ^ this->SubKeys[Constant_InputWhitenIndex + 1];
			const std::uint32_t iw2 = ow2 ^ this->SubKeys[Constant_InputWhitenIndex + 2];
			const std::uint32_t iw3 = ow3 ^ this->SubKeys[Constant_InputWhitenIndex + 3];

			std::array<std::uint8_t, 4> Bytes {0,0,0,0};
			Bytes = CommonToolkit::value_to_bytes<std::uint32_t, std::uint8_t>(iw0);
			::memcpy(OutputBlock.data(), Bytes.data(), Bytes.size());
			Bytes = CommonToolkit::value_to_bytes<std::uint32_t, std::uint8_t>(iw1);
			::memcpy(OutputBlock.data() + Bytes.size(), Bytes.data(), Bytes.size());
			Bytes = CommonToolkit::value_to_bytes<std::uint32_t, std::uint8_t>(iw2);
			::memcpy(OutputBlock.data() + Bytes.size() * 2, Bytes.data(), Bytes.size());
			Bytes = CommonToolkit::value_to_bytes<std::uint32_t, std::uint8_t>(iw3);
			::memcpy(OutputBlock.data() + Bytes.size() * 3, Bytes.data(), Bytes.size());
		}

		~OfficialAlgorithm()
		{
			volatile void* CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>(&this->CipherKey32Bit[0], std::size(this->CipherKey32Bit) * sizeof(std::uint32_t));
			CheckPointer = memory_set_no_optimize_function<0x00>(&this->SubstituteBoxKeys[0], std::size(this->SubstituteBoxKeys) * sizeof(std::uint32_t));
			CheckPointer = memory_set_no_optimize_function<0x00>(&this->SubstituteBox[0], std::size(this->SubstituteBoxKeys) * sizeof(std::uint32_t));
			CheckPointer = memory_set_no_optimize_function<0x00>(&this->SubKeys[0], std::size(this->SubKeys) * sizeof(std::uint32_t));
		}
	};

	#ifdef TWOFISH_ADDRESS_XOR
	#undef TWOFISH_ADDRESS_XOR
	#endif

	#ifdef TWOFISH_FEISTEL_DESIGN_ARCHITECTURE_VERSION
	#undef TWOFISH_FEISTEL_DESIGN_ARCHITECTURE_VERSION
	#endif

	#ifdef TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
	#undef TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
	#endif

	#ifdef TWOFISH_IS_LITTLE_ENDIAN_MACHINES
	#undef TWOFISH_IS_LITTLE_ENDIAN_MACHINES	
	#endif

	#ifdef TWOFISH_BIT_ROTATE_LEFT
	#undef TWOFISH_BIT_ROTATE_LEFT
	#endif

	#ifdef TWOFISH_BIT_ROTATE_RIGHT
	#undef TWOFISH_BIT_ROTATE_RIGHT
	#endif

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
			AlgorithmObject.EncryptBlock(Input, Output);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output) override
		{
			AlgorithmObject.DecryptBlock(Input, Output);
		}

		DataWorker128() = default;
		virtual ~DataWorker128() = default;

		DataWorker128(DataWorker128& _object) = delete;
		DataWorker128& operator=(const DataWorker128& _object) = delete;
	};

	class DataWorker192 : public CommonSecurity::BlockCipher128_192
	{

	private:
		
		OfficialAlgorithm AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.EncryptBlock(Input, Ouput);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.DecryptBlock(Input, Ouput);
		}

		DataWorker192() = default;
		virtual ~DataWorker192() = default;

		DataWorker192(DataWorker192& _object) = delete;
		DataWorker192& operator=(const DataWorker192& _object) = delete;
	};

	class DataWorker256 : public CommonSecurity::BlockCipher128_256
	{

	private:
		
		OfficialAlgorithm AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.EncryptBlock(Input, Ouput);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.DecryptBlock(Input, Ouput);
		}

		DataWorker256() = default;
		virtual ~DataWorker256() = default;

		DataWorker256(DataWorker256& _object) = delete;
		DataWorker256& operator=(const DataWorker256& _object) = delete;
	};
}