#pragma once

namespace CommonSecurity::RC6::DefineConstants
{
	/*
	
	double Number_GoldenRatio 0.618033988749895 = 1 / ((1 + std::sqrt(5)) / 2) is 1 / 1.618033988749895;
	(std::numbers::phi == 1 / 0.618033988749895) is true
	(0.618033988749895 == 1 / std::numbers::phi) is true
	where Î¦ is the golden ratio constant
	
	*/
	inline constexpr double Number_GoldenRatio = 1.618033988749895 - 1;

	/*
	
	double Number_BaseOfTheNaturalLogarithm = sum( 1/(factorial(items_number)) + 1/(factorial(items_number - 1 )) + 1/(factorial(items_number - 2)) ..... + 1/(factorial(1)) + 1/(factorial(0)) ) is 2.718281828459045
	If items_number approaches infinity, hen it is the limit of (1 + 1/items_number)^items_number
	where e is the base of natural logarithm function
	
	*/
	inline constexpr double Number_BaseOfTheNaturalLogarithm = 2.718281828459045;
}

/*
	RC6 ciphers papers:
	http://people.csail.mit.edu/rivest/pubs/RRSY98.pdf

	RC6 ciphers auther code(C languange):
	https://www.schneier.com/wp-content/uploads/2015/03/RC6-AES-2.zip
*/
namespace CommonSecurity::RC6
{
	template<typename Type>
	concept BlockWordType = std::same_as<Type, std::uint32_t> || std::same_as<Type, std::uint64_t>;

	constexpr size_t BlockSize() { return 4; }
	template<BlockWordType Type>
	constexpr size_t BlockByteSize() { return sizeof(Type) * RC6::BlockSize(); }

	//Number of half-rounds (0 ~ 255)
	//Encryption/Decryption consists of a non-negative number of rounds (Based on security estimates)

	template<BlockWordType Type, std::size_t HalfRounds>
	/*
		The three parameters are w, r and b and are used by the RC6 cipher.
		The w is the size (in bits) of each word in the key schedule, r is the number of rounds used during encryption and decryption, and b is the length (in bytes) of the user-supplied key. 
		These parameters are related to each other in that c (the number of words generated from a given byte key) can be calculated by taking b divided by w then rounded up to give c which can then be multiplied by w to get back to b.

		The relationship between b, w and c can be expressed in the following equation: 
		b = ceil(b/w) * w 
		Where b is the length of the byte key, w is the size (in bits) of each word and c is the number of words generated from that key.

		The r is an independent parameter that determines the number of rounds used during encryption and decryption. 
		The value of r can range from 0 to 255 rounds depending on the implementation.

		The maximum value for each parameter is dependent on the implementation, but typically w can range from 16 to 32 bits, r can range from 0 to 255 rounds and b can be up to 2^32 bytes in length. 
		An example would be RC6-w/r/b with a word size of 32 bits (w=32), 8 rounds (r=8) and a key length of 256 bytes (b=256).
		If w is 64 bits and r is 255 rounds, then b would be the maximum key length allowed by the implementation. 
		This could range from 0 to 2^32 bytes in length.
	*/
	class OfficialAlgorithm
	{

	private:

		static constexpr std::uint32_t KeyBitSize_MaxLimit = 255 * std::numeric_limits<std::uint8_t>::digits;

		//Specific to RC6, we have removed the BYTE *KS and added in an array of 2+2*ROUNDS+2 = 44 rounds to hold the key schedule/
		//Default iteration limit for key scheduling
		static constexpr std::size_t KeySchedule_IterationLimit = 2 * HalfRounds + 4;

		//The size of data word from bits
		static constexpr Type WordData_BitSize = std::numeric_limits<Type>::digits;

		//Math exprssion
		//static_cast<Type>(std::log2(RC6_WordData_BitSize))
		static constexpr Type Log2_WordData_BitSize =
			CURRENT_SYSTEM_BITS == 32 
			? 5 : (std::same_as<Type, std::uint32_t>)
			? 5 : 6;

		//BaseOfTheNaturalLogarithm BinaryData
		//16bit: 0xB7E1
		//32bit: 0xB7E15163
		//64bit: 0xB7E151628AED2A6B
		//(e - 2) * (2 ^ WordBitSize)
		static constexpr Type MagicNumber_P = 
			std::same_as<Type, std::uint32_t> 
			? 0xB7E15163 : ( std::same_as<Type, std::uint64_t>
			? 0xB7E151628AED2A6B : 0 );
		
		//GoldenRatio BinaryData
		//16bit: 0x9E37.
		//32bit: 0x9E3779B9
		//64bit: 0x9E3779B97F4A7C15
		//(phi - 1) * (2 ^ WordBitSize)
		static constexpr Type MagicNumber_Q = 
			std::same_as<Type, std::uint32_t> 
			? 0x9E3779B9 : ( std::same_as<Type, std::uint64_t> )
			? 0x9E3779B97F4A7C15 : 0;

		// Create schedule
		// KeyScheduleBox called S from RC6 paper
		std::array<Type, KeySchedule_IterationLimit> KeyScheduleBox {};

	public:

		void KeySchedule(std::span<const std::uint8_t> KeyBlock)
		{
			// Copy key to not modify original
			std::vector<std::uint8_t> BytesKeyCopy { KeyBlock.begin(), KeyBlock.end() };

			// Pad to word length
			while (BytesKeyCopy.size() % sizeof(Type) != 0)
				BytesKeyCopy.push_back(0);

			if(BytesKeyCopy.size() * std::numeric_limits<std::uint8_t>::digits > KeyBitSize_MaxLimit)
				my_cpp2020_assert(false, "", std::source_location::current());

			// TotalWords called c from RC6 paper
			const std::size_t TotalWords = (BytesKeyCopy.size() > 0) ? (BytesKeyCopy.size() + (sizeof(Type) - 1)) / sizeof(Type) : 1;

			// LeastWordKey called L from RC6 paper (Ensure bytes are loaded little endian)
			auto LeastWordKey = CommonToolkit::MessagePacking<Type, std::uint8_t>(BytesKeyCopy.data(), BytesKeyCopy.size());

			//KeyScheduleIndex and WordKeySizeIndex called i and j from RC6 paper
			Type KeyScheduleIndex = 0, WordKeySizeIndex = 0;

			//Initialize array S to a particular fixed pseudo random bit pattern
			KeyScheduleBox[0] = this->MagicNumber_P;
			for (KeyScheduleIndex = 1; KeyScheduleIndex < 2 * HalfRounds + 4; ++KeyScheduleIndex)
			{
				KeyScheduleBox[KeyScheduleIndex] = KeyScheduleBox[KeyScheduleIndex - 1] + this->MagicNumber_Q;
			}

			KeyScheduleIndex = 0;
			Type ValueA = 0, ValueB = 0;

			// NumberIterations called v from RC6 paper
			const std::size_t NumberIterations = 3 * ::std::max<std::size_t>( TotalWords, 2 * HalfRounds + 4 );

			// Round called s from RC6 paper
			for (std::size_t Round = 0; Round < NumberIterations; ++Round)
			{
				KeyScheduleBox[KeyScheduleIndex] = std::rotl(KeyScheduleBox[KeyScheduleIndex] + ValueA + ValueB, 3);
				ValueA = KeyScheduleBox[KeyScheduleIndex];

				LeastWordKey[WordKeySizeIndex] = std::rotl(LeastWordKey[WordKeySizeIndex] + ValueA + ValueB, ValueA + ValueB % std::numeric_limits<Type>::digits);
				ValueB = LeastWordKey[WordKeySizeIndex];

				// Wrapped indices for schedule/little endian word key
				if(++KeyScheduleIndex >= (2 * HalfRounds + 4))
					KeyScheduleIndex = 0;
				if(++WordKeySizeIndex >= TotalWords)
					WordKeySizeIndex = 0;
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(BytesKeyCopy.data(), BytesKeyCopy.size());
			my_cpp2020_assert(CheckPointer == BytesKeyCopy.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		void Encryption(std::span<const std::uint8_t> InputBlock, std::span<std::uint8_t> OutputBlock)
		{
			if(InputBlock.size() != BlockByteSize<Type>())
				my_cpp2020_assert(false, "", std::source_location::current());
			if(OutputBlock.size() != BlockByteSize<Type>())
				my_cpp2020_assert(false, "", std::source_location::current());

			// Set up word-sized 'registers'
			std::array<Type, 4> Registers {0,0,0,0};

			if constexpr(std::same_as<Type, std::uint32_t>)
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(InputBlock, Registers.data());
			else if constexpr(std::same_as<Type, std::uint64_t>)
				CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(InputBlock, Registers.data());

			auto& [ValueA, ValueB, ValueC, ValueD] = Registers;

			/* Do pseudo-round #0: pre-whitening of B and D */
			ValueB += KeyScheduleBox[0];
			ValueD += KeyScheduleBox[1];

			for(std::size_t index = 1; index <= HalfRounds; ++index)
			{
				Type TemporaryValue = ValueB * (2 * ValueB + 1);
				Type TemporaryValue2 = ValueD * (2 * ValueD + 1);

				Type temporary_value_t = std::rotl( TemporaryValue, Log2_WordData_BitSize );
				Type temporary_value_u = std::rotl( TemporaryValue2, Log2_WordData_BitSize );

				Type TemporaryValue3 = ValueA ^ temporary_value_t;
				Type TemporaryValue4 = ValueC ^ temporary_value_u;

				ValueA = std::rotl( TemporaryValue3, temporary_value_u ) + KeyScheduleBox[2 * index];
				ValueC = std::rotl( TemporaryValue4, temporary_value_t ) + KeyScheduleBox[2 * index + 1];

				{
					Type TemporaryValueSwap = 0; 
					TemporaryValueSwap = ValueA;
					ValueA = ValueB;
					ValueB = ValueC;
					ValueC = ValueD;
					ValueD = TemporaryValueSwap;
				}

				//Rotate left 1 offset position
				//std::ranges::rotate(Word32BitRegisters, Word32BitRegisters.begin() + 1);
			}

			/* Do pseudo-round #(ROUNDS+1): post-whitening of A and C */
			ValueA += KeyScheduleBox[2 * HalfRounds + 2];
			ValueC += KeyScheduleBox[2 * HalfRounds + 3];

			if constexpr(std::same_as<Type, std::uint32_t>)
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(Registers, OutputBlock.data());
			else if constexpr(std::same_as<Type, std::uint64_t>)
				CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(Registers, OutputBlock.data());
		}

		void Decryption(std::span<const std::uint8_t> InputBlock, std::span<std::uint8_t> OutputBlock)
		{
			if(InputBlock.size() != BlockByteSize<Type>())
				my_cpp2020_assert(false, "", std::source_location::current());
			if(OutputBlock.size() != BlockByteSize<Type>())
				my_cpp2020_assert(false, "", std::source_location::current());

			// Set up word-sized 'registers'
			std::array<Type, 4> Registers {0,0,0,0};

			if constexpr(std::same_as<Type, std::uint32_t>)
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(InputBlock, Registers.data());
			else if constexpr(std::same_as<Type, std::uint64_t>)
				CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(InputBlock, Registers.data());

			auto& [ValueA, ValueB, ValueC, ValueD] = Registers;

			/* Undo pseudo-round #(ROUNDS+1): post-whitening of A and C */
			ValueC -= KeyScheduleBox[2 * HalfRounds + 3];
			ValueA -= KeyScheduleBox[2 * HalfRounds + 2];

			for(std::size_t index = HalfRounds; index >= 1; --index)
			{
				//Rotate right 1 offset position
				//std::ranges::rotate(Word32BitRegisters, Word32BitRegisters.end() - 1);

				{
					Type TemporaryValueSwap = 0;
					TemporaryValueSwap = ValueD;
					ValueD = ValueC;
					ValueC = ValueB;
					ValueB = ValueA;
					ValueA = TemporaryValueSwap;
				}

				Type TemporaryValue = ValueD * (2 * ValueD + 1);
				Type TemporaryValue2 = ValueB * (2 * ValueB + 1);

				Type temporary_value_u = std::rotl( TemporaryValue, Log2_WordData_BitSize );
				Type temporary_value_t = std::rotl( TemporaryValue2, Log2_WordData_BitSize );

				Type TemporaryValue3 = ValueC - KeyScheduleBox[2 * index + 1];
				Type TemporaryValue4 = ValueA - KeyScheduleBox[2 * index];

				ValueC = std::rotr( TemporaryValue3, temporary_value_t ) ^ temporary_value_u;
				ValueA = std::rotr( TemporaryValue4, temporary_value_u ) ^ temporary_value_t;
			}

			/* Undo pseudo-round #0: pre-whitening of B and D */
			ValueD -= KeyScheduleBox[1];
			ValueB -= KeyScheduleBox[0];

			if constexpr(std::same_as<Type, std::uint32_t>)
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(Registers, OutputBlock.data());
			else if constexpr(std::same_as<Type, std::uint64_t>)
				CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(Registers, OutputBlock.data());
		}

		//RC6 Algorithm <-> (W)ordSize/(R)oundNumber/(B)yteKeySize
		OfficialAlgorithm()
		{
			static_assert(HalfRounds < 256, "RC6 ciphers perform a half round number that is invalid!");

			if constexpr(CURRENT_SYSTEM_BITS == 32)
			{
				static_assert(WordData_BitSize == 32, "ERROR: Trying to run 256-bit blocksize on a 32-bit CPU.\n");
			}
		}

		~OfficialAlgorithm()
		{
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(KeyScheduleBox.data(), sizeof(Type) * KeyScheduleBox.size());
			my_cpp2020_assert(CheckPointer == KeyScheduleBox.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}
	};

	class DataWorker128_128 : public CommonSecurity::BlockCipher128_128
	{

	private:

		OfficialAlgorithm<std::uint32_t, 20> AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.Encryption(Input, Ouput);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.Decryption(Input, Ouput);
		}

		DataWorker128_128() = default;
		virtual ~DataWorker128_128() = default;

		DataWorker128_128(DataWorker128_128& _object) = delete;
		DataWorker128_128& operator=(const DataWorker128_128& _object) = delete;
	};

	class DataWorker128_192 : public CommonSecurity::BlockCipher128_192
	{

	private:

		OfficialAlgorithm<std::uint32_t, 20> AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.Encryption(Input, Ouput);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.Decryption(Input, Ouput);
		}

		DataWorker128_192() = default;
		virtual ~DataWorker128_192() = default;

		DataWorker128_192(DataWorker128_192& _object) = delete;
		DataWorker128_192& operator=(const DataWorker128_192& _object) = delete;
	};

	class DataWorker128_256 : public CommonSecurity::BlockCipher128_256
	{

	private:

		OfficialAlgorithm<std::uint32_t, 20> AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.Encryption(Input, Ouput);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.Decryption(Input, Ouput);
		}

		DataWorker128_256() = default;
		virtual ~DataWorker128_256() = default;

		DataWorker128_256(DataWorker128_256& _object) = delete;
		DataWorker128_256& operator=(const DataWorker128_256& _object) = delete;
	};
}