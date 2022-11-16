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
 * This document is part of TDOM-EncryptOrDecryptFile-Reborn.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "./IsFor_EODF_Reborn.hpp"
#include "./UnitTester.hpp"

auto main(int argument_cout, char* argument_vector[]) -> int
{
	std::cout.tie(0)->sync_with_stdio(false);

	/*

	std::uint32_t LeftWordData = 123456789;
	std::uint32_t RightWordData = 987654321;

	//Pseudo-Hadamard Transformation (Forward)
	auto A = LeftWordData + RightWordData;
	auto B = LeftWordData + RightWordData * 2;

	B ^= std::rotl(A, 1);
	A ^= std::rotr(B, 63);

	A ^= std::rotr(B, 63);
	B ^= std::rotl(A, 1);
				
	//Pseudo-Hadamard Transformation (Backward)
	RightWordData = B - A;
	LeftWordData = 2 * A - B;

	std::cout << std::endl;

	*/

	#if 0
	
	CommonSecurity::RNG_FeedbackShiftRegister::NonlinearFeedbackShiftRegister NLFSR(1);

	std::bernoulli_distribution prng_distribution(0.5);
	
	std::vector<std::uint8_t> random_bits(std::numeric_limits<std::uint64_t>::max() / 10240000000ULL, 0);
	std::vector<std::uint64_t> random_numbers(random_bits.size() / std::numeric_limits<std::uint64_t>::digits, 0);

	for(auto& random_bit : random_bits)
	{
		random_bit = prng_distribution(NLFSR);
	}

	for(std::size_t random_number_index = 0, bit_index_offset = 0; random_number_index < random_numbers.size(); random_number_index++, bit_index_offset += std::numeric_limits<std::uint64_t>::digits)
	{		
		auto& random_number = random_numbers[random_number_index];

		for(std::size_t bit_index = 0; bit_index < std::numeric_limits<std::uint64_t>::digits; bit_index++)
		{
			if(random_bits[bit_index + bit_index_offset])
				random_number |= (static_cast<std::uint64_t>(random_bits[bit_index + bit_index_offset]) << bit_index);
			else
				bit_index++;
		}
		std::cout << "Now random number (NLFSR) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}

	std::cout << std::endl;

	#endif

	#if 0

	CommonSecurity::RNG_FeedbackShiftRegister::NonlinearFeedbackShiftRegister NLFSR(1);

	//CommonSecurity::RND::BernoulliDistribution prng_distribution(0.5);

	for(std::size_t random_number_index = 0; random_number_index < std::numeric_limits<std::uint64_t>::max() / 10240000000ULL; random_number_index++)
	{
		//auto random_number = NLFSR();
		//auto random_number = NLFSR.unpredictable_bits(1, 64);

		/*for(std::size_t bit_index = 0; bit_index < std::numeric_limits<std::uint64_t>::digits; bit_index++)
		{
			auto random_bit = prng_distribution(NLFSR);

			if(random_bit)
				random_number |= (static_cast<std::uint64_t>(random_bit) << bit_index);
			else
				bit_index++;
		}*/

		std::cout << "Now random number (NLFSR) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		/*int result_status = _setmode( _fileno(stdin), _O_BINARY );
		if(result_status == -1)
		{
			throw std::runtime_error("can not set file mode");
		}
		else
		{
			size_t bytes_written = fwrite(&random_number, 1, sizeof(&random_number), stdout);
			if (bytes_written < sizeof(random_number))
			{
				throw std::runtime_error("this is no data!");
			}
		}*/
		
	}

	std::cout << std::endl;

	#endif

	#if 0

	std::vector<std::uint64_t> random_numbers(std::numeric_limits<std::uint64_t>::max() / (sizeof(std::uint64_t) * 10240000000ULL), 0);

	CommonSecurity::RNG_FeedbackShiftRegister::LinearFeedbackShiftRegister LFSR(1);

	for(auto& random_number : random_numbers)
	{
		random_number = 0;

		for(std::size_t bit_index = 0; bit_index < std::numeric_limits<std::uint64_t>::digits; bit_index++)
		{
			auto random_bit = prng_distribution(LFSR);

			if(random_bit)
				random_number |= (static_cast<std::uint64_t>(random_bit) << bit_index);
			else
				bit_index++;
		}

		std::cout << "Now random number (LFSR) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
	}
	std::cout << std::endl;

	#endif

	#if 0

	std::vector<std::uint64_t> random_numbers(std::numeric_limits<std::uint64_t>::max() / (sizeof(std::uint64_t) * 10240000000ULL), 0);

	CommonSecurity::RNG_FeedbackShiftRegister::NonlinearFeedbackShiftRegister LFSR(1);

	for(auto& random_number :random_numbers)
	{
		random_number = LFSR_Object();
		std::cout << "Now random number (LFSR) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	std::cout << std::endl;

	#endif

	#if 0

	std::vector<std::uint64_t> random_numbers(std::numeric_limits<std::uint64_t>::max() / (sizeof(std::uint64_t) * 10240000000ULL), 0);

	CommonSecurity::RNG_ChaoticTheory::SimulateDoublePendulum SDP(std::string("10000000000000001000000000000100000000000000000000000000"));

	random_numbers = SDP(1048576, 0, 1048576);
	for(auto& random_number :random_numbers)
	{
		std::cout << "Now random number (SDP) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	std::cout << std::endl;

	#endif

	//UnitTester::Test_LearningWithErrorModule();
	//UnitTester::Test_InfiniteGarbledCodeDataGeneration();

	/*
	std::size_t value = 123456789;
	auto byte_array = CommonToolkit::value_to_bytes<std::size_t, std::uint8_t>(value);
	std::size_t value2 = CommonToolkit::value_from_bytes<std::size_t, std::uint8_t>(byte_array);

	if(value == value2)
	{
		std::cout << "Worked !" << std::endl;
	}
	else
	{
		std::cout << "Not Worked !" << std::endl;
	}
	*/

	//UnitTester::Test_ShamirSecretSharing();
	//CommonSecurity::UtilGaloisFiniteFieldByTwo UtilGaloisFiniteFieldByTwoObject;
	//UtilGaloisFiniteFieldByTwoObject.polynomial_format(0x4000'0000'0000'0148ULL);
	//UtilGaloisFiniteFieldByTwoObject.polynomial_format(0x4000'0000'0000'0717ULL);

	//UnitTester::Test_ShuffleRangeData();

	//UnitTester::Test_DigestCryptograph_Blake2();
	//UnitTester::Test_DigestCryptograph_Blake3_Modified();
	
	//UnitTester::Test_BlockCryptograph_TripleDES();
	//UnitTester::Test_BlockCryptograph_RC6();
	//UnitTester::Test_BlockCryptograph_AES();
	//UnitTester::Test_BlockCryptograph_ChinaShangYongMiMa();
	//UnitTester::Test_BlockCryptograph_Twofish();
	//UnitTester::Test_StreamCryptograph();
	
	//UnitTester::Test_DRBG_With_HMAC();
	//UnitTester::Test_Argon2_KDF();
	//UnitTester::Test_Scrypt_KDF();

	//UnitTester::Test_BlockCryptograph_CustomOaldresPuzzleCryptic();
	UnitTester::Test_BlockCryptograph_CustomOaldresPuzzleCryptic_2();

	//UnitTester::Test_GenerationSubstitutionBoxWithShuffleArray(UnitTester::CommonRandomDataObject.RandomClassicBytesData);
	//UnitTester::Test_GenerationSubstitutionBoxWithHashValues(UnitTester::CommonRandomDataObject.RandomClassicBytesData);

	//UnitTester::Test_ByteSubstitutionBoxToolkit();
	//UnitTester::Test_CustomByteSubstitutionBox();
	//UnitTester::SubstitutionBoxGeneratorTest SBG_Test;
	//SBG_Test.ApplyGeneratorAlgorithm();
	
	//auto SecureRandomNumberSeedSequence = CommonSecurity::GenerateSecureRandomNumberSeedSequence<std::size_t>(256);

	//UnitTester::Test_SubstitutionBoxGenerationUsingChaoticSineMap();
	//UnitTester::Test_SubstitutionBoxGenerationUsingChaoticSineMapWithKey(UnitTester::CommonRandomDataObject.RandomClassicBytesData);

	/*
	auto random_seed_vector = CommonSecurity::GenerateSecureRandomNumberSeedSequence<std::uint64_t>(64);
	std::seed_seq random_seed_sequence_obejct(random_seed_vector.begin(), random_seed_vector.end());
	std::mt19937_64 pseudo_random_generator_object(random_seed_sequence_obejct);

	std::vector<std::uint64_t> random_numbers;

	for(std::size_t round = 1024; round > 0; --round)
	{
		random_numbers.push_back(pseudo_random_generator_object());
	}
	*/
	
	//Cryptograph::DataPermutation::HexadecimalStringCoder HexadecimalStringCoderObject;

	//auto DisorderedString = HexadecimalStringCoderObject.DataDisorder("ABCDEFHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789");
	//auto OrderedString = HexadecimalStringCoderObject.DataOrder(DisorderedString);
	
	//UnitTester::Test_BuildingKeyStream();
	
	//UnitTester::Test_ByteSubstitutionBoxToolkit();

	//74 68 61 74 73 20 6D 79 20 6B 75 6E 67 20 66 75
	//21 40 23 24 25 5E 26 2A 28 29 30 38 34 36 32 35
	//std::vector<std::uint8_t> Keys = UtilTools::DataFormating::ASCII_Hexadecmial::hexadecimalString2ByteArray(std::string("21402324255E262A2829303834363235"));
	//auto SubsitiutionBoxPair = CustomSecurity::DataObfuscator::SubsitiutionBox::GeneratorAlgorithm(Keys);
	//auto SubsitiutionBoxPair = CustomSecurity::DataObfuscator::SubsitiutionBox::GeneratorAlgorithm2();

	//UnitTester::Test_CustomDataObfuscator();

	/*

	CommonSecurity::RNG_ISAAC::isaac<8> ISAAC(1597346285);
	CommonSecurity::RNG_ISAAC::isaac64<8> ISAAC64(1597346285);

	std::vector<std::uint32_t> random_32bit_numbers;
	std::vector<std::uint64_t> random_64bit_numbers;

	for(std::size_t round = 1024; round > 0; --round)
	{
		random_32bit_numbers.push_back(ISAAC());
	}

	for(std::size_t round = 1024; round > 0; --round)
	{
		random_64bit_numbers.push_back(ISAAC64());
	}

	std::cout << std::endl;

	*/

	/*

	CommonSecurity::RNG_SimpleImplementation::GNU_C_LibraryGenerator PRNG_GNU_C_Library(1);

	std::vector<char> RNG_bytes_state
	{
		8, -72, 13, -54, -55, 85, 43, -127,
		66, -49, 1, 13, -111, 7, 46, 22,
		59, -21, 9, -88, 47, 58, -44, 11,
		-33, 64, 3, 48, -62, 5, -2, 0, 99
	};

	std::vector<char> RNG_bytes_state2
	{
		-34, -101, 3, 48, -62, 5, -44, 0, 99,
		66, 59, 2, 13, 121, 7, 46, 66,
		19, 56, 13, -54, -55, 85, 43, -127,
		59, -21, 42, -88, 47, 58, -44, 11,
	};

	unsigned int seed_number = 1;

	auto PRNG_GNU_C_LibraryStateArgument = std::pair<unsigned int, std::span<const char>>(seed_number, RNG_bytes_state);
	auto PRNG_GNU_C_LibraryStateArgument2 = std::pair<unsigned int, std::span<const char>>(seed_number, RNG_bytes_state2);

	PRNG_GNU_C_LibraryStateArgument.first = PRNG_GNU_C_Library.easy_compute_number(seed_number);
	auto PRNG_GNU_C_LibraryStatePairValue = PRNG_GNU_C_Library.initial_state(PRNG_GNU_C_LibraryStateArgument);

	std::vector<int> RNG_test_random_numbers;

	for(std::size_t count = 128; count > 0; --count)
	{
		auto&& random_number = PRNG_GNU_C_Library();
		RNG_test_random_numbers.push_back(random_number);
	}

	if(PRNG_GNU_C_LibraryStatePairValue.has_value())
	{
		auto& PRNG_GNU_C_LibraryStatePair = PRNG_GNU_C_LibraryStatePairValue.value();
		PRNG_GNU_C_Library.update_state(PRNG_GNU_C_LibraryStateArgument2, PRNG_GNU_C_LibraryStatePair.second);
		PRNG_GNU_C_Library.change_state(PRNG_GNU_C_LibraryStatePair.second);
	}

	std::vector<int> RNG_test_random_numbers2;

	for(std::size_t count = 128; count > 0; --count)
	{
		auto&& random_number = PRNG_GNU_C_Library();
		RNG_test_random_numbers2.push_back(random_number);
	}

	*/

	std::cout << std::endl;

	//MemoryTrackUsageInfo::get_instance().SetIsTracked(true);

	#ifdef _WIN32
	std::system("pause");
	#else
    std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
	#endif

	return 0;
}