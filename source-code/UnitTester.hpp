#pragma once

#include "./IsFor_EODF_Reborn.hpp"

#ifndef BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST
#define BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST
#endif // !BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST

#ifndef STREAM_CRYPTOGRAPH_TEST
#define STREAM_CRYPTOGRAPH_TEST
#endif // !STREAM_CRYPTOGRAPH_TEST

#ifndef DIGEST_CRYPTOGRAPH_TEST
#define DIGEST_CRYPTOGRAPH_TEST
#endif // !DIGEST_CRYPTOGRAPH

#ifndef CUSTOM_BLOCK_CRYPTOGRAPH_TEST
#define CUSTOM_BLOCK_CRYPTOGRAPH_TEST
#endif // !CUSTOM_BLOCK_CRYPTOGRAPH_TEST

#ifndef CUSTOM_BLOCK_CRYPTOGRAPH_WITH_TREADING_TEST
#define CUSTOM_BLOCK_CRYPTOGRAPH_WITH_TREADING_TEST
#endif // !CUSTOM_BLOCK_CRYPTOGRAPH_WITH_TREADING_TEST

#ifndef SHUFFLE_RANGE_DATA_TEST
#define SHUFFLE_RANGE_DATA_TEST
#endif // !SHUFFLE_RANGE_DATA_TEST

#ifndef MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST
#define MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST
#endif // !MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST

#ifndef BUILDING_KEYSTREAM_TEST
#define BUILDING_KEYSTREAM_TEST
#endif // !BUILDING_KEYSTREAM_TEST

#ifndef DIGEST_CRYPTOGRAPH_KDF_TEST
#define DIGEST_CRYPTOGRAPH_KDF_TEST
#endif // !DIGEST_CRYPTOGRAPH_KDF_ARGON2_TEST

#ifndef PROGRAM_MAIN_MODULE_TEST
//#define PROGRAM_MAIN_MODULE_TEST
#endif // !PROGRAM_MAIN_MODULE_TEST

#ifndef CUSTOM_DATA_OBFUSCATOR_TEST
#define CUSTOM_DATA_OBFUSCATOR_TEST
#endif // !CUSTOM_DATA_OBFUSCATOR_TEST

#ifndef SUBSTITUTIONBOX_GENERATION_TEST
#define SUBSTITUTIONBOX_GENERATION_TEST
#endif // !SUBSTITUTIONBOX_GENERATION_TEST

namespace UnitTester
{
	inline std::random_device random_device_object;
	inline std::mt19937_64 RandomGeneraterByReallyTime(CommonSecurity::GenerateSecureRandomNumberSeed<std::uint32_t>(random_device_object));
	inline CommonSecurity::RND::UniformIntegerDistribution<std::size_t> UniformNumberDistribution(0, 255);

	struct CommonRandomData
	{
		std::vector<std::uint8_t> RandomClassicBytesData;

		std::chrono::duration<double> TimeSpent;
		std::chrono::time_point<std::chrono::system_clock> generateDataStartTime;
		std::chrono::time_point<std::chrono::system_clock> generateDataEndTime;

		CommonRandomData()
		{
			generateDataStartTime = std::chrono::system_clock::now();
			//10485760 10MB
			//209715200 200MB
			std::cout << "RandomClassicBytesData" << std::endl;
			for (std::uint32_t index = 0; index < 10485760; index++)
			{
				RandomClassicBytesData.push_back(static_cast<std::uint8_t>(UniformNumberDistribution(RandomGeneraterByReallyTime)));
				//RandomClassicBytesData.push_back(static_cast<std::uint8_t>(index));
			}
			generateDataEndTime = std::chrono::system_clock::now();
			TimeSpent = generateDataEndTime - generateDataStartTime;
			std::cout << "The time spent generating the random data: " << TimeSpent.count() << "s" << std::endl;
		}

		~CommonRandomData()
		{
			RandomClassicBytesData.clear();
			RandomClassicBytesData.shrink_to_fit();
		}
	};

	inline CommonRandomData CommonRandomDataObject {};

	template <typename DataType> 
	requires CommonToolkit::IsIterable::IsIterable<DataType>
	double ShannonInformationEntropy(DataType& data)
	{
		//H
		double entropy { 0.0 };

		#if 1

		std::size_t frequencies_count { 0 };

		std::map<std::ranges::range_value_t<DataType>, std::size_t> map;

		for (const auto& item : data)
		{
			map[item]++;
		}

		std::size_t size = std::size(data);

		for (auto iterator = map.cbegin(); iterator != map.cend(); ++iterator)
		{
			double probability_x = static_cast<double>(iterator->second) / static_cast<double>(size);
			entropy -= probability_x * ::log2(probability_x);
			++frequencies_count;
		}

		if (frequencies_count > 256)
		{
			return -1.0;
		}

		return entropy < 0.0 ? -entropy : entropy;

		#else

		DataType copy_data(data);

		std::sort(std::begin(copy_data), std::end(copy_data));

		const std::size_t copy_data_size = std::size(copy_data);
		std::size_t hide_function = 1;
		for (std::size_t index = 1; index < copy_data_size; ++index)
		{
			if (copy_data[index] == copy_data[index - 1])
				++hide_function;
			else
			{
				const double hide_function_size = static_cast<double>(hide_function) / copy_data_size;
				entropy -= hide_function_size * ::log2(hide_function_size);
				hide_function = 1;
			}
		}

		return entropy;

		#endif
	}
	
	template<typename ThisArgumentType>
	requires std::constructible_from< std::span<std::byte>, ThisArgumentType> || std::constructible_from< std::span<std::uint8_t>, ThisArgumentType>
	void UsedAlgorithmByteDataDifferences(std::string AlgorithmName, ThisArgumentType&& BeforeByteData, ThisArgumentType&& AfterByteData)
	{
		std::size_t DifferentByteCounter = 0;

		std::size_t CountBitOneA = 0;
		std::size_t CountBitOneB = 0;

		for
		(
			auto IteratorBegin = BeforeByteData.begin(), IteratorEnd = BeforeByteData.end(),
			IteratorBegin2 = AfterByteData.begin(), IteratorEnd2 = AfterByteData.end();
			IteratorBegin != IteratorEnd && IteratorBegin2 != IteratorEnd2;
			++IteratorBegin, ++IteratorBegin2
		)
		{
			if(*IteratorBegin != *IteratorBegin2)
				++DifferentByteCounter;

				CountBitOneA += std::popcount( static_cast<std::uint8_t>(*IteratorBegin) );
				CountBitOneB += std::popcount( static_cast<std::uint8_t>(*IteratorBegin2) );
		}

		std::cout << "Applying this symmetric encryption and decryption algorithm " << "[" << AlgorithmName << "]" << std::endl;
		std::cout << "The result is that a difference of ("<< DifferentByteCounter << ") bytes happened !" << std::endl;
		std::cout << "Difference ratio is: " << static_cast<double>(DifferentByteCounter * 100.0) / static_cast<double>( CommonRandomDataObject.RandomClassicBytesData.size() ) << "%" << std::endl;

		std::cout << "The result is that a hamming distance difference of ("  << ( CountBitOneA > CountBitOneB ? "+" : "-" ) << ( CountBitOneA > CountBitOneB ? CountBitOneA - CountBitOneB : CountBitOneB - CountBitOneA ) <<  ") bits happened !" << std::endl;
		std::cout << "Difference ratio is: " << static_cast<double>(CountBitOneA * 100.0) / static_cast<double>(CountBitOneB) << "%" << std::endl;
	}

	#if defined(CUSTOM_DATA_OBFUSCATOR_TEST)

	inline void Test_CustomDataObfuscator()
	{
		using namespace CustomSecurity::DataObfuscator;

		std::unique_ptr<CustomDataObfuscator<false>> UDO_Object_Pointer = std::make_unique<CustomDataObfuscator<false>>(1, 2);
	
		//std::random_device random_number_device;
		//std::unique_ptr<CustomSecurity::DataObfuscator::CustomDataObfuscator<false>> UDO_Object_Pointer = std::make_unique<CustomSecurity::DataObfuscator::CustomDataObfuscator<false>>(random_number_device(), random_number_device());
	
		auto& UDO_Object = *(UDO_Object_Pointer.get());

		std::array<std::uint8_t, 256> TestDataBytes = CommonToolkit::make_array<std::uint8_t, 256>();
		auto CopyTestDataBytes = TestDataBytes;
		auto UDO_ResultObject = UDO_Object.ExportEncodingAndDecodingTable(CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY);

		std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );

		std::cout << "Origin Byte data is : ";
		for(auto& ByteData : TestDataBytes)
		{
			std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<std::uint32_t>(ByteData) << " ";
		}
		std::cout << std::endl;

		UDO_Object.ImportAndEncodeOrDecode(CopyTestDataBytes, UDO_ResultObject, CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY, true);

		std::cout << "Encode Byte data is : ";
		for(auto& ByteData : CopyTestDataBytes)
		{
			std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<std::uint32_t>(ByteData) << " ";
		}
		std::cout << std::endl;

		UDO_Object.ImportAndEncodeOrDecode(CopyTestDataBytes, UDO_ResultObject, CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY, false);

		std::cout << "Decode Byte data is : ";
		for(auto& ByteData : CopyTestDataBytes)
		{
			std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<std::uint32_t>(ByteData) << " ";
		}
		std::cout << std::endl;

		std::cout.flags(cpp_output_formatflag);
	}

	#endif

	inline void Test_ByteSubstitutionBoxToolkit(std::span<std::uint8_t> ByteDataSecurityTestData)
	{
		using namespace CustomSecurity::ByteSubstitutionBoxToolkit;

		if(ByteDataSecurityTestData.size() != static_cast<std::uint32_t>(::pow(2,8)))
			return;

		std::size_t LogarithmicNumberOfTwoBased = static_cast<std::size_t>(::log2(ByteDataSecurityTestData.size()));

		//pow(2, 8) == 256
		//log(2, 256) == 8

		auto ByteDataSecurityTestData_TransparencyOrder = HelperFunctions::SubstitutionBoxTransparencyOrder(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto ByteDataSecurityTestData_SignalToNoiseRatio_DifferentialPowerAnalysis = HelperFunctions::SubstitutionBox_SNR_DPA(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto ByteDataSecurityTestData_Nonlinearity = HelperFunctions::SubstitutionBoxNonlinearityDegree(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto ByteDataSecurityTestData_PropagationCharacteristics_StrictAvalancheCriteria = HelperFunctions::SubstitutionBox_PC_SAC(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto ByteDataSecurityTestData_DeltaUniformity_Robustness = HelperFunctions::SubstitutionBox_DeltaUniformity_Robustness(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto ByteDataSecurityTestData_AbsoluteValueIndicator = HelperFunctions::SubstitutionBoxAbsoluteValueIndicator(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto ByteDataSecurityTestData_SumOfSquareValueIndicator = HelperFunctions::SubstitutionBoxSumOfSquareValueIndicator(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto ByteDataSecurityTestData_AlgebraicDegree = HelperFunctions::SubstitutionBoxAlgebraicDegree(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto ByteDataSecurityTestData_AlgebraicImmunityDegree = HelperFunctions::SubstitutionBoxAlgebraicImmunityDegree(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);

		std::cout << "ByteDataSecurityTestData Transparency Order Is: " << ByteDataSecurityTestData_TransparencyOrder << std::endl;
		std::cout << "ByteDataSecurityTestData Nonlinearity Is: " << ByteDataSecurityTestData_Nonlinearity.first << std::endl;
		std::cout << "ByteDataSecurityTestData Propagation Characteristics Is: " << ByteDataSecurityTestData_PropagationCharacteristics_StrictAvalancheCriteria.first << std::endl;
		std::cout << "ByteDataSecurityTestData Delta Uniformity Is: " << ByteDataSecurityTestData_DeltaUniformity_Robustness.first << std::endl;
		std::cout << "ByteDataSecurityTestData Robustness Is: " << ByteDataSecurityTestData_DeltaUniformity_Robustness.second << std::endl;
		std::cout << "ByteDataSecurityTestData Signal To Noise Ratio/Differential Power Analysis Is: " << ByteDataSecurityTestData_SignalToNoiseRatio_DifferentialPowerAnalysis << std::endl;
		std::cout << "ByteDataSecurityTestData Absolute Value Indicatorer Is: " <<ByteDataSecurityTestData_AbsoluteValueIndicator.first << std::endl;
		std::cout << "ByteDataSecurityTestData Sum Of Square Value Indicator Is: " << ByteDataSecurityTestData_SumOfSquareValueIndicator.first << std::endl;
		std::cout << "ByteDataSecurityTestData Algebraic Degree Is: " << ByteDataSecurityTestData_AlgebraicDegree.first << std::endl;
		std::cout << "ByteDataSecurityTestData Algebraic Immunity Degree Is: " << ByteDataSecurityTestData_AlgebraicImmunityDegree.first << std::endl;

		std::cout << std::endl;

		//HelperFunctions::ShowDifferentialDistributionTable(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		//HelperFunctions::ShowLinearApproximationTable(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		//HelperFunctions::ShowDifferentialApproximationProbabilityTable(ByteDataSecurityTestData, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
	}

	inline void Test_ByteSubstitutionBoxToolkit_AES()
	{
		using namespace CustomSecurity::ByteSubstitutionBoxToolkit;

		//AES Forward Nonlinear Transfrom with Box
		std::array<std::uint8_t, 256> AES_SubstitutionBox
		{
			0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
			0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
			0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
			0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
			0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
			0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
			0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
			0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
			0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
			0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
			0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
			0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
			0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
			0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
			0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
			0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
		};

		std::size_t LogarithmicNumberOfTwoBased = static_cast<std::size_t>(::log2(AES_SubstitutionBox.size()));

		//pow(2, 8) == 256
		//log(2, 256) == 8

		auto AES_SubstitutionBox_TransparencyOrder = HelperFunctions::SubstitutionBoxTransparencyOrder(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_SignalToNoiseRatio_DifferentialPowerAnalysis = HelperFunctions::SubstitutionBox_SNR_DPA(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_Nonlinearity = HelperFunctions::SubstitutionBoxNonlinearityDegree(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_PropagationCharacteristics_StrictAvalancheCriteria = HelperFunctions::SubstitutionBox_PC_SAC(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_DeltaUniformity_Robustness = HelperFunctions::SubstitutionBox_DeltaUniformity_Robustness(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_AbsoluteValueIndicator = HelperFunctions::SubstitutionBoxAbsoluteValueIndicator(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_SumOfSquareValueIndicator = HelperFunctions::SubstitutionBoxSumOfSquareValueIndicator(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_AlgebraicDegree = HelperFunctions::SubstitutionBoxAlgebraicDegree(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_AlgebraicImmunityDegree = HelperFunctions::SubstitutionBoxAlgebraicImmunityDegree(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);

		std::cout << "This Substitution Box Transparency Order Is: " << AES_SubstitutionBox_TransparencyOrder << std::endl;
		std::cout << "This Substitution Box Nonlinearity Is: " << AES_SubstitutionBox_Nonlinearity.first << std::endl;
		std::cout << "This Substitution Box Propagation Characteristics Is: " << AES_SubstitutionBox_PropagationCharacteristics_StrictAvalancheCriteria.first << std::endl;
		std::cout << "This Substitution Box Delta Uniformity Is: " << AES_SubstitutionBox_DeltaUniformity_Robustness.first << std::endl;
		std::cout << "This Substitution Box Robustness Is: " << AES_SubstitutionBox_DeltaUniformity_Robustness.second << std::endl;
		std::cout << "This Substitution Box Signal To Noise Ratio/Differential Power Analysis Is: " << AES_SubstitutionBox_SignalToNoiseRatio_DifferentialPowerAnalysis << std::endl;
		std::cout << "This Substitution Box Absolute Value Indicatorer Is: " << AES_SubstitutionBox_AbsoluteValueIndicator.first << std::endl;
		std::cout << "This Substitution Box Sum Of Square Value Indicator Is: " << AES_SubstitutionBox_SumOfSquareValueIndicator.first << std::endl;
		std::cout << "This Substitution Box Algebraic Degree Is: " << AES_SubstitutionBox_AlgebraicDegree.first << std::endl;
		std::cout << "This Substitution Box Algebraic Immunity Degree Is: " << AES_SubstitutionBox_AlgebraicImmunityDegree.first << std::endl;

		std::cout << std::endl;
		
		//HelperFunctions::ShowDifferentialDistributionTable(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		//HelperFunctions::ShowLinearApproximationTable(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		//HelperFunctions::ShowDifferentialApproximationProbabilityTable(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
	}

	#if defined(SUBSTITUTIONBOX_GENERATION_TEST)

	inline void Test_CustomByteSubstitutionBox()
	{
		std::array<std::uint8_t, 256> TemporaryClassicByteDatas;
		std::iota(TemporaryClassicByteDatas.begin(), TemporaryClassicByteDatas.end(), 1);

		//AES Forward SubstitutionBox Modified
		std::vector<std::uint8_t> ForwardSubstitutionBox
		{
			0x7F, 0x84, 0x01, 0x2B, 0xC3, 0x4E, 0x55, 0x58, 0x21, 0x62, 0x64, 0xF1, 0xE9, 0x81, 0x6F, 0x6D,
			0x50, 0x71, 0x72, 0x61, 0xF2, 0xA9, 0xBB, 0xD7, 0xB7, 0xF8, 0x00, 0x74, 0xF4, 0x05, 0x76, 0x6E,
			0xE8, 0x8F, 0x78, 0x34, 0xF9, 0x28, 0xF3, 0x54, 0x3A, 0x6C, 0x14, 0x02, 0x1D, 0x7B, 0xA8, 0x5E,
			0x98, 0x25, 0x3F, 0x87, 0xC0, 0x8A, 0x79, 0xE2, 0xBA, 0xE5, 0xC1, 0x24, 0xFB, 0x13, 0xF7, 0xCF,
			0xB4, 0x12, 0x07, 0x95, 0xFC, 0x8D, 0xDA, 0x5B, 0x3C, 0x53, 0xD4, 0x09, 0x39, 0x4B, 0xEA, 0x27,
			0xDD, 0xB9, 0x75, 0xB6, 0x49, 0xD5, 0x42, 0x3E, 0xCD, 0xF6, 0x7D, 0x5F, 0x17, 0xA1, 0xEF, 0xD3,
			0x0F, 0x0B, 0x52, 0x2F, 0xDC, 0x46, 0x80, 0x30, 0xA0, 0x99, 0x06, 0x56, 0xFF, 0xE0, 0xB1, 0xB0,
			0x1E, 0x60, 0x32, 0x8E, 0xA3, 0x67, 0x51, 0x7E, 0xBE, 0x15, 0xCA, 0x8C, 0x3B, 0xAB, 0xA4, 0x16,
			0x19, 0xA7, 0xC9, 0x4D, 0x43, 0x94, 0x89, 0xCC, 0x3D, 0x70, 0x85, 0x59, 0x2E, 0xD1, 0xEE, 0x9E,
			0x5D, 0x8B, 0x69, 0x77, 0x29, 0xD2, 0x44, 0x63, 0x5C, 0x82, 0x65, 0x45, 0x36, 0x1A, 0xD0, 0x88,
			0xAD, 0xD6, 0x9F, 0xAC, 0x7A, 0x4F, 0x9B, 0x41, 0xE7, 0x47, 0x2A, 0xB2, 0xE1, 0x0D, 0xDF, 0x97,
			0x26, 0xC5, 0x38, 0x6B, 0xFD, 0x2D, 0xEC, 0xF5, 0xC8, 0x10, 0x93, 0x20, 0x37, 0x9A, 0xAA, 0xA2,
			0xC4, 0xB3, 0xC6, 0xA6, 0x6A, 0xDB, 0x57, 0x0A, 0xAE, 0x9C, 0xE3, 0x08, 0x03, 0x1F, 0xD8, 0x2C,
			0x90, 0xB5, 0x0C, 0x83, 0x40, 0x23, 0x68, 0x91, 0xBC, 0x22, 0x33, 0x66, 0x18, 0xAF, 0x1B, 0xCE,
			0x4C, 0xE4, 0xF0, 0xFE, 0x5A, 0x0E, 0x04, 0x35, 0x11, 0xBD, 0x73, 0xFA, 0xEB, 0x9D, 0x7C, 0x48,
			0x1C, 0xD9, 0x4A, 0xC2, 0xA5, 0xC7, 0x86, 0xED, 0xDE, 0xBF, 0x96, 0xB8, 0x92, 0x31, 0xCB, 0xE6,
		};

		//AES Backward SubstitutionBox Modified
		std::vector<std::uint8_t> BackwardSubstitutionBox(256, 0x00);

		for (std::size_t ByteData = 0; ByteData < 256; ByteData++)
		{
			BackwardSubstitutionBox[ ForwardSubstitutionBox[ByteData] ] = ByteData;
		}

		std::cout << std::endl;
		std::size_t byte_counter = 0;
		for(const auto& byte : ForwardSubstitutionBox )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		std::cout << std::endl;
		byte_counter = 0;
		for(const auto& byte : BackwardSubstitutionBox )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		/*std::ranges::transform
		(
			TemporaryClassicByteDatas.begin(), 
			TemporaryClassicByteDatas.end(), 
			TemporaryClassicByteDatas.begin(),
			[&ForwardSubstitutionBox](const std::uint8_t& byte) -> std::uint8_t
			{ 
				return ForwardSubstitutionBox[ ForwardSubstitutionBox[byte] ];
			}
		);

		std::ranges::transform
		(
			TemporaryClassicByteDatas.begin(), 
			TemporaryClassicByteDatas.end(), 
			TemporaryClassicByteDatas.begin(),
			[&BackwardSubstitutionBox](const std::uint8_t &byte) -> std::uint8_t
			{ 
				return BackwardSubstitutionBox[ BackwardSubstitutionBox[byte] ];
			}
		);*/
	}

	inline void Test_GenerationSubstitutionBoxWithShuffleArray(std::span<std::uint8_t> ByteKeyData)
	{
		std::vector<std::uint8_t> ForwardSubstitutionBox(256, 0x00);
		std::iota(ForwardSubstitutionBox.begin(), ForwardSubstitutionBox.end(), 1);
		std::vector<std::uint8_t> BackwardSubstitutionBox(256, 0x00);

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateSubstitutionBoxPairStartTime = std::chrono::system_clock::now();

		Cryptograph::DataPermutation::CoderWithKey<std::uint8_t, std::uint8_t> Coder(ByteKeyData, 256);

		CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG(ByteKeyData.begin(), ByteKeyData.end());
		Coder.Shuffle(PRNG, ForwardSubstitutionBox, true);

		for(std::size_t SubstitutionBoxIndex = 0; SubstitutionBoxIndex < 256; ++SubstitutionBoxIndex)
		{
			std::uint8_t ValueOfSubstitutionBox = ForwardSubstitutionBox[SubstitutionBoxIndex];
			BackwardSubstitutionBox[ValueOfSubstitutionBox] = SubstitutionBoxIndex;
		}

		std::chrono::time_point<std::chrono::system_clock> generateSubstitutionBoxPairEndTime = std::chrono::system_clock::now();
		TimeSpent = generateSubstitutionBoxPairEndTime - generateSubstitutionBoxPairStartTime;
		std::cout << "The time spent to generate this pair of substitution box data: " << TimeSpent.count() << "s" << std::endl;

		Test_ByteSubstitutionBoxToolkit(ForwardSubstitutionBox);
		Test_ByteSubstitutionBoxToolkit(BackwardSubstitutionBox);
	}

	#if defined(SUBSTITUTIONBOX_GENERATION_TEST) && defined(SUBSTITUTIONBOX_GENERATION_THEORY_EXPERIMENTAL)

	using namespace CustomSecurity::SubstitutionBoxGenerationTheoryExperimental;

	inline void Test_GenerationSubstitutionBoxWithHashValues(std::vector<std::uint8_t>& ByteKeyData)
	{
		using namespace CustomSecurity::SubstitutionBoxGenerationTheoryExperimental;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateSubstitutionBoxPairStartTime = std::chrono::system_clock::now();

		SubstitutionBoxGenerationWithHashedKey<CommonSecurity::SHA::Version2::HashProvider, CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512> SubstitutionBoxGeneratorWithHashedKeyObject;
		auto[ForwardSubstitutionBox, BackwardSubstitutionBox] = SubstitutionBoxGeneratorWithHashedKeyObject(ByteKeyData, 1);

		std::chrono::time_point<std::chrono::system_clock> generateSubstitutionBoxPairEndTime = std::chrono::system_clock::now();
		TimeSpent = generateSubstitutionBoxPairEndTime - generateSubstitutionBoxPairStartTime;
		std::cout << "The time spent to generate this pair of substitution box data: " << TimeSpent.count() << "s" << std::endl;

		Test_ByteSubstitutionBoxToolkit(ForwardSubstitutionBox);
		Test_ByteSubstitutionBoxToolkit(BackwardSubstitutionBox);
	}

	inline void Test_SubstitutionBoxGenerationUsingChaoticSineMap()
	{
		using namespace CustomSecurity::SubstitutionBoxGenerationTheoryExperimental;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateSubstitutionBoxPairStartTime = std::chrono::system_clock::now();
		
		SubstitutionBoxGenerationUsingChaoticSineMapWithKey SubstitutionBoxGenerationUsingChaoticSineMapWithKeyObject;
		auto[ForwardSubstitutionBox, BackwardSubstitutionBox] = SubstitutionBoxGenerationUsingChaoticSineMapWithKeyObject.Test();

		std::chrono::time_point<std::chrono::system_clock> generateSubstitutionBoxPairEndTime = std::chrono::system_clock::now();
		TimeSpent = generateSubstitutionBoxPairEndTime - generateSubstitutionBoxPairStartTime;
		std::cout << "The time spent to generate this pair of substitution box data: " << TimeSpent.count() << "s" << std::endl;

		Test_ByteSubstitutionBoxToolkit(ForwardSubstitutionBox);
		Test_ByteSubstitutionBoxToolkit(BackwardSubstitutionBox);
	}

	inline void Test_SubstitutionBoxGenerationUsingChaoticSineMapWithKey(std::span<std::uint8_t> ByteKeyData)
	{
		using namespace CustomSecurity::SubstitutionBoxGenerationTheoryExperimental;
		
		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateSubstitutionBoxPairStartTime = std::chrono::system_clock::now();
		
		SubstitutionBoxGenerationUsingChaoticSineMapWithKey SubstitutionBoxGenerationUsingChaoticSineMapWithKeyObject;
		CommonSecurity::RNG_Xorshiro::xoshiro1024 PRNG(ByteKeyData.begin(), ByteKeyData.end());
		auto[ForwardSubstitutionBox, BackwardSubstitutionBox] = SubstitutionBoxGenerationUsingChaoticSineMapWithKeyObject.WorkerFunction(PRNG);

		std::chrono::time_point<std::chrono::system_clock> generateSubstitutionBoxPairEndTime = std::chrono::system_clock::now();
		TimeSpent = generateSubstitutionBoxPairEndTime - generateSubstitutionBoxPairStartTime;
		std::cout << "The time spent to generate this pair of substitution box data: " << TimeSpent.count() << "s" << std::endl;

		Test_ByteSubstitutionBoxToolkit(ForwardSubstitutionBox);
		Test_ByteSubstitutionBoxToolkit(BackwardSubstitutionBox);
	}

	#endif

	#endif

	#if defined(BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST)

	inline void Test_BlockCryptograph_TripleDES()
	{
		std::vector<std::uint8_t> Key;
		std::vector<std::uint8_t> EncryptedBytesData;
		std::vector<std::uint8_t> DecryptedBytesData;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generatePasswordStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generatePasswordEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();

		generatePasswordStartTime = std::chrono::system_clock::now();

		std::cout << "KEY" << std::endl;
		//576
		while (Key.size() != 576)
		{
			Key.push_back(static_cast<std::uint8_t>(UniformNumberDistribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		generatePasswordEndTime = std::chrono::system_clock::now();

		TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
		std::cout << "The time spent generating the password: " << TimeSpent.count() << "s" << std::endl;

		CommonSecurity::TripleDES::OfficialWorker TripleDES_Worker;

		#if 0

		/*std::bitset<64> _DefaultBitsetKey_(static_cast<std::uint64_t>(731982465));
		CommonSecurity::TripleDES::ExperimentalWorker TripleDES_ExperimentalWorker(_DefaultBitsetKey_);*/

		std::bitset<64> BitsetData(static_cast<std::uint64_t>(6753387039482051485));
		std::bitset<64> BitsetKey(static_cast<std::uint64_t>(8758140076359010905));

		/*
			Private function implementation of the triple DES class
			三重DES类的私有函数实现
		*/
		TripleDES_ExperimentalWorker.UpadateMainKeyAndSubKey(BitsetKey);
		TripleDES_WorkerBuffer.Bitset64Object_Plain = BitsetData;
		std::cout << BitsetData.to_string() << std::endl;
		TripleDES_ExperimentalWorkerr.DES_Executor(TripleDES_WorkerBuffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER);
		std::cout << TripleDES_WorkerBuffer.Bitset64Object_Cipher.to_string() << std::endl;
		TripleDES_ExperimentalWorker.DES_Executor(TripleDES_WorkerBuffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER);
		std::cout << TripleDES_WorkerBuffer.Bitset64Object_Plain.to_string() << std::endl;

		#endif

		std::deque<std::vector<std::uint8_t>> KeyChain;
		CommonToolkit::ProcessingDataBlock::splitter(Key, KeyChain, sizeof(std::uint64_t) * 3, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Move);

		auto TripleDES_BytesDataCopy = CommonRandomDataObject.RandomClassicBytesData;

		generateEncryptionStartTime = std::chrono::system_clock::now();

		CommonSecurity::TripleDES::TripleDES_Executor(TripleDES_Worker, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, CommonRandomDataObject.RandomClassicBytesData, KeyChain, EncryptedBytesData);
		std::cout << "BytesData - TripleDES Encrypted" << std::endl;

		generateEncryptionEndTime = std::chrono::system_clock::now();

		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent TripleDES encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		std::cout << std::endl;

		generateDecryptionStartTime = std::chrono::system_clock::now();

		CommonSecurity::TripleDES::TripleDES_Executor(TripleDES_Worker, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, EncryptedBytesData, KeyChain, DecryptedBytesData);
		std::cout << "BytesData - TripleDES Decrypted" << std::endl;

		generateDecryptionEndTime = std::chrono::system_clock::now();

		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent TripleDES decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		std::cout << std::endl;

		if(TripleDES_BytesDataCopy != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;

			UsedAlgorithmByteDataDifferences("TripleDES", CommonRandomDataObject.RandomClassicBytesData, EncryptedBytesData);

			auto ShannonInformationEntropyValue0 = ShannonInformationEntropy(EncryptedBytesData);
			std::cout << "Encrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue0 << std::endl;
			auto ShannonInformationEntropyValue1 = ShannonInformationEntropy(DecryptedBytesData);
			std::cout << "Decrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue1 << std::endl;
			
			if(ShannonInformationEntropyValue0 > ShannonInformationEntropyValue1)
				std::cout << "Difference of entropy degree of sequential data :" << ShannonInformationEntropyValue0 - ShannonInformationEntropyValue1  << std::endl;
		}
	}

	#endif

	class BlockCipherTest
	{

	protected:

		static constexpr std::array<std::uint8_t, 16> PlainText128
		{
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};

		static constexpr std::array<std::uint8_t, 32> PlainText256
		{
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};

		static constexpr std::array<std::uint8_t, 16> InitialVector
		{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F
		};

		static constexpr std::array<std::uint8_t, 16> Keys128
		{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F
		};

		static constexpr std::array<std::uint8_t, 24> Keys192
		{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F,
			0x1F, 0x1E, 0x1D, 0x1C,
			0x1B, 0x1A, 0x19, 0x18
		};

		static constexpr std::array<std::uint8_t, 32> Keys256
		{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F,
			0x1F, 0x1E, 0x1D, 0x1C,
			0x1B, 0x1A, 0x19, 0x18,
			0x17, 0x16, 0x15, 0x14,
			0x13, 0x12, 0x11, 0x10
		};

	public:

		virtual void SanityCheck() = 0;

		BlockCipherTest() = default;
		virtual ~BlockCipherTest() = default;
	};

	class AES_Tester256 : BlockCipherTest
	{
		
	private:
		CommonSecurity::AES::DataWorker256 AES_128_256;

	public:
		void SanityCheck() override
		{
			std::array<std::uint8_t, 16> CipherText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> CipherText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 16> TestText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> TestText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			AES_128_256.EncryptionWithECB(PlainText128, Keys256, CipherText128);
	
			AES_128_256.DecryptionWithECB(CipherText128, Keys256, TestText128);

			if(TestText128 != PlainText128)
				std::cout << "AES(ECB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "AES(ECB Mode) 128-256 cipher is OK." << std::endl;

			AES_128_256.EncryptionWithCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			AES_128_256.DecryptionWithCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "AES(CBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "AES(CBC Mode) 128-256 cipher is OK." << std::endl;

			AES_128_256.EncryptionWithPCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			AES_128_256.DecryptionWithPCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "AES(PCBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "AES(PCBC Mode) 128-256 cipher is OK." << std::endl;

			AES_128_256.EncryptionWithCFB(InitialVector, PlainText256, Keys256, CipherText256);
	
			AES_128_256.DecryptionWithCFB(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "AES(CFB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "AES(CFB Mode) 128-256 cipher is OK." << std::endl;

			AES_128_256.CTR_StreamModeBasedEncryptFunction(PlainText256, Keys256, CipherText256);
	
			AES_128_256.CTR_StreamModeBasedEncryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "AES(Counter Mode Based Encrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "AES(Counter Mode Based Encrypt Function) 128-256 cipher is OK." << std::endl;

			AES_128_256.CTR_StreamModeBasedDecryptFunction(PlainText256, Keys256, CipherText256);
	
			AES_128_256.CTR_StreamModeBasedDecryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "AES(Counter Mode Based Decrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "AES(Counter Mode Based Decrypt Function) 128-256 cipher is OK." << std::endl;
		}
	};

	class RC6_Tester256 : BlockCipherTest
	{
		
	private:
		CommonSecurity::RC6::DataWorker128_256 RC6_128_256;

	public:
		void SanityCheck() override
		{
			std::array<std::uint8_t, 16> CipherText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> CipherText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 16> TestText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> TestText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			RC6_128_256.EncryptionWithECB(PlainText128, Keys256, CipherText128);
	
			RC6_128_256.DecryptionWithECB(CipherText128, Keys256, TestText128);

			if(TestText128 != PlainText128)
				std::cout << "RC6(ECB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "RC6(ECB Mode) 128-256 cipher is OK." << std::endl;

			RC6_128_256.EncryptionWithCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			RC6_128_256.DecryptionWithCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "RC6(CBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "RC6(CBC Mode) 128-256 cipher is OK." << std::endl;

			RC6_128_256.EncryptionWithPCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			RC6_128_256.DecryptionWithPCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "RC6(PCBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "RC6(PCBC Mode) 128-256 cipher is OK." << std::endl;

			RC6_128_256.EncryptionWithCFB(InitialVector, PlainText256, Keys256, CipherText256);
	
			RC6_128_256.DecryptionWithCFB(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "RC6(CFB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "RC6(CFB Mode) 128-256 cipher is OK." << std::endl;

			RC6_128_256.CTR_StreamModeBasedEncryptFunction(PlainText256, Keys256, CipherText256);
	
			RC6_128_256.CTR_StreamModeBasedEncryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "RC6(Counter Mode Based Encrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "RC6(Counter Mode Based Encrypt Function) 128-256 cipher is OK." << std::endl;

			RC6_128_256.CTR_StreamModeBasedDecryptFunction(PlainText256, Keys256, CipherText256);
	
			RC6_128_256.CTR_StreamModeBasedDecryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "RC6(Counter Mode Based Decrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "RC6(Counter Mode Based Decrypt Function) 128-256 cipher is OK." << std::endl;
		}
	};

	class SM4_Tester256 : BlockCipherTest
	{
		
	private:
		CommonSecurity::ChinaShangYongMiMa4::DataWorker256 SM4_128_256;

	public:
		void SanityCheck() override
		{
			std::array<std::uint8_t, 16> CipherText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> CipherText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 16> TestText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> TestText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			SM4_128_256.EncryptionWithECB(PlainText128, Keys256, CipherText128);
	
			SM4_128_256.DecryptionWithECB(CipherText128, Keys256, TestText128);

			if(TestText128 != PlainText128)
				std::cout << "SM4(ECB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "SM4(ECB Mode) 128-256 cipher is OK." << std::endl;

			SM4_128_256.EncryptionWithCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			SM4_128_256.DecryptionWithCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "SM4(CBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "SM4(CBC Mode) 128-256 cipher is OK." << std::endl;

			SM4_128_256.EncryptionWithPCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			SM4_128_256.DecryptionWithPCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "SM4(PCBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "SM4(PCBC Mode) 128-256 cipher is OK." << std::endl;

			SM4_128_256.EncryptionWithCFB(InitialVector, PlainText256, Keys256, CipherText256);
	
			SM4_128_256.DecryptionWithCFB(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "SM4(CFB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "SM4(CFB Mode) 128-256 cipher is OK." << std::endl;

			SM4_128_256.CTR_StreamModeBasedEncryptFunction(PlainText256, Keys256, CipherText256);
	
			SM4_128_256.CTR_StreamModeBasedEncryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "SM4(Counter Mode Based Encrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "SM4(Counter Mode Based Encrypt Function) 128-256 cipher is OK." << std::endl;

			SM4_128_256.CTR_StreamModeBasedDecryptFunction(PlainText256, Keys256, CipherText256);
	
			SM4_128_256.CTR_StreamModeBasedDecryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "SM4(Counter Mode Based Decrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "SM4(Counter Mode Based Decrypt Function) 128-256 cipher is OK." << std::endl;
		}
	};

	class Twofish_Tester256 : BlockCipherTest
	{
		
	private:
		CommonSecurity::Twofish::DataWorker256 Twofish_128_256;

	public:
		void SanityCheck() override
		{
			std::array<std::uint8_t, 16> CipherText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> CipherText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 16> TestText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> TestText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			Twofish_128_256.EncryptionWithECB(PlainText128, Keys256, CipherText128);
	
			Twofish_128_256.DecryptionWithECB(CipherText128, Keys256, TestText128);

			if(TestText128 != PlainText128)
				std::cout << "Twofish(ECB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Twofish(ECB Mode) 128-256 cipher is OK." << std::endl;

			Twofish_128_256.EncryptionWithCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			Twofish_128_256.DecryptionWithCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Twofish(CBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Twofish(CBC Mode) 128-256 cipher is OK." << std::endl;

			Twofish_128_256.EncryptionWithPCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			Twofish_128_256.DecryptionWithPCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Twofish(PCBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Twofish(PCBC Mode) 128-256 cipher is OK." << std::endl;

			Twofish_128_256.EncryptionWithCFB(InitialVector, PlainText256, Keys256, CipherText256);
	
			Twofish_128_256.DecryptionWithCFB(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Twofish(CFB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Twofish(CFB Mode) 128-256 cipher is OK." << std::endl;

			Twofish_128_256.CTR_StreamModeBasedEncryptFunction(PlainText256, Keys256, CipherText256);
	
			Twofish_128_256.CTR_StreamModeBasedEncryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Twofish(Counter Mode Based Encrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Twofish(Counter Mode Based Encrypt Function) 128-256 cipher is OK." << std::endl;

			Twofish_128_256.CTR_StreamModeBasedDecryptFunction(PlainText256, Keys256, CipherText256);
	
			Twofish_128_256.CTR_StreamModeBasedDecryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Twofish(Counter Mode Based Decrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Twofish(Counter Mode Based Decrypt Function) 128-256 cipher is OK." << std::endl;
		}
	};

	class Serpent_Tester256 : BlockCipherTest
	{
		
	private:
		CommonSecurity::Serpent::DataWorker256 Serpent_128_256;

	public:
		void SanityCheck() override
		{
			std::array<std::uint8_t, 16> CipherText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> CipherText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 16> TestText128
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			std::array<std::uint8_t, 32> TestText256
			{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
			};

			Serpent_128_256.EncryptionWithECB(PlainText128, Keys256, CipherText128);
	
			Serpent_128_256.DecryptionWithECB(CipherText128, Keys256, TestText128);

			if(TestText128 != PlainText128)
				std::cout << "Serpent(ECB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Serpent(ECB Mode) 128-256 cipher is OK." << std::endl;

			Serpent_128_256.EncryptionWithCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			Serpent_128_256.DecryptionWithCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Serpent(CBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Serpent(CBC Mode) 128-256 cipher is OK." << std::endl;

			Serpent_128_256.EncryptionWithPCBC(InitialVector, PlainText256, Keys256, CipherText256);
	
			Serpent_128_256.DecryptionWithPCBC(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Serpent(PCBC Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Serpent(PCBC Mode) 128-256 cipher is OK." << std::endl;

			Serpent_128_256.EncryptionWithCFB(InitialVector, PlainText256, Keys256, CipherText256);
	
			Serpent_128_256.DecryptionWithCFB(InitialVector, CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Serpent(CFB Mode) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Serpent(CFB Mode) 128-256 cipher is OK." << std::endl;

			Serpent_128_256.CTR_StreamModeBasedEncryptFunction(PlainText256, Keys256, CipherText256);
	
			Serpent_128_256.CTR_StreamModeBasedEncryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Serpent(Counter Mode Based Encrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Serpent(Counter Mode Based Encrypt Function) 128-256 cipher is OK." << std::endl;

			Serpent_128_256.CTR_StreamModeBasedDecryptFunction(PlainText256, Keys256, CipherText256);
	
			Serpent_128_256.CTR_StreamModeBasedDecryptFunction(CipherText256, Keys256, TestText256);

			if(TestText256 != PlainText256)
				std::cout << "Serpent(Counter Mode Based Decrypt Function) 128-256 cipher is Error !" << std::endl;
			else
				std::cout << "Serpent(Counter Mode Based Decrypt Function) 128-256 cipher is OK." << std::endl;
		}
	};
	
	inline void Test_BlockCryptograph_AES()
	{
		AES_Tester256 Tester;
		Tester.SanityCheck();
	}

	inline void Test_BlockCryptograph_RC6()
	{
		RC6_Tester256 Tester;
		Tester.SanityCheck();
	}

	inline void Test_BlockCryptograph_ChinaShangYongMiMa()
	{
		SM4_Tester256 Tester;
		Tester.SanityCheck();
	}

	inline void Test_BlockCryptograph_Twofish()
	{
		Twofish_Tester256 Tester;
		Tester.SanityCheck();
	}

	inline void Test_BlockCryptograph_Serpent()
	{
		Serpent_Tester256 Tester;
		Tester.SanityCheck();
	}

	#if defined(STREAM_CRYPTOGRAPH_TEST)

	inline void Test_StreamCryptograph()
	{
		using namespace CommonSecurity::StreamDataCryptographic;

		std::vector<std::uint8_t> BytesDataInitialVector;
		std::vector<std::uint8_t> InitialKey;
		std::vector<std::uint8_t> Key;
		std::vector<std::uint8_t> EncryptedBytesData;
		std::vector<std::uint8_t> DecryptedBytesData;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generatePasswordStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generatePasswordEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateByteInitialVectorStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateByteInitialVectorEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();

		//
		generatePasswordStartTime = std::chrono::system_clock::now();

		std::cout << "INITIAL KEY" << std::endl;
		//256
		while (InitialKey.size() != WorkerBase::BYTE_SIZE_OF_KEYS)
		{
			InitialKey.push_back(static_cast<std::uint8_t>(UniformNumberDistribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		std::cout << "KEY" << std::endl;
		//256
		while (Key.size() != 2048)
		{
			Key.push_back(static_cast<std::uint8_t>(UniformNumberDistribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		ExtendedChaCha20 ECC20_Object(InitialKey);

		generatePasswordEndTime = std::chrono::system_clock::now();

		TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
		std::cout << "The time spent generating the byte data key and inintal key: " << TimeSpent.count() << "s" << std::endl;

		generateByteInitialVectorStartTime = std::chrono::system_clock::now();

		std::cout << "BytesData - InitialVector" << std::endl;
		//256
		while (BytesDataInitialVector.size() != ECC20_Object.ByteSizeOfNonces())
		{
			BytesDataInitialVector.push_back(static_cast<std::uint8_t>(UniformNumberDistribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		generateByteInitialVectorEndTime = std::chrono::system_clock::now();

		TimeSpent = generateByteInitialVectorEndTime - generateByteInitialVectorStartTime;
		std::cout << "The time spent generating the byte data initial vector: " << TimeSpent.count() << "s" << std::endl;

		//

		auto CopiedMessageData = CommonRandomDataObject.RandomClassicBytesData;
		auto CopiedKey = Key;
		auto CopiedBytesDataInitialVector = BytesDataInitialVector;

		generateEncryptionStartTime = std::chrono::system_clock::now();

		EncryptedBytesData = Helpers::Helper(ECC20_Object, CopiedMessageData, Key, BytesDataInitialVector);

		std::cout << "BytesData - StreamCryptograph - ExtendedChaCha20 Encrypted" << std::endl;

		std::cout << "\n";

		generateEncryptionEndTime = std::chrono::system_clock::now();

		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent StreamCryptograph - ExtendedChaCha20 encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		auto CopiedEncryptedBytesData = EncryptedBytesData;

		ECC20_Object.UpdateKey(InitialKey);

		generateDecryptionStartTime = std::chrono::system_clock::now();

		DecryptedBytesData = Helpers::Helper(ECC20_Object, CopiedEncryptedBytesData, CopiedKey, CopiedBytesDataInitialVector);

		std::cout << "BytesData - StreamCryptograph - ExtendedChaCha20 Decrypted" << std::endl;

		std::cout << "\n";

		generateDecryptionEndTime = std::chrono::system_clock::now();

		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent StreamCryptograph - ExtendedChaCha20 decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		if(CommonRandomDataObject.RandomClassicBytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;

			UsedAlgorithmByteDataDifferences("StreamCryptograph - ExtendedChaCha20", CommonRandomDataObject.RandomClassicBytesData, EncryptedBytesData);

			auto ShannonInformationEntropyValue0 = ShannonInformationEntropy(EncryptedBytesData);
			std::cout << "Encrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue0 << std::endl;
			auto ShannonInformationEntropyValue1 = ShannonInformationEntropy(DecryptedBytesData);
			std::cout << "Decrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue1 << std::endl;
			
			if(ShannonInformationEntropyValue0 > ShannonInformationEntropyValue1)
				std::cout << "Difference of entropy degree of sequential data :" << ShannonInformationEntropyValue0 - ShannonInformationEntropyValue1  << std::endl;
		}



		InitialKey.clear();
		Key.clear();
		BytesDataInitialVector.clear();

		generatePasswordStartTime = std::chrono::system_clock::now();

		std::cout << "INITIAL KEY" << std::endl;
		//256
		while (InitialKey.size() != WorkerBase::BYTE_SIZE_OF_KEYS)
		{
			InitialKey.push_back(static_cast<std::uint8_t>(UniformNumberDistribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		std::cout << "KEY" << std::endl;
		//256
		while (Key.size() != 2048)
		{
			Key.push_back(static_cast<std::uint8_t>(UniformNumberDistribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		ExtendedSalsa20 ES20_Object(InitialKey);

		generatePasswordEndTime = std::chrono::system_clock::now();

		TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
		std::cout << "The time spent generating the byte data key and inintal key: " << TimeSpent.count() << "s" << std::endl;

		generateByteInitialVectorStartTime = std::chrono::system_clock::now();

		std::cout << "BytesData - InitialVector" << std::endl;
		//256
		while (BytesDataInitialVector.size() != ES20_Object.ByteSizeOfNonces())
		{
			BytesDataInitialVector.push_back(static_cast<std::uint8_t>(UniformNumberDistribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		generateByteInitialVectorEndTime = std::chrono::system_clock::now();

		TimeSpent = generateByteInitialVectorEndTime - generateByteInitialVectorStartTime;
		std::cout << "The time spent generating the byte data initial vector: " << TimeSpent.count() << "s" << std::endl;

		//

		CopiedMessageData = CommonRandomDataObject.RandomClassicBytesData;
		CopiedKey = Key;
		CopiedBytesDataInitialVector = BytesDataInitialVector;

		generateEncryptionStartTime = std::chrono::system_clock::now();

		EncryptedBytesData = Helpers::Helper(ES20_Object, CopiedMessageData, Key, BytesDataInitialVector);

		std::cout << "BytesData - StreamCryptograph - ExtendedSalsa20 Encrypted" << std::endl;

		std::cout << "\n";

		generateEncryptionEndTime = std::chrono::system_clock::now();

		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent StreamCryptograph - ExtendedSalsa20 encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		CopiedEncryptedBytesData = EncryptedBytesData;

		ES20_Object.UpdateKey(InitialKey);

		generateDecryptionStartTime = std::chrono::system_clock::now();

		DecryptedBytesData = Helpers::Helper(ES20_Object, CopiedEncryptedBytesData, CopiedKey, CopiedBytesDataInitialVector);

		std::cout << "BytesData - StreamCryptograph - ExtendedSalsa20 Decrypted" << std::endl;

		std::cout << "\n";

		generateDecryptionEndTime = std::chrono::system_clock::now();

		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent StreamCryptograph - ExtendedSalsa20 decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		if(CommonRandomDataObject.RandomClassicBytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;

			UsedAlgorithmByteDataDifferences("StreamCryptograph - ExtendedSalsa20", CommonRandomDataObject.RandomClassicBytesData, EncryptedBytesData);

			auto ShannonInformationEntropyValue0 = ShannonInformationEntropy(EncryptedBytesData);
			std::cout << "Encrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue0 << std::endl;
			auto ShannonInformationEntropyValue1 = ShannonInformationEntropy(DecryptedBytesData);
			std::cout << "Decrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue1 << std::endl;
			
			if(ShannonInformationEntropyValue0 > ShannonInformationEntropyValue1)
				std::cout << "Difference of entropy degree of sequential data :" << ShannonInformationEntropyValue0 - ShannonInformationEntropyValue1  << std::endl;
		}
	}

	#endif

	#define CRYPTOGRAPH_WONDERFUL_DESIGN_IDEAS

	#if defined(CRYPTOGRAPH_WONDERFUL_DESIGN_IDEAS)

	inline void Test_InfiniteGarbledCodeDataGeneration()
	{
		using Cryptograph::CustomizedKDF::IGD_RNG_EnumList;
		using Cryptograph::CustomizedKDF::IGD_Hasher_EnumList;
		using Cryptograph::CustomizedKDF::InfiniteGarbledData;

		InfiniteGarbledData infinite_garbled_data_object = InfiniteGarbledData(IGD_RNG_EnumList::ISAAC, 1);
		
		#if 1

		std::array<std::uint8_t, 16> personal_key_materials
		{
			std::uint8_t{0},
			std::uint8_t{15},
			std::uint8_t{7},
			std::uint8_t{4},
			std::uint8_t{9},
			std::uint8_t{3},
			std::uint8_t{12},
			std::uint8_t{5},
			std::uint8_t{10},
			std::uint8_t{1},
			std::uint8_t{6},
			std::uint8_t{2},
			std::uint8_t{14},
			std::uint8_t{8},
			std::uint8_t{13},
			std::uint8_t{11},
		};
			
		#else

		std::array<std::uint8_t, 16> personal_key_materials
		{
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
		};

		#endif
		
		//混合的乱码的密钥数据
		//Mixed garbled key data
		auto hash_salted_keys = infinite_garbled_data_object.ComputationGarbledData(personal_key_materials);

		std::cout << "已经生成混合的乱码的密钥数据\n现在展示如下字节(16进制)" << std::endl;
		std::cout << "A mixed mess of key data has been generated\nNow shows the following bytes (in hexadecimal)" << std::endl;

		std::size_t byte_counter = 0;
		for(const auto& byte : hash_salted_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;
	}

	inline void Test_LearningWithErrorModule()
	{
		using Cryptograph::QuantumResistantComputers::LearningWithErrorModule;

		LearningWithErrorModule learning_with_error_modules( CommonSecurity::GenerateSecureRandomNumberSeed<std::uint32_t>(random_device_object) );

		#if 0

		std::array<std::uint8_t, 16> personal_key_materials
		{
			std::uint8_t{0},
			std::uint8_t{15},
			std::uint8_t{7},
			std::uint8_t{4},
			std::uint8_t{9},
			std::uint8_t{3},
			std::uint8_t{12},
			std::uint8_t{5},
			std::uint8_t{10},
			std::uint8_t{1},
			std::uint8_t{6},
			std::uint8_t{2},
			std::uint8_t{14},
			std::uint8_t{8},
			std::uint8_t{13},
			std::uint8_t{11},
		};
			
		#else

		std::array<std::uint8_t, 16> personal_key_materials
		{
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
			std::uint8_t{0},
		};

		#endif

		//噪声数据混合处理过的密钥
		//Mixed processed key for noisy data
		auto secure_random_keys = learning_with_error_modules.KeyGeneration(personal_key_materials);

		std::size_t byte_counter = 0;

		std::cout << "已经生成量子计算机，无法穷举破解的密钥\n现在展示如下字节(16进制)" << std::endl;
		std::cout << "A quantum computer has been generated and the key that cannot be exhaustively cracked\nNow show the following bytes (in hexadecimal) that" << std::endl;

		for(const auto& byte : secure_random_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		std::cout << "首先使用任何一种加密和解密算法生成的乱码（密文）数据，这个乱码(密文)数据然后使用xor操作这个密钥，这可以达到防止量子计算机破解的效果。" << std::endl;
		std::cout << "First use any kind of encryption and decryption algorithm to generate the garbled (ciphertext) data, this garbled (ciphertext) data then use xor to manipulate this key, which can achieve the effect of preventing quantum computers from cracking." << std::endl;
		std::cout << std::endl;
	}

	#endif

	#undef CRYPTOGRAPH_WONDERFUL_DESIGN_IDEAS

	#if defined(BIG_FILE_DATA_TEST) && !defined(SMALL_FILE_DATA_TEST)

	inline void Test_BigFileData_ReadAndWrite()
	{
		//将全局语言区域更改为操作系统默认区域
		//Change the global language region to the OS default region
		//std::locale::global(std::locale(""));

		//Restore global language locale settings
		//还原全局语言区域设定
		//std::locale::global(std::locale("C"));

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> readingFileAndMoveBufferDataStartTime;
		std::chrono::time_point<std::chrono::system_clock> readingFileAndMoveBufferDataEndTime;

		std::chrono::time_point<std::chrono::system_clock> moveBufferDataAndWritingFileStartTime;
		std::chrono::time_point<std::chrono::system_clock> moveBufferDataAndWritingFileEndTime;


		std::string fileHashStringID { "6f1c80df72e2a6d6a291e9db3ded5c2d44ec726265654186cfde6457852d8efa66ed9055de24b49ea6f5ed06d4675bc808d5647595ba0e7133b79bd1a9fe5ae1" };
		std::filesystem::path sourceFilePath(u8"D:\\[Twilight-Dream_Sparkle-Magical_Desktop-Data]\\C++ Project Test\\Linux备忘手册.zip");
		std::filesystem::path targetFilePath(u8"D:\\[Twilight-Dream_Sparkle-Magical_Desktop-Data]\\C++ Project Test\\Linux备忘手册.zip.copy");

		std::unique_ptr<std::deque<std::vector<char>>> pointerFileDataDoubleQueue = std::make_unique<std::deque<std::vector<char>>>();
		std::unique_ptr<Cryptograph::CommonModule::FileDataModuleAdapter> FDCMA_Pointer = std::make_unique<Cryptograph::CommonModule::FileDataModuleAdapter>();

		FileProcessing::Operation::BinaryStreamReader fo_bsr;
		FileProcessing::Operation::BinaryStreamWriter fo_bsw;
		std::size_t dataBlockByteSize = 1024 * 1024;

		readingFileAndMoveBufferDataStartTime = std::chrono::system_clock::now();
		fo_bsr.ReadFileData(fileHashStringID, sourceFilePath, FDCMA_Pointer, pointerFileDataDoubleQueue.get(), dataBlockByteSize);
		readingFileAndMoveBufferDataEndTime = std::chrono::system_clock::now();
		TimeSpent = readingFileAndMoveBufferDataEndTime - readingFileAndMoveBufferDataStartTime;

		std::cout << "File all byte data is readed, time passed: " << TimeSpent.count() << " seconds." << std::endl;

		moveBufferDataAndWritingFileStartTime = std::chrono::system_clock::now();
		fo_bsw.WriteFileData(fileHashStringID, targetFilePath, FDCMA_Pointer, pointerFileDataDoubleQueue.get(), dataBlockByteSize);
		moveBufferDataAndWritingFileEndTime = std::chrono::system_clock::now();
		TimeSpent = moveBufferDataAndWritingFileEndTime - moveBufferDataAndWritingFileStartTime;

		std::cout << "File all byte data is writed, time passed: " << TimeSpent.count() << " seconds." << std::endl;
	}

	#endif

	#undef SMALL_FILE_DATA_TEST

	#undef BIG_FILE_DATA_TEST

	#if defined(SHUFFLE_RANGE_DATA_TEST)

	inline void Test_ShuffleRangeData()
	{
		std::vector<std::size_t> DataSet = CommonToolkit::make_vector(std::make_integer_sequence<size_t, 256>{});

		for (auto data : DataSet)
		{
			std::cout << "Current data is " << data << ", " << std::endl;
		}
		std::cout << std::endl;

		std::mt19937 RNGE_Object{128};

		CommonSecurity::ShuffleRangeData(DataSet.begin(), DataSet.end(), RNGE_Object);

		for (auto data : DataSet)
		{
			std::cout << "Shuffled data is " << data << ", " << std::endl;
		}
	}

	#endif

	//#define DATA_FORMATING_TEST

	#if defined(DATA_FORMATTING_TEST)
	inline void Test_DataFormatting()
	{
		using namespace UtilTools::DataFormating;

		auto binary_string_data = Decimal_Hexadecimal::FromDecimalBuilder<long long int>(-1234567898765432LL, AlphabetFormat::LOWER_CASE);
		std::cout << binary_string_data << std::endl;
	
		auto integer_data = Decimal_Hexadecimal::ToDecimalBuilder<long long int>(binary_string_data, AlphabetFormat::LOWER_CASE, true);
		std::cout << integer_data << std::endl;
	}

	#endif

	//#define DATASTREAM_PACKER_AND_UNPACKER_TEST
	#if defined(UTILITY_LIBRARY_DATASTREAM_PACKER_AND_UNPACKER_TEST)

	inline void Test_UtilityLibrary_DataStreamPackerAndUnpacker()
	{
		std::vector<std::uint8_t> characters { 0, 12, 23, 24, 67, 34, 53, 89, 71, 53, 91, 46, 58, 63, 11, 87 };
		std::vector<std::uint32_t> integers;

		std::vector<std::uint8_t> characters2;
		std::vector<std::uint64_t> integers2;

		std::span<const std::uint8_t> character_span { character_span.begin(), character_span.end() };
		std::span<const std::uint32_t> integer_span { integers.begin(), integers.end() };

		CommonToolkit::IntegerExchangeBytes::MessagePacking(character_span, integers.data());
		CommonToolkit::IntegerExchangeBytes::MessageUnpacking(integer_span, characters2.data());

		if(characters != characters2)
		{
			std::cout << "Data Conversion Error!" << std::endl;
		}
		else
		{
			std::cout << "Data Conversion Worked!" << std::endl;
		}

		characters2.clear();
		characters2.shrink_to_fit();

		std::span<const std::uint64_t> integer2_span { integers2.begin(), integers2.end() };

		CommonToolkit::IntegerExchangeBytes::MessagePacking(character_span, integers2.data());
		CommonToolkit::IntegerExchangeBytes::MessageUnpacking(integer2_span, characters2.data());

		if(characters != characters2)
		{
			std::cout << "Data Conversion Error!" << std::endl;
		}
		else
		{
			std::cout << "Data Conversion Worked!" << std::endl;
		}
	}

	#endif
	#undef UTILITY_LIBRARY_DATASTREAM_PACKER_AND_UNPACKER_TEST

	//#define UTILITY_LIBRARY_BITSET_TOOLS_TEST
	#if defined(UTILITY_LIBRARY_BITSET_TOOLS_TEST)

	inline void Test_UtilityLibrary_BitsetTools()
	{
		std::bitset<13> BinaryDataA(0b0110100110011);
		std::bitset<13> BinaryDataB(0b1001100100100);
	
		std::cout << BinaryDataA.to_string() << std::endl;
		std::cout << BinaryDataB.to_string() << std::endl;
		std::bitset<26> BinaryDataC = Cryptograph::Bitset::ConcatenateBitset(BinaryDataA, BinaryDataB, false);
		std::cout << BinaryDataC.to_string() << std::endl;

		auto BinaryDataPair = Cryptograph::Bitset::SplitBitset<BinaryDataC.size(), 13>(BinaryDataC);

		std::cout << BinaryDataPair.first.to_string() << std::endl;
		std::cout << BinaryDataPair.second.to_string() << std::endl;

		std::vector<char> characters { 0, 12, 23, 24, 67, 34, 53, 89 };
		auto Bitset64Object = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(characters);
		std::cout << Bitset64Object.to_string() << std::endl;
		auto CharacterArray = Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(Bitset64Object);
	}

	#endif
	#undef UTILITY_LIBRARY_BITSET_TOOLS_TEST

	#if defined(BUILDING_KEYSTREAM_TEST)

	inline void Test_BuildingKeyStream()
	{
		using namespace CommonSecurity::SHA;
		using namespace CommonSecurity::DataHashingWrapper;

		std::vector<std::string> TestFourPasswords { "1qazxsw23edc", "4RFVBGT56YHN", "!)@(#*$&%", "7ujm,ki89ol./;p0" };
		std::size_t NeedKeyStreamSize = 8192;

		HashTokenForDataParameters HashToken_Parameters;
		HashToken_Parameters.HashersAssistantParameters_Instance.hash_mode = Hasher::WORKER_MODE::ARGON2;
		HashToken_Parameters.HashersAssistantParameters_Instance.whether_use_hash_extension_bit_mode = true;
		HashToken_Parameters.HashersAssistantParameters_Instance.generate_hash_bit_size = 1024;
		HashToken_Parameters.OriginalPasswordStrings = TestFourPasswords;
		HashToken_Parameters.NeedHashByteTokenSize = NeedKeyStreamSize;
		auto HaveKeyStream = BuildingKeyStream<256>(HashToken_Parameters);

		std::cout << std::endl;

		#endif // !BUILDING_KEYSTREAM_TEST
	}

	#if defined(DIGEST_CRYPTOGRAPH_TEST)

	inline void Test_DigestCryptograph_SHA()
	{
		using namespace CommonSecurity::DataHashingWrapper;

		std::string test_message = "Hello World - SHA 512 Bit";
		std::cout << test_message << std::endl;
		std::string hashed_string;

		HashersAssistantParameters hashers_assistant_parameters;

		hashers_assistant_parameters.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512;
		hashers_assistant_parameters.inputDataString = test_message;
		std::cout << "SHA2-512 Bit Hash Value:" << std::endl;
		HashersAssistant::SELECT_HASH_FUNCTION(hashers_assistant_parameters);
		hashed_string = hashers_assistant_parameters.outputHashedHexadecimalString;
		std::cout << hashed_string << std::endl;

		hashers_assistant_parameters.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512;
		hashers_assistant_parameters.inputDataString = test_message;
		std::cout << "SHA3-512 Bit Hash Value:" << std::endl;
		HashersAssistant::SELECT_HASH_FUNCTION(hashers_assistant_parameters);
		hashed_string = hashers_assistant_parameters.outputHashedHexadecimalString;
		std::cout << hashed_string << std::endl;

		std::vector<std::string> passwords;

		std::string password = std::string("123456789");
		passwords.push_back(password);
		std::string password2 = std::string("qwertyuiop");
		passwords.push_back(password2);
		std::string password3 = std::string("ASDFGHJKL");
		passwords.push_back(password3);
		std::string password4 = std::string("!@#$%^&*()");
		passwords.push_back(password4);

		std::cout << "Unique SHA3-512 hash token generated with multiple passwords:" << std::endl;
		CommonSecurity::DataHashingWrapper::HashTokenForDataParameters HashTokenHelper_Parameters;
		HashTokenHelper_Parameters.HashersAssistantParameters_Instance.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512;
		HashTokenHelper_Parameters.OriginalPasswordStrings = passwords;
		HashTokenHelper_Parameters.NeedHashByteTokenSize = 64;

		CommonSecurity::DataHashingWrapper::HashTokenForData HashTokenHelper(HashTokenHelper_Parameters);
		auto Optional_HashTokenResult = HashTokenHelper.GenerateKeyStreamHashToken<CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512>(); 

		std::cout << Optional_HashTokenResult.value().HashKeyStreamToken_String << std::endl;
	}

	inline void Test_DigestCryptograph_Blake2()
	{
		std::string TestMessage("Hello World");
		std::cout << "This TestMessage is:\n" << TestMessage << std::endl;
		std::string Blake2HashedMessage(TestMessage);
		CommonSecurity::SHA::Hasher::HasherTools MainHasher;
		//auto optionalHashedHexadecimalString = MainHasher.GenerateBlake2Hashed(Blake2HashedMessage, true, 2048);
		auto optionalHashedHexadecimalString = MainHasher.GenerateBlake2Hashed(Blake2HashedMessage, false, 512);
		if(optionalHashedHexadecimalString.has_value())
			optionalHashedHexadecimalString.value().swap(Blake2HashedMessage);
		else
			throw std::invalid_argument(" If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");
		std::cout << "This TestMessage Transfromed Blake2HashMessage is:\n" << Blake2HashedMessage << std::endl;
	}

	inline void Test_DigestCryptograph_Blake3_Modified()
	{
		std::string TestMessage("Hello World");

		std::cout << "This TestMessage is:\n" << TestMessage << std::endl;

		CommonSecurity::SHA::Hasher::HasherTools MainHasher;

		auto optionalHashedHexadecimalString = MainHasher.GenerateBlake3ModificationHashed(TestMessage, 83886080);
		std::string Blake3ModificationHashedMessage( TestMessage );

		if(optionalHashedHexadecimalString.has_value())
			optionalHashedHexadecimalString.value().swap(Blake3ModificationHashedMessage);
		else
			throw std::invalid_argument(" If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");
		std::cout << "This TestMessage Transfromed Blake3ModificationHashMessage is:\n" << Blake3ModificationHashedMessage << std::endl;
	}

	inline void Test_DigestCryptograph_ChinaShangYongMiMa()
	{
		std::string TestMessage("Hello World");
		std::cout << "This TestMessage is:\n" << TestMessage << std::endl;
		std::string ChinaShangYongMiMa3HashdMessage(TestMessage);
		CommonSecurity::SHA::Hasher::HasherTools MainHasher;
		auto optionalHashedHexadecimalString = MainHasher.GenerateHashed(CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3, ChinaShangYongMiMa3HashdMessage);
		if(optionalHashedHexadecimalString.has_value())
			optionalHashedHexadecimalString.value().swap(ChinaShangYongMiMa3HashdMessage);
		else
			throw std::invalid_argument(" If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");
		std::cout << "This TestMessage Transfromed ChinaShangYongMiMa3HashMessage is:\n" << ChinaShangYongMiMa3HashdMessage << std::endl;
	}

	#endif

	#if defined(DIGEST_CRYPTOGRAPH_KDF_TEST)

	inline void Test_HMAC_KDF()
	{
		std::cout << "Test HMAC Password-based key derivation function Module ......" << std::endl;

		CommonSecurity::KDF::HMAC::Algorithm hmac_kdf_worker;
		CommonSecurity::DataHashingWrapper::HashersAssistantParameters hasher_assistant_parameters;
		std::string password_string_data = "hello2password";
		std::string salt_string_data = "0123456789";

		hasher_assistant_parameters.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512;
		std::string string_keystream_with_hmac = hmac_kdf_worker.MakeHashByteStreamWithKeyDerivation( hasher_assistant_parameters, password_string_data, salt_string_data, "name", 4096 );
	
		std::cout << "Test this key stream (hexadecimal format): " << string_keystream_with_hmac << std::endl;

		std::cout << "--------------------------------------------------------------------" << std::endl;
	
		std::vector<std::uint8_t> keystream_with_hmac = UtilTools::DataFormating::ASCII_Hexadecmial::hexadecimalString2ByteArray( string_keystream_with_hmac );

		std::cout << "Test keystream (characters format): ";
		for( auto& character : keystream_with_hmac)
		{
			std::cout << character;
		}
		std::cout << std::endl;
	}

	inline void Test_Argon2_KDF_EncodeAndDecode()
	{
		using namespace CommonSecurity::KDF::Argon2;

		Argon2_Parameters argon2_parameter
		(
			std::vector<std::uint8_t>(),
			0,
			std::vector<std::uint8_t>(),
			std::vector<std::uint8_t>(),
			16,
			128,
			10,
			0,
			false,
			false,
			true,
			false,
			HashModeTypeStringAlphabetFormat::LOWER_CASE,
			AlgorithmVersion::NUMBER_0x13,
			HashModeType::IndependentAddressing
		);

		std::string argon2_base64_string = "$argon2i$v=19$m=128,t=16,p=10$RjR0WWhsUXhDNmRxZXF1NXZBWW1mYmFNbUlSeGRJTnY$/305tPJzdKomBM3YXOKDQFRysTjtg10FJO3WBba1hF2+qSbpL4cpWeUFcxc6KJ8oS6V+T2etjyrH/oPUw7XqBjf1cizitOnqyC15CMeynbiMkaxKCXbnn/Bta8S9F/kl";

		Argon2 argon2_object(argon2_parameter);
		std::stringstream test_string_stream(argon2_base64_string);
		test_string_stream >> argon2_object;
		test_string_stream.clear();
		test_string_stream << argon2_object;

		return;
	}

	inline void Test_Argon2_KDF()
	{
		using namespace CommonSecurity::KDF::Argon2;

		/*
		
			Test Data String: ThisPassword0
			Salt String: QaZxCvBnMLkJh
			Generated Hash Byte Size: 64
			
			The correct hash data that should be generated after using the original data for the Argon2 module to process
			Example.
			
			Argon2 Mode I: (IndependentAddressing)
			
			Argon2 Infomation: Hashed digest data of the original data has been generated.
			Argon2 Information: The hashed password does match the supplied hash!
			Argon2 Infomation: Hashed digest data of the original data has been generated.
			Bytes hexadecimal format: ED3E07155EC737F23AB86E172318F747EE5913392597AA750D074B3A2B91B69F0FA07D6CDF78D7829207DE98EAA61BF0A2843859E3C08460C6860FD6470B065D
			Bytes base64 format: 7T4HFV7HN/I6uG4XIxj3R+5ZEzkll6p1DQdLOiuRtp8PoH1s33jXgpIH3pjqphvwooQ4WePAhGDGhg/WRwsGXQ==
			This argon hash base64 and formatted string is:
			$Argon2i$v=19$m=256,t=4,p=1$UWFaeEN2Qm5NTGtKaA$7T4HFV7HN/I6uG4XIxj3R+5ZEzkll6p1DQdLOiuRtp8PoH1s33jXgpIH3pjqphvwooQ4WePAhGDGhg/WRwsGXQ
			
			Argon2 Mode D: (DependentAddressing)
			
			Argon2 Infomation: Hashed digest data of the original data has been generated.
			Argon2 Information: The hashed password does match the supplied hash!
			Argon2 Infomation: Hashed digest data of the original data has been generated.
			Bytes hexadecimal format: 2D7C54BA11FB56457DEE1BBB57852A6061ABC1E202E28013767D2032AD0B48E3553AE334C7D5AC35C4110E655C82580B603C54087F3F15676588DD3D9E5AB524
			Bytes base64 format: LXxUuhH7VkV97hu7V4UqYGGrweIC4oATdn0gMq0LSONVOuM0x9WsNcQRDmVcglgLYDxUCH8/FWdliN09nlq1JA==
			This argon hash base64 and formatted string is:
			$Argon2d$v=19$m=256,t=4,p=1$UWFaeEN2Qm5NTGtKaA$LXxUuhH7VkV97hu7V4UqYGGrweIC4oATdn0gMq0LSONVOuM0x9WsNcQRDmVcglgLYDxUCH8/FWdliN09nlq1JA
			
			Argon2i Mode IS: (MixedAddressing)
			
			Argon2 Infomation: Hashed digest data of the original data has been generated.
			Argon2 Information: The hashed password does match the supplied hash!
			Argon2 Infomation: Hashed digest data of the original data has been generated.
			Bytes hexadecimal format: 54201A817A7FB65FF83BE4B39CFB78E0F3D37F804D2A01FE4734E3C57161D4E18E9CC14BE370C52225A87919C0EF6C1B9134EDD76A7A906F914A6E345CB92C2B
			Bytes base64 format: VCAagXp/tl/4O+SznPt44PPTf4BNKgH+RzTjxXFh1OGOnMFL43DFIiWoeRnA72wbkTTt12p6kG+RSm40XLksKw==
			This argon hash base64 and formatted string is:
			$Argon2id$v=19$m=256,t=4,p=1$UWFaeEN2Qm5NTGtKaA$VCAagXp/tl/4O+SznPt44PPTf4BNKgH+RzTjxXFh1OGOnMFL43DFIiWoeRnA72wbkTTt12p6kG+RSm40XLksKw
			
			Argon2 Mode DS: (SubstitutionBoxHardcore)
			
			Argon2 Infomation: Hashed digest data of the original data has been generated.
			Argon2 Information: The hashed password does match the supplied hash!
			Argon2 Infomation: Hashed digest data of the original data has been generated.
			Bytes hexadecimal format: 33B304A9E2FB2DC9A2800EA6D11987106EAECBCD0D50713E30A9B28F8EEA5F849E70ED08D0BC140399FD0D770E8A56ED31D7A8C0DCD30BA968DAF255EC9FA7DE
			Bytes base64 format: M7MEqeL7LcmigA6m0RmHEG6uy80NUHE+MKmyj47qX4SecO0I0LwUA5n9DXcOilbtMdeowNzTC6lo2vJV7J+n3g==
			This argon hash base64 and formatted string is:
			$Argon2ds$v=19$m=256,t=4,p=1$UWFaeEN2Qm5NTGtKaA$M7MEqeL7LcmigA6m0RmHEG6uy80NUHE+MKmyj47qX4SecO0I0LwUA5n9DXcOilbtMdeowNzTC6lo2vJV7J+n3g
		
			This argon hash base64 and formatted string is:
			$Argon2ds$v=19$m=256,t=4,p=1$UWFaeEN2Qm5NTGtKaA$M7MEqeL7LcmigA6m0RmHEG6uy80NUHE+MKmyj47qX4SecO0I0LwUA5n9DXcOilbtMdeowNzTC6lo2vJV7J+n3g

		*/

		using namespace UtilTools::DataFormating;

		std::cout << "Test Argon2 Password-based key derivation function Module ......" << std::endl;

		std::vector<std::uint8_t> argon2_hashed_bytes(64, 0);
		std::vector<std::uint8_t> message_or_password_bytes{ 'T','h','i','s','P','a','s','s','w','o','r','d','0' };
		std::vector<std::uint8_t> salt_bytes{ 'Q','a','Z','x','C','v','B','n','M','L','k','J','h' };

		Argon2_Parameters argon2_parameter
		(
			argon2_hashed_bytes,
			64,
			message_or_password_bytes,
			salt_bytes,
			4,
			256,
			1,
			1,
			false,
			false,
			false,
			false,
			HashModeTypeStringAlphabetFormat::UPPER_CASE,
			AlgorithmVersion::NUMBER_0x13,
			HashModeType::IndependentAddressing
		);

		Argon2_Parameters argon2_parameter2
		(
			argon2_hashed_bytes,
			64,
			message_or_password_bytes,
			salt_bytes,
			4,
			256,
			1,
			1,
			false,
			false,
			false,
			false,
			HashModeTypeStringAlphabetFormat::UPPER_CASE,
			AlgorithmVersion::NUMBER_0x13,
			HashModeType::DependentAddressing
		);

		Argon2_Parameters argon2_parameter3
		(
			argon2_hashed_bytes,
			64,
			message_or_password_bytes,
			salt_bytes,
			4,
			256,
			1,
			1,
			false,
			false,
			false,
			false,
			HashModeTypeStringAlphabetFormat::UPPER_CASE,
			AlgorithmVersion::NUMBER_0x13,
			HashModeType::MixedAddressing
		);

		Argon2_Parameters argon2_parameter4
		(
			argon2_hashed_bytes,
			64,
			message_or_password_bytes,
			salt_bytes,
			4,
			256,
			1,
			1,
			false,
			false,
			false,
			false,
			HashModeTypeStringAlphabetFormat::UPPER_CASE,
			AlgorithmVersion::NUMBER_0x13,
			HashModeType::SubstitutionBox
		);

		Argon2 argon2_object(argon2_parameter);
		std::stringstream test_string_stream(std::string(""));

		argon2_object.VerifyHashedData("ED3E07155EC737F23AB86E172318F747EE5913392597AA750D074B3A2B91B69F0FA07D6CDF78D7829207DE98EAA61BF0A2843859E3C08460C6860FD6470B065D");
		argon2_object.ResetHashWorkerState();

		argon2_object.Hash<std::vector<std::uint8_t>>(argon2_hashed_bytes);

		std::cout << "Bytes hexadecimal format: " << ASCII_Hexadecmial::byteArray2HexadecimalString(argon2_hashed_bytes) << std::endl;
		std::cout << "Bytes base64 format: " << Base64Coder::Author1::encode(argon2_hashed_bytes) << std::endl;
		
		test_string_stream << argon2_object;
		std::cout << "This argon hash base64 and formatted string is:\n" << test_string_stream.str() << std::endl;
		test_string_stream.str(std::string(""));
		std::cout << std::endl;

		argon2_object.ResetHashWorkerState();
		argon2_object.SetParametersContext(argon2_parameter2);

		argon2_object.VerifyHashedData("2D7C54BA11FB56457DEE1BBB57852A6061ABC1E202E28013767D2032AD0B48E3553AE334C7D5AC35C4110E655C82580B603C54087F3F15676588DD3D9E5AB524");
		argon2_object.ResetHashWorkerState();

		argon2_object.Hash<std::vector<std::uint8_t>>(argon2_hashed_bytes);

		std::cout << "Bytes hexadecimal format: " << ASCII_Hexadecmial::byteArray2HexadecimalString(argon2_hashed_bytes) << std::endl;
		std::cout << "Bytes base64 format: " << Base64Coder::Author1::encode(argon2_hashed_bytes) << std::endl;
		
		test_string_stream << argon2_object;
		std::cout << "This argon hash base64 and formatted string is:\n" << test_string_stream.str() << std::endl;
		test_string_stream.str(std::string(""));
		std::cout << std::endl;

		argon2_object.ResetHashWorkerState();
		argon2_object.SetParametersContext(argon2_parameter3);

		argon2_object.VerifyHashedData("54201A817A7FB65FF83BE4B39CFB78E0F3D37F804D2A01FE4734E3C57161D4E18E9CC14BE370C52225A87919C0EF6C1B9134EDD76A7A906F914A6E345CB92C2B");
		argon2_object.ResetHashWorkerState();

		argon2_object.Hash<std::vector<std::uint8_t>>(argon2_hashed_bytes);

		std::cout << "Bytes hexadecimal format: " << ASCII_Hexadecmial::byteArray2HexadecimalString(argon2_hashed_bytes) << std::endl;
		std::cout << "Bytes base64 format: " << Base64Coder::Author1::encode(argon2_hashed_bytes) << std::endl;
		
		test_string_stream << argon2_object;
		std::cout << "This argon hash base64 and formatted string is:\n" << test_string_stream.str() << std::endl;
		test_string_stream.str(std::string(""));
		std::cout << std::endl;

		argon2_object.ResetHashWorkerState();
		argon2_object.SetParametersContext(argon2_parameter4);

		argon2_object.VerifyHashedData("33B304A9E2FB2DC9A2800EA6D11987106EAECBCD0D50713E30A9B28F8EEA5F849E70ED08D0BC140399FD0D770E8A56ED31D7A8C0DCD30BA968DAF255EC9FA7DE");
		argon2_object.ResetHashWorkerState();

		argon2_object.Hash<std::vector<std::uint8_t>>(argon2_hashed_bytes);

		std::cout << "Bytes hexadecimal format: " << ASCII_Hexadecmial::byteArray2HexadecimalString(argon2_hashed_bytes) << std::endl;
		std::cout << "Bytes base64 format: " << Base64Coder::Author1::encode(argon2_hashed_bytes) << std::endl;
		
		test_string_stream << argon2_object;
		std::cout << "This argon hash base64 and formatted string is:\n" << test_string_stream.str() << std::endl;
		test_string_stream.str(std::string(""));
		std::cout << std::endl;

		argon2_object.ResetHashWorkerState();
		argon2_object.Clear();

		return;
	}

	inline void Test_Scrypt_KDF()
	{
		using CommonSecurity::KDF::Scrypt::Algorithm;

		volatile void* CheckPointer = nullptr;
		std::size_t byte_counter = 0;
		Algorithm scrypt_object;

		std::vector<std::uint8_t> passwords;
		std::vector<std::uint8_t> salts;
		std::vector<std::uint8_t> generated_keys;

		std::cout << "Test Scrypt Password-based key derivation function Module ......" << std::endl;

		/*******************/

		generated_keys = scrypt_object.GenerateKeys(passwords, salts, 256, 16, 8, 1);

		for(const auto& byte : generated_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		CheckPointer = memory_set_no_optimize_function<0x00>(generated_keys.data(), generated_keys.size());
		generated_keys.clear();
		generated_keys.shrink_to_fit();

		generated_keys = scrypt_object.GenerateKeys(passwords, salts, 256, 16, 8, 16);

		byte_counter = 0;
		for(const auto& byte : generated_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		CheckPointer = memory_set_no_optimize_function<0x00>(generated_keys.data(), generated_keys.size());
		generated_keys.clear();
		generated_keys.shrink_to_fit();

		/*******************/

		std::string password_string = "PasswordTest";
		std::string salt_string = "SaltTest";
		passwords.resize(password_string.size());
		salts.resize(salt_string.size());
		std::ranges::copy(password_string.begin(), password_string.end(), std::begin(passwords));
		std::ranges::copy(salt_string.begin(), salt_string.end(), std::begin(salts));

		generated_keys = scrypt_object.GenerateKeys(passwords, salts, 256, 1024, 8, 1);

		byte_counter = 0;
		for(const auto& byte : generated_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		CheckPointer = memory_set_no_optimize_function<0x00>(generated_keys.data(), generated_keys.size());
		generated_keys.clear();
		generated_keys.shrink_to_fit();

		generated_keys = scrypt_object.GenerateKeys(passwords, salts, 256, 1024, 8, 32);

		byte_counter = 0;
		for(const auto& byte : generated_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		CheckPointer = memory_set_no_optimize_function<0x00>(generated_keys.data(), generated_keys.size());
		generated_keys.clear();
		generated_keys.shrink_to_fit();

		/*******************/

		generated_keys = scrypt_object.GenerateKeys(passwords, salts, 256, 16384, 8, 1);

		byte_counter = 0;
		for(const auto& byte : generated_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		CheckPointer = memory_set_no_optimize_function<0x00>(generated_keys.data(), generated_keys.size());
		generated_keys.clear();
		generated_keys.shrink_to_fit();

		generated_keys = scrypt_object.GenerateKeys(passwords, salts, 256, 16384, 8, 64);

		byte_counter = 0;
		for(const auto& byte : generated_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		CheckPointer = memory_set_no_optimize_function<0x00>(generated_keys.data(), generated_keys.size());
		generated_keys.clear();
		generated_keys.shrink_to_fit();

		/*******************/

		generated_keys = scrypt_object.GenerateKeys(passwords, salts, 256, 32768, 8, 1);

		byte_counter = 0;
		for(const auto& byte : generated_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		CheckPointer = memory_set_no_optimize_function<0x00>(generated_keys.data(), generated_keys.size());
		generated_keys.clear();
		generated_keys.shrink_to_fit();

		generated_keys = scrypt_object.GenerateKeys(passwords, salts, 256, 32768, 8, 128);

		byte_counter = 0;
		for(const auto& byte : generated_keys )
		{
			std::cout << "0x" << std::setfill('0') << std::setw(sizeof(std::uint8_t)*2) << std::uppercase << std::hex << static_cast<std::uint32_t>(byte) << ", ";
			++byte_counter;
			if(byte_counter % 16 == 0)
				std::cout << "\n";
		}
		byte_counter = 0;
		std::cout << std::endl;

		CheckPointer = memory_set_no_optimize_function<0x00>(generated_keys.data(), generated_keys.size());
		generated_keys.clear();
		generated_keys.shrink_to_fit();
	}

	#endif

	inline void Test_DRBG_With_HMAC()
	{
		using CommonSecurity::DRBG::HMAC::WorkerBasedHAMC;
		using namespace Cryptograph::CommonModule;

		CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument;
		HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::BLAKE2;
		HAP_ObjectArgument.generate_hash_bit_size = 512;
		HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;
		HAP_ObjectArgument.inputDataString = "";
		HAP_ObjectArgument.outputHashedHexadecimalString = "";

		WorkerBasedHAMC DRBG(HAP_ObjectArgument);

		DRBG.instantiate_state(256, "");
		std::vector<std::uint8_t> random_bytes_data(256, 0x00); 

		DRBG.generate_bytes(random_bytes_data);

		for( const auto& random_bytes : random_bytes_data )
		{
			std::cout << (std::uint32_t)random_bytes << std::endl;
		}
	}

	inline void Test_ShamirSecretSharing()
	{
		using CommonSecurity::SecretSharing::ShamirsAlgorithmScheme;
		using ByteType = std::uint8_t;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateSplitDataStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateSplitDataEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateJoinDataStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateJoinDataEndTime = std::chrono::system_clock::now();

		std::vector<ByteType> sourceByteDatas;
		std::vector<ByteType> targetByteDatas;

		//10485760
		std::cout << "BytesData" << std::endl;
		for (std::uint32_t index = 0; index < 1048576; index++)
		{
			auto integer = UniformNumberDistribution(RandomGeneraterByReallyTime);
			ByteType temporaryData{ static_cast<ByteType>(integer) };
			//std::cout << std::to_integer<signed int>(temporaryData) << " ";
			sourceByteDatas.push_back(temporaryData);
		}

		ShamirsAlgorithmScheme<ByteType, 2, 4> ShamirShareAlgorithmObject;

		generateSplitDataStartTime = std::chrono::system_clock::now();
		auto SplittedBytesDataMap = ShamirShareAlgorithmObject.hide_secret_byte_with_splitter(sourceByteDatas);
		generateSplitDataEndTime = std::chrono::system_clock::now();
		std::cout << "The random secret data has been splitted to the part data !" << std::endl;
		TimeSpent = generateSplitDataEndTime - generateSplitDataStartTime;

		std::cout << "time passed: " << TimeSpent.count() << " seconds." << std::endl;

		SplittedBytesDataMap.erase(3);
		SplittedBytesDataMap.erase(4);
		
		generateJoinDataStartTime = std::chrono::system_clock::now();
		targetByteDatas = ShamirShareAlgorithmObject.apparent_secret_byte_with_joinner(SplittedBytesDataMap);
		generateJoinDataEndTime = std::chrono::system_clock::now();
		std::cout << "The random secret data has been joined from the part data !" << std::endl;
		TimeSpent = generateJoinDataEndTime - generateJoinDataStartTime;

		std::cout << "time passed: " << TimeSpent.count() << " seconds." << std::endl;

		if(sourceByteDatas != targetByteDatas)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}
	}

	inline void Test_CascadedEncryptionAndDecryptionWithAEAD()
	{
		/*
			2023年3月17日
			测试报告
			在测试中使用了三种不同的加密/解密方法，分别是1MB的明文数据和1MB的密文数据。
			这三种方法分别对应于三块不同的256比特密钥，并使用自同步计数器模式。

			到目前为止，测试成功的操作模式是:
			1. 带密码块链的计数器 信息验证码
			2. 伽罗瓦计数器/哈希模式
			3. 先加密后认证再译码的模式
			4. 合成初始化向量模式
			5. 偏移量差分数据代码块模式

			March 17, 2023
			Test Report
			Three different encryption/decryption methods were used in the tests, 1MB of plaintext data and 1MB of ciphertext data. 
			Each of the three methods corresponds to three different 256-bit keys and uses a self-synchronizing counter mode.

			So far, the operation modes tested successfully are:
			1. Counter with cipher block chain Message authentication code
			2. Galois counter/hash mode
			3. Encrypt then authenticate then translate mode
			4. Synthetic initialization vector mode
			5. Offset differential data code block mode
		*/

		using CommonSecurity::CascadedAndUnique::PasscoderType;
		using CommonSecurity::CascadedAndUnique::CompositePasscoder;

		std::vector<PasscoderType> PasscoderTypes { PasscoderType::CHINA_SHANGYONGMIMA4, PasscoderType::RC6, PasscoderType::SERPENT };

		CompositePasscoder ComplexCipher(PasscoderTypes, CommonSecurity::AEAD::BlockCipherMode::WorkMode::OCB);

		std::vector<std::uint8_t> PlainText(1024 * 1024 + 1, 0);
		CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG(2);
		CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> UniformIntegerDistribution(0, 255);
		std::ranges::generate(PlainText.begin(), PlainText.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
		std::vector<std::uint8_t> PlainTextCopy(PlainText.begin(), PlainText.end());
		std::vector<std::uint8_t> CipherText(1024 * 1024 + 1, 0);

		std::vector<std::string> TestPasswords {"00000000", "00000001", "00000002", "00000003"};

		std::deque<std::vector<std::uint8_t>> BuildedKeyStream = ComplexCipher.RegenerateBuildedKeyStream(TestPasswords, CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3 );

		/*
			警告: 前两个模式(CCM, GCM)不需要提供关联数据，后三个模式(EAX, SIV，OCB)认证加密解密必须提供，否则无法保证标签以及数据的一致性。
			Warning: The first two modes (CCM, GCM) do not need to provide associated data, the last three modes (EAX, SIV, OCB) authentication encryption and decryption must be provided, otherwise the consistency of the tag and data cannot be guaranteed.
		*/
		std::vector<std::uint8_t> AssociativeData(512, 0);

		ComplexCipher.ChangeAssociativeData(AssociativeData);
		ComplexCipher.AEAD_EncryptingData(PlainText, BuildedKeyStream, CipherText);
		auto AuthenticationTag = ComplexCipher.GetTag();

		ComplexCipher.SetTag(AuthenticationTag);
		ComplexCipher.ChangeAssociativeData(AssociativeData);
		ComplexCipher.AEAD_DecryptingData(CipherText, BuildedKeyStream, PlainText);

		if(PlainText != PlainTextCopy)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}
	}
}

#ifdef BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST
#undef BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST
#endif

#ifdef STREAM_CRYPTOGRAPH_TEST
#undef STREAM_CRYPTOGRAPH_TEST
#endif

#ifdef DIGEST_CRYPTOGRAPH_TEST
#undef DIGEST_CRYPTOGRAPH_TEST
#endif

#ifdef CUSTOM_BLOCK_CRYPTOGRAPH_TEST
#undef CUSTOM_BLOCK_CRYPTOGRAPH_TEST
#endif

#ifdef CUSTOM_BLOCK_CRYPTOGRAPH_WITH_TREADING_TEST
#undef CUSTOM_BLOCK_CRYPTOGRAPH_WITH_TREADING_TEST
#endif CUSTOM_BLOCK_CRYPTOGRAPH_WITH_TREADING_TEST

#ifdef SHUFFLE_RANGE_DATA_TEST
#undef SHUFFLE_RANGE_DATA_TEST
#endif SHUFFLE_RANGE_DATA_TEST

#ifdef MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST
#undef MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST
#endif MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST

#ifdef BUILDING_KEYSTREAM_TEST
#undef BUILDING_KEYSTREAM_TEST
#endif

#ifdef DIGEST_CRYPTOGRAPH_KDF_TEST
#undef DIGEST_CRYPTOGRAPH_KDF_TEST
#endif DIGEST_CRYPTOGRAPH_KDF_TEST

#ifdef PROGRAM_MAIN_MODULE_TEST
#undef PROGRAM_MAIN_MODULE_TEST
#endif PROGRAM_MAIN_MODULE_TEST

#ifdef CUSTOM_DATA_OBFUSCATOR_TEST
#undef CUSTOM_DATA_OBFUSCATOR_TEST
#endif

#ifdef SUBSTITUTIONBOX_GENERATION_TEST
#undef SUBSTITUTIONBOX_GENERATION_TEST
#endif
