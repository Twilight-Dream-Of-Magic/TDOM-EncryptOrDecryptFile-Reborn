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

#pragma once

#ifndef EODF_PROJECT_DEPRECATED_EXPERIMENTAL_CODEBLOCK_IMPLEMENTATION
#define EODF_PROJECT_DEPRECATED_EXPERIMENTAL_CODEBLOCK_IMPLEMENTATION
#endif

#include "./IsFor_EODF_Reborn.hpp"

#ifndef SHA_TEST
//#define SHA_TEST
#endif // !SHA_TEST

#ifndef DATA_FORMATING_TEST
//#define DATA_FORMATING_TEST
#endif // !DATA_FORMATING_TEST

#ifndef CUSTOM_CRYPTION_TEST
//#define CUSTOM_CRYPTION_TEST
#endif // !CUSTOM_CRYPTION_TEST

#ifndef SHUFFLE_RANGE_DATA_TEST
//#define SHUFFLE_RANGE_DATA_TEST
#endif // !SHUFFLE_RANGE_DATA_TEST

#ifndef MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST
//#define MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST
#endif // !MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST

#ifndef SMALL_FILE_DATA_TEST
//#define SMALL_FILE_DATA_TEST
#endif

#ifndef BIG_FILE_DATA_TEST
//#define BIG_FILE_DATA_TEST
#endif

#ifndef CUSTOM_CRYPTION_WITH_TREADING_TEST
//#define CUSTOM_CRYPTION_WITH_TREADING_TEST
#endif

#ifndef BUILDING_KEYSTREAM_TEST
#define BUILDING_KEYSTREAM_TEST
#endif // !BUILDING_KEYSTREAM_TEST

#ifndef PROGRAM_MAIN_MODULE_TEST
#define PROGRAM_MAIN_MODULE_TEST
#endif // !PROGRAM_MAIN_MODULE_TEST


auto main(int argument_cout, char* argument_vector[]) -> int
{
	using namespace UtilTools;
	using namespace UtilTools::DataFormating;

	//MemoryTrackUsageInfo::get_instance().SetIsTracked(true);

	std::cout.tie(0)->sync_with_stdio(false);
	
	#if !defined(BIG_FILE_DATA_TEST) && defined(SMALL_FILE_DATA_TEST)

	#if defined(_WIN32) || defined(_WIN64)
	//std::system("chcp 65001");
	#endif

	std::string fileHashStringID { "6f1c80df72e2a6d6a291e9db3ded5c2d44ec726265654186cfde6457852d8efa66ed9055de24b49ea6f5ed06d4675bc808d5647595ba0e7133b79bd1a9fe5ae1" };
	std::filesystem::path filePathName("ByteTest.data");

	std::vector<char> testData{'H', 'e', 'l', 'l', 'o', 0x20, 'W', 'o', 'r', 'l', 'd'};

	std::deque<std::vector<char>> sourceDatas;
	sourceDatas.push_back(testData);
	std::deque<std::vector<char>> targetDatas;

	std::unique_ptr<std::deque<std::vector<char>>> pointerSourceDoubleQueue = std::make_unique<std::deque<std::vector<char>>>(std::move(sourceDatas));
	std::unique_ptr<std::deque<std::vector<char>>> pointerTargetDoubleQueue = std::make_unique<std::deque<std::vector<char>>>(std::move(targetDatas));
	std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter> FDCM_Adapter_Pointer = std::make_unique<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>();

	FileProcessing::Operation::BinaryStreamReader fo_bsr;
	FileProcessing::Operation::BinaryStreamWriter fo_bsw;

	std::size_t dataBlockByteSize = 2;

	fo_bsw.WriteFileData(fileHashStringID, filePathName, FDCM_Adapter_Pointer, pointerSourceDoubleQueue.get(), dataBlockByteSize);
	fo_bsr.ReadFileData(fileHashStringID, filePathName, FDCM_Adapter_Pointer, pointerTargetDoubleQueue.get(), dataBlockByteSize);

	if(sourceDatas != targetDatas)
	{
		std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
	}
	else
	{
		std::cout << "Yeah! \nThe module is normal work!" << std::endl;
	}

	#endif

	#if defined(BIG_FILE_DATA_TEST) && !defined(SMALL_FILE_DATA_TEST)

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
	std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter> FDCM_Adapter_Pointer = std::make_unique<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>();

	FileProcessing::Operation::BinaryStreamReader fo_bsr;
	FileProcessing::Operation::BinaryStreamWriter fo_bsw;
	std::size_t dataBlockByteSize = 1024 * 1024;

	readingFileAndMoveBufferDataStartTime = std::chrono::system_clock::now();
	fo_bsr.ReadFileData(fileHashStringID, sourceFilePath, FDCM_Adapter_Pointer, pointerFileDataDoubleQueue.get(), dataBlockByteSize);
	readingFileAndMoveBufferDataEndTime = std::chrono::system_clock::now();
	TimeSpent = readingFileAndMoveBufferDataEndTime - readingFileAndMoveBufferDataStartTime;

	std::cout << "File all byte data is readed, time passed: " << TimeSpent.count() << " seconds." << std::endl;

	moveBufferDataAndWritingFileStartTime = std::chrono::system_clock::now();
	fo_bsw.WriteFileData(fileHashStringID, targetFilePath, FDCM_Adapter_Pointer, pointerFileDataDoubleQueue.get(), dataBlockByteSize);
	moveBufferDataAndWritingFileEndTime = std::chrono::system_clock::now();
	TimeSpent = moveBufferDataAndWritingFileEndTime - moveBufferDataAndWritingFileStartTime;

	std::cout << "File all byte data is writed, time passed: " << TimeSpent.count() << " seconds." << std::endl;

	#endif

	#if defined(SHUFFLE_RANGE_DATA_TEST)

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

	#endif

	#if defined(SHA_TEST)

	using namespace EODF_Reborn::Data_Hashing;

	std::string hello_world = "Hello World - SHA 512 Bit";
	std::cout << hello_world << std::endl;
	std::string hashed_string;

	std::cout << "SHA2-512 Bit Hash Value:" << std::endl;
	HashersAssistant::VERSION2_BIT512(hello_world, hashed_string);
	std::cout << hashed_string << std::endl;

	std::cout << "SHA3-512 Bit Hash Value:" << std::endl;
	HashersAssistant::VERSION3_BIT512(hello_world, hashed_string);
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
	std::optional<std::string> hashed_token_string = HashTokenForData::GenerateHashToken(CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512, passwords);

	std::cout << hashed_token_string.value_or(std::string("This Hash string is empty !")) << std::endl;

	#endif

	#if defined(DATA_FORMATING_TEST)

	auto binary_string_data = Decimal_Hexadecimal::FromDecimalBuilder<long long int>(-1234567898765432LL, AlphabetFormat::LOWER_CASE);
	std::cout << binary_string_data << std::endl;
	
	auto integer_data = Decimal_Hexadecimal::ToDecimalBuilder<long long int>(binary_string_data, AlphabetFormat::LOWER_CASE, true);
	std::cout << integer_data << std::endl;

	#endif

	#if defined(CUSTOM_CRYPTION_TEST)

	using namespace Cryptograph;
	std::mt19937 RandomGeneraterByReallyTime(std::chrono::system_clock::now().time_since_epoch().count());
	CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::size_t> number_distribution(0, 255);
	std::vector<std::byte> BytesData;
	std::vector<std::byte> Key;

	std::chrono::duration<double> TimeSpent;

	std::chrono::time_point<std::chrono::system_clock> generateDataStartTime = std::chrono::system_clock::now();

	//10485760
	std::cout << "BytesData" << std::endl;
	for (int i = 0; i < 104857600; i++)
	{
		auto integer = static_cast<MySupport_Library::Types::my_ui_type>(number_distribution(RandomGeneraterByReallyTime));
		std::byte temporaryData{ static_cast<std::byte>(integer) };
		//std::cout << temporaryData.to_ulong() << " ";
		//std::cout << std::to_integer<signed int>(temporaryData) << " ";
		BytesData.push_back(temporaryData);
	}
	std::cout << "\n";

	std::vector<std::byte> BytesData0 { BytesData };

	std::chrono::time_point<std::chrono::system_clock> generateDataEndTime = std::chrono::system_clock::now();
	TimeSpent = generateDataEndTime - generateDataStartTime;
	std::cout << "The time spent generating the data: " << TimeSpent.count() << "s";

	std::system("pause");
	std::cout << "\n";

	std::chrono::time_point<std::chrono::system_clock> generatePasswordStartTime = std::chrono::system_clock::now();

	std::cout << "KEY" << std::endl;
	for (int i = 0; i < 256; i++)
	{
		auto integer = static_cast<MySupport_Library::Types::my_ui_type>(number_distribution(RandomGeneraterByReallyTime));
		std::byte temporaryData{ static_cast<std::byte>(integer) };
		//std::cout << temporaryData.to_ulong() << " ";
		//std::cout << std::to_integer<signed int>(temporaryData) << " ";
		Key.push_back(temporaryData);
	}
	std::cout << "\n";

	std::chrono::time_point<std::chrono::system_clock> generatePasswordEndTime = std::chrono::system_clock::now();
	TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
	std::cout << "The time spent generating the password: " << TimeSpent.count() << "s";

	std::system("pause");
	std::cout << "\n";

	std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();

	Implementation::Encrypter en;
	en.Main(BytesData, Key, Implementation::NewVersion::SizeCryptographDataBlock::_64_);

	std::cout << "BytesData - Encrypted" << std::endl;

	//for (auto& iter : BytesData)
	//{
	//	//std::cout << iter.to_ulong() << " ";
	//	std::cout << std::to_integer<signed int>(iter) << " ";
	//}
	std::cout << "\n";

	std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
	TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
	std::cout << "The time spent encrypting the data: " << TimeSpent.count() << "s";

	std::system("pause");
	std::cout << "\n";

	std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();

	Implementation::Decrypter de;
	de.Main(BytesData, Key, Implementation::NewVersion::SizeCryptographDataBlock::_64_);

	std::cout << "BytesData - Decrypted" << std::endl;

	//for (auto& iter : BytesData)
	//{
	//	//std::cout << iter.to_ulong() << " ";
	//	std::cout << std::to_integer<signed int>(iter) << " ";
	//}
	std::cout << "\n";

	std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();
	TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
	std::cout << "The time spent decrypting the data: " << TimeSpent.count() << "s";

	std::system("pause");
	std::cout << "\n";

	if(BytesData0 != BytesData)
	{
		std::cout << "Data error !" << std::endl;
	}

	#endif

	#if defined(MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST)

	using namespace EODF_Reborn::MainProgram_ModuleImplementation;

	#if defined(_WIN32) || defined(_WIN64)

	//std::string string_file_path { CommonToolkit::from_u8string( u8"D:\\[Twilight-Dream_Sparkle-Magical_Desktop-Data]\\C++ Project Test\\Linux备忘手册.zip" ) };
	//std::wstring wstring_file_path = string2wstring(string_file_path);
	//std::filesystem::path file_path_object { wstring_file_path };
	
;	std::filesystem::path file_path_object { u8"D:\\[Twilight-Dream_Sparkle-Magical_Desktop-Data]\\C++ Project Test\\Linux备忘手册.zip" };
	std::optional<std::string> HashDigestID = MakeHashDigestByWithProcessingFileData(file_path_object);

	if(HashDigestID.has_value())
	{
		std::cout << "Success, This file hash digest string is: " << HashDigestID.value() << std::endl;
	}
	else
	{
		std::cout << "Failed, This file hash digest string is empty !" << std::endl;
	}

	#else

	#endif

	#endif

	#if defined(CUSTOM_CRYPTION_WITH_TREADING_TEST) && !defined (EODF_PROJECT_DEPRECATED_EXPERIMENTAL_CODEBLOCK_IMPLEMENTATION)

	using namespace CrypticDataThreadingWrapper;
	using namespace CrypticDataThreadingWrapper::Implementation;

	std::default_random_engine RandomGeneraterByReallyTime(std::chrono::system_clock::now().time_since_epoch().count());
	std::uniform_int_distribution<> number_distribution(0, 255);
	std::vector<std::byte> DataBytes;
	std::vector<std::byte> Keys;

	std::size_t dataSize = 1024 * 1024;
	DataBytes.reserve(dataSize);
	for (std::size_t blockCount = 0; blockCount < 1024; blockCount++)
	{
		for (std::size_t dataCount = 0; dataCount < dataSize; dataCount++)
		{
			auto integer = static_cast<std::uint32_t>(number_distribution(RandomGeneraterByReallyTime));
			std::byte temporaryData{ static_cast<std::byte>(integer) };
			DataBytes.push_back(temporaryData);
		}
		Implementation::SharedDataSpace::shared_data.FileDataBytes.push_back(DataBytes);
		DataBytes.shrink_to_fit();
	}

	Keys.reserve(128);
	for (std::size_t blockCount = 0; blockCount < 4; blockCount++)
	{
		for (std::size_t KeyCount = 0; KeyCount < 128; KeyCount++)
		{
			auto integer = static_cast<std::uint32_t>(number_distribution(RandomGeneraterByReallyTime));
			std::byte temporaryData{ static_cast<std::byte>(integer) };
			Keys.push_back(temporaryData);
		}
		Implementation::SharedDataSpace::shared_data.PasswordData.push_back(Keys);
		Keys.shrink_to_fit();
	}

	ThreadTasksManager Tester;
	Tester.setFileDataTransferred();
	std::deque<std::vector<std::byte>> FileDataBytes0 = Implementation::SharedDataSpace::shared_data.FileDataBytes;
	std::chrono::duration<double> TimeSpent;
	std::chrono::time_point<std::chrono::system_clock> generateDataStartTime = std::chrono::system_clock::now();
	Tester.setTaskMaxCount(32 * 2);
	Tester.launchTask(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER);
	Tester.TasksDoJoin();
	std::chrono::time_point<std::chrono::system_clock> generateDataEndTime = std::chrono::system_clock::now();
	TimeSpent = generateDataEndTime - generateDataStartTime;
	std::cout << TimeSpent.count() << std::endl;

	if (Implementation::SharedDataSpace::shared_data.FileDataBytes.empty())
	{
		Implementation::SharedDataSpace::shared_data.FileDataBytes.swap(Implementation::SharedDataSpace::shared_data.ProcessedData);
		std::cout << "swap" << std::endl;
	}
	else
	{
		std::cout << "false: encryption not work" << std::endl;
	}

	ThreadTasksManager Tester2;
	Tester2.setFileDataTransferred();
	Tester2.setTaskMaxCount(32 * 2);
	generateDataStartTime = std::chrono::system_clock::now();
	Tester2.launchTask(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER);
	Tester2.TasksDoJoin();
	generateDataEndTime = std::chrono::system_clock::now();
	TimeSpent = generateDataEndTime - generateDataStartTime;
	std::cout << TimeSpent.count() << std::endl;

	if (Implementation::SharedDataSpace::shared_data.FileDataBytes.empty())
	{
		if (FileDataBytes0 == Implementation::SharedDataSpace::shared_data.ProcessedData)
		{
			std::cout << "true: data is match" << std::endl;
		}
		else
		{
			std::cout << "false: data is not match" << std::endl;
		}
	}
	else
	{
		std::cout << "false: decryption not work" << std::endl;
	}

	#endif // !CUSTOM_CRYPTION_WITH_TREADING_TEST

	#if defined(BUILDING_KEYSTREAM_TEST)

	using namespace EODF_Reborn::MainProgram_ModuleImplementation;

	std::vector<std::string> TestPasswords { "1qazxsw23edc", "4RFVBGT56YHN", "!)@(#*$&%", "7ujm,ki89ol./;p0" };

	auto optional_Passwords = BuildingKeyStream(TestPasswords);

	#endif // !BUILDING_KEYSTREAM_TEST

	#if defined(BUILDING_KEYSTREAM_TEST) && defined(PROGRAM_MAIN_MODULE_TEST)

	using namespace EODF_Reborn;

	MainProgram_ModuleImplementation::CryptographFileDataHelper cf_helper;
	cf_helper.RunCustomEncryptionFile(L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/Linux备忘手册.zip.opc-profile", L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/Linux备忘手册.zip", TestPasswords);
	cf_helper.RunCustomDecryptionFile(L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTestt/Linux备忘手册.zip.opc-profile", L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/Linux备忘手册.zip.opc-encrypted", TestPasswords);

	cf_helper.RunCustomEncryptionFile(L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/白(RGB)(1080p+).zip.opc-profile", L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/白(RGB)(1080p+).zip", TestPasswords);
	cf_helper.RunCustomDecryptionFile(L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/白(RGB)(1080p+).zip.opc-profile", L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/白(RGB)(1080p+).zip.opc-encrypted", TestPasswords);

	#endif

	#ifdef _WIN32
	std::system("pause");
	#else
    std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
	#endif

	return 0;
}