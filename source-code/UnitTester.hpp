#pragma once

#include "./IsFor_EODF_Reborn.hpp"

#ifndef BLOCK_CRYPTOGRAPH_RC6_TEST
#define BLOCK_CRYPTOGRAPH_RC6_TEST
#endif // !BLOCK_CRYPTOGRAPH_RC6_TEST

#ifndef BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST
#define BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST
#endif // !BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST

#ifndef BLOCK_CRYPTOGRAPH_AES_TEST
#define BLOCK_CRYPTOGRAPH_AES_TEST
#endif // !BLOCK_CRYPTOGRAPH_AES_TEST

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

namespace UnitTester
{
	#if defined(BLOCK_CRYPTOGRAPH_RC6_TEST)
	
	inline void Test_BlockCryptograph_RC6()
	{
		std::mt19937 RandomGeneraterByReallyTime(std::chrono::system_clock::now().time_since_epoch().count());
		CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::size_t> number_distribution(0, 255);

		std::vector<unsigned char> BytesData;
		std::vector<unsigned char> Key;
		std::vector<unsigned char> EncryptedBytesData;
		std::vector<unsigned char> DecryptedBytesData;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateDataStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDataEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generatePasswordStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generatePasswordEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();

		generateDataStartTime = std::chrono::system_clock::now();
		//10485760
		std::cout << "BytesData" << std::endl;
		for (int index = 0; index < 10000; index++)
		{
			BytesData.push_back(static_cast<unsigned char>(number_distribution(RandomGeneraterByReallyTime)));
		}
		generateDataEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDataEndTime - generateDataStartTime;
		std::cout << "The time spent generating the data: " << TimeSpent.count() << "s" << std::endl;

		generatePasswordStartTime = std::chrono::system_clock::now();

		std::cout << "KEY" << std::endl;
		//256
		while (Key.size() != 128)
		{
			Key.push_back(static_cast<unsigned char>(number_distribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		generatePasswordEndTime = std::chrono::system_clock::now();
		TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
		std::cout << "The time spent generating the password: " << TimeSpent.count() << "s" << std::endl;

		/*
			SecurityLevel
			ZERO: 20 Half-Rounds
			ONE: 40 Half-Rounds
			TWO: 60 Half-Rounds
		*/
		CommonSecurity::RC6::RC6_SecurityLevel RC6_SecurityLevel = CommonSecurity::RC6::RC6_SecurityLevel::ZERO;

		CommonSecurity::RC6::Worker<unsigned int> RC6_Worker(RC6_SecurityLevel);

		std::cout << "BytesData - RC6 Encrypted" << std::endl;
		generateEncryptionStartTime = std::chrono::system_clock::now();
		EncryptedBytesData = CommonSecurity::RC6::RC6_Executor(RC6_Worker, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, BytesData, Key);
		generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent RC6 encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		std::cout << "BytesData - RC6 Decrypted" << std::endl;
		generateDecryptionStartTime = std::chrono::system_clock::now();
		DecryptedBytesData = CommonSecurity::RC6::RC6_Executor(RC6_Worker, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, EncryptedBytesData, Key);
		generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent RC6 decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		if(BytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}

	}

	#endif // defined(BLOCK_CRYPTOGRAPH_RC6_TEST)

	#if defined(BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST)

	inline void Test_BlockCryptograph_TripleDES()
	{
		std::mt19937 RandomGeneraterByReallyTime(std::chrono::system_clock::now().time_since_epoch().count());
		CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::size_t> number_distribution(0, 255);

		std::vector<unsigned char> BytesData;
		std::vector<unsigned char> Key;
		std::vector<unsigned char> EncryptedBytesData;
		std::vector<unsigned char> DecryptedBytesData;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateDataStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDataEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generatePasswordStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generatePasswordEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();

		generateDataStartTime = std::chrono::system_clock::now();
		//10485760
		std::cout << "BytesData" << std::endl;
		for (int index = 0; index < 10000; index++)
		{
			BytesData.push_back(static_cast<unsigned char>(number_distribution(RandomGeneraterByReallyTime)));
		}
		generateDataEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDataEndTime - generateDataStartTime;
		std::cout << "The time spent generating the data: " << TimeSpent.count() << "s" << std::endl;

		generatePasswordStartTime = std::chrono::system_clock::now();

		std::cout << "KEY" << std::endl;
		//256
		while (Key.size() != 256)
		{
			Key.push_back(static_cast<unsigned char>(number_distribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		generatePasswordEndTime = std::chrono::system_clock::now();
		TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
		std::cout << "The time spent generating the password: " << TimeSpent.count() << "s" << std::endl;

		/*std::bitset<64> _DefaultBitsetKey_(static_cast<unsigned long long>(731982465));
		CommonSecurity::TripleDES::Worker TripleDES_Worker(_DefaultBitsetKey_);*/
		CommonSecurity::TripleDES::Worker TripleDES_Worker;

		#if 0

		std::bitset<64> BitsetData(static_cast<unsigned long long>(6753387039482051485));
		std::bitset<64> BitsetKey(static_cast<unsigned long long>(8758140076359010905));

		/*
			Private function implementation of the triple DES class
			三重DES类的私有函数实现
		*/
		TripleDES_Worker.UpadateMainKeyAndSubKey(BitsetKey);
		TripleDES_WorkerBuffer.Bitset64Object_Plain = BitsetData;
		std::cout << BitsetData.to_string() << std::endl;
		TripleDES_Worker.DES_Executor(TripleDES_WorkerBuffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER);
		std::cout << TripleDES_WorkerBuffer.Bitset64Object_Cipher.to_string() << std::endl;
		TripleDES_Worker.DES_Executor(TripleDES_WorkerBuffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER);
		std::cout << TripleDES_WorkerBuffer.Bitset64Object_Plain.to_string() << std::endl;

		#endif

		std::deque<std::vector<unsigned char>> KeyChain;
		CommonToolkit::ProcessingDataBlock::splitter(Key, KeyChain, 8, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Move);

		auto TripleDES_BytesDataCopy = BytesData;

		std::cout << "BytesData - TripleDES Encrypted" << std::endl;
		generateEncryptionStartTime = std::chrono::system_clock::now();
		CommonSecurity::TripleDES::TripleDES_Executor(TripleDES_Worker, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, BytesData, KeyChain, EncryptedBytesData);
		generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent TripleDES encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		std::cout << "BytesData - TripleDES Decrypted" << std::endl;
		generateDecryptionStartTime = std::chrono::system_clock::now();
		CommonSecurity::TripleDES::TripleDES_Executor(TripleDES_Worker, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, EncryptedBytesData, KeyChain, DecryptedBytesData);
		generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent TripleDES decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		if(TripleDES_BytesDataCopy != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}
	}

	#endif

	#if defined(BLOCK_CRYPTOGRAPH_AES_TEST)

	inline void Test_BlockCryptograph_AES()
	{
		CommonSecurity::AES::Worker AES_Worker(CommonSecurity::AES::AES_SecurityLevel::TWO);
		const unsigned char AESDataByteSize = AES_Worker.GetBlockSize_DataByte();
		const std::size_t AESKeyByteSize = AES_Worker.GetBlockSize_KeyByte();

		std::mt19937 RandomGeneraterByReallyTime(std::chrono::system_clock::now().time_since_epoch().count());
		CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::size_t> number_distribution(0, 255);
	
		std::vector<unsigned char> BytesData;
		std::vector<unsigned char> BytesDataInitialVector;
		std::vector<unsigned char> Key;
		std::vector<unsigned char> EncryptedBytesData;
		std::vector<unsigned char> DecryptedBytesData;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateDataStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDataEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateByteInitialVectorStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateByteInitialVectorEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generatePasswordStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generatePasswordEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();
		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();
		//

		generateDataStartTime = std::chrono::system_clock::now();
		//10485760
		std::cout << "BytesData" << std::endl;
		for (int index = 0; index < 10000; index++)
		{
			BytesData.push_back(static_cast<unsigned char>(number_distribution(RandomGeneraterByReallyTime)));
		}
		generateDataEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDataEndTime - generateDataStartTime;
		std::cout << "The time spent generating the data: " << TimeSpent.count() << "s" << std::endl;

		//

		generateByteInitialVectorStartTime = std::chrono::system_clock::now();

		std::cout << "BytesData - InitialVector" << std::endl;
		//256
		while (BytesDataInitialVector.size() != AESDataByteSize)
		{
			BytesDataInitialVector.push_back(static_cast<unsigned char>(number_distribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		generateByteInitialVectorEndTime = std::chrono::system_clock::now();
		TimeSpent = generateByteInitialVectorEndTime - generateByteInitialVectorStartTime;
		std::cout << "The time spent generating the byte data initial vector: " << TimeSpent.count() << "s" << std::endl;

		//
		generatePasswordStartTime = std::chrono::system_clock::now();

		std::cout << "KEY" << std::endl;
		//256
		while (Key.size() != AESKeyByteSize)
		{
			Key.push_back(static_cast<unsigned char>(number_distribution(RandomGeneraterByReallyTime)));
		}
		std::cout << "\n";

		generatePasswordEndTime = std::chrono::system_clock::now();
		TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
		std::cout << "The time spent generating the password: " << TimeSpent.count() << "s" << std::endl;

		//#define MODE_ECB
		#if defined(BLOCK_CRYPTOGRAPH_AES_TEST) && defined(MODE_ECB)

		//

		generateEncryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.EncryptionWithECB(BytesData, Key, EncryptedBytesData);

		std::cout << "BytesData - AES ECB Encrypted" << std::endl;

		std::cout << "\n";

		generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent AES encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		generateDecryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.DecryptionWithECB(EncryptedBytesData, Key, DecryptedBytesData);

		std::cout << "BytesData - AES ECB Decrypted" << std::endl;

		std::cout << "\n";

		generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent AES decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		if(BytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}

		#endif //! defined(MODE_ECB)
		#undef MODE_ECB

		//#define MODE_CBC
		#if defined(BLOCK_CRYPTOGRAPH_AES_TEST) && defined(MODE_CBC)

		//

		generateEncryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.EncryptionWithCBC(BytesData, Key, BytesDataInitialVector, EncryptedBytesData);

		std::cout << "BytesData - AES CBC Encrypted" << std::endl;

		std::cout << "\n";

		generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent AES encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		generateDecryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.DecryptionWithCBC(EncryptedBytesData, Key, BytesDataInitialVector, DecryptedBytesData);

		std::cout << "BytesData - AES CBC Decrypted" << std::endl;

		std::cout << "\n";

		generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent AES decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		if(BytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}

		#endif //! defined(MODE_CBC)
		#undef MODE_CBC

		//#define MODE_PCBC
		#if defined(BLOCK_CRYPTOGRAPH_AES_TEST) && defined(MODE_PCBC)

		//

		generateEncryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.EncryptionWithPCBC(BytesData, Key, BytesDataInitialVector, EncryptedBytesData);

		std::cout << "BytesData - AES PCBC Encrypted" << std::endl;

		std::cout << "\n";

		generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent AES encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		generateDecryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.DecryptionWithPCBC(EncryptedBytesData, Key, BytesDataInitialVector, DecryptedBytesData);

		std::cout << "BytesData - AES PCBC Decrypted" << std::endl;

		std::cout << "\n";

		generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent AES decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		if(BytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}

		#endif //! defined(MODE_PCBC)
		#undef MODE_PCBC

		//#define AES_MODE_CFB
		#if defined(BLOCK_CRYPTOGRAPH_AES_TEST) && defined(MODE_CFB)

		//

		generateEncryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.EncryptionWithCFB(BytesData, Key, BytesDataInitialVector, EncryptedBytesData);

		std::cout << "BytesData - AES CFB Encrypted" << std::endl;

		std::cout << "\n";

		generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent AES encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		generateDecryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.DecryptionWithCFB(EncryptedBytesData, Key, BytesDataInitialVector, DecryptedBytesData);

		std::cout << "BytesData - AES CFB Decrypted" << std::endl;

		std::cout << "\n";

		generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent AES decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		if(BytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}

		#endif //! defined(MODE_CFB)
		#undef MODE_CFB

		//#define MODE_OFB
		#if defined(BLOCK_CRYPTOGRAPH_AES_TEST) && defined(MODE_OFB)

		//

		generateEncryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.EncryptionWithOFB(BytesData, Key, BytesDataInitialVector, EncryptedBytesData);

		std::cout << "BytesData - AES OFB Encrypted" << std::endl;

		std::cout << "\n";

		generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent AES encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		generateDecryptionStartTime = std::chrono::system_clock::now();

		AES_Worker.DecryptionWithOFB(EncryptedBytesData, Key, BytesDataInitialVector, DecryptedBytesData);

		std::cout << "BytesData - AES OFB Decrypted" << std::endl;

		std::cout << "\n";

		generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent AES decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		//

		if(BytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}

		#endif //! defined(MODE_OFB)
		#undef MODE_OFB
	}

	#endif

	#if defined(CUSTOM_BLOCK_CRYPTOGRAPH_TEST)

	inline void Test_BlockCryptograph_CustomOaldresPuzzleCryptic()
	{
		using namespace Cryptograph;
		std::mt19937 RandomGeneraterByReallyTime(std::chrono::system_clock::now().time_since_epoch().count());
		CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::size_t> number_distribution(0, 255);
		std::vector<std::byte> BytesData;
		std::vector<std::byte> Key;

		std::chrono::duration<double> TimeSpent;

		std::chrono::time_point<std::chrono::system_clock> generateDataStartTime = std::chrono::system_clock::now();

		//10485760
		std::cout << "BytesData" << std::endl;
		for (std::uint32_t index = 0; index < 10485760; index++)
		{
			auto integer = static_cast<MySupport_Library::Types::my_ui_type>(number_distribution(RandomGeneraterByReallyTime));
			std::byte temporaryData{ static_cast<std::byte>(integer) };
			//std::cout << std::to_integer<signed int>(temporaryData) << " ";
			BytesData.push_back(temporaryData);
		}
		std::cout << "\n";

		std::vector<std::byte> BytesData0 { BytesData };

		std::chrono::time_point<std::chrono::system_clock> generateDataEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDataEndTime - generateDataStartTime;
		std::cout << "The time spent generating the data: " << TimeSpent.count() << "s" << std::endl;

		#ifdef _WIN32
		std::system("pause");
		#else
		std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
		#endif

		std::chrono::time_point<std::chrono::system_clock> generatePasswordStartTime = std::chrono::system_clock::now();

		std::cout << "KEY" << std::endl;
		for (std::uint32_t index = 0; index < 256; index++)
		{
			auto integer = static_cast<MySupport_Library::Types::my_ui_type>(number_distribution(RandomGeneraterByReallyTime));
			std::byte temporaryData{ static_cast<std::byte>(integer) };
			//std::cout << std::to_integer<signed int>(temporaryData) << " ";
			Key.push_back(temporaryData);
		}
		std::cout << "\n";

		std::chrono::time_point<std::chrono::system_clock> generatePasswordEndTime = std::chrono::system_clock::now();
		TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
		std::cout << "The time spent generating the password: " << TimeSpent.count() << "s" << std::endl;

		#ifdef _WIN32
		std::system("pause");
		#else
		std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
		#endif

		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();

		Implementation::Encrypter encrypter;

		BytesData = encrypter.Main(BytesData, Key);

		std::cout << "BytesData - Encrypted" << std::endl;

		/*for (auto& byte_value : BytesData)
		{
			std::cout << std::to_integer<signed int>(byte_value) << " ";
		}
		std::cout << "\n";*/

		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		#ifdef _WIN32
		std::system("pause");
		#else
		std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
		#endif

		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();

		Implementation::Decrypter decrypter;
		BytesData = decrypter.Main(BytesData, Key);

		std::cout << "BytesData - Decrypted" << std::endl;

		/*for (auto& byte_value : BytesData)
		{
			std::cout << std::to_integer<signed int>(byte_value) << " ";
		}
		std::cout << "\n";*/

		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		#ifdef _WIN32
		std::system("pause");
		#else
		std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
		#endif
		std::cout << "\n";

		if(BytesData0 != BytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;
		}
	}

	#if defined(CUSTOM_BLOCK_CRYPTOGRAPH_TEST) && defined(CUSTOM_BLOCK_CRYPTOGRAPH_WITH_TREADING_TEST)

	inline void Test_CustomOaldresPuzzleCryptic_WithThreading()
	{
		

		
	}
	
	#endif // !CUSTOM_CRYPTION_WITH_TREADING_TEST

	#endif

	#ifndef SMALL_FILE_DATA_TEST
	#define SMALL_FILE_DATA_TEST
	#endif // !SMALL_FILE_DATA_TEST

	#ifndef BIG_FILE_DATA_TEST
	#define BIG_FILE_DATA_TEST
	#endif // !BIG_FILE_DATA_TEST
	
	#if !defined(BIG_FILE_DATA_TEST) && defined(SMALL_FILE_DATA_TEST)

	inline void Test_SmallFileData_ReadAndWrite()
	{
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
	}

	#endif

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
	void Test_DataFormatting()
	{
		using namespace UtilTools::DataFormating;

		auto binary_string_data = Decimal_Hexadecimal::FromDecimalBuilder<long long int>(-1234567898765432LL, AlphabetFormat::LOWER_CASE);
		std::cout << binary_string_data << std::endl;
	
		auto integer_data = Decimal_Hexadecimal::ToDecimalBuilder<long long int>(binary_string_data, AlphabetFormat::LOWER_CASE, true);
		std::cout << integer_data << std::endl;
	}

	#endif

	#if defined(MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST)
	inline void Test_MakeHashDigestByWithProcessingFileData()
	{
		using namespace EODF_Reborn::MainProgram_ModuleImplementation;

		#if defined(_WIN32) || defined(_WIN64)

		//std::string string_file_path { CommonToolkit::from_u8string( u8"D:\\[Twilight-Dream_Sparkle-Magical_Desktop-Data]\\C++ Project Test\\Linux备忘手册.zip" ) };
		//std::wstring wstring_file_path = string2wstring(string_file_path);
		//std::filesystem::path file_path_object { wstring_file_path };
	
		std::filesystem::path file_path_object { u8"D:\\[Twilight-Dream_Sparkle-Magical_Desktop-Data]\\C++ Project Test\\Linux备忘手册.zip" };
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
	}

	#endif // !MAKE_HASHDIGEST_BY_WITH_PROCESSING_FILEDATA_TEST

	//#define DATASTREAM_PACKER_AND_UNPACKER_TEST
	#if defined(UTILITY_LIBRARY_DATASTREAM_PACKER_AND_UNPACKER_TEST)

	inline void Test_UtilityLibrary_DataStreamPackerAndUnpacker()
	{
		std::vector<unsigned char> characters { 0, 12, 23, 24, 67, 34, 53, 89, 71, 53, 91, 46, 58, 63, 11, 87 };
		std::vector<unsigned int> integers;

		std::vector<unsigned char> characters2;
		std::vector<unsigned long long> integers2;

		std::span<const unsigned char> character_span { character_span.begin(), character_span.end() };
		std::span<const unsigned int> integer_span { integers.begin(), integers.end() };

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

		std::span<const unsigned long long> integer2_span { integers2.begin(), integers2.end() };

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
		using namespace EODF_Reborn::MainProgram_ModuleImplementation;
		using namespace CommonSecurity::SHA;
		using namespace CommonSecurity::DataHashingWrapper;

		std::vector<std::string> TestPasswords { "1qazxsw23edc", "4RFVBGT56YHN", "!)@(#*$&%", "7ujm,ki89ol./;p0" };
		std::size_t NeedKeyStreamSize = 8192;

		HashTokenForDataParameters HashToken_Parameters;
		HashToken_Parameters.HashersAssistantParameters_Instance.hash_mode = Hasher::WORKER_MODE::ARGON2;
		HashToken_Parameters.HashersAssistantParameters_Instance.whether_use_hash_extension_bit_mode = true;
		HashToken_Parameters.HashersAssistantParameters_Instance.generate_hash_bit_size = 1024;
		HashToken_Parameters.OriginalPasswordStrings = TestPasswords;
		HashToken_Parameters.NeedHashByteTokenSize = NeedKeyStreamSize;
		auto optional_Passwords = BuildingKeyStream(HashToken_Parameters);

		#if defined(BUILDING_KEYSTREAM_TEST) && defined(PROGRAM_MAIN_MODULE_TEST)

		using namespace EODF_Reborn;

		MainProgram_ModuleImplementation::CryptographFileDataHelper cf_helper;
		cf_helper.RunCustomEncryptionFile(L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/Linux备忘手册.zip.opc-profile", L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/Linux备忘手册.zip", HashToken_Parameters, FileProcessing::CryptographDataTypePassByFile::COMPLEX, false);
		cf_helper.RunCustomDecryptionFile(L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/Linux备忘手册.zip.opc-profile", L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/Linux备忘手册.zip.opc-encrypted", HashToken_Parameters, false);

		cf_helper.RunCustomEncryptionFile(L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/白(RGB)(1080p+).zip.opc-profile", L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/白(RGB)(1080p+).zip", HashToken_Parameters, FileProcessing::CryptographDataTypePassByFile::COMPLEX, false);
		cf_helper.RunCustomDecryptionFile(L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/白(RGB)(1080p+).zip.opc-profile", L"D:/[Twilight-Dream_Sparkle-Magical_Desktop-Data]/CustomCryptionTest/白(RGB)(1080p+).zip.opc-encrypted", HashToken_Parameters, false);

		#endif
	}
	
	#endif // !BUILDING_KEYSTREAM_TEST

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

		std::string TestRandomCharacterDatas(TestMessage);

		std::seed_seq NumberSeedSequence {16, 34, 28, 67, 49, 58};
		std::mt19937 RNG(NumberSeedSequence);
		CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution IntegerDistribution(-128, 127);
		for(std::size_t index = TestRandomCharacterDatas.size(); index != 4096 - TestRandomCharacterDatas.size(); ++index)
		{
			TestRandomCharacterDatas.push_back( static_cast<char>( IntegerDistribution(RNG) ) );
		}

		std::cout << "This TestRandomCharacterDatas is:" << std::endl;
		for( auto& TestRandomCharacterData : TestRandomCharacterDatas )
		{
			std::cout << static_cast<int>(TestRandomCharacterData) << " ";
		}
		std::cout << std::endl;

		CommonSecurity::SHA::Hasher::HasherTools MainHasher;

		auto optionalHashedHexadecimalString = MainHasher.GenerateBlake3ModificationHashed(TestRandomCharacterDatas, 4096);
		std::string Blake3ModificationHashedMessage( TestRandomCharacterDatas );

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
		CommonSecurity::KDF::HMAC::Worker hmac_kdf_worker;
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
			HashModeType::MixedAddressing
		);

		Argon2 argon2_object(argon2_parameter);

		argon2_object.Hash<std::vector<std::uint8_t>>(argon2_hashed_bytes);

		std::cout << "Bytes converted: " << UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString(argon2_hashed_bytes) << std::endl;
		std::cout << "Bytes base64 converted: " << UtilTools::DataFormating::Base64Coder::Author1::encode(argon2_hashed_bytes) << std::endl;
		
		std::stringstream test_string_stream(std::string(""));

		test_string_stream << argon2_object;

		std::cout << "This argon hash base64 and formatted string is:\n" << test_string_stream.str() << std::endl;

		test_string_stream >> argon2_object;

		return;
	}

	#endif

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

	inline void Test_ByteSubstitutionBoxToolkit()
	{
		using namespace CustomSecurity::ByteSubstitutionBoxToolkit;

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

		//pow(2, 8) == 256
		//log(2, 256) == 8
		std::size_t LogarithmicNumberOfTwoBased = static_cast<std::size_t>(std::log2(AES_SubstitutionBox.size()));

		auto AES_SubstitutionBox_TransparencyOrder = HelperFunctions::SubstitutionBoxTransparencyOrder(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_SignalToNoiseRatio_DifferentialPowerAnalysis = HelperFunctions::SubstitutionBox_SNR_DPA(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_Nonlinearity = HelperFunctions::SubstitutionBoxNonlinearityDegree(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_PropagationCharacteristics_StrictAvalancheCriteria = HelperFunctions::SubstitutionBox_PC_SAC(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_DeltaUniformity_Robustness = HelperFunctions::SubstitutionBox_DeltaUniformity_Robustness(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_AbsoluteValueIndicator = HelperFunctions::SubstitutionBoxAbsoluteValueIndicator(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_SumOfSquareValueIndicator = HelperFunctions::SubstitutionBoxSumOfSquareValueIndicator(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_AlgebraicDegree = HelperFunctions::SubstitutionBoxAlgebraicDegree(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		auto AES_SubstitutionBox_AlgebraicImmunityDegree = HelperFunctions::SubstitutionBoxAlgebraicImmunityDegree(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);

		std::cout << "Substitution Box Transparency Order Is: " << AES_SubstitutionBox_TransparencyOrder << std::endl;
		std::cout << "Substitution Box Nonlinearity Is: " << AES_SubstitutionBox_Nonlinearity.first << std::endl;
		std::cout << "Substitution Box Propagation Characteristics Is: " << AES_SubstitutionBox_PropagationCharacteristics_StrictAvalancheCriteria.first << std::endl;
		std::cout << "Substitution Box Delta Uniformity Is: " << AES_SubstitutionBox_DeltaUniformity_Robustness.first << std::endl;
		std::cout << "Substitution Box Robustness Is: " << AES_SubstitutionBox_DeltaUniformity_Robustness.second << std::endl;
		std::cout << "Substitution Box Signal To Noise Ratio/Differential Power Analysis Is: " << AES_SubstitutionBox_SignalToNoiseRatio_DifferentialPowerAnalysis << std::endl;
		std::cout << "Substitution Box Absolute Value Indicatorer Is: " << AES_SubstitutionBox_AbsoluteValueIndicator.first << std::endl;
		std::cout << "Substitution Box Sum Of Square Value Indicator Is: " << AES_SubstitutionBox_SumOfSquareValueIndicator.first << std::endl;
		std::cout << "Substitution Box Algebraic Degree Is: " << AES_SubstitutionBox_AlgebraicDegree.first << std::endl;
		std::cout << "Substitution Box Algebraic Immunity Degree Is: " << AES_SubstitutionBox_AlgebraicImmunityDegree.first << std::endl;

		std::cout << std::endl;
		
		//HelperFunctions::ShowDifferentialDistributionTable(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		//HelperFunctions::ShowLinearApproximationTable(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
		//HelperFunctions::ShowDifferentialApproximationProbabilityTable(AES_SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
	}

	#endif
}

#ifdef BLOCK_CRYPTOGRAPH_RC6_TEST
#undef BLOCK_CRYPTOGRAPH_RC6_TEST
#endif

#ifdef BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST
#undef BLOCK_CRYPTOGRAPH_TRIPLE_DES_TEST
#endif

#ifdef BLOCK_CRYPTOGRAPH_AES_TEST
#undef BLOCK_CRYPTOGRAPH_AES_TEST
#endif BLOCK_CRYPTOGRAPH_AES_TEST

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
