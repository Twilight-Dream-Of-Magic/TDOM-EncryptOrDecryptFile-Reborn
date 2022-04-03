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
 * This file is part of TDOM-EncryptOrDecryptFile-Reborn.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#ifndef CUSTOM_CRYPTION_CORE_TEST
//#define CUSTOM_CRYPTION_CORE_TEST
#endif	// !CUSTOM_CRYPTION_CORE_TEST

namespace Cryptograph::CommonModule
{
	/**
	* MCA - Multiple Cryptography Algorithm
	*/

	//ENUM: Check Or Verify File Data IS Valid Or Invalid For Worker
	enum class CVFD_IsValidOrInvalid4Worker
	{
		MCA_CHECK_FILE_STRUCT,
		MCA_VERIFY_FILE_HASH
	};

	//ENUM: Cryption Mode To Multiple Cryptography Algorithm Core For File Data Worker
	enum class CryptionMode2MCAC4_FDW
	{
		MCA_ENCRYPTER,
		MCA_DECRYPTER,
		MCA_ENCODER,
		MCA_DECODER,
		MCA_PERMUTATION,
		MCA_PERMUTATION_REVERSE
	};

	struct FileDataCrypticModuleAdapter
	{
		std::string						   FileDataHashString;
		std::size_t						   FileDataBlockCount = 8;
		std::deque<std::vector<std::byte>> FileDataBytes;
		std::deque<std::vector<char>>	   FileDataCharacters;

		std::atomic<std::size_t> fileDataByteReadedCount = 0;
		std::atomic<std::size_t> fileDataByteWritedCount = 0;
		std::atomic<bool>		 allFileDataIsReaded = false;
		std::atomic<bool>		 allFileDataIsWrited = false;
		std::atomic<bool>		 dataCovertingToBytes = false;
		std::atomic<bool>		 dataCovertingFromBytes = false;

		void ResetStatus()
		{
			FileDataHashString.clear();
			fileDataByteReadedCount.store( 0 );
			fileDataByteWritedCount.store( 0 );
			allFileDataIsReaded.store( false );
			allFileDataIsWrited.store( false );
			dataCovertingToBytes.store( false );
			dataCovertingFromBytes.store( false );
		}

		void ClearData()
		{
			FileDataBytes.clear();
			FileDataCharacters.clear();
		}

		std::deque<std::vector<std::byte>> ToBytes( std::deque<std::vector<char>>& FileDataBlock )
		{
			if ( FileDataBlock.size() > 0 )
			{
				if ( FileDataBlock.front().size() == 0 && FileDataBlock.back().size() == 0 )
				{
					return std::deque<std::vector<std::byte>>( 0 );
				}

				std::deque<std::vector<std::byte>> answer;
				for ( std::size_t dataBlockNumber = 0; dataBlockNumber < FileDataBlockCount; ++dataBlockNumber )
				{
					std::vector<char>	   dataBlockIn( std::move( FileDataBlock[ dataBlockNumber ] ) );
					std::vector<std::byte> dataBlockOut;
					dataBlockOut.reserve(dataBlockIn.size());

					for ( char& dataIn : dataBlockIn )
					{
						std::byte dataOut = static_cast<std::byte>( static_cast<unsigned char>( dataIn ) );
						dataBlockOut.push_back( std::move( dataOut ) );
					}
					std::vector<char>().swap( dataBlockIn );
					answer.push_back( std::move( dataBlockOut ) );
				}
				std::deque<std::vector<char>>().swap( FileDataBlock );
				return answer;
			}
			return std::deque<std::vector<std::byte>>( 0 );
		}

		std::deque<std::vector<char>> FromBytes( std::deque<std::vector<std::byte>>& FileDataBlock )
		{
			if ( FileDataBlock.size() > 0 )
			{
				if ( FileDataBlock.front().size() == 0 && FileDataBlock.back().size() == 0 )
				{
					return std::deque<std::vector<char>>( 0 );
				}

				std::deque<std::vector<char>> answer;
				for ( std::size_t dataBlockNumber = 0; dataBlockNumber < FileDataBlockCount; ++dataBlockNumber )
				{
					std::vector<std::byte> dataBlockIn( std::move( FileDataBlock[ dataBlockNumber ] ) );
					std::vector<char>	   dataBlockOut;
					dataBlockOut.reserve(dataBlockIn.size());

					for ( std::byte& dataIn : dataBlockIn )
					{
						char	  dataOut = static_cast<char>( static_cast<unsigned char>( dataIn ) );
						dataBlockOut.push_back( std::move( dataOut ) );
					}
					std::vector<std::byte>().swap( dataBlockIn );
					answer.push_back( std::move( dataBlockOut ) );
				}
				std::deque<std::vector<std::byte>>().swap( FileDataBlock );
				return answer;
			}
			return std::deque<std::vector<char>>( 0 );
		}

		FileDataCrypticModuleAdapter() = default;
		~FileDataCrypticModuleAdapter() = default;
	};

	void ConvertingInputDataAndTransmission( std::unique_ptr<FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlocks )
	{
		if ( FDCM_Adapter_Pointer != nullptr )
		{
			auto						  NativePointer = FDCM_Adapter_Pointer.get();
			FileDataCrypticModuleAdapter& AssociatedObjects = ( *NativePointer );
			AssociatedObjects.FileDataBlockCount = pointerWithFileDataBlocks->size();

			AssociatedObjects.dataCovertingToBytes.store( true );
			AssociatedObjects.FileDataBytes = std::move( AssociatedObjects.ToBytes( *pointerWithFileDataBlocks ) );
			AssociatedObjects.dataCovertingToBytes.store( false );
			AssociatedObjects.dataCovertingToBytes.notify_one();
		}
	}

	void ConvertingOutputDataAndTransmission( std::unique_ptr<FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<std::byte>>* pointerWithFileDataBlocks )
	{
		if ( FDCM_Adapter_Pointer->dataCovertingFromBytes.load() == true )
		{
			FDCM_Adapter_Pointer->dataCovertingFromBytes.wait( true );
		}

		if ( FDCM_Adapter_Pointer != nullptr )
		{
			auto						  NativePointer = FDCM_Adapter_Pointer.get();
			FileDataCrypticModuleAdapter& AssociatedObjects = ( *NativePointer );
			AssociatedObjects.FileDataBlockCount = pointerWithFileDataBlocks->size();

			AssociatedObjects.dataCovertingFromBytes.store( true );
			AssociatedObjects.FileDataCharacters = std::move( AssociatedObjects.FromBytes( *pointerWithFileDataBlocks ) );
			AssociatedObjects.dataCovertingFromBytes.store( false );
			AssociatedObjects.dataCovertingFromBytes.notify_one();
		}
	}

	void ConversionBufferData_Input( std::unique_ptr<FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlocks )
	{
		std::chrono::duration<double> TimeSpent;

		if ( FDCM_Adapter_Pointer->dataCovertingToBytes.load() == true )
		{
			FDCM_Adapter_Pointer->dataCovertingToBytes.wait( true );
		}

		std::cout << "Note that the read-in file data is of type char and needs to be converted to std::byte.\n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
		auto convertTypeDataWithStartTime = std::chrono::system_clock::now();

		std::future<void> futureTask_convertingBufferData = std::async( std::launch::async, CommonModule::ConvertingInputDataAndTransmission, std::ref( FDCM_Adapter_Pointer ), pointerWithFileDataBlocks );

	ConvertingBufferDataFlag:

		std::future_status futureTaskStatus_convertingBufferData = futureTask_convertingBufferData.wait_for( std::chrono::seconds( 1 ) );
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

		if ( futureTaskStatus_convertingBufferData != std::future_status::ready )
		{
			goto ConvertingBufferDataFlag;
		}

		auto convertTypeDataWithEndTime = std::chrono::system_clock::now();
		TimeSpent = convertTypeDataWithEndTime - convertTypeDataWithStartTime;
		std::cout << "The file data has been converted, the time has been spent: " << TimeSpent.count() << " seconds \n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
	}

	void ConversionBufferData_Output( std::unique_ptr<FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<std::byte>>* pointerWithFileDataBlocks )
	{
		std::chrono::duration<double> TimeSpent;

		if ( FDCM_Adapter_Pointer->dataCovertingToBytes.load() == true )
		{
			FDCM_Adapter_Pointer->dataCovertingToBytes.wait( true );
		}

		std::cout << "Note that the write-out file data is about std::byte type and needs to be converted to char type.\n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
		auto convertTypeDataWithStartTime = std::chrono::system_clock::now();

		std::future<void> futureTask_convertingBufferData = std::async( std::launch::async, CommonModule::ConvertingOutputDataAndTransmission, std::ref( FDCM_Adapter_Pointer ), pointerWithFileDataBlocks );

	ConvertingBufferDataFlag:

		std::future_status futureTaskStatus_convertingBufferData = futureTask_convertingBufferData.wait_for( std::chrono::seconds( 1 ) );
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

		if ( futureTaskStatus_convertingBufferData != std::future_status::ready )
		{
			goto ConvertingBufferDataFlag;
		}

		auto convertTypeDataWithEndTime = std::chrono::system_clock::now();
		TimeSpent = convertTypeDataWithEndTime - convertTypeDataWithStartTime;
		std::cout << "The file data has been converted, the time has been spent: " << TimeSpent.count() << " seconds \n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
	}

	namespace Adapters 
	{
		#if __cpp_lib_byte

		void characterToByte(const std::vector<char>& input , std::vector<std::byte>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (char characterData : input)
			{
				output.push_back( static_cast<std::byte>(static_cast<unsigned char>(characterData)) );
			}
		}

		void characterFromByte(const std::vector<std::byte>& input, std::vector<char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (std::byte byteData : input)
			{
				output.push_back( static_cast<char>(static_cast<unsigned char>(byteData)) );
			}
		}

		void classicByteToByte(const std::vector<unsigned char>& input , std::vector<std::byte>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (unsigned char characterData : input)
			{
				output.push_back( static_cast<std::byte>(characterData) );
			}
		}

		void classicByteFromByte(const std::vector<std::byte>& input, std::vector<unsigned char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (std::byte byteData : input)
			{
				output.push_back( static_cast<unsigned char>(byteData) );
			}
		}

		#endif

		void characterToClassicByte(const std::vector<char>& input , std::vector<unsigned char>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (char characterData : input)
			{
				output.push_back( static_cast<unsigned char>(characterData) );
			}
		}

		void characterFromClassicByte(const std::vector<unsigned char>& input, std::vector<char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (unsigned char byteData : input)
			{
				output.push_back( static_cast<char>(byteData) );
			}
		}
	}

}  // namespace Cryptograph::CommonModule

//文件的数据置换或者数据逆置换
//Data permutation or data reverse permutation of files
namespace Cryptograph::DataPermutation
{
	//16进制字符串数据
	class HexadecimalStringCoder
	{
		//	数据置换函数
		//
		//	Return: Disorded hexadecimal formated string
		//	Parameters: Hexadecimal formated string
		std::string DataDisorder( const std::string& string_file_data )
		{
			if ( string_file_data.size() <= 0 )
			{
				return std::string( "" );
			}

			std::string encoded = std::string( string_file_data );

			//运行循环次数
			//RTNOC (Run The Number Of Cycles)

			//正向置换加密
			//Forward permutation encryption
			for ( size_t round = 0, index = 0, RTNOC = encoded.size(); round < ( RTNOC / 2 ) && index < RTNOC; round += 16, index++ )
			{
				std::swap( encoded[ index ], encoded.at( round + 16 ) );
				std::swap( encoded[ index ], encoded.at( round + 8 ) );
				std::swap( encoded[ index ], encoded.at( round + 1 ) );
				std::swap( encoded[ index ], encoded.at( round + 9 ) );
				std::swap( encoded[ index ], encoded.at( round + 15 ) );
				std::swap( encoded[ index ], encoded.at( round + 7 ) );
				std::swap( encoded[ index ], encoded.at( round + 2 ) );
				std::swap( encoded[ index ], encoded.at( round + 10 ) );
				std::swap( encoded[ index ], encoded.at( round + 14 ) );
				std::swap( encoded[ index ], encoded.at( round + 6 ) );
				std::swap( encoded[ index ], encoded.at( round + 3 ) );
				std::swap( encoded[ index ], encoded.at( round + 11 ) );
				std::swap( encoded[ index ], encoded.at( round + 4 ) );
				std::swap( encoded[ index ], encoded.at( round + 12 ) );
				std::swap( encoded[ index ], encoded.at( round + 5 ) );
				std::swap( encoded[ index ], encoded.at( round + 13 ) );
			}

			std::cout << "The file_string_data encode result is: " << encoded << std::endl;

			//Return ciphertext data
			return encoded;
		}

		//	数据逆置换函数
		//
		//	Return: Ordered hexadecimal formated string
		//	Parameters: Disorded hexadecimal formated string
		std::string DataOrder( std::string& string_file_data )
		{
			if ( string_file_data.size() <= 0 )
			{
				return std::string( "" );
			}

			std::string decoded = std::string( string_file_data );

			//运行循环次数
			//RTNOC (Run The Number Of Cycles)

			//逆向置换解密
			//Reverse permutation decryption
			for ( size_t round = 0, index = 0, RTNOC = decoded.size(); round < ( RTNOC / 2 ) && index < RTNOC; round += 16, index++ )
			{
				std::swap( decoded[ index ], decoded.at( round + 13 ) );
				std::swap( decoded[ index ], decoded.at( round + 5 ) );
				std::swap( decoded[ index ], decoded.at( round + 12 ) );
				std::swap( decoded[ index ], decoded.at( round + 4 ) );
				std::swap( decoded[ index ], decoded.at( round + 11 ) );
				std::swap( decoded[ index ], decoded.at( round + 3 ) );
				std::swap( decoded[ index ], decoded.at( round + 6 ) );
				std::swap( decoded[ index ], decoded.at( round + 14 ) );
				std::swap( decoded[ index ], decoded.at( round + 10 ) );
				std::swap( decoded[ index ], decoded.at( round + 2 ) );
				std::swap( decoded[ index ], decoded.at( round + 7 ) );
				std::swap( decoded[ index ], decoded.at( round + 15 ) );
				std::swap( decoded[ index ], decoded.at( round + 9 ) );
				std::swap( decoded[ index ], decoded.at( round + 1 ) );
				std::swap( decoded[ index ], decoded.at( round + 8 ) );
				std::swap( decoded[ index ], decoded.at( round + 16 ) );
			}

			std::cout << "The file_string_data decode result is: " << decoded << std::endl;

			//Return plaintext data
			return decoded;
		}
	};
}  // namespace Cryptograph::DataPermutation

namespace Cryptograph::Encryption_Tools
{
	class Encryption
	{

	public:
		Encryption() : choise( 0 ), move_bit( 0 ) {}

		~Encryption() {}

		Encryption( const Encryption& _object ) = delete;

		std::byte Main_Encryption( std::byte& data, const std::byte& Key );

	private:
		size_t choise;
		size_t move_bit;
	};

	std::byte Encryption::Main_Encryption( std::byte& data, const std::byte& Key )
	{
		constexpr std::byte ByteFlag{ 3 };
		constexpr std::byte ByteFlag2{ 7 };

		//Binary Digits 10101010
		/*
			
			Select Binary Digits
			1 0 1 0 1 0 1 0
			            ^ ^
			
		*/
		choise = std::to_integer<std::size_t>( Key & ByteFlag );

		/*
			
			00101010 = 10101010 >> 2
			
			Select Binary Digits
			0 0 1 0 1 0 1 0
			          ^ ^ ^
			
		*/
		move_bit = std::to_integer<std::size_t>( (Key >> 2) & ByteFlag2 );

		switch ( choise )
		{
			case 0:
			{
				Exclusive_OR( data, Key );
				break;
			}
			case 1:
			{
				Equivalence_OR( data, Key );
				break;
			}

			case 2:
			{
				BitCirculation_Left( data, Key, move_bit );
				break;
			}
			case 3:
			{
				BitCirculation_Right( data, Key, move_bit );
				break;
			}
			default:
				break;
		}

		BitToggle( data, move_bit );

		return data;
	}
}  // namespace Cryptograph::Encryption_Tools

namespace Cryptograph::Decryption_Tools
{
	class Decryption
	{

	public:
		Decryption() : choise( 0 ), move_bit( 0 ) {}

		~Decryption() {}

		Decryption( const Decryption& _object ) = delete;

		std::byte Main_Decryption( std::byte& data, const std::byte& Key );

	private:
		size_t choise;
		size_t move_bit;
	};

	std::byte Decryption::Main_Decryption( std::byte& data, const std::byte& Key )
	{
		constexpr std::byte ByteFlag{ 3 };
		constexpr std::byte ByteFlag2{ 7 };

		//Binary Digits 10101010
		/*
			
			Select Binary Digits
			1 0 1 0 1 0 1 0
			            ^ ^
			
		*/
		choise = std::to_integer<std::size_t>( Key & ByteFlag );

		/*
			
			00101010 = 10101010 >> 2
			
			Select Binary Digits
			0 0 1 0 1 0 1 0
			          ^ ^ ^
			
		*/
		move_bit = std::to_integer<std::size_t>( (Key >> 2) & ByteFlag2 );

		BitToggle( data, move_bit );

		switch ( choise )
		{
			case 0:
			{
				Exclusive_OR( data, Key );
				break;
			}

			case 1:
			{
				Equivalence_OR( data, Key );
				break;
			}

			case 2:
			{
				BitCirculation_Right( data, Key, move_bit );
				break;
			}

			case 3:
			{
				BitCirculation_Left( data, Key, move_bit );
				break;
			}
			default:
				break;
		}

		return data;
	}
}  // namespace Cryptograph::Decryption_Tools

///////////////////////////////TEST/////////////////////////////////////

#if defined( CUSTOM_CRYPTION_CORE_TEST )

int main()
{
	using namespace Cryptograph;
	std::mt19937					gen( time( 0 ) );
	std::uniform_int_distribution<> dis( 0, 255 );

	std::byte a{ ( unsigned long long )dis( gen ) };
	std::byte OriginalKey{ ( unsigned long long )dis( gen ) };
	std::cout << a.to_ulong() << "\n";
	//std::cout << key.to_string() << "\n";
	Decryption_Tools::Decryption de;
	Encryption_Tools::Encryption en;
	en.Main_Encryption( a, OriginalKey );
	//std::cout << a.to_string() << "\n";
	de.Main_Decryption( a, OriginalKey );
	std::cout << a.to_ulong() << "\n";
	int characterData = 10;
	while ( characterData-- )
	{
		std::byte a{ ( unsigned long long )dis( gen ) };
		std::byte OriginalKey{ ( unsigned long long )dis( gen ) };
		std::cout << a.to_ulong() << "\n";
		//std::cout << key.to_string() << "\n";
		Decryption_Tools::Decryption de;
		Encryption_Tools::Encryption en;
		en.Main_Encryption( a, OriginalKey );
		//std::cout << a.to_string() << "\n";
		de.Main_Decryption( a, OriginalKey );
		std::cout << a.to_ulong() << "\n";
	}
}
#endif	// TEST