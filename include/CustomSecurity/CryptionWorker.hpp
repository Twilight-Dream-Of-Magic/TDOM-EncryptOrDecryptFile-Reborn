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

namespace Cryptograph::Implementation
{
	/*
		Implementation of Custom Encrypted Data Worker
		自定义加密数据工作器的实现
	*/
	class Encrypter
	{

	private:

		std::byte default_binary_key { 250 };

	protected:

		void SplitDataBlockToEncrypt(std::vector<std::byte>& PlainText, const std::vector<std::byte>& Key) const
		{
			using namespace CommonSecurity;

			std::size_t PlainText_size = PlainText.size();
            std::byte temporaryBinaryPassword {default_binary_key};
            Cryptograph::Encryption_Tools::Encryption Worker;
            std::vector<unsigned int> temporaryIndexSplited = CommonToolkit::make_vector(std::make_integer_sequence<unsigned int, 64>{});

			for ( std::size_t datablock_size = 0; datablock_size < PlainText_size; datablock_size += 64 )
			{
				//第一次循环加密
				//First cycle encryption
				for ( std::size_t round = datablock_size; round < 64 + datablock_size; round++ )
				{
					std::byte temporaryKey = Worker.Main_Encryption( temporaryBinaryPassword, Key[ round - datablock_size ] );
					temporaryBinaryPassword = Worker.Main_Encryption( PlainText[ round ], temporaryKey );
				}

				PlainText.push_back( temporaryBinaryPassword );

				//随机置换
				//Random Displacement
				std::mt19937 pseudoRandomGenerator { static_cast<unsigned int>( temporaryBinaryPassword ) };
				CommonSecurity::ShuffleRangeData( temporaryIndexSplited, pseudoRandomGenerator );

				//第二次循环加密
				//Second cycle encryption
				for ( std::size_t round2 = 0; round2 < 64; round2++ )
				{
					std::byte temporaryKey = Worker.Main_Encryption( temporaryBinaryPassword, Key[ round2 + 64 ] );
					temporaryBinaryPassword = Worker.Main_Encryption( PlainText[ datablock_size + temporaryIndexSplited[ round2 ] ], temporaryKey );
				}

				temporaryBinaryPassword = PlainText.back();
			}
		}

		/*
			https://en.wikipedia.org/wiki/Padding_(cryptography)

			ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.

			Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
		*/
		void PaddingData(std::vector<std::byte>& Data) const
		{
			std::byte temporaryBinaryData;

			std::size_t Remainder_64 = Data.size() & 63;
			std::size_t NeedPaddingCount = 63 - Remainder_64;
			CommonSecurity::RNG_Xoshiro::xoshiro256 RandomGeneraterByReallyTime (std::chrono::system_clock::now().time_since_epoch().count());
			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution number_distribution(0, 255);

			for (int loopCount = 0; loopCount < NeedPaddingCount; ++loopCount)
			{
				auto integer = static_cast<unsigned int>(number_distribution(RandomGeneraterByReallyTime));
				std::byte byteData{ static_cast<std::byte>(integer) };
				temporaryBinaryData = byteData;
				Data.push_back(temporaryBinaryData);
			}
			auto integer = static_cast<unsigned int>(NeedPaddingCount);
			std::byte byteData{ static_cast<std::byte>(integer) };
			temporaryBinaryData = byteData;
			Data.push_back(temporaryBinaryData);
		}

	public:

		// class CrypticDataThreadingWrapper::FileDataHelper
		// 多线程实现的专用接口，请勿使用不标准的大小数据，进行随意调用，禁止移除该函数！
		// Multi-threaded implementation of the special interface, please do not use non-standard size data, for arbitrary calls, prohibit the removal of the function!
		std::vector<char>& Main(std::vector<char>& PlainText, const std::vector<std::byte>& Key);

		/*
			The file size levels are listed here
			Small file size range: 1BYTE~2GB
			Medium file size range: 2GB~20GB
			Large file size range: 20GB~Number GB
			This function interface is for small files.
			
			这里列出文件大小等级规定
			小型文件大小范围: 1BYTE~2GB
			中型文件大小范围: 2GB~20GB
			大型文件大小范围: 20GB~Number GB
			这个函数接口是给小型文件来使用的。
		*/
		std::vector<std::byte> Main(const std::vector<std::byte>& PlainText, const std::vector<std::byte>& Key);
		
		Encrypter() = default;
		~Encrypter() = default;

		Encrypter( Encrypter& _object ) = delete;
		Encrypter& operator=( const Encrypter& _object ) = delete;
	};

	inline std::vector<char>& Encrypter::Main(std::vector<char>& PlainText, const std::vector<std::byte>& Key)
	{
		std::vector<std::byte> temporaryByteData;
		Cryptograph::CommonModule::Adapters::characterToByte(PlainText, temporaryByteData);
		PlainText.clear();
		PlainText.shrink_to_fit();
		SplitDataBlockToEncrypt(temporaryByteData, Key);
		Cryptograph::CommonModule::Adapters::characterFromByte(temporaryByteData, PlainText);
		return PlainText;
	}

	inline std::vector<std::byte> Encrypter::Main(const std::vector<std::byte>& PlainText, const std::vector<std::byte>& Key)
	{
		std::vector<std::byte> CipherText(PlainText);
		PaddingData(CipherText);
		SplitDataBlockToEncrypt(CipherText, Key);
		return CipherText;
	}


	/*
		Implementation of Custom Decrypted Data Worker
		自定义解密数据工作器的实现
	*/
	class Decrypter
	{
	
	private:

		std::byte default_binary_key { 250 };

	protected:

		void SplitDataBlockToDecrypt(std::vector<std::byte>& CipherText, const std::vector<std::byte>& Key) const
		{
			using namespace CommonSecurity;

			std::byte temporaryBinaryPassword{default_binary_key};
            std::byte temporaryBinaryPassword2{default_binary_key};
            Cryptograph::Encryption_Tools::Encryption MakeKey;
            Cryptograph::Decryption_Tools::Decryption Worker;
            std::byte temporaryBinaryData;
            std::vector<unsigned int> temporaryIndexSplited = CommonToolkit::make_vector(std::make_integer_sequence<unsigned int, 64>{});

            std::stack<std::byte> temporary_head_stack;
            std::size_t stack_size = CipherText.size() / 65;
			while ( stack_size-- )
			{
				temporary_head_stack.push( CipherText.back() );
				CipherText.pop_back();
			}

			for ( std::size_t datablock_size = 0; datablock_size < CipherText.size(); datablock_size += 64 )
			{
				temporaryBinaryPassword = temporary_head_stack.top();

				//随机置换
				//Random Displacement
				std::mt19937 pseudoRandomGenerator { static_cast<unsigned int>( temporaryBinaryPassword ) };
				CommonSecurity::ShuffleRangeData( temporaryIndexSplited, pseudoRandomGenerator );

				//第一次循环解密
				//First cycle Decryption
				for ( std::size_t round = 0; round < 64; round++ )
				{
					temporaryBinaryData = CipherText[ datablock_size + temporaryIndexSplited[ round ] ];
					std::byte temporaryKey = MakeKey.Main_Encryption( temporaryBinaryPassword, Key[ round + 64 ] );
					Worker.Main_Decryption( CipherText[ datablock_size + temporaryIndexSplited[ round ] ], temporaryKey );
					temporaryBinaryPassword = temporaryBinaryData;
				}

				//第二次循环解密
				//Second cycle decryption
				for ( std::size_t round2 = datablock_size; round2 < 64 + datablock_size; round2++ )
				{
					temporaryBinaryData = CipherText[ round2 ];
					std::byte temporaryKey = MakeKey.Main_Encryption( temporaryBinaryPassword2, Key[ round2 - datablock_size ] );
					Worker.Main_Decryption( CipherText[ round2 ], temporaryKey );
					temporaryBinaryPassword2 = temporaryBinaryData;
				}

				temporaryBinaryPassword2 = temporary_head_stack.top();
				temporary_head_stack.pop();
			}
		}

		/*
			https://en.wikipedia.org/wiki/Padding_(cryptography)

			ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.

			Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
		*/
		void UnpaddingData(std::vector<std::byte>& Data) const
		{
			std::size_t count = std::to_integer<size_t>(Data.back());
			Data.pop_back();
			while (count--)
			{
				Data.pop_back();
			}
		}

	public:
		
		// class CrypticDataThreadingWrapper::FileDataHelper
		// 多线程实现的专用接口，请勿使用不标准的大小数据，进行随意调用，禁止移除该函数！
		// Multi-threaded implementation of the special interface, please do not use non-standard size data, for arbitrary calls, prohibit the removal of the function!
		std::vector<char>& Main(std::vector<char>& CipherText, const std::vector<std::byte>& Key);
		
		/*
			The file size levels are listed here
			Small file size range: 1BYTE~2GB
			Medium file size range: 2GB~20GB
			Large file size range: 20GB~Number GB
			This function interface is for small files.
			
			这里列出文件大小等级规定
			小型文件大小范围: 1BYTE~2GB
			中型文件大小范围: 2GB~20GB
			大型文件大小范围: 20GB~Number GB
			这个函数接口是给小型文件来使用的。
		*/
		std::vector<std::byte> Main(const std::vector<std::byte>& CipherText, const std::vector<std::byte>& Key);

		Decrypter() = default;
		~Decrypter() = default;

		Decrypter( Decrypter& _object ) = delete;
		Decrypter& operator=( const Decrypter& _object ) = delete;
	};

	inline std::vector<char>& Decrypter::Main(std::vector<char>& CipherText, const std::vector<std::byte>& Key)
	{
		std::vector<std::byte> temporaryByteData;
		Cryptograph::CommonModule::Adapters::characterToByte(CipherText, temporaryByteData);
		CipherText.clear();
		CipherText.shrink_to_fit();
		SplitDataBlockToDecrypt(temporaryByteData, Key);
		Cryptograph::CommonModule::Adapters::characterFromByte(temporaryByteData, CipherText);
		return CipherText;
	}

	inline std::vector<std::byte> Decrypter::Main(const std::vector<std::byte>& CipherText, const std::vector<std::byte>& Key)
	{
		std::vector<std::byte> PlainText(CipherText);
		SplitDataBlockToDecrypt(PlainText, Key);
		UnpaddingData(PlainText);
		return PlainText;
	}

}