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

//文件的数据置换或者数据逆置换
//Data permutation or data reverse permutation of files
namespace Cryptograph::DataPermutation
{
	//16进制字符串数据
	struct HexadecimalStringCoder
	{
		//	数据置换函数
		//
		//	Return: Disorded hexadecimal formated string
		//	Parameters: Hexadecimal formated string
		std::string DataDisorder( const std::string& string_file_data )
		{
			std::string encoded = std::string( string_file_data );

			if(string_file_data.size() < 2)
			{
				return encoded;
			}

			std::vector<std::uint8_t> byte_array;
			std::size_t accumulator = string_file_data.size();

			for(const auto& character : string_file_data)
			{
				byte_array.push_back(character);
				accumulator += static_cast<std::uint8_t>(character);
			}

			//正向置换加密
			//Forward permutation encryption
			std::size_t index = encoded.size() - 1;
			while(index > 0)
			{
				const std::size_t round_index = accumulator % (index + 1);
				std::swap(byte_array[index], byte_array[round_index]);
				--index;
			}

			encoded.clear();
			encoded.shrink_to_fit();
			for(auto& byte : byte_array)
			{
				encoded.push_back(static_cast<std::int8_t>(byte));
			}

			byte_array.clear();
			byte_array.shrink_to_fit();
			std::cout << "The string encode result is: " << encoded << std::endl;

			//Return ciphertext data
			return encoded;
		}

		//	数据逆置换函数
		//
		//	Return: Ordered hexadecimal formated string
		//	Parameters: Disorded hexadecimal formated string
		std::string DataOrder( const std::string& string_file_data )
		{
			std::string decoded = std::string( string_file_data );

			if(string_file_data.size() < 2)
			{
				return decoded;
			}

			std::vector<std::uint8_t> byte_array;
			std::size_t accumulator = string_file_data.size();

			for(const auto& character : string_file_data)
			{
				byte_array.push_back(character);
				accumulator += static_cast<std::uint8_t>(character);
			}

			//逆向置换解密
			//Reverse permutation decryption
			std::size_t index = 0;
			while(index < decoded.size())
			{
				const std::size_t round_index = accumulator % (index + 1);
				std::swap(byte_array[index], byte_array[round_index]);
				++index;
			}

			decoded.clear();
			decoded.shrink_to_fit();
			for(auto& byte : byte_array)
			{
				decoded.push_back(static_cast<std::int8_t>(byte));
			}

			byte_array.clear();
			byte_array.shrink_to_fit();
			std::cout << "The string decode result is: " << decoded << std::endl;

			//Return plaintext data
			return decoded;
		}
	};
}  // namespace Cryptograph::DataPermutation

namespace Cryptograph::Encryption_Tools
{
	/*
		@author Project Owner and Module Designer: Twilight-Dream
		@author Algorithm Designer: Spiritual-Fish

		@brief OaldresPuzzle-Cryptic's Core - Symmetric Encryption Algorithm Implementation
		@brief OaldresPuzzle-Cryptic的核心 - 对称加密算法实现
	*/
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

	inline std::byte Encryption::Main_Encryption( std::byte& data, const std::byte& Key )
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

		//Non-linear processing - random bit switching
		//非线性处理 - 随机比特位切换
		BitToggle( data, move_bit );

		return data;
	}

}  // namespace Cryptograph::Encryption_Tools

namespace Cryptograph::Decryption_Tools
{
	/*
		@author Project Owner and Module Designer: Twilight-Dream
		@author Algorithm Designer: Spiritual-Fish

		@brief OaldresPuzzle-Cryptic's Core - Symmetric Decryption Algorithm Implementation
		@brief OaldresPuzzle-Cryptic的核心 - 对称解密算法实现
	*/
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

	inline std::byte Decryption::Main_Decryption( std::byte& data, const std::byte& Key )
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

		//Non-linear processing - random bit switching
		//非线性处理 - 随机比特位切换
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