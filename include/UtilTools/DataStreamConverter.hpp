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

#include "../Support+Library/Support-MyType.hpp"

namespace UtilTools
{
	//ASCII characters are they alphabetic characters?
	inline bool IsAlphabetCharacter( char char_data );

	//ASCII characters are they numbers?
	inline bool IsNumberCharacter( char char_data );

	//ASCII characters are they is lower alphabetic characters?
	inline bool IsLowerCase( char char_data );

	//ASCII characters are they is upper alphabetic characters?
	inline bool IsUpperCase( char char_data );

	//Conversion of ASCII lower case characters to ASCII upper case characters
	inline char ToLowerCase( char char_data );

	//Conversion of ASCII lower case characters to ASCII upper case characters
	inline char ToUpperCase( char char_data );

	//ASCII characters are they alphabetic characters?
	inline bool IsAlphabetCharacter( char char_data )
	{
		int ascii_code = static_cast<int>( char_data );
		if ( ( ( ascii_code >= 0x41 ) && ( ascii_code <= 0x5a ) ) || ( ( ascii_code >= 0x61 ) && ( ascii_code <= 0x7a ) ) )
		{
			return true;
		}
		return false;
	}

	//ASCII characters are they numbers?
	inline bool IsNumberCharacter( char char_data )
	{
		int ascii_code = static_cast<int>( char_data );

		//0x30 <=> 48 <=> '0'
		//0x39 <=> 57 <=> '9'
		if ( ( ( ascii_code >= 0x30 ) && ( ascii_code <= 0x39 ) ) )
		{
			return true;
		}
		return false;
	}

	//ASCII characters are they is lower alphabetic characters?
	inline bool IsLowerCase( char char_data )
	{
		int ascii_code = static_cast<int>( char_data );

		//0x61 <=> 97 <=> 'a'
		//0x7a <=> 122 <=> 'z'
		if ( ( ascii_code >= 0x61 ) && ( ascii_code <= 0x7a ) )
		{
			return true;
		}
		return false;
	}

	//ASCII characters are they is upper alphabetic characters?
	inline bool IsUpperCase( char char_data )
	{
		int ascii_code = static_cast<int>( char_data );

		//0x41 <=> 65 <=> 'A'
		//0x5a <=> 90 <=> 'Z'
		if ( ( ascii_code >= 0x41 ) && ( ascii_code <= 0x5a ) )
		{
			return true;
		}
		return false;
	}

	//Conversion of ASCII lower case characters to ASCII upper case characters
	inline char ToLowerCase( char char_data )
	{
		int ascii_code = static_cast<int>( char_data );

		//0x41 <=> 65 <=> 'A'
		//0x5a <=> 90 <=> 'Z'
		if ( ( ascii_code >= 0x41 ) && ( ascii_code <= 0x5a ) )
		{
			int new_ascii_code = ascii_code + ( 0x61 - 0x41 );
			char_data = static_cast<char>( new_ascii_code );
		}
		return char_data;
	}

	//Conversion of ASCII lower case characters to ASCII upper case characters
	inline char ToUpperCase( char char_data )
	{
		int ascii_code = static_cast<int>( char_data );

		//0x61 <=> 97 <=> 'a'
		//0x7a <=> 122 <=> 'z'
		if ( ( ascii_code >= 0x61 ) && ( ascii_code <= 0x7a ) )
		{
			int new_ascii_code = ascii_code + ( 0x41 - 0x61 );
			char_data = static_cast<char>( new_ascii_code );
		}
		return char_data;
	}
}  // namespace UtilTools

namespace UtilTools::DataStreamConverter
{
	/*
		C++ pre-C++98: __cplusplus is 1
		C++98: __cplusplus is 199711L
		C++98 + TR1: This reads as C++98 and there is no way to check that I know of
		C++11: __cplusplus is 201103L
		C++14: __cplusplus is 201402L
		C++17: __cplusplus is 201703L
		C++20: __cplusplus is 202002L
	*/

	// For integer and hexadecimal string the exchange converter
	// For integer and string the exchange converter

	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	std::string IntegerToString( const AnyInteger* input, const std::size_t& input_size, bool raw_mode );

	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	std::vector<AnyInteger> StringToInteger( const std::string& input, bool raw_mode );

	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	std::string Integer2Hexadecimal( const AnyInteger& input );

	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	AnyInteger Hexadecimal2Integer( const std::string& input );

	//---------------------------------------------------------------------------
	// Convert a numbers to a string
	//---------------------------------------------------------------------------
	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	std::string IntegerToString( const AnyInteger* input, const std::size_t& input_size, bool raw_mode = true )
	{
		std::string output;

		std::vector<AnyInteger> integers { input, input_size };

		if(raw_mode)
		{
			for(AnyInteger& integer : integers)
			{
				auto character = static_cast<char>(integer);
				output.push_back(integer);
			}

			return output;
		}
		else
		{
			#if __cplusplus >= 201703L

			std::size_t string_index = 0;

			for(AnyInteger& integer : integers)
			{
				//std::to_chars_result
				auto [ pointer, errorcode ] { std::to_chars( output.data() + string_index, output.data() + string_index * sizeof(char), integer ) };

				std::error_code errorcode_object = std::make_error_code(errorcode);

				if ( errorcode_object.value() == 0 )
				{
					#if __cplusplus >= 202002L

					std::string_view view_string( output.data(), pointer );
					output.append(view_string.begin(), view_string.end());

					#else

					std::string string_data( output.data(), pointer - output.data() );
					output.append(string_data);

					#endif
				}
				else
				{
					throw errorcode;
				}
				++string_index;
			}

			return output;

			#endif

			#if __cplusplus >= 201103L

			return std::to_string( input );

			#endif

			std::ostringstream oss;

			oss.clear();

			auto backup_format_flags = oss.flags();

			for(AnyInteger& integer : integers)
			{
				if ( !( oss << std::dec << integer ) )
				{
					std::string error_message = "UtilTools::DataStreamConverter::IntegerToString: Can't convert to string from " + std::to_string( input );
					throw std::invalid_argument( error_message.c_str() );
				}
			}

			output = oss.str();

			oss.flags(backup_format_flags);

			return output;
		}
	}

	//---------------------------------------------------------------------------
	// Convert a string to a numbers
	//---------------------------------------------------------------------------
	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	std::vector<AnyInteger> StringToInteger( const std::string& input, bool raw_mode = true )
	{
		std::vector<char> characters { input.data(), input.data() + input.size() };

		std::vector<AnyInteger> output;

		if( input.empty() )
		{
			throw std::invalid_argument("[Error] UtilTools::DataStreamConverter::StringToInteger: The size of the string cannot be zero!");
		}

		if( raw_mode )
		{
			for(auto& character : characters)
			{
				auto integer = static_cast<AnyInteger>(character);
				output.push_back(integer);
			}

			return output;
		}
		else
		{
			output.resize(characters.size());

			#if __cplusplus >= 201703L

			std::size_t integers_index = 0;

			for (char& character : characters )
			{
				if(!IsNumberCharacter(character))
				{
					output[integers_index] = static_cast<AnyInteger>(character);
				}
				else
				{
					//std::from_chars_result
					auto [ pointer, errorcode ] { std::from_chars( &character, &character + integers_index * sizeof(character), output[integers_index] ) };

					std::error_code errorcode_object = std::make_error_code(errorcode);

					if ( errorcode_object.value() == static_cast<AnyInteger>(std::errc::invalid_argument) )
					{
						std::cout << "[Error] UtilTools::DataStreamConverter::StringToInteger: That isn't a number." << std::endl;
					}
					else if ( errorcode_object.value() == static_cast<AnyInteger>(std::errc::result_out_of_range) )
					{
						std::cout << "[Error] UtilTools::DataStreamConverter::StringToInteger: This number is larger than an integer." << std::endl;
						throw errorcode;
					}
				}
				++integers_index;
			}

			return output;

			#endif

			#if __cplusplus >= 201103L

			if ( std::is_same_v<AnyInteger, int> )
			{
				for(char& character : characters)
				{
					output.push_back(std::atoi( &character ));
				}
			}
			else if ( std::is_same_v<AnyInteger, long int> )
			{
				for(char& character : characters)
				{
					output.push_back(std::atol( &character ));
				}
			}
			else if ( std::is_same_v<AnyInteger, long long int> )
			{
				for(char& character : characters)
				{
					output.push_back(std::atoll( &character ));
				}
			}

			return output;

			#endif

			std::istringstream iss( input );

			auto backup_format_flags = iss.flags();

			for(AnyInteger& integer : output)
			{
				if ( !( iss >> std::dec >> integer ) )
				{
					throw std::invalid_argument( "UtilTools::DataStreamConverter::StringToInteger: Can't convert to integer from " + input );
				}
			}

			iss.flags(backup_format_flags);

			return output;
		}
	}

	//---------------------------------------------------------------------------
	// Convert an hexadecimal string to a number
	//---------------------------------------------------------------------------
	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	std::string Integer2Hexadecimal( const AnyInteger& input )
	{
		std::ostringstream oss;
		oss.clear();

		auto backup_format_flags = oss.flags();

		if ( !( oss << std::hex << input ) )
		{
			std::string error_message = "[Error] UtilTools::DataStreamConverter::Integer2Hexadecimal: Can't convert to string from " + input;
			throw std::invalid_argument( error_message.c_str() );
		}

		std::string output = oss.str();

		oss.flags(backup_format_flags);

		return output;
	}

	//---------------------------------------------------------------------------
	// Convert a number to an hexadecimal string
	//---------------------------------------------------------------------------
	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	AnyInteger Hexadecimal2Integer( const std::string& input )
	{
		if ( input.size() == 0 )
		{
			return 0;
		}

		std::istringstream iss( input );
		AnyInteger		   output = 0;

		auto backup_format_flags = iss.flags();

		if ( !( iss >> std::hex >> output ) )
		{
			throw std::invalid_argument( "[Error] UtilTools::DataStreamConverter::Hexadecimal2Integer: Can't convert to integer from " + input );
		}

		iss.flags(backup_format_flags);

		return output;
	}
}  // namespace UtilTools::DataStreamConverter