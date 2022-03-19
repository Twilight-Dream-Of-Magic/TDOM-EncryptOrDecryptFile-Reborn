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

#include "Support+Library/Support-MyType.hpp"

namespace UtilTools
{
	//ASCII characters are they alphabetic characters?
	bool IsAlphabetCharacter( char char_data );

	//ASCII characters are they numbers?
	bool IsNumberCharacter( char char_data );

	//ASCII characters are they is lower alphabetic characters?
	bool IsLowerCase( char char_data );

	//ASCII characters are they is upper alphabetic characters?
	bool IsUpperCase( char char_data );

	//Conversion of ASCII lower case characters to ASCII upper case characters
	char ToLowerCase( char char_data );

	//Conversion of ASCII lower case characters to ASCII upper case characters
	char ToUpperCase( char char_data );

	//ASCII characters are they alphabetic characters?
	bool IsAlphabetCharacter( char char_data )
	{
		int ascii_code = static_cast<int>( char_data );
		if ( ( ( ascii_code >= 0x41 ) && ( ascii_code <= 0x5a ) ) || ( ( ascii_code >= 0x61 ) && ( ascii_code <= 0x7a ) ) )
		{
			return true;
		}
		return false;
	}

	//ASCII characters are they numbers?
	bool IsNumberCharacter( char char_data )
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
	bool IsLowerCase( char char_data )
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
	bool IsUpperCase( char char_data )
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
	char ToLowerCase( char char_data )
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
	char ToUpperCase( char char_data )
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
	requires std::is_integral_v<AnyInteger> std::string IntegerToString( const AnyInteger& input );

	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger> AnyInteger StringToInteger( const std::string& input );

	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger> std::string Integer2Hexadecimal( const AnyInteger& input );

	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger> AnyInteger Hexadecimal2Integer( const std::string& input );

	//---------------------------------------------------------------------------
	// Convert a number to a string
	//---------------------------------------------------------------------------
	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	std::string IntegerToString( const AnyInteger& input )
	{
		std::ostringstream oss;
		std::string output = "";

		#if __cplusplus >= 201703L

		//std::to_chars_result
		auto [ pointer, errorcode ] { std::to_chars( output.data(), output.data() + output.size(), input ) };

		std::error_code errorcode_object = std::make_error_code(errorcode);

		if ( errorcode_object.value() == 0 )
		{
			#if __cplusplus >= 202002L

			std::string_view view_string( output.data(), pointer );
			oss << view_string;
			output = oss.str();
			return output;

			#else

			std::string string_data( output.data(), pointer - output.data() );
			output.swap(string_data);
			return output;

			#endif
		}
		else
		{
			return std::string();
		}

		#endif

		#if __cplusplus >= 201103L

		return std::to_string( input );

		#endif

		oss.clear();

		if ( !( oss << std::dec << input ) )
		{
			std::string error_message = "UtilTools::DataStreamConverter::IntegerToString: Can't convert to string from " + std::to_string( input );
			throw std::invalid_argument( error_message.c_str() );
		}

		output = oss.str();

		return output;
	}

	//---------------------------------------------------------------------------
	// Convert a string to a number
	//---------------------------------------------------------------------------
	template <typename AnyInteger>
	requires std::is_integral_v<AnyInteger>
	AnyInteger StringToInteger( const std::string& input )
	{
		AnyInteger output = 0;

		#if __cplusplus >= 201703L

		//std::from_chars_result
		auto [ pointer, errorcode ] { std::from_chars( input.data(), input.data() + input.size(), output ) };

		std::error_code errorcode_object = std::make_error_code(errorcode);

		if ( errorcode_object.value() == 0 )
		{
			return output;
		}
		else if ( errorcode_object.value() == static_cast<int>(std::errc::invalid_argument) )
		{
			std::cout << "[Error] UtilTools::DataStreamConverter::StringToInteger: That isn't a number." << std::endl;
			std::cout << "[Warning] UtilTools::DataStreamConverter::StringToInteger: Conversion of non-numeric forms of characters into superimposed numbers will be an unrecoverable conversion!" << std::endl;
			std::cout << "[Information] UtilTools::DataStreamConverter::StringToInteger: This input string is: " << input << std::endl;
			for ( size_t index = 0; index < input.size(); ++index )
			{
				output += static_cast<AnyInteger>( input[ index ] );
			}
			std::cout << "[Information] UtilTools::DataStreamConverter::StringToInteger: This output superimposed numbers is: " << output << std::endl;
			return output;
		}
		else if ( errorcode_object.value() == static_cast<int>(std::errc::result_out_of_range) )
		{
			std::cout << "[Error] UtilTools::DataStreamConverter::StringToInteger: This number is larger than an integer." << std::endl;
			return 0;
		}

		#endif

		#if __cplusplus >= 201103L

		if ( typeid( int ) == typeid( AnyInteger ) )
		{
			return std::stoi( input );
		}
		else if ( typeid( long int ) == typeid( AnyInteger ) )
		{
			return std::stol( input );
		}
		else if ( typeid( long long int ) == typeid( AnyInteger ) )
		{
			return std::stoll( input );
		}

		#endif

		if ( input.size() == 0 )
		{
			return 0;
		}

		std::istringstream iss( input );

		if ( !( iss >> std::dec >> output ) )
		{
			throw std::invalid_argument( "UtilTools::DataStreamConverter::StringToInteger: Can't convert to integer from " + input );
		}
		return output;
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

		if ( !( oss << std::hex << input ) )
		{
			std::string error_message = "[Error] UtilTools::DataStreamConverter::Integer2Hexadecimal: Can't convert to string from " + input;
			throw std::invalid_argument( error_message.c_str() );
		}

		std::string output = oss.str();
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

		if ( !( iss >> std::hex >> output ) )
		{
			throw std::invalid_argument( "[Error] UtilTools::DataStreamConverter::Hexadecimal2Integer: Can't convert to integer from " + input );
		}
		return output;
	}
}  // namespace UtilTools::DataStreamConverter