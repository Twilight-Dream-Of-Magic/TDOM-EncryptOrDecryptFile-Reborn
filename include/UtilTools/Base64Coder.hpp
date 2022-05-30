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

namespace UtilTools::DataFormating::Base64Coder
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

	static constexpr std::array<MySupport_Library::Types::my_byte_type, 128> from_base64
	{
		// 8 rows of 16 = 128
		// Note: only requires 123 entries, as we only lookup for <= z , which z=122

		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,	 //
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,	 //
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,	255, 62,  255, 63,	 //
		52,	 53,  54,  55,	56,	 57,  58,  59,	60,	 61,  255, 255, 0,	 255, 255, 255,	 //
		255, 0,	  1,   2,	3,	 4,	  5,   6,	7,	 8,	  9,   10,	11,	 12,  13,  14,	 //
		15,	 16,  17,  18,	19,	 20,  21,  22,	23,	 24,  25,  255, 255, 255, 255, 63,	 //
		255, 26,  27,  28,	29,	 30,  31,  32,	33,	 34,  35,  36,	37,	 38,  39,  40,	 //
		41,	 42,  43,  44,	45,	 46,  47,  48,	49,	 50,  51,  255, 255, 255, 255, 255	 //
	};

	static constexpr std::array<char, 64> to_base64
	{
		'A','B','C','D','E','F','G','H',
		'I','J','K','L','M','N','O','P',
		'Q','R','S','T','U','V','W','X',
		'Y','Z','a','b','c','d','e','f',
		'g','h','i','j','k','l','m','n',
		'o','p','q','r','s','t','u','v',
		'w','x','y','z','0','1','2','3',
		'4','5','6','7','8','9','+','/'
	};

	namespace Author1
	{

		#if __cplusplus >= 201402L

		inline static constexpr const std::array<char, 64>& kBase64AlphabetTable = to_base64;
		inline static constexpr const char kPaddingCharacter = '=';

		inline std::string encode( const std::vector<MySupport_Library::Types::my_byte_type>& input )
		{
			std::string encoded;
			encoded.reserve( ( ( input.size() / 3 ) + ( input.size() % 3 > 0 ) ) * 4 );

			std::size_t temporary {};
			auto		iterator_data = input.begin();

			for ( std::size_t i = 0; i < input.size() / 3; ++i )
			{
				temporary = ( *iterator_data++ ) << 16;
				temporary += ( *iterator_data++ ) << 8;
				temporary += ( *iterator_data++ );
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x00FC0000 ) >> 18 ] );
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x0003F000 ) >> 12 ] );
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x00000FC0 ) >> 6 ] );
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x0000003F ) ] );
			}

			switch ( input.size() % 3 )
			{

			case 1:
				temporary = ( *iterator_data++ ) << 16;
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x00FC0000 ) >> 18 ] );
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x0003F000 ) >> 12 ] );
				encoded.append( 2, kPaddingCharacter );
				break;
			case 2:
				temporary = ( *iterator_data++ ) << 16;
				temporary += ( *iterator_data++ ) << 8;
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x00FC0000 ) >> 18 ] );
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x0003F000 ) >> 12 ] );
				encoded.append( 1, kBase64AlphabetTable[ ( temporary & 0x00000FC0 ) >> 6 ] );
				encoded.append( 1, kPaddingCharacter );
				break;
			default:
				break;
			}

			return encoded;
		}

		inline std::vector<MySupport_Library::Types::my_byte_type> decode( const std::string& input )
		{
			if ( input.length() % 4 )
				throw std::runtime_error( "Invalid base64 length!" );

			std::size_t padding {};

			if ( input.length() )
			{
				if ( input[ input.length() - 1 ] == kPaddingCharacter )
					padding++;
				if ( input[ input.length() - 2 ] == kPaddingCharacter )
					padding++;
			}

			std::vector<MySupport_Library::Types::my_byte_type> decoded;
			decoded.reserve( ( ( input.length() / 4 ) * 3 ) - padding );

			std::size_t temporary {};
			auto		iterator_data = input.begin();

			while ( iterator_data < input.end() )
			{
				for ( std::size_t i = 0; i < 4; ++i )
				{
					temporary <<= 6;
					if ( *iterator_data >= 0x41 && *iterator_data <= 0x5A )
						temporary |= *iterator_data - 0x41;
					else if ( *iterator_data >= 0x61 && *iterator_data <= 0x7A )
						temporary |= *iterator_data - 0x47;
					else if ( *iterator_data >= 0x30 && *iterator_data <= 0x39 )
						temporary |= *iterator_data + 0x04;
					else if ( *iterator_data == 0x2B )
						temporary |= 0x3E;
					else if ( *iterator_data == 0x2F )
						temporary |= 0x3F;
					else if ( *iterator_data == kPaddingCharacter )
					{
						switch ( input.end() - iterator_data )
						{
						case 1:
							decoded.push_back( ( temporary >> 16 ) & 0x000000FF );
							decoded.push_back( ( temporary >> 8 ) & 0x000000FF );
							return decoded;
						case 2:
							decoded.push_back( ( temporary >> 10 ) & 0x000000FF );
							return decoded;
						default:
							throw std::runtime_error( "Invalid padding in base64!" );
						}
					}
					else
						throw std::runtime_error( "Invalid character in base64!" );

					++iterator_data;
				}

				decoded.push_back( ( temporary >> 16 ) & 0x000000FF );
				decoded.push_back( ( temporary >> 8 ) & 0x000000FF );
				decoded.push_back( ( temporary )&0x000000FF );
			}

			return decoded;
		}

		#endif

	}  // namespace Author1



	namespace Author2
	{

		//
		// Depending on the url parameter in base64_chars, one of
		// two sets of base64 characters needs to be chosen.
		// They differ in their last two characters.
		//
		static constexpr std::array<std::array<char, 64>, 2> base64_chars
		{
			{
				{
					'A','B','C','D','E','F','G','H',
					'I','J','K','L','M','N','O','P',
					'Q','R','S','T','U','V','W','X',
					'Y','Z','a','b','c','d','e','f',
					'g','h','i','j','k','l','m','n',
					'o','p','q','r','s','t','u','v',
					'w','x','y','z','0','1','2','3',
					'4','5','6','7','8','9','+','/'
				},
				{
					'A','B','C','D','E','F','G','H',
					'I','J','K','L','M','N','O','P',
					'Q','R','S','T','U','V','W','X',
					'Y','Z','a','b','c','d','e','f',
					'g','h','i','j','k','l','m','n',
					'o','p','q','r','s','t','u','v',
					'w','x','y','z','0','1','2','3',
					'4','5','6','7','8','9','-','_'
				}
			},
		};

		//数据Base64编码和数据Base64解码
		//Data Base64 encoding and data Base64 decoding
		struct Base64
		{

			//
			//	@brief Base64 encoding and decoding with c++
			//  @file origin https://github.com/ReneNyffenegger/cpp-base64
			//	base64 encoding and decoding with C++.
			//	Version: 2.rc.08 (release candidate)
			//	fixed by Twilight-Dream
			//

			/*
			   base64.cpp and base64.h
			   base64 encoding and decoding with C++.
			   More information at
				https://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp
				Version: 2.rc.08 (release candidate)
				Copyright (C) 2004-2017, 2020, 2021 Rene Nyffenegger
				This source code is provided 'as-is', without any express or implied
				warranty. In no event will the author be held liable for any damages
				arising from the use of this software.
				Permission is granted to anyone to use this software for any purpose,
				including commercial applications, and to alter it and redistribute it
				freely, subject to the following restrictions:
				1. The origin of this source code must not be misrepresented; you must not
					claim that you wrote the original source code. If you use this source code
					in a product, an acknowledgment in the product documentation would be
					appreciated but is not required.
				2. Altered source versions must be plainly marked as such, and must not be
					misrepresented as being the original source code.
				3. This notice may not be removed or altered from any source distribution.
				Rene Nyffenegger rene.nyffenegger@adp-gmbh.ch
			*/

			std::string encoding( unsigned char const* bytes_encode_base64string, std::size_t in_length, bool url )
			{

				std::size_t size_encoded = ( in_length + 2 ) / 3 * 4;

				unsigned char trailing_char = url ? '.' : '=';

				//
				// Choose set of base64 characters.
				// They differ for the last two positions,
				// depending on the url parameter.
				// A bool (as is the parameter url)
				// is guaranteed to evaluate to either 0 or 1 in C++ therefore,
				// the correct character set is chosen by subscripting base64_chars with url.
				//
				const std::array<char, 64> base64_chars_ = base64_chars[ url ];

				std::string result;
				result.reserve( size_encoded );

				std::size_t position = 0;

				while ( position < in_length )
				{
					result.push_back( base64_chars_[ ( bytes_encode_base64string[ position + 0 ] & 0xfc ) >> 2 ] );

					if ( position + 1 < in_length )
					{
						result.push_back( base64_chars_[ ( ( bytes_encode_base64string[ position + 0 ] & 0x03 ) << 4 ) + ( ( bytes_encode_base64string[ position + 1 ] & 0xf0 ) >> 4 ) ] );

						if ( position + 2 < in_length )
						{
							result.push_back( base64_chars_[ ( ( bytes_encode_base64string[ position + 1 ] & 0x0f ) << 2 ) + ( ( bytes_encode_base64string[ position + 2 ] & 0xc0 ) >> 6 ) ] );
							result.push_back( base64_chars_[ bytes_encode_base64string[ position + 2 ] & 0x3f ] );
						}
						else
						{
							result.push_back( base64_chars_[ ( bytes_encode_base64string[ position + 1 ] & 0x0f ) << 2 ] );
							result.push_back( trailing_char );
						}
					}
					else
					{

						result.push_back( base64_chars_[ ( bytes_encode_base64string[ position + 0 ] & 0x03 ) << 4 ] );
						result.push_back( trailing_char );
						result.push_back( trailing_char );
					}

					position += 3;
				}


				return result;
			}

			template <typename StringType>
			requires std::is_base_of_v<std::string, StringType> || std::is_same_v<std::string_view, StringType>
			std::string decoding( StringType base64string_decode_bytes )
			{
				//
				// decode() is templated so that it can be used with
				// StringType = const std::string& or std::string_view (requires at least C++17)
				//

				std::size_t size_of_string_decoded = base64string_decode_bytes.size();
				std::size_t position = 0;

				//
				// The approximate length (bytes) of the decoded string might be one or
				// two bytes smaller, depending on the amount of trailing equal signs
				// in the encoded string. This approximation is needed to reserve
				// enough space in the string to be returned.
				//
				std::size_t approx_length_of_decoded_string = size_of_string_decoded / 4 * 3;
				std::string result;
				result.reserve( approx_length_of_decoded_string );

				while ( position < size_of_string_decoded )
				{
					//
					// Iterate over encoded input string in chunks. The size of all
					// chunks except the last one is 4 bytes.
					//
					// The last chunk might be padded with equal signs or dots
					// in order to make it 4 bytes in size as well, but this
					// is not required as per RFC 2045.
					//
					// All chunks except the last one produce three output bytes.
					//
					// The last chunk produces at least one and up to three bytes.
					//

					std::size_t pos_of_char_1 = position_of_character( base64string_decode_bytes[ position + 1 ] );

					//
					// Emit the first output byte that is produced in each chunk:
					//
					result.push_back( static_cast<std::string::value_type>( ( ( position_of_character( base64string_decode_bytes[ position + 0 ] ) ) << 2 ) + ( ( pos_of_char_1 & 0x30 ) >> 4 ) ) );

					// Check for data that is not padded with equal signs (which is allowed by RFC 2045)
					bool data_that_is_not_padded = position + 2 < size_of_string_decoded;
					bool with_equal_signs = base64string_decode_bytes[ position + 2 ] != '=';

					// accept URL-safe base 64 strings, too, so check for '.' also.
					bool check_point_character = base64string_decode_bytes[ position + 2 ] != '.';

					if ( data_that_is_not_padded && with_equal_signs && check_point_character )
					{
						//
						// Emit a chunk's second byte (which might not be produced in the last chunk).
						//
						unsigned int pos_of_char_2 = position_of_character( base64string_decode_bytes[ position + 2 ] );
						result.push_back( static_cast<std::string::value_type>( ( ( pos_of_char_1 & 0x0f ) << 4 ) + ( ( pos_of_char_2 & 0x3c ) >> 2 ) ) );

						if ( ( position + 3 < size_of_string_decoded ) && base64string_decode_bytes[ position + 3 ] != '=' && base64string_decode_bytes[ position + 3 ] != '.' )
						{
							//
							// Emit a chunk's third byte (which might not be produced in the last chunk).
							//
							result.push_back( static_cast<std::string::value_type>( ( ( pos_of_char_2 & 0x03 ) << 6 ) + position_of_character( base64string_decode_bytes[ position + 3 ] ) ) );
						}
					}

					position += 4;
				}

				return result;
			}

			static std::size_t position_of_character( const unsigned char chr )
			{
				//
				// Return the position of chr within base64_encode()
				//

				if ( chr >= 'A' && chr <= 'Z' )
					return chr - 'A';
				else if ( chr >= 'a' && chr <= 'z' )
					return chr - 'a' + ( 'Z' - 'A' ) + 1;
				else if ( chr >= '0' && chr <= '9' )
					return chr - '0' + ( 'Z' - 'A' ) + ( 'z' - 'a' ) + 2;
				else if ( chr == '+' || chr == '-' )
					return 62;	// Be liberal with input and accept both url ('-') and non-url ('+') base 64 characters (
				else if ( chr == '/' || chr == '_' )
					return 63;	// Ditto for '/' and '_'
				else
					//
					// 2020-10-23: Throw std::exception rather than const char*
					//(Pablo Martin-Gomez, https://github.com/Bouska)
					//
					throw std::runtime_error( "Input is not valid base64-encoded data." );
			}

			static std::string insert_linebreaks( std::string string_object, std::size_t distance )
			{
				//
				// Provided by https://github.com/JomaCorpFX, adapted by me.
				//
				if ( string_object.size() == 0 )
				{
					return "";
				}

				std::size_t position = distance;

				while ( position < string_object.size() )
				{
					string_object.insert( position, "\n" );
					position += distance + 1;
				}

				return string_object;
			}

			template <typename StringType, std::size_t line_length>
			requires std::is_base_of_v<std::string, StringType> || std::is_same_v<std::string_view, StringType>
			static std::string encode_with_line_breaks(Base64& object, StringType string_object )
			{
				return insert_linebreaks( object.encoder( object, string_object, false ), line_length );
			}

			template <typename StringType>
			requires std::is_base_of_v<std::string, StringType> || std::is_same_v<std::string_view, StringType>
			static std::string encode_pem(Base64& object, StringType string_object )
			{
				return encode_with_line_breaks<StringType, 64>(object, string_object );
			}

			template <typename StringType>
			requires std::is_base_of_v<std::string, StringType> || std::is_same_v<std::string_view, StringType>
			static std::string encode_mime(Base64& object, StringType string_object )
			{
				return encode_with_line_breaks<StringType, 76>(object, string_object );
			}

			template <typename StringType>
			requires std::is_base_of_v<std::string, StringType> || std::is_same_v<std::string_view, StringType>
			static std::string encoder(Base64& object, StringType string_object, bool url )
			{
				return object.encoding( reinterpret_cast<const unsigned char*>( string_object.data() ), string_object.length(), url );
			}

			template <typename StringType>
			requires std::is_base_of_v<std::string, StringType> || std::is_same_v<std::string_view, StringType>
			static std::string decoder(Base64& object, StringType base64string_decode_to_bytes, bool remove_linebreaks )
			{
				if ( base64string_decode_to_bytes.empty() )
					return std::string();

				if ( remove_linebreaks )
				{

					std::string copy( base64string_decode_to_bytes );

					copy.erase( std::remove( copy.begin(), copy.end(), '\n' ), copy.end() );

					return Base64::decoder(object, copy, false );
				}

				return object.decoding( base64string_decode_to_bytes );
			}

			#if __cplusplus < 201703L

			std::string base64_encode( std::string& base64string_decode_bytes, bool url )
			{
				return Base64::encoder( base64string_decode_bytes, url );
			}

			std::string base64_encode_pem( std::string& base64string_decode_bytes )
			{
				return Base64::encode_pem( base64string_decode_bytes );
			}

			std::string base64_encode_mime( std::string& base64string_decode_bytes )
			{
				return Base64::encode_mime( base64string_decode_bytes );
			}

			std::string base64_decode( std::string& base64string_decode_bytes, bool remove_linebreaks )
			{
				return Base64::decoder( base64string_decode_bytes, remove_linebreaks );
			}

			#else

			//
			// Interface with std::string_view rather than const std::string&
			// Requires C++17
			// Provided by Yannic Bonenberger (https://github.com/Yannic)
			//

			std::string base64_encode( std::string_view base64string_decode_bytes, bool url )
			{
				return Base64::encoder(*this, base64string_decode_bytes, url );
			}

			std::string base64_encode_pem( std::string_view base64string_decode_bytes )
			{
				return Base64::encode_pem(*this, base64string_decode_bytes );
			}

			std::string base64_encode_mime( std::string_view base64string_decode_bytes )
			{
				return Base64::encode_mime(*this, base64string_decode_bytes );
			}

			std::string base64_decode( std::string_view base64string_decode_bytes, bool remove_linebreaks )
			{
				return Base64::decoder(*this, base64string_decode_bytes, remove_linebreaks );
			}

			#endif	// __cplusplus >= 201703L
		};

	}  // namespace Author2



	namespace Author3
	{

		static constexpr const std::array<char, 64>& encoding_table = to_base64;

		static constexpr std::array<unsigned char, 256> decoding_table
		{

			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,	 //
			0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,	 //
			0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,	 //
			0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	 //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	 //
		};

		inline std::unique_ptr<char[]> base64_encode( const unsigned char* input_data, std::size_t input_length, std::size_t& output_length )
		{
			const int mod_table[] = { 0, 2, 1 };

			output_length = 4 * ( ( input_length + 2 ) / 3 );

			std::unique_ptr<char[]> encoded_data = std::unique_ptr<char[]>( new char[output_length] );

			if ( encoded_data == nullptr )
				return nullptr;

			for ( std::size_t i = 0, j = 0; i < input_length; )
			{
				std::size_t _a = i < input_length ? ( unsigned char )input_data[ i++ ] : 0;
				std::size_t _b = i < input_length ? ( unsigned char )input_data[ i++ ] : 0;
				std::size_t _c = i < input_length ? ( unsigned char )input_data[ i++ ] : 0;

				std::size_t triple = ( _a << 0x10 ) + ( _b << 0x08 ) + _c;

				encoded_data[ j++ ] = encoding_table[ ( triple >> 3 * 6 ) & 0x3F ];
				encoded_data[ j++ ] = encoding_table[ ( triple >> 2 * 6 ) & 0x3F ];
				encoded_data[ j++ ] = encoding_table[ ( triple >> 1 * 6 ) & 0x3F ];
				encoded_data[ j++ ] = encoding_table[ ( triple >> 0 * 6 ) & 0x3F ];
			}

			for ( int i = 0; i < mod_table[ input_length % 3 ]; i++ )
				encoded_data[ output_length - 1 - i ] = '=';

			return encoded_data;
		};

		inline std::unique_ptr<unsigned char[]> base64_decode( const char* input_data, std::size_t input_length, std::size_t& output_length )
		{
			if ( input_length % 4 != 0 )
				return nullptr;

			output_length = input_length / 4 * 3;

			if ( input_data[ input_length - 1 ] == '=' )
				( output_length )--;
			if ( input_data[ input_length - 2 ] == '=' )
				( output_length )--;

			std::unique_ptr<unsigned char[]> decoded_data = std::unique_ptr<unsigned char[]>( new unsigned char[output_length] );

			if ( decoded_data == nullptr )
				return nullptr;

			for ( std::size_t i = 0, j = 0; i < input_length; )
			{

				std::size_t _a = input_data[ i ] == '=' ? 0 & i++ : decoding_table[ input_data[ i++ ] ];
				std::size_t _b = input_data[ i ] == '=' ? 0 & i++ : decoding_table[ input_data[ i++ ] ];
				std::size_t _c = input_data[ i ] == '=' ? 0 & i++ : decoding_table[ input_data[ i++ ] ];
				std::size_t _d = input_data[ i ] == '=' ? 0 & i++ : decoding_table[ input_data[ i++ ] ];

				std::size_t triple = ( _a << 3 * 6 ) + ( _b << 2 * 6 ) + ( _c << 1 * 6 ) + ( _d << 0 * 6 );

				if ( j < output_length )
					decoded_data[ j++ ] = ( triple >> 2 * 8 ) & 0xFF;
				if ( j < output_length )
					decoded_data[ j++ ] = ( triple >> 1 * 8 ) & 0xFF;
				if ( j < output_length )
					decoded_data[ j++ ] = ( triple >> 0 * 8 ) & 0xFF;
			}

			return decoded_data;
		};

	}  // namespace Author3

	namespace Author4
	{

		#if __cplusplus >= 201103L

		void base64_encode( std::string& out, const std::vector< MySupport_Library::Types::my_byte_type >& bytes_encode_to_base64string );
		void base64_encode( std::string& out, const MySupport_Library::Types::my_byte_type* bytes_encode_to_base64string, std::size_t buffer_length );
		void base64_encode( std::string& out, std::string const& bytes_encode_to_base64string );

		void base64_decode( std::vector< MySupport_Library::Types::my_byte_type >& out, std::string const& base64string_decode_to_bytes );

		// Use this if you know the output should be a valid string
		void base64_decode( std::string& out, std::string const& base64string_decode_to_bytes );

		inline void base64_encode( std::string& result, std::string const& bytes_encode_to_base64string )
		{
			if ( bytes_encode_to_base64string.empty() )
				base64_encode( result, nullptr, 0 );
			else
				base64_encode( result, reinterpret_cast<MySupport_Library::Types::my_byte_type const*>( &bytes_encode_to_base64string[ 0 ] ), bytes_encode_to_base64string.size() );
		}

		inline void base64_encode( std::string& result, std::vector<MySupport_Library::Types::my_byte_type> const& bytes_encode_to_base64string )
		{
			if ( bytes_encode_to_base64string.empty() )
				base64_encode( result, nullptr, 0 );
			else
				base64_encode( result, &bytes_encode_to_base64string[ 0 ], bytes_encode_to_base64string.size() );
		}

		inline void base64_encode( std::string& result, MySupport_Library::Types::my_byte_type const* bytes_encode_to_base64string, std::size_t buffer_length )
		{
			// Calculate how many bytes that needs to be added to get a multiple of 3
			std::size_t missing = 0;
			std::size_t ret_size = buffer_length;
			while ( ( ret_size % 3 ) != 0 )
			{
				++ret_size;
				++missing;
			}

			// Expand the return string size to a multiple of 4
			ret_size = 4 * ret_size / 3;

			result.clear();
			result.reserve( ret_size );

			for ( std::size_t i = 0; i < ret_size / 4; ++i )
			{
				// Read a group of three bytes (avoid buffer overrun by replacing with 0)
				const std::size_t							 index = i * 3;
				const MySupport_Library::Types::my_byte_type b3_0 = ( index + 0 < buffer_length ) ? bytes_encode_to_base64string[ index + 0 ] : 0;
				const MySupport_Library::Types::my_byte_type b3_1 = ( index + 1 < buffer_length ) ? bytes_encode_to_base64string[ index + 1 ] : 0;
				const MySupport_Library::Types::my_byte_type b3_2 = ( index + 2 < buffer_length ) ? bytes_encode_to_base64string[ index + 2 ] : 0;

				// Transform into four base 64 characters
				const MySupport_Library::Types::my_byte_type b4_0 = ( ( b3_0 & 0xfc ) >> 2 );
				const MySupport_Library::Types::my_byte_type b4_1 = ( ( b3_0 & 0x03 ) << 4 ) + ( ( b3_1 & 0xf0 ) >> 4 );
				const MySupport_Library::Types::my_byte_type b4_2 = ( ( b3_1 & 0x0f ) << 2 ) + ( ( b3_2 & 0xc0 ) >> 6 );
				const MySupport_Library::Types::my_byte_type b4_3 = ( ( b3_2 & 0x3f ) << 0 );

				// Add the base 64 characters to the return value
				result.push_back( to_base64[ b4_0 ] );
				result.push_back( to_base64[ b4_1 ] );
				result.push_back( to_base64[ b4_2 ] );
				result.push_back( to_base64[ b4_3 ] );
			}

			// Replace data that is invalid (always as many as there are missing bytes)
			for ( std::size_t i = 0; i != missing; ++i )
				result[ ret_size - i - 1 ] = '=';
		}

		template <class _Type_>
		void base64_decode_any( _Type_& result, std::string const& in )
		{
			using T = typename _Type_::value_type;

			// Make sure the *intended* string length is a multiple of 4
			std::size_t encoded_size = in.size();

			while ( ( encoded_size % 4 ) != 0 )
				++encoded_size;

			const std::size_t SIZE = in.size();
			result.clear();
			result.reserve( 3 * encoded_size / 4 );

			for ( std::size_t index = 0; index < encoded_size; index += 4 )
			{
				// Note: 'z' == 122

				// Get values for each group of four base 64 characters
				const MySupport_Library::Types::my_byte_type b4_0 = ( in[ index + 0 ] <= 'z' ) ? from_base64[ static_cast<MySupport_Library::Types::my_byte_type>( in[ index + 0 ] ) ] : 0xff;
				const MySupport_Library::Types::my_byte_type b4_1 = ( index + 1 < SIZE and in[ index + 1 ] <= 'z' ) ? from_base64[ static_cast<MySupport_Library::Types::my_byte_type>( in[ index + 1 ] ) ] : 0xff;
				const MySupport_Library::Types::my_byte_type b4_2 = ( index + 2 < SIZE and in[ index + 2 ] <= 'z' ) ? from_base64[ static_cast<MySupport_Library::Types::my_byte_type>( in[ index + 2 ] ) ] : 0xff;
				const MySupport_Library::Types::my_byte_type b4_3 = ( index + 3 < SIZE and in[ index + 3 ] <= 'z' ) ? from_base64[ static_cast<MySupport_Library::Types::my_byte_type>( in[ index + 3 ] ) ] : 0xff;

				// Transform into a group of three bytes
				const MySupport_Library::Types::my_byte_type b3_0 = ( ( b4_0 & 0x3f ) << 2 ) + ( ( b4_1 & 0x30 ) >> 4 );
				const MySupport_Library::Types::my_byte_type b3_1 = ( ( b4_1 & 0x0f ) << 4 ) + ( ( b4_2 & 0x3c ) >> 2 );
				const MySupport_Library::Types::my_byte_type b3_2 = ( ( b4_2 & 0x03 ) << 6 ) + ( ( b4_3 & 0x3f ) >> 0 );

				// Add the byte to the return value if it isn't part of an '=' character (indicated by 0xff)
				if ( b4_1 != 0xff )
					result.push_back( static_cast<T>( b3_0 ) );
				if ( b4_2 != 0xff )
					result.push_back( static_cast<T>( b3_1 ) );
				if ( b4_3 != 0xff )
					result.push_back( static_cast<T>( b3_2 ) );
			}
		}

		inline void base64_decode( std::vector<MySupport_Library::Types::my_byte_type>& result, std::string const& base64string_decode_to_bytes )
		{
			base64_decode_any( result, base64string_decode_to_bytes );
		}

		inline void base64_decode( std::string& result, std::string const& base64string_decode_to_bytes )
		{
			base64_decode_any( result, base64string_decode_to_bytes );
		}

		#endif

	}  // namespace Author4


	namespace Author5
	{
		//数据Base64编码和数据Base64解码
		//Data Base64 encoding and data Base64 decoding
		struct Base64
		{
		public:
			static std::string				  encode( const std::vector<unsigned char>& bytes_encode_to_base64string );
			static std::string				  encode( const unsigned char* bytes_encode_to_base64string, unsigned int buffer_length );
			static std::vector<unsigned char> decode( std::string base64string_decode_to_bytes );
		};

		inline std::string Base64::encode( const std::vector<unsigned char>& bytes_encode_to_base64string )
		{
			if ( bytes_encode_to_base64string.empty() )
				return "";	// Avoid dereferencing bytes_encode_to_base64string if it's empty
			return encode( &bytes_encode_to_base64string[ 0 ], ( unsigned int )bytes_encode_to_base64string.size() );
		}

		inline std::string Base64::encode( const unsigned char* bytes_encode_to_base64string, unsigned int buffer_length )
		{
			// Calculate how many bytes that needs to be added to get a multiple of 3
			std::size_t missing = 0;
			std::size_t StringSize = buffer_length;
			while ( ( StringSize % 3 ) != 0 )
			{
				++StringSize;
				++missing;
			}

			// Expand the return string size to a multiple of 4
			StringSize = 4 * StringSize / 3;

			std::string result;
			result.reserve( StringSize );

			for ( unsigned int i = 0; i < StringSize / 4; ++i )
			{
				// Read a group of three bytes (avoid buffer overrun by replacing with 0)
				std::size_t	  index = i * 3;
				unsigned char b3[ 3 ];
				b3[ 0 ] = ( index + 0 < buffer_length ) ? bytes_encode_to_base64string[ index + 0 ] : 0;
				b3[ 1 ] = ( index + 1 < buffer_length ) ? bytes_encode_to_base64string[ index + 1 ] : 0;
				b3[ 2 ] = ( index + 2 < buffer_length ) ? bytes_encode_to_base64string[ index + 2 ] : 0;

				// Transform into four base 64 characters
				unsigned char b4[ 4 ];
				b4[ 0 ] = ( ( b3[ 0 ] & 0xfc ) >> 2 );
				b4[ 1 ] = ( ( b3[ 0 ] & 0x03 ) << 4 ) + ( ( b3[ 1 ] & 0xf0 ) >> 4 );
				b4[ 2 ] = ( ( b3[ 1 ] & 0x0f ) << 2 ) + ( ( b3[ 2 ] & 0xc0 ) >> 6 );
				b4[ 3 ] = ( ( b3[ 2 ] & 0x3f ) << 0 );

				// Add the base 64 characters to the return value
				result.push_back( to_base64[ b4[ 0 ] ] );
				result.push_back( to_base64[ b4[ 1 ] ] );
				result.push_back( to_base64[ b4[ 2 ] ] );
				result.push_back( to_base64[ b4[ 3 ] ] );
			}

			// Replace data that is invalid (always as many as there are missing bytes)
			for ( std::size_t i = 0; i < missing; ++i )
				result[ StringSize - i - 1 ] = '=';

			return result;
		}

		inline std::vector<unsigned char> Base64::decode( std::string base64string_decode_to_bytes )
		{
			// Make sure string length is a multiple of 4
			while ( ( base64string_decode_to_bytes.size() % 4 ) != 0 )
				base64string_decode_to_bytes.push_back( '=' );

			std::size_t				   encodedStringSize = base64string_decode_to_bytes.size();
			std::vector<unsigned char> decodedBytes;
			decodedBytes.reserve( 3 * encodedStringSize / 4 );

			for ( std::size_t i = 0; i < encodedStringSize; i += 4 )
			{
				// Get values for each group of four base 64 characters
				unsigned char b4[ 4 ];
				b4[ 0 ] = ( base64string_decode_to_bytes[ i + 0 ] <= 'z' ) ? from_base64[ base64string_decode_to_bytes[ i + 0 ] ] : 0xff;
				b4[ 1 ] = ( base64string_decode_to_bytes[ i + 1 ] <= 'z' ) ? from_base64[ base64string_decode_to_bytes[ i + 1 ] ] : 0xff;
				b4[ 2 ] = ( base64string_decode_to_bytes[ i + 2 ] <= 'z' ) ? from_base64[ base64string_decode_to_bytes[ i + 2 ] ] : 0xff;
				b4[ 3 ] = ( base64string_decode_to_bytes[ i + 3 ] <= 'z' ) ? from_base64[ base64string_decode_to_bytes[ i + 3 ] ] : 0xff;

				// Transform into a group of three bytes
				unsigned char b3[ 3 ];
				b3[ 0 ] = ( ( b4[ 0 ] & 0x3f ) << 2 ) + ( ( b4[ 1 ] & 0x30 ) >> 4 );
				b3[ 1 ] = ( ( b4[ 1 ] & 0x0f ) << 4 ) + ( ( b4[ 2 ] & 0x3c ) >> 2 );
				b3[ 2 ] = ( ( b4[ 2 ] & 0x03 ) << 6 ) + ( ( b4[ 3 ] & 0x3f ) >> 0 );

				// Add the byte to the return value if it isn't part of an '=' character (indicated by 0xff)
				if ( b4[ 1 ] != 0xff )
					decodedBytes.push_back( b3[ 0 ] );
				if ( b4[ 2 ] != 0xff )
					decodedBytes.push_back( b3[ 1 ] );
				if ( b4[ 3 ] != 0xff )
					decodedBytes.push_back( b3[ 2 ] );
			}

			return decodedBytes;
		}

	}  // namespace Author5



	namespace Author6
	{

		#if __cplusplus > 201703L || __cplusplus == 202002L

		static constexpr const std::array< char, 64 >& base64_encode_table = to_base64;

		static constexpr std::array< MySupport_Library::Types::my_byte_type, 128 > base64_decode_table
		{
			0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
			0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
			0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x3E, 0x64, 0x64, 0x64, 0x3F,
			0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
			0x64, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
			0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x64, 0x64, 0x64, 0x64, 0x64,
			0x64, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x64, 0x64, 0x64, 0x64, 0x64
		};

		//数据Base64编码和数据Base64解码
		//Data Base64 encoding and data Base64 decoding
		class Base64
		{

		public:

			std::string														   encode( const std::span<const MySupport_Library::Types::my_byte_type> input );
			std::optional<std::vector<MySupport_Library::Types::my_byte_type>> decode( const std::string_view encoded_string );

			Base64() {}

			~Base64() {}

		protected:

			std::array<char, 4> encoding_tripplet( MySupport_Library::Types::my_byte_type a, MySupport_Library::Types::my_byte_type b, MySupport_Library::Types::my_byte_type c )
			{
				const std::size_t concat_bit = ( a << 16 ) | ( b << 8 ) | c;

				const auto base64_char1 = base64_encode_table[ ( concat_bit >> 18 ) & 0b0011'1111 ];
				const auto base64_char2 = base64_encode_table[ ( concat_bit >> 12 ) & 0b0011'1111 ];
				const auto base64_char3 = base64_encode_table[ ( concat_bit >> 6 ) & 0b0011'1111 ];
				const auto base64_char4 = base64_encode_table[ concat_bit & 0b0011'1111 ];
				return { base64_char1, base64_char2, base64_char3, base64_char4 };
			}

			std::array<MySupport_Library::Types::my_byte_type, 3> decoding_quad( char a, char b, char c, char d )
			{
				const std::size_t concat_bytes = ( base64_decode_table[ a ] << 18 ) | ( base64_decode_table[ b ] << 12 ) | ( base64_decode_table[ c ] << 6 ) | base64_decode_table[ d ];

				const MySupport_Library::Types::my_byte_type byte1 = ( concat_bytes >> 16 ) & 0b1111'1111;
				const MySupport_Library::Types::my_byte_type byte2 = ( concat_bytes >> 8 ) & 0b1111'1111;
				const MySupport_Library::Types::my_byte_type byte3 = concat_bytes & 0b1111'1111;

				return { byte1, byte2, byte3 };
			}

			bool is_valid_base64_string( const std::string_view encoded_string )
			{
				if ( ( encoded_string.size() % 4 ) != 0 )
				{
					return false;
				}

				auto begin = encoded_string.begin();
				auto end = encoded_string.end();

				if ( !std::all_of( begin, end - 2, [ &, this ]( char _data ) -> bool { return is_valid_base64_char( _data ); } ) )
				{
					return false;
				}

				const auto last = encoded_string.rbegin();
				if ( !is_valid_base64_char( *std::next( last ) ) )
				{
					//return (*next(last) == '=') && (*last == '=');
					return ( *std::next( last ) == char( 0x3d ) ) && ( *last == char( 0x3d ) );
				}

				return is_valid_base64_char( *last ) || ( *last == char( 0x3d ) );
			}

		private:

			bool is_valid_base64_char( char _data )
			{
				//if(_data >= 'A') && (_data <= 'Z')
				if ( ( _data >= 0x41 ) && ( _data <= 0x5a ) )
				{
					return true;
				}

				//if(_data >= 'a') && ('z')
				if ( ( _data >= 0x61 ) && ( 0x7a ) )
				{
					return true;
				}

				//if(_data >= '0') && (_data <= '9')
				if ( ( _data >= 0x30 ) && ( _data <= 0x39 ) )
				{
					return true;
				}

				//if(_data == '+') || (_data == '/')
				if ( ( _data == 0x2b ) || ( _data == 0x2f ) )
				{
					return true;
				}

				return false;
			}
		};

		inline std::string Base64::encode( const std::span<const MySupport_Library::Types::my_byte_type> input )
		{
			const auto size = input.size();
			const auto full_tripple_counts = size / 3;

			std::string output;
			output.reserve( ( full_tripple_counts + 2 ) * 4 );

			for ( std::size_t index = 0; index < full_tripple_counts; ++index )
			{
				const auto tripplet = input.subspan( index * 3, 3 );
				const auto base64_characters = encoding_tripplet( tripplet[ 0 ], tripplet[ 1 ], tripplet[ 2 ] );
				std::copy( std::begin( base64_characters ), std::end( base64_characters ), std::back_inserter( output ) );
			}

			const auto remaining_character_counts = size - full_tripple_counts * 3;
			if ( remaining_character_counts == 2 )
			{
				const auto last_two = input.last( 2 );
				const auto base64_characters = encoding_tripplet( last_two[ 0 ], last_two[ 1 ], 0x00 );

				output.push_back( base64_characters[ 0 ] );
				output.push_back( base64_characters[ 1 ] );
				output.push_back( base64_characters[ 2 ] );
				output.push_back( char( 0x3d ) );
			}
			else if ( remaining_character_counts == 1 )
			{
				auto const base64_characters = encoding_tripplet( input.back(), 0x00, 0x00 );

				output.push_back( base64_characters[ 0 ] );
				output.push_back( base64_characters[ 1 ] );
				output.push_back( char( 0x3d ) );
				output.push_back( char( 0x3d ) );
			}

			return output;
		}

		inline std::optional<std::vector<MySupport_Library::Types::my_byte_type>> Base64::decode( const std::string_view encoded_string )
		{
			const auto size = encoded_string.size();

			if ( size == 0 )
			{
				return std::vector<MySupport_Library::Types::my_byte_type> {};
			}

			if ( ( ( size % 4 ) != 0 ) || !is_valid_base64_string( encoded_string ) )
			{
				return std::nullopt;
			}

			const auto full_quadruple_counts = size / 4 - 1;

			std::vector<MySupport_Library::Types::my_byte_type> decoded_bytes;
			decoded_bytes.reserve( ( ( full_quadruple_counts + 2 ) * 3 ) / 4 );

			for ( size_t index = 0; index < full_quadruple_counts; ++index )
			{
				const auto quad_string = encoded_string.substr( index * 4, 4 );
				const auto quad_bytes = decoding_quad( quad_string[ 0 ], quad_string[ 1 ], quad_string[ 2 ], quad_string[ 3 ] );
				std::copy( std::begin( quad_bytes ), std::end( quad_bytes ), std::back_inserter( decoded_bytes ) );
			}

			auto const last_quad = encoded_string.substr( full_quadruple_counts * 4, 4 );
			if ( last_quad[ 2 ] == char( 0x3d ) )
			{
				auto const bytes = decoding_quad( last_quad[ 0 ], last_quad[ 1 ], char( 0x41 ), char( 0x41 ) );
				decoded_bytes.push_back( bytes[ 0 ] );
			}
			else if ( last_quad[ 3 ] == char( 0x3d ) )
			{
				auto const quad_bytes = decoding_quad( last_quad[ 0 ], last_quad[ 1 ], last_quad[ 2 ], char( 0x41 ) );
				std::copy_n( std::begin( quad_bytes ), 2, std::back_inserter( decoded_bytes ) );
			}
			else
			{
				auto const quad_bytes = decoding_quad( last_quad[ 0 ], last_quad[ 1 ], last_quad[ 2 ], last_quad[ 3 ] );
				std::copy_n( std::begin( quad_bytes ), 3, std::back_inserter( decoded_bytes ) );
			}

			return decoded_bytes;
		}

		#endif

	}  // namespace Author6

}  // namespace UtilTools::DataFormating::Base64Coder