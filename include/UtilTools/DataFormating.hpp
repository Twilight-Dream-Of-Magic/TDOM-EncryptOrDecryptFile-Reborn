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
#include "DataStreamConverter.hpp"

namespace UtilTools::DataFormating
{
	enum class AlphabetFormat
	{
		LOWER_CASE,
		UPPER_CASE,
		FORCE_MODE_LOWER_CASE,
		FORCE_MODE_UPPER_CASE
	};

	bool IsBinaryString( const std::string& input, std::size_t string_size );

	bool IsHexadecimalString( const std::string& input, std::size_t string_size, AlphabetFormat alphabet_format );

	namespace Decimal_Binary
	{
		template <typename IntegerType>
		requires std::is_integral_v<IntegerType> std::string ToBinaryStringBuilder( const IntegerType& input );

		template <typename IntegerType>
		requires std::is_integral_v<IntegerType> IntegerType FromBinaryStringBuilder( const std::string& input );

		std::string		  FromLongIntegerToBinaryString( const signed long int input, bool isNegativeNumber );
		std::string		  FromUnsignedLongIntegerToBinaryString( const unsigned long int input );
		signed long int	  BinaryStringToLongInteger( const std::string& input, bool isNegative );
		unsigned long int BinaryStringToUnsignedLongInteger( const std::string& input );

		std::string			   FromLongLongIntegerToBinaryString( const long long int input, bool isNegativeNumber );
		std::string			   FromUnsignedLongLongIntegerToBinaryString( const unsigned long long int input );
		signed long long int   BinaryStringToLongLongInteger( const std::string& input, bool isNegative );
		unsigned long long int BinaryStringToUnsignedLongLongInteger( const std::string& input );

		template <typename IntegerType>
		requires std::is_integral_v<IntegerType>
		std::string ToBinaryStringBuilder( const IntegerType& input )
		{
			IntegerType data = input;
			std::string output = "";

			// The sizeof() operator returns the size of a byte of this type by the type of an integer.
			// One byte has eight bits of data.
			// sizeof()运算符按一个整数的类型，返回这个类型的字节大小。
			// 一个字节有八个比特的数据。
			IntegerType bits_size = sizeof( IntegerType ) * 8;

			IntegerType _minimum_ = std::numeric_limits<IntegerType>::min();
			IntegerType _maximum_ = std::numeric_limits<IntegerType>::max();

			// Size of an integer is assumed to be sizeof(IntegerType) * 8 bits
			for ( IntegerType bit_loop_count = bits_size - 1; bit_loop_count >= _minimum_; bit_loop_count-- )
			{
				IntegerType mask_digits = data >> bit_loop_count;

				if constexpr ( std::is_signed_v<IntegerType> )
				{
					if ( bit_loop_count == -1 )
					{
						break;
					}
				}
				else if constexpr ( std::is_unsigned_v<IntegerType> )
				{
					if ( bit_loop_count == _maximum_ )
					{
						break;
					}
				}

				//当前这个数是奇数还是偶数
				//Is the current number odd or is it even?
				if ( ( mask_digits & 1 ) != 0 )
				{
					output.push_back( '1' );
				}
				else
				{
					output.push_back( '0' );
				}
			}

			return output;
		}

		template <typename IntegerType>
		requires std::is_integral_v<IntegerType>
		IntegerType FromBinaryStringBuilder( const std::string& input )
		{
			IntegerType string_bits_size = input.size();

			if ( string_bits_size <= 0 )
			{
				return 0;
			}
			else
			{
				std::string string_data = std::string( input );

				IntegerType output = 0;

				// Initializing base value to 1, i.e 2^0 == 1
				// 将次方基值初始化为1，即2^0 (2的0次方) 等于 1
				IntegerType InBaseNumber = 1;

				if ( !IsBinaryString( string_data, string_bits_size ) )
				{
					std::cout << "The input string data is illegal, it is not in a standard binary byte format, stop immediately!" << std::endl;
					return 0;
				}

				IntegerType lastStringRemainder = string_bits_size % 4;
				if ( lastStringRemainder != 0 )
				{
					IntegerType missingDigits = 4 - lastStringRemainder;
					string_bits_size += missingDigits;
					while ( missingDigits != 0 )
					{
						string_data.insert( 0, "0" );
						--missingDigits;
					}
				}

				auto rbegin = string_data.rbegin();
				auto rend = string_data.rend();

				while ( rbegin != rend )
				{
					if ( *rbegin == '1' )
					{
						output += InBaseNumber;
					}
					InBaseNumber *= 2;
					rbegin++;
				}

				return output;
			}
		}

		inline std::string FromLongIntegerToBinaryString( const signed long int input, bool isNegativeNumber )
		{
			const auto			   bit_count = sizeof( input ) * 8;
			std::string			   output = "";
			std::bitset<bit_count> binary_object;

			if ( isNegativeNumber && input < 0 )
			{
				//BinarySignReversal
				auto positiveNumber = static_cast<unsigned long int>( ~input + 1 );
				binary_object = std::bitset<bit_count>( positiveNumber );
				binary_object.flip();
				binary_object.set( bit_count - 1, true );
				output = binary_object.to_string();
				return output;
			}
			binary_object = std::bitset<bit_count>( input );

			output = binary_object.to_string();
			return output;
		}

		inline std::string FromUnsignedLongIntegerToBinaryString( const unsigned long int input )
		{
			const auto			   bit_count = sizeof( input ) * 8;
			std::string			   output = "";
			std::bitset<bit_count> binary_object = std::bitset<bit_count>( input );
			output = binary_object.to_string();
			return output;
		}

		inline signed long int BinaryStringToLongInteger( const std::string& input, bool isNegative )
		{
			std::size_t string_length = input.length();
			if ( string_length <= 0 )
			{
				return 0;
			}
			else
			{
				std::string			   string_data = std::string( input );
				const auto			   bit_count = sizeof( input ) * 8;
				signed long int		   output = 0;
				std::bitset<bit_count> binary_object;
				binary_object = std::bitset<bit_count>( string_data );

				if ( isNegative )
				{
					//BinarySignReversal
					for ( std::size_t index = 0; index < string_length; ++index )
					{
						if ( input.at( index ) == '0' )
						{
							string_data[ index ] = '1';
						}
						else if ( input.at( index ) == '1' )
						{
							string_data[ index ] = '0';
						}
					}
					string_data[ string_length - 1 ] = '1';

					binary_object = std::bitset<bit_count>( string_data );
					auto positiveNumber = binary_object.to_ulong();

					//BinarySignReversal
					output = static_cast<signed long int>( ~positiveNumber + 1 );
					return output;
				}
				else
				{
					binary_object = std::bitset<bit_count>( string_data );
					auto positiveNumber = binary_object.to_ulong();

					output = static_cast<signed long int>( positiveNumber );
					return output;
				};
			}
		}

		inline unsigned long int BinaryStringToUnsignedLongInteger( const std::string& input )
		{
			std::size_t string_length = input.length();
			if ( string_length <= 0 )
			{
				return 0;
			}
			else
			{
				std::string			   string_data = std::string( input );
				const auto			   bit_count = sizeof( input ) * 8;
				unsigned long int	   output = 0;
				std::bitset<bit_count> binary_object = std::bitset<bit_count>( string_data );
				output = binary_object.to_ulong();
				return output;
			}
		}

		inline std::string FromLongLongIntegerToBinaryString( const long long int input, bool isNegativeNumber )
		{
			const auto			   bit_count = sizeof( input ) * 8;
			std::string			   output = "";
			std::bitset<bit_count> binary_object;

			if ( isNegativeNumber && input < 0 )
			{
				//BinarySignReversal
				auto positiveNumber = static_cast<unsigned long long int>( ~input + 1 );
				binary_object = std::bitset<bit_count>( positiveNumber );
				binary_object.flip();
				binary_object.set( bit_count - 1, true );
				output = binary_object.to_string();
				return output;
			}
			binary_object = std::bitset<bit_count>( input );

			output = binary_object.to_string();
			return output;
		}

		inline std::string FromUnsignedLongLongIntegerToBinaryString( const unsigned long long int input )
		{
			const auto			   bit_count = sizeof( input ) * 8;
			std::string			   output = "";
			std::bitset<bit_count> binary_object = std::bitset<bit_count>( input );
			output = binary_object.to_string();
			return output;
		}

		inline signed long long int BinaryStringToLongLongInteger( const std::string& input, bool isNegative )
		{
			std::size_t string_length = input.length();
			if ( string_length <= 0 )
			{
				return 0;
			}
			else
			{
				std::string			   string_data = std::string( input );
				const auto			   bit_count = sizeof( input ) * 8;
				signed long long int   output = 0;
				std::bitset<bit_count> binary_object;
				binary_object = std::bitset<bit_count>( string_data );

				if ( isNegative )
				{
					//BinarySignReversal
					for ( std::size_t index = 0; index < string_length; ++index )
					{
						if ( input.at( index ) == '0' )
						{
							string_data[ index ] = '1';
						}
						else if ( input.at( index ) == '1' )
						{
							string_data[ index ] = '0';
						}
					}
					string_data[ string_length - 1 ] = '1';

					binary_object = std::bitset<bit_count>( string_data );
					auto positiveNumber = binary_object.to_ullong();

					//BinarySignReversal
					output = static_cast<signed long long int>( ~positiveNumber + 1 );
					return output;
				}
				else
				{
					binary_object = std::bitset<bit_count>( string_data );
					auto positiveNumber = binary_object.to_ullong();

					output = static_cast<signed long long int>( positiveNumber );
					return output;
				};
			}
		}

		inline unsigned long long int BinaryStringToUnsignedLongLongInteger( const std::string& input )
		{
			std::size_t string_length = input.length();
			if ( string_length <= 0 )
			{
				return 0;
			}
			else
			{
				std::string			   string_data = std::string( input );
				const auto			   bit_count = sizeof( input ) * 8;
				unsigned long long int output = 0;
				std::bitset<bit_count> binary_object = std::bitset<bit_count>( string_data );
				output = binary_object.to_ullong();
				return output;
			}
		}
	}  // namespace Decimal_Binary

	namespace Hexadecimal_Binary
	{
		//Hexadecimal To Binary String
		static const std::unordered_map<char, std::string> Hashmap_Number_H2BS
		{
			std::make_pair<char, std::string>( '0', "0000" ), 
			std::make_pair<char, std::string>( '1', "0001" ),
			std::make_pair<char, std::string>( '2', "0010" ),
			std::make_pair<char, std::string>( '3', "0011" ),
			std::make_pair<char, std::string>( '4', "0100" ),
			std::make_pair<char, std::string>( '5', "0101" ),
			std::make_pair<char, std::string>( '6', "0110" ),
			std::make_pair<char, std::string>( '7', "0111" ),
			std::make_pair<char, std::string>( '8', "1000" ),
			std::make_pair<char, std::string>( '9', "1001" )
		};

		//Hexadecimal To Binary String
		static const std::unordered_map<char, std::string> Hashmap_LowerCase_H2BS
		{
			std::make_pair<char, std::string>( 'a', "1010" ),
			std::make_pair<char, std::string>( 'b', "1011" ),
			std::make_pair<char, std::string>( 'c', "1100" ),
			std::make_pair<char, std::string>( 'd', "1101" ),
			std::make_pair<char, std::string>( 'e', "1110" ),
			std::make_pair<char, std::string>( 'f', "1111" )
		};

		//Hexadecimal To Binary String
		static const std::unordered_map<char, std::string> Hashmap_UpperCase_H2BS
		{
			std::make_pair<char, std::string>( 'A', "1010" ),
			std::make_pair<char, std::string>( 'B', "1011" ),
			std::make_pair<char, std::string>( 'C', "1100" ),
			std::make_pair<char, std::string>( 'D', "1101" ),
			std::make_pair<char, std::string>( 'E', "1110" ),
			std::make_pair<char, std::string>( 'F', "1111" )
		};

		//Hexadecimal From Binary String
		static const std::unordered_map<std::string, char> Hashmap_Number_BS2H
		{
			std::make_pair<std::string, char>( "0000", '0' ),
			std::make_pair<std::string, char>( "0001", '1' ),
			std::make_pair<std::string, char>( "0010", '2' ),
			std::make_pair<std::string, char>( "0011", '3' ),
			std::make_pair<std::string, char>( "0100", '4' ),
			std::make_pair<std::string, char>( "0101", '5' ),
			std::make_pair<std::string, char>( "0110", '6' ),
			std::make_pair<std::string, char>( "0111", '7' ),
			std::make_pair<std::string, char>( "1000", '8' ),
			std::make_pair<std::string, char>( "1001", '9' )
		};

		//Hexadecimal From Binary String
		static const std::unordered_map<std::string, char> Hashmap_LowerCase_BS2H
		{
			std::make_pair<std::string, char>( "1010", 'a' ),
			std::make_pair<std::string, char>( "1011", 'b' ),
			std::make_pair<std::string, char>( "1100", 'c' ),
			std::make_pair<std::string, char>( "1101", 'd' ),
			std::make_pair<std::string, char>( "1110", 'e' ),
			std::make_pair<std::string, char>( "1111", 'f' )
		};

		//Hexadecimal From Binary String
		static const std::unordered_map<std::string, char> Hashmap_UpperCase_BS2H
		{
			std::make_pair<std::string, char>( "1010", 'A' ),
			std::make_pair<std::string, char>( "1011", 'B' ),
			std::make_pair<std::string, char>( "1100", 'C' ),
			std::make_pair<std::string, char>( "1101", 'D' ),
			std::make_pair<std::string, char>( "1110", 'E' ),
			std::make_pair<std::string, char>( "1111", 'F' )
		};

		static const std::map<int, std::unordered_map<char, std::string>> Map_H2BS{ { 0, Hashmap_Number_H2BS }, { 1, Hashmap_LowerCase_H2BS }, { 2, Hashmap_UpperCase_H2BS } };

		static const std::map<int, std::unordered_map<std::string, char>> Map_BS2H{ { 0, Hashmap_Number_BS2H }, { 1, Hashmap_LowerCase_BS2H }, { 2, Hashmap_UpperCase_BS2H } };


		std::string FromHexadecimal( const std::string& input, DataFormating::AlphabetFormat alphabet_format );
		std::string ToHexadecimal( const std::string& input, DataFormating::AlphabetFormat alphabet_format );

		inline std::string FromHexadecimal( const std::string& input, DataFormating::AlphabetFormat alphabet_format )
		{
			std::size_t string_size = input.size();

			if ( string_size <= 0 )
			{
				return input;
			}
			else
			{
				std::string string_data = std::string( input );
				std::string output = "";

				bool lower_mode = alphabet_format == AlphabetFormat::LOWER_CASE;
				bool upper_mode = alphabet_format == AlphabetFormat::UPPER_CASE;
				bool lower_force_mode = alphabet_format == AlphabetFormat::FORCE_MODE_LOWER_CASE;
				bool upper_force_mode = alphabet_format == AlphabetFormat::FORCE_MODE_UPPER_CASE;

				if ( !lower_force_mode && !upper_force_mode )
				{
					if ( !IsHexadecimalString( string_data, string_size, alphabet_format ) )
					{
						std::cout << "The input string data is illegal, it is not in a standard hexadecimal string format, stop immediately!" << std::endl;
						return "";
					}
				}
				else
				{
					std::cout << "[Warning] String data has been input, but the forced mode has been used, so it is not possible to check the validity of the data." << std::endl;
					std::cout << "Please note that your improper use may cause the data formatting to fail." << std::endl;

					for ( auto& character_data : string_data )
					{
						if ( UtilTools::IsAlphabetCharacter( character_data ) )
						{
							if ( UtilTools::IsLowerCase( character_data ) && upper_force_mode )
							{
								character_data = UtilTools::ToUpperCase( character_data );
							}
							else if ( UtilTools::IsUpperCase( character_data ) && lower_force_mode )
							{
								character_data = UtilTools::ToLowerCase( character_data );
							}
						}
					}
				}

				auto lookupTable1 = Map_H2BS.at( 0 );
				auto lookupTable2 = Map_H2BS.at( 1 );
				auto lookupTable3 = Map_H2BS.at( 2 );

				if ( lower_mode || lower_force_mode )
				{
					for ( auto& character_data : string_data )
					{
						auto isContaions = lookupTable1.contains( character_data );
						auto isContaions2 = lookupTable2.contains( character_data );

						if ( isContaions )
						{
							output.append( lookupTable1.at( character_data ) );
						}
						if ( isContaions2 )
						{
							output.append( lookupTable2.at( character_data ) );
						}
					}
				}
				else if ( upper_mode || upper_force_mode )
				{
					for ( auto& character_data : string_data )
					{
						auto isContaions = lookupTable1.contains( character_data );
						auto isContaions2 = lookupTable3.contains( character_data );

						if ( isContaions )
						{
							output.append( lookupTable1.at( character_data ) );
						}
						if ( isContaions2 )
						{
							output.append( lookupTable3.at( character_data ) );
						}
					}
				}

				return output;
			}
		}

		inline std::string ToHexadecimal( const std::string& input, DataFormating::AlphabetFormat alphabet_format )
		{
			using namespace UtilTools;

			std::size_t string_size = input.size();

			if ( string_size <= 0 )
			{
				return input;
			}
			else
			{
				std::string string_data = std::string( input );
				std::string output = "";

				if ( !IsBinaryString( string_data, string_size ) )
				{
					std::cout << "The input string data is illegal, it is not in a standard binary string format, stop immediately!" << std::endl;
					return input;
				}

				auto lookupTable1 = Map_BS2H.at( 0 );
				auto lookupTable2 = Map_BS2H.at( 1 );
				auto lookupTable3 = Map_BS2H.at( 2 );

				std::size_t lastStringRemainder = string_size % 4;
				if ( lastStringRemainder != 0 )
				{
					std::size_t missingDigits = 4 - lastStringRemainder;
					string_size += missingDigits;
					while ( missingDigits != 0 )
					{
						string_data.insert( 0, "0" );
						--missingDigits;
					}
				}

				if ( alphabet_format == AlphabetFormat::LOWER_CASE || alphabet_format == AlphabetFormat::FORCE_MODE_LOWER_CASE )
				{
					for ( std::size_t index = 0; !( index > string_size ); index += 4 )
					{
						std::string sub_binary_string = string_data.substr( index, 4 );
						auto		isContaions = lookupTable1.contains( sub_binary_string );
						auto		isContaions2 = lookupTable2.contains( sub_binary_string );

						if ( isContaions )
						{
							output.push_back( lookupTable1.at( sub_binary_string ) );
						}
						if ( isContaions2 )
						{
							output.push_back( lookupTable2.at( sub_binary_string ) );
						}
					}

					for ( auto& character_data : output )
					{
						if ( UtilTools::IsUpperCase( character_data ) )
						{
							character_data = UtilTools::ToLowerCase( character_data );
						}
					}
				}
				else if ( alphabet_format == AlphabetFormat::UPPER_CASE || alphabet_format == AlphabetFormat::FORCE_MODE_UPPER_CASE )
				{
					for ( std::size_t index = 0; !( index > string_size ); index += 4 )
					{
						std::string sub_binary_string = string_data.substr( index, 4 );
						bool		isContaions = lookupTable1.contains( sub_binary_string );
						bool		isContaions2 = lookupTable3.contains( sub_binary_string );

						if ( isContaions )
						{
							output.push_back( lookupTable1.at( sub_binary_string ) );
						}
						if ( isContaions2 )
						{
							output.push_back( lookupTable3.at( sub_binary_string ) );
						}
					}

					for ( auto& character_data : output )
					{
						if ( UtilTools::IsLowerCase( character_data ) )
						{
							character_data = UtilTools::ToUpperCase( character_data );
						}
					}
				}

				return output;
			}
		}

	}  // namespace Hexadecimal_Binary

	inline bool IsBinaryString( const std::string& input, std::size_t string_size )
	{
		std::size_t					  string_length = input.length();
		bool					  flag = false;
		const std::array<char, 2> bitArray{ '0', '1' };
		std::size_t					  findedValiedBitCounters = 0;

		if ( string_length != string_size || string_length <= 0 )
		{
			return false;
		}
		else
		{
			std::string string_data = std::string( input );

			if ( string_size % 8 != 0 )
			{
				std::cout << "[Warning] String data was input, not in standard binary byte format, try to continue checking for validity......" << std::endl;
			}

			auto begin = string_data.begin();
			auto end = string_data.end();

			while ( begin != end )
			{
				if ( begin == string_data.end() || end == string_data.begin() )
				{
					break;
				}

				if ( *begin == bitArray[ 0 ] || *begin == bitArray[ 1 ] )
				{
					++findedValiedBitCounters;
				}
				else if ( *end == bitArray[ 0 ] || *end == bitArray[ 1 ] )
				{
					++findedValiedBitCounters;
				}
				else
				{
					findedValiedBitCounters = 0;
					break;
				}

				if ( begin != string_data.end() )
				{
					begin++;
				}

				if ( end != string_data.begin() )
				{
					end--;
				}
			}

			if ( findedValiedBitCounters != 0 )
			{
				flag = true;
				return flag;
			}

			return flag;
		}
	}

	inline bool IsHexadecimalString( const std::string& input, std::size_t string_size, AlphabetFormat alphabet_format )
	{
		using namespace Hexadecimal_Binary;

		std::size_t string_length = input.length();
		bool   flag = false;
		std::size_t findedValiedCharacterCounters = 0;

		auto lookupTable1 = Map_H2BS.at( 0 );
		auto lookupTable2 = Map_H2BS.at( 1 );
		auto lookupTable3 = Map_H2BS.at( 2 );

		if ( string_length != string_size || string_length <= 0 )
		{
			return false;
		}
		else
		{
			std::string string_data = std::string( input );

			for ( const auto& charactar_data : string_data )
			{
				if ( alphabet_format == AlphabetFormat::LOWER_CASE )
				{
					auto IsContains = lookupTable1.contains( charactar_data );
					auto IsContains2 = lookupTable2.contains( charactar_data );

					if ( !IsContains && !IsContains2 )
					{
						findedValiedCharacterCounters = 0;
						break;
					}
					else
					{
						++findedValiedCharacterCounters;
						continue;
					}
				}
				else if ( alphabet_format == AlphabetFormat::UPPER_CASE )
				{
					auto IsContains = lookupTable1.contains( charactar_data );
					auto IsContains2 = lookupTable3.contains( charactar_data );

					if ( !IsContains && !IsContains2 )
					{
						findedValiedCharacterCounters = 0;
						break;
					}
					else
					{
						++findedValiedCharacterCounters;
						continue;
					}
				}
			}

			if ( findedValiedCharacterCounters != 0 )
			{
				flag = true;
				return flag;
			}
			return flag;
		}
	}

	namespace ASCII_Hexadecmial
	{
		inline void IntegerToBytes( int& number, unsigned char* bytes, const int sizeInteger )
		{
			for ( int index = 0; index < sizeInteger; index++ )
			{
				int offset_bit = index * 8;
				bytes[ index ] = ( number >> offset_bit ) & 0xFF;
			}
		}

		inline void BytesToInteger( int& number, const unsigned char* bytes, const int sizeBytes )
		{
			number = 0;

			for ( int index = 0; index < sizeBytes; index++ )
			{
				int offset_bit = index * 8;
				number |= ( bytes[ index ] & 0xFF ) << offset_bit;
			}
		}

		inline auto byteArray2HexadecimalString( std::span<unsigned char> byteArray ) -> std::string
		{
			constexpr char transArray[]{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

			std::string hexadecimalString;

			for ( auto begin = byteArray.begin(), end = byteArray.end(); begin != end; begin++ )
			{
				auto high4Bits = ( *begin ) >> 4;
				auto low4Bits = ( *begin ) & 0x0F;

				hexadecimalString += transArray[ high4Bits ];
				hexadecimalString += transArray[ low4Bits ];
			}

			return hexadecimalString;
		}

		inline auto hexadecimalString2ByteArray( const std::string& hexadecimalString ) -> std::vector<unsigned char>
		{
			auto lambda_character2Number = []( char character_data ) -> int {
				// 返回类型提升默认会到int，不放心可以写static_cast
				if ( character_data >= '0' && character_data <= '9' )
					return static_cast<int>( character_data - '0' );
				else
					return static_cast<int>( ( character_data - 'A' ) + 10 );
			};

			auto lambda_reversalTransArray = [ & ]( char high, char low ) -> unsigned char {
				auto high4Bits = lambda_character2Number( high );
				auto low4Bits = lambda_character2Number( low );
				// 注意括号一定要打，加法减法优先级高于左移右移
				return ( high4Bits << 4 ) + low4Bits;
			};

			std::vector<unsigned char> byteArray;
			byteArray.reserve( hexadecimalString.size() / 2 );
			for ( std::size_t index = 0; index < hexadecimalString.length(); index += 2 )
			{
				byteArray.push_back( lambda_reversalTransArray( hexadecimalString[ index ], hexadecimalString[ index + 1 ] ) );
			}
			return byteArray;
		}

		/* For base string and hexadecimal string the exchange converter */

		// Convert string of chars to its representative string of hexadecimal numbers
		inline void streamToHexadecimal( const std::string& string_data, std::string& hexadecimal_string, AlphabetFormat alphabet_format )	 // Version 1
		{
			hexadecimal_string.resize( string_data.size() * 2 );
			const std::size_t a = alphabet_format == AlphabetFormat::UPPER_CASE ? 'A' - 1 : 'a' - 1;
			char		 character_data = string_data.at( 0 ) & 0xFF;
			for ( std::size_t index = 0; index < hexadecimal_string.size(); character_data = string_data.at( index / 2 ) & 0xFF )
			{
				hexadecimal_string[ index++ ] = character_data > 0x9F ? ( character_data / 16 - 9 ) | a : character_data / 16 | '0';
				hexadecimal_string[ index++ ] = ( character_data & 0xF ) > 9 ? ( character_data % 16 - 9 ) | a : character_data % 16 | '0';
			}
		}

		// Convert string of hex numbers to its equivalent character-stream
		inline void streamFromHexadecimal( const std::string& hexadecimal_string, std::string& string_data )
		{
			string_data.resize( ( hexadecimal_string.size() + 1 ) / 2 );

			for ( std::size_t target_index = 0, source_index = 0; target_index < string_data.size(); target_index++, source_index++ )
			{
				string_data[ target_index ] = ( hexadecimal_string[ source_index ] & '@' ? hexadecimal_string[ source_index ] + 9 : hexadecimal_string[ source_index ] ) << 4, source_index++;
				string_data[ target_index ] |= ( hexadecimal_string[ source_index ] & '@' ? hexadecimal_string[ source_index ] + 9 : hexadecimal_string[ source_index ] ) & 0xF;
			}
		}

		inline std::string string_to_hex( const std::string& this_string )	 //Version 2
		{
			std::stringstream ss;

			ss << std::hex << std::setfill( '0' );
			for ( std::size_t index = 0; this_string.size() > index; ++index )
			{
				ss << std::setw( 2 ) << static_cast<unsigned int>( static_cast<unsigned char>( this_string[ index ] ) );
			}

			return ss.str();
		}

		inline std::string string_from_hex( const std::string& hexadecimal_string )
		{
			std::string string_data;

			if ( ( hexadecimal_string.size() % 2 ) != 0 )
			{
				throw std::runtime_error( "String is not valid length ..." );
			}

			std::size_t round = hexadecimal_string.size() / 2;

			for ( std::size_t index = 0; round > index; ++index )
			{
				MySupport_Library::Types::my_ui_type		ascii_code = 0;
				std::stringstream ss;
				ss << std::hex << hexadecimal_string.substr( index * 2, 2 );
				ss >> ascii_code;

				string_data.push_back( static_cast<unsigned char>( ascii_code ) );
			}

			return string_data;
		}

		/* For byte array and hexadecimal string the exchange converter */

#if 0

		inline std::string new_bytesToHexadecimalString( const unsigned char* bytes, const int bytesSize )
		{
			if ( bytes == nullptr )
			{
				return "";
			}

			const int   sizeBytes = bytesSize;
			std::string stringBuffers;

			for ( int index = 0; index < sizeBytes; index++ )
			{
				/*if ((bytes[j] & 0xff) < 16) {
					buffer_HexString.append("0");
				}*/
				int high = bytes[ index ] / 16, low = bytes[ index ] % 16;
				stringBuffers += ( high < 10 ) ? ( '0' + high ) : ( 'a' + high - 10 );
				stringBuffers += ( low < 10 ) ? ( '0' + low ) : ( 'a' + low - 10 );
			}
			return stringBuffers;
		}

		inline std::vector<unsigned char> new_hexadecimalStringToBytes( const std::string& hexadecimalString )
		{
			int			   byteSize = hexadecimalString.length() / 2;
			std::string	string_byteFormat;
			unsigned int   unsigned_number;
			std::vector<unsigned char> byteBuffers;

			for ( int index = 0; index < byteSize; index++ )
			{
				string_byteFormat = hexadecimalString.substr( index * 2, 2 );

#if __cplusplus >= 201103L

				std::size_t format_size = sscanf_s( string_byteFormat.c_str(), "%x", &unsigned_number );

#else

				std::size_t format_size = std::sscanf( string_byteFormat.c_str(), "%x", &unsigned_number );

#endif


				if(format_size > 0)
				{
					byteBuffers.at(index) = unsigned_number;
				}
			}
			return byteBuffers;
		}

#endif

		inline std::string HexStringFromBytes( const std::vector<unsigned char>& bytes, int bytesSize )
		{
			std::string hexadecimalString;

			unsigned char highByte, lowByte;

			std::vector<char> temporary;

			for ( short int index = 0; index < bytesSize; index++ )
			{
				highByte = bytes.at( index ) >> 4;
				lowByte = bytes.at( index ) & 0x0f;

				highByte += 0x30;

				if ( highByte > 0x39 )
				{
					temporary.at( index * 2 ) = highByte + 0x07;
				}
				else
				{
					temporary.at( index * 2 ) = highByte;
				}

				lowByte += 0x30;

				if ( lowByte > 0x39 )
				{
					temporary.at( index * 2 + 1 ) = lowByte + 0x07;
				}
				else
				{
					temporary.at( index * 2 + 1 ) = lowByte;
				}

				hexadecimalString.append( temporary.data() );

				temporary.clear();
				std::vector<char>().swap( temporary );
			}

			return hexadecimalString;
		}

		inline std::vector<unsigned char> BytesFromHexString( std::string& hexadecimalString, int hexadecimalStringSize )
		{
			std::vector<unsigned char> bytes;
			unsigned char			   highByte, lowByte;

			char* temporary = nullptr;
			temporary = hexadecimalString.data();

			for ( short int index = 0; index < hexadecimalStringSize; index += 2 )
			{
				highByte = toupper( temporary[ index ] );
				lowByte = toupper( temporary[ index + 1 ] );

				if ( highByte > 0x39 )
				{
					highByte -= 0x37;
				}
				else
				{
					highByte -= 0x30;
				}
				if ( lowByte > 0x39 )
				{
					lowByte -= 0x37;
				}
				else
				{
					lowByte -= 0x30;
				}

				bytes.at( index / 2 ) = ( highByte << 4 ) | lowByte;
			}

			temporary = nullptr;
			return bytes;
		}

		inline static std::string bytesToHexString( const std::vector<unsigned char>& inputData )
		{
			std::string output_myHexString;
			std::size_t		byteSize = inputData.size();

			for ( std::size_t count = 0; count < byteSize; ++count )
			{
				int c = inputData.at( count );
				int a = c / 16;
				int b = c % 16;

				auto& reference_a = a;
				auto& reference_b = b;
				output_myHexString.append( 1, reinterpret_cast<unsigned char&>( reference_a ) );
				output_myHexString.append( 1, reinterpret_cast<unsigned char&>( reference_b ) );
				if ( count != byteSize - 1 )
				{
					output_myHexString.append( 1, '\0' );
				}
			}

			if ( output_myHexString.size() > 0 )
			{
				return output_myHexString;
			}
			else
			{
				throw std::runtime_error( "May be bytes to hexadecimal-string convertion has been failed ?" );
			}
		}

		inline static std::vector<unsigned char> hexStringToBytes( const std::string& input_myHexString )
		{
			std::vector<unsigned char> outputData;
			std::size_t					   hexStringSize = input_myHexString.size() + 1;
			outputData.resize( hexStringSize );

			for ( std::size_t count = 0; count < hexStringSize; count++ )
			{
				outputData[ count ] = 0x00;
			}

			std::vector<std::string> myStringVector;
			std::string::size_type	 currPos = 0, prevPos = 0;

			while ( ( currPos = input_myHexString.find( ' ', prevPos ) ) != std::string::npos )
			{
				std::string binaryString( input_myHexString.substr( prevPos, currPos - prevPos ) );
				myStringVector.push_back( binaryString );
				prevPos = currPos + 1;
			}

			while ( prevPos < input_myHexString.size() )
			{
				std::string binaryString( input_myHexString.substr( prevPos, 1 ) );
				myStringVector.push_back( binaryString );
				++prevPos;
			}

			std::vector<std::string>::size_type byteSize = myStringVector.size();
			for ( std::vector<std::string>::size_type count = 0; count < byteSize; ++count )
			{
				int	 a = static_cast<unsigned int>( std::ref( myStringVector[ count ][ 0 ] ) );
				int	 b = static_cast<unsigned int>( std::ref( myStringVector[ count ][ 1 ] ) );
				char character_data = static_cast<char>( a * 16 + b );
				outputData[ count ] = reinterpret_cast<unsigned char&>( character_data );
			}

			myStringVector.clear();
			std::vector<std::string>().swap( myStringVector );

			if ( outputData.size() > 0 || byteSize > 0 )
			{
				return outputData;
			}
			else
			{
				throw std::runtime_error( "May be hexadecimal-string to bytes convertion has been failed ?" );
			}
		}
	}  // namespace ASCII_Hexadecmial

	namespace Decimal_Hexadecimal
	{
		template <typename IntegerType>
		requires std::is_integral_v<IntegerType> std::string FromDecimalBuilder( const IntegerType& input, DataFormating::AlphabetFormat alphabet_format );

		template <typename IntegerType>
		requires std::is_integral_v<IntegerType> IntegerType ToDecimalBuilder( const std::string& input, DataFormating::AlphabetFormat alphabet_format, bool isNegative );

		template <typename IntegerType>
		requires std::is_integral_v<IntegerType>
		std::string FromDecimalBuilder( const IntegerType& input, DataFormating::AlphabetFormat alphabet_format )
		{
			IntegerType integer = input;

			std::size_t		index = 0;
			std::string buffer;
			std::string output;

			if ( integer < 0 )
			{
				std::string binary_string = Decimal_Binary::ToBinaryStringBuilder<IntegerType>( integer );
				output.assign( Hexadecimal_Binary::ToHexadecimal( binary_string, alphabet_format ) );

				return output;
			}

			char	   temporary = 0;
			const char _0_ = 0x30;
			const char _7_ = 0x37;
			const char _W_ = 0x57;

			if ( integer == 0 )
			{
				output = std::string( "0" );
				return output;
			}

			while ( integer != 0 )
			{
				temporary = static_cast<char>( integer % 16 );
				if ( temporary < 10 )
				{
					//0x30 <=> 48 <=> '0'
					char character_data = _0_ + temporary;
					buffer = ( character_data + buffer );
					++index;
				}
				else
				{
					//0x41 <=> 65 <=> 'A'
					//'A' - 10 == '7'
					//0x37 <=> 55 <=> '7'
					char character_data = 0;

					if ( alphabet_format == AlphabetFormat::UPPER_CASE || alphabet_format == AlphabetFormat::FORCE_MODE_UPPER_CASE )
					{
						character_data = temporary + _7_;
					}
					else if ( alphabet_format == AlphabetFormat::LOWER_CASE || alphabet_format == AlphabetFormat::FORCE_MODE_LOWER_CASE )
					{
						character_data = temporary + _W_;
					}

					buffer = ( character_data + buffer );
					++index;
				}
				integer /= 16;
			}

			output = std::string( buffer );

			buffer.clear();
			return output;
		}

		template <typename IntegerType>
		requires std::is_integral_v<IntegerType>
		IntegerType ToDecimalBuilder( const std::string& input, DataFormating::AlphabetFormat alphabet_format, bool isNegative )
		{
			std::size_t		string_length = input.length();
			std::string string_data = std::string( input );

			// Initializing base value to 1, i.e 16^0 == 1
			// 将次方基值初始化为1，即16^0 (16的0次方) 等于 1
			IntegerType InBaseNumber = 1;
			IntegerType output = 0;

			if ( isNegative == true )
			{
				std::string binary_string = Hexadecimal_Binary::FromHexadecimal( string_data, alphabet_format );
				output = Decimal_Binary::FromBinaryStringBuilder<IntegerType>( binary_string );

				return output;
			}

			const IntegerType _0_ = static_cast<IntegerType>( 0x30 );
			const IntegerType _9_ = static_cast<IntegerType>( 0x39 );

			const IntegerType _A_ = static_cast<IntegerType>( 0x41 );
			const IntegerType _F_ = static_cast<IntegerType>( 0x46 );
			const IntegerType _7_ = static_cast<IntegerType>( 0x37 );

			const IntegerType _a_ = static_cast<IntegerType>( 0x61 );
			const IntegerType _f_ = static_cast<IntegerType>( 0x66 );
			const IntegerType _W_ = static_cast<IntegerType>( 0x57 );


			if ( string_length <= 0 )
			{
				return 0;
			}
			else
			{
				bool lower_mode = alphabet_format == AlphabetFormat::LOWER_CASE;
				bool upper_mode = alphabet_format == AlphabetFormat::UPPER_CASE;
				bool lower_force_mode = alphabet_format == AlphabetFormat::FORCE_MODE_LOWER_CASE;
				bool upper_force_mode = alphabet_format == AlphabetFormat::FORCE_MODE_UPPER_CASE;

				if ( !lower_force_mode && !upper_force_mode )
				{
					if ( !IsHexadecimalString( string_data, string_length, alphabet_format ) )
					{
						std::cout << "The input string data is illegal, it is not in a standard hexadecimal string format, stop immediately!" << std::endl;
						return 0;
					}
				}
				else
				{
					std::cout << "[Warning] String data has been input, but the forced mode has been used, so it is not possible to check the validity of the data." << std::endl;
					std::cout << "Please note that your improper use may cause the data formatting to fail." << std::endl;

					for ( auto& character_data : string_data )
					{
						if ( UtilTools::IsAlphabetCharacter( character_data ) )
						{
							if ( UtilTools::IsLowerCase( character_data ) && upper_force_mode )
							{
								character_data = UtilTools::ToUpperCase( character_data );
							}
							else if ( UtilTools::IsUpperCase( character_data ) && lower_force_mode )
							{
								character_data = UtilTools::ToLowerCase( character_data );
							}
						}
					}
				}

				auto rbegin = string_data.rbegin();
				auto rend = string_data.rend();

				while ( rbegin != rend )
				{
					IntegerType ascii_code = static_cast<IntegerType>( *rbegin );

					//0x30 <=> 48 <=> '0'
					//0x39 <=> 57 <=> '9'
					if ( ( ascii_code >= _0_ ) && ( ascii_code <= _9_ ) )
					{
						output += ( ascii_code - _0_ ) * InBaseNumber;
						InBaseNumber *= 16;
					}

					if ( upper_mode || upper_force_mode )
					{
						//0x41 <=> 65 <=> 'A'
						//'A' - 10 == '7'
						//0x46 <=> 70 <=> 'F'
						if ( ( ascii_code >= _A_ ) && ( ascii_code <= _F_ ) )
						{
							//0x37 <=> 55 <=> '7'
							output += ( ascii_code - _7_ ) * InBaseNumber;
							InBaseNumber *= 16;
						}
					}

					if ( lower_mode || lower_force_mode )
					{
						//0x61 <=> 97 <=> 'a'
						//'a' - 10 == 'W'
						//0x66 <=> 102 <=> 'f'
						if ( ( ascii_code >= _a_ ) && ( ascii_code <= _f_ ) )
						{
							//0x57 <=> 87 <=> 'W'
							output += ( ascii_code - _W_ ) * InBaseNumber;
							InBaseNumber *= 16;
						}
					}

					rbegin++;
				}

				return output;
			}
		}
	}  // namespace Decimal_Hexadecimal
}  // namespace UtilTools::DataFormating