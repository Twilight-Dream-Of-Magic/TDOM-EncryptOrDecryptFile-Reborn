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
	struct Coder
	{
		/*
			数据置换函数
		
			@param Orded string
			@return Disorded string
		*/
		std::string StringDataDisorder( const std::string& characters_data )
		{
			std::string encoded = std::string( characters_data );

			if(characters_data.size() < 2)
			{
				return encoded;
			}

			std::size_t accumulator = characters_data.size();

			for(const auto& character : characters_data)
			{
				if(accumulator + static_cast<std::uint8_t>(character) < std::numeric_limits<std::size_t>::max())
				{
					accumulator += static_cast<std::uint8_t>(character);
				}
				else
				{
					break;
				}
			}

			//正向置换加密
			//Forward permutation encryption
			std::size_t index = encoded.size() - 1;
			while(index > 0)
			{
				const std::size_t round_index = accumulator % (index + 1);
				std::swap(encoded[index], encoded[round_index]);
				--index;
			}

			accumulator = 0;

			#if defined(_DEBUG)
			std::cout << "The string encode result is: " << encoded << std::endl;
			#endif

			//Return ciphertext data
			return encoded;
		}

		/*
			数据逆置换函数
			
			@param Disorded string
			@return Ordered string
		*/
		std::string StringDataOrder( const std::string& characters_data )
		{
			std::string decoded = std::string( characters_data );

			if(characters_data.size() < 2)
			{
				return decoded;
			}

			std::size_t accumulator = characters_data.size();

			for(const auto& character : characters_data)
			{
				if(accumulator + static_cast<std::uint8_t>(character) < std::numeric_limits<std::size_t>::max())
				{
					accumulator += static_cast<std::uint8_t>(character);
				}
				else
				{
					break;
				}
			}

			//逆向置换解密
			//Reverse permutation decryption
			std::size_t index = 0;
			while(index < decoded.size())
			{
				const std::size_t round_index = accumulator % (index + 1);
				std::swap(decoded[index], decoded[round_index]);
				++index;
			}

			accumulator = 0;

			#if defined(_DEBUG)
			std::cout << "The string decode result is: " << decoded << std::endl;
			#endif

			//Return plaintext data
			return decoded;
		}

		#if __cplusplus >= 202002L

		template<typename DataElementType>
		requires std::integral<DataElementType>
		void DataDisorder( std::span<DataElementType> elements_data )
		{
			std::size_t accumulator = elements_data.size();

			for(const auto& element : elements_data)
			{
				if(accumulator + static_cast<std::size_t>(element) < std::numeric_limits<std::size_t>::max())
				{
					accumulator += static_cast<std::size_t>(element);
				}
				else
				{
					break;
				}
			}

			//正向置换加密
			//Forward permutation encryption
			std::size_t index = elements_data.size() - 1;
			while(index > 0)
			{
				const std::size_t round_index = accumulator % (index + 1);
				std::swap(elements_data[index], elements_data[round_index]);
				--index;
			}

			accumulator = 0;
		}

		template<typename DataElementType>
		requires std::integral<DataElementType>
		void DataOrder( std::span<DataElementType> elements_data )
		{
			std::size_t accumulator = elements_data.size();

			for(const auto& element : elements_data)
			{
				if(accumulator + static_cast<std::size_t>(element) < std::numeric_limits<std::size_t>::max())
				{
					accumulator += static_cast<std::size_t>(element);
				}
				else
				{
					break;
				}
			}

			//逆向置换解密
			//Reverse permutation decryption
			std::size_t index = 0;
			while(index < elements_data.size())
			{
				const std::size_t round_index = accumulator % (index + 1);
				std::swap(elements_data[index], elements_data[round_index]);
				++index;
			}

			accumulator = 0;
		}

		#endif
	};

	#if __cplusplus >= 202002L

	/*
		使用Fisher-Yates洗牌算法
		Using the Fisher-Yates shuffling algorithm.

		https://stackoverflow.com/questions/3541378/reversible-shuffle-algorithm-using-a-key
	*/
	template<typename DataElementType, typename KeyElementType>
	requires std::integral<DataElementType> && std::integral<KeyElementType>
	class CoderWithKey
	{
		
	private:
		std::deque<std::span<KeyElementType>> ForwardKeySpans;
		std::deque<std::span<KeyElementType>> BackwardKeySpans;

		std::size_t KeySpans_IndexWithShuffle = 0;
		std::size_t KeySpans_IndexWithDeShuffle = 0;

		template<typename RNG_Type>
		requires std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		std::vector<std::size_t> GenerationShuffleExchanges
		(
			RNG_Type& random_number_function_object,
			std::size_t random_indices_size,
			std::span<KeyElementType> key_block_data
		)
		{
			std::vector<std::size_t> random_indices(random_indices_size, 0x00);

			random_number_function_object = RNG_Type(key_block_data.begin(), key_block_data.end());

			for (std::int64_t index = random_indices_size - 1; index > 0; index--)
			{
				random_indices[random_indices_size - 1 - index] = random_number_function_object();
			}

			return random_indices;
		}

	public:

		void UpdateKey(std::span<KeyElementType> elements_key, std::size_t block_size)
		{
			if(block_size != 0 && elements_key.size() % block_size == 0)
			{
				for(std::int64_t index = 0; index + block_size <= elements_key.size(); index += block_size)
				{
					std::span<KeyElementType> elements_splitted_key = elements_key.subspan(index, block_size);
					this->ForwardKeySpans.push_back(elements_splitted_key);
				}

				for(std::int64_t index = ForwardKeySpans.size() - 1; index > -1; --index )
				{
					std::span<KeyElementType> elements_splitted_key = ForwardKeySpans[index];
					this->BackwardKeySpans.push_back(elements_splitted_key);
				}
			}
			else
			{
				this->ForwardKeySpans.push_back(elements_key);
				this->BackwardKeySpans.push_back(elements_key);
			}
		}

		template<typename RNG_Type>
		requires std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		void Shuffle
		(
			RNG_Type& random_number_function_object,
			std::span<DataElementType> elements_data,
			bool use_keyspans_index_loop
		)
		{
			if(this->ForwardKeySpans.empty())
				return;

			if(!use_keyspans_index_loop)
			{
				if(this->KeySpans_IndexWithShuffle >= this->ForwardKeySpans.size())
					return;
			}
			else
			{
				if(this->KeySpans_IndexWithShuffle >= this->ForwardKeySpans.size())
					this->KeySpans_IndexWithShuffle = 0;
			}
			
			std::vector<std::size_t> random_indices = this->GenerationShuffleExchanges(random_number_function_object, elements_data.size(), this->ForwardKeySpans[this->KeySpans_IndexWithShuffle]);

			DataElementType temporary_value { 0 };

			for(std::int64_t index = elements_data.size() - 1; index > 0; index--)
			{
				std::size_t random_index = random_indices[elements_data.size() - 1 - index];

				temporary_value = elements_data[index];
				elements_data[index] = elements_data[random_index % elements_data.size()];
				elements_data[random_index % elements_data.size()] = temporary_value;
			}

			std::ranges::fill(random_indices, static_cast<std::size_t>(0));
			temporary_value = static_cast<DataElementType>(random_indices[0]);
			random_indices.clear();
			random_indices.shrink_to_fit();

			++(this->KeySpans_IndexWithShuffle);
		}

		template<typename RNG_Type>
		requires std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		void DeShuffle
		(
			RNG_Type& random_number_function_object,
			std::span<DataElementType> elements_data,
			bool use_keyspans_index_loop
		)
		{
			if(this->BackwardKeySpans.empty())
				return;
			
			if(!use_keyspans_index_loop)
			{
				if(this->KeySpans_IndexWithDeShuffle >= this->BackwardKeySpans.size())
					return;
			}
			else
			{
				if(this->KeySpans_IndexWithDeShuffle >= this->BackwardKeySpans.size())
					this->KeySpans_IndexWithDeShuffle = 0;
			}
			
			std::vector<std::size_t> random_indices = this->GenerationShuffleExchanges(random_number_function_object, elements_data.size(), this->BackwardKeySpans[this->KeySpans_IndexWithDeShuffle]);
		
			DataElementType temporary_value { 0 };

			for(std::int64_t index = 1; index < elements_data.size(); index++)
			{
				std::size_t random_index = random_indices[elements_data.size() - 1 - index];

				temporary_value = elements_data[index];
				elements_data[index] = elements_data[random_index % elements_data.size()];
				elements_data[random_index % elements_data.size()] = temporary_value;
			}

			std::ranges::fill(random_indices, static_cast<std::size_t>(0));
			temporary_value = static_cast<DataElementType>(random_indices[0]);
			random_indices.clear();
			random_indices.shrink_to_fit();

			++(this->KeySpans_IndexWithDeShuffle);
		}

		explicit CoderWithKey(std::span<KeyElementType> elements_key, std::size_t block_size)
		{
			this->UpdateKey(elements_key, block_size);
		}

		~CoderWithKey()
		{
			this->ForwardKeySpans.clear();
			this->BackwardKeySpans.clear();
		}

		CoderWithKey() = delete;
	};

	#endif

}  // namespace Cryptograph::DataPermutation

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