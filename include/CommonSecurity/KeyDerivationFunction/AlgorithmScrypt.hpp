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

namespace CommonSecurity::KDF::PBKDF2
{
	struct Algorithm
	{
		std::vector<std::uint8_t> WithSHA2_512
		(
			std::span<std::uint8_t> secret_passsword_or_key_byte,
			std::span<std::uint8_t> salt_data,
			const std::size_t round_count,
			std::uint64_t result_byte_size
		)
		{
			my_cpp2020_assert
			(
				result_byte_size > 0,
				"When using PBKDF2<PRF>, the byte size of the key that needs to be generated is not zero.",
				std::source_location::current()
			);
			
			using CommonSecurity::DataHashingWrapper::HMAC_FunctionObject;
			using UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString;
			using UtilTools::DataFormating::ASCII_Hexadecmial::hexadecimalString2ByteArray;

			/* PRF is HMAC-SHA2-512 */
			CommonSecurity::DataHashingWrapper::HashersAssistantParameters HashersAssistantParameters_Instance;
			HashersAssistantParameters_Instance.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512;
			HashersAssistantParameters_Instance.generate_hash_bit_size = 512;
			HashersAssistantParameters_Instance.whether_use_hash_extension_bit_mode = false;

			my_cpp2020_assert
			(
				result_byte_size <= (std::numeric_limits<std::uint64_t>::max() / (512 / sizeof(std::uint8_t))),
				"When using PBKDF2<PRF>, pseudo random function is HMAC-SHA2-512, the byte size of the key that needs to be generated is over the limit.",
				std::source_location::current()
			);

			const std::string secret_passsword_or_key_string = byteArray2HexadecimalString(secret_passsword_or_key_byte);
			const std::string salt_string_data = byteArray2HexadecimalString(salt_data);
				
			std::vector<std::uint8_t> result_byte;

			std::string U_Characters;
			std::string T_Characters;

			std::vector<std::uint8_t> _T_Array_;
			std::vector<std::uint8_t> _U_Array_;

			std::uint64_t integer = 0;
			while (result_byte_size > 0)
			{
				++integer;
				std::string block_number_string;

				block_number_string.push_back( static_cast<char>( (integer >> 56) & 0xff ) );
				block_number_string.push_back( static_cast<char>( (integer >> 48) & 0xff ) );
				block_number_string.push_back( static_cast<char>( (integer >> 40) & 0xff ) );
				block_number_string.push_back( static_cast<char>( (integer >> 32) & 0xff ) );
				block_number_string.push_back( static_cast<char>( (integer >> 24) & 0xff ) );
				block_number_string.push_back( static_cast<char>( (integer >> 16) & 0xff ) );
				block_number_string.push_back( static_cast<char>( (integer >> 8) & 0xff ) );
				block_number_string.push_back( static_cast<char>( (integer) & 0xff ) );

				/* Compute U[0] = PRF(Password, Salt || INTEGER(index)). */
				U_Characters = HMAC_FunctionObject(HashersAssistantParameters_Instance, secret_passsword_or_key_string, 64, salt_string_data + block_number_string);
					
				/* T[index] = U[0] ... */
				T_Characters = U_Characters;

				for(std::size_t round = 1; round < round_count; ++round)
				{
					/* Compute U[index] = PRF(Password, U[index - 1]) , index ∈ [1, round_count] */
					U_Characters = HMAC_FunctionObject(HashersAssistantParameters_Instance, secret_passsword_or_key_string, 64, U_Characters);

					_T_Array_ = hexadecimalString2ByteArray(T_Characters);
					_U_Array_ = hexadecimalString2ByteArray(U_Characters);

					/* Exclusive-or operation U[index], U[index + 1] ... */
					std::ranges::transform
					(
						_T_Array_.begin(),
						_T_Array_.end(),
						_U_Array_.begin(),
						_U_Array_.end(),
						_T_Array_.begin(),
						[](std::uint8_t left, std::uint8_t right)
						{
							return left ^ right;
						}
					);
				}

				if(_T_Array_.empty())
					_T_Array_ = hexadecimalString2ByteArray(T_Characters);

				/* Copy as many bytes as necessary into buffer. */
				result_byte.insert(result_byte.end(), _T_Array_.begin(), _T_Array_.begin() + std::min(result_byte_size, _T_Array_.size()));
				result_byte_size -= _T_Array_.size();

				block_number_string.clear();
			}

			integer = 0;

			std::ranges::fill(U_Characters.begin(), U_Characters.end(), '\x00');
			std::ranges::fill(T_Characters.begin(), T_Characters.end(), '\x00');

			U_Characters.clear();
			T_Characters.clear();

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>(_T_Array_.data(), _T_Array_.size());
			CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>(_U_Array_.data(), _U_Array_.size());
			CheckPointer = nullptr;

			return result_byte;
		}
	};
}

namespace CommonSecurity::KDF::Scrypt
{
	class Algorithm
	{

	private:

		static constexpr std::size_t DefaultResourceCost = 1;
		static constexpr std::size_t DefaultBlockSize = 8;
		static constexpr std::size_t DefaultParallelizationCount = 1;

		void Salsa20_WordSpecification( const std::array<std::uint32_t, 16>& in, std::array<std::uint32_t, 16>& out )
		{
			std::array<std::uint32_t, 16> words;

			// Words = Input
			std::ranges::copy(in.begin(), in.end(), words.begin());

			// Words[index]..... = Words
			auto&
			[
				word00, word01, word02, word03,
				word04, word05, word06, word07,
				word08, word09, word10, word11,
				word12, word13, word14, word15
			] = words;

			// While round = 8, rounds > 0, round = round - 2
			// Words[index] = Salsa20Round(Words[index]) ......
			std::int32_t round = 8;
			while (round > 0)
			{
				//Odd round
				word04 ^= std::rotl( word00 + word12, 7 );
				word08 ^= std::rotl( word04 + word00, 9 );
				word12 ^= std::rotl( word08 + word04, 13 );
				word00 ^= std::rotl( word12 + word08, 18 );
				word09 ^= std::rotl( word05 + word01, 7 );
				word13 ^= std::rotl( word09 + word05, 9 );
				word01 ^= std::rotl( word13 + word09, 13 );
				word05 ^= std::rotl( word01 + word13, 18 );
				word14 ^= std::rotl( word10 + word06, 7 );
				word02 ^= std::rotl( word14 + word10, 9 );
				word06 ^= std::rotl( word02 + word14, 13 );
				word10 ^= std::rotl( word06 + word02, 18 );
				word03 ^= std::rotl( word15 + word11, 7 );
				word07 ^= std::rotl( word03 + word15, 9 );
				word11 ^= std::rotl( word07 + word03, 13 );
				word15 ^= std::rotl( word11 + word07, 18 );

				//Even round
				word01 ^= std::rotl( word00 + word03, 7 );
				word02 ^= std::rotl( word01 + word00, 9 );
				word03 ^= std::rotl( word02 + word01, 13 );
				word00 ^= std::rotl( word03 + word02, 18 );
				word06 ^= std::rotl( word05 + word04, 7 );
				word07 ^= std::rotl( word06 + word05, 9 );
				word04 ^= std::rotl( word07 + word06, 13 );
				word05 ^= std::rotl( word04 + word07, 18 );
				word11 ^= std::rotl( word10 + word09, 7 );
				word08 ^= std::rotl( word11 + word10, 9 );
				word09 ^= std::rotl( word08 + word11, 13 );
				word10 ^= std::rotl( word09 + word08, 18 );
				word12 ^= std::rotl( word15 + word14, 7 );
				word13 ^= std::rotl( word12 + word15, 9 );
				word14 ^= std::rotl( word13 + word12, 13 );
				word15 ^= std::rotl( word14 + word13, 18 );

				round -= 2;
			}

			round = 0;

			// Output[index] = Input[index] + Words[index] ......
			std::ranges::transform
			(
				in.begin(),
				in.end(),
				words.begin(),
				words.end(),
				out.begin(),
				[](const std::uint32_t a, const std::uint32_t b)
				{
					return a + b;
				}
			);

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>(words.data(), words.size() * sizeof(std::uint32_t));
			CheckPointer = nullptr;
		}

		std::array<std::uint32_t, 16> ExclusiveOrBlock(std::span<const std::uint32_t> left, std::span<const std::uint32_t> right)
		{
			std::array<std::uint32_t, 16> exclusive_or_word_result;

			std::ranges::transform
			(
				left.begin(),
				left.end(),
				right.begin(),
				right.end(),
				exclusive_or_word_result.begin(),
				[](const std::uint32_t a, const std::uint32_t b)
				{
					return a ^ b;
				}
			);

			return exclusive_or_word_result;
		}

		void MixBlock(std::array<std::uint32_t, 16>& word32_buffer, std::span<const std::uint32_t> in, std::span<std::uint32_t> out, const std::uint64_t block_size)
		{
			std::array<std::uint32_t, 16> word32_buffer_t {};

			/* 1: X = Block[2 * block_size - 1] */
			std::memcpy(word32_buffer.data(), &in[ (2 * block_size - 1) * 16 ], 16 * sizeof(std::uint32_t));
			
			/* 2: for index = 0 to 2 * block_size - 1 do */
			for(std::size_t index = 0; index < 2 * block_size; index += 2)
			{
				/* 3: T = X xor Block[index] */
				word32_buffer_t = this->ExclusiveOrBlock(word32_buffer, {in.begin() + (index * 16), in.end()});

				/* 4: X = Salsa20(T) */
				//Exclusive-or And Salsa20
				this->Salsa20_WordSpecification
				(
					word32_buffer_t,
					word32_buffer
				);

				/* 5: Y[index] = X */
				/* 6: Block' = (Y[0], Y[2], ..., Y[2 * block_size - 2], Y[1], Y[3], ..., Y[2 * block_size - 1]) */
				std::memcpy(&out[index * 8], word32_buffer.data(), word32_buffer.size() * sizeof(std::uint32_t));

				word32_buffer_t = this->ExclusiveOrBlock(word32_buffer, {in.begin() + (index * 16 + 16), in.end()});
				
				this->Salsa20_WordSpecification
				(
					word32_buffer_t,
					word32_buffer
				);

				std::memcpy(&out[index * 8 + block_size * 16], word32_buffer.data(), word32_buffer.size() * sizeof(std::uint32_t));
			}

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>(word32_buffer_t.data(), word32_buffer_t.size() * sizeof(std::uint32_t));
			CheckPointer = nullptr;
		}

		std::uint64_t Integerify(std::span<std::uint32_t> block, const std::uint64_t block_size)
		{
			const std::uint64_t index = (2 * block_size - 1) * 16;
			return static_cast<std::uint64_t>(block[index]) | static_cast<std::uint64_t>( block[index + 1] ) << 32;
		}

		void ScryptMixFuncton
		(
			std::span<std::uint8_t> block,
			const std::uint64_t& block_size,
			const std::uint64_t resource_cost,
			std::span<std::uint32_t> block_v,
			std::span<std::uint32_t> block_xy
		)
		{
			std::array<std::uint32_t, 16> word32_buffer {};
			const std::size_t word32_block_size = 32 * block_size;
			std::span<std::uint32_t> block_x {block_xy.begin(), block_xy.end()};
			std::span<std::uint32_t> block_y {block_xy.begin() + word32_block_size, block_xy.end()};

			std::uint64_t offset_index = 0;

			/* 1: X = Block */
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>({block.begin(), block.begin() + word32_block_size * sizeof(std::uint32_t)}, block_x.data());

			/* 2: for index = 0 to resource_cost - 1 do */
			for(std::size_t index = 0; index < resource_cost; index += 2)
			{
				/* 3: V[index] = X */
				std::memcpy(&block_v[index * word32_block_size], block_x.data(), word32_block_size * sizeof(std::uint32_t));
				
				/* 4: Y = MixSalsa20(X) */
				this->MixBlock(word32_buffer, block_x, block_y, block_size);

				/* 5: V[index] = Y */
				std::memcpy(&block_v[(index + 1) * word32_block_size], block_y.data(), word32_block_size * sizeof(std::uint32_t));
				
				/* 4: X = MixSalsa20(Y) */
				this->MixBlock(word32_buffer, block_y, block_x, block_size);
			}

			/* 5: for index = 0 to resource_cost - 1 do */
			for(std::size_t index = 0; index < resource_cost; index += 2)
			{
				/* 6: offset_index = Integerify(X) mod resource_cost */
				offset_index = static_cast<int>( this->Integerify(block_x, block_size) & (resource_cost - 1) );

				/* 7: X = X ExclusiveOr V[offset_index] */
				std::span<std::uint32_t> _block_v_{block_v.begin() + offset_index * word32_block_size, block_v.end()};
				std::ranges::transform
				(
					_block_v_.begin(),
					_block_v_.begin() + word32_block_size,
					block_x.begin(),
					block_x.begin() + word32_block_size,
					block_x.begin(),
					[](const std::uint32_t a, const std::uint32_t b)
					{
						return a ^ b;
					}
				);
				
				/* 8: Y = MixSalsa20(X) */
				this->MixBlock(word32_buffer, block_x, block_y, block_size);

				/* 9: offset_index = Integerify(Y) mod resource_cost */
				offset_index = static_cast<int>( this->Integerify(block_y, block_size) & (resource_cost - 1) );

				/* 10: Y = Y ExclusiveOr V[offset_index] */
				_block_v_ = {block_v.begin() + offset_index * word32_block_size, block_v.end()};
				std::ranges::transform
				(
					_block_v_.begin(),
					_block_v_.begin() + word32_block_size,
					block_y.begin(),
					block_y.begin() + word32_block_size,
					block_y.begin(),
					[](const std::uint32_t a, const std::uint32_t b)
					{
						return a ^ b;
					}
				);
				
				/* 11: X = MixSalsa20(Y) */
				this->MixBlock(word32_buffer, block_y, block_x, block_size);
			}

			offset_index = 0;

			/* 12: Block = X */
			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>({block_x.begin(), block_x.begin() + word32_block_size}, block.data() + offset_index);

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>(word32_buffer.data(), word32_buffer.size() * sizeof(std::uint32_t));
			CheckPointer = nullptr;
		}

		std::vector<std::uint8_t> DoGenerateKeys
		(
			std::span<std::uint8_t> secret_passsword_or_key_byte,
			std::span<std::uint8_t> salt_data,
			std::uint64_t& result_byte_size,
			std::uint64_t& resource_cost,
			std::uint64_t& block_size,
			std::uint64_t& parallelization_count
		)
		{
			CommonSecurity::KDF::PBKDF2::Algorithm pbkdf2;

			// 1: (Block[0] ... Block{ParallelizationCount-1}) = PBKDF2(Password, Salt, 1, ParallelizationCount * MixFunctionLength)
			std::vector<std::uint8_t> block = pbkdf2.WithSHA2_512(secret_passsword_or_key_byte, salt_data, 1, parallelization_count * 128 * block_size);
			
			std::vector<std::uint32_t> block_xy(64 * block_size, 0);
			std::vector<std::uint32_t> block_v(32 * resource_cost * block_size, 0);

			// 2: for index = 0 to ParallelizationCount - 1 do
			for(std::size_t index = 0; index < parallelization_count; index++)
			{
				// 3: Block[index] = MixFunction(Block[index], N)
				std::span<std::uint8_t> slice_block {block.begin() + index * 128 * block_size, block.end()};
				this->ScryptMixFuncton(slice_block, block_size, resource_cost, block_v, block_xy);
			}

			// 4: DeriveKey = PBKDF2(Password, Block, 1, DeriveKeyLength)
			std::vector<std::uint8_t> generated_secure_keys = pbkdf2.WithSHA2_512(secret_passsword_or_key_byte, block, 1, result_byte_size);

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>(block.data(), block.size());
			CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>(block_xy.data(), block_xy.size() * sizeof(std::uint32_t));
			CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>(block_v.data(), block_v.size() * sizeof(std::uint32_t));
			CheckPointer = nullptr;

			return generated_secure_keys;
		}

	public:

		std::vector<std::uint8_t> GenerateKeys
		(
			std::span<std::uint8_t> secret_passsword_or_key_byte,
			std::span<std::uint8_t> salt_data,
			std::uint64_t result_byte_size,
			std::uint64_t resource_cost = DefaultResourceCost,
			std::uint64_t block_size = DefaultBlockSize,
			std::uint64_t parallelization_count = DefaultParallelizationCount
		)
		{
			my_cpp2020_assert
			(
				(resource_cost != 0 && (resource_cost & (resource_cost - 1)) == 0) == true, 
				"When using Scrypt, the memory and cpu resource cost must be a power of 2!", 
				std::source_location::current()
			);
			
			my_cpp2020_assert
			(
				parallelization_count > 0,
				"When using Scrypt, providing parallelized counts is cannot be zero!",
				std::source_location::current()
			);
			
			my_cpp2020_assert
			(
				parallelization_count <= static_cast<std::uint64_t>(std::numeric_limits<int>::max()),
				"When using Scrypt, providing parallelized counts is over the limit!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				(block_size * parallelization_count) < (1ULL << 30ULL),
				"When using Scrypt, the block_size to be generated is multiplied by the parallelized buffer size, which is over the limit!",
				std::source_location::current()
			);
			
		
			my_cpp2020_assert
			(
				result_byte_size > 0,
				"When using Scrypt, the byte size of the key that needs to be generated is not zero!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				result_byte_size <= std::numeric_limits<std::uint64_t>::max(),
				"When using Scrypt, the byte size of the key that needs to be generated is over the limit!",
				std::source_location::current()
			);

			return this->DoGenerateKeys(secret_passsword_or_key_byte, salt_data, result_byte_size, resource_cost, block_size, parallelization_count);
		}
	};
}
