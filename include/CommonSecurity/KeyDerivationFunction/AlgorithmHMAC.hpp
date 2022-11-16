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

namespace CommonSecurity::KDF::HMAC
{
	/*
		HKDF is a simple key derivation function (KDF) based on HMAC message authentication code.
		It was initially proposed by its authors as a building block in various protocols and applications, as well as to discourage the proliferation of multiple KDF mechanisms.
		The main approach HKDF follows is the "extract-then-expand" paradigm, where the KDF logically consists of two modules: the first stage takes the input keying material and "extracts" from it a fixed-length pseudorandom key, and then the second stage "expands" this key into several additional pseudorandom keys (the output of the KDF).
		It can be used, for example, to convert shared secrets exchanged via Diffie–Hellman into key material suitable for use in encryption, integrity checking or authentication.
		It is formally described in the RFC 5869.
		One of its authors also described the algorithm in a companion paper in 2010.
		NIST SP800-56Cr2 specifies a parameterizable extract-then-expand scheme, noting that RFC5869 HKDF is a version of it and citing its paper for the rationale for the recommendations' extract-and-expand mechanisms.
	*/

	/*
		HKDF是一个基于HMAC消息认证码的简单密钥派生函数（KDF）。
		它最初是由其作者提出的，作为各种协议和应用的构建块，同时也是为了阻止多种KDF机制的扩散。
		HKDF遵循的主要方法是 "提取-然后扩展 "范式，KDF在逻辑上由两个模块组成：第一阶段接收输入的密钥材料并从中 "提取 "一个固定长度的伪随机密钥，然后第二阶段将这个密钥 "扩展 "成几个额外的伪随机密钥（KDF的输出）。
		例如，它可以用来将通过Diffie-Hellman交换的共享秘密转换成适合用于加密、完整性检查或认证的密钥材料。
		它在RFC 5869中得到了正式的描述。
		其作者之一还在2010年的一篇配套论文中描述了该算法。
		NIST SP800-56Cr2规定了一个可参数化的先提取后扩展方案，指出RFC5869 HKDF是它的一个版本，并引用其论文来说明建议提取和扩展机制的理由。
	*/

	//Reference Paper: https://datatracker.ietf.org/doc/rfc5869/
	struct Algorithm
	{

	private:
		static constexpr std::size_t HashMessageBlockSize = CURRENT_SYSTEM_BITS == 64 ? 512 / 8 : 256 / 8;

		/**
		* @param input_keying_material;
		* @param salt_data; optional salt value (a non-secret random value) if not provided, it is set to a string of HashMessageBlockSize zeros.
		* @return extracted_pseudorandom_key_data; a pseudorandom key (of HashMessageBlockSize octets).
		*/
		std::string ExtractKeyDataWithHMAC
		(
			CommonSecurity::DataHashingWrapper::HashersAssistantParameters& HashersAssistantParameters_Instance,
			const std::string& input_keying_material,
			std::string& salt_data
		)
		{
			my_cpp2020_assert( !input_keying_material.empty(), "The size of the input keying material key cannot be null", std::source_location::current() );

			if(salt_data.empty())
				std::string(HashMessageBlockSize, 0).swap(salt_data);

			std::string extracted_pseudorandom_key_data = CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HashersAssistantParameters_Instance, input_keying_material, HashMessageBlockSize, salt_data);
			return extracted_pseudorandom_key_data;
		}

		/**
		* @param extracted_pseudorandom_key_data; a pseudorandom key of at least HashMessageBlockSize octets (usually, the output from the extract step)
		* @param context_info; optional context and application specific information (can be a zero-length string)
		* @param requirement_hashed_key_size; length of output keying material in octets
		* @return output_keying_material; output keying material (of requirement_hashed_key_size octets)
		*/
		std::string ExpandKeyDataWithHMAC
		(
			CommonSecurity::DataHashingWrapper::HashersAssistantParameters& HashersAssistantParameters_Instance,
			const std::string& ExtractedPseudorandomKeyData,
			const std::string& context_info,
			const std::size_t& requirement_hashed_key_size
		)
		{
			my_cpp2020_assert( !ExtractedPseudorandomKeyData.empty() && ExtractedPseudorandomKeyData.size() % 8 == 0, "The size of the pseudo-random key cannot be null and must be a multiple of eight", std::source_location::current() );

			my_cpp2020_assert( requirement_hashed_key_size % 8 == 0 && requirement_hashed_key_size <= 255 * HashMessageBlockSize, "The size of the requirement keystream does not meet the standard! \n(requirement_keystream_size modulo 8 == 0 and requirement_keystream_size <= 255 * HashMessageBlockSize)", std::source_location::current() );

			std::size_t execute_loop_count = static_cast<std::size_t>( ::ceil( static_cast<double>( requirement_hashed_key_size / HashMessageBlockSize ) ) );

			std::string output_keying_material;

			if(context_info.empty())
			{
				std::string current_derived_keystream = CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HashersAssistantParameters_Instance, std::string(1,0), HashMessageBlockSize, ExtractedPseudorandomKeyData);
				for( std::size_t index = 1; index < execute_loop_count; ++index)
				{
					current_derived_keystream = CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HashersAssistantParameters_Instance, current_derived_keystream + static_cast<char>(index), HashMessageBlockSize, ExtractedPseudorandomKeyData);
					output_keying_material.append(current_derived_keystream);
				}
			}
			else
			{
				std::string current_derived_keystream = CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HashersAssistantParameters_Instance, context_info + std::string(1,0), HashMessageBlockSize, ExtractedPseudorandomKeyData);
				for( std::size_t index = 1; index < execute_loop_count; ++index)
				{
					current_derived_keystream = CommonSecurity::DataHashingWrapper::HMAC_FunctionObject(HashersAssistantParameters_Instance, current_derived_keystream + context_info + static_cast<char>(index), HashMessageBlockSize, ExtractedPseudorandomKeyData);
					output_keying_material.append(current_derived_keystream);
				}
			}

			return output_keying_material;
		}

	public:
		std::string MakeHashByteStreamWithKeyDerivation
		(
			CommonSecurity::DataHashingWrapper::HashersAssistantParameters& HashersAssistantParameters_Instance,
			const std::string& key_material,
			std::string& salt_data,
			const std::string& context_info,
			const std::size_t& requirement_hashed_key_size
		)
		{
			std::string pseudorandom_key = this->ExtractKeyDataWithHMAC( HashersAssistantParameters_Instance, key_material, salt_data );
			std::string processed_string_key_material = this->ExpandKeyDataWithHMAC( HashersAssistantParameters_Instance, pseudorandom_key, context_info, requirement_hashed_key_size );
			return processed_string_key_material;
		}
	
	};
}