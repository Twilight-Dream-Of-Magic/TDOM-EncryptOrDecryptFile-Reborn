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

#include "RefactoringCodeImplement.hpp"

/*

	Cryptography partial terminology
	密码学部分术语

		Byte Data Substitution Box
		字节数据代换盒
		The role of S-box is to confuse (Confusion), mainly to increase the complexity between plaintext and ciphertext (including non-linearity, etc.)
		S盒的作用是混淆(Confusion),主要增加明文和密文之间的复杂度（包括非线性度等）

		Byte Data Permutation Box
		字节数据置换盒
		The purpose of P-box is Diffusion, which is to allow the effect of the plaintext and key to spread rapidly throughout the ciphertext. (i.e. a change in the plaintext or key of 1 bit affects multiple bits of the ciphertext.)
		P盒的作用是扩散(Diffusion),目的是让明文和密钥的影响迅速扩散到整个密文中。(即1位的明文或密钥的改变会影响到密文的多个比特。)

*/

/*
	https://en.wikipedia.org/wiki/XXTEA
	Corrected Block TEA (often referred to as XXTEA) is a block cipher designed to correct weaknesses in the original Block TEA.
	XXTEA is vulnerable to a chosen-plaintext attack requiring 259 queries and negligible work.
	The cipher's designers were Roger Needham and David Wheeler of the Cambridge Computer Laboratory, and the algorithm was presented in an unpublished[clarification needed] technical report in October 1998 (Wheeler and Needham, 1998).
	It is not subject to any patents.
	Formally speaking, XXTEA is a consistent incomplete source-heavy heterogeneous UFN (unbalanced Feistel network) block cipher.
	XXTEA operates on variable-length blocks that are some arbitrary multiple of 32 bits in size (minimum 64 bits).
	The number of full cycles depends on the block size, but there are at least six (rising to 32 for small block sizes).
	The original Block TEA applies the XTEA round function to each word in the block and combines it additively with its leftmost neighbour.
	Slow diffusion rate of the decryption process was immediately exploited to break the cipher. 
	Corrected Block TEA uses a more involved round function which makes use of both immediate neighbours in processing each word in the block.
	XXTEA is likely to be more efficient than XTEA for longer messages.

	Corrected Block TEA（通常被称为XXTEA）是一种块密码，旨在纠正原始Block TEA的弱点。
	XXTEA容易受到选择明文的攻击，需要259次查询和可忽略不计的工作。
	该密码的设计者是剑桥计算机实验室的Roger Needham和David Wheeler，该算法于1998年10月在一份未发表的[澄清需要]技术报告中提出（Wheeler and Needham, 1998）。
	它不受任何专利限制。
	从形式上讲，XXTEA是一种一致的不完全源重异质UFN（不平衡的Feistel网络）区块密码。
	XXTEA在可变长度的块上运行，这些块的大小是32位的任意倍数（最小64位）。
	全周期的数量取决于区块大小，但至少有6个（小区块大小上升到32）。
	原始的块TEA将XTEA圆函数应用于块中的每个字，并将其与最左边的邻居加在一起。
	解密过程的缓慢扩散率立即被利用来破解密码。 
	修正后的区块TEA使用了一个更多的圆形函数，在处理区块中的每个字时利用了两个近邻。
	对于较长的信息，XXTEA可能比XTEA更有效。
*/
namespace CommonSecurity::CorrectedBlockTEA
{
	constexpr std::uint32_t DELTA_VALUE = static_cast<std::uint32_t>(0x9e3779b9);
	
	class DataWorker
	{
		
	private:
		
		std::uint32_t MixValue(std::uint32_t& a, std::uint32_t& b, std::uint32_t& sum, const std::array<std::uint32_t, 4>& keys, std::uint32_t& data_values_index, std::uint32_t& choice_sum)
		{
			auto left_value = ((b >> 5 ^ a << 2) + (a >> 3 ^ b << 4));
			auto right_value = ((sum ^ a) + (keys[(data_values_index & 3) ^ choice_sum] ^ b));
			auto mixed_value = left_value ^ right_value;
			return mixed_value;
		}

	public:

		void operator()(std::uint32_t* data_values, std::uint32_t data_values_size, bool mode, const std::array<std::uint32_t, 4>& keys)
		{
			std::uint32_t a = 0, b = 0, sum = 0;
			std::uint32_t data_values_index;
			std::uint32_t execute_rounds = 0, choice_sum = 0;
			
			if(mode == true)
			{
				//Encoding Part
				execute_rounds = 6 + 52 / data_values_size;
				b = data_values[data_values_size - 1];
				do
				{
					sum += DELTA_VALUE;
					choice_sum = (sum >> 2) & 3;
					for(data_values_index = 0; data_values_index < data_values_size - 1; ++data_values_index)
					{
						a = data_values[data_values_index + 1];
						b = data_values[data_values_index] += MixValue(a, b, sum, keys, data_values_index, choice_sum);
					}
					a = data_values[0];
					b = data_values[data_values_size - 1] += MixValue(a, b, sum, keys, data_values_index, choice_sum);
				} while (--execute_rounds);
			}
			else
			{
				//Decoding Part
				execute_rounds = 6 + 52 / data_values_size;
				sum = execute_rounds * DELTA_VALUE;
				a = data_values[0];
				do
				{
					choice_sum = (sum >> 2) & 3;
					for (data_values_index = data_values_size - 1; data_values_index > 0; --data_values_index)
					{
						b = data_values[data_values_index - 1];
						a = data_values[data_values_index] -= MixValue(a, b, sum, keys, data_values_index, choice_sum);
					}
					b = data_values[data_values_size - 1];
					a = data_values[0] -= MixValue(a, b, sum, keys, data_values_index, choice_sum);
					sum -= DELTA_VALUE;
				} while (--execute_rounds);
			}
		}
		
		DataWorker() = default;
		~DataWorker() = default;
		
	};

	inline DataWorker SuperTEA;
}

/*
	https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
	https://zh.wikipedia.org/wiki/%E9%AB%98%E7%BA%A7%E5%8A%A0%E5%AF%86%E6%A0%87%E5%87%86
	
	The Advanced Encryption Standard (AES), also known by its original name Rijndael (Dutch pronunciation: [ˈrɛindaːl]),[3]
	is a specification for the encryption of electronic data established by the U.S.
	National Institute of Standards and Technology (NIST) in 2001.[4]

	AES is a variant of the Rijndael block cipher[3] developed by two Belgian cryptographers, Joan Daemen and Vincent Rijmen, who submitted a proposal[5]
	to NIST during the AES selection process.[6] Rijndael is a family of ciphers with different key and block sizes.
	For AES, NIST selected three members of the Rijndael family, each with a block size of 128 bits, but three different key lengths: 128, 192 and 256 bits.

	AES has been adopted by the U.S. government. It supersedes the Data Encryption Standard (DES),[7]
	which was published in 1977. 
	The algorithm described by AES is a symmetric-key algorithm, meaning the same key is used for both encrypting and decrypting the data.

	In the United States, AES was announced by the NIST as U.S.FIPS PUB 197 (FIPS 197) on November 26, 2001.[4]
	This announcement followed a five-year standardization process in which fifteen competing designs were presented and evaluated, before the Rijndael cipher was selected as the most suitable (see Advanced Encryption Standard process for more details).

	AES is included in the ISO/IEC 18033-3 standard.
	AES became effective as a U.S. federal government standard on May 26, 2002, after approval by the U.S. Secretary of Commerce.
	AES is available in many different encryption packages, and is the first (and only) publicly accessible cipher approved by the U.S.
	National Security Agency (NSA) for top secret information when used in an NSA approved cryptographic module (see Security of AES, below).
	
	高级加密标准（英语：Advanced Encryption Standard，缩写：AES），又称Rijndael加密法（荷兰语发音： [ˈrɛindaːl]，音似英文的“Rhine doll”），是美国联邦政府采用的一种区块加密标准
	这个标准用来替代原先的DES，已经被多方分析且广为全世界所使用。
	经过五年的甄选流程，高级加密标准由美国国家标准与技术研究院（NIST）于2001年11月26日发布于FIPS PUB 197，并在2002年5月26日成为有效的标准
	现在，高级加密标准已然成为对称密钥加密中最流行的算法之一

	该算法为比利时密码学家Joan Daemen和Vincent Rijmen所设计，结合两位作者的名字，以Rijndael为名投稿高级加密标准的甄选流程
*/
namespace CommonSecurity::AES
{
	template<AES_SecurityLevel SecurityLevel>
	class DataWorker
	{
	
	#if 1

	private:
		
		OfficialAlgorithm<SecurityLevel> AlogritmObject;

		ChunkedDataPadders<ChunkedDataPaddingMode::PKCS7> ChunkedDataPadManager;

	public:

		constexpr std::uint8_t GetBlockSize_DataByte() const
		{
			return AlogritmObject.Number_Block_Data_Byte_Size;
		}

		constexpr std::size_t GetBlockSize_KeyByte() const
		{
			return AlogritmObject.Number_Key_Data_Block_Size * AlogritmObject.ONE_WORD_BYTE_SIZE;
		}

		constexpr std::size_t GetBlockSize_ExpandedKeyByte()
		{
			return AlogritmObject.ONE_WORD_BYTE_SIZE * AlogritmObject.NUMBER_DATA_BLOCK_COUNT * (AlogritmObject.Number_Execute_Round_Count + 1);
		}

		/*
			
			最简单的工作模式即为电子密码本（Electronic codebook，ECB）模式。
			需要加密的消息按照块密码的块大小被分为数个块，并对每个块进行独立加密。

			The simplest mode of operation is the electronic codebook (ECB) mode.
			The message to be encrypted is divided into several blocks according to the block size of the block cipher, and each block is encrypted independently.

			Execute Process (执行过程):
			CipherText[index] = EncryptionDataFunction(PlainText[index], Key[index])

			PlainText[index] = DecryptionDataFunction(CipherText[index], Key[index])

		*/

		/**
		* Encrypt input plain text with an AES key in ECB Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithECB(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t>& output)
		{
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(inputDataSubrange);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in ECB Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithECB(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t>& output)
		{
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty() || (input.size() % AlogritmObject.Number_Block_Data_Byte_Size != 0))
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.DecryptBlockData(inputDataSubrange);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);
			
			return true;
		}

		/*
			
			1976 年，IBM 发明了密码分组链接（CBC，Cipher-block chaining）模式。
			在 CBC 模式中，每个明文块先与前一个密文块进行异或后，再进行加密。
			在这种方法中，每个密文块都依赖于它前面的所有明文块。同时，为了保证每条消息的唯一性，在第一个块中需要使用初始化向量。

			CBC 是最为常用的工作模式。
			它的主要缺点在于加密过程是串行的，无法被并行化，而且消息必须被填充到块大小的整数倍。
			解决后一个问题的一种方法是利用密文窃取。

			注意在加密时，明文中的微小改变会导致其后的全部密文块发生改变，而在解密时，从两个邻接的密文块中即可得到一个明文块。
			因此，解密过程可以被并行化，而解密时，密文中一位的改变只会导致其对应的明文块完全改变和下一个明文块中对应位发生改变，不会影响到其它明文的内容。

			In 1976, IBM invented the Cipher Block Chaining (CBC) model.
			In the CBC mode, each plaintext block is first heterodyned with the previous ciphertext block and then encrypted.
			In this method, each ciphertext block depends on all the plaintext blocks that precede it. Also, to ensure the uniqueness of each message, an initialization vector needs to be used in the first block.

			CBC is the most commonly used mode of operation.
			Its main drawbacks are that the encryption process is serial and cannot be parallelized, and that messages must be padded to an integer multiple of the block size.
			One way to solve the latter problem is to use ciphertext steganography.

			Note that during encryption, a small change in the plaintext causes a change in all subsequent ciphertext blocks, while during decryption, a plaintext block is obtained from two neighboring ciphertext blocks.
			Therefore, the decryption process can be parallelized, and the change of one bit in the ciphertext only leads to the complete change of its corresponding plaintext block and the change of the corresponding bit in the next plaintext block during decryption, without affecting the content of the other plaintexts.

			Execute Process (执行过程):
			CipherText[index] = EncryptionDataFunction(PlainText[index] ^ InitialVector[index], Key[index])
			InitialVector[index] = CipherText[index]

			PlainText[index] = DecryptionDataFunction(CipherText[index], Key[index]) ^ InitialVector[index]
			InitialVector[index] = CipherText[index]

		*/

		/**
		* Encrypt input plain text with an AES key in CBC Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithCBC(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, inputDataSubrange, initialVectorBlock, AlogritmObject.Number_Block_Data_Byte_Size);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock);
				
				initialVectorBlock = outputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
				
				//The initial vector data for the next(forward) round is the output data
				//下一轮的初始向量数据是输出数据
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in CBC Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithCBC(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty() || (input.size() % AlogritmObject.Number_Block_Data_Byte_Size != 0))
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				//The key data are involved in the decryption calculation
				//密钥数据参与了解密计算
				outputDataSubrange = AlogritmObject.DecryptBlockData(inputDataSubrange);
				
				//The initial vector data for the previous(backward) round is the input data
				//上一轮的初始向量数据是输入数据
				
				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				initialVectorBlock = inputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);
			
			return true;
		}

		/*
			
			填充密码块链接（PCBC，Propagating cipher-block chaining）或称为明文密码块链接（Plaintext cipher-block chaining）
			是一种可以使密文中的微小更改在解密时导致明文大部分错误的模式，并在加密的时候也具有同样的特性。

			Propagating cipher-block chaining (PCBC) or Plaintext cipher-block chaining
			Is a pattern that allows small changes in the ciphertext to cause most errors in the plaintext when decrypted, and has the same property when encrypted.

			Execute Process (执行过程):
			CipherText[index] = EncryptDataFunction(PlainText[index] ^ InitialVector[index], Key[index])
			InitialVector[index] = PlainText[index] ^ CipherText[index]

			PlainText[index] = DecryptDataFunction(CipherText[index], Key[index]) ^ InitialVector[index]
			InitialVector[index] = PlainText[index] ^ CipherText[index]

		*/

		/**
		* Encrypt input plain text with an AES key in PCBC Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithPCBC(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, inputDataSubrange, initialVectorBlock, AlogritmObject.Number_Block_Data_Byte_Size);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock);
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, initialVectorBlock, AlogritmObject.Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
				
				//The initial vector data for the next(forward) round is the output data
				//下一轮的初始向量数据是输出数据
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in PCBC Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithPCBC(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty() || (input.size() % AlogritmObject.Number_Block_Data_Byte_Size != 0))
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				//The key data are involved in the decryption calculation
				//密钥数据参与了解密计算
				outputDataSubrange = AlogritmObject.DecryptBlockData(inputDataSubrange);
				
				AES_ExclusiveOR_ByteDataBlock(outputDataSubrange, initialVectorBlock, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				//The initial vector data for the previous(backward) round is the input data
				//上一轮的初始向量数据是输入数据
				
				AES_ExclusiveOR_ByteDataBlock(outputDataSubrange, inputDataSubrange, initialVectorBlock, AlogritmObject.Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);
			
			return true;
		}

		/*
			
			密文反馈（CFB，Cipher feedback）模式类似于 CBC，可以将块密码变为自同步的流密码；
			工作过程亦非常相似，CFB 的解密过程几乎就是颠倒的 CBC 的加密过程

			Cipher feedback (CFB) mode is similar to CBC in that it turns a block cipher into a self-synchronizing stream cipher; 
			the process is also very similar, and the decryption process of CFB is almost the reverse of the encryption process of CBC.

			Execute Process (执行过程):
			CipherInitialVector[index] = EncryptionDataFunction(InitialVector[index], Key[index])
			CipherText[index] = CipherInitialVector[index] ^ PlainText[index]
			InitialVector[index] = CipherText[index]

			CipherInitialVector[index] = EncryptionDataFunction(InitialVector[index], Key[index])
			PlainText[index] = CipherText[index] ^ CipherInitialVector[index]
			InitialVector[index] = CipherText[index]
			
		*/

		/**
		* Encrypt input plain text with an AES key in CFB Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/			
		bool EncryptionWithCFB(std::vector<std::uint8_t> input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t> initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock);
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				initialVectorBlock = outputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in CFB Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithCFB(std::vector<std::uint8_t> input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t> initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock);
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				initialVectorBlock = inputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);

			return true;
		}

		/*
			
			输出反馈（OFB）
			输出反馈模式（Output feedback, OFB）可以将块密码变成同步的流密码。
			它产生密钥流的块，然后将其与明文块进行异或，得到密文。与其它流密码一样，密文中一个位的翻转会使明文中同样位置的位也产生翻转。
			这种特性使得许多错误校正码，例如奇偶校验位，即使在加密前计算，而在加密后进行校验也可以得出正确结果。

			由于 XOR 操作的对称性，加密和解密操作是完全相同的

			Execute Process (执行过程):

			CipherInitialVector[index] = EncryptionDataFunction(InitialVector[index], Key[index])
			CipherText[index] = PlainText[index] ^ CipherInitialVector[index]
			InitialVector[index] = CipherInitialVector[index]
			
		*/

		/**
		* Encrypt input plain text with an AES key in OFB Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithOFB(std::vector<std::uint8_t> input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t> initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock);
				
				initialVectorBlock = outputDataSubrange;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in OFB Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithOFB(std::vector<std::uint8_t> input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t> initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			std::span<const std::uint8_t> byteKeySpan(key.begin(), key.end());
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//Key data for extension
				//密钥数据进行扩展
				AlogritmObject.KeyExpansion(byteKeySpan.subspan(blockIndex, AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)));
				blockIndex += AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t);
				if(blockIndex >= byteKeySpan.size())
					blockIndex = 0;

				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock);
				
				initialVectorBlock = outputDataSubrange;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			
			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);

			return true;
		}

	#else

	private:
		
		ExperimentalAlgorithm<SecurityLevel> AlogritmObject;

		ChunkedDataPadders<ChunkedDataPaddingMode::PKCS7> ChunkedDataPadManager;

	public:

		constexpr std::uint8_t GetBlockSize_DataByte() const
		{
			return AlogritmObject.Number_Block_Data_Byte_Size;
		}

		constexpr std::size_t GetBlockSize_KeyByte() const
		{
			return AlogritmObject.Number_Key_Data_Block_Size * AlogritmObject.ONE_WORD_BYTE_SIZE;
		}

		constexpr std::size_t GetBlockSize_ExpandedKeyByte()
		{
			return AlogritmObject.ONE_WORD_BYTE_SIZE * AlogritmObject.NUMBER_DATA_BLOCK_COUNT * (AlogritmObject.Number_Execute_Round_Count + 1);
		}

		/**
		* Encrypt input plain text with an AES key in ECB Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithECB(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t>& output)
		{
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(inputDataSubrange, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;

				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in ECB Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithECB(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t>& output)
		{
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty() || (input.size() % AlogritmObject.Number_Block_Data_Byte_Size != 0))
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.DecryptBlockData(inputDataSubrange, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();

			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);
			
			return true;
		}

		/**
		* Encrypt input plain text with an AES key in CBC Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithCBC(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, inputDataSubrange, initialVectorBlock, AlogritmObject.Number_Block_Data_Byte_Size);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				initialVectorBlock = outputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
				
				//The initial vector data for the next(forward) round is the output data
				//下一轮的初始向量数据是输出数据
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in CBC Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithCBC(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty() || (input.size() % AlogritmObject.Number_Block_Data_Byte_Size != 0))
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the decryption calculation
				//密钥数据参与了解密计算
				outputDataSubrange = AlogritmObject.DecryptBlockData(inputDataSubrange, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				//The initial vector data for the previous(backward) round is the input data
				//上一轮的初始向量数据是输入数据
				
				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				initialVectorBlock = inputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();

			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);
			
			return true;
		}

		/**
		* Encrypt input plain text with an AES key in PCBC Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithPCBC(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, inputDataSubrange, initialVectorBlock, AlogritmObject.Number_Block_Data_Byte_Size);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, initialVectorBlock, AlogritmObject.Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
				
				//The initial vector data for the next(forward) round is the output data
				//下一轮的初始向量数据是输出数据
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in PCBC Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithPCBC(const std::vector<std::uint8_t>& input, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty() || (input.size() % AlogritmObject.Number_Block_Data_Byte_Size != 0))
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the decryption calculation
				//密钥数据参与了解密计算
				outputDataSubrange = AlogritmObject.DecryptBlockData(inputDataSubrange, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				AES_ExclusiveOR_ByteDataBlock(outputDataSubrange, initialVectorBlock, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				//The initial vector data for the previous(backward) round is the input data
				//上一轮的初始向量数据是输入数据
				
				AES_ExclusiveOR_ByteDataBlock(outputDataSubrange, inputDataSubrange, initialVectorBlock, AlogritmObject.Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}
			
			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();

			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);
			
			return true;
		}

		/**
		* Encrypt input plain text with an AES key in CFB Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/			
		bool EncryptionWithCFB(std::vector<std::uint8_t> input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t> initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				initialVectorBlock = outputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in CFB Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithCFB(std::vector<std::uint8_t> input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t> initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				initialVectorBlock = inputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();

			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);

			return true;
		}

		/**
		* Encrypt input plain text with an AES key in OFB Mode.
		*
		* @param in; Plain text to encrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES encryption.
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithOFB(std::vector<std::uint8_t> input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t> initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			this->ChunkedDataPadManager.Pad(data_copy_input, AlogritmObject.Number_Block_Data_Byte_Size);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				initialVectorBlock = outputDataSubrange;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in OFB Mode.
		*
		* @param in; Cipher text to decrypt.
		* @param key; AES encryption key.
		* @param out; The result of AES decryption.
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithOFB(std::vector<std::uint8_t> input, const std::vector<std::uint8_t>& key, std::vector<std::uint8_t> initialVector, std::vector<std::uint8_t>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if (key.size() % (AlogritmObject.Number_Key_Data_Block_Size * sizeof(std::uint32_t)) != 0)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != AlogritmObject.Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<std::uint8_t> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<std::vector<std::uint8_t>> expandedWordRoundKeyBlock;
			AlogritmObject.KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<std::uint8_t> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0, blockIndex = 0; index < data_copy_input.size(); index += AlogritmObject.Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = AlogritmObject.Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = AlogritmObject.Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<std::uint8_t>, std::vector<std::uint8_t>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = AlogritmObject.EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock[blockIndex]);
				++blockIndex;

				if(blockIndex >= expandedWordRoundKeyBlock.size())
					blockIndex = 0;
				
				initialVectorBlock = outputDataSubrange;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, AlogritmObject.Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(data_copy_input.data(), data_copy_input.size());
			my_cpp2020_assert(CheckPointer == data_copy_input.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();

			CheckPointer = memory_set_no_optimize_function<0x00>(initialVectorBlock.data(), initialVectorBlock.size());
			my_cpp2020_assert(CheckPointer == initialVectorBlock.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();

			for(std::size_t blockIndex = 0; blockIndex < expandedWordRoundKeyBlock.size(); ++blockIndex)
			{
				CheckPointer = memory_set_no_optimize_function<0x00>(expandedWordRoundKeyBlock[blockIndex].data(), expandedWordRoundKeyBlock[blockIndex].size());
				my_cpp2020_assert(CheckPointer == expandedWordRoundKeyBlock[blockIndex].data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			this->ChunkedDataPadManager.Unpad(output, AlogritmObject.Number_Block_Data_Byte_Size);

			return true;
		}

	#endif

		DataWorker() = default;
		~DataWorker() = default;

		DataWorker(DataWorker& _object) = delete;
		DataWorker& operator=(const DataWorker& _object) = delete;
	};
}

/*
	
	Paper: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf
	
*/
namespace CommonSecurity::TripleDES
{
	using ExperimentalWorker = CommonSecurity::TripleDES::ProcedureFunctions::TripleDES<true>;
	using OfficialWorker = CommonSecurity::TripleDES::ProcedureFunctions::TripleDES<false>;
	
	inline void TripleDES_Executor
	(
		ProcedureFunctions::TripleDES<true>& TripleDES_Object,
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
		const std::vector<std::uint8_t>& inputDataBlock,
		std::deque<std::vector<std::uint8_t>>& keyBlockChain,
		std::vector<std::uint8_t>& outputDataBlock,
		bool forceAssert = true
	)
	{
		CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange MemoryDataFormatExchanger;
		std::vector<std::uint64_t> Bit64_Keys;

		std::mt19937 pseudoRandomGenerator { static_cast<std::uint32_t>( keyBlockChain.front().operator[](0) ) };
		CommonSecurity::RND::UniformIntegerDistribution number_distribution(0, 255);

		if(inputDataBlock.empty())
		{
			throw std::length_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the input data cannot be zero!");
		}

		if(forceAssert)
		{
			my_cpp2020_assert(keyBlockChain.size() % 3 == 0, "CommonSecurity::TripleDES::TripleDES_Executor() The Triple DES algorithm requires the number of keys to be modulo 3 to work!", std::source_location::current());

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : keyBlockChain)
			{
				while(keyBlock.size() % sizeof(std::uint64_t) != 0)
				{
					std::uint8_t randomByte = static_cast<std::uint8_t>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bit64_Keys.push_back( MemoryDataFormatExchanger.Packer_8Byte(keyBlock) );
			}
		}
		else
		{
			std::deque<std::vector<std::uint8_t>> copiedKeyBlockChain = keyBlockChain;

			std::size_t KeyBlockTruncationCount = copiedKeyBlockChain.size() % 3;
			while (KeyBlockTruncationCount > 0)
			{
				copiedKeyBlockChain.back().clear();
				copiedKeyBlockChain.back().shrink_to_fit();
				copiedKeyBlockChain.pop_back();
				--KeyBlockTruncationCount;
			}

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : copiedKeyBlockChain)
			{
				while(keyBlock.size() % sizeof(std::uint64_t) != 0)
				{
					std::uint8_t randomByte = static_cast<std::uint8_t>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bit64_Keys.push_back( MemoryDataFormatExchanger.Packer_8Byte(keyBlock) );
			}
		}

		std::vector<std::uint8_t> temporaryDataBlock { inputDataBlock };
		
		std::size_t dataBlockByteSize = inputDataBlock.size();

		CommonSecurity::ChunkedDataPadders<CommonSecurity::ChunkedDataPaddingMode::PKCS7> ChunkedDataPadManager;

		using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

		switch (executeMode)
		{
			//CipherText = Encryption(Decryption(Encryption(PlainText, Key), Key2), Key3);
			case CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				ChunkedDataPadManager.Pad(temporaryDataBlock, sizeof(std::uint64_t));

				std::cout << "TripleDES Encryption Start !" << std::endl;

				for(std::size_t index = 0; index < Bit64_Keys.size(); index += 3)
				{
					//Use Encryption Main Round Key 1
					TripleDES_Object.DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index));
					temporaryDataBlock = TripleDES_Object.DES_Worker.DES_Executor(CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				
					//Use Encryption Main Round Key 2
					TripleDES_Object.DES_Worker2.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index + 1));
					temporaryDataBlock = TripleDES_Object.DES_Worker2.DES_Executor(CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);

					//Use Encryption Main Round Key 3
					TripleDES_Object.DES_Worker3.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index + 2));
					temporaryDataBlock = TripleDES_Object.DES_Worker3.DES_Executor(CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				}

				std::cout << "TripleDES Encryption End !" << std::endl;

				outputDataBlock.resize(temporaryDataBlock.size());

				std::ranges::copy(temporaryDataBlock.begin(), temporaryDataBlock.end(), outputDataBlock.begin());
				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				break;
			}
			//PlainText = Decryption(Encryption(Decryption(CipherText, Key3), Key2), Key);
			case CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				std::cout << "TripleDES Decryption Start !" << std::endl;

				for(std::size_t index = Bit64_Keys.size() - 1; index > 0;)
				{
					//Use Decryption Main Round Key 1
					TripleDES_Object.DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index));
					temporaryDataBlock = TripleDES_Object.DES_Worker.DES_Executor(CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);
				
					//Use Decryption Main Round Key 2
					TripleDES_Object.DES_Worker2.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index - 1));
					temporaryDataBlock = TripleDES_Object.DES_Worker2.DES_Executor(CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);

					//Use Decryption Main Round Key 3
					TripleDES_Object.DES_Worker3.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index - 2));
					temporaryDataBlock = TripleDES_Object.DES_Worker3.DES_Executor(CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);

					if(index - 3 > index)
					{
						break;
					}
					else
					{
						index -= 3;
					}
				}

				std::cout << "TripleDES Decryption End !" << std::endl;

				outputDataBlock.resize(temporaryDataBlock.size());

				std::ranges::copy(temporaryDataBlock.begin(), temporaryDataBlock.end(), outputDataBlock.begin());
				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				ChunkedDataPadManager.Unpad(outputDataBlock, sizeof(std::uint64_t));

				break;
			}
			default:
			{
				std::cout << "Wrong TripleDES DataWorker worker is selected" << std::endl;
				abort();
			}
		}
	}

	inline void TripleDES_Executor
	(
		ProcedureFunctions::TripleDES<false>& TripleDES_Object,
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
		const std::vector<std::uint8_t>& inputDataBlock,
		const std::deque<std::vector<std::uint8_t>>& keyBlockChain,
		std::vector<std::uint8_t>& outputDataBlock,
		bool forceAssert = true
	)
	{
		std::deque<std::vector<std::uint8_t>> copiedKeyBlockChain {keyBlockChain.begin(), keyBlockChain.end()};

		if(inputDataBlock.empty())
		{
			throw std::length_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the input data cannot be zero!");
		}

		if(forceAssert)
		{
			my_cpp2020_assert(keyBlockChain.size() % 3 == 0, "CommonSecurity::TripleDES::TripleDES_Executor() The Triple DES algorithm requires the number of keys to be modulo 3 to work!", std::source_location::current());

			CommonSecurity::RNG_Xoshiro::xoshiro256 pseudoRandomGenerator { static_cast<std::uint32_t>( keyBlockChain.front().operator[](0) ) };
			CommonSecurity::RND::UniformIntegerDistribution number_distribution(0, 255);

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : copiedKeyBlockChain)
			{
				while(keyBlock.size() < sizeof(std::uint64_t) * 3)
				{
					std::uint8_t randomByte = static_cast<std::uint8_t>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				if(keyBlock.size() > sizeof(std::uint64_t) * 3)
					keyBlock.resize(sizeof(std::uint64_t) * 3);
			}
		}
		else
		{
			std::size_t KeyBlockTruncationCount = copiedKeyBlockChain.size() % 3;
			while (KeyBlockTruncationCount > 0)
			{
				copiedKeyBlockChain.back().clear();
				copiedKeyBlockChain.back().shrink_to_fit();
				copiedKeyBlockChain.pop_back();
				--KeyBlockTruncationCount;
			}

			CommonSecurity::RNG_Xoshiro::xoshiro256 pseudoRandomGenerator { static_cast<std::uint32_t>( keyBlockChain.front().operator[](0) ) };
			CommonSecurity::RND::UniformIntegerDistribution number_distribution(0, 255);

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : copiedKeyBlockChain)
			{
				while(keyBlock.size() < sizeof(std::uint64_t) * 3)
				{
					std::uint8_t randomByte = static_cast<std::uint8_t>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				if(keyBlock.size() > sizeof(std::uint64_t) * 3)
					keyBlock.resize(sizeof(std::uint64_t) * 3);
			}
		}

		std::vector<std::uint8_t> temporaryDataBlock { inputDataBlock };

		std::size_t dataBlockByteSize = inputDataBlock.size();

		CommonSecurity::ChunkedDataPadders<CommonSecurity::ChunkedDataPaddingMode::PKCS7> ChunkedDataPadManager;

		using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

		switch (executeMode)
		{
			//CipherText = Encryption(Decryption(Encryption(PlainText, Key), Key2), Key3);
			case CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				//Padding Data

				ChunkedDataPadManager.Pad(temporaryDataBlock, sizeof(std::uint64_t));
				outputDataBlock.resize(temporaryDataBlock.size(), 0);

				my_cpp2020_assert
				(
					outputDataBlock.size() % sizeof(std::uint64_t) == 0,
					"CommonSecurity::TripleDES::TripleDES_Executor() The encryption of the triple DES algorithm requires a data number of modulo 8 to work!",
					std::source_location::current()
				);

				std::span<std::uint8_t> inputDataBlockSpan { temporaryDataBlock };
				std::span<std::uint8_t> outputDataBlockSpan { outputDataBlock };

				auto inputDataBlockSubSpan = inputDataBlockSpan.subspan(0, sizeof(std::uint64_t));
				auto outputDataBlockSubSpan = outputDataBlockSpan.subspan(0, sizeof(std::uint64_t));

				std::span<std::uint8_t> PadedBlock = inputDataBlockSpan.subspan
				(
					temporaryDataBlock.size() - sizeof(std::uint64_t),
					sizeof(std::uint64_t)
				);

				for(std::uint32_t Index = 0U; Index < sizeof(std::uint64_t) - 1; ++Index)
				{
					PadedBlock[Index] ^= copiedKeyBlockChain[0U][Index];
				}

				std::cout << "TripleDES Encryption Start !" << std::endl;

				for
				(
					std::size_t keyblock_index = 0, datablock_index = 0;
					datablock_index < temporaryDataBlock.size() - sizeof(std::uint64_t);
				)
				{
					TripleDES_Object.GenerateSubkeys(copiedKeyBlockChain.operator[](keyblock_index));
					TripleDES_Object.BlockEncryption(inputDataBlockSubSpan, outputDataBlockSubSpan);

					datablock_index += sizeof(std::uint64_t);
					
					if(datablock_index + sizeof(std::uint64_t) >= temporaryDataBlock.size())
						break;

					inputDataBlockSubSpan = inputDataBlockSpan.subspan(datablock_index, sizeof(std::uint64_t));
					outputDataBlockSubSpan = outputDataBlockSpan.subspan(datablock_index, sizeof(std::uint64_t));

					if(keyblock_index + 1 >= copiedKeyBlockChain.size())
						keyblock_index = 0U;
					else
						++keyblock_index;
				}

				std::cout << "TripleDES Encryption End !" << std::endl;

				std::span<std::uint8_t> PadedBlock2 = outputDataBlockSpan.subspan
				(
					outputDataBlock.size() - sizeof(std::uint64_t),
					sizeof(std::uint64_t)
				);

				std::ranges::copy(PadedBlock.begin(), PadedBlock.end(), PadedBlock2.begin());

				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				break;
			}
			//PlainText = Decryption(Encryption(Decryption(CipherText, Key3), Key2), Key);
			case CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				my_cpp2020_assert
				(
					temporaryDataBlock.size() % sizeof(std::uint64_t) == 0,
					"CommonSecurity::TripleDES::TripleDES_Executor() The decryption of the triple DES algorithm requires a data number of modulo 8 to work!",
					std::source_location::current()
				);

				std::cout << "TripleDES Decryption Start !" << std::endl;

				outputDataBlock.resize(temporaryDataBlock.size(), 0);

				std::span<std::uint8_t> inputDataBlockSpan { temporaryDataBlock };
				std::span<std::uint8_t> outputDataBlockSpan { outputDataBlock };

				auto inputDataBlockSubSpan = inputDataBlockSpan.subspan(0, sizeof(std::uint64_t));
				auto outputDataBlockSubSpan = outputDataBlockSpan.subspan(0, sizeof(std::uint64_t));

				std::uint32_t PadedBlockSize = temporaryDataBlock.back();

				std::span<std::uint8_t> PadedBlock = inputDataBlockSpan.subspan
				(
					temporaryDataBlock.size() - sizeof(std::uint64_t),
					sizeof(std::uint64_t)
				);

				for(std::uint32_t Index = 0U; Index < sizeof(std::uint64_t) - 1; ++Index)
				{
					PadedBlock[Index] ^= copiedKeyBlockChain[0U][Index];
				}				

				for
				(
					std::size_t keyblock_index = 0, datablock_index = 0;
					datablock_index < temporaryDataBlock.size() - sizeof(std::uint64_t);
				)
				{
					TripleDES_Object.GenerateSubkeys(copiedKeyBlockChain.operator[](keyblock_index));
					TripleDES_Object.BlockDecryption(inputDataBlockSubSpan, outputDataBlockSubSpan);

					datablock_index += sizeof(std::uint64_t);

					if(datablock_index + sizeof(std::uint64_t) >= temporaryDataBlock.size())
						break;

					inputDataBlockSubSpan = inputDataBlockSpan.subspan(datablock_index, sizeof(std::uint64_t));
					outputDataBlockSubSpan = outputDataBlockSpan.subspan(datablock_index, sizeof(std::uint64_t));

					if(keyblock_index + 1 >= copiedKeyBlockChain.size())
						keyblock_index = 0U;
					else
						++keyblock_index;
				}

				std::cout << "TripleDES Decryption End !" << std::endl;

				std::span<std::uint8_t> PadedBlock2 = outputDataBlockSpan.subspan
				(
					outputDataBlock.size() - sizeof(std::uint64_t),
					sizeof(std::uint64_t)
				);

				std::ranges::copy(PadedBlock.begin(), PadedBlock.end(), PadedBlock2.begin());

				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				ChunkedDataPadManager.Unpad(outputDataBlock, sizeof(std::uint64_t));

				break;
			}
			default:
			{
				std::cout << "Wrong TripleDES DataWorker worker is selected" << std::endl;
				abort();
			}
		}
	}
}

/*
	RC6 ciphers papers:
	http://people.csail.mit.edu/rivest/pubs/RRSY98.pdf

	RC6 ciphers auther code(C languange):
	https://www.schneier.com/wp-content/uploads/2015/03/RC6-AES-2.zip
*/
namespace CommonSecurity::RC6
{
	/*
		RC6 SecurityLevel
		ZERO: 20 Half-Rounds
		ONE: 40 Half-Rounds
		TWO: 60 Half-Rounds
	*/
	enum class RC6_SecurityLevel
	{
		ZERO = 0,
		ONE = 1,
		TWO = 2
	};

	template<typename Type>
	concept BlockWordType = std::same_as<Type, std::uint32_t> || std::same_as<Type, std::uint64_t>;

	constexpr size_t BlockSize() { return 4; }
	template<BlockWordType Type>
	constexpr size_t BlockByteSize() { return sizeof(Type) * RC6::BlockSize(); }

	template<BlockWordType Type>
	class DataWorker
	{

	private:

		//Number of half-rounds
		//Encryption/Decryption consists of a non-negative number of rounds (Based on security estimates)
		Type RC6_Cryption_RoundNumber;

		//Specific to RC6, we have removed the BYTE *KS and added in an array of 2+2*ROUNDS+2 = 44 rounds to hold the key schedule/
		//Default iteration limit for key scheduling
		size_t RC6_Default_IterationLimit;

		//The size of data word from bits
		static constexpr Type RC6_WordData_BitSize = std::numeric_limits<Type>::digits;

		//Math exprssion
		//static_cast<Type>(std::log2(RC6_WordData_BitSize))
		static constexpr Type RC6_Log2_WordData_BitSize = CURRENT_SYSTEM_BITS == 32 ? 5 : 6;

		//16bit: 0xB7E1, 32bit: 0xB7E15163
		const Type MagicNumber_P = static_cast<Type>(DefineConstants::Number_BaseOfTheNaturalLogarithm - 2) * ::pow(2, RC6_WordData_BitSize);
		
		//16bit: 0x9E37. 32bit: 0x9E3779B9
		const Type MagicNumber_Q = static_cast<Type>(DefineConstants::Number_GoldenRatio * ::pow(2, RC6_WordData_BitSize));

		void KeySchedule(std::span<const std::uint8_t> keySpan, std::span<Type> keyScheduleBoxSpan)
		{
			// Copy key to not modify original
			std::vector<std::uint8_t> key_copy { keySpan.begin(), keySpan.end() };

			// Pad to word length
			while (key_copy.size() % sizeof(Type) != 0)
				key_copy.push_back(0);

			// total_words called c from RC6 paper
			const std::size_t total_words = key_copy.size() / sizeof(Type);

			// least_word_key called L from RC6 paper (Ensure bytes are loaded little endian)
			auto least_word_key = CommonToolkit::MessagePacking<Type, std::uint8_t>(key_copy.data(), key_copy.size());

			// number_iterations called v from RC6 paper
			const std::size_t number_iterations = 3 * std::max( static_cast<Type>(total_words), static_cast<Type>(this->RC6_Default_IterationLimit) );
			Type schedule_index = 0, word_index = 0;

			// Create initial schedule
			keyScheduleBoxSpan[0] = this->MagicNumber_P;
			for (schedule_index = 1; schedule_index <= 2 * this->RC6_Cryption_RoundNumber + 3; ++schedule_index)
			{
				keyScheduleBoxSpan[schedule_index] = keyScheduleBoxSpan[schedule_index - 1] + this->MagicNumber_Q;
			}

			// Create schedule for determined iterations
			schedule_index = 0;
			Type ValueA = 0, ValueB = 0;
			// iteration called s from RC6 paper
			for (std::size_t iteration = 1; iteration <= number_iterations; ++iteration)
			{
				Type AB_SumValue = 0;

				AB_SumValue = ValueA + ValueB;
				keyScheduleBoxSpan[schedule_index] = ProcedureFunctions::LeftRotateBit(keyScheduleBoxSpan[schedule_index] + AB_SumValue, 3);
				ValueA = keyScheduleBoxSpan[schedule_index];

				AB_SumValue = ValueA + ValueB;
				least_word_key[word_index] = ProcedureFunctions::LeftRotateBit(least_word_key[word_index] + AB_SumValue, AB_SumValue % std::numeric_limits<Type>::digits);
				ValueB = least_word_key[word_index];

				// Wrapped indices for schedule/little endian word key
				schedule_index = (schedule_index + 1) % this->RC6_Default_IterationLimit;
				word_index = (word_index + 1) % total_words;
			}

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(key_copy.data(), key_copy.size());
			my_cpp2020_assert(CheckPointer == key_copy.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		void Encryption(std::span<std::uint8_t> dataBlock, std::span<const std::uint8_t> keyBlock)
		{
			// Set up word-sized 'registers'
			Type* block_worlds = reinterpret_cast<Type*>(dataBlock.data());
			Type& ValueA = block_worlds[0];
			Type& ValueB = block_worlds[1];
			Type& ValueC = block_worlds[2];
			Type& ValueD = block_worlds[3];

			if constexpr(std::endian::native == std::endian::big)
			{
				ValueA = CommonToolkit::ByteSwap::byteswap(ValueA);
				ValueB = CommonToolkit::ByteSwap::byteswap(ValueB);
				ValueC = CommonToolkit::ByteSwap::byteswap(ValueC);
				ValueD = CommonToolkit::ByteSwap::byteswap(ValueD);
			}

			// Create schedule
			// schedule called S from RC6 paper
			std::vector<Type> keyScheduleBox(this->RC6_Default_IterationLimit, Type{0U});

			std::span keyScheduleBoxSpan{ keyScheduleBox };

			// The role of S-box is to confuse (Confusion), mainly to increase the complexity between plaintext and ciphertext (including non-linearity, etc.)
			// S盒的作用是混淆(Confusion),主要增加明文和密文之间的复杂度（包括非线性度等）。
			this->KeySchedule(keyBlock, keyScheduleBoxSpan);

			/* Do pseudo-round #0: pre-whitening of B and D */
			ValueB += keyScheduleBox.operator[](0);
			ValueD += keyScheduleBox.operator[](1);

			for(std::size_t index = 1; index <= this->RC6_Cryption_RoundNumber; ++index)
			{
				Type TemporaryValue = ValueB * (2 * ValueB + 1);
				Type TemporaryValue2 = ValueD * (2 * ValueD + 1);

				Type temporary_value_t = ProcedureFunctions::LeftRotateBit( TemporaryValue, RC6_Log2_WordData_BitSize );
				Type temporary_value_u = ProcedureFunctions::LeftRotateBit( TemporaryValue2, RC6_Log2_WordData_BitSize );

				Type TemporaryValue3 = ValueA ^ temporary_value_t;
				Type TemporaryValue4 = ValueC ^ temporary_value_u;

				ValueA = ProcedureFunctions::LeftRotateBit( TemporaryValue3, temporary_value_u ) + keyScheduleBox.operator[](2 * index);
				ValueC = ProcedureFunctions::LeftRotateBit( TemporaryValue4, temporary_value_t ) + keyScheduleBox.operator[](2 * index + 1);

				{
					Type TemporaryValueSwap = 0; 
					TemporaryValueSwap = ValueA;
					ValueA = ValueB;
					ValueB = ValueC;
					ValueC = ValueD;
					ValueD = TemporaryValueSwap;
				}

				//Rotate left 1 offset position
				//std::ranges::rotate(Word32BitRegisters, Word32BitRegisters.begin() + 1);
			}

			/* Do pseudo-round #(ROUNDS+1): post-whitening of A and C */
			ValueA += keyScheduleBox.operator[](this->RC6_Default_IterationLimit - 2);
			ValueC += keyScheduleBox.operator[](this->RC6_Default_IterationLimit - 1);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(keyScheduleBox.data(), sizeof(Type) * keyScheduleBox.size());
			my_cpp2020_assert(CheckPointer == keyScheduleBox.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		void Decryption(std::span<std::uint8_t> dataBlock, std::span<const std::uint8_t> keyBlock)
		{
			// Set up word-sized 'registers'
			Type* block_worlds = reinterpret_cast<Type*>(dataBlock.data());
			Type& ValueA = block_worlds[0];
			Type& ValueB = block_worlds[1];
			Type& ValueC = block_worlds[2];
			Type& ValueD = block_worlds[3];

			if constexpr(std::endian::native == std::endian::big)
			{
				ValueA = CommonToolkit::ByteSwap::byteswap(ValueA);
				ValueB = CommonToolkit::ByteSwap::byteswap(ValueB);
				ValueC = CommonToolkit::ByteSwap::byteswap(ValueC);
				ValueD = CommonToolkit::ByteSwap::byteswap(ValueD);
			}

			// Create schedule
			// schedule called S from RC6 paper
			std::vector<Type> keyScheduleBox(this->RC6_Default_IterationLimit, Type{0U});

			std::span keyScheduleBoxSpan{ keyScheduleBox };

			// The role of S-box is to confuse (Confusion), mainly to increase the complexity between plaintext and ciphertext (including non-linearity, etc.)
			// S盒的作用是混淆(Confusion),主要增加明文和密文之间的复杂度（包括非线性度等）。
			this->KeySchedule(keyBlock, keyScheduleBoxSpan);

			/* Do pseudo-round #(ROUNDS+1): post-whitening of A and C */
			ValueC -= keyScheduleBox.operator[](this->RC6_Default_IterationLimit - 1);
			ValueA -= keyScheduleBox.operator[](this->RC6_Default_IterationLimit - 2);

			for(std::size_t index = this->RC6_Cryption_RoundNumber; index >= 1; --index)
			{
				//Rotate right 1 offset position
				//std::ranges::rotate(Word32BitRegisters, Word32BitRegisters.end() - 1);

				{
					Type TemporaryValueSwap = 0;
					TemporaryValueSwap = ValueD;
					ValueD = ValueC;
					ValueC = ValueB;
					ValueB = ValueA;
					ValueA = TemporaryValueSwap;
				}

				Type TemporaryValue = ValueD * (2 * ValueD + 1);
				Type TemporaryValue2 = ValueB * (2 * ValueB + 1);

				Type __u__ = ProcedureFunctions::LeftRotateBit( TemporaryValue, RC6_Log2_WordData_BitSize );
				Type __t__ = ProcedureFunctions::LeftRotateBit( TemporaryValue2, RC6_Log2_WordData_BitSize );

				Type TemporaryValue3 = ValueC - keyScheduleBox.operator[](2 * index + 1);
				Type TemporaryValue4 = ValueA - keyScheduleBox.operator[](2 * index);

				ValueC = ProcedureFunctions::RightRotateBit( TemporaryValue3, __t__ ) ^ __u__;
				ValueA = ProcedureFunctions::RightRotateBit( TemporaryValue4, __u__ ) ^ __t__;
			}

			/* Undo pseudo-round #0: pre-whitening of B and D */
			ValueD -= keyScheduleBox.operator[](1);
			ValueB -= keyScheduleBox.operator[](0);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(keyScheduleBox.data(), sizeof(Type) * keyScheduleBox.size());
			my_cpp2020_assert(CheckPointer == keyScheduleBox.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

	public:

		std::vector<std::uint8_t> EncryptionECB(const std::vector<std::uint8_t>& dataBlock, const std::vector<std::uint8_t>& keyBlock)
		{
			constexpr std::size_t BlockByteSize = RC6::BlockByteSize<Type>();
			// key_bit_len called b from RC6 paper

			const std::size_t key_bit_size = keyBlock.size() * std::numeric_limits<std::uint8_t>::digits;
			my_cpp2020_assert(key_bit_size <= DefineConstants::RC6_KeyBitSize_MaxLimit && key_bit_size % (RC6::BlockByteSize<Type>() * std::numeric_limits<std::uint8_t>::digits) == 0, "The byte size of the RC6 key must be in the range of 1 to 255, and the key byte size must be a multiple of BlockByteSize: sizeof(Type) * 4!\n", std::source_location::current());

			std::vector<std::uint8_t> processedDataBlock(dataBlock.begin(), dataBlock.end());
			auto key_begin = keyBlock.begin(), key_end = keyBlock.end();
			for
			(
				auto begin = processedDataBlock.begin(), end = processedDataBlock.end();
				begin + BlockByteSize < end && key_begin + BlockByteSize < key_end;
				begin += BlockByteSize, key_begin += BlockByteSize
			)
			{
				std::span<std::uint8_t> dataChunkBlock { begin, begin + BlockByteSize };
				std::span<const std::uint8_t> keyChunkBlock { key_begin, key_begin + BlockByteSize };
				this->Encryption(dataChunkBlock, keyChunkBlock);
			}

			return processedDataBlock;
		}

		std::vector<std::uint8_t> DecryptionECB(const std::vector<std::uint8_t>& dataBlock, const std::vector<std::uint8_t>& keyBlock)
		{
			constexpr std::size_t BlockByteSize = RC6::BlockByteSize<Type>();

			const std::size_t key_bit_size = keyBlock.size() * std::numeric_limits<std::uint8_t>::digits;
			my_cpp2020_assert(key_bit_size <= DefineConstants::RC6_KeyBitSize_MaxLimit && key_bit_size % (RC6::BlockByteSize<Type>() * std::numeric_limits<std::uint8_t>::digits) == 0, "The byte size of the RC6 key must be in the range of 1 to 255, and the key byte size must be a multiple of BlockByteSize: sizeof(Type) * 4!\n", std::source_location::current());

			std::vector<std::uint8_t> processedDataBlock(dataBlock.begin(), dataBlock.end());
			
			auto key_begin = keyBlock.begin(), key_end = keyBlock.end();
			for
			(
				auto begin = processedDataBlock.begin(), end = processedDataBlock.end();
				begin + BlockByteSize < end && key_begin + BlockByteSize < key_end;
				begin += BlockByteSize, key_begin += BlockByteSize
			)
			{
				std::span<std::uint8_t> dataChunkBlock { begin, begin + BlockByteSize };
				std::span<const std::uint8_t> keyChunkBlock { key_begin, key_begin + BlockByteSize };
				this->Decryption(dataChunkBlock, keyChunkBlock);
			}

			return processedDataBlock;
		}

		std::vector<std::uint8_t> EncryptionCBC(const std::vector<std::uint8_t>& dataBlock, const std::vector<std::uint8_t>& keyBlock, const std::vector<std::uint8_t>& initialVector)
		{
			constexpr std::size_t BlockByteSize = RC6::BlockByteSize<Type>();
			my_cpp2020_assert(initialVector.size() == BlockByteSize, "The initial vector data size must be equal BlockByteSize: sizeof(Type) * 4 !\n", std::source_location::current());

			const std::size_t key_bit_size = keyBlock.size() * std::numeric_limits<std::uint8_t>::digits;
			my_cpp2020_assert(key_bit_size <= DefineConstants::RC6_KeyBitSize_MaxLimit && key_bit_size % (RC6::BlockByteSize<Type>() * std::numeric_limits<std::uint8_t>::digits) == 0, "The byte size of the RC6 key must be in the range of 1 to 255, and the key byte size must be a multiple of BlockByteSize: sizeof(Type) * 4!\n", std::source_location::current());

			std::size_t offset = 0;

			std::vector<std::uint8_t> processingInitialVector(initialVector.begin(), initialVector.end());
			std::vector<std::uint8_t> processedDataBlock(dataBlock.begin(), dataBlock.end());

			auto key_begin = keyBlock.begin(), key_end = keyBlock.end();
			for
			(
				auto begin = processedDataBlock.begin(), end = processedDataBlock.end();
				begin + BlockByteSize < end && key_begin + BlockByteSize < key_end;
				begin += BlockByteSize, key_begin += BlockByteSize
			)
			{
				std::span<std::uint8_t> dataChunkBlock { begin, begin + BlockByteSize };
				std::span<const std::uint8_t> keyChunkBlock { key_begin, key_begin + BlockByteSize };

				for(std::size_t index = 0; index < BlockByteSize; ++index)
				{
					processingInitialVector[index] ^= dataChunkBlock[index];
				}

				this->Encryption(processingInitialVector, keyChunkBlock);

				for(std::size_t index = 0; index < BlockByteSize; ++index)
				{
					dataChunkBlock[index] = processingInitialVector[index];
				}
			}

			return processedDataBlock;
		}

		std::vector<std::uint8_t> DecryptionCBC(const std::vector<std::uint8_t>& dataBlock, const std::vector<std::uint8_t>& keyBlock, const std::vector<std::uint8_t>& initialVector)
		{
			constexpr std::size_t BlockByteSize = RC6::BlockByteSize<Type>();
			my_cpp2020_assert(initialVector.size() == BlockByteSize, "The initial vector data size must be equal BlockByteSize: sizeof(Type) * 4 !\n", std::source_location::current());

			const std::size_t key_bit_size = keyBlock.size() * std::numeric_limits<std::uint8_t>::digits;
			my_cpp2020_assert(key_bit_size <= DefineConstants::RC6_KeyBitSize_MaxLimit && key_bit_size % (RC6::BlockByteSize<Type>() * std::numeric_limits<std::uint8_t>::digits) == 0, "The byte size of the RC6 key must be in the range of 1 to 255, and the key byte size must be a multiple of BlockByteSize: sizeof(Type) * 4!\n", std::source_location::current());

			std::vector<std::uint8_t> processingInitialVector(initialVector.begin(), initialVector.end());
			std::vector<std::uint8_t> processedDataBlock(dataBlock.begin(), dataBlock.end());
			
			std::size_t cipherDataIndex = 0;
			auto key_begin = keyBlock.begin(), key_end = keyBlock.end();
			for
			(
				auto begin = processedDataBlock.begin(), end = processedDataBlock.end();
				begin + BlockByteSize < end && key_begin + BlockByteSize < key_end;
				begin += BlockByteSize, key_begin += BlockByteSize
			)
			{
				std::span<std::uint8_t> dataChunkBlock { begin, begin + BlockByteSize };
				std::span<const std::uint8_t> keyChunkBlock { key_begin, key_begin + BlockByteSize };
				this->Decryption(dataChunkBlock, keyBlock);

				for(std::size_t index = 0; index < BlockByteSize; ++index)
				{
					dataChunkBlock[index] ^= processingInitialVector[index];
				}

				for(std::size_t index = 0; index < BlockByteSize && cipherDataIndex + index < dataBlock.size(); ++index)
				{
					processingInitialVector[index] = dataBlock[cipherDataIndex + index];
				}
				if(cipherDataIndex + BlockByteSize < dataBlock.size())
					cipherDataIndex += BlockByteSize;
			}

			return processedDataBlock;
		}

		//RC6 Algorithm <-> (W)ordSize/(R)oundNumber/(B)yteKeySize
		DataWorker(Type half_round = 20)
			:
			RC6_Cryption_RoundNumber(half_round),
			RC6_Default_IterationLimit(2 * RC6_Cryption_RoundNumber + 4)
		{
			my_cpp2020_assert(this->RC6_Cryption_RoundNumber != 0 && this->RC6_Cryption_RoundNumber % 4 == 0, "RC6 ciphers perform a half round count that is invalid!", std::source_location::current());

			if constexpr(CURRENT_SYSTEM_BITS == 32)
			{
				my_cpp2020_assert(RC6_WordData_BitSize != 32, "ERROR: Trying to run 256-bit blocksize on a 32-bit CPU.\n", std::source_location::current());
			}
		}

		DataWorker(RC6_SecurityLevel SecurityLevel)
		{
			switch (SecurityLevel)
			{
				case CommonSecurity::RC6::RC6_SecurityLevel::ZERO:
					RC6_Cryption_RoundNumber = 20;
					break;
				case CommonSecurity::RC6::RC6_SecurityLevel::ONE:
					RC6_Cryption_RoundNumber = 40;
					break;
				case CommonSecurity::RC6::RC6_SecurityLevel::TWO:
					RC6_Cryption_RoundNumber = 60;
					break;
				default:
					break;
			}

			RC6_Default_IterationLimit = 2 * RC6_Cryption_RoundNumber + 4;

			my_cpp2020_assert(this->RC6_Cryption_RoundNumber != 0 && this->RC6_Cryption_RoundNumber % 4 == 0, "RC6 ciphers perform a half round count that is invalid!", std::source_location::current());

			if constexpr(CURRENT_SYSTEM_BITS == 32)
			{
				my_cpp2020_assert(RC6_WordData_BitSize != 32, "ERROR: Trying to run 256-bit blocksize on a 32-bit CPU.\n", std::source_location::current());
			}
		}

		~DataWorker() = default;

		DataWorker(DataWorker& _object) = delete;
		DataWorker& operator=(const DataWorker& _object) = delete;
	};

	template<typename WordType>
	std::vector<std::uint8_t> RC6_Executor
	(
		CommonSecurity::RC6::DataWorker<WordType>& RC6_Worker,
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
		const std::vector<std::uint8_t>& dataBlock,
		std::vector<std::uint8_t>& key
	)
	{
		my_cpp2020_assert(!dataBlock.empty() && !key.empty(), "CommonSecurity::RC6::RC6_Executor: The data and key can not be empty!", std::source_location::current() );
		
		ChunkedDataPadders<ChunkedDataPaddingMode::PKCS7> ChunkedDataPadManager;

		switch (executeMode)
		{
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				auto dataBlockCopy { dataBlock };

				//Padding Data #5 standard
				
				ChunkedDataPadManager.Pad(dataBlockCopy, 16);

				if(dataBlockCopy.size() % 4 != 0)
				{
					throw std::logic_error("CommonSecurity::RC6::RC6_Executor::Encryption: The size of the input data must be a multiple of four to ensure that the output data is properly sized!\nOperation failed, and the size of the padded data may have been miscalculated?");
				}

				auto processedDataBlock = RC6_Worker.EncryptionECB(dataBlockCopy, key);

				return processedDataBlock;

				//break;
			}
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				auto dataBlockCopy { dataBlock };
				auto processedDataBlock = RC6_Worker.DecryptionECB(dataBlockCopy, key);

				//Unpadding Data #5 standard

				ChunkedDataPadManager.Unpad(processedDataBlock, 16);

				return processedDataBlock;

				//break;
			}
			default:
			{
				std::cout << "Wrong RC6 DataWorker worker is selected" << std::endl;
				abort();
			}	
		}
	}
}

namespace CommonSecurity::ChinaShangYongMiMa4
{
	using ProcedureFunctions::ExperimentalAlgorithm;
	using ProcedureFunctions::OfficialAlgorithm;

	class DataWorker
	{
	
	private:

		OfficialAlgorithm AlgorithmObject;

	public:

		/**
		* Encrypt input plain text with an SM4 key in ECB Mode.
		*
		* @param data; Plain text to encrypt.
		* @param key; SM4 encryption key.
		* @return Encryption result like as executed this function.
		*/
		void EncryptionWithECB
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}

				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(ProcessedDataByteSpan);
			}
		}

		/**
		* Decrypt input cipher text with an SM4 key in ECB Mode.
		*
		* @param data; Cipher text to decrypt.
		* @param key; SM4 encryption key.
		* @return Decryption result like as executed this function.
		*/
		void DecryptionWithECB
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}

				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(ProcessedDataByteSpan);
			}
		}

		/**
		* Encrypt input plain text with an SM4 key in CBC Mode.
		*
		* @param data; Plain text to encrypt.
		* @param initial_vector; Initial randomized data
		* @param key; SM4 encryption key.
		* @return Encryption result like as executed this function.
		*/
		void EncryptionWithCBC
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			const std::span<const std::uint8_t> InitialVector,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				InitialVector.size() == AlgorithmObject.Number_Block_Data_Byte_Size,
				"ChinaShangYongMiMa4::DataWorker: The data size of this initial vector is not 16!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			std::vector<std::uint8_t> ProcessingInitialVector { InitialVector.begin(), InitialVector.end() };

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());

				//The plain-text do associative initial vector data
				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessedDataByteSpan[InitialVectorIndex] ^= ProcessingInitialVector[InitialVectorIndex];
				}

				//The data that needs cipher-text data should be associated with the initial vector data using the block cipher encryption function
				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(ProcessedDataByteSpan);

				//The inital vector data copy from cipher-text data
				std::ranges::copy(ProcessedDataByteSpan.begin(), ProcessedDataByteSpan.end(), ProcessingInitialVector.begin());
			}
		}

		/**
		* Decrypt input cipher text with an SM4 key in CBC Mode.
		*
		* @param data; Cipher text to decrypt.
		* @param initial_vector; Initial randomized data
		* @param key; SM4 encryption key.
		* @return Decryption result like as executed this function.
		*/
		void DecryptionWithCBC
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			const std::span<const std::uint8_t> InitialVector,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				InitialVector.size() == AlgorithmObject.Number_Block_Data_Byte_Size,
				"ChinaShangYongMiMa4::DataWorker: The data size of this initial vector is not 16!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			std::vector<std::uint8_t> ProcessingInitialVector { InitialVector.begin(), InitialVector.end() };

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());

				//The data that needs to be associated with the initial vector data should be cipher-text data using the block cipher decryption function
				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(ProcessedDataByteSpan);

				//Initial vector undo associative to plain-text data
				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessedDataByteSpan[InitialVectorIndex] ^= ProcessingInitialVector[InitialVectorIndex];
				}

				//The cipher-text data copy to inital vector data
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessingInitialVector.begin());
			}
		}

		/**
		* Encrypt input plain text with an SM4 key in PCBC Mode.
		*
		* @param data; Plain text to encrypt.
		* @param initial_vector; Initial randomized data
		* @param key; SM4 encryption key.
		* @return Encryption result like as executed this function.
		*/
		void EncryptionWithPCBC
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			const std::span<const std::uint8_t> InitialVector,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				InitialVector.size() == AlgorithmObject.Number_Block_Data_Byte_Size,
				"ChinaShangYongMiMa4::DataWorker: The data size of this initial vector is not 16!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			std::vector<std::uint8_t> ProcessingInitialVector { InitialVector.begin(), InitialVector.end() };

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());

				//Initial vector data do associative from plain-text data
				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessedDataByteSpan[InitialVectorIndex] ^= ProcessingInitialVector[InitialVectorIndex];
				}

				//The cipher-text, since initial vector of associated data using the block cipher encryption function
				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(ProcessedDataByteSpan);

				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessingInitialVector[InitialVectorIndex] = ProcessedDataByteSpan[InitialVectorIndex] ^ DataByteSpan[InitialVectorIndex];
				}
			}
		}

		/**
		* Decrypt input cipher text with an SM4 key in PCBC Mode.
		*
		* @param data; Cipher text to decrypt.
		* @param initial_vector; Initial randomized data
		* @param key; SM4 encryption key.
		* @return Decryption result like as executed this function.
		*/
		void DecryptionWithPCBC
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			const std::span<const std::uint8_t> InitialVector,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				InitialVector.size() == AlgorithmObject.Number_Block_Data_Byte_Size,
				"ChinaShangYongMiMa4::DataWorker: The data size of this initial vector is not 16!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			std::vector<std::uint8_t> ProcessingInitialVector { InitialVector.begin(), InitialVector.end() };

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());

				//The initial vector of associated data, since cipher-text using the block cipher decryption function
				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER>(ProcessedDataByteSpan);

				//Initial vector undo associative to plain-text data
				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessedDataByteSpan[InitialVectorIndex] ^= ProcessingInitialVector[InitialVectorIndex];
				}

				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessingInitialVector[InitialVectorIndex] = ProcessedDataByteSpan[InitialVectorIndex] ^ DataByteSpan[InitialVectorIndex];
				}
			}
		}

		/**
		* Encrypt input plain text with an SM4 key in CFB Mode.
		*
		* @param data; Plain text to encrypt.
		* @param initial_vector; Initial randomized data
		* @param key; SM4 encryption key.
		* @return Encryption result like as executed this function.
		*/
		void EncryptionWithCFB
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			const std::span<const std::uint8_t> InitialVector,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				InitialVector.size() == AlgorithmObject.Number_Block_Data_Byte_Size,
				"ChinaShangYongMiMa4::DataWorker: The data size of this initial vector is not 16!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			std::vector<std::uint8_t> ProcessingInitialVector { InitialVector.begin(), InitialVector.end() };

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());

				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(ProcessingInitialVector);

				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessedDataByteSpan[InitialVectorIndex] ^= ProcessingInitialVector[InitialVectorIndex];
				}

				std::ranges::copy(ProcessedDataByteSpan.begin(), ProcessedDataByteSpan.end(), ProcessingInitialVector.begin());
			}
		}

		/**
		* Decrypt input cipher text with an SM4 key in CFB Mode.
		*
		* @param data; Cipher text to decrypt.
		* @param initial_vector; Initial randomized data
		* @param key; SM4 encryption key.
		* @return Decryption result like as executed this function.
		*/
		void DecryptionWithCFB
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			const std::span<const std::uint8_t> InitialVector,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				InitialVector.size() == AlgorithmObject.Number_Block_Data_Byte_Size,
				"ChinaShangYongMiMa4::DataWorker: The data size of this initial vector is not 16!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			std::vector<std::uint8_t> ProcessingInitialVector { InitialVector.begin(), InitialVector.end() };

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());

				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(ProcessingInitialVector);

				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessedDataByteSpan[InitialVectorIndex] ^= ProcessingInitialVector[InitialVectorIndex];
				}

				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessingInitialVector.begin());
			}
		}

		/**
		* Encrypt input plain text with an SM4 key in OFB Mode.
		*
		* @param data; Plain text to encrypt.
		* @param initial_vector; Initial randomized data
		* @param key; SM4 encryption key.
		* @return Encryption result like as executed this function.
		*/
		void EncryptionWithOFB
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			const std::span<const std::uint8_t> InitialVector,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				InitialVector.size() == AlgorithmObject.Number_Block_Data_Byte_Size,
				"ChinaShangYongMiMa4::DataWorker: The data size of this initial vector is not 16!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			std::vector<std::uint8_t> ProcessingInitialVector { InitialVector.begin(), InitialVector.end() };

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());

				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(ProcessingInitialVector);

				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessedDataByteSpan[InitialVectorIndex] = DataByteSpan[InitialVectorIndex] ^ ProcessingInitialVector[InitialVectorIndex];
				}
			}
		}

		/**
		* Decrypt input cipher text with an SM4 key in OFB Mode.
		*
		* @param data; Cipher text to decrypt.
		* @param initial_vector; Initial randomized data
		* @param key; SM4 encryption key.
		* @return Decryption result like as executed this function.
		*/
		void DecryptionWithOFB
		(
			const std::span<const std::uint8_t> Data,
			const std::span<const std::uint8_t> Keys,
			const std::span<const std::uint8_t> InitialVector,
			std::span<std::uint8_t> ProcessedData
		)
		{
			my_cpp2020_assert
			(
				Data.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0 && Data.size() == ProcessedData.size(),
				"ChinaShangYongMiMa4::DataWorker: This source data size is not a multiple of 16, or the destination data size is not the same as the source data size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				InitialVector.size() == AlgorithmObject.Number_Block_Data_Byte_Size,
				"ChinaShangYongMiMa4::DataWorker: The data size of this initial vector is not 16!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				Keys.size() % AlgorithmObject.Number_Block_Data_Byte_Size == 0,
				"ChinaShangYongMiMa4::DataWorker: This key data size is not a multiple of 16!",
				std::source_location::current()
			);

			std::vector<std::uint8_t> ProcessingInitialVector { InitialVector.begin(), InitialVector.end() };

			for(std::size_t DataIndex = 0, KeyIndex = 0; DataIndex < Data.size(); DataIndex += AlgorithmObject.Number_Block_Data_Byte_Size)
			{
				std::span<const std::uint8_t> DataByteSpan { Data.begin() + DataIndex, Data.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::span<std::uint8_t> ProcessedDataByteSpan { ProcessedData.begin() + DataIndex, ProcessedData.begin() + DataIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				std::ranges::copy(DataByteSpan.begin(), DataByteSpan.end(), ProcessedDataByteSpan.begin());

				std::span<const std::uint8_t> KeyByteSpan { Keys.begin() + KeyIndex, Keys.begin() + KeyIndex + AlgorithmObject.Number_Block_Data_Byte_Size };
				AlgorithmObject.KeyExpansion(KeyByteSpan);
				KeyIndex += AlgorithmObject.Number_Block_Data_Byte_Size;

				if(Keys.begin() + KeyIndex >= Keys.end())
				{
					KeyIndex = 0;
				}
				AlgorithmObject.RoundFunction<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER>(ProcessingInitialVector);

				for(std::size_t InitialVectorIndex = 0; InitialVectorIndex < AlgorithmObject.Number_Block_Data_Byte_Size; ++InitialVectorIndex)
				{
					ProcessedDataByteSpan[InitialVectorIndex] = DataByteSpan[InitialVectorIndex] ^ ProcessingInitialVector[InitialVectorIndex];
				}
			}
		}

		DataWorker() = default;

		~DataWorker() = default;

	};
}

/*
	https://en.wikipedia.org/wiki/Twofish
	
	Reference code:
	https://github.dev/mycielski/twofish-in-java
	https://github.dev/Incr3dible/Twofish/blob/master/src/Twofish/DWord.cs
	https://github.dev/Incr3dible/Twofish/blob/master/src/Twofish/TwofishImplementation.cs
	https://www.schneier.com/
*/
namespace CommonSecurity::Twofish
{
	#if __cplusplus >= 202002L
	
	#define	TWOFISH_BIT_ROTATE_LEFT(word, n) ( std::rotl(word, n) )
	#define	TWOFISH_BIT_ROTATE_RIGHT(word, n) ( std::rotr(word, n) )

	#elif __cplusplus >= 201103L

	#define	TWOFISH_BIT_ROTATE_LEFT(word, n) ( CommonSecurity::Binary_LeftRotateMove(word, n) )
	#define	TWOFISH_BIT_ROTATE_RIGHT(word, n) ( CommonSecurity::Binary_RightRotateMove(word, n) )

	#else

	#define TWOFISH_BIT_ROTATE_LEFT(word, n) ( ( ( word ) << ( ( n ) & 0x1F ) ) | ( ( word ) >> ( 32 - ( ( n ) & 0x1F ) ) ) )
	#define TWOFISH_BIT_ROTATE_RIGHT(word, n) ( ( ( word ) >> ( ( n ) & 0x1F ) ) | ( ( word ) << ( 32 - ( ( n ) & 0x1F ) ) ) )

	#endif

	#if __cplusplus >= 202002L

	inline constexpr bool CHECK_IS_BIG_ENDIAN_ORDER = std::endian::native == std::endian::big;

		#if CHECK_IS_BIG_ENDIAN_ORDER == false
			#define		TWOFISH_IS_LITTLE_ENDIAN_MACHINES true
		#else
			#define		TWOFISH_IS_LITTLE_ENDIAN_MACHINES false
		#endif

	#else

		#ifndef _M_IX86
			#ifdef	__BORLANDC__
			#define	_M_IX86	300		/* make sure this is defined for Intel CPUs */
			#endif
		#endif

		#if defined(__i386__) || defined(_M_IX86) || defined(_M_IX64)
			#define		TWOFISH_IS_LITTLE_ENDIAN_MACHINES true /* e.g., 1 for Pentium, 0 for 68K */
			#define		TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32	0 /* need dword alignment? (no for Pentium) */
		#else	/* non-Intel platforms */
			#define		TWOFISH_IS_LITTLE_ENDIAN_MACHINES false /* (assume big-endian machines) */
			#define		TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32	1 /* (assume need alignment for non-Intel) */
		#endif

	#endif

	#if TWOFISH_IS_LITTLE_ENDIAN_MACHINES
		#define		TWOFISH_BYTE_SWAP(word) (word) /* NOP for little-endian machines */
		#define		TWOFISH_ADDRESS_XOR 0 /* NOP for little-endian machines */
	#else
		#define		TWOFISH_BYTE_SWAP(word) ((TWOFISH_BIT_ROTATE_RIGHT(word, 8) & 0xFF00FF00) | (TWOFISH_BIT_ROTATE_LEFT(word, 8) & 0x00FF00FF))
		#define		TWOFISH_ADDRESS_XOR 3 /* convert byte address in dword */
	#endif
	
	/* nonzero --> use Feistel version (slow) */
	#define TWOFISH_FEISTEL_DESIGN_ARCHITECTURE_VERSION 0

	using ClassicByte = std::uint8_t;
	using DoubleWord = std::uint32_t;
	
	/* class Initialization signature ('FISH') */
	inline constexpr std::uint32_t ValidInstanceFlag = 0x48534946U;
	inline constexpr std::uint32_t InitialVectorByteSize = 16U;
	
	enum class DataProcessingMode : std::uint8_t
	{
		/* Are we ciphering in ECB mode? */
		ECB = 0,

		/* Are we ciphering in CBC mode? */
		CBC = 1,

		/* Are we ciphering in PCBC mode? */
		PCBC = 2,

		/* Are we ciphering in 1-bit CFB mode? */
		CFB = 3,

		/* Are we ciphering in OFB mode? */
		OFB = 4
	};

	/*
	+*****************************************************************************
	*
	* Function Name:	HexadecimalClassicBytesToDoubleWord
	*
	* Function:			Parse ASCII hexadecimal nibbles and fill in key/iv double-words
	*
	* Arguments:		bits_size			=	# bits to read
	*					source_context		=	ASCII source
	*					destination_context	=	where to make a copy of ASCII source
	*					dw_pointer			=	pointer to double-words to fill
	*
	* Return:			bool Success or failure
	*
	* Notes:  Note that the parameter d is a DWORD array, not a byte array.
	*	This routine is coded to work both for little-endian and big-endian architectures.
	*   The character stream is interpreted as a LITTLE-ENDIAN byte stream,
	*   since that is how the Pentium works, but the conversion happens automatically below. 
	*
	+***************************************************************************
	*/
	inline bool HexadecimalClassicBytesToDoubleWord(std::uint32_t bits_size, const std::int8_t* source_context, std::int8_t* destination_context, DoubleWord* dw_pointer)
	{
		if(source_context == nullptr)
			return false;

		if(dw_pointer == nullptr)
			return false;

		std::uint32_t index = 0;
		DoubleWord word_bytes = 0;
		std::int8_t character = 0;
		#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
		/* keep dword alignment */
		std::int8_t align_dummy[3] {0, 0, 0};
		#endif

		/* Make sure LittleEndian is defined correctly */
		ClassicByte test_endian_bytes[ 4U ] { 0,0,0,0 };
		const DoubleWord test_endian_word = 1U;

		std::memmove(&test_endian_bytes[0], &test_endian_word, sizeof(DoubleWord));

		/* Sanity check on compile-time switch */
		if(test_endian_bytes[0 ^ TWOFISH_ADDRESS_XOR] != 1)
			return false;

		#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
		if( ( (std::int32_t)destination_context ) & 3 )
			return false;
		#endif

		for( index = 0; index * std::numeric_limits<DoubleWord>::digits < bits_size; ++index)
		{
			dw_pointer[index] = 0U;
		}

		/* Parse one nibble at a time */
		for(index = 0; index * sizeof(DoubleWord) < bits_size; index++)
		{
			character = source_context[index];

			if(destination_context != nullptr)
				destination_context[index] = character;

			if ( ( character >= '0' ) && ( character <= '9' ) )
				word_bytes = character - '0';
			else if ( ( character >= 'a' ) && ( character <= 'f' ) )
				word_bytes = character - 'a' + 10;
			else if ( ( character >= 'A' ) && ( character <= 'F' ) )
				word_bytes = character - 'A' + 10;
			else if( character == 0 )
				break;
			else
				/* invalid hexadecimal character */
				return false;
			
			/* works for big and little endian! */
			dw_pointer[ index / std::numeric_limits<std::uint8_t>::digits ] |= word_bytes << ( sizeof(DoubleWord) * ( ( index ^ 1 ) & 7 ) );
		}

		return true;
	}

	class Algorithm
	{

	private:

		friend struct TwofishUnitTest;
		friend class DataWorker;

		static DoubleWord H_Function(DoubleWord data, const DoubleWord* key_32_bit_data, std::uint32_t key_bit_size)
		{
			auto lambda_extracting_bytes = [](const DoubleWord& word_data, std::uint32_t byte_index) -> ClassicByte
			{
				const ClassicByte* byte_pointer = reinterpret_cast<const ClassicByte*>(&word_data);
				return byte_pointer[(byte_index & sizeof(std::uint32_t) - 1) ^ TWOFISH_ADDRESS_XOR];
			};

			using CommonSecurity::Twofish::DefineConstants::PSB_Matrix_Fixed;

			/*
				Define the fixed p0/p1 permutations used in keyed S-box lookup.  
				By changing the following constant definitions for P_ij,
				the S-boxes will automatically get changed in all the Twofish source code.
				Note that P_i0 is the "outermost" 8x8 permutation applied. 
				See the f32() function : ProcessFunction32Bit, to see how these constants are to be used.
			*/

			constexpr std::uint8_t PermuteIndex_00 = 1U; /* "outermost" permutation */
			constexpr std::uint8_t PermuteIndex_01 = 0U; 
			constexpr std::uint8_t PermuteIndex_02 = 0U;
			constexpr std::uint8_t PermuteIndex_03 = PermuteIndex_01 ^ 1U;
			constexpr std::uint8_t PermuteIndex_04 = 1U;

			constexpr std::uint8_t PermuteIndex_10 = 0U;
			constexpr std::uint8_t PermuteIndex_11 = 0U;
			constexpr std::uint8_t PermuteIndex_12 = 1U;
			constexpr std::uint8_t PermuteIndex_13 = PermuteIndex_11 ^ 1U;
			constexpr std::uint8_t PermuteIndex_14 = 0U;

			constexpr std::uint8_t PermuteIndex_20 = 1U;
			constexpr std::uint8_t PermuteIndex_21 = 1U;
			constexpr std::uint8_t PermuteIndex_22 = 0U;
			constexpr std::uint8_t PermuteIndex_23 = PermuteIndex_21 ^ 1U;
			constexpr std::uint8_t PermuteIndex_24 = 0U;

			constexpr std::uint8_t PermuteIndex_30 = 0U;
			constexpr std::uint8_t PermuteIndex_31 = 1U;
			constexpr std::uint8_t PermuteIndex_32 = 1U;
			constexpr std::uint8_t PermuteIndex_33 = PermuteIndex_31 ^ 1U;
			constexpr std::uint8_t PermuteIndex_34 = 1U;

			/* Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. */
			/* Note that each byte goes through a different combination of S-boxes.*/

			#if __cplusplus
			std::array<ClassicByte, 4U> state_bytes_data { 0, 0, 0, 0 };
			#else
			ClassicByte state_bytes_data[4] = { 0 };
			#endif

			/* make state_bytes_data[0] = LSB, state_bytes_data[3] = MSB */
			DoubleWord& word_data_reference = *( reinterpret_cast<DoubleWord*>( state_bytes_data.data() ) );
			word_data_reference = TWOFISH_BYTE_SWAP(data);
			
			//由于不需要设置break语句，switch分支语句继续执行
			//Since there is no need to set a break statement, the switch branch statement continues to be executed
			switch ( ( (key_bit_size + 63) / 64 ) & 3 )
			{
				/* 256 bits of key */
				case 0:
				{
					state_bytes_data[0] = PSB_Matrix_Fixed[PermuteIndex_04][state_bytes_data[0]] ^ lambda_extracting_bytes(key_32_bit_data[3], 0U);
					state_bytes_data[1] = PSB_Matrix_Fixed[PermuteIndex_14][state_bytes_data[1]] ^ lambda_extracting_bytes(key_32_bit_data[3], 1U);
					state_bytes_data[2] = PSB_Matrix_Fixed[PermuteIndex_24][state_bytes_data[2]] ^ lambda_extracting_bytes(key_32_bit_data[3], 2U);
					state_bytes_data[3] = PSB_Matrix_Fixed[PermuteIndex_34][state_bytes_data[3]] ^ lambda_extracting_bytes(key_32_bit_data[3], 3U);
				}
				/* having pre-processed bytes[0]..bytes[3] with k32[3] */
				
				/* 192 bits of key */
				case 3:
				{
					state_bytes_data[0] = PSB_Matrix_Fixed[PermuteIndex_03][state_bytes_data[0]] ^ lambda_extracting_bytes(key_32_bit_data[2], 0U);
					state_bytes_data[1] = PSB_Matrix_Fixed[PermuteIndex_13][state_bytes_data[1]] ^ lambda_extracting_bytes(key_32_bit_data[2], 1U);
					state_bytes_data[2] = PSB_Matrix_Fixed[PermuteIndex_23][state_bytes_data[2]] ^ lambda_extracting_bytes(key_32_bit_data[2], 2U);
					state_bytes_data[3] = PSB_Matrix_Fixed[PermuteIndex_33][state_bytes_data[3]] ^ lambda_extracting_bytes(key_32_bit_data[2], 3U);
				}
				/* having pre-processed bytes[0]..bytes[3] with k32[2] */
				
				/* 128 bits of key */
				case 2:
				{
					state_bytes_data[0] = PSB_Matrix_Fixed[PermuteIndex_00][ PSB_Matrix_Fixed[PermuteIndex_01][ PSB_Matrix_Fixed[PermuteIndex_02][state_bytes_data[0]] ^ lambda_extracting_bytes(key_32_bit_data[1], 0U) ] ^ lambda_extracting_bytes(key_32_bit_data[0], 0U) ];
					state_bytes_data[1] = PSB_Matrix_Fixed[PermuteIndex_10][ PSB_Matrix_Fixed[PermuteIndex_11][ PSB_Matrix_Fixed[PermuteIndex_12][state_bytes_data[1]] ^ lambda_extracting_bytes(key_32_bit_data[1], 1U) ] ^ lambda_extracting_bytes(key_32_bit_data[0], 1U) ];
					state_bytes_data[2] = PSB_Matrix_Fixed[PermuteIndex_20][ PSB_Matrix_Fixed[PermuteIndex_21][ PSB_Matrix_Fixed[PermuteIndex_22][state_bytes_data[2]] ^ lambda_extracting_bytes(key_32_bit_data[1], 2U) ] ^ lambda_extracting_bytes(key_32_bit_data[0], 2U) ];
					state_bytes_data[3] = PSB_Matrix_Fixed[PermuteIndex_30][ PSB_Matrix_Fixed[PermuteIndex_31][ PSB_Matrix_Fixed[PermuteIndex_32][state_bytes_data[3]] ^ lambda_extracting_bytes(key_32_bit_data[1], 3U) ] ^ lambda_extracting_bytes(key_32_bit_data[0], 3U) ];
				}
				/* having pre-processed bytes[0]..bytes[3] with k32[1] xor k32[0] */

				word_data_reference = *(reinterpret_cast<DoubleWord*>(state_bytes_data.data()));
				return word_data_reference;
			}
		}

		/*
		+*****************************************************************************
		*
		* Function Name:	ReedSolomon (Encode)
		*
		* Function:			Use (12,8) Reed-Solomon code over GF(256) to produce a key S-box dword from two key material dwords.
		*
		* Arguments:		key0	=	1st dword
		*					key1	=	2nd dword
		*
		* Return:			Remainder polynomial generated using RS code
		*
		* Notes:
		*	Since this computation is done only once per reKey per 64 bits of key,
		*	the performance impact of this routine is imperceptible.
		*	The RS code chosen has "simple" coefficients to allow smartcard/hardware implementation without lookup tables.
		*
		+***************************************************************************
		*/
		static DoubleWord ReedSolomon(DoubleWord key_data0, DoubleWord key_data1)
		{
			using CommonSecurity::Twofish::DefineConstants::BinaryFeedbackFormulaB;
			
			DoubleWord result_word_data;

			for (std::uint8_t i=result_word_data=0; i<2; i++)
			{
				/* Merge in 32 more key bits */
				result_word_data ^= (i) ? key_data0 : key_data1;

				/* Shift one byte at a time */
				for (std::uint8_t j=0; j<4; j++)				
				{
					//Reed-Solomon_rem
					ClassicByte current_byte = (ClassicByte) (result_word_data >> 24);									 
					DoubleWord g2 = ((current_byte << 1) ^ ((current_byte & 0x80) ? BinaryFeedbackFormulaB : 0 )) & 0xFF;		
					DoubleWord g3 = ((current_byte >> 1) & 0x7F) ^ ((current_byte & 1) ? BinaryFeedbackFormulaB >> 1 : 0 ) ^ g2 ;
					result_word_data = (result_word_data << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ current_byte;
				}
			}
			return result_word_data;
		}

		/*
		+*****************************************************************************
		*
		* Function Name:	f32
		*
		* Function:			Run four bytes through keyed S-boxes and apply MDS matrix
		*
		* Arguments:		data = input to f function
		*					key_32_bit_data	= pointer to key dwords
		*					key_bit_size = total key length (key_32_bit_data --> key_bit_size / 2 bits)
		*
		* Return:			The output of the keyed permutation applied to x.
		*
		* Notes:
		*   This function is a keyed 32-bit permutation.
		*   It is the major building block for the Twofish round function,
		*   including the four keyed 8x8 permutations and the 4x4 MDS matrix multiply.
		*   This function is used both for generating round subkeys and within the round function on the block being encrypted.  
		*
		*	This version is fairly slow and pedagogical,
		*   although a smartcard would probably perform the operation exactly this way in firmware.
		*   For ultimate performance, the entire operation can be completed with four lookups into four 256x32-bit tables, with three dword xors.
		*
		*	The MDS matrix is defined in CommonSecurity::Twofish::DefineConstants::MAXIMUM_DISATANCE_SEPARABLE_MATRIX.
		*
		+***************************************************************************
		*/
		static DoubleWord ProcessFunction32Bit(DoubleWord data, const DoubleWord* key_32_bit_data, std::uint32_t key_bit_size)
		{
			auto& MDS = CommonSecurity::Twofish::DefineConstants::MAXIMUM_DISATANCE_SEPARABLE_MATRIX;

			auto lambda_extracting_bytes = [](const DoubleWord& word_data, std::uint32_t byte_index)	-> DoubleWord
			{
				return static_cast<DoubleWord>( static_cast<ClassicByte>(word_data >> (std::numeric_limits<ClassicByte>::digits * byte_index)) );
			};

			auto word_data = H_Function(data, key_32_bit_data, key_bit_size);

			return MDS[0][lambda_extracting_bytes(word_data, 0U)]
			^ MDS[1][lambda_extracting_bytes(word_data, 1U)]
			^ MDS[2][lambda_extracting_bytes(word_data, 2U)]
			^ MDS[3][lambda_extracting_bytes(word_data, 3U)];
		}

		struct KeyInstance
		{
			
		public:
			
		#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
			/* keep 32-bit alignment */
			ClassicByte DummyAlign[3] = {0, 0, 0};
		#endif
			/* Length of the key */
			std::uint32_t ByteKeyBitSize = 0;

		#if __cplusplus
			std::array<ClassicByte, CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize / sizeof(DoubleWord) + 4> ByteKeyMaterial
			{ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
		#else
			ClassicByte ByteKeyMaterial[68] = { 0 };
		#endif

			/* Twofish-specific parameters: */

			/* set to VALID_SIG by MakeKey() */
			std::uint32_t KeySign = 0U;

			/* number of rounds in cipher */
			std::int32_t NumberRounds = 0U;

		#if __cplusplus
			/* Actual key bits, in dwords */
			std::array<DoubleWord, CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize / std::numeric_limits<std::uint32_t>::digits> CipherKey32Bit {};
		#else
			DoubleWord CipherKey32Bit[8] = { 0 };
		#endif

		#if __cplusplus
			/* Key bits used for S-boxes */
			std::array<DoubleWord, CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize / std::numeric_limits<std::uint64_t>::digits> SubstituteBoxKeys {};
		#else
			DoubleWord SubstituteBoxKeys[4] = { 0 };
		#endif

		#if __cplusplus
			/* Round subkeys, input/output whitening bits */
			std::array<DoubleWord, CommonSecurity::Twofish::DefineConstants::Constant_TotalSubkeys> SubKeys {};
		#else
			DoubleWord SubKeys[72] = { 0 };
		#endif
			
			/*
			* Function:			Initialize the Twofish key schedule from key32
			*
			* Arguments:		ThisInstance = Reference Algorithm object to be initialized
			*
			* Return:			void
			*
			* Notes:
			*	Here we precompute all the round subkeys, although that is not actually required. 
			*	For example, on a smartcard, the round subkeys can be generated on-the-fly using f32()
			*/
			void KeySchedule(const std::uint32_t byte_key_bit_size)
			{
				using CommonSecurity::Twofish::DefineConstants::Constant_SubkeyRounds;
				using CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize;
				using CommonSecurity::Twofish::DefineConstants::Constant_SubkeysStep;
				using CommonSecurity::Twofish::DefineConstants::Constant_SubkeysBump;
				using CommonSecurity::Twofish::DefineConstants::Constant_SubkeyRotateLeft;
				using CommonSecurity::Twofish::DefineConstants::Constant_TotalSubkeys;
				
				if( this->KeySign != ValidInstanceFlag )
					return;

				const std::uint32_t key_64_bit_count = ( byte_key_bit_size + 63 ) / 64;
				const std::uint32_t subkey_count = Constant_SubkeyRounds + 2 * this->NumberRounds;

				if(subkey_count > Constant_TotalSubkeys)
					return; //The subkeys size for this key instance reference is invalid

				DoubleWord A = 0U, B = 0U;

				/* even/odd key dwords */
				DoubleWord key_32_bit_even[ Constant_MaxKeySize / 64 ], key_32_bit_odd[ Constant_MaxKeySize / 64 ];

				for ( std::uint32_t keys_index = 0; keys_index < key_64_bit_count; keys_index++ )
				{
					/* split into even/odd key dwords */
					key_32_bit_even[ keys_index ] = this->CipherKey32Bit[ 2 * keys_index ];
					key_32_bit_odd[ keys_index ] = this->CipherKey32Bit[ 2 * keys_index + 1 ];

					/* compute S-box keys using (12,8) Reed-Solomon code over GF(256) */
					/* reverse order */
					this->SubstituteBoxKeys[ key_64_bit_count - 1 - keys_index ] = Algorithm::ReedSolomon( key_32_bit_even[ keys_index ], key_32_bit_odd[ keys_index ] );
				}

				/* Compute round subkeys for Pseudo-Hadamard Transform  */
				for ( std::uint32_t subkeys_index = 0; subkeys_index < subkey_count / 2; subkeys_index++ )
				{
					/* A uses even key dwords */
					A = Algorithm::ProcessFunction32Bit( subkeys_index * Constant_SubkeysStep, key_32_bit_even, byte_key_bit_size );
					/* B uses odd  key dwords */
					B = Algorithm::ProcessFunction32Bit( subkeys_index * Constant_SubkeysStep + Constant_SubkeysBump, key_32_bit_odd, byte_key_bit_size );
					B = TWOFISH_BIT_ROTATE_LEFT( B, 8 );

					/* combine with a Pseudo-Hadamard Transform */
					this->SubKeys[ 2 * subkeys_index ] = A + B;
					this->SubKeys[ 2 * subkeys_index + 1 ] = TWOFISH_BIT_ROTATE_LEFT( A + 2 * B, Constant_SubkeyRotateLeft );
				}
			}

			/*
			+*****************************************************************************
			*
			* Function Name:	MakeKey
			*
			* Function:			Initialize the Twofish key schedule
			*
			* Arguments:		worker_mode			= Enum class type instance of the PasscoderWorkMode
			*					byte_key_bit_size	= # bits size of key text at *byte_key_material
			*					byte_key_material	= pointer to hex ASCII chars representing key bits
			*
			* Return:			true or false
			*
			* Notes:
			*   This parses the key bits from classicByteKeyMaterial.
			*   No crypto stuff happens here.
			*   The function KeySchedule() is called to actually build the key schedule after the byte_key_material has been parsed.
			*
			+***************************************************************************
			*/
			bool MakeKey(std::uint32_t byte_key_bit_size, const std::int8_t* byte_key_material)
			{
				using CommonSecurity::Twofish::DefineConstants::Constant_MinCipherRounds;
				using CommonSecurity::Twofish::DefineConstants::Constant_MaxCipherRounds;
				using CommonSecurity::Twofish::DefineConstants::Constant_MinKeySize;
				using CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize;
				
				if( this == nullptr)
					return false; //Invalid key instance reference
				if( (byte_key_bit_size > Constant_MaxKeySize) || (byte_key_bit_size < Constant_MinKeySize) || ((byte_key_bit_size & std::numeric_limits<std::uint64_t>::digits - 1) != 0) )
					return false; //The byte key bit size for this key instance reference is invalid
				if( (byte_key_material == nullptr) || (byte_key_material[ 0 ] == 0) )
					return false; //The pointer to the byte_key_material parameter can be a null pointer or a zero data byte

			#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
				if ((((std::int32_t)this) & 3) || ((std::int32_t)(&this->CipherKey32Bit[0])) & 3)
					return;
			#endif

				this->ByteKeyBitSize = byte_key_bit_size;

				/* Cipher round */
				this->NumberRounds = byte_key_bit_size / std::numeric_limits<std::uint8_t>::digits;

				if constexpr(false)
				{
					/* Terminate ASCII string */
					this->ByteKeyMaterial[ Constant_MaxKeySize / sizeof(DoubleWord) ] = 0U;

					if (!HexadecimalClassicBytesToDoubleWord(byte_key_bit_size, byte_key_material, (std::int8_t*)(&this->ByteKeyMaterial[0]), &this->CipherKey32Bit[0]))
						return false;
				}
				else
				{
					std::span<const std::int8_t> classic_byte_span( byte_key_material, byte_key_material + (byte_key_bit_size / std::numeric_limits<std::uint8_t>::digits) );
					for(std::uint32_t index = 0; index < (byte_key_bit_size / std::numeric_limits<std::uint8_t>::digits); ++index)
						this->ByteKeyMaterial[index] = static_cast<ClassicByte>(classic_byte_span[index]);

					CommonToolkit::MessagePacking<DoubleWord, ClassicByte>({this->ByteKeyMaterial.data(), byte_key_bit_size / std::numeric_limits<std::uint8_t>::digits}, this->CipherKey32Bit.data());
				}

				if(this->KeySign == 0U)
					this->KeySign = ValidInstanceFlag;

				/* Generate round subkeys */
				this->KeySchedule(byte_key_bit_size);

				return true;
			}

			bool MakeKey(std::uint32_t byte_key_bit_size, const std::uint8_t* byte_key_material)
			{
				using CommonSecurity::Twofish::DefineConstants::Constant_MinCipherRounds;
				using CommonSecurity::Twofish::DefineConstants::Constant_MaxCipherRounds;
				using CommonSecurity::Twofish::DefineConstants::Constant_MinKeySize;
				using CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize;

				if( this == nullptr)
					return false; //Invalid key instance reference
				if( (byte_key_bit_size > Constant_MaxKeySize) || (byte_key_bit_size < Constant_MinKeySize) || ((byte_key_bit_size & std::numeric_limits<std::uint64_t>::digits - 1) != 0) )
					return false; //The bit size of the material for this key instance is invalid
				if( (byte_key_material == nullptr) || (byte_key_material[ 0 ] == 0) )
					return false; //The pointer to the byte_key_material parameter can be a null pointer or a zero data byte

			#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
				if ((((std::int32_t)this) & 3) || ((std::int32_t)(&this->CipherKey32Bit[0])) & 3)
					return;
			#endif

				this->ByteKeyBitSize = byte_key_bit_size;

				/* Cipher round */
				this->NumberRounds = byte_key_bit_size / std::numeric_limits<std::uint8_t>::digits;

				if constexpr(false)
				{
					/* Terminate ASCII string */
					this->ByteKeyMaterial[ Constant_MaxKeySize / sizeof(DoubleWord) ] = 0U;

					if (!HexadecimalClassicBytesToDoubleWord(byte_key_bit_size, (std::int8_t*)(byte_key_material), (std::int8_t*)(&this->ByteKeyMaterial[0]), &this->CipherKey32Bit[0]))
						return false;
				}
				else
				{
					std::span<const std::uint8_t> classic_byte_span( byte_key_material, byte_key_material + (byte_key_bit_size / std::numeric_limits<std::uint8_t>::digits) );
					std::memcpy(this->ByteKeyMaterial.data(), classic_byte_span.data(), classic_byte_span.size());

					CommonToolkit::MessagePacking<DoubleWord, ClassicByte>({this->ByteKeyMaterial.data(), byte_key_bit_size / std::numeric_limits<std::uint8_t>::digits}, this->CipherKey32Bit.data());
				}

				if(this->KeySign == 0U)
					this->KeySign = ValidInstanceFlag;

				/* Generate round subkeys */
				this->KeySchedule(byte_key_bit_size);

				return true;
			}

			~KeyInstance()
			{
				this->KeySign = 0U;
				memory_set_no_optimize_function<0x00>(&this->ByteKeyMaterial[0], std::size(this->ByteKeyMaterial));
				memory_set_no_optimize_function<0x00>(&this->CipherKey32Bit[0], std::size(this->CipherKey32Bit) * sizeof(DoubleWord));
				memory_set_no_optimize_function<0x00>(&this->SubstituteBoxKeys[0], std::size(this->SubstituteBoxKeys) * sizeof(DoubleWord));
				memory_set_no_optimize_function<0x00>(&this->SubKeys[0], std::size(this->SubKeys) * sizeof(DoubleWord));
			}
		};

		struct CipherInstance
		{
		
		public:
			
			DataProcessingMode DataMode;

		#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
			/* keep 32-bit alignment */
			ClassicByte DummyAlign[3] = {0, 0, 0};
		#endif

		#if __cplusplus
			std::array<ClassicByte, InitialVectorByteSize> ByteInitialVector;
		#else
			ClassicByte ByteInitialVector[16] = { 0 };
		#endif

			/* Twofish-specific parameters: */

			/* set to VALID_SIG by CipherInit() */
			std::uint32_t CipherSign = 0U;

		#if __cplusplus
			/* DataProcessingMode CBC INITIAL_VECTOR bytes arranged as dwords */
			std::array<DoubleWord, CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits> InitialVector32Bit;
		#else
			DoubleWord InitialVector32Bit[4] = { 0 };
		#endif

			/*
			+*****************************************************************************
			*
			* Function Name:	MakeCipher
			*
			* Function:			Initialize the Twofish cipher in a given mode
			*
			* Arguments:		data_mode				=	Enum class type instance of the DataProcessingMode
			*					initial_vector			=	pointer to hex ASCII test representing IV bytes
			*
			* Return:			void
			*
			+*****************************************************************************
			*/
			void MakeCipher(DataProcessingMode data_mode, const std::int8_t* initial_vector = nullptr)
			{
				using CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize;

				//Must have this cipher instance to initialized
				if(this == nullptr)
					return;

			#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
				if( ( ((std::int32_t)this) & 3 ) || ( ((std::int32_t)&this->ByteInitialVector[0]) & 3 ) || ( ((std::int32_t)&this->InitialVector32Bit[0]) & 3 ) )
					return;
			#endif
				
				if( ( data_mode != DataProcessingMode::ECB ) && ( initial_vector != nullptr ) )
				{
					if constexpr(false)
					{
						if( !HexadecimalClassicBytesToDoubleWord(Constant_DataBlockSize, initial_vector, nullptr, &this->InitialVector32Bit[0]) )
							return;
					}
					else
					{
						std::span<const std::int8_t> classic_byte_span( initial_vector, initial_vector + (Constant_DataBlockSize / std::numeric_limits<std::uint8_t>::digits) );
						for(std::uint32_t index = 0; index < (Constant_DataBlockSize / std::numeric_limits<std::uint8_t>::digits); ++index)
							this->ByteInitialVector[index] = static_cast<ClassicByte>(classic_byte_span[index]);

						CommonToolkit::MessagePacking<DoubleWord, ClassicByte>(this->ByteInitialVector, this->InitialVector32Bit.data());
					}
				}

				this->DataMode = data_mode;

				this->CipherSign = ValidInstanceFlag;
			}

			void MakeCipher(DataProcessingMode data_mode, const std::uint8_t* initial_vector = nullptr)
			{
				using CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize;

				if(this == nullptr)
					return; //Must have this cipher instance to initialized

			#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
				if( ( ((std::int32_t)this) & 3 ) || ( ((std::int32_t)&this->ByteInitialVector[0]) & 3 ) || ( ((std::int32_t)&this->InitialVector32Bit[0]) & 3 ) )
					return;
			#endif
				
				if( ( data_mode != DataProcessingMode::ECB ) && ( initial_vector != nullptr ) )
				{
					if constexpr(false)
					{
						if( !HexadecimalClassicBytesToDoubleWord(Constant_DataBlockSize, (std::int8_t*)initial_vector, nullptr, &this->InitialVector32Bit[0]) )
							return;
					}
					else
					{
						std::span<const std::uint8_t> classic_byte_span( initial_vector, initial_vector + (Constant_DataBlockSize / std::numeric_limits<std::uint8_t>::digits) );
						std::memcpy(this->ByteInitialVector.data(), classic_byte_span.data(), classic_byte_span.size());

						CommonToolkit::MessagePacking<DoubleWord, ClassicByte>(this->ByteInitialVector, this->InitialVector32Bit.data());
					}

					for(std::uint32_t index = 0; index < Constant_DataBlockSize / 32; ++index)
					{
						((DoubleWord*) (&this->ByteInitialVector[0]))[index] = TWOFISH_BYTE_SWAP(this->InitialVector32Bit[index]);
					}
				}

				this->DataMode = data_mode;

				this->CipherSign = ValidInstanceFlag;
			}

			/*
			+*****************************************************************************
			*
			* Function Name:	BlockEncryption (Key used for encrypting)
			*
			* Function:			Encrypt block(s) of data using Twofish
			*
			* Arguments:		processing_key_object	=	pointer to already initialized KeyInstance
			*					input_buffer		=	pointer to data blocks to be encrypted
			*					input_buffer_size	=	# bits to encrypt (multiple of CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize)
			*					output_buffer	=	pointer to where to put encrypted blocks
			*
			* Return:			true or false
			*
			* Notes: The only supported block size for ECB/CBC data modes is TWOFISH_CONSTANT_BLOCK_SIZE bits.
			*		 If input_buffer_size is not a multiple of TWOFISH_CONSTANT_BLOCK_SIZE bits in those modes, 
			*        In CFB-1bit data mode, all block sizes can be supported.
			*
			+***************************************************************************
			*/
			bool BlockEncryption(const KeyInstance& processing_key_object, const ClassicByte* input_buffer, std::uint64_t input_buffer_size, ClassicByte* output_buffer)
			{
				using CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize;
				using CommonSecurity::Twofish::DefineConstants::Constant_MinCipherRounds;
				using CommonSecurity::Twofish::DefineConstants::Constant_MaxCipherRounds;
				
				if( (this == nullptr) || (this->CipherSign != ValidInstanceFlag) )
					return false; //This is the invalid status of the cipher instance
				if( processing_key_object.KeySign != ValidInstanceFlag )
					return false; //Invalid status of this key instance reference
				if( (processing_key_object.NumberRounds < Constant_MinCipherRounds) || (processing_key_object.NumberRounds > Constant_MaxCipherRounds) || ((processing_key_object.NumberRounds & (8 - 1)) != 0) )
					return false; //Invalid key instance reference of Cipher round
				if( (this->DataMode != DataProcessingMode::CFB) && (input_buffer_size % Constant_DataBlockSize) != 0 )
					return false; //The size of the data block to processes is incorrect
				if( (input_buffer_size == 0) )
					return false;

			#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
				if ( ( ( (std::int32_t)input_buffer ) & 3 ) || ( ( (std::int32_t)output_buffer ) & 3 ) )
					return false;
			#endif

				/* Loop counter variables */
				std::int64_t current_index = 0ULL, bits_counter = 0ULL;
				std::int32_t current_round = 0, need_round = processing_key_object.NumberRounds;

				/* Temporary do processing data block */
				#if __cplusplus
				std::array<DoubleWord, Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits> temporary_data_block { 0, 0, 0, 0 };
				#else
				DoubleWord temporary_data_block[4] = { 0 };
				#endif

				/* Temporary data variables */
				DoubleWord text0 = 0U, text1 = 0U;

				if(this->DataMode == DataProcessingMode::CFB)
				{
					ClassicByte bit = 0, context_bit = 0, carry_bit = 0;

					/* Key and initial_vector generation with do encryption function in cryptograph ECB data mode */
					this->DataMode = DataProcessingMode::ECB;
					for(std::uint64_t bits_counter = 0; bits_counter < input_buffer_size; bits_counter++)
					{
						/* Recursively make the BlockEncryption function here handle cryptograph CFB data modes, one block at a time */
						this->BlockEncryption(processing_key_object, &this->ByteInitialVector[0], Constant_DataBlockSize, (ClassicByte*)(&temporary_data_block[0]));

						/* Which bit popition in byte */
						bit = 0x80 >> ( bits_counter & 7U );
						context_bit = ( input_buffer[ bits_counter / 8U ] & bit ) ^ ( ( ( (ClassicByte*)(&temporary_data_block[0]) )[0] & 0x80 ) >> ( bits_counter & 7U ) );
						output_buffer[ bits_counter / 8U ] = ( output_buffer[ bits_counter / 8U ] & ~bit ) | context_bit;
						carry_bit = context_bit >> ( 7U - ( bits_counter & 7U ) );

						for(current_index = Constant_DataBlockSize / 8 - 1; current_index >= 0; current_index--)
						{
							/* Save next "carry" from shift */
							bit = this->ByteInitialVector[ current_index ] >> 7;
							this->ByteInitialVector[ current_index ] = ( this->ByteInitialVector[ current_index ] << 1 ) ^ carry_bit;
							carry_bit = bit;
						}
					}
					/* Restore mode for next time */
					this->DataMode = DataProcessingMode::CFB;
					return true;
				}

				if(this->DataMode == DataProcessingMode::OFB)
				{
					/* Key and initial_vector generation with do encryption function in cryptograph ECB data mode */
					this->DataMode = DataProcessingMode::ECB;

					std::uint64_t byte_step = 0;

					for(std::uint64_t bits_counter = 0; bits_counter < input_buffer_size; bits_counter += Constant_DataBlockSize)
					{
						/* Recursively make the BlockEncryption function here handle cryptograph CFB data modes, one block at a time */
						this->BlockEncryption(processing_key_object, &this->ByteInitialVector[0], Constant_DataBlockSize, (ClassicByte*)(&temporary_data_block[0]));
						
						for(std::uint32_t current_index = 0; current_index < std::size(temporary_data_block); current_index++)
						{
							/* Update initial vector bytes */
							((DoubleWord*)&(this->ByteInitialVector[0]))[current_index] = TWOFISH_BYTE_SWAP(temporary_data_block[ current_index ]);
						}

						/* XOR data */
						std::uint32_t byte_offset = byte_step + std::size(this->ByteInitialVector);
						while(byte_step < byte_offset && byte_offset <= (input_buffer_size / std::numeric_limits<std::uint8_t>::digits))
						{
							output_buffer[ byte_step ] = input_buffer[ byte_step ] ^ this->ByteInitialVector[ byte_step & 15 ];
							++byte_step;
						}
					}

					/* Restore mode for next time */
					this->DataMode = DataProcessingMode::OFB;
					return true;
				}
				
				using CommonSecurity::Twofish::DefineConstants::Constant_InputWhitenIndex;
				using CommonSecurity::Twofish::DefineConstants::Constant_OutputWhitenIndex;
				using CommonSecurity::Twofish::DefineConstants::Constant_SubkeyRounds;

				#if __cplusplus
				std::array<DoubleWord, Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits> temporary_data_block_copy { 0, 0, 0, 0 };
				#else
				DoubleWord temporary_data_block_copy[4] = { 0 };
				#endif

				/* Here for ECB, CBC modes */
				for
				(
					bits_counter = 0;
					bits_counter < input_buffer_size;
					bits_counter += Constant_DataBlockSize,
					input_buffer += (Constant_DataBlockSize / std::numeric_limits<std::uint8_t>::digits),
					output_buffer += (Constant_DataBlockSize / std::numeric_limits<std::uint8_t>::digits)
				)
				{
					/* Copy input the block, add whitening */
					for (current_index = 0; current_index < std::size(temporary_data_block); current_index++)
					{
						temporary_data_block[ current_index ] = TWOFISH_BYTE_SWAP( ( (DoubleWord*)input_buffer )[ current_index ] ) ^ processing_key_object.SubKeys[ Constant_InputWhitenIndex + current_index ];
						if( this->DataMode == DataProcessingMode::CBC )
							temporary_data_block[ current_index ] ^= TWOFISH_BYTE_SWAP( this->InitialVector32Bit[ current_index ] );
						else if( this->DataMode == DataProcessingMode::PCBC )
						{
							temporary_data_block_copy[ current_index ] = TWOFISH_BYTE_SWAP( temporary_data_block[ current_index ] );
							temporary_data_block[ current_index ] ^= TWOFISH_BYTE_SWAP( this->InitialVector32Bit[ current_index ] );
						}
					}

					/* Main Twofish encryption loop */
					for(current_round = 0; current_round < need_round; current_round++)
					{
						
					#if TWOFISH_FEISTEL_DESIGN_ARCHITECTURE_VERSION
						
						text0 = Algorithm::ProcessFunction32Bit( TWOFISH_BIT_ROTATE_RIGHT( temporary_data_block[ 0 ], ( current_round + 1 ) / 2 ), &processing_key_object.SubstituteBoxKeys[0], processing_key_object.ByteKeyBitSize );
						text1 = Algorithm::ProcessFunction32Bit( TWOFISH_BIT_ROTATE_LEFT( temporary_data_block[ 1 ], 8 + ( current_round + 1 ) / 2 ), &processing_key_object.SubstituteBoxKeys[0], processing_key_object.ByteKeyBitSize );

						/* Apply round subkeys with Pseudo-Hadamard Transform */
						temporary_data_block[ 2 ] ^= TWOFISH_BIT_ROTATE_LEFT( text0 + text1 + processing_key_object.SubKeys[ Constant_SubkeyRounds + 2 * current_round ], current_round / 2 );
						temporary_data_block[ 3 ] ^= TWOFISH_BIT_ROTATE_RIGHT( text0 + 2 * text1 + processing_key_object.SubKeys[ Constant_SubkeyRounds + 2 * current_round + 1 ], ( current_round + 2 ) / 2 );

					#else

						text0 = Algorithm::ProcessFunction32Bit( temporary_data_block[ 0 ], &processing_key_object.SubstituteBoxKeys[0], processing_key_object.ByteKeyBitSize );
						text1 = Algorithm::ProcessFunction32Bit( TWOFISH_BIT_ROTATE_LEFT( temporary_data_block[ 1 ], 8 ), &processing_key_object.SubstituteBoxKeys[0], processing_key_object.ByteKeyBitSize );

						/* Apply round subkeys with Pseudo-Hadamard Transform */
						temporary_data_block[ 3 ] = TWOFISH_BIT_ROTATE_LEFT( temporary_data_block[ 3 ], 1 );
						temporary_data_block[ 2 ] ^= text0 + text1 + processing_key_object.SubKeys[ Constant_SubkeyRounds + 2 * current_round ];
						temporary_data_block[ 3 ] ^= text0 + 2 * text1 + processing_key_object.SubKeys[ Constant_SubkeyRounds + 2 * current_round + 1 ];
						temporary_data_block[ 2 ] = TWOFISH_BIT_ROTATE_RIGHT( temporary_data_block[ 2 ], 1 );

					#endif

						/* Swap for next round */
						if (current_round < need_round - 1)
						{
							/*
								DoubleWord temporary_word = 0;
								
								temporary_word = temporary_data_block[ 0 ];
								temporary_data_block[ 0 ] = x[ 2 ];
								temporary_data_block[ 2 ] = temporary_word;

								temporary_word = temporary_data_block[ 1 ];
								temporary_data_block[ 1 ] = temporary_data_block[ 3 ];
								temporary_data_block[ 3 ] = temporary_word;
							*/

							//https://en.wikipedia.org/wiki/XOR_swap_algorithm
							temporary_data_block[ 0 ] ^= temporary_data_block[ 2 ];
							temporary_data_block[ 2 ] ^= temporary_data_block[ 0 ];
							temporary_data_block[ 0 ] ^= temporary_data_block[ 2 ];

							temporary_data_block[ 1 ] ^= temporary_data_block[ 3 ];
							temporary_data_block[ 3 ] ^= temporary_data_block[ 1 ];
							temporary_data_block[ 1 ] ^= temporary_data_block[ 3 ];
						}
					}

					#if TWOFISH_FEISTEL_DESIGN_ARCHITECTURE_VERSION

					/* "Final permutation" */
					temporary_data_block[ 0 ] = TWOFISH_BIT_ROTATE_RIGHT( temporary_data_block[ 0 ], 8 );
					temporary_data_block[ 1 ] = TWOFISH_BIT_ROTATE_LEFT( temporary_data_block[ 1 ], 8 );
					temporary_data_block[ 2 ] = TWOFISH_BIT_ROTATE_RIGHT( temporary_data_block[ 2 ], 8 );
					temporary_data_block[ 3 ] = TWOFISH_BIT_ROTATE_LEFT( temporary_data_block[ 3 ], 8 );

					#endif

					/* Copy output the block, with whitening */
					for (current_index = 0; current_index < std::size(temporary_data_block); current_index++)
					{
						( (DoubleWord*)output_buffer )[ current_index ] = TWOFISH_BYTE_SWAP( temporary_data_block[ current_index ] ^ processing_key_object.SubKeys[ Constant_OutputWhitenIndex + current_index ] );
						if( this->DataMode == DataProcessingMode::CBC )
							this->InitialVector32Bit[ current_index ] = ( (DoubleWord*)output_buffer )[ current_index ];
						else if( this->DataMode == DataProcessingMode::PCBC )
						{
							this->InitialVector32Bit[ current_index ] = temporary_data_block_copy[ current_index ] ^ ( (DoubleWord*)output_buffer )[ current_index ];
						}
					}
				}

				return true;
			}

			/*
			+*****************************************************************************
			*
			* Function Name:	BlockDecryption (Key used for decrypting)
			*
			* Function:			Decrypt block(s) of data using Twofish
			*
			* Arguments:		processing_key_object	=	pointer to already initialized KeyInstance
			*					input_buffer		=	pointer to data blocks to be decrypted
			*					input_buffer_size	=	# bits to decrypt (multiple of CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize)
			*					output_buffer	=	pointer to where to put decrypted blocks
			*
			* Return:			true or false
			*
			* Notes: The only supported block size for ECB/CBC data modes is TWOFISH_CONSTANT_BLOCK_SIZE bits.
			*		 If input_buffer_size is not a multiple of TWOFISH_CONSTANT_BLOCK_SIZE bits in those modes,
			*        In CFB-1bit data mode, all block sizes can be supported.
			*
			+***************************************************************************
			*/
			bool BlockDecryption(const KeyInstance& processing_key_object, const ClassicByte* input_buffer, std::uint64_t input_buffer_size, ClassicByte* output_buffer)
			{
				using CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize;
				using CommonSecurity::Twofish::DefineConstants::Constant_MinCipherRounds;
				using CommonSecurity::Twofish::DefineConstants::Constant_MaxCipherRounds;
				
				if( (this == nullptr) || (CipherSign != ValidInstanceFlag) )
					return false; //This is the invalid status of the cipher instance
				if( processing_key_object.KeySign != ValidInstanceFlag )
					return false; //Invalid status of this key instance reference
				if( (processing_key_object.NumberRounds < Constant_MinCipherRounds) || (processing_key_object.NumberRounds > Constant_MaxCipherRounds) || ((processing_key_object.NumberRounds & (8 - 1)) != 0) )
					return false; //Invalid key instance reference of Cipher round
				if( (this->DataMode != DataProcessingMode::CFB) && (input_buffer_size % Constant_DataBlockSize) )
					return false; //The size of the data block to processes is incorrect
				if( (input_buffer_size == 0) )
					return false;

			#if TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
				if ( ( ( (std::int32_t)input_buffer ) & 3 ) || ( ( (std::int32_t)output_buffer ) & 3 ) )
					return false;
			#endif

				/* Loop counter variables */
				std::int64_t current_index = 0ULL, bits_counter = 0ULL;
				std::int32_t current_round = 0, need_round = processing_key_object.NumberRounds;

				/* Temporary do processing data block */
				#if __cplusplus
				std::array<DoubleWord, Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits> temporary_data_block { 0, 0, 0, 0 };
				#else
				DoubleWord temporary_data_block[4] = { 0 };
				#endif

				/* Temporary data variables */
				DoubleWord text0 = 0U, text1 = 0U;

				if(this->DataMode == DataProcessingMode::CFB)
				{
					ClassicByte bit = 0, context_bit = 0, carry_bit = 0;

					/* Key and initial_vector generation with do encryption function in cryptograph ECB data mode */
					this->DataMode = DataProcessingMode::ECB;
					for(std::uint64_t bits_counter = 0; bits_counter < input_buffer_size; bits_counter++)
					{
						/* Recursively make the BlockEncryption function here handle cryptograph CFB data modes, one block at a time */
						this->BlockEncryption(processing_key_object, &this->ByteInitialVector[0], Constant_DataBlockSize, (ClassicByte*)(&temporary_data_block[0]));

						/* Which bit popition in byte */
						bit = 0x80 >> ( bits_counter & 7U );
						context_bit = input_buffer[ bits_counter / 8U ] & bit;
						output_buffer[ bits_counter / 8U ] = ( output_buffer[ bits_counter / 8U ] & ~bit ) | ( context_bit ^ ( ( (ClassicByte*)(&temporary_data_block[0]) )[0] & 0x80 ) >> ( bits_counter & 7 ) );
						carry_bit = context_bit >> ( 7U - ( bits_counter & 7U ) );
						
						for(current_index = Constant_DataBlockSize / 8 - 1; current_index >= 0; current_index--)
						{
							/* Save next "carry" from shift */
							bit = this->ByteInitialVector[ current_index ] >> 7;
							this->ByteInitialVector[ current_index ] = ( this->ByteInitialVector[ current_index ] << 1 ) ^ carry_bit;
							carry_bit = bit;
						}
					}
					/* Restore mode for next time */
					this->DataMode = DataProcessingMode::CFB;
					return true;
				}

				if(this->DataMode == DataProcessingMode::OFB)
				{
					/* Key and initial_vector generation with do encryption function in cryptograph ECB data mode */
					this->DataMode = DataProcessingMode::ECB;

					std::uint64_t byte_step = 0;

					for(std::uint64_t bits_counter = 0; bits_counter < input_buffer_size; bits_counter += Constant_DataBlockSize)
					{
						/* Recursively make the BlockEncryption function here handle cryptograph CFB data modes, one block at a time */
						this->BlockEncryption(processing_key_object, &this->ByteInitialVector[0], Constant_DataBlockSize, (ClassicByte*)(&temporary_data_block[0]));
						
						for(std::uint32_t current_index = 0; current_index < std::size(temporary_data_block); current_index++)
						{
							/* Update initial vector bytes */
							((DoubleWord*)&(this->ByteInitialVector[0]))[current_index] = TWOFISH_BYTE_SWAP(temporary_data_block[ current_index ]);
						}

						/* XOR data */
						std::uint32_t byte_offset = byte_step + std::size(this->ByteInitialVector);
						while(byte_step < byte_offset && byte_offset <= (input_buffer_size / std::numeric_limits<std::uint8_t>::digits))
						{
							output_buffer[ byte_step ] = input_buffer[ byte_step ] ^ this->ByteInitialVector[ byte_step & 15 ];
							++byte_step;
						}
					}

					/* Restore mode for next time */
					this->DataMode = DataProcessingMode::OFB;
					return true;
				}

				using CommonSecurity::Twofish::DefineConstants::Constant_InputWhitenIndex;
				using CommonSecurity::Twofish::DefineConstants::Constant_OutputWhitenIndex;
				using CommonSecurity::Twofish::DefineConstants::Constant_SubkeyRounds;

				#if __cplusplus
				std::array<DoubleWord, Constant_DataBlockSize / std::numeric_limits<std::uint32_t>::digits> temporary_data_block_copy { 0, 0, 0, 0 };
				#else
				DoubleWord temporary_data_block_copy[4] = { 0 };
				#endif

				/* Here for ECB, CBC modes */
				for
				(
					bits_counter = 0;
					bits_counter < input_buffer_size;
					bits_counter += Constant_DataBlockSize,
					input_buffer += (Constant_DataBlockSize / std::numeric_limits<std::uint8_t>::digits),
					output_buffer += (Constant_DataBlockSize / std::numeric_limits<std::uint8_t>::digits)
				)
				{
					/* Copy output the block, add whitening */
					for (current_index = 0; current_index < std::size(temporary_data_block); current_index++)
					{
						temporary_data_block[ current_index ] = TWOFISH_BYTE_SWAP( ( (DoubleWord*)input_buffer )[ current_index ] ) ^ processing_key_object.SubKeys[ Constant_OutputWhitenIndex + current_index ];
					}

					/* Main Twofish decryption loop */
					for(current_round = need_round - 1; current_round >= 0; current_round--)
					{
						text0 = Algorithm::ProcessFunction32Bit( temporary_data_block[ 0 ], &processing_key_object.SubstituteBoxKeys[0], processing_key_object.ByteKeyBitSize );
						text1 = Algorithm::ProcessFunction32Bit( TWOFISH_BIT_ROTATE_LEFT( temporary_data_block[ 1 ], 8 ), &processing_key_object.SubstituteBoxKeys[0], processing_key_object.ByteKeyBitSize );
						
						/* Apply round subkeys with Pseudo-Hadamard Transform */
						temporary_data_block[ 2 ] = TWOFISH_BIT_ROTATE_LEFT( temporary_data_block[ 2 ], 1 );
						temporary_data_block[ 2 ] ^= text0 + text1 + processing_key_object.SubKeys[ Constant_SubkeyRounds + 2 * current_round ];
						temporary_data_block[ 3 ] ^= text0 + 2 * text1 + processing_key_object.SubKeys[ Constant_SubkeyRounds + 2 * current_round + 1 ];
						temporary_data_block[ 3 ] = TWOFISH_BIT_ROTATE_RIGHT( temporary_data_block[ 3 ], 1 );
						
						/* Unswap, except for last round */
						if (current_round > 0)
						{
							/*
								text0 = temporary_data_block[ 0 ];
								temporary_data_block[ 0 ] = x[ 2 ];
								temporary_data_block[ 2 ] = text0;

								text1 = temporary_data_block[ 1 ];
								temporary_data_block[ 1 ] = temporary_data_block[ 3 ];
								temporary_data_block[ 3 ] = text1;
							*/

							text0 = temporary_data_block[0], text1 = temporary_data_block[1];

							//https://en.wikipedia.org/wiki/XOR_swap_algorithm
							temporary_data_block[ 0 ] ^= temporary_data_block[ 2 ];
							temporary_data_block[ 2 ] ^= temporary_data_block[ 0 ];
							temporary_data_block[ 0 ] ^= temporary_data_block[ 2 ];

							temporary_data_block[ 1 ] ^= temporary_data_block[ 3 ];
							temporary_data_block[ 3 ] ^= temporary_data_block[ 1 ];
							temporary_data_block[ 1 ] ^= temporary_data_block[ 3 ];
						}
					}

					/* Copy input the block, with whitening */
					for (current_index = 0; current_index < std::size(temporary_data_block); current_index++)
					{
						if(this->DataMode == DataProcessingMode::PCBC)
						{
							temporary_data_block[ current_index ] ^= TWOFISH_BYTE_SWAP( this->InitialVector32Bit[ current_index ] );
							temporary_data_block_copy[ current_index ] = ( (DoubleWord*)input_buffer )[ current_index ];
							this->InitialVector32Bit[ current_index ] = temporary_data_block_copy[ current_index ] ^ temporary_data_block[ current_index ];
						}

						temporary_data_block[ current_index ] ^= TWOFISH_BYTE_SWAP( processing_key_object.SubKeys[ Constant_InputWhitenIndex + current_index ] );
						
						if(this->DataMode == DataProcessingMode::CBC)
						{
							temporary_data_block[ current_index ] ^= TWOFISH_BYTE_SWAP( this->InitialVector32Bit[ current_index ] );
							this->InitialVector32Bit[ current_index ] = ( (DoubleWord*)input_buffer )[ current_index ];
						}
						
						( (DoubleWord*)output_buffer )[ current_index ] = TWOFISH_BYTE_SWAP( temporary_data_block[ current_index ] );
					}
				}

				return true;
			}

			~CipherInstance()
			{
				this->CipherSign = 0U;
				memory_set_no_optimize_function<0x00>(&this->ByteInitialVector[0], std::size(this->ByteInitialVector));
				memory_set_no_optimize_function<0x00>(&this->InitialVector32Bit[0], std::size(this->InitialVector32Bit) * sizeof(DoubleWord));
			}
		};

		//KeyInstance KeyInstanceObject;
		//CipherInstance CipherInstanceObject;

	public:

		struct TwofishUnitTest
		{
			std::uint32_t KeyBitSize = 0;
			ClassicByte TestData[CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize / std::numeric_limits<std::uint8_t>::digits] = { 0 };

			Algorithm::KeyInstance KeyInstanceObject;
			Algorithm::CipherInstance CipherInstanceObject;

			//Knuth's additive random number generator
			struct KnuthRandomNumberGenerator
			{
				DoubleWord RandomBits[ 64 ] = { 1 };
				std::uint32_t RandomBitsIndex = 0;
				/* Whether number seeds have been sown */
				bool WhetherNumberNumberHaveBeenSown = false;

				DoubleWord GenerateNumber()
				{
					if(!WhetherNumberNumberHaveBeenSown)
						return 0;

					if(RandomBitsIndex >= 57U)
						RandomBitsIndex = 0U; /* This index range is 0~56 */

					RandomBits[ RandomBitsIndex ] += RandomBits[ ( RandomBitsIndex < 7U ) ? RandomBitsIndex - 7U + 57U: RandomBitsIndex - 7U ];

					RandomBits[ 62 ] += RandomBits[ 61 ];

					/* Very long period! */
					RandomBits[ 63 ] = TWOFISH_BIT_ROTATE_LEFT( RandomBits[ 63 ], 9 ) + 0x6F4ED7D0U;

					return ( RandomBits[ RandomBitsIndex++ ] ^ RandomBits[ 63 ] ) + RandomBits[ 62 ];
				}

				void Seed(DoubleWord seed)
				{
					DoubleWord number = 0;

					for( std::size_t index = 0; index < 64; ++index )
					{
						RandomBits[ index ] = seed;
						/* Keep track of lsb of all entries */
						number |= seed;
						seed = TWOFISH_BIT_ROTATE_LEFT(seed, 11) + 0x12345678U;
					}

					if( (number & 1) == 0 )
						++(RandomBits[ 0 ]);

					for( std::size_t index = 0; index < 1000; ++index )
						this->GenerateNumber(); //Discard result

					RandomBits[ 63 ] = this->GenerateNumber();
					RandomBits[ 62 ] = this->GenerateNumber();
					RandomBits[ 61 ] = this->GenerateNumber() | 1U; //Make it is odd number

					if(WhetherNumberNumberHaveBeenSown == false)
						WhetherNumberNumberHaveBeenSown = true;
				}
			};

			void ErrorMesssage(const char* message, const std::int8_t* message2)
			{
				std::cout << message << " " << message2 << std::endl;
				throw std::runtime_error("");
			}

			void SanityCheck(std::uint32_t test_count)
			{
				using CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize;
				using CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize;
				using CommonSecurity::Twofish::DefineConstants::Constant_MinKeySize;
				
				static const std::int8_t* data_mode_names[] = { (std::int8_t*)"DATA_MODE_ECB", (std::int8_t*)"DATA_MODE_CBC", (std::int8_t*)"DATA_MODE_CBC", (std::int8_t*)"DATA_MODE_CFB_1BIT", (std::int8_t*)"DATA_MODE_OFB" };
				static DataProcessingMode data_proceesing_modes[] = { DataProcessingMode::ECB, DataProcessingMode::CBC, DataProcessingMode::PCBC, DataProcessingMode::CFB, DataProcessingMode::OFB };
				static const std::int8_t hexadecimal_table[] = "0123456789ABCDEF";

				const std::int8_t test_hexadecimal_string[] = "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF";
				
				std::vector<ClassicByte> string_bytes(std::size(test_hexadecimal_string), 0);
				for(std::size_t index = 0; index < string_bytes.size(); index++)
					string_bytes[index] = static_cast<std::uint8_t>(test_hexadecimal_string[index]);

				auto test_hexadecimal_values = CommonToolkit::MessagePacking<DoubleWord, ClassicByte>(string_bytes.data(), 64);

				ClassicByte current_plain_text[128] = { 0 };
				ClassicByte current_cipher_text[128] = { 0 };
				std::int8_t current_initial_vector_string[Constant_DataBlockSize / 4U] = { 0 };
				KnuthRandomNumberGenerator prng; 

				if(test_count)
				{
					prng.Seed(0);

					for(std::size_t data_mode_index = 0; data_mode_index < std::size(data_proceesing_modes); data_mode_index++)
					{
						DataProcessingMode current_data_mode = data_proceesing_modes[data_mode_index];
						const std::int8_t* current_data_mode_name = data_mode_names[data_mode_index];

						CipherInstanceObject.MakeCipher(current_data_mode, test_hexadecimal_string);
						if(CipherInstanceObject.DataMode != current_data_mode)
							this->ErrorMesssage("Cipher mode not set properly during sanity check", current_data_mode_name);
						
						if(current_data_mode != DataProcessingMode::ECB)
						{
							for(std::size_t index = 0; index < Constant_DataBlockSize / 32U; ++index)
								if(CipherInstanceObject.InitialVector32Bit[index] != test_hexadecimal_values[index])
									this->ErrorMesssage("Cipher mode not set properly during sanity check", current_data_mode_name);
						}

						std::int32_t test_number_limit = ( current_data_mode == DataProcessingMode::CFB ) ? ( test_count + 31 ) / 32 : test_count ;
						for
						(
							KeyBitSize = Constant_MinKeySize;
							KeyBitSize <= Constant_MaxKeySize;
							KeyBitSize += (Constant_MaxKeySize - Constant_MinKeySize) / 2U
						)
						{
							std::cout << ".";
							this->ClearTestData();

							if(!KeyInstanceObject.MakeKey(KeyBitSize, test_hexadecimal_string))
								this->ErrorMesssage("Error parsing key during sanity check", current_data_mode_name);

							for(std::size_t index = 0; index < KeyInstanceObject.ByteKeyBitSize / 32U; ++index)
								if(KeyInstanceObject.CipherKey32Bit[index] != test_hexadecimal_values[index])
									this->ErrorMesssage("Invalid key parse during sanity check", current_data_mode_name);

							for(std::int32_t test_number = 0; test_number < test_number_limit; test_number++)
							{
								/* Periodic key schedule time? */
								if( (test_number & 0x1F) == 0 )
								{
									for(std::size_t random_number_index = 0; random_number_index < (KeyBitSize / sizeof(DoubleWord)); ++random_number_index)
									{
										KeyInstanceObject.ByteKeyMaterial[ random_number_index ] = hexadecimal_table[prng.GenerateNumber() & 0xF ];
									}

									if(test_number == 0)
										/* Give "easy" test data the first time */
										this->ClearTestData();
									if(!KeyInstanceObject.MakeKey(KeyBitSize, &KeyInstanceObject.ByteKeyMaterial[0]))
										this->ErrorMesssage("Encrypt makeKey during sanity check", current_data_mode_name);
								}

								if(current_data_mode != DataProcessingMode::ECB)
								{
									/* Update initial vector data, if needed */
									for(std::size_t random_number_index = 0; random_number_index < Constant_DataBlockSize / 4U; ++random_number_index)
									{
										KeyInstanceObject.ByteKeyMaterial[ random_number_index ] = hexadecimal_table[ (test_number != 0) ? prng.GenerateNumber() & 0xF : 0];
									}
								}

								std::uint32_t byte_number = 0U;
								if(test_number == 0)
									byte_number = Constant_DataBlockSize / 8U;
								else
									byte_number = ( Constant_DataBlockSize / 8U ) * ( 1U + ( prng.GenerateNumber() % ( sizeof(current_plain_text) / (Constant_DataBlockSize / 8U) ) ) );
							
								/* Set random plaintext */
								for(std::size_t random_number_index = 0; random_number_index < byte_number; ++random_number_index)
									current_plain_text[random_number_index] = (test_number != 0) ? (ClassicByte)prng.GenerateNumber() : 0;

								/* Check that CBC data work mode as advertised */
								if(current_data_mode == DataProcessingMode::CBC)
								{
									CipherInstanceObject.MakeCipher(current_data_mode, current_initial_vector_string);
									CipherInstanceObject.DataMode = DataProcessingMode::ECB;

									/* Copy new data over the initial vector */
									for(std::size_t number_index_offset = 0; number_index_offset < Constant_DataBlockSize / 8U; number_index_offset++)
										/* Auto-Byteswap! */
										TestData[ number_index_offset ] = (ClassicByte)( CipherInstanceObject.InitialVector32Bit[ number_index_offset / 4U] >> ( 8U * ( number_index_offset & 3U ) ) );

									for(std::size_t random_number_index = 0; random_number_index < byte_number; random_number_index += Constant_DataBlockSize / 8U)
									{
										/* XOR in next block */
										for(std::size_t number_index_offset = 0; number_index_offset < Constant_DataBlockSize / 8U; number_index_offset++)
											TestData[ number_index_offset ] ^= current_plain_text[ random_number_index + number_index_offset ];

										if(!CipherInstanceObject.BlockEncryption(KeyInstanceObject, TestData, Constant_DataBlockSize, TestData))
											this->ErrorMesssage("BlockEncryption return value during sanity check", current_data_mode_name);
									}

									/* Restore CBC data work mode */
									CipherInstanceObject.DataMode = DataProcessingMode::CBC;
								}

								/* Test encrypt data */
								CipherInstanceObject.MakeCipher(current_data_mode, current_initial_vector_string);
								if(!CipherInstanceObject.BlockEncryption(KeyInstanceObject, current_plain_text, byte_number * 8U, current_cipher_text))
									this->ErrorMesssage("BlockEncryption return value during sanity check", current_data_mode_name);

								/* Validate CBC "hash" */
								if(current_data_mode == DataProcessingMode::CBC)
									for(std::size_t number_index_offset = 0; number_index_offset < Constant_DataBlockSize / 8U; number_index_offset++)
										if( TestData[ number_index_offset ] != current_cipher_text[ byte_number - Constant_DataBlockSize / 8U + number_index_offset ] )
											this->ErrorMesssage("CBC data mode does not work during sanity check", current_data_mode_name);

								/* Test decrypt data */
								CipherInstanceObject.MakeCipher(current_data_mode, current_initial_vector_string);
								if(!CipherInstanceObject.BlockDecryption(KeyInstanceObject, current_cipher_text, byte_number * 8U, current_cipher_text))
									this->ErrorMesssage("BlockDecryption return value during sanity check", current_data_mode_name);
							
								/* Compare bytes data */
								for(std::size_t random_number_index = 0; random_number_index < byte_number; ++random_number_index)
								{
									if(current_plain_text[ random_number_index ] != current_cipher_text[ random_number_index ])
									{
										std::cout << "Twofish ciphers sanity check: encrypt/decrypt miscompare (mode=" << current_data_mode_name << ",keySize=" << KeyBitSize << ")" << std::endl;
										throw std::runtime_error("");
									}
								}
							}
						}
						std::cout << "--------------------------------------------------------------------------------------------------" << std::endl;
					}
					std::cout << "The sanity check for Twofish ciphers is complete!" << std::endl;
				}
			}

			void ClearTestData()
			{
				volatile void* CheckPointer = nullptr;
				CheckPointer = memory_set_no_optimize_function<0x00>(&TestData[0], sizeof(TestData) / sizeof(TestData[0]));
				my_cpp2020_assert(CheckPointer == &TestData[0], "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;

				CheckPointer = memory_set_no_optimize_function<0x00>(&CipherInstanceObject.InitialVector32Bit[0], std::size(CipherInstanceObject.InitialVector32Bit) * sizeof(CipherInstanceObject.InitialVector32Bit[0]));
				my_cpp2020_assert(CheckPointer == &CipherInstanceObject.InitialVector32Bit[0], "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;

				CheckPointer = memory_set_no_optimize_function<0x00>(&KeyInstanceObject.CipherKey32Bit[0], std::size(KeyInstanceObject.CipherKey32Bit) * sizeof(KeyInstanceObject.CipherKey32Bit[0]));
				my_cpp2020_assert(CheckPointer == &KeyInstanceObject.CipherKey32Bit[0], "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			
				const std::vector<ClassicByte> CharacterZeroKeysData(CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize / sizeof(DoubleWord) + 4, (ClassicByte)'0');

				CheckPointer = std::memmove(std::addressof(KeyInstanceObject.ByteKeyMaterial[0]), CharacterZeroKeysData.data(), CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize / sizeof(DoubleWord) + 4);
				CheckPointer = nullptr;
			}
		};

	};

	#ifdef TWOFISH_ADDRESS_XOR
	#undef TWOFISH_ADDRESS_XOR
	#endif

	#ifdef TWOFISH_FEISTEL_DESIGN_ARCHITECTURE_VERSION
	#undef TWOFISH_FEISTEL_DESIGN_ARCHITECTURE_VERSION
	#endif

	#ifdef TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
	#undef TWOFISH_CLASSINSTANCE_BYTE_SIZE_ALIGN32
	#endif

	#ifdef TWOFISH_IS_LITTLE_ENDIAN_MACHINES
	#undef TWOFISH_IS_LITTLE_ENDIAN_MACHINES	
	#endif

	#ifdef TWOFISH_BIT_ROTATE_LEFT
	#undef TWOFISH_BIT_ROTATE_LEFT
	#endif

	#ifdef TWOFISH_BIT_ROTATE_RIGHT
	#undef TWOFISH_BIT_ROTATE_RIGHT
	#endif

	class DataWorker
	{
		
	private:

		std::size_t KeyByteBlockSize = 16;
		Algorithm::KeyInstance KeyInstanceObject;
		Algorithm::CipherInstance CipherInstanceObject;

		std::span<const std::uint8_t> KeyBlockSpan;

		void UpdateKeyBlock(std::span<const std::uint8_t> keys, std::size_t data_block_count)
		{
			if(this->KeyIndex + data_block_count > this->KeyBlockSpan.size())
				this->KeyIndex = 0;
			this->KeyBlockSpan = keys.subspan(this->KeyIndex, data_block_count);

			KeyInstanceObject.MakeKey(KeyBlockSpan.size() * ByteBitsSize, KeyBlockSpan.data());

			this->KeyIndex += KeyBlockSpan.size();
		}

		void UpdateInitialVector
		(
			std::span<const std::uint8_t> initial_vector
		)
		{
			using CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize;

			//InitialVector data size does not match, the specification of the cryptograph processing mode
			if( DataProcessingModeObject != DataProcessingMode::ECB && (initial_vector.empty() || initial_vector.size() != Number_Block_Data_Byte_Size) )
				return;

			if( DataProcessingModeObject == DataProcessingMode::ECB && !initial_vector.empty() )
				return;

			CipherInstanceObject.MakeCipher(DataProcessingModeObject, initial_vector.data());
		}

		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW WorkMode>
		void DoProcessFunction
		(
			std::span<const std::uint8_t> keys,
			std::span<const std::uint8_t> initial_vector,
			std::span<const std::uint8_t> input_buffer,
			std::span<std::uint8_t> output_buffer,
			const std::size_t input_buffer_offset = 0,
			const std::size_t output_buffer_offset = 0,
			const std::size_t data_block_count = Number_Block_Data_Byte_Size,
			const std::size_t key_block_count = Number_Block_Data_Byte_Size
		)
		{
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;

			this->UpdateInitialVector(initial_vector);

			const std::uint8_t* input_data_pointer = input_buffer.data() + input_buffer_offset;
			std::uint8_t* output_data_pointer = output_buffer.data() + output_buffer_offset;

			if constexpr(WorkMode == CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
			{
				//Twofish Encryption
				for(std::uint64_t round_index = 0; input_buffer_offset + round_index < input_buffer.size() && output_buffer_offset + round_index < output_buffer.size(); round_index += data_block_count)
				{
					this->UpdateKeyBlock(keys, key_block_count);
					
					CipherInstanceObject.BlockEncryption
					(
						KeyInstanceObject,
						input_data_pointer + round_index,
						data_block_count * ByteBitsSize,
						output_data_pointer + round_index
					);
				}
			}
			else if constexpr(WorkMode == CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
			{
				//Twofish Decryption
				for(std::uint64_t round_index = 0; input_buffer_offset + round_index < input_buffer.size() && output_buffer_offset + round_index < output_buffer.size(); round_index += data_block_count)
				{
					this->UpdateKeyBlock(keys, key_block_count);
					
					CipherInstanceObject.BlockDecryption
					(
						KeyInstanceObject,
						input_data_pointer + round_index,
						data_block_count * ByteBitsSize,
						output_data_pointer + round_index
					);
				}
			}

			input_data_pointer = nullptr;
			output_data_pointer = nullptr;
		}

	public:
		
		static constexpr std::uint64_t ByteBitsSize = std::numeric_limits<std::uint8_t>::digits;
		static constexpr std::uint64_t Number_Block_Data_Byte_Size = CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize / ByteBitsSize;

		DataProcessingMode DataProcessingModeObject = DataProcessingMode::ECB;
		//ChunkedDataPadders<ChunkedDataPaddingMode::ANSI_X9_23> ChunkedDataPadManager;

		std::size_t KeyIndex = 0;

		template<Cryptograph::CommonModule::CryptionMode2MCAC4_FDW WorkMode>
		/*
			@param keys: The key byte data for used in this ciphers
			@param initial_vector: The initial vector data for used in this ciphers
			@param input_buffer: The input byte array is used for the computation.
			@param output_buffer: The output byte array is used for the computation result.
			@param input_buffer_offset: Offset index of the input_buffer
			@param output_buffer_offset: Offset index of the output_buffer
			@param data_block_count: Number of bytes of data blocks to be processed
			@param key_block_count: Number of bytes of key blocks to be used
		*/
		void ProcessFunction
		(
			std::vector<std::uint8_t>& keys,
			std::vector<std::uint8_t>& initial_vector,
			std::vector<std::uint8_t>& input_buffer,
			std::vector<std::uint8_t>& output_buffer,
			const std::size_t input_buffer_offset = 0,
			const std::size_t output_buffer_offset = 0,
			const std::size_t data_block_count = Number_Block_Data_Byte_Size,
			const std::size_t key_block_count = Number_Block_Data_Byte_Size
		)
		{
			using Cryptograph::CommonModule::CryptionMode2MCAC4_FDW;
			using CommonSecurity::Twofish::DefineConstants::Constant_DataBlockSize;
			using CommonSecurity::Twofish::DefineConstants::Constant_MinKeySize;
			using CommonSecurity::Twofish::DefineConstants::Constant_MaxKeySize;

			//Check key byte block count

			my_cpp2020_assert
			(
				(key_block_count != 0U)
				&& static_cast<std::size_t>(key_block_count * ByteBitsSize) >= Constant_MinKeySize
				&& static_cast<std::size_t>(key_block_count * ByteBitsSize) <= Constant_MaxKeySize
				&& static_cast<std::size_t>(key_block_count * ByteBitsSize) % Constant_DataBlockSize == 0ULL,
				"Twofish DataWorker: The byte count of key block, must be a multiple of 16, 24, 32",
				std::source_location::current()
			);

			//Check data byte block count

			my_cpp2020_assert
			(
				(data_block_count != 0U) && (data_block_count % Number_Block_Data_Byte_Size) == 0U,
				"Twofish DataWorker: The byte count of data block, must be a multiple of 16",
				std::source_location::current()
			);

			//Check input buffer
			
			my_cpp2020_assert
			(
				input_buffer.data() != nullptr && !input_buffer.empty(),
				"Twofish DataWorker: input_buffer cannot be null-pointer and size must be not zero.",
				std::source_location::current()
			);

			//Check output buffer

			my_cpp2020_assert
			(
				output_buffer.data() != nullptr && !output_buffer.empty(),
				"Twofish DataWorker: output_buffer cannot be null-pointer and size must be not zero.",
				std::source_location::current()
			);

			//Check data buffer offset

			my_cpp2020_assert
			(
				input_buffer.size() - data_block_count >= input_buffer_offset,
				"Twofish DataWorker: Invalid input_buffer_offset, need greater or equal input_buffer size!",
				std::source_location::current()
			);

			my_cpp2020_assert
			(
				output_buffer_offset + data_block_count <= output_buffer.size(),
				"Twofish DataWorker: Invalid output_buffer_offset, need less or equal output_buffer size! which will be over the size of output_buffer!",
				std::source_location::current()
			);
			
			if constexpr(WorkMode == CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
			{
				this->DoProcessFunction<WorkMode>(keys, initial_vector, input_buffer, output_buffer, input_buffer_offset, output_buffer_offset, data_block_count, key_block_count);
			}
			else if constexpr(WorkMode == CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
			{
				this->DoProcessFunction<WorkMode>(keys, initial_vector, input_buffer, output_buffer, input_buffer_offset, output_buffer_offset, data_block_count, key_block_count);
			}
			else
			{
				static_assert(CommonToolkit::Dependent_Always_Failed<WorkMode>, "");
			}

			return;
		}

		DataWorker() = default;
		~DataWorker() = default;
	};
}

/*
	https://en.wikipedia.org/wiki/Threefish

	Reference code:
	https://github.dev/dvolkow/threefish/blob/master/include/threefish.hpp
	https://github.dev/nitrocaster/SkeinFish/blob/master/src/SkeinFish/Threefish.cs
*/
namespace CommonSecurity::Threefish
{
	/**
     * Only 4, 8 or 16 DWords size value may be parameters (SIZE_BLOCK)
     */
    template <std::uint8_t SIZE_BLOCK>
	class Algorithm
	{
		
	private:
		using RotationBitType = CommonSecurity::Threefish::DefineConstants::RotationBit<SIZE_BLOCK>;
		using InvertibleIndicesType = CommonSecurity::Threefish::DefineConstants::InvertibleIndices<SIZE_BLOCK>;

		static constexpr std::uint8_t												 Word_Count = SIZE_BLOCK;
		static constexpr std::uint8_t												 Word_ExecuteRound = Word_Count < 16 ? 72 : 80;
		static constexpr std::uint64_t												 KeyScheduleConstant_240 = 0x1BD11BDAA9FC1A22;
		RotationBitType																 RotationBitObject;
		InvertibleIndicesType														 InvertibleIndicesObject;
		std::array<std::array<std::uint64_t, Word_Count>, Word_ExecuteRound / 4 + 1> Words_Subkey {};
		std::array<std::uint64_t, 3>												 Words_Tweak { 0, 0, 0 };

		inline void ExpandKeys( std::span<const std::uint64_t> Keys )
		{
			volatile void* CheckPointer = nullptr;

			std::array<std::uint64_t, Word_Count + 1> ExpandDataKeys {};
			CheckPointer = memory_set_no_optimize_function<0x00>( ExpandDataKeys.data(), ExpandDataKeys.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == ExpandDataKeys.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;

			ExpandDataKeys[ Word_Count ] = KeyScheduleConstant_240;

			for ( std::uint8_t Index = 0; Index < Word_Count; ++Index )
				ExpandDataKeys[ Index ] = Keys[ Index ], ExpandDataKeys[ Word_Count ] ^= Keys[ Index ];

			for ( std::uint8_t Index = 0; Index < Words_Subkey.size(); ++Index )
			{
				for ( std::uint8_t Index2 = 0; Index2 < Word_Count; ++Index2 )
					Words_Subkey[ Index ][ Index2 ] = ExpandDataKeys[ ( Index + Index2 ) % ( Word_Count + 1 ) ];

				Words_Subkey[ Index ][ Word_Count - 3 ] += Words_Tweak[ Index % 3 ];
				Words_Subkey[ Index ][ Word_Count - 2 ] += Words_Tweak[ ( Index + 1 ) % 3 ];
				Words_Subkey[ Index ][ Word_Count - 1 ] += Index;
			}

			CheckPointer = memory_set_no_optimize_function<0x00>( ExpandDataKeys.data(), ExpandDataKeys.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == ExpandDataKeys.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
			
		}

		inline void MixFunction( std::uint64_t Input, std::uint64_t Input2, std::uint64_t& Output, std::uint64_t& Output2, std::uint64_t BitShiftCount )
		{
			#define THREEFISH_CRYPTION_WITH_LEFT_ROTATION_BIT64( Word, BitShiftCount ) ( ( Word << BitShiftCount ) | ( Word >> ( 64 - BitShiftCount ) ) )

			Output = Input + Input2;
			Output2 = THREEFISH_CRYPTION_WITH_LEFT_ROTATION_BIT64( Input2, BitShiftCount ) ^ Output;

			#undef THREEFISH_CRYPTION_WITH_LEFT_ROTATION_BIT64
		}

		inline void UnMixFunction( std::uint64_t Input, std::uint64_t Input2, std::uint64_t& Output, std::uint64_t& Output2, std::uint64_t BitShiftCount )
		{
			#define THREEFISH_CRYPTION_WITH_RIGHT_ROTATION_BIT64( Word, BitShiftCount ) ( ( Word << ( 64 - BitShiftCount ) ) | ( Word >> BitShiftCount ) )

			Output2 = THREEFISH_CRYPTION_WITH_RIGHT_ROTATION_BIT64( ( Input ^ Input2 ), BitShiftCount );
			Output = Input - Output2;

			#undef THREEFISH_CRYPTION_WITH_RIGHT_ROTATION_BIT64
		}

		inline void RoundEncryption( std::span<std::uint64_t> Words_Data, std::span<const std::uint8_t> RotationBitTable, std::span<const std::uint8_t> InvertibleIndicesTable )
		{
			for ( std::uint8_t Index = 0; Index < Word_Count; Index += 2U )
			{
				this->MixFunction( Words_Data[ InvertibleIndicesTable[ Index ] ], Words_Data[ InvertibleIndicesTable[ Index + 1 ] ], Words_Data[ InvertibleIndicesTable[ Index ] ], Words_Data[ InvertibleIndicesTable[ Index + 1 ] ], RotationBitTable[ Index / 2U ] );
			}
		}

		inline void RoundDecryption( std::span<std::uint64_t> Words_Data, std::span<const std::uint8_t> RotationBitTable, std::span<const std::uint8_t> InvertibleIndicesTable )
		{
			for ( std::uint8_t Index = 0; Index < Word_Count; Index += 2U )
			{
				this->UnMixFunction( Words_Data[ InvertibleIndicesTable[ Index ] ], Words_Data[ InvertibleIndicesTable[ Index + 1 ] ], Words_Data[ InvertibleIndicesTable[ Index ] ], Words_Data[ InvertibleIndicesTable[ Index + 1 ] ], RotationBitTable[ Index / 2U ] );
			}
		}

		inline void ProcessBlockEncryption( std::span<const std::uint64_t> InputData, std::span<std::uint64_t> OutputData )
		{
			volatile void* CheckPointer = nullptr;

			std::array<std::uint64_t, Word_Count> DataBuffer;
			std::ranges::copy( InputData.begin(), InputData.end(), DataBuffer.begin() );

			std::uint8_t ExecuteRound = 0;
			while ( ExecuteRound < Word_ExecuteRound )
			{
				for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
					DataBuffer[ ProcessIndex ] += Words_Subkey[ ExecuteRound / 4 ][ ProcessIndex ];

				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 0 ) % 8 ], InvertibleIndicesObject.Table[ 0 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 1 ) % 8 ], InvertibleIndicesObject.Table[ 1 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 2 ) % 8 ], InvertibleIndicesObject.Table[ 2 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 3 ) % 8 ], InvertibleIndicesObject.Table[ 3 ] );

				for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
					DataBuffer[ ProcessIndex ] += Words_Subkey[ ExecuteRound / 4 + 1 ][ ProcessIndex ];

				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 4 ) % 8 ], InvertibleIndicesObject.Table[ 0 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 5 ) % 8 ], InvertibleIndicesObject.Table[ 1 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 6 ) % 8 ], InvertibleIndicesObject.Table[ 2 ] );
				this->RoundEncryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 7 ) % 8 ], InvertibleIndicesObject.Table[ 3 ] );

				ExecuteRound += 8U;
			}
			ExecuteRound = 0;

			for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
				OutputData[ ProcessIndex ] = DataBuffer[ ProcessIndex ] + Words_Subkey[ Word_ExecuteRound / 4 ][ ProcessIndex ];

			CheckPointer = memory_set_no_optimize_function<0x00>( DataBuffer.data(), DataBuffer.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == DataBuffer.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

		inline void ProcessBlockDecryption( std::span<const std::uint64_t> InputData, std::span<std::uint64_t> OutputData )
		{
			volatile void* CheckPointer = nullptr;

			std::array<std::uint64_t, Word_Count> DataBuffer;

			for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
				DataBuffer[ ProcessIndex ] = InputData[ ProcessIndex ] - Words_Subkey[ Word_ExecuteRound / 4 ][ ProcessIndex ];

			std::uint8_t ExecuteRound = Word_ExecuteRound;
			while ( ExecuteRound > 0 )
			{
				ExecuteRound -= 8U;

				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 7 ) % 8 ], InvertibleIndicesObject.Table[ 3 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 6 ) % 8 ], InvertibleIndicesObject.Table[ 2 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 5 ) % 8 ], InvertibleIndicesObject.Table[ 1 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 4 ) % 8 ], InvertibleIndicesObject.Table[ 0 ] );

				for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
					DataBuffer[ ProcessIndex ] -= Words_Subkey[ ExecuteRound / 4 + 1 ][ ProcessIndex ];

				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 3 ) % 8 ], InvertibleIndicesObject.Table[ 3 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 2 ) % 8 ], InvertibleIndicesObject.Table[ 2 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 1 ) % 8 ], InvertibleIndicesObject.Table[ 1 ] );
				this->RoundDecryption( DataBuffer, RotationBitObject.Table[ ( ExecuteRound + 0 ) % 8 ], InvertibleIndicesObject.Table[ 0 ] );

				for ( std::uint8_t ProcessIndex = 0; ProcessIndex < Word_Count; ++ProcessIndex )
					DataBuffer[ ProcessIndex ] -= Words_Subkey[ ExecuteRound / 4 ][ ProcessIndex ];
			}
			ExecuteRound = 0;

			std::ranges::copy( DataBuffer.begin(), DataBuffer.end(), OutputData.begin() );

			CheckPointer = memory_set_no_optimize_function<0x00>( DataBuffer.data(), DataBuffer.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == DataBuffer.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}

	public:
		void EncryptionWithECB( const std::size_t WordSize, std::span<const std::uint64_t> InputData, std::span<std::uint64_t> OutputData )
		{
			for ( std::size_t BlockIndex = 0; BlockIndex < ( WordSize / SIZE_BLOCK ); ++BlockIndex )
			{
				this->ProcessBlockEncryption( InputData.subspan( BlockIndex, SIZE_BLOCK ), OutputData.subspan( BlockIndex, SIZE_BLOCK ) );
			}
		}

		void DecryptionWithECB( const std::size_t WordSize, std::span<const std::uint64_t> InputData, std::span<std::uint64_t> OutputData )
		{
			for ( std::size_t BlockIndex = 0; BlockIndex < ( WordSize / SIZE_BLOCK ); ++BlockIndex )
			{
				this->ProcessBlockDecryption( InputData.subspan( BlockIndex, SIZE_BLOCK ), OutputData.subspan( BlockIndex, SIZE_BLOCK ) );
			}
		}

		void UpdateKey( std::span<const std::uint64_t> Keys, std::span<const std::uint64_t> TweakWords )
		{
			if ( TweakWords.size() != 3 )
				return;
			else
				std::ranges::copy( TweakWords.begin(), TweakWords.end(), Words_Tweak.begin() );
			this->ExpandKeys( Keys );
		}

		void UpdateKey( std::span<const std::uint64_t> Keys )
		{
			if ( Keys.size() != SIZE_BLOCK )
				return;
			this->ExpandKeys( Keys );
		}

		explicit Algorithm( std::span<const std::uint64_t> Keys )
		{
			constexpr std::uint64_t BitSize = std::numeric_limits<std::uint64_t>::digits;
			static_assert( ( 256U / SIZE_BLOCK ) == BitSize || ( 512U / SIZE_BLOCK ) == BitSize || ( 1024U / SIZE_BLOCK ) == BitSize, "Threefish DataWorker: SIZE_BLOCK is invalid!" );

			my_cpp2020_assert( Keys.size() == SIZE_BLOCK, "", std::source_location::current() );

			volatile void* CheckPointer = nullptr;

			for ( auto& ArrayData : Words_Subkey )
			{
				CheckPointer = memory_set_no_optimize_function<0x00>( ArrayData.data(), ArrayData.size() * sizeof( std::uint64_t ) );
				my_cpp2020_assert(CheckPointer == ArrayData.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}
			this->ExpandKeys( Keys );
		}

		~Algorithm()
		{
			volatile void* CheckPointer = nullptr;

			for ( auto& ArrayData : Words_Subkey )
			{
				CheckPointer = memory_set_no_optimize_function<0x00>( ArrayData.data(), ArrayData.size() * sizeof( std::uint64_t ) );
				my_cpp2020_assert(CheckPointer == ArrayData.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
				CheckPointer = nullptr;
			}

			CheckPointer = memory_set_no_optimize_function<0x00>( Words_Tweak.data(), Words_Tweak.size() * sizeof( std::uint64_t ) );
			my_cpp2020_assert(CheckPointer == Words_Tweak.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
			CheckPointer = nullptr;
		}
	};
}