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
	constexpr unsigned int DELTA_VALUE = static_cast<unsigned int>(0x9e3779b9);
	
	class Worker
	{
		
	private:
		
		unsigned int MixValue(unsigned int& a, unsigned int& b, unsigned int& sum, const std::array<unsigned int, 4>& keys, unsigned int& data_values_index, unsigned int& choice_sum)
		{
			auto left_value = ((b >> 5 ^ a << 2) + (a >> 3 ^ b << 4));
			auto right_value = ((sum ^ a) + (keys[(data_values_index & 3) ^ choice_sum] ^ b));
			auto mixed_value = left_value ^ right_value;
			return mixed_value;
		}

	public:

		void operator()(unsigned int* data_values, unsigned int data_values_size, bool mode, const std::array<unsigned int, 4>& keys)
		{
			unsigned int a = 0, b = 0, sum = 0;
			unsigned int data_values_index;
			unsigned int execute_rounds = 0, choice_sum = 0;
			
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
		
		Worker() = default;
		~Worker() = default;
		
	};

	inline Worker SuperTEA;
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
	enum class AES_SecurityLevel
	{
		//128 bit
		ZERO = 0,
		//192 bit
		ONE = 1,
		//256 bit
		TWO = 2
	};

	/*
		Description of the Cryptographs(密码器的说明):

			AES is based on a design principle known as a substitution–permutation network, and is efficient in both software and hardware.
			Unlike its predecessor DES, AES does not use a Feistel network. AES is a variant of Rijndael, with a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
			By contrast, Rijndael per se is specified with block and key sizes that may be any multiple of 32 bits, with a minimum of 128 and a maximum of 256 bits.

			AES是基于一种被称为替换-互斥网络的设计原理，在软件和硬件上都很高效。 
			与其前身DES不同，AES不使用Feistel网络。
			AES是Rijndael的一个变种，其固定块大小为128比特，密钥大小为128、192或256比特。
			相比之下，Rijndael本身规定的块和密钥大小可以是32位的任何倍数，最小为128位，最大为256位。

			AES operates on a 4 × 4 column-major order array of bytes, termed the state.
			Most AES calculations are done in a particular finite field.
			AES在一个4×4列主序的字节数组上操作，称为状态。
			大多数AES的计算是在一个特定的有限域中进行的。
			For instance, 16 bytes, {byte0,byte1,......,btye15} are represented as this two-dimensional array:
			例如，16个字节，{byte0,byte1,......,btye15}被表示为这个二维阵列。
		
			(Byte data has been represented in hexadecimal 字节数据已用16进制表示)
			Byte two_dimensional_array
			{
				{0x00, 0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06, 0x07},
				{0x08, 0x09, 0x0F, 0x10},
				{0x11, 0x12, 0x13, 0x14},
			}

			The key size used for an AES cipher specifies the number of transformation rounds that convert the input, called the plaintext, into the final output, called the ciphertext. 
			The number of rounds are as follows:
			10 rounds for 128-bit keys.
			12 rounds for 192-bit keys.
			14 rounds for 256-bit keys.

			用于AES密码的密钥大小规定了将输入（称为明文）转换成最终输出（称为密文）的转换轮数。 
			轮数如下。
			128位密钥为10轮。
			192位密钥的12轮。
			256位密钥的14轮。

		Paper: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

		High-level description of the algorithm(密码器算法的高级说明):

			1.Key Expansion (密钥的扩展):
			Round keys are derived from the cipher key using the AES key schedule.
			AES requires a separate 128-bit round key block for each round plus one more.
			每一轮的子密钥都是使用AES的密钥计划从主密码密钥衍生出来的
			AES要求每一轮都有一个单独的128位比特的每轮密钥块，再加一个。

			2.Initial(1) round key addition (添加首轮密钥):

				2-1.AddRoundKey:
				Each byte of the state is combined with a byte of the round key using bitwise exclusive-OR operation.
				状态的每一个字节都与圆周率密钥的一个字节用按比特单位的异或运算结合起来。

			3.9,11 or 13 rounds (9、11或13轮):

				3-1.SubBytes:
				A non-linear substitution step where each byte is replaced with another according to a lookup table.
				一个非线性替换步骤，每个字节根据一个查找表被替换成另一个字节。

				3-2 ShiftRows:
				A transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
				转位步骤，状态的最后三行被循环地移位一定的步数。

				3-3: MixColumns:
				A linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
				一个线性混合操作，对状态的列进行操作，将每一列中的四个字节合并。

				3-4: 
					Execute 2-1 operation
					执行2-1 操作
			4.Final round (making 10, 12 or 14 rounds in total) 最后一轮（总共有10轮、12轮或14轮）:
				4-1: 
					Execute 3-1 operation
					执行3-1 操作
				4-2: 
					Execute 3-2 operation
					执行3-2 操作
				4-3: 
					Execute 2-1 operation
					执行2-1 操作
	*/

	class Worker
	{
	
	private:
		
		const std::size_t ONE_WORD_BYTE_SIZE = 4;
		
		//The number of 32-bit words comprising the plaintext and columns comprising the state matrix of an AES cipher.
		//Paper content: Number of columns (32-bit words) comprising the State. For this standard, Nb = 4. (Also see Sec. 6.3.)
		//Nb is block word size
		const std::size_t NUMBER_DATA_BLOCK_COUNT = 4;
		
		//The number of 32-bit words comprising the cipher key in this AES cipher.
		//Paper content: Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4, 6, or 8. (Also see Sec. 6.3.) 
		//Nk is key word size
		std::size_t Number_Key_Data_Block_Size = 0;
		
		//The number of rounds in this AES cipher.
		//Paper content: Number of rounds, which is a function of Nk and Nb (which is fixed). For this standard, Nr = 10, 12, or 14. (Also see Sec. 6.3.) 
		//Nr is * of rounds
		std::size_t Number_Execute_Round_Count = 0;
		
		unsigned char Number_Block_Data_Byte_Size = 0;
		
		std::vector<unsigned char> EncryptBlockData(const std::vector<unsigned char>& byteData, const std::vector<unsigned char>& expandedWordRoundKeyBlock)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			if(byteData.size() == GetBlockSize_DataByte() && expandedWordRoundKeyBlock.size() == GetBlockSize_ExpandedKeyByte())
			{
				std::vector<unsigned char> encryptedByteDataBlock(byteData.size());
				
				std::array<std::array<unsigned char, 4>, 4> currentStateBlock
				{
					{
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 }
					},
				};
				
				unsigned int row = 0, column = 0;
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						stateBlockContent.operator[](column) = byteData.operator[](row + 4 * column);
					}
					++row;
				}
				row = 0, column = 0;
				
				// ROUND: 0
				AddRoundKey(currentStateBlock, expandedWordRoundKeyBlock.begin());
				
				// ROUNDS: 1 ~ NRound-1
				for (unsigned int round = 1; round <= this->Number_Execute_Round_Count - 1; ++round)
				{
					SubtituteBytes(currentStateBlock);
					ShiftRows(currentStateBlock);
					MixColumns(currentStateBlock);
					
					AddRoundKey(currentStateBlock, expandedWordRoundKeyBlock.begin() + round * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				}
				
				// ROUND: NRound
				SubtituteBytes(currentStateBlock);
				ShiftRows(currentStateBlock);
				
				AddRoundKey(currentStateBlock, expandedWordRoundKeyBlock.begin() + this->Number_Execute_Round_Count * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						encryptedByteDataBlock.operator[](row + 4 * column) = stateBlockContent.operator[](column);
					}
					++row;
				}
				row = 0, column = 0;
				
				return encryptedByteDataBlock;
			}
			else
			{
				throw std::length_error("");
			}
		}

		std::vector<unsigned char> DecryptBlockData(const std::vector<unsigned char>& byteData, const std::vector<unsigned char>& expandedWordRoundKeyBlock)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			if(byteData.size() == GetBlockSize_DataByte() && expandedWordRoundKeyBlock.size() == GetBlockSize_ExpandedKeyByte())
			{
				std::vector<unsigned char> decryptedByteDataBlock(byteData.size());
				
				std::array<std::array<unsigned char, 4>, 4> currentStateBlock
				{
					{
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 },
						{ 0, 0, 0, 0 }
					},
				};
				
				unsigned int row = 0, column = 0;
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						stateBlockContent.operator[](column) = byteData.operator[](row + 4 * column);
					}
					++row;
				}
				row = 0, column = 0;
				
				// INVERSE ROUND: NRound
				AddRoundKey(currentStateBlock, expandedWordRoundKeyBlock.begin() + this->Number_Execute_Round_Count * 4 * this->NUMBER_DATA_BLOCK_COUNT);
				
				// INVERSE ROUNDS: NRound-1 ~ 1
				for (unsigned int round = this->Number_Execute_Round_Count - 1; round >= 1; --round)
				{
					InverseSubtituteBytes(currentStateBlock);
					InverseShiftRows(currentStateBlock);
					
					AddRoundKey(currentStateBlock, expandedWordRoundKeyBlock.begin() + round * 4 * this->NUMBER_DATA_BLOCK_COUNT);
					
					InverseMixColumns(currentStateBlock);
				}
				
				// INVERSE ROUND: 0
				InverseSubtituteBytes(currentStateBlock);
				InverseShiftRows(currentStateBlock);
				
				AddRoundKey(currentStateBlock, expandedWordRoundKeyBlock.begin());
				
				for(auto& stateBlockContent : currentStateBlock )
				{
					for(column = 0; column < this->NUMBER_DATA_BLOCK_COUNT; ++column)
					{
						decryptedByteDataBlock.operator[](row + 4 * column) = stateBlockContent.operator[](column);
					}
					++row;
				}
				row = 0, column = 0;
				
				return decryptedByteDataBlock;
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			KEY SCHEDULING
			https://en.wikipedia.org/wiki/AES_key_schedule
			https://autonome-antifa.org/IMG/pdf/Rijndael.pdf
		*/
		void KeyExpansion(const std::vector<unsigned char>& byteKeys, std::vector<unsigned char>& expandedRoundKeys)
		{
			using namespace AES::DefineConstants;
			using namespace AES::ProcedureFunctions;
			
			//Key schedule round
			unsigned int round = this->Number_Execute_Round_Count + 1;
			
			expandedRoundKeys.resize(this->ONE_WORD_BYTE_SIZE * this->NUMBER_DATA_BLOCK_COUNT * round);
			
			using ByteArray4 = std::array<unsigned char, 4>;
			
			ByteArray4 temporaryWord { 0, 0, 0, 0 };
			//Round constants
			ByteArray4 RCON_Word_Data { 0, 0, 0, 0 };
			
			for(unsigned int index = 0; index < this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size; ++index)
			{
				expandedRoundKeys.operator[](index) = byteKeys.operator[](index);
			}
			
			// 同余式
			// congruent exprssion
			// a ≡ b (mod m)
			
			// Definition of congruence theorem
			// An important concept in number theory.
			// Given a positive integer c
			// Two integers a and b are said to be congruent to mod c if they satisfy that a-b is divisible by m, i.e., (a-b)/c yields an integer.
			// congruence of modulo c is an equivalence of integers
			
			// 同余定理的定义
			// 数论中的重要概念。
			// 给定一个正整数c
			// 如果两个整数a和b满足a-b能够被m整除，即(a-b)/c得到一个整数，那么就称整数a与b对模c同余。
			// 对模c同余是整数的一个等价关系
			
			//N是论文内容中的变量Nk（KeyWordSize）。
			//N is the variable Nk (KeyWordSize) from the paper content.
			
			//Index_Round是密钥安排轮次的索引
			//Index_Round is the index of the key schedule round
			
			for(unsigned int index_round = this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size; index_round < this->ONE_WORD_BYTE_SIZE * this->NUMBER_DATA_BLOCK_COUNT * round; index_round += 4)
			{
				temporaryWord.operator[](0) = expandedRoundKeys.operator[](index_round - 4 + 0);
				temporaryWord.operator[](1) = expandedRoundKeys.operator[](index_round - 4 + 1);
				temporaryWord.operator[](2) = expandedRoundKeys.operator[](index_round - 4 + 2);
				temporaryWord.operator[](3) = expandedRoundKeys.operator[](index_round - 4 + 3);
				
				//Condition 1: N ≤ 6
				//Code: this->NKeyWordSize <= 6
				//Condition 2: index ≡ 0 ( modulo N )
				//Condition 1 And Condition 2
				//Code: index_round % this->NKeyWordSize == 0
				if(index_round / 4 % this->Number_Key_Data_Block_Size == 0)
				{
					KeyWordAES_LeftRotate(temporaryWord);
					KeyWordAES_Subtitute(temporaryWord);
					RCON(RCON_Word_Data, index_round / (this->ONE_WORD_BYTE_SIZE * this->Number_Key_Data_Block_Size));
					
					ByteArray4 temporaryWord2 { 0, 0, 0, 0 };
					
					for (int indexByte = 0; indexByte < 4; ++indexByte)
					{
						temporaryWord2[indexByte] = temporaryWord[indexByte] ^ RCON_Word_Data[indexByte];
					}
					
					temporaryWord = temporaryWord2;
				}
				
				//Condition 1: N ＞ 6
				//Code: this->NKeyWordSize > 6
				//Condition 2: index ≡ 4 ( modulo N )
				//Condition 1 Or Condition 2
				//Code: ((index_round - 4) % this->NKeyWordSize) == 0
				else if(this->Number_Key_Data_Block_Size > 6 && index_round / 4 % this->Number_Key_Data_Block_Size == 4)
				{
					KeyWordAES_Subtitute(temporaryWord);
				}
				
				expandedRoundKeys.operator[](index_round + 0) = expandedRoundKeys.operator[](index_round + 0 - 4 * this->Number_Key_Data_Block_Size) ^ temporaryWord.operator[](0);
				expandedRoundKeys.operator[](index_round + 1) = expandedRoundKeys.operator[](index_round + 1 - 4 * this->Number_Key_Data_Block_Size) ^ temporaryWord.operator[](1);
				expandedRoundKeys.operator[](index_round + 2) = expandedRoundKeys.operator[](index_round + 2 - 4 * this->Number_Key_Data_Block_Size) ^ temporaryWord.operator[](2);
				expandedRoundKeys.operator[](index_round + 3) = expandedRoundKeys.operator[](index_round + 3 - 4 * this->Number_Key_Data_Block_Size) ^ temporaryWord.operator[](3);
			}
			
			memory_set_no_optimize_function(temporaryWord.data(), 0x00, temporaryWord.size());
		}

		void DataPaddingWithZeroByte(std::vector<unsigned char>& data)
		{
			const std::vector<unsigned char> ZeroByteDatas(this->Number_Block_Data_Byte_Size, static_cast<unsigned char>(0x00));
			data.insert(data.end(), ZeroByteDatas.begin(), ZeroByteDatas.end());
		}

		//PKCS is Public Key Cryptography Standards
		/*
			https://en.wikipedia.org/wiki/Padding_(cryptography)
			https://datatracker.ietf.org/doc/html/rfc5652
			PKCS#7 is described in RFC 5652. (section-6.3)

			Padding is in whole bytes.
			The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
			The number of bytes added will depend on the block boundary to which the message needs to be extended. 
		*/
		void DataPaddingWithPKCS7(std::vector<unsigned char>& data, const unsigned int NeedPaddingSize)
		{
			unsigned int NeedLoopSaltCout = static_cast<unsigned int>(this->Number_Block_Data_Byte_Size);

			std::random_device RandomDevice;
			CommonSecurity::RNG_Xoshiro::xoshiro256 RandomNumberGenerator(CommonSecurity::GenerateSecureRandomNumberSeed<unsigned int>(RandomDevice));
			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution RandomNumberDistribution(0, 255);

			//Random Salt Data
			while (NeedLoopSaltCout > 0)
			{
				data.push_back(static_cast<unsigned char>(RandomNumberDistribution(RandomNumberGenerator)));
				--NeedLoopSaltCout;
			}

			//Same PKCS7 Data
			const std::vector<unsigned char> SameByteDatas(static_cast<unsigned char>(NeedPaddingSize), NeedPaddingSize);
			data.insert(data.end(), SameByteDatas.begin(), SameByteDatas.end());
		}

		void DataUnpaddingWithZeroByte(std::vector<unsigned char>& data)
		{
			auto SearchHasBeenFoundSubrange = std::ranges::search_n(data.end() - this->Number_Block_Data_Byte_Size * 2, data.end(), this->Number_Block_Data_Byte_Size, static_cast<unsigned char>(0x00));
				
			if(SearchHasBeenFoundSubrange.begin() != SearchHasBeenFoundSubrange.end())
			{
				data.erase(SearchHasBeenFoundSubrange.begin(), SearchHasBeenFoundSubrange.end());
			}
			else
			{
				throw std::logic_error("Operation failed, maybe the padding data was corrupted?");
			}
		}

		//PKCS is Public Key Cryptography Standards
		/*
			https://en.wikipedia.org/wiki/Padding_(cryptography)
			https://datatracker.ietf.org/doc/html/rfc5652
			PKCS#7 is described in RFC 5652. (section-6.3)

			Padding is in whole bytes.
			The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
			The number of bytes added will depend on the block boundary to which the message needs to be extended. 
		*/
		void DataUnpaddingWithPKCS7(std::vector<unsigned char>& data, const unsigned int NeedUnpaddingSize)
		{
			//Same PKCS7 Data
			auto SearchHasBeenFoundSubrange = std::ranges::search_n(data.end() - NeedUnpaddingSize * 2, data.end(), NeedUnpaddingSize, static_cast<unsigned char>(NeedUnpaddingSize));
				
			if(SearchHasBeenFoundSubrange.begin() != SearchHasBeenFoundSubrange.end())
			{
				data.erase(SearchHasBeenFoundSubrange.begin(), SearchHasBeenFoundSubrange.end());
			}
			else
			{
				throw std::logic_error("Operation failed, maybe the padding data was corrupted?");
			}

			//Random Salt Data
			data.erase(data.end() - Number_Block_Data_Byte_Size, data.end());
		}

		void DataPadding(std::vector<unsigned char>& inputPlainData)
		{
            auto lambda_ShouldPaddingAndCalculationSize = [this](unsigned int currentDataByteSize) -> std::tuple<bool, unsigned int>
            {
				if(currentDataByteSize < this->Number_Block_Data_Byte_Size)
				{
					std::size_t result = this->Number_Block_Data_Byte_Size - currentDataByteSize;
					return std::tuple<bool, unsigned int>(true, result);
				}
				else
				{
					std::size_t sizeRemainderWithPadding = currentDataByteSize % this->Number_Block_Data_Byte_Size;
					if(sizeRemainderWithPadding != 0)
					{
						/* number of bytes to be appended */
						std::size_t result = this->Number_Block_Data_Byte_Size - sizeRemainderWithPadding;

						return std::tuple<bool, unsigned int>(true, result);
					}
					else
					{
						return std::tuple<bool, unsigned int>(false, this->Number_Block_Data_Byte_Size);
					}
				}
            };

			auto [DataBlockIsNeedPadding, NeedPaddingDataSize] = lambda_ShouldPaddingAndCalculationSize(inputPlainData.size());
			
			if(DataBlockIsNeedPadding)
			{
				DataPaddingWithPKCS7(inputPlainData, NeedPaddingDataSize);
			}
			else
			{
				DataPaddingWithZeroByte(inputPlainData);
			}
		}

		void DataUnpadding(std::vector<unsigned char>& outputPlainData)
		{
			unsigned int PaddedIsByteZeroCounter = 0;
			unsigned int PaddedIsNotByteZeroCounter = 0;

			if
			(
				*(outputPlainData.rbegin()) != static_cast<unsigned char>(0x00) 
				&& *(outputPlainData.rbegin() + 1) != static_cast<unsigned char>(0x00)
				&& *(outputPlainData.rbegin()) == *(outputPlainData.rbegin() + 1)
			)
			{
				PaddedIsNotByteZeroCounter += 2;

				//也许这种填充过的数据，是来自(PKSC7+盐数据)的填充方式，然后生成的函数结果？
				//Maybe this padded data is from the way (PKSC7+salt data) is padded and then the function result is generated?
				const unsigned char WithPKCS7_Paded_Value = outputPlainData.back();

				for(std::vector<unsigned char>::const_reverse_iterator constant_rbegin = outputPlainData.crbegin() + 2, constant_end = outputPlainData.crbegin() + WithPKCS7_Paded_Value * 2; constant_rbegin != constant_end; ++constant_rbegin)
				{
					if(*constant_rbegin == WithPKCS7_Paded_Value)
					{
						const unsigned char& foundValue = *constant_rbegin;

						++PaddedIsNotByteZeroCounter;

						while(PaddedIsNotByteZeroCounter != static_cast<unsigned int>(WithPKCS7_Paded_Value))
						{
							auto foundValue2 = *constant_rbegin;

							if(foundValue == foundValue2)
							{
								++PaddedIsNotByteZeroCounter;
								++constant_rbegin;
							}
							else
							{
								goto DoNotLoop;
							}
						}

						DoNotLoop:

						if(PaddedIsNotByteZeroCounter == static_cast<unsigned int>(WithPKCS7_Paded_Value))
						{
							break;
						}
						else
						{
							//哦，不，这不是一个有效的填充数据块。
							//Oh no, this is not a valid padded data block!

							PaddedIsByteZeroCounter = 0;
							PaddedIsNotByteZeroCounter = 0;
							break;
						}
					}
					else
					{
						break;
					}
				}
			}
			else
			{
				PaddedIsByteZeroCounter = this->Number_Block_Data_Byte_Size;
			}

			if(PaddedIsNotByteZeroCounter > 0 && PaddedIsNotByteZeroCounter < this->Number_Block_Data_Byte_Size && PaddedIsByteZeroCounter == 0)
			{
				DataUnpaddingWithPKCS7(outputPlainData, PaddedIsNotByteZeroCounter);
			}
			else if(PaddedIsByteZeroCounter == this->Number_Block_Data_Byte_Size && PaddedIsNotByteZeroCounter == 0)
			{
				//哦，我已经确定这个填充数据的结果是来自经典的填充方法，即用 "0" 填充数据。
				//Oh, I have determined that this padding data results from the classic padding method of filling the data with "0".
				DataUnpaddingWithZeroByte(outputPlainData);
			}
			else
			{
				//Try unpadding filled data, A fatal error has occurred 
				throw std::logic_error("Although after the previous encryption step, arbitrary data was padded to ensure data alignment; now when you try to remove the padded arbitrary data after the completion of the decryption step, a serious logic error occurs and your data cannot be recovered.");
			}
		}

	public:

		const unsigned char GetBlockSize_DataByte() const
		{
			return this->Number_Block_Data_Byte_Size;
		}

		const std::size_t GetBlockSize_KeyByte() const
		{
			return this->Number_Key_Data_Block_Size * this->ONE_WORD_BYTE_SIZE;
		}

		const std::size_t GetBlockSize_ExpandedKeyByte()
		{
			return this->ONE_WORD_BYTE_SIZE * this->NUMBER_DATA_BLOCK_COUNT * (this->Number_Execute_Round_Count + 1);
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
		* @param in; Plain text to encrypt (std::deque<Byte>).
		* @param key; AES encryption key (std::deque<Byte>).
		* @param out; The result of AES encryption (std::deque<Byte>).
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithECB(const std::vector<unsigned char>& input, const std::vector<unsigned char>& key, std::vector<unsigned char>& output)
		{
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if(key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if(input.empty())
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			DataPadding(data_copy_input);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->EncryptBlockData(inputDataSubrange, expandedWordRoundKeyBlock);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
			}
			
			memory_set_no_optimize_function(data_copy_input.data(), 0x00, data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
						return true;
		}

		/**
		* Decrypt input cipher text with an AES key in ECB Mode.
		*
		* @param in; Cipher text to decrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES decryption (deque<Byte>).
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithECB(const std::vector<unsigned char>& input, const std::vector<unsigned char>& key, std::vector<unsigned char>& output)
		{
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty() || (input.size() % this->Number_Block_Data_Byte_Size != 0))
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->DecryptBlockData(inputDataSubrange, expandedWordRoundKeyBlock);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
			}
			
			DataUnpadding(output);
			
			memory_set_no_optimize_function(data_copy_input.data(), 0x00, data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
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
		* @param in; Plain text to encrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES encryption (deque<Byte>).
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithCBC(const std::vector<unsigned char>& input, const std::vector<unsigned char>& key, const std::vector<unsigned char>& initialVector, std::vector<unsigned char>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != this->Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			DataPadding(data_copy_input);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<unsigned char> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, inputDataSubrange, initialVectorBlock, this->Number_Block_Data_Byte_Size);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock);
				
				initialVectorBlock = outputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
				
				//The initial vector data for the next(forward) round is the output data
				//下一轮的初始向量数据是输出数据
			}

			memory_set_no_optimize_function(data_copy_input.data(), 0x00,  data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(initialVectorBlock.data(), 0x00, initialVectorBlock.size());
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in CBC Mode.
		*
		* @param in; Cipher text to decrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES decryption (deque<Byte>).
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithCBC(const std::vector<unsigned char>& input, const std::vector<unsigned char>& key, const std::vector<unsigned char>& initialVector, std::vector<unsigned char>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty() || (input.size() % this->Number_Block_Data_Byte_Size != 0))
				return false;
			if (initialVector.size() != this->Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<unsigned char> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->DecryptBlockData(inputDataSubrange, expandedWordRoundKeyBlock);
				
				//The initial vector data for the previous(backward) round is the input data
				//上一轮的初始向量数据是输入数据
				
				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, outputDataSubrange, outputDataSubrange, this->Number_Block_Data_Byte_Size);
				
				initialVectorBlock = inputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}
			
			DataUnpadding(output);
			
			memory_set_no_optimize_function(data_copy_input.data(), 0x00,  data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(initialVectorBlock.data(), 0x00, initialVectorBlock.size());
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
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
		* @param in; Plain text to encrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES encryption (deque<Byte>).
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithPCBC(const std::vector<unsigned char>& input, const std::vector<unsigned char>& key, const std::vector<unsigned char>& initialVector, std::vector<unsigned char>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != this->Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			DataPadding(data_copy_input);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<unsigned char> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				AES_ExclusiveOR_ByteDataBlock(initialVectorBlock, inputDataSubrange, initialVectorBlock, this->Number_Block_Data_Byte_Size);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock);
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, initialVectorBlock, this->Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
				
				//The initial vector data for the next(forward) round is the output data
				//下一轮的初始向量数据是输出数据
			}
			
			memory_set_no_optimize_function(data_copy_input.data(), 0x00,  data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(initialVectorBlock.data(), 0x00, initialVectorBlock.size());
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in PCBC Mode.
		*
		* @param in; Cipher text to decrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES decryption (deque<Byte>).
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithPCBC(const std::vector<unsigned char>& input, const std::vector<unsigned char>& key, const std::vector<unsigned char>& initialVector, std::vector<unsigned char>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty() || (input.size() % this->Number_Block_Data_Byte_Size != 0))
				return false;
			if (initialVector.size() != this->Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<unsigned char> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->DecryptBlockData(inputDataSubrange, expandedWordRoundKeyBlock);
				
				AES_ExclusiveOR_ByteDataBlock(outputDataSubrange, initialVectorBlock, outputDataSubrange, this->Number_Block_Data_Byte_Size);
				
				//The initial vector data for the previous(backward) round is the input data
				//上一轮的初始向量数据是输入数据
				
				AES_ExclusiveOR_ByteDataBlock(outputDataSubrange, inputDataSubrange, initialVectorBlock, this->Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}
			
			DataUnpadding(output);
			
			memory_set_no_optimize_function(data_copy_input.data(), 0x00,  data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(initialVectorBlock.data(), 0x00, initialVectorBlock.size());
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
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
		* @param in; Plain text to encrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES encryption (deque<Byte>).
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/			
		bool EncryptionWithCFB(std::vector<unsigned char> input, const std::vector<unsigned char>& key, std::vector<unsigned char> initialVector, std::vector<unsigned char>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != this->Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			DataPadding(data_copy_input);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<unsigned char> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock);
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, this->Number_Block_Data_Byte_Size);
				
				initialVectorBlock = outputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			memory_set_no_optimize_function(data_copy_input.data(), 0x00,  data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(initialVectorBlock.data(), 0x00, initialVectorBlock.size());
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in CFB Mode.
		*
		* @param in; Cipher text to decrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES decryption (deque<Byte>).
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithCFB(std::vector<unsigned char> input, const std::vector<unsigned char>& key, std::vector<unsigned char> initialVector, std::vector<unsigned char>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != this->Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<unsigned char> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock);
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, this->Number_Block_Data_Byte_Size);
				
				initialVectorBlock = inputDataSubrange;
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			memory_set_no_optimize_function(data_copy_input.data(), 0x00,  data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(initialVectorBlock.data(), 0x00, initialVectorBlock.size());
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			

			DataUnpadding(output);

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
		* @param in; Plain text to encrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES encryption (deque<Byte>).
		* @return Encryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool EncryptionWithOFB(std::vector<unsigned char> input, const std::vector<unsigned char>& key, std::vector<unsigned char> initialVector, std::vector<unsigned char>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != this->Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			DataPadding(data_copy_input);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<unsigned char> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock);
				
				initialVectorBlock = outputDataSubrange;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, this->Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			memory_set_no_optimize_function(data_copy_input.data(), 0x00,  data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(initialVectorBlock.data(), 0x00, initialVectorBlock.size());
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			return true;
		}

		/**
		* Decrypt input cipher text with an AES key in OFB Mode.
		*
		* @param in; Cipher text to decrypt (deque<Byte>).
		* @param key; AES encryption key (deque<Byte>).
		* @param out; The result of AES decryption (deque<Byte>).
		* @return Decryption result as boolean (true: SUCCESS; false: FAILED).
		*/
		bool DecryptionWithOFB(std::vector<unsigned char> input, const std::vector<unsigned char>& key, std::vector<unsigned char> initialVector, std::vector<unsigned char>& output)
		{
			using namespace AES::ProcedureFunctions;
			
			if(this->Number_Key_Data_Block_Size == 0 && this->Number_Execute_Round_Count == 0)
			{
				this->Number_Key_Data_Block_Size = key.size() / 4;
				this->Number_Execute_Round_Count = this->Number_Key_Data_Block_Size + 6;
			}
			
			if (key.size() != this->Number_Key_Data_Block_Size * 4)
				return false;
			if (input.empty())
				return false;
			if (initialVector.size() != this->Number_Block_Data_Byte_Size)
				return false;
			
			std::vector<unsigned char> data_copy_input(input.begin(), input.end());
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);
			
			auto iteratorBegin_input = data_copy_input.begin();
			auto iteratorEnd_input = data_copy_input.end();
			
			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();
			
			std::vector<unsigned char> initialVectorBlock(initialVector);
			
			for (std::size_t index = 0; index < data_copy_input.size(); index += this->Number_Block_Data_Byte_Size)
			{
				std::size_t iteratorOffset = this->Number_Block_Data_Byte_Size;
				std::size_t iteratorOffset2 = this->Number_Block_Data_Byte_Size;
				
				//数据必须复制到这里，不要移动它!
				//The data must be copied here, don't move it!
				auto inputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_input, iteratorEnd_input, iteratorOffset, true);
				auto outputDataSubrange = CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(iteratorBegin_output, iteratorEnd_output, iteratorOffset2, true);
				
				//The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				outputDataSubrange = this->EncryptBlockData(initialVectorBlock, expandedWordRoundKeyBlock);
				
				initialVectorBlock = outputDataSubrange;
				
				AES_ExclusiveOR_ByteDataBlock(inputDataSubrange, outputDataSubrange, outputDataSubrange, this->Number_Block_Data_Byte_Size);
				
				output.insert(output.end(), outputDataSubrange.begin(), outputDataSubrange.end());
				
				inputDataSubrange.clear();
				outputDataSubrange.clear();
			}

			memory_set_no_optimize_function(data_copy_input.data(), 0x00,  data_copy_input.size());
			data_copy_input.clear();
			data_copy_input.shrink_to_fit();
			memory_set_no_optimize_function(initialVectorBlock.data(), 0x00, initialVectorBlock.size());
			initialVectorBlock.clear();
			initialVectorBlock.shrink_to_fit();
			memory_set_no_optimize_function(expandedWordRoundKeyBlock.data(), 0x00, expandedWordRoundKeyBlock.size());
			expandedWordRoundKeyBlock.clear();
			expandedWordRoundKeyBlock.shrink_to_fit();
			
			DataUnpadding(output);

			return true;
		}

		Worker(AES_SecurityLevel SecurityLevel) : Number_Block_Data_Byte_Size(this->ONE_WORD_BYTE_SIZE * this->NUMBER_DATA_BLOCK_COUNT * sizeof(unsigned char))
		{
			switch (SecurityLevel)
			{
				case CommonSecurity::AES::AES_SecurityLevel::ZERO:
				{
					this->Number_Key_Data_Block_Size = 4;
					this->Number_Execute_Round_Count = 10;
					break;
				}
				case CommonSecurity::AES::AES_SecurityLevel::ONE:
				{
					this->Number_Key_Data_Block_Size = 6;
					this->Number_Execute_Round_Count = 12;
					break;
				}
				case CommonSecurity::AES::AES_SecurityLevel::TWO:
				{
					this->Number_Key_Data_Block_Size = 8;
					this->Number_Execute_Round_Count = 14;
					break;
				}
				default:
				{
					std::cout << "Wrong AES Algorithm security level is selected !" << std::endl;
					abort();
					break;
				}
			}
		}

		~Worker() = default;

		Worker(Worker& _object) = delete;
		Worker& operator=(const Worker& _object) = delete;
	
	};
}

/*
	
	Paper: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf
	
*/
namespace CommonSecurity::TripleDES
{
	using ExperimentalWorker = CommonSecurity::TripleDES::ProcedureFunctions::Worker<true>;
	using OfficialWorker = CommonSecurity::TripleDES::ProcedureFunctions::Worker<false>;
	using CommonSecurity::TripleDES::ProcedureFunctions::TripleDES_Executor;
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

	template<class Type>
	class Worker : ProcedureFunctions::BaseInterface<Type>
	{

	private:

		//Number of half-rounds
		//Encryption/Decryption consists of a non-negative number of rounds (Based on security estimates)
		Type RC6_CRYPTION_ROUND_NUMBER;

		//Specific to RC6, we have removed the BYTE *KS and added in an array of 2+2*ROUNDS+2 = 44 rounds to hold the key schedule/
		//Default iteration limit for key scheduling
		size_t DEFAULT_ITERATION_LIMIT;

		//The size of data word from bits
		const Type RC6_WORD_DATA_BIT_SIZE;

		//Math exprssion
		//static_cast<signed long long>(std::pow(2, RC6_WORD_DATA_BIT_SIZE))
		const Type LOG2_WORD_DATA_BIT_SIZE;

		//16bit: 0xB7E1, 32bit: 0xB7E15163
		const Type MAGIC_NUMBER_P;
		
		//16bit: 0x9E37. 32bit: 0x9E3779B9
		const Type MAGIC_NUMBER_Q;

		void KeySchedule(std::span<const unsigned char>& keySpan, std::span<Type>& keyScheduleBoxSpan)
		{
			// Copy key to not modify original
			std::vector<unsigned char> key_copy { keySpan.begin(), keySpan.end() };
			// key_bit_len called b from RC6 paper
			const std::size_t key_bit_size = key_copy.size() * 8;

			my_cpp2020_assert(key_bit_size <= DefineConstants::KEY_BIT_SIZE_MAX_LIMIT && key_bit_size % 16 == 0, "The byte size of the RC6 key must be in the range of 1 to 255, and the key byte size must be a multiple of 16!\n", std::source_location::current());

			// Pad to word length
			while (key_copy.size() % sizeof(Type) != 0)
				key_copy.push_back(0);

			// total_words called c from RC6 paper
			const std::size_t total_words = key_copy.size() / sizeof(Type);

			// least_word_key called L from RC6 paper
			Type* least_word_key = reinterpret_cast<Type*>(key_copy.data());

			// Ensure bytes are loaded little endian
			if (ProcedureFunctions::is_big_endian())
				for (std::size_t index = 0; index < total_words; ++index)
					least_word_key[index] = ProcedureFunctions::SwapEndian(least_word_key[index]);

			// number_iterations called v from RC6 paper
			const std::size_t number_iterations = 3 * std::max( static_cast<Type>(total_words), static_cast<Type>(this->DEFAULT_ITERATION_LIMIT) );
			Type schedule_index = 0, word_index = 0;

			// Create initial schedule
			keyScheduleBoxSpan[0] = this->MAGIC_NUMBER_P;
			for (schedule_index = 1; schedule_index <= 2 * this->RC6_CRYPTION_ROUND_NUMBER + 3; ++schedule_index)
			{
				keyScheduleBoxSpan[schedule_index] = keyScheduleBoxSpan[schedule_index - 1] + this->MAGIC_NUMBER_Q;
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
				least_word_key[word_index] = ProcedureFunctions::LeftRotateBit(least_word_key[word_index] + AB_SumValue, AB_SumValue);
				ValueB = least_word_key[word_index];

				// Wrapped indices for schedule/little endian word key
				schedule_index = (schedule_index + 1) % this->DEFAULT_ITERATION_LIMIT;
				word_index = (word_index + 1) % total_words;
			}

			memory_set_no_optimize_function(key_copy.data(), 0x00, key_copy.size());
		}

		void Encryption(std::vector<unsigned char>& dataBlock, const std::vector<unsigned char>& keyBlock) override
		{
			// Set up word-sized 'registers'
			Type* block_worlds = reinterpret_cast<Type*>(dataBlock.data());
			Type& ValueA = block_worlds[0];
			Type& ValueB = block_worlds[1];
			Type& ValueC = block_worlds[2];
			Type& ValueD = block_worlds[3];

			// Create schedule
			// schedule called S from RC6 paper
			std::vector<Type> keyScheduleBox(this->DEFAULT_ITERATION_LIMIT);

			std::span keyBlockSpan { keyBlock.begin(), keyBlock.end() };
			std::span keyScheduleBoxSpan{ keyScheduleBox };

			// The role of S-box is to confuse (Confusion), mainly to increase the complexity between plaintext and ciphertext (including non-linearity, etc.)
			// S盒的作用是混淆(Confusion),主要增加明文和密文之间的复杂度（包括非线性度等）。
			this->KeySchedule(keyBlockSpan, keyScheduleBoxSpan);

			/* Do pseudo-round #0: pre-whitening of B and D */
			ValueB += keyScheduleBox.operator[](0);
			ValueD += keyScheduleBox.operator[](1);

			for(std::size_t index = 1; index <= this->RC6_CRYPTION_ROUND_NUMBER; ++index)
			{
				Type TemporaryValue = ValueB * (2 * ValueB + 1);
				Type TemporaryValue2 = ValueD * (2 * ValueD + 1);

				Type __t__ = ProcedureFunctions::LeftRotateBit( TemporaryValue, LOG2_WORD_DATA_BIT_SIZE );
				Type __u__ = ProcedureFunctions::LeftRotateBit( TemporaryValue2, LOG2_WORD_DATA_BIT_SIZE );

				Type TemporaryValue3 = ValueA ^ __t__;
				Type TemporaryValue4 = ValueC ^ __u__;

				ValueA = ProcedureFunctions::LeftRotateBit( TemporaryValue3, __u__ ) + keyScheduleBox.operator[](2 * index);
				ValueC = ProcedureFunctions::LeftRotateBit( TemporaryValue4, __t__ ) + keyScheduleBox.operator[](2 * index + 1);

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
			ValueA += keyScheduleBox.operator[](this->DEFAULT_ITERATION_LIMIT - 2);
			ValueC += keyScheduleBox.operator[](this->DEFAULT_ITERATION_LIMIT - 1);

			memory_set_no_optimize_function(keyScheduleBox.data(), 0x00, sizeof(Type) * keyScheduleBox.size());
		}

		void Decryption(std::vector<unsigned char>& dataBlock, const std::vector<unsigned char>& keyBlock) override
		{
			// Set up word-sized 'registers'
			Type* block_worlds = reinterpret_cast<Type*>(dataBlock.data());
			Type& ValueA = block_worlds[0];
			Type& ValueB = block_worlds[1];
			Type& ValueC = block_worlds[2];
			Type& ValueD = block_worlds[3];

			// Create schedule
			// schedule called S from RC6 paper
			std::vector<Type> keyScheduleBox(this->DEFAULT_ITERATION_LIMIT);

			std::span keyBlockSpan { keyBlock.begin(), keyBlock.end() };
			std::span keyScheduleBoxSpan{ keyScheduleBox };

			// The role of S-box is to confuse (Confusion), mainly to increase the complexity between plaintext and ciphertext (including non-linearity, etc.)
			// S盒的作用是混淆(Confusion),主要增加明文和密文之间的复杂度（包括非线性度等）。
			this->KeySchedule(keyBlockSpan, keyScheduleBoxSpan);

			/* Do pseudo-round #(ROUNDS+1): post-whitening of A and C */
			ValueC -= keyScheduleBox.operator[](this->DEFAULT_ITERATION_LIMIT - 1);
			ValueA -= keyScheduleBox.operator[](this->DEFAULT_ITERATION_LIMIT - 2);

			for(std::size_t index = this->RC6_CRYPTION_ROUND_NUMBER; index >= 1; --index)
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

				Type __u__ = ProcedureFunctions::LeftRotateBit( TemporaryValue, LOG2_WORD_DATA_BIT_SIZE );
				Type __t__ = ProcedureFunctions::LeftRotateBit( TemporaryValue2, LOG2_WORD_DATA_BIT_SIZE );

				Type TemporaryValue3 = ValueC - keyScheduleBox.operator[](2 * index + 1);
				Type TemporaryValue4 = ValueA - keyScheduleBox.operator[](2 * index);

				ValueC = ProcedureFunctions::RightRotateBit( TemporaryValue3, __t__ ) ^ __u__;
				ValueA = ProcedureFunctions::RightRotateBit( TemporaryValue4, __u__ ) ^ __t__;
			}

			/* Undo pseudo-round #0: pre-whitening of B and D */
			ValueD -= keyScheduleBox.operator[](1);
			ValueB -= keyScheduleBox.operator[](0);

			memory_set_no_optimize_function(keyScheduleBox.data(), 0x00, sizeof(Type) * keyScheduleBox.size());
		}

	public:

		std::vector<unsigned char> EncryptionECB(std::vector<unsigned char>& dataBlock, const std::vector<unsigned char>& keyBlock)
		{
			const std::size_t BLOCK_BYTE_SIZE = this->BlockByteSize();
			std::size_t offset = 0;

			std::vector<unsigned char> processedDataBlock(dataBlock.size());
			for(auto begin = dataBlock.begin(), end = dataBlock.end(); begin != end; begin += BLOCK_BYTE_SIZE, offset += BLOCK_BYTE_SIZE )
			{
				std::vector<unsigned char> dataChunkBlock { begin, begin + BLOCK_BYTE_SIZE };
				this->Encryption(dataChunkBlock, keyBlock);

				for(std::size_t index = 0; index < BLOCK_BYTE_SIZE; ++index)
				{
					processedDataBlock[offset + index] = dataChunkBlock[index];
				}
			}

			return processedDataBlock;
		}

		std::vector<unsigned char> DecryptionECB(std::vector<unsigned char>& dataBlock, const std::vector<unsigned char>& keyBlock)
		{
			const std::size_t BLOCK_BYTE_SIZE = this->BlockByteSize();
			std::size_t offset = 0;

			std::vector<unsigned char> processedDataBlock(dataBlock.size());
			for(auto begin = dataBlock.begin(), end = dataBlock.end(); begin != end; begin += BLOCK_BYTE_SIZE, offset += BLOCK_BYTE_SIZE )
			{
				std::vector<unsigned char> dataChunkBlock { begin, begin + BLOCK_BYTE_SIZE };
				this->Decryption(dataChunkBlock, keyBlock);

				for(std::size_t index = 0; index < BLOCK_BYTE_SIZE; ++index)
				{
					processedDataBlock[offset + index] = dataChunkBlock[index];
				}
			}

			return processedDataBlock;
		}

		std::vector<unsigned char> EncryptionCBC(std::vector<unsigned char>& dataBlock, const std::vector<unsigned char>& keyBlock, const std::vector<unsigned char>& initialVector)
		{
			my_cpp2020_assert(initialVector.size() % 16 == 0, "The initial vector data size must be a multiple of 16!\n", std::source_location::current());

			const std::size_t BLOCK_BYTE_SIZE = this->BlockByteSize();
			std::size_t offset = 0;

			for(std::size_t index = 0; index < initialVector.size(); ++index)
			{
				dataBlock[index] ^= initialVector[index];
			}

			std::vector<unsigned char> processedDataBlock(dataBlock.size());
			for(auto begin = dataBlock.begin(), end = dataBlock.end(); begin != end; begin += BLOCK_BYTE_SIZE, offset += BLOCK_BYTE_SIZE )
			{
				std::vector<unsigned char> dataChunkBlock { begin, begin + BLOCK_BYTE_SIZE };
				this->Encryption(dataChunkBlock, keyBlock);

				for(std::size_t index = 0; index < BLOCK_BYTE_SIZE; ++index)
				{
					processedDataBlock[offset + index] = dataChunkBlock[index];
				}
			}

			return processedDataBlock;
		}

		std::vector<unsigned char> DecryptionCBC(std::vector<unsigned char>& dataBlock, const std::vector<unsigned char>& keyBlock, const std::vector<unsigned char>& initialVector)
		{
			my_cpp2020_assert(initialVector.size() % 16 == 0, "The initial vector data size must be a multiple of 16!\n", std::source_location::current());

			const std::size_t BLOCK_BYTE_SIZE = this->BlockByteSize();
			std::size_t offset = 0;

			std::vector<unsigned char> processedDataBlock(dataBlock.size());
			for(auto begin = dataBlock.begin(), end = dataBlock.end(); begin != end; begin += BLOCK_BYTE_SIZE, offset += BLOCK_BYTE_SIZE )
			{
				std::vector<unsigned char> dataChunkBlock { begin, begin + BLOCK_BYTE_SIZE };
				this->Decryption(dataChunkBlock, keyBlock);

				for(std::size_t index = 0; index < BLOCK_BYTE_SIZE; ++index)
				{
					processedDataBlock[offset + index] = dataChunkBlock[index];
				}
			}

			for(std::size_t index = 0; index < initialVector.size(); ++index)
			{
				processedDataBlock[index] ^= initialVector[index];
			}

			return processedDataBlock;
		}

		//RC6 Algorithm <-> (W)ordSize/(R)oundNumber/(B)yteKeySize
		Worker(Type half_round = 20) : RC6_CRYPTION_ROUND_NUMBER(half_round),
			RC6_WORD_DATA_BIT_SIZE(std::numeric_limits<Type>::digits),
			DEFAULT_ITERATION_LIMIT(2 * RC6_CRYPTION_ROUND_NUMBER + 4), 
			LOG2_WORD_DATA_BIT_SIZE(std::log2(RC6_WORD_DATA_BIT_SIZE)),
			MAGIC_NUMBER_P( static_cast<Type>( std::ceil( (DefineConstants::BASE_OF_THE_NATURAL_LOGARITHM - 2) * std::pow(2, RC6_WORD_DATA_BIT_SIZE) ) ) ),
			MAGIC_NUMBER_Q( static_cast<Type>( DefineConstants::GOLDEN_RATIO * std::pow(2, RC6_WORD_DATA_BIT_SIZE) ) )
		{
			my_cpp2020_assert(this->RC6_CRYPTION_ROUND_NUMBER != 0 && this->RC6_CRYPTION_ROUND_NUMBER % 4 == 0, "RC6 ciphers perform a half round count that is invalid!", std::source_location::current());

			if constexpr(CURRENT_SYSTEM_BITS == 32)
			{
				my_cpp2020_assert(RC6_WORD_DATA_BIT_SIZE != 32, "ERROR: Trying to run 256-bit blocksize on a 32-bit CPU.\n", std::source_location::current());
			}
		}

		Worker(RC6_SecurityLevel SecurityLevel) : RC6_WORD_DATA_BIT_SIZE(std::numeric_limits<Type>::digits),
			LOG2_WORD_DATA_BIT_SIZE(std::log2(RC6_WORD_DATA_BIT_SIZE)),
			MAGIC_NUMBER_P( static_cast<Type>( std::ceil( (DefineConstants::BASE_OF_THE_NATURAL_LOGARITHM - 2) * std::pow(2, RC6_WORD_DATA_BIT_SIZE) ) ) ),
			MAGIC_NUMBER_Q( static_cast<Type>( DefineConstants::GOLDEN_RATIO * std::pow(2, RC6_WORD_DATA_BIT_SIZE) ) )
		{
			switch (SecurityLevel)
			{
				case CommonSecurity::RC6::RC6_SecurityLevel::ZERO:
					RC6_CRYPTION_ROUND_NUMBER = 20;
					break;
				case CommonSecurity::RC6::RC6_SecurityLevel::ONE:
					RC6_CRYPTION_ROUND_NUMBER = 40;
					break;
				case CommonSecurity::RC6::RC6_SecurityLevel::TWO:
					RC6_CRYPTION_ROUND_NUMBER = 60;
					break;
				default:
					break;
			}

			DEFAULT_ITERATION_LIMIT = 2 * RC6_CRYPTION_ROUND_NUMBER + 4;

			my_cpp2020_assert(this->RC6_CRYPTION_ROUND_NUMBER != 0 && this->RC6_CRYPTION_ROUND_NUMBER % 4 == 0, "RC6 ciphers perform a half round count that is invalid!", std::source_location::current());

			if constexpr(CURRENT_SYSTEM_BITS == 32)
			{
				my_cpp2020_assert(RC6_WORD_DATA_BIT_SIZE != 32, "ERROR: Trying to run 256-bit blocksize on a 32-bit CPU.\n", std::source_location::current());
			}
		}

		~Worker() = default;

		Worker(Worker& _object) = delete;
		Worker& operator=(const Worker& _object) = delete;
	};

	template<typename WordType>
	std::vector<unsigned char> RC6_Executor(CommonSecurity::RC6::Worker<WordType>& RC6_Worker, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode, const std::vector<unsigned char>& dataBlock, std::vector<unsigned char>& key)
	{
		switch (executeMode)
		{
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				auto dataBlockCopy { dataBlock };
				std::size_t dataBlockByteSize = dataBlockCopy.size();

				//PKCS is Public Key Cryptography Standards
				/*
					https://en.wikipedia.org/wiki/Padding_(cryptography)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Padding Data #5 standard
				
				if(dataBlockByteSize % 16 != 0)
				{
					if(dataBlockByteSize > 16)
					{
						std::size_t paddingDataByteSize = 16 - (dataBlockByteSize % 16);
						const std::vector<unsigned char> paddingDataBytes(paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));
						dataBlockCopy.insert( dataBlockCopy.end(), paddingDataBytes.begin(), paddingDataBytes.end() );
					}
					else if(dataBlockByteSize < 16)
					{
						std::size_t paddingDataByteSize = 16 - dataBlockByteSize;
						const std::vector<unsigned char> paddingDataBytes(paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));
						dataBlockCopy.insert( dataBlockCopy.end(), paddingDataBytes.begin(), paddingDataBytes.end() );
					}
				}
				else
				{
					const std::vector<unsigned char> paddingDataBytes(16, static_cast<unsigned char>(16));
					dataBlockCopy.insert( dataBlockCopy.end(), paddingDataBytes.begin(), paddingDataBytes.end() );
				}

				dataBlockByteSize = dataBlockCopy.size();
				if(dataBlockByteSize % 4 != 0)
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

				//PKCS is Public Key Cryptography Standards
				/*
					https://en.wikipedia.org/wiki/Padding_(cryptography)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Unpadding Data #5 standard

				unsigned int paddingDataByteSize = processedDataBlock.back();

				auto find_subrange_sized = std::ranges::search_n(processedDataBlock.end() - paddingDataByteSize * 2, processedDataBlock.end(), paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));
				if(find_subrange_sized.begin() != find_subrange_sized.end())
				{
					processedDataBlock.erase(find_subrange_sized.begin(), find_subrange_sized.end());
				}
				else
				{
					throw std::logic_error("CommonSecurity::RC6::RC6_Executor::Decryption: Operation failed, maybe the padding data, before encryption, was corrupted?");
				}

				return processedDataBlock;

				//break;
			}
			default:
			{
				std::cout << "Wrong RC6 Algorithm worker is selected" << std::endl;
				abort();
			}	
		}
	}
}