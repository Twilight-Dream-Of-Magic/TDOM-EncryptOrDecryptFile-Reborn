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

	Worker SuperTEA;
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

				using ByteArray4 = std::array<unsigned char, 4>;
				ByteArray4 ByteArray4_Object { 0, 0, 0, 0 };
				
				std::array<ByteArray4, 4> currentStateBlock
				{
					ByteArray4_Object,
					ByteArray4_Object,
					ByteArray4_Object,
					ByteArray4_Object
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

				using ByteArray4 = std::array<unsigned char, 4>;
				ByteArray4 ByteArray4_Object { 0, 0, 0, 0 };
				
				std::array<ByteArray4, 4> currentStateBlock
				{
					ByteArray4_Object,
					ByteArray4_Object,
					ByteArray4_Object,
					ByteArray4_Object
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

			CommonSecurity::RNG_Xoshiro::xoshiro256 randomNumberGeneratorByRealTime(std::chrono::system_clock::now().time_since_epoch().count());
			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution randomNumberDistribution(0, 255);

			//Random Salt Data
			while (NeedLoopSaltCout > 0)
			{
				data.push_back(static_cast<unsigned char>(randomNumberDistribution(randomNumberGeneratorByRealTime)));
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
			unsigned int NeedLoopSaltCout = static_cast<unsigned int>(this->Number_Block_Data_Byte_Size);

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
		bool EncryptionWithECB(std::vector<unsigned char> input, const std::vector<unsigned char>& key, std::vector<unsigned char>& output)
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

			DataPadding(input);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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
		bool DecryptionWithECB(std::vector<unsigned char> input, const std::vector<unsigned char>& key, std::vector<unsigned char>& output)
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
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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
		bool EncryptionWithCBC(std::vector<unsigned char> input, const std::vector<unsigned char>& key, const std::vector<unsigned char>& initialVector, std::vector<unsigned char>& output)
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
			
			DataPadding(input);

			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			std::vector<unsigned char> initialVectorBlock(initialVector);

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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
		bool DecryptionWithCBC(std::vector<unsigned char> input, const std::vector<unsigned char>& key, const std::vector<unsigned char>& initialVector, std::vector<unsigned char>& output)
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

			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			std::vector<unsigned char> initialVectorBlock(initialVector);

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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
		bool EncryptionWithPCBC(std::vector<unsigned char> input, const std::vector<unsigned char>& key, const std::vector<unsigned char>& initialVector, std::vector<unsigned char>& output)
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

			DataPadding(input);
			
			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			std::vector<unsigned char> initialVectorBlock(initialVector);

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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
		bool DecryptionWithPCBC(std::vector<unsigned char> input, const std::vector<unsigned char>& key, const std::vector<unsigned char>& initialVector, std::vector<unsigned char>& output)
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

			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			std::vector<unsigned char> initialVectorBlock(initialVector);

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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

			DataPadding(input);

			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			std::vector<unsigned char> initialVectorBlock(initialVector);

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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

			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			std::vector<unsigned char> initialVectorBlock(initialVector);

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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

			DataUnpadding(output);
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

			DataPadding(input);

			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			std::vector<unsigned char> initialVectorBlock(initialVector);

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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

			//Key data for extension
			//密钥数据进行扩展
			std::vector<unsigned char> expandedWordRoundKeyBlock;
			this->KeyExpansion(key, expandedWordRoundKeyBlock);

			auto iteratorBegin_input = input.begin();
			auto iteratorEnd_input = input.end();

			auto iteratorBegin_output = output.begin();
			auto iteratorEnd_output = output.end();

			std::vector<unsigned char> initialVectorBlock(initialVector);

			for (std::size_t index = 0; index < input.size(); index += this->Number_Block_Data_Byte_Size)
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

			DataUnpadding(output);
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

#if 0
	
namespace CommonSecurity::AES::Experimental
{
	using ByteBit = std::bitset<8>;
	using WordBit = std::bitset<32>;

	inline WordBit FourByteBitToWordBit(ByteBit key, ByteBit key2, ByteBit key3, ByteBit key4)
	{
		WordBit resultWordBit(0x00000000);
		WordBit temporaryWordBit;
		temporaryWordBit = key.to_ulong();  // K1
		temporaryWordBit <<= 24;
		resultWordBit |= temporaryWordBit;
		temporaryWordBit = key2.to_ulong();  // K2
		temporaryWordBit <<= 16;
		resultWordBit |= temporaryWordBit;
		temporaryWordBit = key3.to_ulong();  // K3
		temporaryWordBit <<= 8;
		resultWordBit |= temporaryWordBit;
		temporaryWordBit = key4.to_ulong();  // K4
		resultWordBit |= temporaryWordBit;
		return resultWordBit;
	}

	/**
		*  按字节 循环左移一位
		*  即把[byte0, byte1, byte2, byte3]变成[byte1, byte2, byte3, byte0]
		*/
	//Function used in the Key Expansion routine that takes a four-byte word and performs a cyclic permutation
	//在密钥扩展例程中使用的函数，它接收一个四字节的字并进行循环排列。
	inline WordBit KeyWordAES_LeftRotate(WordBit& word)
	{
		/*
			WordBit highBit = rw << 8;
			WordBit lowBit = rw >> 24;
			return highBit | lowBit;
		*/
		return (word << 8) | (word >> 24);
	}

	//在密钥扩展例程中使用的函数，它接收一个四字节的输入字，并对四个字节中的每个字节应用一个S-box，以产生一个输出字。
	//Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word. 
	inline WordBit KeyWordAES_Subtitute(const WordBit& word)
	{
		std::bitset<32> WordBitset;
		for(unsigned int index = 0; index < 32; index+=8)
		{
			unsigned int row = word[index+7]*8 + word[index+6]*4 + word[index+5]*2 + word[index+4];
			unsigned int column = word[index+3]*8 + word[index+2]*4 + word[index+1]*2 + word[index];
			std::bitset<8> ByteBitsetValue = Forward_S_Box[row][column];
			for(unsigned int index2 = 0; index2 < 8; ++index2)
			{
				WordBitset[index + index2] = ByteBitsetValue[index2];
			}
		}
		return WordBitset;
	}

	inline WordBit RCON(WordBit& Word, int roundCount)
	{
		//Byte data
		unsigned int word = Word.to_ulong();
		auto byte_array = std::bit_cast<std::array<unsigned char, 4>>(word);

		unsigned char constantByteForThisRound = unsigned char(1);
	
		for(unsigned char indexCount = 0; indexCount < roundCount - 1; ++indexCount)
		{
			constantByteForThisRound = XTime(constantByteForThisRound);
		}

		byte_array.operator[](0) = constantByteForThisRound;
		byte_array.operator[](1) = byte_array.operator[](2) = byte_array.operator[](3) = unsigned char(0);
		word = std::bit_cast<unsigned int>(byte_array);

		return WordBit(word);
	}

	inline ByteBit UnsignedCharacterToBitset8(unsigned char unignedCharacterData)
	{
		return ByteBit(unignedCharacterData);
	}

	inline unsigned char UnsignedCharacterFromBitset8(ByteBit bitset8)
	{
		return static_cast<unsigned char>(bitset8.to_ulong());
	}

	class ECB_Mode_Tiny128bit
	{

		private:
		// Paper content: Number of columns (32-bit words) comprising the State. For this standard, Nb = 4. (Also see
		// Sec. 6.3.) Nb is block word size
		const std::size_t NBlockWordSize = 4;

		// Paper content: Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4, 6, or 8. (Also see
		// Sec. 6.3.) Nk is key word size
		std::size_t NKeyWordSize = 4;

		// Paper content: Number of rounds, which is a function of Nk and Nb (which is fixed). For this standard, Nr = 10,
		// 12, or 14. (Also see Sec. 6.3.) Nr is * of rounds
		std::size_t NRound = 0;

		unsigned char NBlockDataByteSize = 0;

		std::vector<ByteBit> StateByteDataBlock;
		std::vector<ByteBit> BitsetKeyBlock;
		std::vector<WordBit> BitsetExpandedWordRoundKeyBlock;

		ByteBit MultiplicationOfByteWithGaloisField(ByteBit ByteA, ByteBit ByteB)
		{
			// Taken and documented from https://en.wikipedia.org/wiki/Rijndael_MixColumns

			/* Accumulator for the product of the multiplication */
			ByteBit result{0x00};
			const ByteBit moduloInnumerableMask{0x1B};
			const ByteBit highBitMask{0x80};

			for (int counter = 0; counter < 8; ++counter)
			{
				// If LSB is active (equivalent to a '1' in the polynomial of ByteB)
				/* If the polynomial for ByteB has a constant term, add the corresponding ByteA to Result */
				if ((ByteB & ByteBit{0x01}) != 0)
				{
					// result += ByteA in GF(2^8)
					/* Addition in GF(2^m) is an XOR of the polynomial coefficients */
					result ^= ByteA;
				}

				// ByteA >= 128 = 0b0100'0000
				/* GF modulo: if a has a nonzero term x^7, then must be reduced when it becomes x^8 */
				ByteBit highBit = (ByteA & highBitMask);

				// Rotate ByteA left (multiply by (?) in GF(2^8))
				ByteA <<= 1;
				if (highBit != 0)
				{
					// Must reduce
					// ByteA -= 00011011 == modulo(x^8 + x^4 + x^3 + x + 1) = AES irreducible
					/* Subtract (XOR) the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1'0001'1011) – you can change it
						* but it must be irreducible */
					ByteA ^= moduloInnumerableMask;
				}
				// Rotate ByteB right (divide by (?) in GF(2^8))
				ByteB >>= 1;
			}

			return result;
		}

		/*
			The MixColumns() transformation operates on the State column-by-column, treating each column as a four-term
			polynomial as described in Sec. 4.3. The columns are considered as polynomials over GF(2^8) and multiplied modulo
			x^4 + 1 with a fixed polynomial a(x), given by

			Mathematical equations 5.5
			a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

			Mathematical equations 5.6
			As described in Sec. 4.3, this can be written as a matrix multiplication.
			state' = a(x) (*) state(x):

			As a result of this multiplication, the four bytes in a column are replaced by the following:
			state'[0][column] = ({02} • state[0][column]) (+) ({03} • state[1][column]) (+) state[2][column] (+)
			state[3][column] state'[1][column] = state[0][column] (+) ({02} • state[1][column]) (+) ({03} • state[2][column])
			(+) state[3][column] state'[2][column] = state[0][column] (+) state[1][column] (+) ({02} • state[2][column]) (+)
			({03} • state[3][column]) state'[3][column] = ({03} • state[0][column]) (+) state[1][column] (+) state[2][column]
			(+) ({02} • state[3][column])

			MixColumns()转换对状态逐列操作，如第4.3节所述，将每一列作为一个四项多项式处理。
			这些列被视为GF(2^8)上的多项式，并与固定的多项式a(x)相乘以x^4+1，给出如下

			数学公式5.5
			a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

			数学方程5.6
			如第4.3节所述，这可以写成一个矩阵乘法。
			state' = a(x) (*) state(x)

			作为这个乘法的结果，一列中的四个字节被替换成以下内容:
			state'[0][column] = ({02} • state[0][column]) (+) ({03} • state[1][column]) (+) state[2][column] (+)
			state[3][column] state'[1][column] = state[0][column] (+) ({02} • state[1][column]) (+) ({03} • state[2][column])
			(+) state[3][column] state'[2][column] = state[0][column] (+) state[1][column] (+) ({02} • state[2][column]) (+)
			({03} • state[3][column]) state'[3][column] = ({03} • state[0][column]) (+) state[1][column] (+) state[2][column]
			(+) ({02} • state[3][column])

			In the MixColumns step, the four bytes of each column of the state are combined using an invertible linear
			transformation. The MixColumns function takes four bytes as input and outputs four bytes, where each input byte
			affects all four output bytes. Together with ShiftRows, MixColumns provides diffusion in the cryptographs.

			在MixColumns步骤中，状态的每一列的四个字节用一个可逆的线性变换进行组合。
			MixColumns函数将四个字节作为输入，并输出四个字节，其中每个输入字节会影响所有四个输出字节。
			与ShiftRows一起，MixColumns在密码器中提供了扩散性。
		*/
		void MixColumns(std::vector<ByteBit> &stateBlock)
		{
			std::vector<ByteBit> ByteBitArray(4);
			for (int row = 0; row < 4; ++row)
			{
				for (int column = 0; column < 4; ++column)
					ByteBitArray[column] = stateBlock[row + column * 4];

				stateBlock[row] = MultiplicationOfByteWithGaloisField(0x02, ByteBitArray[0]) ^
									MultiplicationOfByteWithGaloisField(0x03, ByteBitArray[1]) ^ ByteBitArray[2] ^
									ByteBitArray[3];
				stateBlock[row + 4] = ByteBitArray[0] ^ MultiplicationOfByteWithGaloisField(0x02, ByteBitArray[1]) ^
										MultiplicationOfByteWithGaloisField(0x03, ByteBitArray[2]) ^ ByteBitArray[3];
				stateBlock[row + 8] = ByteBitArray[0] ^ ByteBitArray[1] ^
										MultiplicationOfByteWithGaloisField(0x02, ByteBitArray[2]) ^
										MultiplicationOfByteWithGaloisField(0x03, ByteBitArray[3]);
				stateBlock[row + 12] = MultiplicationOfByteWithGaloisField(0x03, ByteBitArray[0]) ^ ByteBitArray[1] ^
										ByteBitArray[2] ^ MultiplicationOfByteWithGaloisField(0x02, ByteBitArray[3]);
			}
		}

		/*

			InvMixColumns() is the inverse of the MixColumns() transformation.
			InvMixColumns() operates on the State column-by-column, treating each column as a fourterm polynomial as
			described in Sec. 4.3. The columns are considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with
			a fixed polynomial a^-1*(x), given by Mathematical equations 5.9

			a^-1*x = {0b}*x^3 + {0d}*x^2 + {09}*x + {0e}

			Mathematical equations 5.10
			As described in Sec. 4.3, this can be written as a matrix multiplication.
			state'[x] = a^-1*x (*) state[x]

			As a result of this multiplication, the four bytes in a column are replaced by the following:

			state'[0][column] = ({0e} • state[0][column]) (+) ({0b} • state[1][column]) (+) ({0d} • state[2][column]) (+)
			({09} • state[3][column]) state'[1][column] = ({09} • state[0][column]) (+) ({0e} • state[1][column]) (+) ({0b} •
			state[2][column]) (+) ({0d} • state[3][column]) state'[2][column] = ({0d} • state[0][column]) (+) ({09} •
			state[1][column]) (+) ({0e} • state[2][column]) (+) ({0b} • state[3][column]) state'[3][column] = ({0b} •
			state[0][column]) (+) ({0d} • state[1][column]) (+) ({09} • state[2][column]) (+) ({0e} • state[3][column])

			InvMixColumns()是MixColumns()的逆向转换。
			InvMixColumns()对国家逐列操作，如第4.3节所述，将每一列作为一个四项式多项式处理。
			这些列被视为GF(2^8)上的多项式，并与固定的多项式a^-1*(x)相乘以x^4+1，给出如下
			数学方程式 5.9

			a^-1*x = {0b}*x^3 + {0d}*x^2 + {09}*x + {0e}

			数学方程式5.10
			如第4.3节所述，这可以写成一个矩阵乘法。
			state'[x] = a^-1*x (*) state[x]

			作为这个乘法的结果，一列中的四个字节被替换成以下内容:

			state'[0][column] = ({0e} • state[0][column]) (+) ({0b} • state[1][column]) (+) ({0d} • state[2][column]) (+)
			({09} • state[3][column]) state'[1][column] = ({09} • state[0][column]) (+) ({0e} • state[1][column]) (+) ({0b} •
			state[2][column]) (+) ({0d} • state[3][column]) state'[2][column] = ({0d} • state[0][column]) (+) ({09} •
			state[1][column]) (+) ({0e} • state[2][column]) (+) ({0b} • state[3][column]) state'[3][column] = ({0b} •
			state[0][column]) (+) ({0d} • state[1][column]) (+) ({09} • state[2][column]) (+) ({0e} • state[3][column])

		*/
		void InverseMixColumns(std::vector<ByteBit> &stateBlock)
		{
			if (stateBlock.size() == 4 * 4)
			{
				std::vector<ByteBit> ByteBitArray(4);
				for (int row = 0; row < 4; ++row)
				{
					for (int column = 0; column < 4; ++column)
						ByteBitArray[column] = stateBlock[row + column * 4];

					stateBlock[row] = MultiplicationOfByteWithGaloisField(0x0e, ByteBitArray[0]) ^
										MultiplicationOfByteWithGaloisField(0x0b, ByteBitArray[1]) ^
										MultiplicationOfByteWithGaloisField(0x0d, ByteBitArray[2]) ^
										MultiplicationOfByteWithGaloisField(0x09, ByteBitArray[3]);
					stateBlock[row + 4] = MultiplicationOfByteWithGaloisField(0x09, ByteBitArray[0]) ^
											MultiplicationOfByteWithGaloisField(0x0e, ByteBitArray[1]) ^
											MultiplicationOfByteWithGaloisField(0x0b, ByteBitArray[2]) ^
											MultiplicationOfByteWithGaloisField(0x0d, ByteBitArray[3]);
					stateBlock[row + 8] = MultiplicationOfByteWithGaloisField(0x0d, ByteBitArray[0]) ^
											MultiplicationOfByteWithGaloisField(0x09, ByteBitArray[1]) ^
											MultiplicationOfByteWithGaloisField(0x0e, ByteBitArray[2]) ^
											MultiplicationOfByteWithGaloisField(0x0b, ByteBitArray[3]);
					stateBlock[row + 12] = MultiplicationOfByteWithGaloisField(0x0b, ByteBitArray[0]) ^
											MultiplicationOfByteWithGaloisField(0x0d, ByteBitArray[1]) ^
											MultiplicationOfByteWithGaloisField(0x09, ByteBitArray[2]) ^
											MultiplicationOfByteWithGaloisField(0x0e, ByteBitArray[3]);
				}
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			In the ShiftRows() transformation, the bytes in the last three rows of the State are cyclically shifted over
			different numbers of bytes (offsets). The first row, r = 0, is not shifted. Specifically, the ShiftRows()
			transformation proceeds as follows:

			Mathematical equations 5.3
			function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)

			where the shift value shift(row,Nb) depends on the row number, row, as follows (recall that Nb = 4):

			Mathematical equations 5.4
			shift(1,4) = 1;
			shift(2,4) = 2;
			shift(3,4) = 3;

			This has the effect of moving bytes to "lower" positions in the row (i.e., lower values of column in a given
			row), While the "lowest "bytes wrap around into the "top" of the row (i.e., higher values of column in a given
			row).

			在ShiftRows()转换中，State最后三行的字节在不同的字节数（偏移量）上被循环移位
			第一行，r = 0，不被移位。
			具体来说，ShiftRows()转换的过程如下。

			数学公式5.3
			function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)

			其中移位值shift(row,Nb)取决于行数row，如下所示（记得Nb=4）

			数学公式5.4
			shift(1,4) = 1;
			shift(2,4) = 2;
			shift(3,4) = 3。

			这样做的效果是将字节移到行中的 "较低 "位置（即在给定行中列的低值）
			而 "最低的 "字节则环绕到行的 "顶部"（即某一行中列的数值较高）

			The ShiftRows step operates on the rows of the state;
			It cyclically shifts the bytes in each row by a certain offset.
			In this way, each column of the output state of the ShiftRows step is composed of bytes from each column of the
			input state. The importance of this step is to avoid the columns being encrypted independently, in which case AES
			would degenerate into four independent block ciphers.

			ShiftRows步骤对状态的行进行操作。
			它循环地将每一行的字节按一定的偏移量移动。
			这样，ShiftRows步骤的输出状态的每一列都是由输入状态的每一列的字节组成。
			这一步的重要性在于避免各列被独立加密，在这种情况下，AES将退化为四个独立的块密码。
		*/
		void ShiftRows(std::vector<ByteBit> &stateBlock)
		{
			if (stateBlock.size() == 4 * 4)
			{
				// 第二行循环左移一位
				ByteBit temporaryByteBit = stateBlock[4];
				for (int index = 0; index < 3; ++index)
					stateBlock[index + 4] = stateBlock[index + 5];
				stateBlock[7] = temporaryByteBit;
				// 第三行循环左移两位
				for (int index = 0; index < 2; ++index)
				{
					temporaryByteBit = stateBlock[index + 8];
					stateBlock[index + 8] = stateBlock[index + 10];
					stateBlock[index + 10] = temporaryByteBit;
				}
				// 第四行循环左移三位
				temporaryByteBit = stateBlock[15];
				for (int index = 3; index > 0; --index)
					stateBlock[index + 12] = stateBlock[index + 11];
				stateBlock[12] = temporaryByteBit;
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			This is the inverse of the ShiftRows() transformation.
			The bytes in the last three rows of the State are cyclically shifted over different numbers of bytes (offsets).
			The first row, r = 0, is not shifted.
			The bottom three rows are cyclically shifted by Nb - shift(r, Nb) bytes, where the shift value shift(r,Nb)
			depends on the row number, and is given in equation (5.4) (see Sec. 5.1.2).

			Specifically, the InvShiftRows() transformation proceeds as follows:
			function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)
			Conditions for variables: 0 < row < 4 and 0 <= column < Nb

			这是ShiftRows()转换的逆运算。
			最后三行的字节在不同的字节数（偏移量）上被循环移位。
			第一行，row = 0，不被移位。
			最下面的三行被循环移位Nb-shift(r,Nb)字节，其中shift(r,Nb)的值取决于行数，在公式(5.4)中给出
			(见第5.1.2节)。

			具体来说，InvShiftRows()转换的过程如下。
			function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)
			变量的条件：0 < row < 4 和 0 <= column < Nb
		*/
		void InverseShiftRows(std::vector<ByteBit> &stateBlock)
		{
			if (stateBlock.size() == 4 * 4)
			{
				// 第二行循环右移一位
				ByteBit temporaryByteBit = stateBlock[7];
				for (int index = 3; index > 0; --index)
					stateBlock[index + 4] = stateBlock[index + 3];
				stateBlock[4] = temporaryByteBit;
				// 第三行循环右移两位
				for (int index = 0; index < 2; ++index)
				{
					temporaryByteBit = stateBlock[index + 8];
					stateBlock[index + 8] = stateBlock[index + 10];
					stateBlock[index + 10] = temporaryByteBit;
				}
				// 第四行循环右移三位
				temporaryByteBit = stateBlock[12];
				for (int index = 0; index < 3; ++index)
					stateBlock[index + 12] = stateBlock[index + 13];
				stateBlock[15] = temporaryByteBit;
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			The SubBytes() transformation is a non-linear byte substitution that operates independently on each byte of the
			State using a substitution table (S-box). This S-box which is invertible, is constructed by composing two
			transformations:
			1. Take the multiplicative inverse in the finite field GF(2^8), described in Sec. 4.2;
			the element {00} is mapped to itself.
			2. Apply the following affine transformation (over GF(2) ):
			Mathematical equations 5.1
			bit[index] = bit[index] (+) bit[index + 4 mod 8] (+) bit[index + 5 mod 8] (+) bit[index + 6 mod 8] (+) bit[index
			+ 7 mod 8] (+) c[index]

			for 0 <= index < 8 , where bit[index] is the index ^ the bit of the byte, and c[index] is the index ^ the bit of
			a byte c with the value {63} or {01100011}. Here and elsewhere, a prime on a variable (e.g., bit' ) indicates
			that the variable is to be updated with the value on the right.

			SubBytes()转换是一种非线性的字节替换，它使用一个替换表（S-box）对State的每个字节独立操作。
			这个S-box是可反转的，它是由两个转换组成的。
			1. 在有限域GF(2^8)中进行乘法逆运算，在第4.2节中描述。
			元素{00}被映射到它自己。
			2. 应用下面的仿射变换（在GF(2)上）。
			数学公式5.1
			bit[index] = bit[index] (+) bit[index + 4 mod 8] (+) bit[index + 5 mod 8] (+) bit[index + 6 mod 8] (+) bit[index
			+ 7 mod 8] (+) c[index] for 0 <= index < 8 , 其中bit[index]是字节的index ^ the位，c[index]是字节c的index ^
			the位，值为{63}或{01100011}。 在这里和其他地方，变量上的素数（例如，bit'）表示该变量要用右边的值来更新。

			In the SubBytes step, each byte arrays[i][j] in the state array is replaced with a SubByte S-box[arrays[i][j]]
			using an 8-bit substitution box. Note that before round 0, the state array is simply the plaintext/input. This
			operation provides the non-linearity in the cipher. The S-box used is derived from the multiplicative inverse
			over GF(2^8), known to have good non-linearity properties. To avoid attacks based on simple algebraic properties,
			the S-box is constructed by combining the inverse function with an invertible affine transformation. The S-box is
			also chosen to avoid any fixed points (and so is a derangement), i.e., S-box[arrays[i][j]] != arrays[i][j] , and
			also any opposite fixed points, i.e., S-box[arrays[i][j]] (+) arrays[i][j] != FF16. While performing the
			decryption, the InvSubBytes step (the inverse of SubBytes) is used, which requires first taking the inverse of
			the affine transformation and then finding the multiplicative inverse.

			在SubBytes步骤中，状态数组中的每个字节arrays[i][j]被替换为SubByte S-box[arrays[i][j]]，使用一个8位替换框。
			注意，在第0轮之前，状态数组只是明文/输入。
			这个操作提供了密码中的非线性。
			所用的S-box是由GF(2^8)上的乘法逆推而来，已知其具有良好的非线性特性。
			为了避免基于简单代数特性的攻击，S-box是通过将反函数与可反转的仿射变换相结合而构建的。
			S-box的选择也是为了避免任何固定点（因此是一个脱轨），即S-box[arrays[i][j]] != arrays[i][j]
			，以及任何相反的固定点，即S-box[ arrays[i][j] ] (+) arrays[i][j] != FF16。
			在进行解密时，使用了InvSubBytes步骤（SubBytes的逆），这需要先取仿射变换的逆，然后找到乘法的逆。
		*/
		void SubtituteBytes(std::vector<ByteBit> &stateBlock) const
		{
			if (stateBlock.size() == 4 * 4)
			{
				for (unsigned int index = 0; index < 16; ++index)
				{
					unsigned int row = stateBlock[index][7] * 8 + stateBlock[index][6] * 4 + stateBlock[index][5] * 2 +
										stateBlock[index][4];
					unsigned int column = stateBlock[index][3] * 8 + stateBlock[index][2] * 4 + stateBlock[index][1] * 2 +
											stateBlock[index][0];
					stateBlock[index] = CommonSecurity::AES::Forward_S_Box[row][column];
				}
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			InvSubBytes() is the inverse of the byte substitution transformation, in which the inverse S-box is applied to
			each byte of the State. This is obtained by applying the inverse of the affine transformation (5.1) followed by
			taking the multiplicative inverse in GF(2^8).

			InvSubBytes()是字节替换变换的逆运算，其中逆S-box被应用于状态的每个字节。
			这是由应用仿射变换的逆（5.1），然后在GF(2^8)中取乘法逆得到的。
		*/
		void InverseSubtituteBytes(std::vector<ByteBit> &stateBlock) const
		{
			if (stateBlock.size() == 4 * 4)
			{
				for (unsigned int index = 0; index < 16; ++index)
				{
					unsigned int row = stateBlock[index][7] * 8 + stateBlock[index][6] * 4 + stateBlock[index][5] * 2 +
										stateBlock[index][4];
					unsigned int column = stateBlock[index][3] * 8 + stateBlock[index][2] * 4 + stateBlock[index][1] * 2 +
											stateBlock[index][0];
					stateBlock[index] = CommonSecurity::AES::Backward_S_Box[row][column];
				}
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			In the AddRoundKey step, the subkey is combined with the state.
			For each round, a subkey is derived from the main key using Rijndael's key schedule; each subkey is the same
			size as the state. The subkey is added by combining each byte of the state with the corresponding byte of the
			subkey using bitwise (+).

			在AddRoundKey步骤中，子密钥与状态相结合。
			对于每一轮，使用Rijndael的密钥计划从主密钥中导出一个子密钥；每个子密钥的大小与状态相同。
			子密钥的添加是通过将状态的每个字节与子密钥的相应字节用位法（+）结合起来。

			Transformation in the Cipher and Inverse Cipher in which a Round Key is added to the State using an XOR
			operation. The length of a Round Key equals the size of the State data block (i.e., for Nb = 4, the Round Key
			length equals 128 bits/16 bytes).

			在密码器和反密码器中的转换，其中一个轮密钥是使用XOR操作添加到状态数据中
			轮密钥的长度等于状态数据块的大小（例如，对于Nb=4，轮密钥的长度等于128比特/16字节）
		*/
		void AddRoundKey(std::vector<ByteBit> &stateBlock, const std::vector<WordBit> &wordKey) const
		{
			if (stateBlock.size() == 4 * 4 && wordKey.size() == this->NKeyWordSize)
			{
				for (unsigned int index = 0; index < this->NKeyWordSize; ++index)
				{
					WordBit key = wordKey[index] >> 24;
					WordBit key2 = (wordKey[index] << 8) >> 24;
					WordBit key3 = (wordKey[index] << 16) >> 24;
					WordBit key4 = (wordKey[index] << 24) >> 24;

					for (unsigned int index2 = 0; index2 < 4; ++index2)
					{
						stateBlock[index2] = stateBlock[index2] ^ ByteBit(key.to_ulong());
						stateBlock[index2 + 4] = stateBlock[index2 + 4] ^ ByteBit(key2.to_ulong());
						stateBlock[index2 + 8] = stateBlock[index2 + 8] ^ ByteBit(key3.to_ulong());
						stateBlock[index2 + 12] = stateBlock[index2 + 12] ^ ByteBit(key4.to_ulong());
					}
				}
			}
			else
			{
				throw std::length_error("");
			}
		}

		void EncryptBlockData(std::span<ByteBit> byteData)
		{
			if (byteData.size() == GetBlockKeyByteSize() &&
				this->BitsetExpandedWordRoundKeyBlock.size() == 4 * (this->NRound + 1))
			{
				this->StateByteDataBlock.clear();
				this->StateByteDataBlock.shrink_to_fit();

				std::vector<WordBit> key(this->NKeyWordSize);

				auto iteratorDataBegin = byteData.begin();
				auto iteratorDataEnd = byteData.end();

				while (iteratorDataBegin != iteratorDataEnd)
				{
					std::size_t stateBlockByteSize = 16;
					std::span<ByteBit> ByteDataSpan{
						CommonToolkit::MakeSubrangeContent<std::span<ByteBit>, std::span<ByteBit>::iterator>(
							iteratorDataBegin, iteratorDataEnd, stateBlockByteSize, true)};
					std::vector<ByteBit> currentStateBlock{ByteDataSpan.begin(), ByteDataSpan.end()};

					if (currentStateBlock.size() < 16)
					{
						break;
					}

					// ROUND: 0
					for (unsigned int index = 0; index < this->NKeyWordSize; ++index)
					{
						key[index] = this->BitsetExpandedWordRoundKeyBlock[index];
					}
					this->AddRoundKey(currentStateBlock, key);

					// ROUNDS: 1 ~ NRound-1
					for (unsigned int round = 1; round <= this->NRound - 1; ++round)
					{
						this->SubtituteBytes(currentStateBlock);
						this->ShiftRows(currentStateBlock);
						this->MixColumns(currentStateBlock);

						for (int index = 0; index < 4; ++index)
						{
							key[index] = this->BitsetExpandedWordRoundKeyBlock[4 * round + index];
						}
						this->AddRoundKey(currentStateBlock, key);
					}

					// ROUND: NRound
					this->SubtituteBytes(currentStateBlock);
					this->ShiftRows(currentStateBlock);

					for (unsigned int index = 0; index < 4; ++index)
					{
						key[index] = this->BitsetExpandedWordRoundKeyBlock[4 * this->NRound + index];
					}
					this->AddRoundKey(currentStateBlock, key);

					this->StateByteDataBlock.insert(this->StateByteDataBlock.end(), currentStateBlock.begin(),
													currentStateBlock.end());
				}

				std::ranges::move(this->StateByteDataBlock.begin(), this->StateByteDataBlock.end(), byteData.begin());
			}
			else
			{
				throw std::length_error("");
			}
		}

		void DecryptBlockData(std::span<ByteBit> byteData)
		{
			if (byteData.size() == GetBlockKeyByteSize() &&
				this->BitsetExpandedWordRoundKeyBlock.size() == 4 * (this->NRound + 1))
			{
				this->StateByteDataBlock.clear();
				this->StateByteDataBlock.shrink_to_fit();

				std::vector<WordBit> key(this->NKeyWordSize);

				auto iteratorDataBegin = byteData.begin();
				auto iteratorDataEnd = byteData.end();

				while (iteratorDataBegin != iteratorDataEnd)
				{
					std::size_t stateBlockByteSize = 16;
					std::span<ByteBit> ByteDataSpan{
						CommonToolkit::MakeSubrangeContent<std::span<ByteBit>, std::span<ByteBit>::iterator>(
							iteratorDataBegin, iteratorDataEnd, stateBlockByteSize, true)};
					std::vector<ByteBit> currentStateBlock{ByteDataSpan.begin(), ByteDataSpan.end()};

					if (currentStateBlock.size() < 16)
					{
						break;
					}

					// INVERSE ROUND: NRound
					for (unsigned int index = 0; index < 4; ++index)
					{
						key[index] = this->BitsetExpandedWordRoundKeyBlock[4 * this->NRound + index];
					}
					this->AddRoundKey(currentStateBlock, key);

					// INVERSE ROUNDS: NRound-1 ~ 1
					for (unsigned int round = this->NRound - 1; round >= 1; --round)
					{
						this->InverseSubtituteBytes(currentStateBlock);
						this->InverseShiftRows(currentStateBlock);

						for (int index = 0; index < 4; ++index)
						{
							key[index] = this->BitsetExpandedWordRoundKeyBlock[4 * round + index];
						}
						this->AddRoundKey(currentStateBlock, key);

						this->InverseMixColumns(currentStateBlock);
					}

					// INVERSE ROUND: 0
					this->InverseSubtituteBytes(currentStateBlock);
					this->InverseShiftRows(currentStateBlock);

					for (unsigned int index = 0; index < this->NKeyWordSize; ++index)
					{
						key[index] = this->BitsetExpandedWordRoundKeyBlock[index];
					}
					this->AddRoundKey(currentStateBlock, key);

					this->StateByteDataBlock.insert(this->StateByteDataBlock.end(), currentStateBlock.begin(),
													currentStateBlock.end());
				}

				std::ranges::move(this->StateByteDataBlock.begin(), this->StateByteDataBlock.end(), byteData.begin());
			}
			else
			{
				throw std::length_error("");
			}
		}

		/*
			KEY SCHEDULING
		*/
		void KeyExpansion(const std::vector<ByteBit> &byteKeys, std::vector<WordBit> &expandedRoundKeys)
		{
			if (byteKeys.size() == 4 * this->NKeyWordSize)
			{
				expandedRoundKeys.resize(4 * (this->NRound + 1));
				WordBit temporaryWordBit;
				WordBit RCON_Word_Data = 0;

				for (unsigned int index = 0; index < this->NKeyWordSize; ++index)
				{
					expandedRoundKeys[index] = FourByteBitToWordBit(byteKeys[4 * index], byteKeys[4 * index + 1],
																		byteKeys[4 * index + 2], byteKeys[4 * index + 3]);
				}

				for (unsigned int index = this->NKeyWordSize; index < 4 * (this->NRound + 1); ++index)
				{
					temporaryWordBit = expandedRoundKeys[index - 1];
					if (index % NKeyWordSize == 0)
					{
						expandedRoundKeys[index] = expandedRoundKeys[index - this->NKeyWordSize] ^
														KeyWordAES_Subtitute(KeyWordAES_LeftRotate(temporaryWordBit)) ^
														RCON(RCON_Word_Data, index / byteKeys.size());
					}
					else
					{
						expandedRoundKeys[index] = expandedRoundKeys[index - this->NKeyWordSize] ^ temporaryWordBit;
					}
				}
			}
			else
			{
				throw std::length_error("");
			}
		}

		void CalculationPaddingDataSize(std::size_t currentDataSize, std::size_t &NeedPaddingDataSize)
		{
			if (currentDataSize < this->NBlockDataByteSize)
			{
				NeedPaddingDataSize = this->NBlockDataByteSize - currentDataSize;
			}
			else
			{
				std::size_t Remainder = currentDataSize % this->NBlockDataByteSize;
				if (Remainder == 1)
				{
					NeedPaddingDataSize = (NBlockDataByteSize - 1);
				}
				if (Remainder == 0)
				{
					NeedPaddingDataSize = NBlockDataByteSize;
				}
				else
				{
					NeedPaddingDataSize = (NBlockDataByteSize - Remainder);
				}
			}
		}

		void DataPaddingWithPKCS7(std::vector<unsigned char> &data, std::size_t &NeedPaddingSize)
		{
			long long NeedLoopCount = NeedPaddingSize;
			while (NeedLoopCount > 0)
			{
				data.push_back(static_cast<unsigned char>(NeedPaddingSize));
				--NeedLoopCount;
			}
		}

		void DataUnpaddingWithPKCS7(std::vector<unsigned char> &data, const std::size_t &NeedPaddingSize)
		{
			long long foundPaddingDataCounter = 0;
			for (std::vector<unsigned char>::const_reverse_iterator constant_rbegin = data.crbegin(),
																	constant_end = data.crend();
					constant_rbegin != constant_end; ++constant_rbegin)
			{
				if (*constant_rbegin == static_cast<unsigned char>(NeedPaddingSize))
				{
					++foundPaddingDataCounter;
				}
				else if (foundPaddingDataCounter == NeedPaddingSize)
				{
					break;
				}
				else
				{
					throw std::logic_error("");
				}
			}

			while (foundPaddingDataCounter > 0)
			{
				data.pop_back();
				--foundPaddingDataCounter;
			}
		}

		public:
		const unsigned char GetBlockDataByteSize() const
		{
			return this->NBlockDataByteSize;
		}

		const std::size_t GetBlockKeyByteSize() const
		{
			return this->NKeyWordSize * this->NBlockWordSize;
		}

		/*

			最简单的工作模式即为电子密码本（Electronic codebook，ECB）模式。
			需要加密的消息按照块密码的块大小被分为数个块，并对每个块进行独立加密。

			The simplest mode of operation is the electronic codebook (ECB) mode.
			The message to be encrypted is divided into several blocks according to the block size of the block cipher, and
			each block is encrypted independently.

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
		bool EncryptionWithECB(std::vector<unsigned char> input, const std::vector<unsigned char> &key,
								std::vector<unsigned char> &output)
		{
			if (this->NKeyWordSize == 0 && this->NRound == 0)
			{
				this->NKeyWordSize = key.size() / 4;
				this->NRound = this->NKeyWordSize + 6;
			}

			if (key.size() != this->NKeyWordSize * 4)
				return false;
			if (input.empty())
				return false;

			std::size_t NeedPaddingDataSize = 0;
			this->CalculationPaddingDataSize(input.size(), NeedPaddingDataSize);
			if (NeedPaddingDataSize != 0)
			{
				DataPaddingWithPKCS7(input, NeedPaddingDataSize);
			}

			// Key data for extension
			//密钥数据进行扩展
			for (auto &_key : key)
			{
				this->BitsetKeyBlock.push_back(UnsignedCharacterToBitset8(_key));
			}
			this->KeyExpansion(this->BitsetKeyBlock, this->BitsetExpandedWordRoundKeyBlock);
			this->BitsetKeyBlock.clear();

			output.resize(input.size());

			auto iteratorBegin = input.begin();
			auto iteratorEnd = input.end();

			for (unsigned char index = 0; index < input.size(); index += this->NBlockDataByteSize)
			{
				std::size_t iteratorOffset = this->NBlockDataByteSize;

				//数据必须复制到这里，不要移动它!
				// The data must be copied here, don't move it!
				auto dataSubrange =
					CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(
						iteratorBegin, iteratorEnd, iteratorOffset, true);

				std::vector<unsigned char> temporaryVectorData(dataSubrange.size());
				std::ranges::copy(dataSubrange.begin(), dataSubrange.end(), temporaryVectorData.begin());
				dataSubrange.clear();

				std::vector<ByteBit> temporaryVectorData2;
				for (auto &unsignedCharacter : temporaryVectorData)
				{
					temporaryVectorData2.push_back(UnsignedCharacterToBitset8(unsignedCharacter));
				}
				temporaryVectorData.clear();
				temporaryVectorData.shrink_to_fit();

				// The key data are involved in the encryption calculation
				//密钥数据参与了加密计算
				this->EncryptBlockData(temporaryVectorData2);

				for (auto &bitset8 : temporaryVectorData2)
				{
					temporaryVectorData.push_back(UnsignedCharacterFromBitset8(bitset8));
				}
				temporaryVectorData2.clear();
				temporaryVectorData2.shrink_to_fit();

				std::ranges::move(temporaryVectorData.begin(), temporaryVectorData.end(), output.begin() + index);

				temporaryVectorData.shrink_to_fit();
				temporaryVectorData.~vector();
				temporaryVectorData2.~vector();
			}

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
		bool DecryptionWithECB(std::vector<unsigned char> input, const std::vector<unsigned char> &key,
								std::vector<unsigned char> &output)
		{
			if (this->NKeyWordSize == 0 && this->NRound == 0)
			{
				this->NKeyWordSize = key.size() / 4;
				this->NRound = this->NKeyWordSize + 6;
			}

			if (key.size() != this->NKeyWordSize * 4)
				return false;
			if (input.empty() || (input.size() % this->NBlockDataByteSize != 0))
				return false;

			// Key data for extension
			//密钥数据进行扩展
			for (auto &_key : key)
			{
				this->BitsetKeyBlock.push_back(UnsignedCharacterToBitset8(_key));
			}
			this->KeyExpansion(this->BitsetKeyBlock, this->BitsetExpandedWordRoundKeyBlock);
			this->BitsetKeyBlock.clear();

			output.resize(input.size());

			auto iteratorBegin = input.begin();
			auto iteratorEnd = input.end();

			for (unsigned char index = 0; index < input.size(); index += this->NBlockDataByteSize)
			{
				std::size_t iteratorOffset = this->NBlockDataByteSize;

				//数据必须复制到这里，不要移动它!
				// The data must be copied here, don't move it!
				auto dataSubrange =
					CommonToolkit::MakeSubrangeContent<std::vector<unsigned char>, std::vector<unsigned char>::iterator>(
						iteratorBegin, iteratorEnd, iteratorOffset, true);

				std::vector<unsigned char> temporaryVectorData(dataSubrange.size());
				std::ranges::copy(dataSubrange.begin(), dataSubrange.end(), temporaryVectorData.begin());
				dataSubrange.clear();

				std::vector<ByteBit> temporaryVectorData2;
				for (auto &unsignedCharacter : temporaryVectorData)
				{
					temporaryVectorData2.push_back(UnsignedCharacterToBitset8(unsignedCharacter));
				}
				temporaryVectorData.clear();
				temporaryVectorData.shrink_to_fit();

				// The key data are involved in the decryption calculation
				//密钥数据参与了解密计算
				this->DecryptBlockData(temporaryVectorData2);

				for (auto &bitset8 : temporaryVectorData2)
				{
					temporaryVectorData.push_back(UnsignedCharacterFromBitset8(bitset8));
				}
				temporaryVectorData2.clear();
				temporaryVectorData2.shrink_to_fit();

				std::ranges::move(temporaryVectorData.begin(), temporaryVectorData.end(), output.begin() + index);

				temporaryVectorData.shrink_to_fit();
				temporaryVectorData.~vector();
				temporaryVectorData2.~vector();
			}

			if (*(output.rbegin() + 1) != static_cast<unsigned char>(0) && *(output.rbegin() + 2) != static_cast<unsigned char>(0))
			{
				DataUnpaddingWithPKCS7(output, output.back());
			}

			return true;
		}

		ECB_Mode_Tiny128bit()
		{
			this->NBlockDataByteSize = this->NKeyWordSize * this->NBlockWordSize * sizeof(unsigned char);
			this->NKeyWordSize = 4;
			this->NRound = 10;
			this->StateByteDataBlock.resize(this->NBlockDataByteSize);
			this->BitsetExpandedWordRoundKeyBlock.clear();
		}

		~ECB_Mode_Tiny128bit()
		{
			this->StateByteDataBlock.clear();
			this->StateByteDataBlock.shrink_to_fit();
			this->BitsetExpandedWordRoundKeyBlock.clear();
			this->BitsetExpandedWordRoundKeyBlock.shrink_to_fit();
		}

		ECB_Mode_Tiny128bit(ECB_Mode_Tiny128bit& _object) = delete;
		ECB_Mode_Tiny128bit &operator=(const ECB_Mode_Tiny128bit& _object) = delete;
	};
}
	
#endif

namespace CommonSecurity::TripleDES
{
	//First Step
	//第一个步骤
	//Forward Permutation Table - Initial
	constexpr std::array<signed int, 64> InitialPermutationTable
	{
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17,  9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};

	//Last Step
	//最后一步
	//Backward Permutation Table - Final
	constexpr std::array<signed int, 64> FinalPermutationTable
	{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25
	};

	//The 64 bit key Transform(Results like data compression) to 56 bit key
	//64位的密钥转换（结果像数据压缩）为56位的密钥
	constexpr std::array<signed int, 56> KeyParityChoiceTable
	{
        57, 49, 41, 33, 25, 17, 9,  1,
		58, 50, 42, 34, 26, 18, 10, 2,
		59, 51, 43, 35, 27, 19, 11, 3,
		60, 52, 44, 36, 63, 55, 47, 39, 
		31, 23, 15, 7, 62, 54, 46, 38,
		30, 22, 14, 6, 61, 53, 45, 37,
		29, 21, 13, 5, 28, 20, 12, 4
	};

	//The 56 bit key Transform(Results like data compression) to 48 bit key
	//56位的密钥转换（结果像数据压缩）为48位的密钥
	constexpr std::array<signed int, 48> KeyPermutationCompressionChoiceTable
	{
        14, 17, 11, 24, 1,  5,  3,  28,
		15, 6,  21, 10, 23, 19, 12, 4, 
		26, 8,  16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
		51, 45, 33, 48, 44, 49, 39, 56,
		34, 53, 46, 42, 50, 36, 29, 32
	};

	//Generate the number of bits to be shifted left and right for each (16) key rounds
	//每轮左移的比特数
	constexpr std::array<signed int, 16> BitShiftWithRound
	{
		1, 1, 2, 2, 2, 2, 2, 2,
		1, 2, 2, 2, 2, 2, 2, 1
	};

	//The 32 bit data extension to 48 bit data
	//32位数据扩展为48位数据
    constexpr std::array<signed int, 48> DataExtensionPermutationTable
	{
		32, 1,  2,  3,  4,  5,  4,  5, 
		6,  7,  8,  9,  8,  9,  10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1
	};
	

	//Byte Data Substitution Box
	//字节数据代换盒
	//Here it means that each S-box is a 4x16 permutation table, 6 bits -> 4 bits, 8 S-boxes
	//在这里表示每个S盒是4x16的置换表，6位 -> 4位，8个S盒
	static const std::vector<std::vector<std::array<signed int, 16>>> S_Box
	{
		{
				{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
				{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
				{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
				{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
		},
		{
				{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
				{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
				{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
				{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
		},
		{
				{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
				{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
				{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
				{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
		},
		{
				{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
				{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
				{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
				{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
		},
		{
				{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
				{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
				{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
				{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
		},
		{
				{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
				{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
				{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
				{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
		},
		{
				{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
				{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
				{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
				{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
		},
		{
				{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
				{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
				{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
				{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
		}
	};

	//Byte Data Permutation Box
	//字节数据置换盒
	constexpr std::array<signed int, 32> P_Box
	{
		16, 7,  20, 21,
		29, 12, 28, 17,
		1,  15, 23, 26,
		5,  18, 31, 10,
        2,  8,  24, 14,
		32, 27, 3,  9,
		19, 13, 30, 6,
		22, 11, 4,  25
	};

	/*
	
		Paper: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf
	
	*/
	class Worker
	{

	public:

		struct DataBuffer
		{
			std::bitset<64> Bitset64Object_Plain;
			std::bitset<64> Bitset64Object_Cipher;
		};

	private:
		
		//64位密钥
		std::bitset<64> OriginalKey;
		std::bitset<64> RecordOriginalKey;

		//存放16轮子密钥
		std::array<std::bitset<48>, 16> SubKeyArray;

		/*
				Binary 6 bit:
						
						column
						   |
						*--+--*
					[0 (0 0 0 0) 0]
					 ^           ^
					 |           |
					 +-----+-----+
						   |
						  row
		*/

		std::pair<signed int, signed int> SubstitutionIndex(const std::bitset<6>& DataBits)
		{
			std::bitset<4> SubstitutionBox_RowBinary;
			std::bitset<4> SubstitutionBox_ColumnBinary;

			bool bitDigit5 = DataBits.operator[](5);
			bool bitDigit4 = DataBits.operator[](4);
			bool bitDigit3 = DataBits.operator[](3);
			bool bitDigit2 = DataBits.operator[](2);
			bool bitDigit1 = DataBits.operator[](1);
			bool bitDigit0 = DataBits.operator[](0);

			//The first and sixth binary digits are converted to decimal and set to row
			//第一和第六位二进制数字被转换为十进制并设置为行
			SubstitutionBox_RowBinary.set(1, bitDigit5);
			SubstitutionBox_RowBinary.set(0, bitDigit0);

			//The four adjacent binary bits in the middle are converted to decimal and set as columns
			//中间相邻的四个二进制位被转换为十进制并设置为列
			SubstitutionBox_ColumnBinary.set(3, bitDigit4);
			SubstitutionBox_ColumnBinary.set(2, bitDigit3);
			SubstitutionBox_ColumnBinary.set(1, bitDigit2);
			SubstitutionBox_ColumnBinary.set(0, bitDigit1);

			//The current bitset data, need to access the current bitset according to the index inside the loop, construct the decimal number representing the row as well as the column
			//当前bitset数据，需要根据循环内部的index访问当前比特位，构造出代表行以及列的十进制数
			return std::pair<signed int, signed int>(SubstitutionBox_RowBinary.to_ulong(), SubstitutionBox_ColumnBinary.to_ulong());
		}

		//The new decimal number as index passed to S_box for access operation, according to the value obtained update to the new S_box data to the new variable
		//So far the transformation of S_box is implemented
		//新的十进制数作为index传递给S_Box进行访问操作，根据得到的数值更新到新的S_Box数据到新的变量
		//至此就实现了S_box的变换。
		std::bitset<4> SubstitutionDataBits(signed int WhereBoxNumber, signed int BoxRowNumber, signed int BoxColumnNumber)
		{
			unsigned int TransformedBoxNumber = S_Box.operator[](WhereBoxNumber).operator[](BoxRowNumber).operator[](BoxColumnNumber);
			std::bitset<4> TransformedBinaryData(TransformedBoxNumber);
			return TransformedBinaryData;
		}

		template<typename InputType, typename OutputType>
		void PermuteData(InputType&& Data, OutputType&& PermutedData, const auto* PermutationTable, auto PermutationTableSize)
		{
			for (decltype(PermutationTableSize) index = 0; index < PermutationTableSize; index++)
			{
				PermutedData[PermutationTableSize - 1 - index] = Data[PermutationTableSize - PermutationTable[index]];
			}
		}

		std::bitset<32> RoundFeistelFunction(const std::bitset<32>& CurrentRoundDataBlock, std::bitset<48>& CurrentRoundKey)
		{
			//std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );
			//std::cout << "RoundFeistelFunction Before:" << std::hex << CurrentRoundDataBlock.to_ulong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			std::bitset<48> CurrentExtendData;
		
			//Extend the data block and then re-permute the operation
			//对数据块进行扩展，然后重新置换操作
			for(unsigned int index=0; index < 48; ++index)
				CurrentExtendData[47 - index] = CurrentRoundDataBlock[32 - DataExtensionPermutationTable[index]];

			//Use the key's data for exclusive-or operation with the original data
			//使用密钥的数据与原始数据进行异或操作
			CurrentExtendData ^= CurrentRoundKey;

			std::array<std::bitset<6>, 8> GroupedCurrentExtendDataBits;

			auto GroupingCurrentExtendDataBits = [&GroupedCurrentExtendDataBits](const std::bitset<48>& CurrentExtendData) -> void
			{
				for(unsigned int index = 0, index2 = 0; index < CurrentExtendData.size() && index2 < GroupedCurrentExtendDataBits.size(); ++index, ++index2)
				{
					std::bitset<6> TemporaryDataBits;
					TemporaryDataBits.operator[](5) = CurrentExtendData.operator[](47 - index);
					TemporaryDataBits.operator[](4) = CurrentExtendData.operator[](47 - index - 1);
					TemporaryDataBits.operator[](3) = CurrentExtendData.operator[](47 - index - 2);
					TemporaryDataBits.operator[](2) = CurrentExtendData.operator[](47 - index - 3);
					TemporaryDataBits.operator[](1) = CurrentExtendData.operator[](47 - index - 4);
					TemporaryDataBits.operator[](0) = CurrentExtendData.operator[](47 - index - 5);
					GroupedCurrentExtendDataBits.operator[](7 - index2) = TemporaryDataBits;
				}
			};

			//The 48-bit extended replacement key, divided into eight groups of six bits each
			//48位扩展置换后的密钥，分成8组，每组6位
			GroupingCurrentExtendDataBits(CurrentExtendData);
			
			std::bitset<32> Transformed_S_Box;

			for (std::size_t index = 0, index2 = 0; index < GroupedCurrentExtendDataBits.size(); ++index, index2 += 4)
			{
				auto [S_BoxRowNumber, BoxColumnNumber] = SubstitutionIndex(GroupedCurrentExtendDataBits.operator[](index));

				std::bitset<4> TransformedBinaryData = SubstitutionDataBits(index, S_BoxRowNumber, BoxColumnNumber);

				Transformed_S_Box.operator[](31 - index2) = TransformedBinaryData.operator[](3);
				Transformed_S_Box.operator[](31 - index2 - 1) = TransformedBinaryData.operator[](2);
				Transformed_S_Box.operator[](31 - index2 - 2) = TransformedBinaryData.operator[](1);
				Transformed_S_Box.operator[](31 - index2 - 3) = TransformedBinaryData.operator[](0);
			}

			//The value of P_Box is accessed through the index inside the loop, and then given to Transformed_S_Box
			//The index is 32 subtracted from the value of P_Box already accessed, and the data can be transformed
			//通过循环内部的索引访问P_Box的值，然后给Transformed_S_Box
			//索引是32减去已经访问P_Box的值，就可以对数据进行变换

			std::bitset<32> ProcessedCurrentRoundDataBlock;
			PermuteData(Transformed_S_Box, ProcessedCurrentRoundDataBlock, P_Box.data(), P_Box.size());

			//std::cout << "RoundFeistelFunction After:" << std::hex << ProcessedCurrentRoundDataBlock.to_ulong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			return ProcessedCurrentRoundDataBlock;
		}

		void GenerateSubKeys()
		{
			std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );

			//二进制位数，最左边是最高位，最右边是最低位。
			//Binary bits, the leftmost is the highest bit and the rightmost is the lowest bit.

			/*
				In this std::bitset<BitsetSize> template class, All binary data is stored with the same number of bits as index.
				A larger index accessed means the higher part of the real binary data, and a smaller index accessed means the lower part of the real binary data.
				在这个std::bitset<BitsetSize>模板类中
				所有二进制数据的储存位数与index相同，访问的index越大表示的是真实二进制数据的高位部分，访问的index越小表示的是真实二进制数据的低位部分。

				Example:
				例子：
			
				std::bitset<64> bitset_binary_data_object;
			
				// This is accessing the 0th bit of the original binary data
				//此处是访问原有二进制数据第0位
				bitset_binary_data_object.operator[](0);
			
				//this is accessing the 63rd bit of the original binary data
				//此处是访问原有二进制数据第63位
				bitset_binary_data_object.operator[](63);

				The website link for the reference problem:
				https://stackoverflow.com/questions/29483123/why-does-stdbitset-expose-bits-in-little-endian-fashion
				https://stackoverflow.com/questions/37200967/is-bitset-data-stored-in-reverse-order
			*/

			std::bitset<56> BinaryKeyNotParityMarker;
			std::bitset<48> GenerateCompressedBinaryKey;

			//通过访问置换选择表1，去掉奇偶标记位，将64位密钥变成56位
			//Select Table 1 by accessing the permutation, removing the parity marker bits and turning the 64-bit key into a 56-bit
			for (unsigned int index=0; index < 56; ++index)
				BinaryKeyNotParityMarker[55 - index] = this->OriginalKey[64 - KeyParityChoiceTable[index]];

			//Split the 56-bit key into the first 28 bits and the last 28 bits
			//将56位密钥分解成为前28位和后28位
			auto SplitedBitsetPair = Cryptograph::Bitset::SplitBitset<BinaryKeyNotParityMarker.size(), BinaryKeyNotParityMarker.size() / 2>(BinaryKeyNotParityMarker);

			std::bitset<28> BinaryKeyHighDigitPart { SplitedBitsetPair.first };
			std::bitset<28> BinaryKeyLowDigitPart { SplitedBitsetPair.second };

			for (unsigned int RoundNumber = 0; RoundNumber < 16; RoundNumber++)
			{
				//Perform circular left-shift and circular right-shift for the front and back parts of the 56-bit key
				//对56位密钥的前后部分，进行循环左移和循环右移

				Cryptograph::Bitset::BitLeftCircularShift<28>(BinaryKeyHighDigitPart, BitShiftWithRound.operator[](RoundNumber), BinaryKeyHighDigitPart);
				Cryptograph::Bitset::BitRightCircularShift<28>(BinaryKeyLowDigitPart, BitShiftWithRound.operator[](RoundNumber), BinaryKeyLowDigitPart);
				
				/*
				
					std::size_t shift_count = BitShiftWithRound.operator[](RoundNumber);
					shift_count %= BinaryKeyHighDigitPart.size();
					BinaryKeyHighDigitPart = (BinaryKeyHighDigitPart << shift_count) | (BinaryKeyHighDigitPart >> (BinaryKeyHighDigitPart.size() - shift_count));
					std::size_t shift_count2 = BitShiftWithRound.operator[](RoundNumber);
					shift_count2 %= BinaryKeyHighDigitPart.size();
					BinaryKeyLowDigitPart = (BinaryKeyLowDigitPart >> shift_count2) | (BinaryKeyLowDigitPart << (BinaryKeyHighDigitPart.size() - shift_count2));
				
				*/

				//Concatenation into a 56-bit key
				//组合成56比特位密钥
				BinaryKeyNotParityMarker = Cryptograph::Bitset::ConcatenateBitset<BinaryKeyLowDigitPart.size(), BinaryKeyHighDigitPart.size()>(BinaryKeyHighDigitPart, BinaryKeyLowDigitPart, false);

				//Turn a 56-bit key into a 48-bit key by accessing permutation selection table 2
				//通过访问置换选择表2，将56位密钥变成48位
				for (unsigned int index=0; index < 48; ++index)
					GenerateCompressedBinaryKey[47 - index] = BinaryKeyNotParityMarker[56 - KeyPermutationCompressionChoiceTable[index]];

				//std::cout << "DES Round " << RoundNumber;
				//std::cout << " Sub-key is generated: " << std::hex << GenerateCompressedBinaryKey.to_ullong() << std::endl;
				//std::cout.flags(cpp_output_formatflag);

				this->SubKeyArray.operator[](RoundNumber) = GenerateCompressedBinaryKey;
			}
		}

		std::bitset<64> Encryption(const std::bitset<64>& PlainBits)
		{
			std::bitset<64> CurrentBits;

			//std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );
			//std::cout << "InitialPermutation Before:" << std::hex << PlainBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			PermuteData(PlainBits, CurrentBits, InitialPermutationTable.data(), InitialPermutationTable.size());

			//std::cout << "InitialPermutation After:" << std::hex << CurrentBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			//Step 2: PlainBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			auto SplitedBitsetPair = Cryptograph::Bitset::SplitBitset<CurrentBits.size(), CurrentBits.size() / 2>(CurrentBits);

			/*
				Left<--------------------------------------------->Right
					[      High Bits     ] | [      Low Bits      ]
				
					std::bitset<64> Index:
					63                   32  31                   0

					BinaryDataHighDigitPart( std::bitset<64>.operator[](): 63 ~ 32 )
					BinaryDataLowDigitPart( std::bitset<64>.operator[](): 31 ~ 0 )
			*/

			std::bitset<32> BinaryData_LeftBits { SplitedBitsetPair.first};
			std::bitset<32> BinaryData_RightBits { SplitedBitsetPair.second };

			//Step 3: Total 16 rounds of iterations (Sub-key forward sequential application)
			//共16轮迭代（子密钥正向顺序应用）
			
			for (auto& SubKey : this->SubKeyArray)
			{
				/*std::cout << "Round: " << RoundNumber << " Encryption Data (Left):" << std::endl;
				std::cout << std::dec << std::hex << BinaryData_LeftBits.to_ulong() << std::endl;
				std::cout << "Round: " << RoundNumber << " Encryption Data (Right):" << std::endl;
				std::cout << std::dec << std::hex << BinaryData_RightBits.to_ulong() << std::endl;*/
				
				std::bitset<32> TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = Cryptograph::Bitset::ConcatenateBitset<BinaryData_LeftBits.size(), BinaryData_RightBits.size()>(BinaryData_LeftBits, BinaryData_RightBits, true);

			//std::cout << "FinalPermutationTable Before:" << std::hex << CurrentBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			std::bitset<64> CipherBits;
			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			PermuteData(CurrentBits, CipherBits, FinalPermutationTable.data(), FinalPermutationTable.size());

			//std::cout << "FinalPermutationTable After:" << std::hex << CipherBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			return CipherBits;
		}

		std::bitset<64> Decryption(const std::bitset<64>& CipherBits)
		{
			std::bitset<64> CurrentBits;

			//std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );
			//std::cout << "InitialPermutation Before:" << std::hex << CipherBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			PermuteData(CipherBits, CurrentBits, InitialPermutationTable.data(), InitialPermutationTable.size());

			//std::cout << "InitialPermutation After:" << std::hex << CurrentBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			//Step 2: CipherBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			auto SplitedBitsetPair = Cryptograph::Bitset::SplitBitset<CurrentBits.size(), CurrentBits.size() / 2>(CurrentBits);

			/*
				Left<--------------------------------------------->Right
					[      High Bits     ] | [      Low Bits      ]
				
					std::bitset<64> Index:
					63                   32  31                   0

					BinaryDataHighDigitPart( std::bitset<64>.operator[](): 63 ~ 32 )
					BinaryDataLowDigitPart( std::bitset<64>.operator[](): 31 ~ 0 )
			*/
			std::bitset<32> BinaryData_LeftBits { SplitedBitsetPair.first};
			std::bitset<32> BinaryData_RightBits { SplitedBitsetPair.second };

			//Step 3: Total 16 rounds of iterations (Sub-key backward sequential application)
			//共16轮迭代（子密钥反向顺序应用）
			for (auto& SubKey : std::ranges::subrange(this->SubKeyArray.rbegin(), this->SubKeyArray.rend()))
			{
				/*std::cout << "Round: " << RoundNumber << " Decryption Data (Left):" << std::endl;
				std::cout << std::dec << std::hex << BinaryData_LeftBits.to_ulong() << std::endl;
				std::cout << "Round: " << RoundNumber << " Decryption Data (Right):" << std::endl;
				std::cout << std::dec << std::hex << BinaryData_RightBits.to_ulong() << std::endl;*/

				std::bitset<32> TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = Cryptograph::Bitset::ConcatenateBitset<BinaryData_LeftBits.size(), BinaryData_RightBits.size()>(BinaryData_LeftBits, BinaryData_RightBits, true);

			//std::cout << "FinalPermutationTable Before:" << std::hex << CurrentBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			std::bitset<64> PlainBits;

			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			PermuteData(CurrentBits, PlainBits, FinalPermutationTable.data(), FinalPermutationTable.size());

			//std::cout << "FinalPermutationTable Atfer:" << std::hex << PlainBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			return PlainBits;
		}

		std::bitset<64> DES_Executor(Worker::DataBuffer& buffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode)
		{
			switch (executeMode)
			{
				case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
				{
					buffer.Bitset64Object_Cipher = this->Encryption(buffer.Bitset64Object_Plain);
					return buffer.Bitset64Object_Cipher;
				}
				case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
				{
					buffer.Bitset64Object_Plain = this->Decryption(buffer.Bitset64Object_Cipher);
					return buffer.Bitset64Object_Plain;
				}
				default:
				{
					std::cout << "Wrong worker is selected" << std::endl;
					abort();
				}	
			}
		}

	public:
		
		void UpadateMainKeyOnly(std::bitset<64>& Key)
		{
			if(Key != this->RecordOriginalKey)
			{
				this->OriginalKey = Key;
				this->RecordOriginalKey = Key;
			}
		}

		void UpadateSubKeyOnly()
		{
			this->GenerateSubKeys();
		}

		//The update sub-round key by the main-round key
		//通过主轮密钥更新子轮密钥 
		void UpadateMainKeyAndSubKey(std::bitset<64>& Key)
		{
			UpadateMainKeyOnly(Key);
			UpadateSubKeyOnly();
		}

		std::vector<unsigned char> DES_Executor(DataBuffer& buffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode, const std::vector<unsigned char>& dataBlock, bool updateSubKey)
		{
			std::size_t dataBlockByteSize = dataBlock.size();

			if(updateSubKey)
			{
				UpadateSubKeyOnly();
			}

			my_cpp2020_assert(dataBlockByteSize != 0 && dataBlockByteSize % 8 == 0, "The size of the input data must be a multiple of eight to ensure that the output data is properly sized! ", std::source_location::current());

			if(dataBlockByteSize == 8)
			{
				//Byte array data container size is 64 bits
				if(executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					buffer.Bitset64Object_Plain = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(dataBlock);
					buffer.Bitset64Object_Cipher = DES_Executor(buffer, executeMode);
					return Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(buffer.Bitset64Object_Cipher);
				}
				else if (executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					buffer.Bitset64Object_Cipher = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(dataBlock);
					buffer.Bitset64Object_Plain = DES_Executor(buffer, executeMode);
					return Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(buffer.Bitset64Object_Plain);
				}
				else
				{
					std::cout << "Wrong DES Algorithm worker is selected" << std::endl;
					abort();
				}
			}
			else
			{
				//Byte array data container size is not 64 bits

				std::vector<unsigned char> processedDataBlock;

				switch (executeMode)
				{
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
					{
						std::deque<std::vector<unsigned char>> dataBlockChain;
						std::deque<std::vector<unsigned char>> processedDataBlockChain;

						CommonToolkit::ProcessingDataBlock::splitter(dataBlock, std::back_inserter(dataBlockChain), 8);

						//For each 8-byte size of data to be processed
						for(auto& EightClassicByteBlock : dataBlockChain)
						{
							buffer.Bitset64Object_Plain = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(EightClassicByteBlock);
							buffer.Bitset64Object_Cipher = this->Encryption(buffer.Bitset64Object_Plain);
							processedDataBlock = Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(buffer.Bitset64Object_Cipher);
							processedDataBlockChain.push_back(std::move(processedDataBlock));
						}

						processedDataBlock.clear();
						processedDataBlock.shrink_to_fit();

						CommonToolkit::ProcessingDataBlock::merger(processedDataBlockChain, std::back_inserter(processedDataBlock));

						dataBlockChain.clear();
						dataBlockChain.shrink_to_fit();

						break;
					}
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
					{
						std::deque<std::vector<unsigned char>> dataBlockChain;
						std::deque<std::vector<unsigned char>> processedDataBlockChain;

						CommonToolkit::ProcessingDataBlock::splitter(dataBlock, std::back_inserter(dataBlockChain), 8);

						//For each 8-byte size of data to be processed
						for(auto& EightClassicByteBlock : dataBlockChain)
						{
							buffer.Bitset64Object_Cipher = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(EightClassicByteBlock);
							buffer.Bitset64Object_Plain = this->Decryption(buffer.Bitset64Object_Cipher);
							processedDataBlock = Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(buffer.Bitset64Object_Plain);
							processedDataBlockChain.push_back(processedDataBlock);
						}

						processedDataBlock.clear();
						processedDataBlock.shrink_to_fit();

						CommonToolkit::ProcessingDataBlock::merger(processedDataBlockChain, std::back_inserter(processedDataBlock));

						dataBlockChain.clear();
						dataBlockChain.shrink_to_fit();

						break;
					}
					default:
					{
						std::cout << "Wrong DES Algorithm worker is selected" << std::endl;
						abort();
					}
				}

				return processedDataBlock;
			}
		}

		explicit Worker(std::bitset<64>& key) : OriginalKey(key), RecordOriginalKey(key)
		{
		}

		Worker() :OriginalKey(std::bitset<64>()), RecordOriginalKey(std::bitset<64>())
		{
		}

		~Worker() = default;

		Worker(Worker& _object) = delete;
		Worker& operator=(Worker& _object) = delete;
	};

	inline void TripleDES_Executor(Worker& DES_Worker, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode, const std::vector<unsigned char>& inputDataBlock, std::deque<std::vector<unsigned char>>& keyBlockChain, std::vector<unsigned char>& outputDataBlock, bool forceAssert = true)
	{
		std::vector<std::bitset<64>> Bitset64_Keys;

		std::mt19937 pseudoRandomGenerator { static_cast<unsigned int>( keyBlockChain.front().operator[](0) ) };
		CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution number_distribution(0, 255);

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
				while(keyBlock.size() % 8 != 0)
				{
					unsigned char randomByte = static_cast<unsigned char>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bitset64_Keys.push_back( Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(keyBlock) );
			}
		}
		else
		{
			std::deque<std::vector<unsigned char>> copiedKeyBlockChain = keyBlockChain;

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
				while(keyBlock.size() % 8 != 0)
				{
					unsigned char randomByte = static_cast<unsigned char>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bitset64_Keys.push_back( Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(keyBlock) );
			}
		}

		std::size_t dataBlockByteSize = inputDataBlock.size();

		Worker::DataBuffer buffer;

		switch (executeMode)
		{
			//CipherText = Encryption(Decryption(Encryption(PlainText, Key), Key2), Key3);
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				//PKCS is Public Key Cryptography Standards
				/*
					https://en.wikipedia.org/wiki/Padding_(cryptography)
					https://datatracker.ietf.org/doc/html/rfc5652
					PKCS#7 is described in RFC 5652. (section-6.3)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Padding Data
				std::size_t padedDataByteSize = dataBlockByteSize + 8 - (dataBlockByteSize % 8);
				std::size_t paddingDataByteSize = padedDataByteSize - dataBlockByteSize;
				const std::vector<unsigned char> paddingData(paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));

				std::vector<unsigned char> temporaryDataBlock { std::move(inputDataBlock) };
				temporaryDataBlock.insert(temporaryDataBlock.end(), paddingData.begin(), paddingData.end());

				std::cout << "TripleDES Encryption Start !" << std::endl;

				for(signed int index = 0; index < Bitset64_Keys.size(); index += 3)
				{
					//Use Encryption Main Round Key 1
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index));
					temporaryDataBlock = DES_Worker.DES_Executor(buffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				
					//Use Encryption Main Round Key 2
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index + 1));
					temporaryDataBlock = DES_Worker.DES_Executor(buffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);

					//Use Encryption Main Round Key 3
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index + 2));
					temporaryDataBlock = DES_Worker.DES_Executor(buffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				}

				std::cout << "TripleDES Encryption End !" << std::endl;

				outputDataBlock.resize(padedDataByteSize);

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
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				std::vector<unsigned char> temporaryDataBlock { std::move(inputDataBlock) };

				std::cout << "TripleDES Decryption Start !" << std::endl;

				for(signed int index = Bitset64_Keys.size() - 1; index > 0; index -= 3)
				{
					//Use Decryption Main Round Key 1
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index));
					temporaryDataBlock = DES_Worker.DES_Executor(buffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);
				
					//Use Decryption Main Round Key 2
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index - 1));
					temporaryDataBlock = DES_Worker.DES_Executor(buffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);

					//Use Decryption Main Round Key 3
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index - 2));
					temporaryDataBlock = DES_Worker.DES_Executor(buffer, Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);
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

				//PKCS is Public Key Cryptography Standards
				/*
					https://en.wikipedia.org/wiki/Padding_(cryptography)
					https://datatracker.ietf.org/doc/html/rfc5652
					PKCS#7 is described in RFC 5652. (section-6.3)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Unpadding Data
				std::size_t paddingDataByteSize = outputDataBlock.back();
				const std::vector<unsigned char> paddingData(paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));
				auto searchHasBeenFoundSubrange = std::ranges::search(outputDataBlock.end() - paddingDataByteSize * 2, outputDataBlock.end(), paddingData.begin(), paddingData.end());
				if(searchHasBeenFoundSubrange.begin() != searchHasBeenFoundSubrange.end())
				{
					outputDataBlock.erase(searchHasBeenFoundSubrange.begin(), searchHasBeenFoundSubrange.end());
					outputDataBlock.shrink_to_fit();
				}
				else
				{
					throw std::logic_error("Operation failed, maybe the padding data, before encryption, was corrupted?");
				}

				break;
			}
			default:
			{
				std::cout << "Wrong TripleDES Algorithm worker is selected" << std::endl;
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
					https://datatracker.ietf.org/doc/html/rfc5652
					PKCS#7 is described in RFC 5652. (section-6.3)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Padding Data
				if(dataBlockByteSize % 16 != 0)
				{
					if(dataBlockByteSize > 16)
					{
						std::size_t paddingDataByteSize = 16 - (dataBlockByteSize % 16);
						const std::vector<unsigned char> paddingDataBytes(static_cast<unsigned char>(paddingDataByteSize), paddingDataByteSize);
						dataBlockCopy.insert( dataBlockCopy.end(), paddingDataBytes.begin(), paddingDataBytes.end() );
					}
					else if(dataBlockByteSize < 16)
					{
						std::size_t paddingDataByteSize = 16 - dataBlockByteSize;
						const std::vector<unsigned char> paddingDataBytes(static_cast<unsigned char>(paddingDataByteSize), paddingDataByteSize);
						dataBlockCopy.insert( dataBlockCopy.end(), paddingDataBytes.begin(), paddingDataBytes.end() );
					}
				}
				else
				{
					const std::vector<unsigned char> paddingDataBytes(static_cast<unsigned char>(16), 16);
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
					https://datatracker.ietf.org/doc/html/rfc5652
					PKCS#7 is described in RFC 5652. (section-6.3)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Unpadding Data

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