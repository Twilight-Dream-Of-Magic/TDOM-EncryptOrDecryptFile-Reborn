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


namespace CommonSecurity
{
	static struct BlockCipherConstant1
	{
		//128 bits
		static constexpr std::size_t DataBlockByteSize = 16;

		//128 bits
		static constexpr std::size_t KeyBlockByteSize = 16;
	};

	static struct BlockCipherConstant2
	{
		//128 bits
		static constexpr std::size_t DataBlockByteSize = 16;

		//192 bits
		static constexpr std::size_t KeyBlockByteSize = 24;
	};

	static struct BlockCipherConstant3
	{
		//128 bits
		static constexpr std::size_t DataBlockByteSize = 16;

		//256 bits
		static constexpr std::size_t KeyBlockByteSize = 32;
	};

	/*
		最简单的工作模式即为电子密码本（Electronic codebook，ECB）模式。
		需要加密的消息按照块密码的块大小被分为数个块，并对每个块进行独立加密。
		The simplest mode of operation is the electronic codebook (ECB) mode.
		The message to be encrypted is divided into several blocks according to the block size of the block cipher, and each block is encrypted independently.

		Execute Process (执行过程):
		CipherText[index] = EncryptionDataFunction(PlainText[index], Key[index])

		PlainText[index] = DecryptionDataFunction(CipherText[index], Key[index])
	*/

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

	/*
		输出反馈（OFB）
		输出反馈模式（Output feedback, OFB）可以将块密码变成同步的流密码。
		它产生密钥流的块，然后将其与明文块进行异或，得到密文。与其它流密码一样，密文中一个位的翻转会使明文中同样位置的位也产生翻转。
		这种特性使得许多错误校正码，例如奇偶校验位，即使在加密前计算，而在加密后进行校验也可以得出正确结果。

		由于 XOR 操作的对称性，基于加密函数的流密码和基于解密函数的流密码操作是完全相同的

		Execute Process (执行过程):

		CipherInitialVector[index] = EncryptionDataFunction(InitialVector[index], Key[index])
		CipherText[index] = PlainText[index] ^ CipherInitialVector[index]
		InitialVector[index] = CipherInitialVector[index]

		Or

		CipherInitialVector[index] = DecryptionDataFunction(InitialVector[index], Key[index])
		CipherText[index] = PlainText[index] ^ CipherInitialVector[index]
		InitialVector[index] = CipherInitialVector[index]
	*/

	/*
		标准块密码器 统一接口调用
		Standard block ciphers Unified interface calls
	*/

	struct BlockCipher128_256
	{
		static constexpr auto DataBlockByteSize = CommonSecurity::BlockCipherConstant3::DataBlockByteSize;
		static constexpr auto KeyBlockByteSize = CommonSecurity::BlockCipherConstant3::KeyBlockByteSize;

		/*
			Use the cryptographic key schedule algorithm to process one key block of data
		*/
		virtual void KeyExpansion(std::span<const std::uint8_t> BytesKey) = 0;

		/*
			Use the cryptographic encryption algorithms to process one data block of data
		*/
		virtual void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) = 0;

		/*
			Use the cryptographic decryption algorithms to process one data block of data
		*/
		virtual void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) = 0;

		void EncryptionWithECB(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));
				this->ProcessBlockEncryption(Input.subspan(DataOffset, DataBlockByteSize), Output.subspan(DataOffset, DataBlockByteSize));
			}
		}

		void DecryptionWithECB(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));
				this->ProcessBlockDecryption(Input.subspan(DataOffset, DataBlockByteSize), Output.subspan(DataOffset, DataBlockByteSize));
			}
		}

		void EncryptionWithCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] ^= InputBlock[Index];

				this->ProcessBlockEncryption(Buffer, OutputBlock);

				::memcpy(Buffer.data(), OutputBlock.data(), DataBlockByteSize);
			}
		}

		void DecryptionWithCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockDecryption(InputBlock, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] ^= Buffer[Index];

				::memcpy(Buffer.data(), InputBlock.data(), DataBlockByteSize);
			}
		}

		void EncryptionWithPCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				::memcpy(Buffer2.data(), InputBlock.data(), DataBlockByteSize);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer2[Index] ^= Buffer[Index];

				this->ProcessBlockEncryption(Buffer2, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] = InputBlock[Index] ^ OutputBlock[Index];
			}
		}

		void DecryptionWithPCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				::memcpy(Buffer2.data(), InputBlock.data(), DataBlockByteSize);

				this->ProcessBlockDecryption(Buffer2, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] ^= Buffer[Index];

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] = OutputBlock[Index] ^ InputBlock[Index];
			}
		}

		void EncryptionWithCFB(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] = Buffer2[Index] ^ InputBlock[Index];

				::memcpy(Buffer.data(), OutputBlock.data(), DataBlockByteSize);
			}
		}

		void DecryptionWithCFB(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] = InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), InputBlock.data(), DataBlockByteSize);
			}
		}

		void OFB_StreamModeBasedEncryptFunction(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				auto OutputBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < InputBlock.size(); ++Index)
					OutputBlock[Index] =  InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), Buffer2.data(), DataBlockByteSize);
			}
		}

		void OFB_StreamModeBasedDecryptFunction(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				auto OutputBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				this->ProcessBlockDecryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < InputBlock.size(); ++Index)
					OutputBlock[Index] =  InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), Buffer2.data(), DataBlockByteSize);
			}
		}

		void CTR_StreamModeBasedEncryptFunction(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			auto UniformInteger_Pointer = std::make_unique<CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t>>
			(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
			auto& UniformInteger = *UniformInteger_Pointer;
			
			//Seed, Seed2 = BytesView(Key)
			//NumberOnce = UniformInteger(PRNG)
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			//This algorithm comes from RC4+
			//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
			CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG((PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5));

			std::uint64_t NumberOncePart = 0; //Number Once Bytes Size Is 8
			std::uint64_t CounterPart = 0; //Counter Bytes Size Is 8
			std::array<std::uint8_t, DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, DataBlockByteSize> KeyStream {};
			
			//Change number once value is uniform random integer
			NumberOncePart = UniformInteger(PRNG);

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += DataBlockByteSize)
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, KeyBlockByteSize);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				this->KeyExpansion(KeyBlock);
				this->ProcessBlockEncryption(CounterBlock, KeyStream);
					
				for(std::size_t Index = 0; Index < InputDataBlock.size(); ++Index)
				{
					OutputDataBlock[Index] = KeyStream[Index] ^ InputDataBlock[Index];
				}

				if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0)
				{
					++SanityCounterLow;
				}
				else if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0)
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;
					
					//Change number once value is uniform random integer
					NumberOncePart = UniformInteger(PRNG);
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += KeyBlockByteSize;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}

			UniformInteger_Pointer.reset();
		}

		void CTR_StreamModeBasedDecryptFunction(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			auto UniformInteger_Pointer = std::make_unique<CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t>>
			(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
			auto& UniformInteger = *UniformInteger_Pointer;
			
			//Seed, Seed2 = BytesView(Key)
			//NumberOnce = UniformInteger(PRNG)
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			//This algorithm comes from RC4+
			//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
			CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG((PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5));

			std::uint64_t NumberOncePart = 0; //Number Once Bytes Size Is 8
			std::uint64_t CounterPart = 0; //Counter Bytes Size Is 8
			std::array<std::uint8_t, DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, DataBlockByteSize> KeyStream {};
			
			//Change number once value is uniform random integer
			NumberOncePart = UniformInteger(PRNG);

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += DataBlockByteSize)
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, KeyBlockByteSize);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				this->KeyExpansion(KeyBlock);
				this->ProcessBlockDecryption(CounterBlock, KeyStream);
					
				for(std::size_t Index = 0; Index < InputDataBlock.size(); ++Index)
				{
					OutputDataBlock[Index] = KeyStream[Index] ^ InputDataBlock[Index];
				}

				if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0)
				{
					++SanityCounterLow;
				}
				else if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0)
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					//Change number once value is uniform random integer
					NumberOncePart = UniformInteger(PRNG);
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += KeyBlockByteSize;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}

			UniformInteger_Pointer.reset();
		}

		BlockCipher128_256() = default;
		virtual ~BlockCipher128_256() = default;
	};

	struct BlockCipher128_192
	{
		static constexpr auto DataBlockByteSize = CommonSecurity::BlockCipherConstant2::DataBlockByteSize;
		static constexpr auto KeyBlockByteSize = CommonSecurity::BlockCipherConstant2::KeyBlockByteSize;

		virtual void KeyExpansion(std::span<const std::uint8_t> BytesKey) = 0;

		virtual void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) = 0;
		virtual void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) = 0;

		void EncryptionWithECB(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));
				this->ProcessBlockEncryption(Input.subspan(DataOffset, DataBlockByteSize), Output.subspan(DataOffset, DataBlockByteSize));
			}
		}

		void DecryptionWithECB(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));
				this->ProcessBlockDecryption(Input.subspan(DataOffset, DataBlockByteSize), Output.subspan(DataOffset, DataBlockByteSize));
			}
		}

		void EncryptionWithCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] ^= InputBlock[Index];

				this->ProcessBlockEncryption(Buffer, OutputBlock);

				::memcpy(Buffer.data(), OutputBlock.data(), DataBlockByteSize);
			}
		}

		void DecryptionWithCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockDecryption(InputBlock, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] ^= Buffer[Index];

				::memcpy(Buffer.data(), InputBlock.data(), DataBlockByteSize);
			}
		}

		void EncryptionWithPCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				::memcpy(Buffer2.data(), InputBlock.data(), DataBlockByteSize);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer2[Index] ^= Buffer[Index];

				this->ProcessBlockEncryption(Buffer2, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] = InputBlock[Index] ^ OutputBlock[Index];
			}
		}

		void DecryptionWithPCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				::memcpy(Buffer2.data(), InputBlock.data(), DataBlockByteSize);

				this->ProcessBlockDecryption(Buffer2, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] ^= Buffer[Index];

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] = OutputBlock[Index] ^ InputBlock[Index];
			}
		}

		void EncryptionWithCFB(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] = Buffer2[Index] ^ InputBlock[Index];

				::memcpy(Buffer.data(), OutputBlock.data(), DataBlockByteSize);
			}
		}

		void DecryptionWithCFB(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] = InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), InputBlock.data(), DataBlockByteSize);
			}
		}

		void OFB_StreamModeBasedEncryptFunction(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				auto OutputBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < InputBlock.size(); ++Index)
					OutputBlock[Index] =  InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), Buffer2.data(), DataBlockByteSize);
			}
		}

		void OFB_StreamModeBasedDecryptFunction(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				auto OutputBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				this->ProcessBlockDecryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < InputBlock.size(); ++Index)
					OutputBlock[Index] =  InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), Buffer2.data(), DataBlockByteSize);
			}
		}

		void CTR_StreamModeBasedEncryptFunction(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			auto UniformInteger_Pointer = std::make_unique<CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t>>
			(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
			auto& UniformInteger = *UniformInteger_Pointer;
			
			//Seed, Seed2 = BytesView(Key)
			//NumberOnce = UniformInteger(PRNG)
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			//This algorithm comes from RC4+
			//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
			CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG((PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5));

			std::uint64_t NumberOncePart = 0; //Number Once Bytes Size Is 8
			std::uint64_t CounterPart = 0; //Counter Bytes Size Is 8
			std::array<std::uint8_t, DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, DataBlockByteSize> KeyStream {};
			
			//Change number once value is uniform random integer
			NumberOncePart = UniformInteger(PRNG);

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += DataBlockByteSize)
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, KeyBlockByteSize);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				this->KeyExpansion(KeyBlock);
				this->ProcessBlockEncryption(CounterBlock, KeyStream);
					
				for(std::size_t Index = 0; Index < InputDataBlock.size(); ++Index)
				{
					OutputDataBlock[Index] = KeyStream[Index] ^ InputDataBlock[Index];
				}

				if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0)
				{
					++SanityCounterLow;
				}
				else if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0)
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					//Change number once value is uniform random integer
					NumberOncePart = UniformInteger(PRNG);
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += KeyBlockByteSize;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}

			UniformInteger_Pointer.reset();
		}

		void CTR_StreamModeBasedDecryptFunction(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			auto UniformInteger_Pointer = std::make_unique<CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t>>
			(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
			auto& UniformInteger = *UniformInteger_Pointer;
			
			//Seed, Seed2 = BytesView(Key)
			//NumberOnce = UniformInteger(PRNG)
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			//This algorithm comes from RC4+
			//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
			CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG((PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5));

			std::uint64_t NumberOncePart = 0; //Number Once Bytes Size Is 8
			std::uint64_t CounterPart = 0; //Counter Bytes Size Is 8
			std::array<std::uint8_t, DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, DataBlockByteSize> KeyStream {};
			
			//Change number once value is uniform random integer
			NumberOncePart = UniformInteger(PRNG);

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += DataBlockByteSize)
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, KeyBlockByteSize);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				this->KeyExpansion(KeyBlock);
				this->ProcessBlockDecryption(CounterBlock, KeyStream);
					
				for(std::size_t Index = 0; Index < InputDataBlock.size(); ++Index)
				{
					OutputDataBlock[Index] = KeyStream[Index] ^ InputDataBlock[Index];
				}

				if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0)
				{
					++SanityCounterLow;
				}
				else if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0)
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					//Change number once value is uniform random integer
					NumberOncePart = UniformInteger(PRNG);
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += KeyBlockByteSize;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}

			UniformInteger_Pointer.reset();
		}

		BlockCipher128_192() = default;
		virtual ~BlockCipher128_192() = default;
	};

	struct BlockCipher128_128
	{
		static constexpr auto DataBlockByteSize = CommonSecurity::BlockCipherConstant1::DataBlockByteSize;
		static constexpr auto KeyBlockByteSize = CommonSecurity::BlockCipherConstant1::KeyBlockByteSize;

		virtual void KeyExpansion(std::span<const std::uint8_t> BytesKey) = 0;

		virtual void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) = 0;
		virtual void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) = 0;

		void EncryptionWithECB(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));
				this->ProcessBlockEncryption(Input.subspan(DataOffset, DataBlockByteSize), Output.subspan(DataOffset, DataBlockByteSize));
			}
		}

		void DecryptionWithECB(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));
				this->ProcessBlockDecryption(Input.subspan(DataOffset, DataBlockByteSize), Output.subspan(DataOffset, DataBlockByteSize));
			}
		}

		void EncryptionWithCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] ^= InputBlock[Index];

				this->ProcessBlockEncryption(Buffer, OutputBlock);

				::memcpy(Buffer.data(), OutputBlock.data(), DataBlockByteSize);
			}
		}

		void DecryptionWithCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockDecryption(InputBlock, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] ^= Buffer[Index];

				::memcpy(Buffer.data(), InputBlock.data(), DataBlockByteSize);
			}
		}

		void EncryptionWithPCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				::memcpy(Buffer2.data(), InputBlock.data(), DataBlockByteSize);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer2[Index] ^= Buffer[Index];

				this->ProcessBlockEncryption(Buffer2, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] = InputBlock[Index] ^ OutputBlock[Index];
			}
		}

		void DecryptionWithPCBC(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				::memcpy(Buffer2.data(), InputBlock.data(), DataBlockByteSize);

				this->ProcessBlockDecryption(Buffer2, OutputBlock);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] ^= Buffer[Index];

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					Buffer[Index] = OutputBlock[Index] ^ InputBlock[Index];
			}
		}

		void EncryptionWithCFB(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] = Buffer2[Index] ^ InputBlock[Index];

				::memcpy(Buffer.data(), OutputBlock.data(), DataBlockByteSize);
			}
		}

		void DecryptionWithCFB(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.size() % DataBlockByteSize != 0 && (!Input.empty()))
				my_cpp2020_assert(false, "Error: The input data block size is not a multiple of 128 bits!", std::source_location::current());
			if((Output.size() % DataBlockByteSize != 0) && (!Output.empty()))
				my_cpp2020_assert(false, "Error: The output data block size is not a multiple of 128 bits!", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, DataBlockByteSize);
				auto OutputBlock = Output.subspan(DataOffset, DataBlockByteSize);

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < DataBlockByteSize; ++Index)
					OutputBlock[Index] = InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), InputBlock.data(), DataBlockByteSize);
			}
		}

		void OFB_StreamModeBasedEncryptFunction(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				auto OutputBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				this->ProcessBlockEncryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < InputBlock.size(); ++Index)
					OutputBlock[Index] =  InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), Buffer2.data(), DataBlockByteSize);
			}
		}

		void OFB_StreamModeBasedDecryptFunction(std::span<const std::uint8_t> InitialVector, std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::array<std::uint8_t, DataBlockByteSize> Buffer {};
			std::array<std::uint8_t, DataBlockByteSize> Buffer2 {};
			::memcpy(Buffer.data(), InitialVector.data(), DataBlockByteSize);

			for
			(
				std::uint64_t DataOffset = 0, KeyOffset = 0; 
				DataOffset < Input.size() && KeyOffset < BytesKey.size(); 
				DataOffset += DataBlockByteSize, KeyOffset += KeyBlockByteSize
			)
			{
				this->KeyExpansion(BytesKey.subspan(KeyOffset, KeyBlockByteSize));

				auto InputBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				auto OutputBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				this->ProcessBlockDecryption(Buffer, Buffer2);

				for(std::uint32_t Index = 0; Index < InputBlock.size(); ++Index)
					OutputBlock[Index] =  InputBlock[Index] ^ Buffer2[Index];

				::memcpy(Buffer.data(), Buffer2.data(), DataBlockByteSize);
			}
		}

		void CTR_StreamModeBasedEncryptFunction(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			auto UniformInteger_Pointer = std::make_unique<CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t>>
			(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
			auto& UniformInteger = *UniformInteger_Pointer;
			
			//Seed, Seed2 = BytesView(Key)
			//NumberOnce = UniformInteger(PRNG)
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			//This algorithm comes from RC4+
			//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
			CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG((PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5));

			std::uint64_t NumberOncePart = 0; //Number Once Bytes Size Is 8
			std::uint64_t CounterPart = 0; //Counter Bytes Size Is 8
			std::array<std::uint8_t, DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, DataBlockByteSize> KeyStream {};
			
			//Change number once value is uniform random integer
			NumberOncePart = UniformInteger(PRNG);

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += DataBlockByteSize)
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, KeyBlockByteSize);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				this->KeyExpansion(KeyBlock);
				this->ProcessBlockEncryption(CounterBlock, KeyStream);
					
				for(std::size_t Index = 0; Index < InputDataBlock.size(); ++Index)
				{
					OutputDataBlock[Index] = KeyStream[Index] ^ InputDataBlock[Index];
				}

				if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0)
				{
					++SanityCounterLow;
				}
				else if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0)
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					//Change number once value is uniform random integer
					NumberOncePart = UniformInteger(PRNG);
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += KeyBlockByteSize;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}

			UniformInteger_Pointer.reset();
		}

		void CTR_StreamModeBasedDecryptFunction(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			auto UniformInteger_Pointer = std::make_unique<CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t>>
			(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
			auto& UniformInteger = *UniformInteger_Pointer;
			
			//Seed, Seed2 = BytesView(Key)
			//NumberOnce = UniformInteger(PRNG)
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			//This algorithm comes from RC4+
			//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
			CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG((PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5));

			std::uint64_t NumberOncePart = 0; //Number Once Bytes Size Is 8
			std::uint64_t CounterPart = 0; //Counter Bytes Size Is 8
			std::array<std::uint8_t, DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, DataBlockByteSize> KeyStream {};
			
			//Change number once value is uniform random integer
			NumberOncePart = UniformInteger(PRNG);

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += DataBlockByteSize)
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, KeyBlockByteSize);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				this->KeyExpansion(KeyBlock);
				this->ProcessBlockDecryption(CounterBlock, KeyStream);
					
				for(std::size_t Index = 0; Index < InputDataBlock.size(); ++Index)
				{
					OutputDataBlock[Index] = KeyStream[Index] ^ InputDataBlock[Index];
				}

				if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0)
				{
					++SanityCounterLow;
				}
				else if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0)
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					//Change number once value is uniform random integer
					NumberOncePart = UniformInteger(PRNG);
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += KeyBlockByteSize;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}

			UniformInteger_Pointer.reset();
		}

		BlockCipher128_128() = default;
		virtual ~BlockCipher128_128() = default;
	};
}
