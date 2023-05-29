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

//#define USE_MEMORY_TRACKER_CODE
//#define PRINT_MEMORY_TRACKING_INFORATION

/* Priority Level 1 */
#include "./Support+Library/Support-Library.hpp"
//#include "./Support+Library/Support-MyType.hpp"

/* Priority Level 2 */
#include "UtilTools/UtilTools.hpp"
#include "CommonToolkit/CommonToolkit.hpp"
#include "CommonToolkit/BytesExchangeInteger.hpp"

/* Priority Level 3 */
#include "ThreadingToolkit/Pool/Version1/ThreadPool.hpp"
#include "ThreadingToolkit/Pool/Version2/ThreadPool.hpp"
#include "ThreadingToolkit/Pool/Version3/ThreadPool.hpp"
#include "ThreadingToolkit/Time/TimedThreadExecutor.hpp"
#include "ThreadingToolkit/Wrapper/AsyncTaskWrapper.hpp"

/* Priority Level 4 */
#include "CommonSecurity/CommonSecurity.hpp"
#include "CommonSecurity/SecureRandomUtilLibrary.hpp"

/* Priority Level 5 */
#include "CommonSecurity/BlockDataCryption.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmCorrectedBlockTEA.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmAES.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmTripleDES.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmRC6.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmChinaShangYongMiMa4.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmTwofish.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmThreefish.hpp"
#include "CommonSecurity/BlockCiphers/AlgorithmSerpent.hpp"
#include "CommonSecurity/StreamDataCryption.hpp"

/* Priority Level 6 */
#include "CommonSecurity/SecureHashProvider/Hasher.hpp"
#include "CommonSecurity/KeyDerivationFunction/AlgorithmHMAC.hpp"
#include "CommonSecurity/KeyDerivationFunction/AlgorithmArgon2.hpp"
#include "CommonSecurity/KeyDerivationFunction/AlgorithmScrypt.hpp"
#include "CommonSecurity/DeterministicRandomBitGenerator/BasedAlgorithmHMAC.hpp"

/* Priority Level 7  */
#include "CustomSecurity/ByteSubstitutionBoxToolkit.hpp"
#include "CustomSecurity/DataObfuscator.hpp"

/* Priority Level 8 */
#include "CommonSecurity/DataHashingWrapper.hpp"
#include "CommonSecurity/AEAD_Cascaded.hpp"
#include "CommonSecurity/Shamir's-SecretSharing.hpp"

/* Priority Level 9 */
#include "CustomSecurity/CustomCryption.hpp"

/* Priority Level 10 */
#include "CustomSecurity/WonderfulDesignIdeas.hpp"

/* Priority Level 11 */
#include "./FileProcessing/FileProcessing.hpp"
#include "./FileProcessing/MemoryMappingByFile.hpp"

/**
*	@file IsFor_EODF_Reborn.hpp
*
*	@brief 加密或解密文件重生版本 - 实用工具
*	@brief Encrypting or Decrypting File Reborn Versions - Utility tools
*
*	作者成员：
*	Author Members:
*
*	@author Project Owner and Module Designer: Twilight-Dream
*	@author Algorithm Designer: Spiritual-Fish
*	@author Tech Supporter : XiLiuFeng
* 
*	功能名：隐秘的奥尔德雷斯之谜
*	Function Name: OaldresPuzzle-Cryptic
*
*	@details
*	项目反馈URL (Github/GitLab):
*	Project Feedback URL (Github/GitLab):
*
*	联系方式:
*	Contact details:
*	
*		With by bilibili website personal space:
*		Twilight-Dream https://space.bilibili.com/21974189
*		Spiritual-Fish https://space.bilibili.com/1545018134
*		XiLiuFeng https://space.bilibili.com/4357220
*
*	All copyrights reserved from ©2021 year forward (Author Members)
*	保留所有权利，从@2021年开始 (作者成员)
*/
namespace EODF_Reborn
{
	// 压缩和解压缩文件数据过程处理
	// Compress and Decompress file data process handling
	namespace CompressDataProcessing
	{
		//文件数据压缩器
		//File data compressor
		class FileCompressor
		{
		};

		//文件数据解压缩器
		//File data decompressor
		class FileDecompressor
		{
		};

	}  // namespace CompressDataProcessing

	// 主程序模块实现
	// Main program module implementation
	namespace MainProgram_ModuleImplementation
	{

		

	}  // namespace MainProgram_ModulemImplementation
}  // namespace EODF_Reborn