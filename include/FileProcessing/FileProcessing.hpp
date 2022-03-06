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

#include "c-plus-plus-serializer-master/c_plus_plus_serializer.h"

//文件处理数据的过程
//The process of file processing data
namespace FileProcessing
{
	enum class CryptographDataTypePassByFile : unsigned int
	{
		AES = 0,
		DES = 1,
		CUSTOM_OPC = 2,
	};

	//密码配置文件建造器
	//Cryptographic profile builder
	struct CryptographProfileBuilder
	{
		//文件大小
		//This file size
		std::size_t FileSize = 0;

		//填充的对齐数据的大小
		//This size of the filled alignment data
		std::size_t SizeOfTheFilledAlignment = 0;

		//文件主要名
		//This file main name
		std::wstring FileMainName;

		//文件扩展名
		//This file extension name
		std::wstring FileExtensionName;
		
		//原文件哈希
		//Hashing of original file data
		std::string FileDataHashedID;
		
		//文件压缩后数据的哈希
		//Hashing of data after file compression
		std::string FileCompressdDataHashID = "NULL_HASH_ID";

		//原文件数据经过密码处理之后的哈希
		//Hash of the original file data after cryptographic processing
		std::string FileProceesedDataHashID;
		
		//密码1的哈希数据()
		//The Password One Hash Data
		std::vector<std::byte> PasswordOneHashData;
		
		//密码2的哈希数据()
		//The Password Two Hash Data
		std::vector<std::byte> PasswordTwoHashData;
		
		//密码3的哈希数据()
		//The Password Three Hash Data
		std::vector<std::byte> PasswordThreeHashData;
		
		//密码4的哈希数据()
		//The Password Four Hash Data
		std::vector<std::byte> PasswordFourHashData;

		//对文件操作的密码学类型
		//Types of cryptography for file operations
		CryptographDataTypePassByFile CryptographDataEnumType;

		friend std::ostream& operator<<(std::ostream &out, CPlusPlus_Serializer::Bits<const CryptographProfileBuilder &> const profile_bulider)
        {
            out << CPlusPlus_Serializer::bits(profile_bulider.object_type.FileSize)
				<< CPlusPlus_Serializer::bits(profile_bulider.object_type.SizeOfTheFilledAlignment)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.FileMainName)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.FileExtensionName)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.FileDataHashedID)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.FileCompressdDataHashID)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.FileProceesedDataHashID)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.PasswordOneHashData)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.PasswordTwoHashData)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.PasswordThreeHashData)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.PasswordFourHashData)
                << CPlusPlus_Serializer::bits(profile_bulider.object_type.CryptographDataEnumType);
			return (out);
        }

        friend std::istream& operator>>(std::istream &in, CPlusPlus_Serializer::Bits<CryptographProfileBuilder &> profile_bulider)
        {
            in >> CPlusPlus_Serializer::bits(profile_bulider.object_type.FileSize) >>
				CPlusPlus_Serializer::bits(profile_bulider.object_type.SizeOfTheFilledAlignment) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.FileMainName) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.FileExtensionName) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.FileDataHashedID) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.FileCompressdDataHashID) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.FileProceesedDataHashID) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.PasswordOneHashData) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.PasswordTwoHashData) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.PasswordThreeHashData) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.PasswordFourHashData) >>
                CPlusPlus_Serializer::bits(profile_bulider.object_type.CryptographDataEnumType);
			return (in);
        }

		void swap(CryptographProfileBuilder& other)
		{
			std::swap(FileSize, other.FileSize);
			std::swap(SizeOfTheFilledAlignment, other.SizeOfTheFilledAlignment);
			FileMainName.swap(other.FileMainName);
			FileExtensionName.swap(other.FileExtensionName);
			FileDataHashedID.swap(FileDataHashedID);
			FileCompressdDataHashID.swap(other.FileCompressdDataHashID);
			FileProceesedDataHashID.swap(other.FileProceesedDataHashID);
			PasswordOneHashData.swap(other.PasswordOneHashData);
			PasswordTwoHashData.swap(other.PasswordTwoHashData);
			PasswordThreeHashData.swap(other.PasswordThreeHashData);
			PasswordFourHashData.swap(other.PasswordFourHashData);
			std::swap(CryptographDataEnumType, other.CryptographDataEnumType);
		}
	};

	static void profile_serialize (std::ofstream& out, const CryptographProfileBuilder& profile_bulider)
	{
		out << CPlusPlus_Serializer::bits(profile_bulider);
	}

	static void profile_deserialize (std::ifstream& in, CryptographProfileBuilder& profile_bulider)
	{
		in >> CPlusPlus_Serializer::bits(profile_bulider);
	}
}

#include "FileOperationNew.hpp"
