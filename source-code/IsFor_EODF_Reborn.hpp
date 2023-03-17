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

//Eigen is a C++ template library for linear algebra: matrices, vectors, numerical solvers, and related algorithms.
//https://gitlab.com/libeigen/eigen
#include <Eigen/Dense>
#include <unsupported/Eigen/KroneckerProduct>

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
#include "CommonSecurity/Shamir's-SecretSharing.hpp"

/* Priority Level 9 */
#include "CustomSecurity/CustomCryption.hpp"

/* Priority Level 10 */
#include "CustomSecurity/CryptionWorker.hpp"
#include "CustomSecurity/WonderfulDesignIdeas.hpp"
#include "CustomSecurity/CrypticDataThreadingWrapper.hpp"

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
		//制作UUID通过处理文件数据和使用简单哈希
		//Making UUIDs by processing file data and using simple hashes
		inline std::optional<std::string> ProcessingFileData_MakeUUID(const std::filesystem::path& file_path_name)
		{
			using namespace MemoryObjectConfrontationDiskFileData;
			using namespace EODF_Reborn;
			using namespace UtilTools;
			using namespace CrypticDataThreadingWrapper;

			using namespace CommonSecurity::FNV_1a;

			//RO is ReadOnly
			//RW is ReadAndWrite
			MemoryMapPointers ro_mmap_pointers_object = MakeDefaultMemoryMappingObject(MemoryMapTypes::SIGNED_READ_ONLY);
			auto& ro_mmap_pointer_reference  = ro_mmap_pointers_object.signed_ro();
			auto* managed_ro_mmap_pointer = ro_mmap_pointer_reference.get();

			//[packing and unpacking]
			//相关的内存映射对象数据，将会被进行打包和进行解包
			//The associated memory mapped object data will be packaged and unpacked
			
			mio::mmap_source mapped_ro_object;
			auto mmap_data_package = MMMO_TryAssociateFile_ToPack(file_path_name, managed_ro_mmap_pointer);
			bool associated_mmap_data_package_status = MMMO_FromUnpack(mmap_data_package, mapped_ro_object);

			if(associated_mmap_data_package_status)
			{
				std::size_t hashed_number {0};
				std::size_t hashed_number2 {0};
				std::size_t hashed_number3 {0};

				//Hashing function by FNV-1a algorithm
				Hasher::hash_combine hash_combine_object;
				constexpr std::size_t message_size = 4096;

				auto file_data_begin = mapped_ro_object.begin();
				auto file_data_end = mapped_ro_object.end();

				std::size_t	iteratorOffset;
				while (file_data_begin != file_data_end)
				{
					iteratorOffset = CommonToolkit::IteratorOffsetDistance( file_data_begin, file_data_end, message_size );
					if(iteratorOffset < message_size)
					{
						std::string temporary_string_data3 { file_data_begin, file_data_begin + iteratorOffset };
						hashed_number3 = hash_combine_object( temporary_string_data3 );

						hashed_number ^= hashed_number3;

						break;
					}
					else
					{
						auto file_part_data_begin = file_data_begin;
						auto file_part_data_end = file_data_begin + iteratorOffset;

						std::string temporary_string_data { file_part_data_begin, file_part_data_end };

						file_data_begin += iteratorOffset;

						iteratorOffset = CommonToolkit::IteratorOffsetDistance( file_data_begin, file_data_end, message_size );
						if(iteratorOffset < message_size)
						{
							continue;
						}
						else
						{
							file_part_data_begin = file_data_begin;
							file_part_data_end = file_data_begin + iteratorOffset;

							std::string temporary_string_data2 { file_part_data_begin, file_part_data_end };

							file_data_begin += iteratorOffset;

							if(!temporary_string_data.empty() && !temporary_string_data2.empty())
							{
								hashed_number = hash_combine_object( temporary_string_data );
								hashed_number2 = hash_combine_object( temporary_string_data2 );

								hashed_number ^= hashed_number2;
							}
							else
							{
								return std::nullopt;
							}
						}
					}
				}

				UnmappingMemoryMapObject(mapped_ro_object);

				std::string file_hash_string_part { std::move(DataStreamConverter::Integer2Hexadecimal(hashed_number)) };
				std::string file_hash_string_part2 { std::move(DataStreamConverter::Integer2Hexadecimal(hashed_number2)) };
				std::string file_hash_string_part3 { std::move(DataStreamConverter::Integer2Hexadecimal(hashed_number3)) };
				return file_hash_string_part + "-" + file_hash_string_part2 + "-" + file_hash_string_part3;
			}
			else
			{
				return std::nullopt;
			}
		}

		class CryptographFileDataHelper
		{

		private:
			std::filesystem::path UseEncryptorWithMemoryMapping
			(
				const std::filesystem::path& file_path_name,
				const std::filesystem::path& encrypted_file_name,
				std::deque<std::vector<std::uint8_t>>& builded_key_stream,
				FileProcessing::CryptographProfileBuilder& profile_builder,
				ThreadingToolkit::Pool::Version1::ThreadPool& threadPoolVersion1
			)
			{
				using namespace MemoryObjectConfrontationDiskFileData;

				// RO is ReadOnly
				// RW is ReadAndWrite

				try
				{
					std::cout << "UseEncryptorWithMemoryMapping: Please wait, the source file is copying to the target file.\n";
					std::filesystem::copy_file(file_path_name, encrypted_file_name);
				}
				catch (const std::filesystem::filesystem_error& excecption)
				{
					std::cout << "Could not copy file "
								<< "[" << file_path_name << "]"
								<< " , Error is " << excecption.what() << '\n';
					std::cout << "Source file path is: " << "[" << excecption.path1() << "]"
								<< "Taregt file path is: " 	<< "[" << excecption.path2() << "]" << '\n';;
				}

				MemoryMapPointers rw_mmap_pointers_object = MakeDefaultMemoryMappingObject( MemoryMapTypes::SIGNED_READ_AND_WRITE );

				auto* managed_rw_mmap_pointer = rw_mmap_pointers_object.signed_rw().get();

				//[packing and unpacking]
				//相关的内存映射对象数据，将会被进行打包和进行解包
				//The associated memory mapped object data will be packaged and unpacked
				
				mio::mmap_sink mapped_rw_object;
				std::error_code error_code_object;
				auto mmap_data_package = MMMO_TryAssociateFile_ToPack(encrypted_file_name, managed_rw_mmap_pointer);
				bool associated_mmap_data_package_status = MMMO_FromUnpack(mmap_data_package, mapped_rw_object, error_code_object);
				
				if (associated_mmap_data_package_status)
				{
					auto file_data_begin = mapped_rw_object.begin();
					auto file_data_end = mapped_rw_object.end();

					std::size_t	iterator_offset;

					constexpr std::size_t MB_Size = 1024 * 1024;

					//每个数据块有多少byte的大小?
					//What is the size of each data block in byte?
					constexpr std::size_t file_data_block_byte_size = 64 * MB_Size;

					//多少个数据块是按照一个组来处理？
					//How many data blocks are processed as a group?
					constexpr std::size_t file_data_block_byte_count = 4;

					constexpr std::size_t need_process_block_size = file_data_block_byte_size * file_data_block_byte_count;

					auto builded_key_stream_begin = builded_key_stream.begin();
					auto builded_key_stream_end = builded_key_stream.end();

					while (file_data_begin != file_data_end)
					{
						iterator_offset = CommonToolkit::IteratorOffsetDistance( file_data_begin, file_data_end, need_process_block_size );

						if(iterator_offset < need_process_block_size)
						{
							std::vector<char> file_data_part { file_data_begin, file_data_begin + iterator_offset };
								
							//Encryption Function
							//this->_EncryptingData_MemoryMappcation_(file_data_part, custom_encrypter, builded_key_stream, builded_key_stream_begin, builded_key_stream_end);

							const char* next_file_data_begin = file_data_begin + iterator_offset;

							//Change File Mapped Data
							for (std::size_t encrypted_data_offset = 0; file_data_begin != next_file_data_begin; ++encrypted_data_offset)
							{
								*file_data_begin = file_data_part.operator[](encrypted_data_offset);
								++file_data_begin;
							}

							MMMO_TrySyncDiskFile(mapped_rw_object, error_code_object);
							AnalysisErrorCode(error_code_object);

							file_data_part.clear();
							file_data_part.shrink_to_fit();
						}
						else
						{
							std::vector<char> file_data_part { file_data_begin, file_data_begin + need_process_block_size };
							
							//Encryption Function
							//this->_EncryptingData_MemoryMappcation_(file_data_part, custom_encrypter, builded_key_stream, builded_key_stream_begin, builded_key_stream_end);

							const char* next_file_data_begin = file_data_begin + need_process_block_size;

							//Change File Mapped Data
							for (std::size_t encrypted_data_offset = 0; file_data_begin != next_file_data_begin; ++encrypted_data_offset)
							{
								*file_data_begin = file_data_part.operator[](encrypted_data_offset);
								++file_data_begin;
							}

							MMMO_TrySyncDiskFile(mapped_rw_object, error_code_object);
							AnalysisErrorCode(error_code_object);

							file_data_part.clear();
							file_data_part.shrink_to_fit();
						}

						//Check the validity of the iterator (pointer) and update the memory address of the iterator (pointer)
						if(file_data_begin != file_data_end)
						{
							const std::ptrdiff_t pointer_distance = file_data_end - file_data_begin;

							if(pointer_distance > 0)
							{
								//?
								++file_data_begin;
							}
							else if(pointer_distance == 0)
							{
								continue;
							}
							else if(pointer_distance < 0)
							{
								UnmappingMemoryMapObject(mapped_rw_object);
								std::string error_message = "UseEncryptorWithMemoryMapping: A fatal logic error occurred when an iterator (pointer) was accessing a file that was already mapped to a memory block!\nThe iterator (pointer) has gone out of range of the memory block to which the file is mapped.";
								std::out_of_range iterator_access_abort(error_message);
								throw iterator_access_abort;
							}
						}
					}

					UnmappingMemoryMapObject(mapped_rw_object);
					return encrypted_file_name;
				}
				else
				{
					UnmappingMemoryMapObject(mapped_rw_object);
					AnalysisErrorCode(error_code_object);
				}
			}

			std::filesystem::path UseDecryptorWithMemoryMapping
			(
				const std::filesystem::path& file_path_name,
				const std::filesystem::path& decrypted_file_name,
				std::deque<std::vector<std::uint8_t>>& builded_key_stream,
				FileProcessing::CryptographProfileBuilder& profile_builder,
				ThreadingToolkit::Pool::Version1::ThreadPool& threadPoolVersion1
			)
			{
				using namespace MemoryObjectConfrontationDiskFileData;

				// RO is ReadOnly
				// RW is ReadAndWrite

				try
				{
					std::cout << "UseDecryptorWithMemoryMapping: Please wait, the source file is copying to the target file.\n";
					std::filesystem::copy_file(file_path_name, decrypted_file_name);
				}
				catch (const std::filesystem::filesystem_error& excecption)
				{
					std::cout << "Could not copy file "
								<< "[" << file_path_name << "]"
								<< " , Error is " << excecption.what() << '\n';
					std::cout << "Source file path is: " << "[" << excecption.path1() << "]"
								<< "Taregt file path is: " 	<< "[" << excecption.path2() << "]" << '\n';;
				}

				MemoryMapPointers rw_mmap_pointers_object = MakeDefaultMemoryMappingObject( MemoryMapTypes::SIGNED_READ_AND_WRITE );

				auto* managed_rw_mmap_pointer = rw_mmap_pointers_object.signed_rw().get();

				//[packing and unpacking]
				//相关的内存映射对象数据，将会被进行打包和进行解包
				//The associated memory mapped object data will be packaged and unpacked
								
				mio::mmap_sink mapped_rw_object;
				std::error_code error_code_object;
				auto mmap_data_package = MMMO_TryAssociateFile_ToPack(decrypted_file_name, managed_rw_mmap_pointer);
				bool associated_mmap_data_package_status = MMMO_FromUnpack(mmap_data_package, mapped_rw_object, error_code_object);

				if (associated_mmap_data_package_status)
				{
					auto file_data_begin = mapped_rw_object.begin();
					auto file_data_end = mapped_rw_object.end();

					std::size_t	iterator_offset;

					constexpr std::size_t MB_Size = 1024 * 1024;

					//每个数据块有多少byte的大小?
					//What is the size of each data block in byte?
					constexpr std::size_t file_data_block_byte_size = 64 * MB_Size;

					//多少个数据块是按照一个组来处理？
					//How many data blocks are processed as a group?
					constexpr std::size_t file_data_block_byte_count = 4;

					constexpr std::size_t need_process_block_size = file_data_block_byte_size * file_data_block_byte_count;

					auto builded_key_stream_begin = builded_key_stream.begin();
					auto builded_key_stream_end = builded_key_stream.end();

					while (file_data_begin != file_data_end)
					{
						iterator_offset = CommonToolkit::IteratorOffsetDistance( file_data_begin, file_data_end, need_process_block_size );

						if(iterator_offset < need_process_block_size)
						{
							std::vector<char> file_data_part { file_data_begin, file_data_begin + iterator_offset };
							
							//Decryption Function
							//this->_DecryptingData_MemoryMappcation_(file_data_part, custom_decrypter, builded_key_stream, builded_key_stream_begin, builded_key_stream_end);

							const char* next_file_data_begin = file_data_begin + iterator_offset;

							//Change File Mapped Data
							for (std::size_t decrypted_data_offset = 0; file_data_begin != next_file_data_begin; ++decrypted_data_offset)
							{
								*file_data_begin = file_data_part.operator[](decrypted_data_offset);
								++file_data_begin;
							}

							MMMO_TrySyncDiskFile(mapped_rw_object, error_code_object);
							AnalysisErrorCode(error_code_object);

							file_data_part.clear();
							file_data_part.shrink_to_fit();
						}
						else
						{
							std::vector<char> file_data_part { file_data_begin, file_data_begin + need_process_block_size };
							
							//Decryption Function
							//this->_DecryptingData_MemoryMappcation_(file_data_part, custom_decrypter, builded_key_stream, builded_key_stream_begin, builded_key_stream_end);

							const char* next_file_data_begin = file_data_begin + need_process_block_size;

							//Change File Mapped Data
							for (std::size_t decrypted_data_offset = 0; file_data_begin != next_file_data_begin; ++decrypted_data_offset)
							{
								*file_data_begin = file_data_part.operator[](decrypted_data_offset);
								++file_data_begin;
							}

							MMMO_TrySyncDiskFile(mapped_rw_object, error_code_object);
							AnalysisErrorCode(error_code_object);

							file_data_part.clear();
							file_data_part.shrink_to_fit();
						}

						//Check the validity of the iterator (pointer) and update the memory address of the iterator (pointer)
						if(file_data_begin != file_data_end)
						{
							const std::ptrdiff_t pointer_distance = file_data_end - file_data_begin;

							if(pointer_distance > 0)
							{
								//?
								++file_data_begin;
							}
							else if(pointer_distance == 0)
							{
								continue;
							}
							else if(pointer_distance < 0)
							{
								file_data_begin = file_data_end;
								UnmappingMemoryMapObject(mapped_rw_object);
								std::string error_message = "UseDecryptorWithMemoryMapping: A fatal logic error occurred when an iterator (pointer) was accessing a file that was already mapped to a memory block!\nThe iterator (pointer) has gone out of range of the memory block to which the file is mapped.";
								std::out_of_range iterator_access_abort(error_message);
								throw iterator_access_abort;
							}
						}
					}

					UnmappingMemoryMapObject(mapped_rw_object);
					return decrypted_file_name;
				}
				else
				{
					UnmappingMemoryMapObject(mapped_rw_object);
					AnalysisErrorCode(error_code_object);
				}
			}

			std::filesystem::path UseEncryptor
			(
				const std::filesystem::path& file_path_name,
				const std::filesystem::path& encrypted_file_name,
				std::deque<std::vector<std::uint8_t>>& builded_key_stream,
				FileProcessing::CryptographProfileBuilder& profile_builder,
				ThreadingToolkit::Pool::Version1::ThreadPool& threadPoolVersion1
			)
			{
				return encrypted_file_name;
			}

			std::filesystem::path UseDecryptor
			(
				const std::filesystem::path& file_path_name,
				const std::filesystem::path& decrypted_file_name,
				std::deque<std::vector<std::uint8_t>>& builded_key_stream,
				FileProcessing::CryptographProfileBuilder& profile_builder,
				ThreadingToolkit::Pool::Version1::ThreadPool& threadPoolVersion1
			)
			{
				return decrypted_file_name;
			}

		public:
			bool RunCustomEncryptionFile
			(
				const std::filesystem::path& profile_path_name,
				const std::filesystem::path& file_path_name,
				CommonSecurity::DataHashingWrapper::HashTokenForDataParameters& HashTokenForDataParameters_Instance,
				const FileProcessing::CryptographDataTypePassByFile& cryptograph_function_type,
				bool UseMemoryMappcation = false
			)
			{
				using namespace EODF_Reborn;
				using namespace UtilTools;
				using namespace CrypticDataThreadingWrapper;
				using namespace ThreadingToolkit;
				using FileProcessing::Operation::FileDataModuleAdapter;
				using CommonSecurity::DataHashingWrapper::BuildingKeyStream;

				if(profile_paths.find(profile_path_name.u8string()) != profile_paths.end())
				{
					return false;
				}
				else
				{
					profile_paths.insert(profile_path_name.u8string());

					if(file_paths.find(file_path_name.u8string()) != file_paths.end())
					{
						profile_paths.erase(file_path_name.u8string());
						return false;
					}
					else
					{
						file_paths.insert(file_path_name.u8string());
					}
				}

				FileProcessing::CryptographProfileBuilder profile_builder;

				if(!std::filesystem::exists(file_path_name))
				{
					std::stringstream error_message;
					error_message << "Error: An error occurred in the encryption operation, Because the path name "
									<< "[" << file_path_name << "] "
									<< "does not exist\n";
					std::runtime_error path_is_not_exist(error_message.str());

					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					throw path_is_not_exist;
				}
				else
				{
					if(!std::filesystem::is_regular_file(file_path_name))
					{
						std::stringstream error_message;
						error_message << "Error: file encryption failed, Because "
									  << "[" << file_path_name << "] "
									  << "is not a regular file\n";
						std::runtime_error path_is_not_regular_file(error_message.str());

						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						throw path_is_not_regular_file;
					}
				}

				if(std::filesystem::exists(profile_path_name))
				{
					std::cerr << "RunCustomEncryptionFile: Wait, what are you doing? You can't overwrite an existing file, I don't even know what it does!\nPlease use a non-existent filename as the path to the binary configuration file.\nThe operation is aborted!" << std::endl;
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				std::future<std::optional<std::string>> futureTask_makeHashDigestID = std::async(std::launch::async, ProcessingFileData_MakeUUID, std::ref(file_path_name));
				std::future<std::optional<std::deque<std::vector<std::uint8_t>>>> futureTask2_buildingKeyStream = std::async(std::launch::async, BuildingKeyStream<256>, std::ref(HashTokenForDataParameters_Instance));

				std::optional<std::string> optional_makeHashDigestID = futureTask_makeHashDigestID.get();
				std::optional<std::deque<std::vector<std::uint8_t>>> optional_buildedKeyStream = futureTask2_buildingKeyStream.get();

				std::deque<std::vector<std::uint8_t>> buildedKeyStream;

				if(optional_makeHashDigestID.has_value())
				{
					std::cout << "RunCustomEncryptionFile: Make file hash digest id is succeed!" << std::endl;
					std::string makeHashDigestID = optional_makeHashDigestID.value();

					profile_builder.FileDataHashedID = makeHashDigestID;

					std::cout << "RunCustomDecryptionFile: The file hash data is saved." << std::endl;
				}
				else
				{
					std::cerr << "RunCustomEncryptionFile: Make file hash digest id is failed!" << std::endl;

					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				if(optional_buildedKeyStream.has_value())
				{
					std::cout << "RunCustomEncryptionFile: Build key stream is succeed!" << std::endl;
					buildedKeyStream = optional_buildedKeyStream.value();

					profile_builder.PasswordOneHashData = buildedKeyStream.operator[](0);
					profile_builder.PasswordTwoHashData = buildedKeyStream.operator[](1);
					profile_builder.PasswordThreeHashData = buildedKeyStream.operator[](2);
					profile_builder.PasswordFourHashData = buildedKeyStream.operator[](3);

					std::cout << "RunCustomDecryptionFile: The password hash data is saved." << std::endl;
				}
				else
				{
					std::cerr << "RunCustomEncryptionFile: Build key stream is failed!" << std::endl;

					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				std::cout << "Please wait for your file to be encrypted......" << std::endl;

				/*std::vector<std::byte> buildedKeyBlock;

				CommonToolkit::ProcessingDataBlock::merger(buildedKeyStream, std::back_inserter(buildedKeyBlock));
				buildedKeyStream.clear();
				CommonToolkit::ProcessingDataBlock::splitter(buildedKeyBlock, buildedKeyStream, 128, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Move);*/

				//Aligning key data
				if(buildedKeyStream.back().size() % 128 != 0)
				{
					buildedKeyStream.pop_back();
				}

				std::unique_ptr<FileDataModuleAdapter> FDMA_Pointer = std::make_unique<FileDataModuleAdapter>();
				std::unique_ptr<std::deque<std::vector<char>>> pointer_filedata_blockchain = std::make_unique<std::deque<std::vector<char>>>();
				constexpr std::size_t MB_Size = 1024 * 1024;

				//每个数据块有多少MB的大小?
				//What is the size of each data block in MB?
				std::size_t file_data_block_byte_size = 128 * MB_Size;

				//多少个数据块是按照一个组来处理？
				//How many data blocks are processed as a group?
				std::size_t file_data_block_byte_count = 64;

				profile_builder.FileSize = std::filesystem::file_size(file_path_name);

				FileProcessing::Operation::BinaryStreamReader file_reader;
				FileProcessing::Operation::FILE_OPERATION_STATUS file_stream_operation_status = file_reader.ReadFileData(profile_builder.FileDataHashedID, file_path_name, FDMA_Pointer, pointer_filedata_blockchain.get(), file_data_block_byte_size, file_data_block_byte_count);

				switch (file_stream_operation_status)
				{
					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_EMPTY:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_RUNNING:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_ZERO:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_OVERLIMIT:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_NOT_STANDARD_DATA_SIZE:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					default:
						break;
				}

				std::filesystem::path encrypted_file_name;
				encrypted_file_name += file_path_name.u8string();
				encrypted_file_name += u8".mk-encrypted";

				if (file_stream_operation_status == FileProcessing::Operation::FILE_OPERATION_STATUS::DONE)
				{
					#if 0

					Cryptograph::CommonModule::ConversionBufferData_Input(FDMA_Pointer, pointer_filedata_blockchain.get());
					pointer_filedata_blockchain.get()->clear();
					auto* bytesPointer = std::addressof(FDMA_Pointer.get()->FileDataBytes);
					auto& fileDataPart = *(pointer_filedata_blockchain.get());

					//Do File Encryption
					Cryptograph::OaldresPuzzle_Cryptic::Version1::Encrypter CustomEncrypter;
					
					auto buildedKeyStreamBegin = buildedKeyStream.begin();
					auto buildedKeyStreamEnd = buildedKeyStream.end();

					for(auto begin = fileDataPart.begin(), end = fileDataPart.end(); begin != end; ++begin)
					{
						if(buildedKeyStreamBegin != buildedKeyStreamEnd)
						{
							CustomEncrypter.Main(*begin, *buildedKeyStreamBegin);
							++buildedKeyStreamBegin;
						}
						else
						{
							buildedKeyStreamBegin = buildedKeyStream.begin();
							CustomEncrypter.Main(*begin, *buildedKeyStreamBegin);
							++buildedKeyStreamBegin;
						}
					}
					
					Cryptograph::CommonModule::ConversionBufferData_Output(FDMA_Pointer, bytesPointer);
					bytesPointer->clear();
					auto* charactersPointer = std::addressof(FDMA_Pointer.get()->FileDataCharacters);

					#endif

					Pool::Version1::ThreadPool threadPoolVersion1(2, 4);

					if(UseMemoryMappcation)
					{
						std::function<std::filesystem::path()> taskFunction = std::bind_front(&CryptographFileDataHelper::UseEncryptorWithMemoryMapping, this, std::ref(file_path_name), std::ref(encrypted_file_name), std::ref(buildedKeyStream), std::ref(profile_builder), std::ref(threadPoolVersion1));

						std::future<std::filesystem::path> asyncTask = std::async(std::launch::async, taskFunction);
				
						while (std::future_status::ready != asyncTask.wait_for(std::chrono::seconds(10)))
						{
							if(std::future_status::ready == asyncTask.wait_for(std::chrono::seconds(10)))
							{
								break;
							}
						}

						try
						{
							encrypted_file_name = asyncTask.get();
						}
						catch ( const std::exception& except )
						{
							std::cerr << "[Error] Exception message is" << except.what() << std::endl;
						}

						futureTask_makeHashDigestID = ThreadingToolkit::Pool::Version2::ThreadPool::get_instance( 2 ).submit( std::bind_front(ProcessingFileData_MakeUUID, std::ref(encrypted_file_name)) );
						optional_makeHashDigestID = futureTask_makeHashDigestID.get();

						if(optional_makeHashDigestID.has_value())
						{
							std::cout << "UseEncryptorWithMemoryMapping: Make file hash digest id is succeed!" << std::endl;
							std::string makeHashDigestID = optional_makeHashDigestID.value();

							profile_builder.FileProceesedDataHashID = makeHashDigestID;

							std::cout << "UseEncryptorWithMemoryMapping: The processed file hash data is saved." << std::endl;
						}
						else
						{
							std::runtime_error make_hash_digest_is_invalid("UseEncryptorWithMemoryMapping: Make file hash digest id is failed!");
							throw make_hash_digest_is_invalid;
						}
					}
					else
					{
						this->UseEncryptor(file_path_name, encrypted_file_name, buildedKeyStream, profile_builder, threadPoolVersion1);

						futureTask_makeHashDigestID = ThreadingToolkit::Pool::Version2::ThreadPool::get_instance( 2 ).submit( std::bind_front(ProcessingFileData_MakeUUID, std::ref(encrypted_file_name)) );
						optional_makeHashDigestID = futureTask_makeHashDigestID.get();

						if(optional_makeHashDigestID.has_value())
						{
							std::cout << "RunCustomEncryptionFile: Make file hash digest id is succeed!" << std::endl;
							std::string makeHashDigestID = optional_makeHashDigestID.value();

							profile_builder.FileProceesedDataHashID = makeHashDigestID;

							std::cout << "RunCustomEncryptionFile: The processed file hash data is saved." << std::endl;
						}
						else
						{
							std::cerr << "RunCustomEncryptionFile: Make file hash digest id is failed!" << std::endl;

							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}
					}

					FileProcessing::Operation::BinaryStreamWriter file_writer;
					file_writer.WriteFileData(profile_builder.FileDataHashedID, encrypted_file_name, FDMA_Pointer, pointer_filedata_blockchain.get(), file_data_block_byte_size, file_data_block_byte_count);
				}

				std::ofstream outputProfileObject;

				#if defined(_WIN32)
				#define CURRENT_PATH_POINT_STRING L"."
				#else
				#define CURRENT_PATH_POINT_STRING "."
				#endif

				profile_builder.FileMainName = file_path_name.filename();
				profile_builder.FileMainName.resize(profile_builder.FileMainName.find(CURRENT_PATH_POINT_STRING, 0));
				profile_builder.FileExtensionName = file_path_name.extension();
				profile_builder.CryptographDataEnumType = cryptograph_function_type;

				#undef CURRENT_PATH_POINT_STRING

				outputProfileObject.open(profile_path_name, std::ios::binary | std::ios::trunc);
				if(outputProfileObject.is_open())
				{
					FileProcessing::profile_serialize(outputProfileObject, profile_builder);
					std::cout << "RunCustomEncryptionFile: All data has been saved to the binary configuration file" << std::endl;
				}
				else
				{
					std::cerr << "RunCustomEncryptionFile: Access to the binary configuration file happens to be blocked, Serialization is not complete!" << std::endl;
					outputProfileObject.close();
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				outputProfileObject.close();

				std::cout << "RunCustomEncryptionFile: Your file has been completed encrypted !!!" << std::endl;
				profile_paths.erase(profile_path_name.u8string());
				file_paths.erase(file_path_name.u8string());
				return true;
			}

			bool RunCustomDecryptionFile
			(
				const std::filesystem::path& profile_path_name,
				const std::filesystem::path& file_path_name,
				CommonSecurity::DataHashingWrapper::HashTokenForDataParameters& HashTokenForDataParameters_Instance,
				bool UseMemoryMappcation = false
			)
			{
				using namespace MemoryObjectConfrontationDiskFileData;
				using namespace EODF_Reborn;
				using namespace UtilTools;
				using namespace CrypticDataThreadingWrapper;
				using namespace ThreadingToolkit;
				using FileProcessing::Operation::FileDataModuleAdapter;
				using CommonSecurity::DataHashingWrapper::BuildingKeyStream;

				if(profile_paths.find(profile_path_name.u8string()) != profile_paths.end())
				{
					return false;
				}
				else
				{
					profile_paths.insert(profile_path_name.u8string());

					if(file_paths.find(file_path_name.u8string()) != file_paths.end())
					{
						profile_paths.erase(file_path_name.u8string());
						return false;
					}
					else
					{
						file_paths.insert(file_path_name.u8string());
					}
				}

				if(!std::filesystem::exists(file_path_name))
				{
					std::stringstream error_message;
					error_message << "Error: An error occurred in the decryption operation, Because the path name "
									<< "[" << file_path_name << "] "
									<< "does not exist\n";
					std::runtime_error path_is_not_exist(error_message.str());

					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					throw path_is_not_exist;
				}
				else
				{
					if(!std::filesystem::is_regular_file(file_path_name))
					{
						std::stringstream error_message;
						error_message << "Error: file decryption failed, Because "
									  << "[" << file_path_name << "] "
									  << "is not a regular file\n";
						std::runtime_error path_is_not_regular_file(error_message.str());

						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						throw path_is_not_regular_file;
					}
				}

				if(!std::filesystem::exists(profile_path_name))
				{
					std::cerr << "RunCustomDecryptionFile: The binary profile does not exist and the operation is aborted." << std::endl;
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				FileProcessing::CryptographProfileBuilder profile_builder;
				
				std::ifstream inputProfileObject;

				inputProfileObject.open(profile_path_name, std::ios::binary);
				if(inputProfileObject.is_open())
				{
					FileProcessing::profile_deserialize(inputProfileObject, profile_builder);
					std::cout << "RunCustomDecryptionFile: All data has been loaded from the binary configuration file" << std::endl;
				}
				else
				{
					std::cerr << "RunCustomDecryptionFile: Access to the binary configuration file happens to be blocked, Deserialization is not complete!" << std::endl;
					inputProfileObject.close();
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}
				inputProfileObject.close();

				std::future<std::optional<std::deque<std::vector<std::uint8_t>>>> futureTask_buildingKeyStream = std::async(std::launch::async, BuildingKeyStream<256>, std::ref(HashTokenForDataParameters_Instance));
				std::optional<std::deque<std::vector<std::uint8_t>>> optional_buildedKeyStream = futureTask_buildingKeyStream.get();
				
				std::deque<std::vector<std::uint8_t>> buildedKeyStream;

				if(optional_buildedKeyStream.has_value())
				{
					std::cout << "RunCustomDecryptionFile: Build key stream is succeed!" << std::endl;
					buildedKeyStream = optional_buildedKeyStream.value();

					if(profile_builder.PasswordOneHashData.empty() || profile_builder.PasswordTwoHashData.empty() || profile_builder.PasswordThreeHashData.empty() || profile_builder.PasswordFourHashData.empty())
					{
						std::cerr << "RunCustomDecryptionFile: Oops, there was an error in the profile data, maybe your binary profile is corrupted?" << std::endl;
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						return false;
					}
					else
					{
						if(buildedKeyStream.operator[](0) != profile_builder.PasswordOneHashData)
						{
							std::cerr << "RunCustomDecryptionFile: Oops, the password hash data doesn't match, maybe there is something wrong with your number 1 password?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}
						if(buildedKeyStream.operator[](1) != profile_builder.PasswordTwoHashData)
						{
							std::cerr << "RunCustomDecryptionFile: Oops, the password hash data doesn't match, maybe there is something wrong with your number 2 password?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}
						if(buildedKeyStream.operator[](2) != profile_builder.PasswordThreeHashData)
						{
							std::cerr << "RunCustomDecryptionFile: Oops, the password hash data doesn't match, maybe there is something wrong with your number 3 password?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}
						if(buildedKeyStream.operator[](3) != profile_builder.PasswordFourHashData)
						{
							std::cerr << "RunCustomDecryptionFile: Oops, the password hash data doesn't match, maybe there is something wrong with your number 4 password?" << std::endl;
							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}

						std::cout << "RunCustomDecryptionFile: The password hash check is complete." << std::endl;
					}
				}
				else
				{
					std::cerr << "RunCustomDecryptionFile: Build key stream is failed!" << std::endl;
					profile_paths.erase(profile_path_name.u8string());
					file_paths.erase(file_path_name.u8string());
					return false;
				}

				std::cout << "Please wait for your file to be decrypted......" << std::endl; 

				/*std::vector<std::byte> buildedKeyBlock;

				CommonToolkit::ProcessingDataBlock::merger(buildedKeyStream, std::back_inserter(buildedKeyBlock));
				buildedKeyStream.clear();
				CommonToolkit::ProcessingDataBlock::splitter(buildedKeyBlock, buildedKeyStream, 128, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Move);*/

				//Aligning key data
				if(buildedKeyStream.back().size() % 128 != 0)
				{
					buildedKeyStream.pop_back();
				}

				FileProcessing::CryptographDataTypePassByFile cryptograph_function_type = profile_builder.CryptographDataEnumType;

				std::unique_ptr<FileDataModuleAdapter> FDMA_Pointer = std::make_unique<FileDataModuleAdapter>();
				std::unique_ptr<std::deque<std::vector<char>>> pointer_filedata_blockchain = std::make_unique<std::deque<std::vector<char>>>();
				constexpr std::size_t MB_Size = 1024 * 1024;

				//每个数据块有多少MB的大小?
				//What is the size of each data block in MB?
				std::size_t file_data_block_byte_size = 128 * MB_Size;

				//多少个数据块是按照一个组来处理？
				//How many data blocks are processed as a group?
				std::size_t file_data_block_byte_count = 64;

				FileProcessing::Operation::BinaryStreamReader file_reader;
				FileProcessing::Operation::FILE_OPERATION_STATUS file_stream_operation_status = file_reader.ReadFileData(profile_builder.FileProceesedDataHashID, file_path_name, FDMA_Pointer, pointer_filedata_blockchain.get(), file_data_block_byte_size, file_data_block_byte_count);

				switch (file_stream_operation_status)
				{
					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_EMPTY:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_RUNNING:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_ZERO:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_OVERLIMIT:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					case FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_NOT_STANDARD_DATA_SIZE:
					{
						profile_paths.erase(profile_path_name.u8string());
						file_paths.erase(file_path_name.u8string());
						FDMA_Pointer->ClearData();
						FDMA_Pointer->ResetStatus();
						return false;
						break;
					}

					default:
						break;
				}

				std::filesystem::path decrypted_file_name;
				decrypted_file_name += file_path_name.parent_path();
				decrypted_file_name += u8"/";
				decrypted_file_name += profile_builder.FileMainName;
				std::u8string file_extension_name(profile_builder.FileExtensionName.begin(), profile_builder.FileExtensionName.end());
				decrypted_file_name += u8"_mk-decrypted";
				decrypted_file_name += file_extension_name;

				if (file_stream_operation_status == FileProcessing::Operation::FILE_OPERATION_STATUS::DONE)
				{
					std::future<std::optional<std::string>> futureTask_makeHashDigestID = std::async(std::launch::async, ProcessingFileData_MakeUUID, std::ref(file_path_name));
					std::optional<std::string> optional_makeHashDigestID = futureTask_makeHashDigestID.get();

					#if 0

					Cryptograph::CommonModule::ConversionBufferData_Input(FDMA_Pointer, pointer_filedata_blockchain.get());
					pointer_filedata_blockchain.get()->clear();
					auto* bytesPointer = std::addressof(FDMA_Pointer.get()->FileDataBytes);
					auto& fileDataPart = *(pointer_filedata_blockchain.get());

					//Do File Decryption
					Cryptograph::OaldresPuzzle_Cryptic::Version1::Decrypter CustomDecrypter;

					auto buildedKeyStreamBegin = buildedKeyStream.begin();
					auto buildedKeyStreamEnd = buildedKeyStream.end();

					for(auto begin = fileDataPart.begin(), end = fileDataPart.end(); begin != end; ++begin)
					{
						if(buildedKeyStreamBegin != buildedKeyStreamEnd)
						{
							CustomDecrypter.Main(*begin, *buildedKeyStreamBegin);
							++buildedKeyStreamBegin;
						}
						else
						{
							buildedKeyStreamBegin = buildedKeyStream.begin();
							CustomDecrypter.Main(*begin, *buildedKeyStreamBegin);
							++buildedKeyStreamBegin;
						}
					}
					
					Cryptograph::CommonModule::ConversionBufferData_Output(FDMA_Pointer, bytesPointer);
					auto* charactersPointer = std::addressof(FDMA_Pointer.get()->FileDataCharacters);

					#endif

					Pool::Version1::ThreadPool threadPoolVersion1(2, 4);

					if(UseMemoryMappcation)
					{
						if(optional_makeHashDigestID.has_value())
						{
							std::cout << "UseDecryptorWithMemoryMapping: Make file hash digest id is succeed!" << std::endl;
							std::string makeHashDigestID = optional_makeHashDigestID.value();

							if(!profile_builder.FileProceesedDataHashID.empty())
							{
								if(makeHashDigestID != profile_builder.FileProceesedDataHashID)
								{
									std::runtime_error processed_file_hash_is_not_match("UseDecryptorWithMemoryMapping: Oops, the processed file hash data doesn't match, maybe your encrypted file is corrupted?");
									throw processed_file_hash_is_not_match;
								}
							}
							else
							{
								std::runtime_error profile_is_corrupted("UseDecryptorWithMemoryMapping: Oops, there was an error in the profile data, maybe your binary profile is corrupted?");
								throw profile_is_corrupted;
							}
						}
						else
						{
							std::runtime_error make_hash_digest_is_invalid("UseDecryptorWithMemoryMapping: Make file hash digest id is failed!");
							throw make_hash_digest_is_invalid;
						}

						std::function<std::filesystem::path()> taskFunction = std::bind_front(&CryptographFileDataHelper::UseDecryptorWithMemoryMapping, this, std::ref(file_path_name), std::ref(decrypted_file_name), std::ref(buildedKeyStream), std::ref(profile_builder), std::ref(threadPoolVersion1));
						
						std::future<std::filesystem::path> asyncTask = std::async(std::launch::async, taskFunction);
				
						while (std::future_status::ready != asyncTask.wait_for(std::chrono::seconds(10)))
						{
							if(std::future_status::ready == asyncTask.wait_for(std::chrono::seconds(10)))
							{
								break;
							}
						}

						try
						{
							decrypted_file_name = asyncTask.get();
						}
						catch ( const std::exception& except )
						{
							std::cerr << "[Error] Exception message is" << except.what() << std::endl;
						}

						futureTask_makeHashDigestID = ThreadingToolkit::Pool::Version2::ThreadPool::get_instance( 2 ).submit( std::bind_front(ProcessingFileData_MakeUUID, std::ref(decrypted_file_name)) );
						optional_makeHashDigestID = futureTask_makeHashDigestID.get();

						if(optional_makeHashDigestID.has_value())
						{
							std::cout << "UseDecryptorWithMemoryMapping: Make file hash digest id is succeed!" << std::endl;
							std::string makeHashDigestID = optional_makeHashDigestID.value();

							if(!profile_builder.FileDataHashedID.empty())
							{
								if(makeHashDigestID != profile_builder.FileDataHashedID)
								{
									std::runtime_error file_hash_is_not_match("UseDecryptorWithMemoryMapping: Oops, the file hash data doesn't match, maybe your encrypted file is corrupted?");
									throw file_hash_is_not_match;
								}
							}
							else
							{
								std::runtime_error profile_is_corrupted("UseDecryptorWithMemoryMapping: Oops, there was an error in the profile data, maybe your binary profile is corrupted?");
								throw profile_is_corrupted;
							}
						}
						else
						{
							std::runtime_error make_hash_digest_is_invalid("UseDecryptorWithMemoryMapping: Make file hash digest id is failed!");
							throw make_hash_digest_is_invalid;
						}
					}
					else
					{
						if(optional_makeHashDigestID.has_value())
						{
							std::cout << "RunCustomDecryptionFile: Make file hash digest id is succeed!" << std::endl;
							std::string makeHashDigestID = optional_makeHashDigestID.value();

							if(!profile_builder.FileProceesedDataHashID.empty())
							{
								if(makeHashDigestID != profile_builder.FileProceesedDataHashID)
								{
									std::cerr << "RunCustomDecryptionFile: Oops, the processed file hash data doesn't match, maybe your encrypted file is corrupted?" << std::endl;
									profile_paths.erase(profile_path_name.u8string());
									file_paths.erase(file_path_name.u8string());
									return false;
								}
							}
							else
							{
								std::cerr << "RunCustomDecryptionFile: Oops, there was an error in the profile data, maybe your binary profile is corrupted?" << std::endl;
								profile_paths.erase(profile_path_name.u8string());
								file_paths.erase(file_path_name.u8string());
								return false;
							}
						}
						else
						{
							std::cerr << "RunCustomDecryptionFile: Make file hash digest id is failed!" << std::endl;

							profile_paths.erase(profile_path_name.u8string());
							file_paths.erase(file_path_name.u8string());
							return false;
						}

						this->UseDecryptor(file_path_name, decrypted_file_name, buildedKeyStream, profile_builder, threadPoolVersion1);

						futureTask_makeHashDigestID = ThreadingToolkit::Pool::Version2::ThreadPool::get_instance( 2 ).submit( std::bind_front(ProcessingFileData_MakeUUID, std::ref(decrypted_file_name)) );
						optional_makeHashDigestID = futureTask_makeHashDigestID.get();

						if(optional_makeHashDigestID.has_value())
						{
							std::cout << "RunCustomDecryptionFile: Make file hash digest id is succeed!" << std::endl;
							std::string makeHashDigestID = optional_makeHashDigestID.value();

							if(!profile_builder.FileDataHashedID.empty())
							{
								if(makeHashDigestID != profile_builder.FileDataHashedID)
								{
									std::runtime_error file_hash_is_not_match("RunCustomDecryptionFile: Oops, the file hash data doesn't match, maybe your encrypted file is corrupted?");
									throw file_hash_is_not_match;
								}
							}
							else
							{
								std::runtime_error profile_is_corrupted("RunCustomDecryptionFile: Oops, there was an error in the profile data, maybe your binary profile is corrupted?");
								throw profile_is_corrupted;
							}
						}
						else
						{
							std::runtime_error make_hash_digest_is_invalid("RunCustomDecryptionFile: Make file hash digest id is failed!");
							throw make_hash_digest_is_invalid;
						}
					}

					FileProcessing::Operation::BinaryStreamWriter file_writer;
					file_writer.WriteFileData(profile_builder.FileProceesedDataHashID, decrypted_file_name, FDMA_Pointer, pointer_filedata_blockchain.get(), file_data_block_byte_size, file_data_block_byte_count);
				}

				std::cout << "RunCustomDecryptionFile: Your file has been completed decrypted !!!" << std::endl;

				profile_paths.erase(profile_path_name.u8string());
				file_paths.erase(file_path_name.u8string());
				return true;
			}

		private:
			std::unordered_set<std::u8string> profile_paths;
			std::unordered_set<std::u8string> file_paths;
		};

	}  // namespace MainProgram_ModulemImplementation
}  // namespace EODF_Reborn