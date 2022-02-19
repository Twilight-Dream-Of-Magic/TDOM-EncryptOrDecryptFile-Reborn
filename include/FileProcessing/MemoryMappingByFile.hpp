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

#include "mio/mio.hpp"

//将文件数据进行镜像（映射）到操作系统的内存对象。以实现对磁盘的大文件(这里规定大小大于2GB)的字节流模拟访问和修改
//Mirroring (mapping) file data to the operating system's memory objects. to enable byte stream emulation access and modification of large files (here specified size > 2 giga byte) on disk
namespace MemoryObjectConfrontationDiskFileData
{
	namespace MIO_LibraryHelper
	{

		/*

			Use C++ project mio

			Github https://github.com/mandreyel/mio

			An easy to use header-only cross-platform C++11 memory mapping library with an MIT license.
			mio has been created with the goal to be easily includable (i.e. no dependencies) in any C++ project that needs memory mapped file IO without the need to pull in C++ Boost library.
			Please feel free to open an issue, I'll try to address any concerns as best I can.

			一个易于使用的头文件跨平台的C++11内存映射库，拥有MIT许可证。
			创建mio的目的是为了在任何需要内存映射文件IO的C++项目中都能方便地包含（即没有依赖性），而不需要拉入C++ Boost 库。
			请随时提出问题，我将尽力解决任何问题。

		*/

		template <typename Type>
		concept TemplateConcept_MemoryMap = std::is_same_v<Type, mio::mmap_source> || std::is_same_v<Type, mio::mmap_sink> || std::is_same_v<Type, mio::ummap_source> || std::is_same_v<Type, mio::ummap_sink>;

		template <typename Type>
		concept TemplateConcept_MemoryMap_ReadAndWrite = std::is_same_v<Type, mio::mmap_sink> || std::is_same_v<Type, mio::ummap_sink>;

		enum class MemoryMapTypes
		{
			SIGNED_READ_AND_WRITE = 0,
			SIGNED_READ_ONLY = 1,
			UNSIGNED_READ_AND_WRITE = 2,
			UNSIGNED_READ_ONLY = 3
		};

		class MemoryMapPointers
		{

		private:

			std::unique_ptr<mio::mmap_sink>	   pointer_signed_rw;
			std::unique_ptr<mio::mmap_source>  pointer_signed_ro;
			std::unique_ptr<mio::ummap_sink>   pointer_unsigned_rw;
			std::unique_ptr<mio::ummap_source> pointer_unsigned_ro;

		public:

			std::unique_ptr<mio::mmap_sink>& signed_rw()
			{
				return pointer_signed_rw;
			}

			std::unique_ptr<mio::mmap_source>& signed_ro()
			{
				return pointer_signed_ro;
			}

			std::unique_ptr<mio::ummap_sink>& unsigned_rw()
			{
				return pointer_unsigned_rw;
			}

			std::unique_ptr<mio::ummap_source>& unsigned_ro()
			{
				return pointer_unsigned_ro;
			}

			MemoryMapPointers() noexcept : pointer_signed_rw( nullptr ), pointer_signed_ro( nullptr ), pointer_unsigned_rw( nullptr ), pointer_unsigned_ro( nullptr ) {}

			MemoryMapPointers(MemoryMapPointers& _object) = delete;
			MemoryMapPointers& operator=(const MemoryMapPointers _object) = delete;

			MemoryMapPointers( MemoryMapTypes map_types )
			{
				switch ( map_types )
				{
					case MemoryObjectConfrontationDiskFileData::MIO_LibraryHelper::MemoryMapTypes::SIGNED_READ_AND_WRITE:
					{
						this->pointer_signed_rw = std::unique_ptr<mio::mmap_sink, std::default_delete<mio::mmap_sink>>( new mio::mmap_sink, std::default_delete<mio::mmap_sink>() );
						break;
					}
					case MemoryObjectConfrontationDiskFileData::MIO_LibraryHelper::MemoryMapTypes::SIGNED_READ_ONLY:
					{
						this->pointer_signed_ro = std::unique_ptr<mio::mmap_source, std::default_delete<mio::mmap_source>>( new mio::mmap_source, std::default_delete<mio::mmap_source>() );
						break;
					}
					case MemoryObjectConfrontationDiskFileData::MIO_LibraryHelper::MemoryMapTypes::UNSIGNED_READ_AND_WRITE:
					{
						this->pointer_unsigned_rw = std::unique_ptr<mio::ummap_sink, std::default_delete<mio::ummap_sink>>( new mio::ummap_sink, std::default_delete<mio::ummap_sink>() );
						break;
					}
					case MemoryObjectConfrontationDiskFileData::MIO_LibraryHelper::MemoryMapTypes::UNSIGNED_READ_ONLY:
					{
						this->pointer_unsigned_ro = std::unique_ptr<mio::ummap_source, std::default_delete<mio::ummap_source>>( new mio::ummap_source, std::default_delete<mio::ummap_source>() );
						break;
					}
					default:
						break;
				}
			}

			~MemoryMapPointers()
			{
				if ( !( pointer_signed_rw == nullptr ) )
				{
					auto* pointer = pointer_signed_rw.release();
					pointer = nullptr;
				}

				if ( !( pointer_signed_ro == nullptr ) )
				{
					auto* pointer = pointer_signed_ro.release();
					pointer = nullptr;
				}

				if ( !( pointer_unsigned_rw == nullptr ) )
				{
					auto* pointer = pointer_unsigned_rw.release();
					pointer = nullptr;
				}

				if ( !( pointer_unsigned_ro == nullptr ) )
				{
					auto* pointer = pointer_unsigned_ro.release();
					pointer = nullptr;
				}
			}
		};

		int AnalysisErrorCode( const std::error_code& error_code_object );

		template <typename MemoryMapType>
		requires TemplateConcept_MemoryMap<MemoryMapType>
		bool CheckMemoryMapObjectIsAssocisatedFile( MemoryMapType& mapped_object );

		inline MemoryMapPointers MakeDefaultMemoryMappingObject( MIO_LibraryHelper::MemoryMapTypes map_types );

		template <typename MemoryMapType>
		requires TemplateConcept_MemoryMap<MemoryMapType>
		std::tuple<bool, MemoryMapType, std::error_code> MappingMemoryMapObject_TryAssociateFile_ToPack( const std::filesystem::path& file_path_name, MemoryMapType* memory_map_pointer );

		template <typename MemoryMapType>
		requires TemplateConcept_MemoryMap<MemoryMapType>
		MemoryMapType MappedMemoryMapObject_FromUnpack( std::tuple<bool, MemoryMapType, std::error_code>& mapped_group_data, bool result_status, std::error_code& error_code_object );

		template <typename MemoryMapType_ReadAndWrite>
		requires TemplateConcept_MemoryMap_ReadAndWrite<MemoryMapType_ReadAndWrite>
		std::error_code NeedSyncDiskFile_ByManagedDataIsChanged_WithMappedObject( MemoryMapType_ReadAndWrite& mapped, std::error_code& object_error_code );

		template <typename MemoryMapType>
		requires TemplateConcept_MemoryMap<MemoryMapType>
		bool UnmappingMemoryMapObject( MemoryMapType& mapped );

		inline int AnalysisErrorCode( const std::error_code& error_code_object )
		{
			const std::string& error_message = error_code_object.message();
			std::cout << CommonToolkit::from_u8string(u8"发生错误，已获得标准系统错误代码，代码为：") << error_code_object.value() << ", 中止..." << std::endl;
			std::cout << "Error occurred, Standard system error codes have been obtained, code is: " << error_code_object.value() << ", aborting..." << std::endl;
			std::cout << CommonToolkit::from_u8string(u8"The error message is(错误消息是): ") << error_message << std::endl;
			return error_code_object.value();
		}

		template <typename MemoryMapType>
		requires TemplateConcept_MemoryMap<MemoryMapType>
		inline bool CheckMemoryMapObjectIsAssocisatedFile( MemoryMapType& mapped_object )
		{
			if ( !mapped_object.is_mapped() )
			{
				std::cerr << CommonToolkit::from_u8string(u8"你开玩笑呢？这个内存映射对象根本就没有关联一个文件。") << std::endl;
				std::cerr << "Are you kidding me? This memory mapped object is not associated with a file at all." << std::endl;
				return false;
			}
			else
			{
				return true;
			}
		}

		//创建一个内存映射对象
		//Create a memory map object
		inline MemoryMapPointers MakeDefaultMemoryMappingObject( MIO_LibraryHelper::MemoryMapTypes map_types )
		{
			return MemoryMapPointers( map_types );
		}

		//提供一个内存映射对象，然后尝试关联文件
		//Provide a memory map object and then try to associate the file
		template <typename MemoryMapType>
		requires TemplateConcept_MemoryMap<MemoryMapType>
		std::tuple<bool, MemoryMapType, std::error_code> MappingMemoryMapObject_TryAssociateFile_ToPack( const std::filesystem::path& file_path_name, MemoryMapType* memory_map_pointer )
		{
			int				error_code_value;
			std::error_code object_error_code;
			auto& memory_map_reference = *memory_map_pointer;

			if ( std::is_same_v<std::remove_reference_t<decltype(memory_map_reference)>, mio::mmap_sink> || std::is_same_v<std::remove_reference_t<decltype(memory_map_reference)>, mio::ummap_sink> )
			{
				auto _file_path_name = std::move( file_path_name );
				std::fstream file_stream_object;

				if ( std::filesystem::exists( file_path_name ) )
				{
					std::u8string u8string_extension_name = u8".newfile";
					_file_path_name += u8string_extension_name;
				}

				//文件打开后立即寻找流的末端
				//seek to the end of stream immediately after open
				file_stream_object.open( file_path_name, std::ios::in | std::ios::out | std::ios::ate | std::ios::binary );

				//立即关闭文件
				//Close the file now
				file_stream_object.close();
			}

			memory_map_reference.map( file_path_name.string(), 0, mio::map_entire_file, object_error_code );

			if ( !memory_map_reference.is_open() )
			{
				std::cerr << CommonToolkit::from_u8string(u8"呃，你确定那个文件的路径确实存在吗？你需要好好检查一下。") << std::endl;
				std::cerr << "Uh, are you sure the path to that file actually exists? You need to check it properly." << std::endl;

				error_code_value = AnalysisErrorCode( object_error_code );

				if ( error_code_value != 0 )
				{
					std::cerr << CommonToolkit::from_u8string(u8"内存映射对象无效，可能是文件无法访问或者内存不足。\n文件路径是： ")
							  << "[" << CommonToolkit::from_u8string(file_path_name.u8string()) << "]" << std::endl;
					std::cerr << "The memory mapped object is invalid, probably because the file is inaccessible or out of memory.\nThe file path is. "
							  << "[" << CommonToolkit::from_u8string(file_path_name.u8string()) << "]" << std::endl;
					object_error_code = std::make_error_code( std::errc::io_error );
					UnmappingMemoryMapObject( memory_map_reference );
					return std::make_tuple( std::move( false ), std::move( memory_map_reference ), std::move( object_error_code ) );
				}
			}
			else
			{
				if ( CheckMemoryMapObjectIsAssocisatedFile( memory_map_reference ) )
				{
					std::cout << CommonToolkit::from_u8string(u8"内存映射对象已经关联文件\n文件路径是： ")
							  << "[" << CommonToolkit::from_u8string(file_path_name.u8string()) << "]" << std::endl;
					std::cout << "The memory mapped object has associated files.\nThe file path is: "
							  << "[" << CommonToolkit::from_u8string(file_path_name.u8string()) << "]" << std::endl;
					return std::make_tuple( std::move( true ), std::move( memory_map_reference ), std::move( object_error_code ) );
				}
				else
				{
					std::cerr << CommonToolkit::from_u8string(u8"内存映射对象不能关联文件，文件路径是： ")
							  << "[" << CommonToolkit::from_u8string(file_path_name.u8string()) << "]" << std::endl;
					std::cerr << "The memory mapped objects cannot be associated with files.\nThe file path is. "
							  << "[" << CommonToolkit::from_u8string(file_path_name.u8string()) << "]" << std::endl;
					object_error_code = std::make_error_code( std::errc::io_error );
					error_code_value = AnalysisErrorCode( object_error_code );
					UnmappingMemoryMapObject( memory_map_reference );
					return std::make_tuple( std::move( false ), std::move( memory_map_reference ), std::move( object_error_code ) );
				}
			}
		}

		template <typename MemoryMapType>
		requires TemplateConcept_MemoryMap<MemoryMapType>
		MemoryMapType MappedMemoryMapObject_FromUnpack( std::tuple<bool, MemoryMapType, std::error_code>& associated_data, bool result_status, std::error_code& error_code_object )
		{
			result_status = std::get<bool>( associated_data );

			if ( result_status )
			{
				MemoryMapType memory_map_object = std::move( std::get<MemoryMapType>( associated_data ) );
				return memory_map_object;
			}
			else
			{
				error_code_object = std::move( std::get<std::error_code>( associated_data ) );
				return MemoryMapType();
			}
		}

		//已经映射完成的内存对象，只要内存对象管理的数据发生改变时，就需要同步磁盘文件数据进行写入
		//Whenever the memory object is mapped, the data managed by the memory object is changed, the disk file data needs to be synchronized for writing.
		template <typename MemoryMapType_ReadAndWrite>
		requires TemplateConcept_MemoryMap_ReadAndWrite<MemoryMapType_ReadAndWrite>
		std::error_code NeedSyncDiskFile_ByManagedDataIsChanged_WithMappedObject( MemoryMapType_ReadAndWrite& mapped_object, std::error_code& object_error_code )
		{
			if ( mapped_object.is_open() && CheckMemoryMapObjectIsAssocisatedFile( mapped_object ) )
			{
				std::cout << CommonToolkit::from_u8string(u8"好了，试着把内存映射对象管理的数据的变化同步到磁盘上。但是接下来请注意错误代码是否有变化？") << std::endl;
				std::cout << "OK, try synchronizing the changes in the data managed by the memory mapped object to the disk. But then notice if the error code has changed?" << std::endl;
				mapped_object.sync( object_error_code );
				return object_error_code;
			}
			else
			{

				return std::make_error_code( std::errc::invalid_argument );
			}
		}

		//提供一个内存映射对象，然后解除关联文件。
		//Provide a memory map object and then unassociate the file
		template <typename MemoryMapType>
		requires TemplateConcept_MemoryMap<MemoryMapType>
		inline bool UnmappingMemoryMapObject( MemoryMapType& mapped_object )
		{
			if ( CheckMemoryMapObjectIsAssocisatedFile( mapped_object ) )
			{
				mapped_object.unmap();
				return true;
			}
			else
			{
				return false;
			}
		}

		//测试代码是否可以被编译
		//Test if the code can be compiled
		#if 0

		MemoryMapPointers mmp_pointer_object = MakeDefaultMemoryMappingObject(MIO_LibraryHelper::MemoryMapTypes::SIGNED_READ_AND_WRITE);
		auto* managed_pointer = mmp_pointer_object.signed_rw().get();
		auto associated_mmap_data_package = MappingMemoryMapObject_TryAssociateFile_ToPack(std::string("./filename.dat"), managed_pointer);
		std::error_code error_code_object;
		bool associated_mmap_data_unpackage_status;
		auto mapped_object = MappedMemoryMapObject_FromUnpack(associated_mmap_data_package, associated_mmap_data_unpackage_status, error_code_object);
		std::error_code error_code_object2 = NeedSyncDiskFile_ByManagedDataIsChanged_WithMappedObject(mapped_object, error_code_object);
		bool unmake_status = UnmappingMemoryMapObject(mapped_object);

		#endif
	}  // namespace MIO_LibraryHelper
}  // namespace MemoryObjectConfrontationDiskFileData