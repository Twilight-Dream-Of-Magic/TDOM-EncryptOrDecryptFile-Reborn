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

#include "./FileProcessing.hpp"

//将全局语言区域更改为操作系统默认区域
//Change the global language region to the OS default region
//std::locale::global(std::locale(""));

//Restore global language locale settings
//还原全局语言区域设定
//std::locale::global(std::locale("C"));

//对文件操作
//Operation on files
namespace FileProcessing::Operation
{
	//Check that the unit size of the data block meets the standard
	inline bool CheckDataBlockByteSize( const std::size_t& dataBlockByteSize )
	{
		auto isMultiplesOfTwo = [ & ]() -> bool {
			return dataBlockByteSize > 0 && ( dataBlockByteSize & 1 ) == 0;
		};

		auto isPowerOfTwo = [ & ]() -> bool {
			return dataBlockByteSize > 0 && ( dataBlockByteSize & ( dataBlockByteSize - 1 ) ) == 0;
		};

		bool _isMultiplesOfTwo = isMultiplesOfTwo();
		bool _isPowerOfTwo = isPowerOfTwo();

		if ( _isMultiplesOfTwo || _isPowerOfTwo )
		{
			return true;
		}
		else
		{
			if ( ( dataBlockByteSize % 1024 ) != 0 )
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}

	class BinaryStreamReader
	{

	private:

		std::set<std::string> taskUniqueNames;

		struct TaskStatusData
		{
			std::map<std::size_t, std::vector<char>> bufferDataMap;
			std::vector<char>						 bufferData;

			std::atomic<std::size_t> currentDataBlockNumber = 0;
			std::atomic<std::size_t> filePartDataProcessingByTaskCount = 0;

			//谁没有了占用权，谁就不可以被使用
			//Whoever does not have the right of occupancy is not allowed to be used
			std::atomic<bool> bufferIsNotOccupiedWithReading = true;
			std::atomic<bool> bufferIsNotOccupiedWithMoving = true;
		};

		enum class ReadingFileDataStatus
		{
			WORKED = 0,
			CONTINUE_WORKING = 1,
			WAIT_DATA_IS_IDLE = 2,
			FILE_INVALIED = 3,
			READ_DATA_FAILED = 4
		};

		void MovingBufferData( std::unique_ptr<TaskStatusData>& TaskStatusData_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlockChain, std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer )
		{
			std::chrono::duration<double> TimeSpent;

			std::cout << "The file data transmission begins! \n"
					  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;
			auto dataTransmisionWithStartTime = std::chrono::system_clock::now();

			for ( std::map<std::size_t, std::vector<char>>::iterator bufferDataIterator = TaskStatusData_Pointer->bufferDataMap.begin(); bufferDataIterator != TaskStatusData_Pointer->bufferDataMap.end(); ++bufferDataIterator )
			{
				auto& pairBufferData = *bufferDataIterator;
				if ( TaskStatusData_Pointer->bufferDataMap.contains( pairBufferData.first ) )
				{
					if ( pairBufferData.second.size() != 0 )
					{
						std::cout << "Moving data blocks are in progress and the current block index number is: " << pairBufferData.first << std::endl;
						pointerWithFileDataBlockChain->push_back( std::move( pairBufferData.second ) );
					}
				}
			}
			TaskStatusData_Pointer->bufferDataMap.clear();

			auto dataTransmisionWithEndTime = std::chrono::system_clock::now();
			TimeSpent = dataTransmisionWithEndTime - dataTransmisionWithStartTime;
			std::cout << "The file data transmission ends! the time has been spent: " << TimeSpent.count() << " seconds \n"
					  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;

			std::size_t _fileDataByteSize = 0;
			for ( auto beginIterator = pointerWithFileDataBlockChain->begin(), endIterator = pointerWithFileDataBlockChain->end(); beginIterator != endIterator; ++beginIterator )
			{
				std::size_t partElementSize = beginIterator->size();

				_fileDataByteSize += partElementSize;
			}
			FDCM_Adapter_Pointer->fileDataByteReadedCount = _fileDataByteSize;

			TaskStatusData_Pointer->bufferIsNotOccupiedWithMoving.store( true );
			TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.store( false );

			TaskStatusData_Pointer->bufferIsNotOccupiedWithMoving.notify_one();
			TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.notify_one();
		}

	protected:

		ReadingFileDataStatus ReadingFileData( TaskStatusData* TaskStatusData_Pointer, std::ifstream* FS_Object_Pointer, const std::size_t& dataBlockByteSize, const std::size_t& fileDataByteSize, std::streampos& currentFilePointerPosition )
		{
			using namespace Cryptograph::CommonModule;

			if ( FS_Object_Pointer->is_open() )
			{
				std::ios::iostate io_state;
				std::streampos	  newFilePointerPosition;
				// !!! Begin Of Critical Zone !!! //

				try
				{
					if ( TaskStatusData_Pointer->bufferIsNotOccupiedWithMoving.load() == true && TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.load() == false )
					{
						std::cout << "Note that the file is about to be read!\n"
								  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;

						TaskStatusData_Pointer->bufferData.resize( dataBlockByteSize );

						std::chrono::duration<double> TimeSpent;
						auto						  startTimeByReadedData = std::chrono::system_clock::now();

						currentFilePointerPosition = FS_Object_Pointer->tellg();

						FS_Object_Pointer->read( reinterpret_cast<char*>( &( TaskStatusData_Pointer->bufferData[ 0 ] ) ), dataBlockByteSize );

						newFilePointerPosition = FS_Object_Pointer->tellg();

						auto endTimeByReadedData = std::chrono::system_clock::now();
						TimeSpent = endTimeByReadedData - startTimeByReadedData;

						io_state = FS_Object_Pointer->rdstate();
						//FS_Object_Pointer->fail() && !FS_Object_Pointer-> eof()
						if ( ( io_state & ( std::ios::badbit | std::ios::failbit ) ) && !( io_state & std::ios::eofbit ) || currentFilePointerPosition == newFilePointerPosition )
						{
							std::stringstream ss_object;
							ss_object << "File data block read failed.\n"
									  << "Current Thread ID: " << std::this_thread::get_id();

							return ReadingFileDataStatus::READ_DATA_FAILED;
						}

						std::cout << "File data block read successfully, the time has heen spent: " << TimeSpent.count() << " seconds \n"
								  << "The current is the [" << TaskStatusData_Pointer->currentDataBlockNumber << "] data block." << std::endl;

						//对已经分裂的数据块，进行编号记录
						//Numbered records for splited data blocks
						std::pair<std::size_t, std::vector<char>> pairBufferDataNode = std::make_pair( TaskStatusData_Pointer->currentDataBlockNumber.load(), TaskStatusData_Pointer->bufferData );
						TaskStatusData_Pointer->bufferDataMap.insert( std::move( pairBufferDataNode ) );
						TaskStatusData_Pointer->currentDataBlockNumber += 1;
						std::vector<char>().swap( TaskStatusData_Pointer->bufferData );

						TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.store( false );

						if ( TaskStatusData_Pointer->bufferDataMap.size() == TaskStatusData_Pointer->filePartDataProcessingByTaskCount )
						{
							if ( TaskStatusData_Pointer->bufferIsNotOccupiedWithMoving.load() == true )
							{
								TaskStatusData_Pointer->bufferIsNotOccupiedWithMoving.store( false );
								TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.store( true );
							}
							return ReadingFileDataStatus::WAIT_DATA_IS_IDLE;
						}

						//FS_Object_Pointer->eof()
						//io_state & std::ios::eofbit

						if ( fileDataByteSize == newFilePointerPosition )
						{
							return ReadingFileDataStatus::WORKED;
						}
						else
						{
							currentFilePointerPosition = newFilePointerPosition;
							return ReadingFileDataStatus::CONTINUE_WORKING;
						}
					}
				}
				catch ( const std::exception& except )
				{
					std::cerr << "[Error] BinaryStreamReader::ReadingFileData Exception message is" << except.what() << std::endl;
				}

				// !!! End Of Critical Zone !!! //
			}
			else
			{
				return ReadingFileDataStatus::FILE_INVALIED;
			}
		}

	public:

		//读取文件数据到内存的函数
		//Functions for reading file data into memory
		bool ReadFileData( std::string taskUniqueName, const std::filesystem::path& filePathName, std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlocks, std::size_t& dataBlockByteSize, std::size_t dataBlockCount );

		BinaryStreamReader() = default;
		~BinaryStreamReader() = default;

		BinaryStreamReader(BinaryStreamReader& _object) = delete;
		BinaryStreamReader& operator=(const BinaryStreamReader& _object) = delete;
	};

	bool BinaryStreamReader::ReadFileData( std::string taskUniqueName, const std::filesystem::path& filePathName, std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlockChain, std::size_t& dataBlockByteSize, std::size_t dataBlockCount = 32 )
	{
		using namespace Cryptograph;

		if ( CheckDataBlockByteSize( dataBlockByteSize ) == false )
		{
			std::cerr << "The unit size of the data block not from standard !" << std::endl;
			return false;
		}

		const std::size_t	  fileDataByteSize = std::filesystem::file_size( filePathName );
		constexpr std::size_t GB_SizeLimit = static_cast<std::size_t>( 2 ) * static_cast<std::size_t>( 1024 ) * static_cast<std::size_t>( 1024 ) * static_cast<std::size_t>( 1024 );

		if ( fileDataByteSize > static_cast<std::size_t>( GB_SizeLimit ) )
		{
			std::cerr << "因为我觉得你的内存条的容量不够大，所以我不允许使用你这个方法，来读写2GB以上大小的文件！" << std::endl;
			std::cerr << "Because I don't think the capacity of your memory stick is large enough, I'm not allowed to use this method of yours to read and write files over 2GB in size!" << std::endl;

			return false;
		}
		else if ( fileDataByteSize == 0 )
		{
			std::cerr << "你不允许在这里将空文件的内容读到内存中!" << std::endl;
			std::cerr << "You are not allowed to read empty file of content to the memory here!" << std::endl;
			return false;
		}

		if ( taskUniqueName.empty() )
		{
			std::cerr << "任务ID名称不能为空!" << std::endl;
			std::cerr << "The task ID name cannot be empty!" << std::endl;
		}


		auto taskUniqueNamesIterator = taskUniqueNames.find( taskUniqueName );
		if ( taskUniqueNamesIterator == taskUniqueNames.end() )
		{
			auto EmplaceResultFromMap = taskUniqueNames.insert( taskUniqueName );

			if ( EmplaceResultFromMap.second == true )
			{
				taskUniqueNamesIterator = EmplaceResultFromMap.first;
			}
			else
			{
				std::stringstream ss_object;
				ss_object << "线程锁对象无法被管理，初始化已被终止！\nThread lock object cannot be managed, initialization has been terminated!\n"
						  << "Current Thread ID: " << std::this_thread::get_id();

				std::string error_message{ ss_object.str() };

				throw std::runtime_error( error_message );
			}
		}
		else
		{
			std::cerr << "Task ID名称(Task ID name): " << taskUniqueName << std::endl;
			std::cerr << "线程锁无法获得资源的所有权，请等待线程锁释放资源的所有权！" << std::endl;
			std::cerr << "Thread locks cannot acquire ownership of resources, wait for the thread lock to release ownership of the resource!" << std::endl;
			return false;
		}

		if ( taskUniqueNames.contains( taskUniqueName ) )
		{
			std::cout << "Task ID名称(Task ID name): " << taskUniqueName << std::endl;
			std::cout << "线程锁已经获得资源的所有权！" << std::endl;
			std::cout << "Thread lock has acquired ownership of the resource!" << std::endl;

			std::unique_ptr<TaskStatusData> TaskStatusData_Pointer = std::make_unique<TaskStatusData>();

			TaskStatusData_Pointer->filePartDataProcessingByTaskCount.store( dataBlockCount );

			auto lambda_MovingBufferData = [ this, &TaskStatusData_Pointer, pointerWithFileDataBlockChain, &FDCM_Adapter_Pointer ]() -> void {
				this->MovingBufferData( TaskStatusData_Pointer, pointerWithFileDataBlockChain, FDCM_Adapter_Pointer );
			};

			auto lambda_ReadingData = [ this, &dataBlockByteSize, &filePathName, fileDataByteSize, &TaskStatusData_Pointer, &FDCM_Adapter_Pointer ]() -> void {
				std::streampos _filePointerPosition;
				std::streamoff _filePointerOffset = 0;

				std::size_t _dataBlockByteSize = dataBlockByteSize;

				std::ifstream* FS_Object_Pointer = new std::ifstream();
				FS_Object_Pointer->open( filePathName, std::ios::in | std::ios::binary );

				ReadingFileDataStatus statusReading;

				auto lambda_TerminationFunction = [ &FS_Object_Pointer ]() -> void {
					FS_Object_Pointer->close();
					delete FS_Object_Pointer;
					FS_Object_Pointer = nullptr;
				};

				if ( TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.load() == true && TaskStatusData_Pointer->bufferIsNotOccupiedWithMoving.load() == true )
				{
					TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.store( false );
				}

				ReadingFileDataFlag:

				statusReading = this->ReadingFileData( TaskStatusData_Pointer.get(), FS_Object_Pointer, _dataBlockByteSize, fileDataByteSize, _filePointerPosition );

				switch ( statusReading )
				{
					case FileProcessing::Operation::BinaryStreamReader::ReadingFileDataStatus::WAIT_DATA_IS_IDLE:
					{
						TaskStatusData_Pointer->bufferIsNotOccupiedWithMoving.wait( false );
						TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.wait( true );

						goto ReadingFileDataFlag;
					}
					case FileProcessing::Operation::BinaryStreamReader::ReadingFileDataStatus::FILE_INVALIED:
					{
						lambda_TerminationFunction();
						break;
					}
					case FileProcessing::Operation::BinaryStreamReader::ReadingFileDataStatus::READ_DATA_FAILED:
					{
						lambda_TerminationFunction();
						break;
					}
					default:
						break;
				}

				_filePointerOffset = static_cast<std::streamoff>( _filePointerPosition );

				if ( statusReading == ReadingFileDataStatus::CONTINUE_WORKING )
				{
					if ( _filePointerOffset >= 0 || _filePointerOffset < fileDataByteSize )
					{
						std::streamoff _filePointerOffsetDifferences = fileDataByteSize - _filePointerOffset;

						if ( _filePointerOffsetDifferences >= 0 && _filePointerOffsetDifferences < dataBlockByteSize )
						{
							_dataBlockByteSize = _filePointerOffsetDifferences;
						}
						else if ( _filePointerOffsetDifferences < 0 || _filePointerOffsetDifferences > fileDataByteSize )
						{
							std::string error_message = "";
							throw std::runtime_error( error_message );
						}
					}
					goto ReadingFileDataFlag;
				}
				else if ( statusReading == ReadingFileDataStatus::WORKED )
				{
					FDCM_Adapter_Pointer->allFileDataIsReaded.store( true );

					lambda_TerminationFunction();
				}
			};

			///// Task Area /////

			std::future<void> futureTask_readingFileData = std::async( std::launch::async, lambda_ReadingData );

		TaskNotDone:

			if ( TaskStatusData_Pointer->bufferIsNotOccupiedWithReading.load() == true && TaskStatusData_Pointer->bufferIsNotOccupiedWithMoving.load() == false )
			{
				std::future<void> futureTask_movingBufferDataBlock = std::async( std::launch::async, lambda_MovingBufferData );

				MovingBufferDataFlag:
				std::future_status futureTaskStatus_movingBufferDataFunction = futureTask_movingBufferDataBlock.wait_for( std::chrono::seconds( 1 ) );
				std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

				if ( futureTaskStatus_movingBufferDataFunction != std::future_status::ready )
				{
					if ( futureTask_readingFileData.valid() == false )
					{
						try
						{
							futureTask_readingFileData.get();
						}
						catch ( const std::exception& except )
						{
							std::cerr << "[Error] Exception message is" << except.what() << std::endl;
						}
					}

					if ( futureTask_movingBufferDataBlock.valid() == false )
					{
						try
						{
							futureTask_movingBufferDataBlock.get();
						}
						catch ( const std::exception& except )
						{
							std::cerr << "[Error] Exception message is" << except.what() << std::endl;
						}
					}

					goto MovingBufferDataFlag;
				}
			}

			std::future_status futureTaskStatus_readingFileDataBlockFunction = futureTask_readingFileData.wait_for( std::chrono::seconds( 1 ) );
			std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

			if ( futureTaskStatus_readingFileDataBlockFunction != std::future_status::ready )
			{
				goto TaskNotDone;
			}
			else
			{
				if ( FDCM_Adapter_Pointer->allFileDataIsReaded.load() == true )
				{
					std::future<void> futureTask_movingBufferData = std::async( std::launch::async, lambda_MovingBufferData );

					goto TaskDone;
				}
				else
				{
					throw std::runtime_error( "" );
				}
			}

		TaskDone:

			///// Task Area /////

			taskUniqueNames.erase( taskUniqueName );
			return true;
		}
	}

	class BinaryStreamWriter
	{

	private:

		std::set<std::string> taskUniqueNames;

		struct TaskStatusData
		{
			std::deque<std::vector<char>>			 bufferDataBlockChain;
			std::map<std::size_t, std::vector<char>> bufferDataMap;
			std::vector<char>						 bufferData;

			std::atomic<std::size_t> currentDataBlockGroupNumber = 0;
			std::atomic<std::size_t> currentDataBlockNumber = 0;
			std::atomic<std::size_t> filePartDataProcessingByTaskCount = 0;

			//谁拥有了占用权，谁就可以去使用
			//Whoever has the right of occupancy can go ahead and use
			std::atomic<bool> bufferIsOccupiedWithWriting = false;
			std::atomic<bool> bufferIsOccupiedWithMoving = false;
		};

		enum class WritingFileDataStatus
		{
			WORKED = 0,
			CONTINUE_WORKING = 1,
			WRITING_WAIT_DATA_READY = 2,
			FILE_INVALIED = 3,
			BUFFER_DATA_INVALIED = 4,
			WRITE_DATA_FAILED = 5
		};

		void MovingDataBlock( std::unique_ptr<TaskStatusData>& TaskStatusData_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlockChain, std::size_t& dataBlockCount )
		{
			std::chrono::duration<double> TimeSpent;

			std::cout << "The file data transmission begins! \n"
					  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;
			auto dataTransmisionWithStartTime = std::chrono::system_clock::now();

			//交换两个数据块链
			//Exchange two data block chains
			( *pointerWithFileDataBlockChain ).swap( TaskStatusData_Pointer->bufferDataBlockChain );

			//迭代器（泛型指针）偏移量为零，当前是容器开头
			//The iterator (generic pointer) offset is zero, the current is the begin of the container
			auto range_beginIterator = TaskStatusData_Pointer->bufferDataBlockChain.begin();
			auto range_endIterator = TaskStatusData_Pointer->bufferDataBlockChain.end();

			std::vector<char> temporaryBufferData;

			if ( TaskStatusData_Pointer->bufferIsOccupiedWithWriting.load() == true )
			{
				TaskStatusData_Pointer->bufferIsOccupiedWithWriting.store( false );
			}

			TaskStatusData_Pointer->bufferIsOccupiedWithMoving.store( true );

			while ( range_beginIterator != range_endIterator )
			{
				std::size_t					  iteratorOffset = CommonToolkit::IteratorOffsetDistance( range_beginIterator, range_endIterator, dataBlockCount );
				std::deque<std::vector<char>> subRange_container( range_beginIterator, range_beginIterator + iteratorOffset );

				std::size_t _currentDataBlockSize = TaskStatusData_Pointer->bufferDataBlockChain.size();

				//数据块链向临时缓冲区复制数据
				//Copying data to the temporary buffer.
				for ( auto container : subRange_container )
				{
					for ( auto data : container )
					{
						temporaryBufferData.emplace( temporaryBufferData.end(), std::move( data ) );
					}
					std::cout << "Moving data blocks are in progress and the current block index number is: " << TaskStatusData_Pointer->currentDataBlockNumber << std::endl;
					TaskStatusData_Pointer->currentDataBlockNumber += 1;
				}

				std::size_t _currentDataBlockSize2 = TaskStatusData_Pointer->bufferDataBlockChain.size();

				//移除已经复制过的数据在数据块链中
				//Remove data that has been copied in the data block chain
				if ( _currentDataBlockSize >= _currentDataBlockSize2 || temporaryBufferData.size() != 0 )
				{
					subRange_container.clear();
					std::deque<std::vector<char>>().swap( subRange_container );
				}

				//对可能重分过的数据块，进行编号记录
				//Numbered records of data blocks that may have been re-splited
				std::pair<std::size_t, std::vector<char>> pairBufferDataNode = std::make_pair( TaskStatusData_Pointer->currentDataBlockGroupNumber.load(), std::move( temporaryBufferData ) );
				TaskStatusData_Pointer->bufferDataMap.insert( std::move( pairBufferDataNode ) );
				TaskStatusData_Pointer->currentDataBlockGroupNumber += 1;

				//必须清除临时缓冲区的旧数据
				//The old data in the temporary buffer must be cleared
				temporaryBufferData.clear();
				std::vector<char>().swap( temporaryBufferData );

				range_beginIterator += iteratorOffset;
			}

			auto dataTransmisionWithEndTime = std::chrono::system_clock::now();
			TimeSpent = dataTransmisionWithEndTime - dataTransmisionWithStartTime;
			std::cout << "The file data transmission ends! the time has been spent: " << TimeSpent.count() << " seconds \n"
					  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;

			std::deque<std::vector<char>>().swap( TaskStatusData_Pointer->bufferDataBlockChain );
			TaskStatusData_Pointer->bufferDataBlockChain.clear();

			TaskStatusData_Pointer->bufferIsOccupiedWithMoving.store( false );
			TaskStatusData_Pointer->bufferIsOccupiedWithWriting.store( true );

			TaskStatusData_Pointer->bufferIsOccupiedWithMoving.notify_one();
			TaskStatusData_Pointer->bufferIsOccupiedWithWriting.notify_one();
		}

	protected:

		WritingFileDataStatus WritingFileData( TaskStatusData* TaskStatusData_Pointer, std::ofstream* FS_Object_Pointer, const std::size_t& fileDataByteSize, std::streampos& newFilePointerPosition )
		{
			using namespace Cryptograph::CommonModule;

			if ( FS_Object_Pointer->is_open() )
			{
				std::size_t		  dataBlockByteGroupID = 0;
				std::ios::iostate io_state;
				std::streampos	  currentFilePointerPosition;

				try
				{
					//当前的缓冲区中，是否不存在任何数据？
					//Is the current buffer not contain any data?
					if ( TaskStatusData_Pointer->bufferDataMap.size() == 0 || TaskStatusData_Pointer->bufferDataBlockChain.size() != 0 && currentFilePointerPosition != fileDataByteSize )
					{
						return WritingFileDataStatus::WRITING_WAIT_DATA_READY;
					}
					else
					{
						if ( TaskStatusData_Pointer->bufferIsOccupiedWithMoving.load() == false && TaskStatusData_Pointer->bufferIsOccupiedWithWriting.load() == true )
						{
							std::cout << "Note that the file is about to be write!\n"
									  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;

							currentFilePointerPosition = FS_Object_Pointer->tellp();

							for ( std::map<std::size_t, std::vector<char>>::iterator bufferDataIterator = TaskStatusData_Pointer->bufferDataMap.begin(); bufferDataIterator != TaskStatusData_Pointer->bufferDataMap.end(); ++bufferDataIterator )
							{
								auto& pairBufferData = *bufferDataIterator;
								if ( TaskStatusData_Pointer->bufferDataMap.contains( pairBufferData.first ) )
								{
									if ( pairBufferData.second.size() != 0 )
									{
										dataBlockByteGroupID = pairBufferData.first;
										TaskStatusData_Pointer->bufferData = pairBufferData.second;
										break;
									}
								}
							}

							if ( TaskStatusData_Pointer->bufferDataMap.contains( dataBlockByteGroupID ) )
							{
								TaskStatusData_Pointer->bufferDataMap.erase( dataBlockByteGroupID );
							}

							if ( TaskStatusData_Pointer->bufferData.size() == 0 && currentFilePointerPosition != fileDataByteSize )
							{
								return WritingFileDataStatus::BUFFER_DATA_INVALIED;
							}

							std::chrono::duration<double> TimeSpent;
							auto						  startTimeByWritedData = std::chrono::system_clock::now();

							FS_Object_Pointer->write( TaskStatusData_Pointer->bufferData.data(), TaskStatusData_Pointer->bufferData.size() );

							auto endTimeByWritedData = std::chrono::system_clock::now();

							newFilePointerPosition = FS_Object_Pointer->tellp();

							io_state = FS_Object_Pointer->rdstate();
							if ( ( io_state & ( std::ios::badbit | std::ios::failbit ) ) && !( io_state & std::ios::eofbit ) || currentFilePointerPosition == newFilePointerPosition )
							{
								std::stringstream ss_object;
								ss_object << "File data block write failed.\n"
										  << "Current Thread ID: " << std::this_thread::get_id();
								return WritingFileDataStatus::WRITE_DATA_FAILED;
							}
							else
							{

								TimeSpent = endTimeByWritedData - startTimeByWritedData;

								std::cout << "File data block write successfully, the time has heen spent: " << TimeSpent.count() << " seconds \n"
										  << "The current is the [" << dataBlockByteGroupID << "] data block group ID" << std::endl;

								TaskStatusData_Pointer->bufferIsOccupiedWithWriting.store( false );

								if ( fileDataByteSize == newFilePointerPosition )
								{
									return WritingFileDataStatus::WORKED;
								}
								else
								{
									return WritingFileDataStatus::CONTINUE_WORKING;
								}
							}
						}
					}
				}
				catch ( const std::exception& except )
				{
					std::cerr << "[Error] BinaryStreamWriter::WritingFileData Exception message is" << except.what() << std::endl;
				}
			}
			else
			{
				return WritingFileDataStatus::FILE_INVALIED;
			}
		}

	public:

		//写入内存数据到文件的函数
		//Functions for writing memory data to a file
		bool WriteFileData( std::string taskUniqueName, const std::filesystem::path& filePathName, std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlocks, std::size_t& dataBlockByteSize, std::size_t dataBlockCount );

		BinaryStreamWriter() = default;
		~BinaryStreamWriter() = default;

		BinaryStreamWriter(BinaryStreamWriter& _object) = delete;
		BinaryStreamWriter& operator=(const BinaryStreamWriter& _object) = delete;
	};

	bool BinaryStreamWriter::WriteFileData( std::string taskUniqueName, const std::filesystem::path& filePathName, std::unique_ptr<Cryptograph::CommonModule::FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlockChain, std::size_t& dataBlockByteSize, std::size_t dataBlockCount = 32 )
	{
		using namespace Cryptograph;

		//文件数据块链是否需要重新分组？
		//Does the file data block chain need to be regrouped?
		bool fileDataBlockChainNeedRegroup = false;

		//文件数据块链是否重新分组完成？
		//Is the file data block chain regrouped?
		bool fileDataBlockChainIsRegrouped = false;

		if ( dataBlockByteSize == 0 )
		{
			dataBlockByteSize = pointerWithFileDataBlockChain->front().size();
		}

		if ( CheckDataBlockByteSize( dataBlockByteSize ) == false )
		{
			std::cout << "The unit size of the data block not from standard !" << std::endl;
			return false;
		}

		std::size_t fileDataByteSize = 0;

		for ( auto beginIterator = pointerWithFileDataBlockChain->begin(), endIterator = pointerWithFileDataBlockChain->end(); beginIterator != endIterator; ++beginIterator )
		{
			auto partElementSize = beginIterator->size();

			//检查2GB数据块链的大小，是否不等于数据块的大小
			//Check that the size of the 2GB data block chain is not equal to the size of the data block
			if ( beginIterator != ( endIterator - 1 ) )
			{
				if ( partElementSize != dataBlockByteSize )
				{
					fileDataBlockChainNeedRegroup = true;
				}
			}
			fileDataByteSize += partElementSize;
		}

		constexpr std::size_t GB_SizeLimit = static_cast<std::size_t>( 2 ) * static_cast<std::size_t>( 1024 ) * static_cast<std::size_t>( 1024 ) * static_cast<std::size_t>( 1024 );

		if ( fileDataByteSize > GB_SizeLimit )
		{
			std::cerr << "因为我觉得你的内存条的容量不够大，所以我不允许使用你这个方法，来读写2GB以上大小的文件！" << std::endl;
			std::cerr << "Because I don't think the capacity of your memory stick is large enough, I'm not allowed to use this method of yours to read and write files over 2GB in size!" << std::endl;

			return false;
		}
		else if ( fileDataByteSize == 0 )
		{
			std::cerr << "这里不允许你写入空内容到文件!" << std::endl;
			std::cerr << "You are not allowed to write empty content to the file here!" << std::endl;
			return false;
		}

		if ( taskUniqueName.empty() )
		{
			std::cerr << "任务ID名称不能为空!" << std::endl;
			std::cerr << "The task ID name cannot be empty!" << std::endl;
		}

		auto taskUniqueNamesIterator = taskUniqueNames.find( taskUniqueName );
		if ( taskUniqueNamesIterator == taskUniqueNames.end() )
		{
			auto EmplaceResultFromMap = taskUniqueNames.insert( taskUniqueName );

			if ( EmplaceResultFromMap.second == true )
			{
				taskUniqueNamesIterator = EmplaceResultFromMap.first;
			}
			else
			{
				std::stringstream ss_object;
				ss_object << "线程锁对象无法被管理，初始化已被终止！\nThread lock object cannot be managed, initialization has been terminated!\n"
						  << "Current Thread ID: " << std::this_thread::get_id();

				std::string error_message{ ss_object.str() };

				throw std::runtime_error( error_message );
			}
		}
		else
		{
			std::cerr << "Task ID名称(Task ID name): " << taskUniqueName << std::endl;
			std::cerr << "线程锁无法获得资源的所有权，请等待线程锁释放资源的所有权！" << std::endl;
			std::cerr << "Thread locks cannot acquire ownership of resources, wait for the thread lock to release ownership of the resource!" << std::endl;
			return false;
		}

		if ( taskUniqueNames.contains( taskUniqueName ) )
		{
			std::cout << "Task ID名称(Task ID name): " << taskUniqueName << std::endl;
			std::cout << "线程锁已经获得资源的所有权！" << std::endl;
			std::cout << "Thread lock has acquired ownership of the resource!" << std::endl;

			std::unique_ptr<TaskStatusData> TaskStatusData_Pointer = std::make_unique<TaskStatusData>();

			TaskStatusData_Pointer->filePartDataProcessingByTaskCount.store( dataBlockCount );

			if ( fileDataBlockChainNeedRegroup == true )
			{
				fileDataBlockChainNeedRegroup = false;

				std::vector<char> _bufferDataBlock;
				_bufferDataBlock.reserve( fileDataByteSize );

				/*while (TaskStatusData_Pointer->bufferDataBlock.size() != fileDataByteSize)
				{
					if(pointerWithFileDataBlocks->front().size() > 0)
					{
						TaskStatusData_Pointer->bufferDataBlock.insert(TaskStatusData_Pointer->bufferDataBlock.end(), pointerWithFileDataBlocks->front().begin(), pointerWithFileDataBlocks->front().end());
						pointerWithFileDataBlocks->pop_front();
					}
				}*/

				//合并分组的数据块链
				//Combine grouped data block chain

				auto& sourceData = *pointerWithFileDataBlockChain;
				auto& targetData = _bufferDataBlock;
				CommonToolkit::ProcessingDataBlock::merger( sourceData, std::back_inserter( targetData ) );

				//分解数据块链并重新分组
				//Split and regroup data block chain

				auto& sourceData1 = _bufferDataBlock;
				auto& targetData1 = *pointerWithFileDataBlockChain;
				CommonToolkit::ProcessingDataBlock::splitter( sourceData1, std::back_inserter( targetData1 ), dataBlockByteSize );

				fileDataBlockChainIsRegrouped = true;
			}

			auto lambda_MovingDataBlock = [ this, &TaskStatusData_Pointer, pointerWithFileDataBlockChain, &dataBlockCount ]() -> void {
				this->MovingDataBlock( TaskStatusData_Pointer, pointerWithFileDataBlockChain, dataBlockCount );
			};

			auto lambda_WritingData = [ this, &filePathName, &TaskStatusData_Pointer, &FDCM_Adapter_Pointer, &fileDataByteSize ]() -> void {
				std::streampos _filePointerPosition;
				std::streamoff _filePointerOffset = 0;

				std::ofstream* FS_Object_Pointer = new std::ofstream();
				FS_Object_Pointer->open( filePathName, std::ios::out | std::ios::binary );

				WritingFileDataStatus statusWriting;

				auto lambda_TerminationFunction = [ &FS_Object_Pointer ]() -> void {
					FS_Object_Pointer->close();
					delete FS_Object_Pointer;
					FS_Object_Pointer = nullptr;
				};

			WritingFileDataFlag:

				TaskStatusData_Pointer->bufferIsOccupiedWithWriting.store( true );
				TaskStatusData_Pointer->bufferIsOccupiedWithWriting.notify_one();

				statusWriting = this->WritingFileData( TaskStatusData_Pointer.get(), FS_Object_Pointer, fileDataByteSize, _filePointerPosition );
				FDCM_Adapter_Pointer->fileDataByteWritedCount = _filePointerPosition;

				switch ( statusWriting )
				{
					case FileProcessing::Operation::BinaryStreamWriter::WritingFileDataStatus::WRITING_WAIT_DATA_READY:
					{
						TaskStatusData_Pointer->bufferIsOccupiedWithMoving.store( true );
						TaskStatusData_Pointer->bufferIsOccupiedWithWriting.store( false );

						TaskStatusData_Pointer->bufferIsOccupiedWithMoving.notify_one();
						TaskStatusData_Pointer->bufferIsOccupiedWithWriting.notify_one();

						TaskStatusData_Pointer->bufferIsOccupiedWithMoving.wait( true );
						TaskStatusData_Pointer->bufferIsOccupiedWithWriting.wait( false );

						goto WritingFileDataFlag;
					}
					case FileProcessing::Operation::BinaryStreamWriter::WritingFileDataStatus::FILE_INVALIED:
					{
						lambda_TerminationFunction();
						std::string error_message = "";
						throw std::runtime_error( error_message );
					}
					case FileProcessing::Operation::BinaryStreamWriter::WritingFileDataStatus::BUFFER_DATA_INVALIED:
					{
						lambda_TerminationFunction();
						std::string error_message = "";
						throw std::invalid_argument( error_message );
					}
					case FileProcessing::Operation::BinaryStreamWriter::WritingFileDataStatus::WRITE_DATA_FAILED:
					{
						lambda_TerminationFunction();
						std::string error_message = "";
						throw std::runtime_error( error_message );
					}

					default:
						break;
				}

				TaskStatusData_Pointer->bufferIsOccupiedWithWriting.store( false );
				TaskStatusData_Pointer->bufferIsOccupiedWithWriting.notify_one();

				if ( statusWriting == WritingFileDataStatus::CONTINUE_WORKING )
				{
					goto WritingFileDataFlag;
				}
				else if ( statusWriting == WritingFileDataStatus::WORKED )
				{
					FDCM_Adapter_Pointer->allFileDataIsWrited.store( true );
					lambda_TerminationFunction();
					return;
				}
			};

			if ( TaskStatusData_Pointer->bufferDataBlockChain.size() != 0 )
			{
				TaskStatusData_Pointer->bufferDataBlockChain.clear();
			}

			std::future<void> futureTask_writingDataBlock = std::async( std::launch::async, lambda_WritingData );

			///// Task Area /////

		TaskNotDone:

			if ( TaskStatusData_Pointer->bufferIsOccupiedWithMoving.load() == true && TaskStatusData_Pointer->bufferIsOccupiedWithWriting.load() == false )
			{
				std::future<void> futureTask_movingBufferDataBlock = std::async( std::launch::async, lambda_MovingDataBlock );

			MovingBufferDataFlag:

				std::future_status futureTaskStatus_movingBufferDataFunction = futureTask_movingBufferDataBlock.wait_for( std::chrono::seconds( 1 ) );
				std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

				if ( futureTaskStatus_movingBufferDataFunction != std::future_status::ready )
				{
					if ( futureTask_movingBufferDataBlock.valid() == false )
					{
						try
						{
							futureTask_movingBufferDataBlock.get();
						}
						catch ( const std::exception& except )
						{
							std::cerr << "[Error] Exception message is" << except.what() << std::endl;
						}
					}

					if ( futureTask_writingDataBlock.valid() == false )
					{
						try
						{
							futureTask_writingDataBlock.get();
						}
						catch ( const std::exception& except )
						{
							std::cerr << "[Error] Exception message is" << except.what() << std::endl;
						}
					}

					if ( TaskStatusData_Pointer->bufferIsOccupiedWithMoving.load() == false && TaskStatusData_Pointer->bufferIsOccupiedWithWriting.load() == false )
					{
						TaskStatusData_Pointer->bufferIsOccupiedWithWriting.store( true );
						TaskStatusData_Pointer->bufferIsOccupiedWithWriting.notify_one();
					}

					goto MovingBufferDataFlag;
				}
				else
				{
					futureTask_movingBufferDataBlock.get();
				}
			}

			std::future_status futureTaskStatus_writingFileDataBlockFunction = futureTask_writingDataBlock.wait_for( std::chrono::seconds( 1 ) );
			std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

			if ( futureTaskStatus_writingFileDataBlockFunction != std::future_status::ready )
			{
				goto TaskNotDone;
			}
			else
			{
				if ( FDCM_Adapter_Pointer->allFileDataIsWrited.load() == true )
				{
					goto TaskDone;
				}
				else
				{
					throw std::runtime_error( "" );
				}
			}

		TaskDone:

			///// Task Area /////

			taskUniqueNames.erase( taskUniqueName );
			return true;
		}
	}
}  // namespace FileProcessing::Operation
