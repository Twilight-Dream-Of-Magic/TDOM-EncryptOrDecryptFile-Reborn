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

//将全局语言区域更改为操作系统默认区域
//Change the global language region to the OS default region
//std::locale::global(std::locale(""));

//Restore global language locale settings
//还原全局语言区域设定
//std::locale::global(std::locale("C"));

#if __cplusplus >= 202002L

//对文件操作
//Operation on files
namespace FileProcessing::Operation
{
	struct FileDataModuleAdapter
	{
		std::string						   FileDataHashString;
		std::size_t						   FileDataBlockCount = 8;
		std::deque<std::vector<std::byte>> FileDataBytes;
		std::deque<std::vector<char>>	   FileDataCharacters;

		std::atomic<std::size_t> ByteReadedCount = 0;
		std::atomic<std::size_t> ByteWritedCount = 0;
		std::atomic<bool>		 AllDataIsReaded = false;
		std::atomic<bool>		 AllDataIsWrited = false;
		std::atomic<bool>		 IsCovertingToBytes = false;
		std::atomic<bool>		 IsCovertingFromBytes = false;

		void ResetStatus()
		{
			FileDataHashString.clear();
			ByteReadedCount.store( 0 );
			ByteWritedCount.store( 0 );
			AllDataIsReaded.store( false );
			AllDataIsWrited.store( false );
			IsCovertingToBytes.store( false );
			IsCovertingFromBytes.store( false );
		}

		void ClearData()
		{
			FileDataBytes.clear();
			FileDataCharacters.clear();
		}

		std::deque<std::vector<std::byte>> ToBytes( std::deque<std::vector<char>>& FileDataBlock )
		{
			if ( FileDataBlock.size() > 0 )
			{
				if ( FileDataBlock.front().size() == 0 && FileDataBlock.back().size() == 0 )
				{
					return std::deque<std::vector<std::byte>>( 0 );
				}

				std::deque<std::vector<std::byte>> answer;
				for ( std::size_t dataBlockNumber = 0; dataBlockNumber < FileDataBlockCount; ++dataBlockNumber )
				{
					std::vector<char>	   dataBlockIn( std::move( FileDataBlock[ dataBlockNumber ] ) );
					std::vector<std::byte> dataBlockOut;
					dataBlockOut.reserve(dataBlockIn.size());

					for ( char& dataIn : dataBlockIn )
					{
						std::byte dataOut = static_cast<std::byte>( static_cast<std::uint8_t>( dataIn ) );
						dataBlockOut.push_back( std::move( dataOut ) );
					}
					std::vector<char>().swap( dataBlockIn );
					answer.push_back( std::move( dataBlockOut ) );
				}
				std::deque<std::vector<char>>().swap( FileDataBlock );
				return answer;
			}
			return std::deque<std::vector<std::byte>>( 0 );
		}

		std::deque<std::vector<char>> FromBytes( std::deque<std::vector<std::byte>>& FileDataBlock )
		{
			if ( FileDataBlock.size() > 0 )
			{
				if ( FileDataBlock.front().size() == 0 && FileDataBlock.back().size() == 0 )
				{
					return std::deque<std::vector<char>>( 0 );
				}

				std::deque<std::vector<char>> answer;
				for ( std::size_t dataBlockNumber = 0; dataBlockNumber < FileDataBlockCount; ++dataBlockNumber )
				{
					std::vector<std::byte> dataBlockIn( std::move( FileDataBlock[ dataBlockNumber ] ) );
					std::vector<char>	   dataBlockOut;
					dataBlockOut.reserve(dataBlockIn.size());

					for ( std::byte& dataIn : dataBlockIn )
					{
						char	  dataOut = static_cast<char>( static_cast<std::uint8_t>( dataIn ) );
						dataBlockOut.push_back( std::move( dataOut ) );
					}
					std::vector<std::byte>().swap( dataBlockIn );
					answer.push_back( std::move( dataBlockOut ) );
				}
				std::deque<std::vector<std::byte>>().swap( FileDataBlock );
				return answer;
			}
			return std::deque<std::vector<char>>( 0 );
		}

		FileDataModuleAdapter() = default;
		~FileDataModuleAdapter() = default;
	};

	inline void ConvertingInputDataAndTransmission( std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlocks )
	{
		if ( FDMA_Pointer != nullptr )
		{
			auto						  NativePointer = FDMA_Pointer.get();
			FileDataModuleAdapter& AssociatedObjects = ( *NativePointer );
			AssociatedObjects.FileDataBlockCount = pointerWithFileDataBlocks->size();

			AssociatedObjects.IsCovertingToBytes.store( true );
			AssociatedObjects.FileDataBytes = std::move( AssociatedObjects.ToBytes( *pointerWithFileDataBlocks ) );
			AssociatedObjects.IsCovertingToBytes.store( false );
			AssociatedObjects.IsCovertingToBytes.notify_one();
		}
	}

	inline void ConvertingOutputDataAndTransmission( std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer, std::deque<std::vector<std::byte>>* pointerWithFileDataBlocks )
	{
		if ( FDMA_Pointer->IsCovertingFromBytes.load() == true )
		{
			FDMA_Pointer->IsCovertingFromBytes.wait( true );
		}

		if ( FDMA_Pointer != nullptr )
		{
			auto						  NativePointer = FDMA_Pointer.get();
			FileDataModuleAdapter& AssociatedObjects = ( *NativePointer );
			AssociatedObjects.FileDataBlockCount = pointerWithFileDataBlocks->size();

			AssociatedObjects.IsCovertingFromBytes.store( true );
			AssociatedObjects.FileDataCharacters = std::move( AssociatedObjects.FromBytes( *pointerWithFileDataBlocks ) );
			AssociatedObjects.IsCovertingFromBytes.store( false );
			AssociatedObjects.IsCovertingFromBytes.notify_one();
		}
	}

	inline void ConversionBufferData_Input( std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlocks )
	{
		std::chrono::duration<double> TimeSpent;

		if ( FDMA_Pointer->IsCovertingToBytes.load() == true )
		{
			FDMA_Pointer->IsCovertingToBytes.wait( true );
		}

		std::cout << "Note that the read-in file data is of type char and needs to be converted to std::byte.\n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
		auto convertTypeDataWithStartTime = std::chrono::system_clock::now();

		std::future<void> futureTask_convertingBufferData = std::async( std::launch::async, ConvertingInputDataAndTransmission, std::ref( FDMA_Pointer ), pointerWithFileDataBlocks );

	ConvertingBufferDataFlag:

		std::future_status futureTaskStatus_convertingBufferData = futureTask_convertingBufferData.wait_for( std::chrono::seconds( 1 ) );
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

		if ( futureTaskStatus_convertingBufferData != std::future_status::ready )
		{
			goto ConvertingBufferDataFlag;
		}

		auto convertTypeDataWithEndTime = std::chrono::system_clock::now();
		TimeSpent = convertTypeDataWithEndTime - convertTypeDataWithStartTime;
		std::cout << "The file data has been converted, the time has been spent: " << TimeSpent.count() << " seconds \n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
	}

	inline void ConversionBufferData_Output( std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer, std::deque<std::vector<std::byte>>* pointerWithFileDataBlocks )
	{
		std::chrono::duration<double> TimeSpent;

		if ( FDMA_Pointer->IsCovertingToBytes.load() == true )
		{
			FDMA_Pointer->IsCovertingToBytes.wait( true );
		}

		std::cout << "Note that the write-out file data is about std::byte type and needs to be converted to char type.\n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
		auto convertTypeDataWithStartTime = std::chrono::system_clock::now();

		std::future<void> futureTask_convertingBufferData = std::async( std::launch::async, ConvertingOutputDataAndTransmission, std::ref( FDMA_Pointer ), pointerWithFileDataBlocks );

	ConvertingBufferDataFlag:

		std::future_status futureTaskStatus_convertingBufferData = futureTask_convertingBufferData.wait_for( std::chrono::seconds( 1 ) );
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

		if ( futureTaskStatus_convertingBufferData != std::future_status::ready )
		{
			goto ConvertingBufferDataFlag;
		}

		auto convertTypeDataWithEndTime = std::chrono::system_clock::now();
		TimeSpent = convertTypeDataWithEndTime - convertTypeDataWithStartTime;
		std::cout << "The file data has been converted, the time has been spent: " << TimeSpent.count() << " seconds \n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
	}

	enum class FILE_OPERATION_STATUS
	{
		DONE = 0,
		ABORT_WITH_NOT_STANDARD_DATA_SIZE = 1,
		ABORT_WITH_CURRENT_TASKNAME_IS_EMPTY = 2,
		ABORT_WITH_CURRENT_TASKNAME_IS_RUNNING = 3,
		ERROR_WITH_DATA_SIZE_IS_ZERO = 4,
		ERROR_WITH_DATA_SIZE_IS_OVERLIMIT = 5,
		ERROR_WITH_TASKNAME_INITIAL = 6
	};

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

		std::set<std::string> TaskUniqueNames;

		struct TaskStatusData
		{
			std::map<std::size_t, std::vector<char>> BufferDataMap;
			std::vector<char>						 BufferData;

			std::size_t FilePartDataProcessingByTaskCount = 0;
			std::atomic<std::size_t> CurrentDataBlockNumber = 0;

			//谁没有了占用权，谁就不可以被使用
			//Whoever does not have the right of occupancy is not allowed to be used
			std::atomic<bool> BufferIsNotOccupiedWithReading = true;
			std::atomic<bool> BufferIsNotOccupiedWithMoving = true;
		};

		enum class ReadingStatus
		{
			WORKED = 0,
			CONTINUE_WORKING = 1,
			WAIT_DATA_IS_IDLE = 2,
			FILE_INVALIED = 3,
			READ_DATA_FAILED = 4
		};

		void MovingBufferData
		(
			std::unique_ptr<TaskStatusData>& TaskStatusData_Pointer,
			std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
			std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
			const std::size_t FileDataByteSize
		)
		{
			std::chrono::duration<double> TimeSpent;

			std::cout << "The file data transmission begins! \n"
					  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;
			auto dataTransmisionWithStartTime = std::chrono::system_clock::now();

			while (FDMA_Pointer->AllDataIsReaded.load( std::memory_order_acquire ) == false)
			{
				if(TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.load( std::memory_order_acquire ) == false && TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.load( std::memory_order_acquire ) == true)
				{
					BugFix:

					for ( std::pair<const std::size_t, std::vector<char>>& pairBufferData : TaskStatusData_Pointer->BufferDataMap )
					{
						if ( TaskStatusData_Pointer->BufferDataMap.contains( pairBufferData.first ) )
						{
							if ( pairBufferData.second.size() != 0 )
							{
								std::cout << "Moving data blocks are in progress and the current block index number is: " << pairBufferData.first << std::endl;
								pointerWithFileDataBlockChain->push_back( std::move( pairBufferData.second ) );
							}
						}
					}
					TaskStatusData_Pointer->BufferDataMap.clear();

					std::size_t _fileDataByteSize = 0;
					for ( auto beginIterator = pointerWithFileDataBlockChain->begin(), endIterator = pointerWithFileDataBlockChain->end(); beginIterator != endIterator; ++beginIterator )
					{
						std::size_t partElementSize = beginIterator->size();

						_fileDataByteSize += partElementSize;
					}

					FDMA_Pointer->ByteReadedCount.store( _fileDataByteSize, std::memory_order_relaxed );
				}

				if(TaskStatusData_Pointer->BufferDataMap.empty() && TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.load( std::memory_order_acquire ) == true && TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.load( std::memory_order_acquire ) == false)
				{
					TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.wait(true, std::memory_order_seq_cst );
					TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.wait(false, std::memory_order_seq_cst );
				}
				else if(FDMA_Pointer->ByteReadedCount.load( std::memory_order_relaxed ) == FileDataByteSize)
				{
					FDMA_Pointer->AllDataIsReaded.store( true, std::memory_order_release );
					FDMA_Pointer->AllDataIsReaded.notify_all();
				}
				else if(!TaskStatusData_Pointer->BufferDataMap.empty() && TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.load( std::memory_order_acquire ) == true && TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.load( std::memory_order_acquire ) == false)
				{
					TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.store( true, std::memory_order_release );
					TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.store( false, std::memory_order_release );

					TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.notify_one();
					TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.notify_one();

					goto BugFix;
				}
			}

			auto dataTransmisionWithEndTime = std::chrono::system_clock::now();
			TimeSpent = dataTransmisionWithEndTime - dataTransmisionWithStartTime;
			std::cout << "The file data transmission ends! the time has been spent: " << TimeSpent.count() << " seconds \n" << "Current Thread ID: " << std::this_thread::get_id() << std::endl;
		}

	protected:

		ReadingStatus ReadingFileData
		(
			TaskStatusData* TaskStatusData_Pointer,
			std::ifstream* FS_Object_Pointer,
			std::size_t& dataBlockByteSize,
			const std::size_t& fileDataByteSize,
			std::streampos& currentFilePointerPosition
		)
		{
			using namespace Cryptograph::CommonModule;

			if ( FS_Object_Pointer->is_open() )
			{
				std::ios::iostate io_state;
				std::streampos	  newFilePointerPosition;
				// !!! Begin Of Critical Zone !!! //

				try
				{
					if( TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.load( std::memory_order_acquire ) == true && TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.load( std::memory_order_acquire ) == false )
					{
						std::cout << "Note that the file is about to be read!\n"
								  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;

						if(dataBlockByteSize > fileDataByteSize)
						{
							dataBlockByteSize = fileDataByteSize;
						}

						TaskStatusData_Pointer->BufferData.resize( dataBlockByteSize );

						std::chrono::duration<double> TimeSpent;
						auto startTimeByReadedData = std::chrono::system_clock::now();

						currentFilePointerPosition = FS_Object_Pointer->tellg();

						FS_Object_Pointer->read( reinterpret_cast<char*>( &( TaskStatusData_Pointer->BufferData[ 0 ] ) ), dataBlockByteSize );

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

							return ReadingStatus::READ_DATA_FAILED;
						}

						std::cout << "File data block read successfully, the time has heen spent: " << TimeSpent.count() << " seconds \n"
								  << "The current is the [" << TaskStatusData_Pointer->CurrentDataBlockNumber << "] data block." << std::endl;

						//对已经分裂的数据块，进行编号记录
						//Numbered records for splited data blocks
						std::pair<std::size_t, std::vector<char>> pairBufferDataNode = std::make_pair( TaskStatusData_Pointer->CurrentDataBlockNumber.load( std::memory_order_acquire ), TaskStatusData_Pointer->BufferData );
						TaskStatusData_Pointer->BufferDataMap.insert( std::move( pairBufferDataNode ) );
						TaskStatusData_Pointer->CurrentDataBlockNumber += 1;
						std::vector<char>().swap( TaskStatusData_Pointer->BufferData );

						TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.store( false, std::memory_order_release );

						if ( TaskStatusData_Pointer->BufferDataMap.size() == TaskStatusData_Pointer->FilePartDataProcessingByTaskCount )
						{
							return ReadingStatus::WAIT_DATA_IS_IDLE;
						}

						//FS_Object_Pointer->eof()
						//io_state & std::ios::eofbit

						if ( fileDataByteSize == newFilePointerPosition )
						{
							return ReadingStatus::WORKED;
						}
						else
						{
							currentFilePointerPosition = newFilePointerPosition;
							return ReadingStatus::CONTINUE_WORKING;
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
				return ReadingStatus::FILE_INVALIED;
			}
		}

		ThreadingToolkit::Pool::Version3::Implementation::task LaunchAsyncTask
		(
			std::string taskUniqueName,
			ThreadingToolkit::Pool::Version3::ThreadPool& threadPool,
			ThreadingToolkit::Pool::Version3::Implementation::fire_once_event& onceEvent,
			const std::filesystem::path& filePathName,
			std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
			std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
			std::size_t& dataBlockByteSize,
			std::size_t dataBlockCount,
			const std::size_t& fileDataByteSize
		);

	public:

		//读取文件数据到内存的函数
		//Functions for reading file data into memory
		FileProcessing::Operation::FILE_OPERATION_STATUS ReadFileData
		(
			std::string taskUniqueName,
			const std::filesystem::path& filePathName,
			std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
			std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
			std::size_t& dataBlockByteSize,
			std::size_t dataBlockCount
		);

		BinaryStreamReader() = default;
		~BinaryStreamReader() = default;

		BinaryStreamReader(BinaryStreamReader& _object) = delete;
		BinaryStreamReader& operator=(const BinaryStreamReader& _object) = delete;
	};

	class BinaryStreamWriter
	{

	private:

		std::set<std::string> TaskUniqueNames;

		struct TaskStatusData
		{
			std::deque<std::vector<char>>			 BufferDataBlockChain;
			std::map<std::size_t, std::vector<char>> BufferDataMap;
			std::vector<char>						 BufferData;

			std::size_t FilePartDataProcessingByTaskCount = 0;
			std::atomic<std::size_t> CurrentDataBlockGroupNumber = 0;
			std::atomic<std::size_t> CurrentDataBlockNumber = 0;

			//谁拥有了占用权，谁就可以去使用
			//Whoever has the right of occupancy can go ahead and use
			std::atomic<bool> BufferIsOccupiedWithWriting = false;
			std::atomic<bool> BufferIsOccupiedWithMoving = false;
		};

		enum class WritingStatus
		{
			WORKED = 0,
			CONTINUE_WORKING = 1,
			WRITING_WAIT_DATA_READY = 2,
			FILE_INVALIED = 3,
			BUFFER_DATA_INVALIED = 4,
			WRITE_DATA_FAILED = 5
		};

		void MovingDataBlock
		(
			std::unique_ptr<TaskStatusData>& TaskStatusData_Pointer,
			std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
			std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
			std::size_t& dataBlockCount
		)
		{
			std::chrono::duration<double> TimeSpent;

			std::cout << "The file data transmission begins! \n"
					  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;
			auto dataTransmisionWithStartTime = std::chrono::system_clock::now();

			while (FDMA_Pointer->AllDataIsWrited.load( std::memory_order_acquire ) == false)
			{
				if(TaskStatusData_Pointer->BufferIsOccupiedWithMoving.load( std::memory_order_acquire ) == true && TaskStatusData_Pointer->BufferIsOccupiedWithWriting.load( std::memory_order_acquire ) == false)
				{
					BugFix:

					//交换两个数据块链
					//Exchange two data block chains
					( *pointerWithFileDataBlockChain ).swap( TaskStatusData_Pointer->BufferDataBlockChain );

					//迭代器（泛型指针）偏移量为零，当前是容器开头
					//The iterator (generic pointer) offset is zero, the current is the begin of the container
					auto range_beginIterator = TaskStatusData_Pointer->BufferDataBlockChain.begin();
					auto range_endIterator = TaskStatusData_Pointer->BufferDataBlockChain.end();

					std::vector<char> temporaryBufferData;

					while ( range_beginIterator != range_endIterator )
					{
						std::size_t					  iteratorOffset = CommonToolkit::IteratorOffsetDistance( range_beginIterator, range_endIterator, dataBlockCount );
						std::deque<std::vector<char>> subRange_container( range_beginIterator, range_beginIterator + iteratorOffset );

						std::size_t _currentDataBlockSize = TaskStatusData_Pointer->BufferDataBlockChain.size();

						//数据块链向临时缓冲区复制数据
						//Copying data to the temporary buffer.
						for ( auto container : subRange_container )
						{
							for ( auto data : container )
							{
								temporaryBufferData.emplace( temporaryBufferData.end(), std::move( data ) );
							}
							std::cout << "Moving data blocks are in progress and the current block index number is: " << TaskStatusData_Pointer->CurrentDataBlockNumber << std::endl;
							TaskStatusData_Pointer->CurrentDataBlockNumber += 1;
						}

						std::size_t _currentDataBlockSize2 = TaskStatusData_Pointer->BufferDataBlockChain.size();

						//移除已经复制过的数据在数据块链中
						//Remove data that has been copied in the data block chain
						if ( _currentDataBlockSize >= _currentDataBlockSize2 || temporaryBufferData.size() != 0 )
						{
							subRange_container.clear();
							std::deque<std::vector<char>>().swap( subRange_container );
						}

						//对可能重分过的数据块，进行编号记录
						//Numbered records of data blocks that may have been re-splited
						std::pair<std::size_t, std::vector<char>> pairBufferDataNode = std::make_pair( TaskStatusData_Pointer->CurrentDataBlockGroupNumber.load( std::memory_order_acquire ), std::move( temporaryBufferData ) );
						TaskStatusData_Pointer->BufferDataMap.insert( std::move( pairBufferDataNode ) );
						TaskStatusData_Pointer->CurrentDataBlockGroupNumber += 1;

						//必须清除临时缓冲区的旧数据
						//The old data in the temporary buffer must be cleared
						temporaryBufferData.clear();
						std::vector<char>().swap( temporaryBufferData );

						range_beginIterator += iteratorOffset;
					}

					std::deque<std::vector<char>>().swap( TaskStatusData_Pointer->BufferDataBlockChain );
					TaskStatusData_Pointer->BufferDataBlockChain.clear();
				}

				if(TaskStatusData_Pointer->BufferDataBlockChain.empty() && TaskStatusData_Pointer->BufferDataMap.empty() && pointerWithFileDataBlockChain->empty())
				{
					TaskStatusData_Pointer->BufferIsOccupiedWithMoving.store( false, std::memory_order_release );
					TaskStatusData_Pointer->BufferIsOccupiedWithWriting.store( true, std::memory_order_release );

					TaskStatusData_Pointer->BufferIsOccupiedWithMoving.notify_one();
					TaskStatusData_Pointer->BufferIsOccupiedWithWriting.notify_one();

					FDMA_Pointer->AllDataIsWrited.wait( false, std::memory_order_seq_cst );
				}
				else
				{
					goto BugFix;
				}
			}

			auto dataTransmisionWithEndTime = std::chrono::system_clock::now();
			TimeSpent = dataTransmisionWithEndTime - dataTransmisionWithStartTime;
			std::cout << "The file data transmission ends! the time has been spent: " << TimeSpent.count() << " seconds \n" << "Current Thread ID: " << std::this_thread::get_id() << std::endl;
		}

	protected:

		WritingStatus WritingFileData
		(
			TaskStatusData* TaskStatusData_Pointer,
			std::ofstream* FS_Object_Pointer,
			const std::size_t& fileDataByteSize,
			std::streampos& newFilePointerPosition
		)
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
					if ( TaskStatusData_Pointer->BufferDataMap.size() == 0 || TaskStatusData_Pointer->BufferDataBlockChain.size() != 0 && currentFilePointerPosition != fileDataByteSize )
					{
						return WritingStatus::WRITING_WAIT_DATA_READY;
					}
					else
					{
						if ( TaskStatusData_Pointer->BufferIsOccupiedWithMoving.load( std::memory_order_acquire ) == false && TaskStatusData_Pointer->BufferIsOccupiedWithWriting.load( std::memory_order_acquire ) == true )
						{
							std::cout << "Note that the file is about to be write!\n"
									  << "Current Thread ID: " << std::this_thread::get_id() << std::endl;

							currentFilePointerPosition = FS_Object_Pointer->tellp();

							for ( std::pair<const std::size_t, std::vector<char>>& pairBufferData : TaskStatusData_Pointer->BufferDataMap )
							{
								if ( TaskStatusData_Pointer->BufferDataMap.contains( pairBufferData.first ) )
								{
									if ( pairBufferData.second.size() != 0 )
									{
										dataBlockByteGroupID = std::move(pairBufferData.first);
										TaskStatusData_Pointer->BufferData = std::move(pairBufferData.second);
										break;
									}
								}
							}

							if ( TaskStatusData_Pointer->BufferDataMap.contains( dataBlockByteGroupID ) )
							{
								TaskStatusData_Pointer->BufferDataMap.erase( dataBlockByteGroupID );
							}

							// Do not allow the compiler to optimize this variable address
							// 不允许编译器优化这个变量地址
							volatile std::size_t dataBlockByteSize = TaskStatusData_Pointer->BufferData.size();

							if ( dataBlockByteSize == 0 && currentFilePointerPosition != fileDataByteSize )
							{
								return WritingStatus::BUFFER_DATA_INVALIED;
							}

							if(dataBlockByteSize > fileDataByteSize)
							{
								dataBlockByteSize = fileDataByteSize;
							}

							std::chrono::duration<double> TimeSpent;
							auto startTimeByWritedData = std::chrono::system_clock::now();

							FS_Object_Pointer->write( TaskStatusData_Pointer->BufferData.data(), dataBlockByteSize );

							auto endTimeByWritedData = std::chrono::system_clock::now();

							newFilePointerPosition = FS_Object_Pointer->tellp();

							io_state = FS_Object_Pointer->rdstate();
							if ( ( io_state & ( std::ios::badbit | std::ios::failbit ) ) && !( io_state & std::ios::eofbit ) || currentFilePointerPosition == newFilePointerPosition )
							{
								std::stringstream ss_object;
								ss_object << "File data block write failed.\n"
										  << "Current Thread ID: " << std::this_thread::get_id();
								return WritingStatus::WRITE_DATA_FAILED;
							}
							else
							{

								TimeSpent = endTimeByWritedData - startTimeByWritedData;

								std::cout << "File data block write successfully, the time has heen spent: " << TimeSpent.count() << " seconds \n"
										  << "The current is the [" << dataBlockByteGroupID << "] data block group ID" << std::endl;

								if ( fileDataByteSize == newFilePointerPosition )
								{
									return WritingStatus::WORKED;
								}
								else
								{
									return WritingStatus::CONTINUE_WORKING;
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
				return WritingStatus::FILE_INVALIED;
			}
		}

		ThreadingToolkit::Pool::Version3::Implementation::task LaunchAsyncTask
		(
			std::string taskUniqueName,
			ThreadingToolkit::Pool::Version3::ThreadPool& threadPool,
			ThreadingToolkit::Pool::Version3::Implementation::fire_once_event& onceEvent,
			const std::filesystem::path& filePathName,
			std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
			std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
			std::size_t& dataBlockByteSize,
			std::size_t dataBlockCount,
			std::size_t& fileDataByteSize
		);

	public:

		//写入内存数据到文件的函数
		//Functions for writing memory data to a file
		FileProcessing::Operation::FILE_OPERATION_STATUS WriteFileData
		(
			std::string taskUniqueName,
			const std::filesystem::path& filePathName,
			std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
			std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
			std::size_t& dataBlockByteSize,
			std::size_t dataBlockCount
		);

		BinaryStreamWriter() = default;
		~BinaryStreamWriter() = default;

		BinaryStreamWriter(BinaryStreamWriter& _object) = delete;
		BinaryStreamWriter& operator=(const BinaryStreamWriter& _object) = delete;
	};

	inline FileProcessing::Operation::FILE_OPERATION_STATUS BinaryStreamReader::ReadFileData
	(
		std::string taskUniqueName,
		const std::filesystem::path& filePathName,
		std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
		std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
		std::size_t& dataBlockByteSize,
		std::size_t dataBlockCount = 32
	)
	{
		using namespace Cryptograph;

		if ( CheckDataBlockByteSize( dataBlockByteSize ) == false )
		{
			std::cerr << "The unit size of the data block not from standard !" << std::endl;
			return FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_NOT_STANDARD_DATA_SIZE;
		}

		const std::size_t	  fileDataByteSize = std::filesystem::file_size( filePathName );
		constexpr std::size_t GB_SizeLimit = static_cast<std::size_t>( 4 ) * static_cast<std::size_t>( 1024 ) * static_cast<std::size_t>( 1024 ) * static_cast<std::size_t>( 1024 );

		if ( fileDataByteSize > static_cast<std::size_t>( GB_SizeLimit ) )
		{
			std::cerr << "因为我觉得你的内存条的容量不够大，所以我不允许使用你这个方法，来读写4GB以上大小的文件！" << std::endl;
			std::cerr << "Because I don't think the capacity of your memory stick is large enough, I'm not allowed to use this method of yours to read and write files over 4GB in size!" << std::endl;

			return FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_OVERLIMIT;
		}
		else if ( fileDataByteSize == 0 )
		{
			std::cerr << "你不允许在这里将空文件的内容读到内存中!" << std::endl;
			std::cerr << "You are not allowed to read empty file of content to the memory here!" << std::endl;
			return FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_ZERO;
		}

		if ( taskUniqueName.empty() )
		{
			std::cerr << "任务ID名称不能为空!" << std::endl;
			std::cerr << "The task ID name cannot be empty!" << std::endl;
			return FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_EMPTY;
		}


		auto taskUniqueNamesIterator = TaskUniqueNames.find( taskUniqueName );
		if ( taskUniqueNamesIterator == TaskUniqueNames.end() )
		{
			auto insertResultFromMap = TaskUniqueNames.insert( taskUniqueName );

			if ( insertResultFromMap.second == true )
			{
				taskUniqueNamesIterator = insertResultFromMap.first;
			}
			else
			{
				std::stringstream ss_object;
				ss_object << "任务名称(像线程锁一样)对象无法被管理，初始化已被终止！\nTask name (like a thread lock) object cannot be managed, initialization has been terminated!\n"
						  << "Current Thread ID: " << std::this_thread::get_id();

				return FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_TASKNAME_INITIAL;
			}
		}
		else
		{
			std::cerr << "Task ID名称(Task ID name): " << taskUniqueName << std::endl;
			std::cerr << "任务名称(像线程锁一样)无法获得资源的所有权，请等待线程锁释放资源的所有权！" << std::endl;
			std::cerr << "Task name (like a thread lock) cannot acquire ownership of resources, wait for the thread lock to release ownership of the resource!" << std::endl;
			return FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_RUNNING;
		}

		if ( TaskUniqueNames.contains( taskUniqueName ) )
		{
			ThreadingToolkit::Pool::Version3::ThreadPool threadPool { 2 };

			ThreadingToolkit::Pool::Version3::Implementation::fire_once_event onceEvent;

			ThreadingToolkit::Pool::Version3::Implementation::task theAsyncTask = this->LaunchAsyncTask(taskUniqueName, threadPool, onceEvent, filePathName, FDMA_Pointer, pointerWithFileDataBlockChain, dataBlockByteSize, dataBlockCount, fileDataByteSize);

			ThreadingToolkit::Pool::Version3::Implementation::sync_wait(theAsyncTask, onceEvent);

			return FileProcessing::Operation::FILE_OPERATION_STATUS::DONE;
		}
	}

	inline FileProcessing::Operation::FILE_OPERATION_STATUS BinaryStreamWriter::WriteFileData
	(
		std::string taskUniqueName,
		const std::filesystem::path& filePathName,
		std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
		std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
		std::size_t& dataBlockByteSize,
		std::size_t dataBlockCount = 32
	)
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
			return FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_NOT_STANDARD_DATA_SIZE;
		}

		std::size_t fileDataByteSize = 0;

		for ( auto beginIterator = pointerWithFileDataBlockChain->begin(), endIterator = pointerWithFileDataBlockChain->end(); beginIterator != endIterator; ++beginIterator )
		{
			auto partElementSize = beginIterator->size();

			//检查4GB数据块链的大小，是否不等于数据块的大小
			//Check that the size of the 4GB data block chain is not equal to the size of the data block
			if ( beginIterator != ( endIterator - 1 ) )
			{
				if ( partElementSize != dataBlockByteSize )
				{
					fileDataBlockChainNeedRegroup = true;
				}
			}
			fileDataByteSize += partElementSize;
		}

		constexpr std::size_t GB_SizeLimit = static_cast<std::size_t>( 4 ) * static_cast<std::size_t>( 1024 ) * static_cast<std::size_t>( 1024 ) * static_cast<std::size_t>( 1024 );

		if ( fileDataByteSize > GB_SizeLimit )
		{
			std::cerr << "因为我觉得你的内存条的容量不够大，所以我不允许使用你这个方法，来读写4GB以上大小的文件！" << std::endl;
			std::cerr << "Because I don't think the capacity of your memory stick is large enough, I'm not allowed to use this method of yours to read and write files over 4GB in size!" << std::endl;

			return FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_OVERLIMIT;
		}
		else if ( fileDataByteSize == 0 )
		{
			std::cerr << "这里不允许你写入空内容到文件!" << std::endl;
			std::cerr << "You are not allowed to write empty content to the file here!" << std::endl;
			return FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_DATA_SIZE_IS_ZERO;
		}

		if ( taskUniqueName.empty() )
		{
			std::cerr << "任务ID名称不能为空!" << std::endl;
			std::cerr << "The task ID name cannot be empty!" << std::endl;
			return FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_EMPTY;
		}

		auto taskUniqueNamesIterator = TaskUniqueNames.find( taskUniqueName );
		if ( taskUniqueNamesIterator == TaskUniqueNames.end() )
		{
			auto insertResultFromMap = TaskUniqueNames.insert( taskUniqueName );

			if ( insertResultFromMap.second == true )
			{
				taskUniqueNamesIterator = insertResultFromMap.first;
			}
			else
			{
				std::stringstream ss_object;
				ss_object << "任务名称(像线程锁一样)对象无法被管理，初始化已被终止！\nTask name (like a thread lock) object cannot be managed, initialization has been terminated!\n"
						  << "Current Thread ID: " << std::this_thread::get_id();

				return FileProcessing::Operation::FILE_OPERATION_STATUS::ERROR_WITH_TASKNAME_INITIAL;
			}
		}
		else
		{
			std::cerr << "Task ID名称(Task ID name): " << taskUniqueName << std::endl;
			std::cerr << "线程锁无法获得资源的所有权，请等待线程锁释放资源的所有权！" << std::endl;
			std::cerr << "Thread locks cannot acquire ownership of resources, wait for the thread lock to release ownership of the resource!" << std::endl;
			return FileProcessing::Operation::FILE_OPERATION_STATUS::ABORT_WITH_CURRENT_TASKNAME_IS_RUNNING;
		}

		if ( TaskUniqueNames.contains( taskUniqueName ) )
		{
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

			ThreadingToolkit::Pool::Version3::ThreadPool threadPool { 2 };

			ThreadingToolkit::Pool::Version3::Implementation::fire_once_event onceEvent;

			ThreadingToolkit::Pool::Version3::Implementation::task theAsyncTask = this->LaunchAsyncTask(taskUniqueName, threadPool, onceEvent, filePathName, FDMA_Pointer, pointerWithFileDataBlockChain, dataBlockByteSize, dataBlockCount, fileDataByteSize);

			ThreadingToolkit::Pool::Version3::Implementation::sync_wait(theAsyncTask, onceEvent);

			return FileProcessing::Operation::FILE_OPERATION_STATUS::DONE;
		}
	}

	inline ThreadingToolkit::Pool::Version3::Implementation::task BinaryStreamReader::LaunchAsyncTask
	(
		std::string taskUniqueName,
		ThreadingToolkit::Pool::Version3::ThreadPool& threadPool,
		ThreadingToolkit::Pool::Version3::Implementation::fire_once_event& onceEvent,
		const std::filesystem::path& filePathName,
		std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
		std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
		std::size_t& dataBlockByteSize,
		std::size_t dataBlockCount,
		const std::size_t& fileDataByteSize
	)
	{
		std::cout << "Task ID名称(Task ID name): " << taskUniqueName << std::endl;
		std::cout << "线程锁已经获得资源的所有权！" << std::endl;
		std::cout << "Thread lock has acquired ownership of the resource!" << std::endl;

		co_await threadPool.schedule();
		std::cout << "这是一个异步线程的任务，具体是读取文件数据，ID是: " << std::this_thread::get_id() << "\n";
		std::cout << "This is an asynchronous threaded task, specifically reading file data with the ID: " << std::this_thread::get_id() << "\n";

		std::unique_ptr<TaskStatusData> TaskStatusData_Pointer = std::make_unique<TaskStatusData>();

		TaskStatusData_Pointer->FilePartDataProcessingByTaskCount = dataBlockCount;

		auto lambda_MovingBufferData = [ this, &TaskStatusData_Pointer, pointerWithFileDataBlockChain, &FDMA_Pointer, &fileDataByteSize ]() -> void
		{
			this->MovingBufferData( TaskStatusData_Pointer, pointerWithFileDataBlockChain, FDMA_Pointer, fileDataByteSize );
		};

		auto lambda_ReadingData = [ this, &dataBlockByteSize, &filePathName, &fileDataByteSize, &TaskStatusData_Pointer, &FDMA_Pointer ]() -> void
		{
			std::streampos _filePointerPosition;
			std::streamoff _filePointerOffset = 0;

			std::size_t _dataBlockByteSize = dataBlockByteSize;

			std::unique_ptr<std::ifstream> FS_Object = std::make_unique<std::ifstream>();
			std::ifstream* FS_Object_Pointer = FS_Object.get();
			FS_Object_Pointer->open( filePathName, std::ios::in | std::ios::binary );
			FS_Object_Pointer->seekg( 0, std::ios::beg );

			ReadingStatus statusReading;

			auto lambda_TerminationFunction = [ &FS_Object_Pointer, &FS_Object ]() -> void
			{
				FS_Object_Pointer->close();
				FS_Object.reset();
			};

			ReadingFileDataFlag:

			statusReading = this->ReadingFileData( TaskStatusData_Pointer.get(), FS_Object_Pointer, _dataBlockByteSize, fileDataByteSize, _filePointerPosition );

			switch ( statusReading )
			{
				case FileProcessing::Operation::BinaryStreamReader::ReadingStatus::WAIT_DATA_IS_IDLE:
				{
					for(;;)
					{
						if(TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.load( std::memory_order_acquire ) == true && TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.load( std::memory_order_acquire ) == false)
						{
							break;
						}
						else if(TaskStatusData_Pointer->BufferDataMap.empty() && _filePointerPosition != fileDataByteSize)
						{
							TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.store( true, std::memory_order_release );
							TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.store( false, std::memory_order_release );

							TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.notify_one();
							TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.notify_one();
						}
						else
						{
							std::this_thread::sleep_for(std::chrono::seconds(10));
						}
					}

					goto ReadingFileDataFlag;
				}
				case FileProcessing::Operation::BinaryStreamReader::ReadingStatus::FILE_INVALIED:
				{
					lambda_TerminationFunction();
					std::string error_message = "";
					throw std::runtime_error( error_message );
				}
				case FileProcessing::Operation::BinaryStreamReader::ReadingStatus::READ_DATA_FAILED:
				{
					lambda_TerminationFunction();
					std::string error_message = "";
					throw std::runtime_error( error_message );
				}
				default:
					break;
			}

			_filePointerOffset = static_cast<std::streamoff>( _filePointerPosition );

			if ( statusReading == ReadingStatus::CONTINUE_WORKING )
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

				TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.exchange( true, std::memory_order_release );
				TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.exchange( false, std::memory_order_release );

				TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.notify_one();
				TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.notify_one();

				goto ReadingFileDataFlag;
			}
			else if ( statusReading == ReadingStatus::WORKED )
			{
				lambda_TerminationFunction();

				if(TaskStatusData_Pointer != nullptr)
				{
					TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.exchange( false, std::memory_order_seq_cst );
					TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.exchange( true, std::memory_order_seq_cst );

					TaskStatusData_Pointer->BufferIsNotOccupiedWithMoving.notify_one();
					TaskStatusData_Pointer->BufferIsNotOccupiedWithReading.notify_one();
				}

				FDMA_Pointer->AllDataIsReaded.wait( false, std::memory_order_seq_cst );

				return;
			}
		};

		///// Task Area /////

		//https://en.cppreference.com/w/cpp/experimental/future/is_ready
		//std::experimental::future<T>::is_ready
		
		auto asyncTaskFurture_MovingBufferData = std::async(std::launch::async, lambda_MovingBufferData);

		if ( FDMA_Pointer->AllDataIsReaded.load( std::memory_order_acquire ) == false )
		{
			ThreadingToolkit::Wrapper::AsyncTask_SyncWrapper( lambda_ReadingData );
			asyncTaskFurture_MovingBufferData.get();
		}

		///// Task Area /////

		TaskUniqueNames.erase( taskUniqueName );
		//onceEvent.set();
	}

	inline ThreadingToolkit::Pool::Version3::Implementation::task BinaryStreamWriter::LaunchAsyncTask
	(
		std::string taskUniqueName,
		ThreadingToolkit::Pool::Version3::ThreadPool& threadPool,
		ThreadingToolkit::Pool::Version3::Implementation::fire_once_event& onceEvent,
		const std::filesystem::path& filePathName,
		std::unique_ptr<FileDataModuleAdapter>& FDMA_Pointer,
		std::deque<std::vector<char>>* pointerWithFileDataBlockChain,
		std::size_t& dataBlockByteSize,
		std::size_t dataBlockCount,
		std::size_t& fileDataByteSize
	)
	{
		std::cout << "Task ID名称(Task ID name): " << taskUniqueName << std::endl;
		std::cout << "线程锁已经获得资源的所有权！" << std::endl;
		std::cout << "Thread lock has acquired ownership of the resource!" << std::endl;

		/*
			关于Coroutine的任务函数，co_await 运算符的作用:
			当前线程所执行的函数被Coroutine的任务给暂停，
			把当前线程的调用控制权立即转移给线程池对象(一个可等待的表达式)，
			等到线程池对象完全创建多个线程对象之后，由线程池Coroutine任务的等待器(自行实现)，
			立即转移它的调用控制权，恢复给当前线程所执行的函数。
			
			About Coroutine's task functions, the co_await operator works:
			The function executed by the current thread is suspended by the Coroutine's task that
			transferring control of the current thread's invocation to a thread pool object ( the expression of awaitable) immediately
			After the thread pool object has completely created multiple thread objects,
			the awaiter of the Coroutine task of the thread pool (implemented by itself) immediately transfers its invocation control to the function executed by the current thread.
		*/
		co_await threadPool.schedule();
		std::cout << "这是一个异步线程的任务，具体是写入文件数据，ID是: " << std::this_thread::get_id() << "\n";
		std::cout << "This is an asynchronous threaded task, specifically writing file data with the ID: " << std::this_thread::get_id() << "\n";

		std::unique_ptr<TaskStatusData> TaskStatusData_Pointer = std::make_unique<TaskStatusData>();

		TaskStatusData_Pointer->FilePartDataProcessingByTaskCount = dataBlockCount;

		auto lambda_MovingDataBlock = [ this, &TaskStatusData_Pointer, pointerWithFileDataBlockChain, &FDMA_Pointer ]() -> void
		{
			this->MovingDataBlock( TaskStatusData_Pointer, pointerWithFileDataBlockChain, FDMA_Pointer, TaskStatusData_Pointer->FilePartDataProcessingByTaskCount );
		};

		auto lambda_WritingData = [ this, &filePathName, &TaskStatusData_Pointer, &FDMA_Pointer, &fileDataByteSize ]() -> void
		{
			std::streampos _filePointerPosition;
			/* std::streamoff _filePointerOffset = 0; */

			std::unique_ptr<std::ofstream> FS_Object = std::make_unique<std::ofstream>();
			std::ofstream* FS_Object_Pointer = FS_Object.get();
			
			//访问这个文件时，截断这个文件数据，不可恢复
			//When accessing this file, the data of this file is truncated and cannot be recovered.
			FS_Object_Pointer->open( filePathName, std::ios::out |std::ios::trunc | std::ios::binary );
			if(FS_Object_Pointer->is_open())
			{
				FS_Object_Pointer->close();
			}
			else
			{
				std::string error_message = "";
				throw std::invalid_argument( error_message );
			}

			FS_Object_Pointer->open( filePathName, std::ios::out |std::ios::app | std::ios::binary );

			WritingStatus statusWriting;

			auto lambda_TerminationFunction = [ &FS_Object_Pointer, &FS_Object ]() -> void
			{
				FS_Object_Pointer->close();
				FS_Object.reset();
			};

		WritingFileDataFlag:

			statusWriting = this->WritingFileData( TaskStatusData_Pointer.get(), FS_Object_Pointer, fileDataByteSize, _filePointerPosition );
			FDMA_Pointer->ByteWritedCount.store( _filePointerPosition, std::memory_order_relaxed );

			switch ( statusWriting )
			{
				case FileProcessing::Operation::BinaryStreamWriter::WritingStatus::WRITING_WAIT_DATA_READY:
				{

					for(;;)
					{
						if(TaskStatusData_Pointer->BufferIsOccupiedWithMoving.load( std::memory_order_acquire ) == false && TaskStatusData_Pointer->BufferIsOccupiedWithWriting.load( std::memory_order_acquire ) == true )
						{
							break;
						}
						else if(TaskStatusData_Pointer->BufferDataBlockChain.empty() && !TaskStatusData_Pointer->BufferDataMap.empty() && _filePointerPosition != fileDataByteSize)
						{
							TaskStatusData_Pointer->BufferIsOccupiedWithMoving.store( false, std::memory_order_release );
							TaskStatusData_Pointer->BufferIsOccupiedWithWriting.store( true, std::memory_order_release );

							TaskStatusData_Pointer->BufferIsOccupiedWithMoving.notify_one();
							TaskStatusData_Pointer->BufferIsOccupiedWithWriting.notify_one();
						}
						else
						{
							std::this_thread::sleep_for(std::chrono::seconds(10));
						}
					}

					goto WritingFileDataFlag;
				}
				case FileProcessing::Operation::BinaryStreamWriter::WritingStatus::FILE_INVALIED:
				{
					lambda_TerminationFunction();
					std::string error_message = "";
					throw std::runtime_error( error_message );
				}
				case FileProcessing::Operation::BinaryStreamWriter::WritingStatus::BUFFER_DATA_INVALIED:
				{
					lambda_TerminationFunction();
					std::string error_message = "";
					throw std::invalid_argument( error_message );
				}
				case FileProcessing::Operation::BinaryStreamWriter::WritingStatus::WRITE_DATA_FAILED:
				{
					lambda_TerminationFunction();
					std::string error_message = "";
					throw std::runtime_error( error_message );
				}

				default:
					break;
			}

			if ( statusWriting == WritingStatus::CONTINUE_WORKING )
			{
				goto WritingFileDataFlag;
			}
			else if ( statusWriting == WritingStatus::WORKED )
			{
				lambda_TerminationFunction();

				if(TaskStatusData_Pointer != nullptr)
				{
					TaskStatusData_Pointer->BufferIsOccupiedWithMoving.exchange( true, std::memory_order_seq_cst );
					TaskStatusData_Pointer->BufferIsOccupiedWithWriting.exchange( false, std::memory_order_seq_cst );

					TaskStatusData_Pointer->BufferIsOccupiedWithMoving.notify_one();
					TaskStatusData_Pointer->BufferIsOccupiedWithWriting.notify_one();

					FDMA_Pointer->AllDataIsWrited.exchange( true, std::memory_order_seq_cst );
					FDMA_Pointer->AllDataIsWrited.notify_all();
				}

				return;
			}
		};

		if ( TaskStatusData_Pointer->BufferDataBlockChain.size() != 0 )
		{
			TaskStatusData_Pointer->BufferDataBlockChain.clear();
		}

		///// Task Area /////

		//https://en.cppreference.com/w/cpp/experimental/future/is_ready
		//std::experimental::future<T>::is_ready

		auto asyncTaskFurture_WritingData = std::async(std::launch::async, lambda_WritingData);

		if ( FDMA_Pointer->AllDataIsWrited.load( std::memory_order_acquire ) == false )
		{
			ThreadingToolkit::Wrapper::AsyncTask_SyncWrapper( lambda_MovingDataBlock );

			asyncTaskFurture_WritingData.get();
		}

		///// Task Area /////

		TaskUniqueNames.erase( taskUniqueName );
		//onceEvent.set();
	}

}  // namespace FileProcessing::Operation

#endif