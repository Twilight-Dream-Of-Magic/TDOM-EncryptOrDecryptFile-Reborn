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

//对文件操作
//Operation on files
namespace FileProcessing::FileOperation
{
	//Check that the unit size of the data block meets the standard
	inline bool CheckDataBlockByteSize(std::size_t& dataBlockByteSize)
	{
		auto isMultiplesOfTwo = [&]() -> bool
		{
			return dataBlockByteSize > 0 && (dataBlockByteSize & 1) == 0;
		};

		auto isPowerOfTwo = [&]() -> bool
		{
			return dataBlockByteSize > 0 && (dataBlockByteSize & (dataBlockByteSize - 1)) == 0;
		};

		bool _isMultiplesOfTwo = isMultiplesOfTwo();
		bool _isPowerOfTwo = isPowerOfTwo();

		if(_isMultiplesOfTwo || _isPowerOfTwo)
		{
			return true;
		}
		else
		{
			if ((dataBlockByteSize % 1024) != 0)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}

	class StreamReader
	{

	private:

		std::shared_timed_mutex thread_lock;
		std::vector<char> buffer_vector;

	public:

		//读取文件数据到内存的函数
		//Functions for reading file data into memory
		void ReadData(const std::string& filePathName, std::list<char>& fileData, std::size_t dataBlockByteSize);
	};

	void StreamReader::ReadData(const std::string& filePathName, std::list<char>& fileData, std::size_t dataBlockByteSize = 1024)
	{
		if(CheckDataBlockByteSize(dataBlockByteSize) == false)
		{
			std::cout << "The unit size of the data block not from standard !" << std::endl;
			return;
		}
		else
		{
			size_t _fileDataSize = fileData.size();

			while (CheckDataBlockByteSize(_fileDataSize) == false)
			{
				fileData.push_back(0x00);
				_fileDataSize = fileData.size();
			}
		}

		std::unique_lock<std::shared_timed_mutex> locker(thread_lock, std::defer_lock);
		//thread_lock.lock_shared();
		std::ifstream fileInputObject;

		if (locker.try_lock_for( std::chrono::seconds(10) ))
		{
			const std::size_t _dataBlockByteSize = dataBlockByteSize;
			fileInputObject.open(filePathName, std::ios::in | std::ios::binary);

			if (fileInputObject.is_open())
			{
				std::mutex sub_thread_lock;

				fileInputObject.seekg(0, std::ios::end);
				std::streampos file_end_position = fileInputObject.tellg();
				fileInputObject.seekg(0, std::ios::beg);
				std::streampos file_begin_position = fileInputObject.tellg();

				buffer_vector.reserve(_dataBlockByteSize);

				auto lambda_ReadingData = [&]() -> void
				{
					std::cout << "NameSpace: FileProcessing::FileOperation, Class: StreamReader, Function: ReadData.lambda_ReadingData\n" << " is thread id <-> " << std::this_thread::get_id() << std::endl;
					if(buffer_vector.size() == 0)
					{
						std::lock_guard<std::mutex> lockRange(sub_thread_lock);
						buffer_vector.resize(_dataBlockByteSize);
						fileInputObject.read(reinterpret_cast<char*>(&buffer_vector[0]), _dataBlockByteSize);
						
						if(fileInputObject.gcount() == 0)
						{
							return;
						}
					}
				};

				auto lambda_InsertData = [&]() -> void
				{
					std::cout << "NameSpace: FileProcessing::FileOperation, Class: StreamReader, Function: ReadData.lamdba_InsertData\n" << " is thread id <-> " << std::this_thread::get_id() << std::endl;
					
					if(buffer_vector.size() != 0)
					{
						std::lock_guard<std::mutex> lockRange(sub_thread_lock);
						fileData.insert(fileData.end(), buffer_vector.cbegin(), buffer_vector.cend());
					}
					else
					{
						return;
					}
				};

				std::cout << "NameSpace: FileProcessing::FileOperation, Class: StreamReader, Function: ReadData\n" << " is thread id <-> " << std::this_thread::get_id() << std::endl;
				while (fileInputObject.tellg() != file_end_position)
				{
					std::future<void> futureTask_ReadingData = std::async(std::launch::async, lambda_ReadingData);
					std::future_status futureTaskStatus_ReadingData;

					do
					{
						futureTaskStatus_ReadingData = futureTask_ReadingData.wait_for(std::chrono::seconds(1));
						if (futureTaskStatus_ReadingData == std::future_status::deferred)
						{
							std::cout << "The asynchronous subthread task has not yet been executed? (Function: ReadData.lambda_ReadingData)" << std::endl;
							futureTask_ReadingData.wait();
						}
						if (futureTaskStatus_ReadingData == std::future_status::timeout)
						{
							std::cout << "The asynchronous subthread task is executing, please wait......" << std::endl;
							std::this_thread::sleep_for(std::chrono::seconds(5));
						}
					}
					while (futureTaskStatus_ReadingData != std::future_status::ready);

					if (futureTaskStatus_ReadingData == std::future_status::ready)
					{
						std::cout << "The asynchronous subthread task has been execute completed! (Function: ReadData.lambda_ReadingData)" << std::endl;
						futureTask_ReadingData.get();
					}

					std::future<void> futureTask_InsertData = std::async(std::launch::async, lambda_InsertData);
					std::future_status futureTaskStatus_InsertData;

					do
					{
						futureTaskStatus_InsertData = futureTask_InsertData.wait_for(std::chrono::seconds(1));
						if (futureTaskStatus_InsertData == std::future_status::deferred)
						{
							std::cout << "The asynchronous subthread task has not yet been executed? (ReadData.lamdba_InsertData)" << std::endl;
							futureTask_InsertData.wait();
						}
						if (futureTaskStatus_InsertData == std::future_status::timeout)
						{
							std::cout << "The asynchronous subthread task is executing, please wait......" << std::endl;
							std::this_thread::sleep_for(std::chrono::seconds(5));
						}
					}
					while (futureTaskStatus_InsertData != std::future_status::ready);

					if(futureTaskStatus_InsertData == std::future_status::ready)
					{
						std::cout << "The asynchronous subthread task has been execute completed! (ReadData.lamdba_InsertData)" << std::endl;
						futureTask_InsertData.get();
						buffer_vector.clear();
					}
				}
				std::cout << "NameSpace: FileProcessing::FileOperation, Class: StreamReader, Function: ReadData\n" << " is thread id <-> " << std::this_thread::get_id() << std::endl;

				std::vector<char>().swap(buffer_vector);
			}

			fileInputObject.close();
			//thread_lock.unlock_shared();
			locker.unlock();
		}
		else
		{
			return;
		}
	}

	class StreamWriter
	{

	private:

		std::shared_timed_mutex thread_lock;
		std::vector<char> buffer_vector;

	public:

		//写入内存数据到文件的函数
		//Functions for writing memory data to a file
		void WriteData(const std::string& filePathName, std::list<char>& fileData, std::size_t dataBlockByteSize);
	};

	void StreamWriter::WriteData(const std::string& filePathName, std::list<char>& fileData, std::size_t dataBlockByteSize = 1024)
	{
		if(CheckDataBlockByteSize(dataBlockByteSize) == false)
		{
			std::cout << "The unit size of the data block not from standard !" << std::endl;
			return;
		}
		else
		{
			size_t _fileDataSize = fileData.size();

			while (CheckDataBlockByteSize(_fileDataSize) == false)
			{
				fileData.push_back(0x00);
				_fileDataSize = fileData.size();
			}
		}

		std::unique_lock<std::shared_timed_mutex> locker(thread_lock, std::defer_lock);
		//thread_lock.lock_shared()
		std::ofstream fileOutputObject;
		
		if (locker.try_lock_for( std::chrono::seconds(10) ))
		{
			const std::size_t _dataBlockByteSize = dataBlockByteSize;
			fileOutputObject.open(filePathName, std::ios::out | std::ios::binary);

			if (fileOutputObject.is_open())
			{
				std::mutex sub_thread_lock;

				auto listIterator = fileData.begin();
				auto listIterator2 = fileData.begin();
				std::ranges::advance(listIterator2, _dataBlockByteSize);

				auto lambda_InsertData = [&]() -> bool
				{
					std::lock_guard<std::mutex> lockRange(sub_thread_lock);

					std::cout << "NameSpace: FileProcessing::FileOperation, Class: StreamWriter, Function: WriteData.lambda_InsertData\n" << " is thread id <-> " << std::this_thread::get_id() << std::endl;
					if (std::ranges::distance(listIterator, listIterator2) == _dataBlockByteSize)
					{
						if (listIterator2 != fileData.end())
						{
							buffer_vector.insert(buffer_vector.end(), listIterator, listIterator2);
							std::ranges::advance(listIterator, _dataBlockByteSize);
							std::ranges::advance(listIterator2, _dataBlockByteSize);
						}
						else
						{
							buffer_vector.insert(buffer_vector.end(), listIterator, listIterator2);
						}
						return true;
					}
					else
					{
						return false;
					}
				};

				auto lambda_WritingData = [&]() -> void
				{
					std::cout << "NameSpace: FileProcessing::FileOperation, Class: StreamWriter, Function: WriteData.lambda_WritingData\n" << " is thread id <-> " << std::this_thread::get_id() << std::endl;
					if(buffer_vector.size() != 0)
					{
						std::lock_guard<std::mutex> lockRange(sub_thread_lock);
						fileOutputObject.write(reinterpret_cast<char*>(buffer_vector.data()), _dataBlockByteSize);
					}
				};

				if (fileOutputObject.tellp() != 0)
				{
					fileOutputObject.seekp(std::ios::beg);
				}

				std::cout << "NameSpace: FileProcessing::FileOperation, Class: StreamWriter, Function: WriteData\n" << " is thread id <-> " << std::this_thread::get_id() << std::endl;
				for (unsigned long long file_begin_position = 0, file_end_position = fileData.size(); file_begin_position != file_end_position; file_begin_position += _dataBlockByteSize)
				{
					std::future<bool> futureTask_InsertData = std::async(std::launch::async, lambda_InsertData);
					std::future_status futureTaskStatus_InsertData;

					do
					{
						futureTaskStatus_InsertData = futureTask_InsertData.wait_for(std::chrono::seconds(1));
						if (futureTaskStatus_InsertData == std::future_status::deferred)
						{
							std::cout << "The asynchronous subthread task has not yet been executed? (Function: WriteData.lambda_InsertData)" << std::endl;
							futureTask_InsertData.wait();
						}
						if (futureTaskStatus_InsertData == std::future_status::timeout)
						{
							std::cout << "The asynchronous subthread task is executing, please wait......" << std::endl;
							std::this_thread::sleep_for(std::chrono::seconds(5));
						}
					}
					while (futureTaskStatus_InsertData != std::future_status::ready);

					if (futureTaskStatus_InsertData == std::future_status::ready)
					{
						std::cout << "The asynchronous subthread task has been execute completed! (Function: WriteData.lambda_InsertData)" << std::endl;
						bool InsertData = futureTask_InsertData.get();

						if(InsertData == false)
						{
							std::string error_message = "[Debug] Oh, no!\nThe list container iterator offset position of the memory data, the calculated range is incorrect!\nMaybe you should adjust the offset position of the iterator?";
							throw std::runtime_error(error_message);
						}
					}

					std::future<void> futureTask_WritingData = std::async(std::launch::async, lambda_WritingData);
					std::future_status futureTaskStatus_WritingData;

					do
					{
						futureTaskStatus_WritingData = futureTask_WritingData.wait_for(std::chrono::seconds(1));
						if (futureTaskStatus_WritingData == std::future_status::deferred)
						{
							std::cout << "The asynchronous subthread task has not yet been executed? (Function: WriteData.lambda_WritingData)" << std::endl;
							futureTask_WritingData.wait();
						}
						if(futureTaskStatus_WritingData == std::future_status::timeout)
						{
							std::cout << "The asynchronous subthread task is executing, please wait......" << std::endl;
							std::this_thread::sleep_for(std::chrono::seconds(5));
						}
					}
					while (futureTaskStatus_WritingData != std::future_status::ready);

					if(futureTaskStatus_WritingData == std::future_status::ready)
					{
						std::cout << "The asynchronous subthread task has been execute completed! (Function: WriteData.lambda_WritingData)" << std::endl;
						futureTask_WritingData.get();
						buffer_vector.clear();
					}
				}
				std::cout << "NameSpace: FileProcessing::FileOperation, Class: StreamWriter, Function: WriteData\n" << " is thread id <-> " << std::this_thread::get_id() << std::endl;

				std::vector<char>().swap(buffer_vector);
			}

			fileOutputObject.close();
			//thread_lock.unlock_shared();
			locker.unlock();
		}
		else
		{
			return;
		}
	}
}
