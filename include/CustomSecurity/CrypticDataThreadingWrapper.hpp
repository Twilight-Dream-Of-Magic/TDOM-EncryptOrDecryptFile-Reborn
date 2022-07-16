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

#include "CryptionWorker.hpp"

#pragma once

namespace CrypticDataThreadingWrapper
{
	class FileDataHelper
	{

	private:
		struct TaskStatusData
		{
			std::vector<std::byte> _Status_SymmetricSecretKey_;
			std::size_t  _Status_FileBiockSize_;
			std::size_t  _Status_FileDataOffest_;
			TaskStatusData(std::vector<std::byte>& key, std::size_t FileBiockSize, std::size_t FileWhere)
			{
				_Status_SymmetricSecretKey_ = key;
				_Status_FileBiockSize_ = FileBiockSize;
				_Status_FileDataOffest_ = FileWhere;
			}
		};
		
	public:
		FileDataHelper
		(
			std::deque<std::vector<std::byte>>& key,
			const std::filesystem::path inputFileName, const std::filesystem::path outputFileName,
			std::size_t fileByteSize,
			const Cryptograph::CommonModule::CryptionMode2MCAC4_FDW choiseWorker,
			std::size_t planRunThread = 128, std::size_t fileBlock_NumberOfMegaByteSize = 8
		)
		:
		_SymmetricSecretKeyData_(key), _InputFileName_(inputFileName), _OutputFileName_(outputFileName),
		_FileByteSize_(fileByteSize), _ChoiseWorkerMode_(choiseWorker)
		{
			_OneFileBlock_MegaByteSize_ = 1024 * 16; //16 Mega byte
			
			auto CheckFileByteSize = std::filesystem::file_size(_InputFileName_);
			_FileByteSize_ = ( fileByteSize == CheckFileByteSize ? fileByteSize : CheckFileByteSize );
			
			//在加密模式：大小是 OneFileBlock *= 64
			//在解密模式：大小是 OneFileBlock *= 65
			//In encrypted mode: size is OneFileBlock *= 64
			//In decryption mode: size is OneFileBlock *= 65
			switch (_ChoiseWorkerMode_)
			{
				case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
					_OneFileBlock_MegaByteSize_ *= 64;
					break;
				case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
					_OneFileBlock_MegaByteSize_ *= 65;
					break;
			}
		
			if(planRunThread <= std::thread::hardware_concurrency() / 2)
			{
				_RunThreadTaskCount_ = planRunThread;
			}
			else
			{
				_RunThreadTaskCount_ = planRunThread / 4;
			}

			//The fileBlock_MegaByteSizeOfCount default value is 8
			//If you change it when you use encryption, you also need to change it when you use decryption
			//fileBlock_NumberOfMegaByteSize的默认值是8
			//如果在使用加密的时候改动了它，那么在使用解密的时候也需要改动它
			_EachFileBlock_MegaByteSize_ = _OneFileBlock_MegaByteSize_ * fileBlock_NumberOfMegaByteSize;
		}

		~FileDataHelper()
		{
			if (push_future_thread.joinable())
			{
				push_future_thread.join();
			}
			if (pop_future_thread.joinable())
			{
				pop_future_thread.join();
			}
		}

		void launch_work()
		{
			before_run();
		}

		FileDataHelper() = delete;
		FileDataHelper(FileDataHelper& _object) = delete;

	protected:
		std::thread push_future_thread;
		std::thread pop_future_thread;
		//是否完成了处理操作
		//Whether the processing operation is completed
		std::atomic<bool> is_processing_operation_done = false;
		std::atomic<int> CurrentThreadTaskCount = 0;

		std::deque<TaskStatusData> TasksStatusDataDeque;
		std::deque<std::vector<std::byte>> _SymmetricSecretKeyData_;
		std::deque<std::future<std::vector<char>>> _FileDataWithAsyncDeque_;

	private:
		
		const std::filesystem::path _InputFileName_;
		const std::filesystem::path _OutputFileName_;

		//The size of a block of the file with mega bytes
		//文件的一个分块大小，以Mega字节为单位
		std::size_t _OneFileBlock_MegaByteSize_;
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW _ChoiseWorkerMode_;
		std::size_t _FileByteSize_;
		
		//Maybe this value can be 256?
		//Number of tasks planned to run threads
		//计划运行线程的任务数
		std::size_t _RunThreadTaskCount_;
		
		std::size_t _EachFileBlock_MegaByteSize_;

	private:
		void before_run();
		void read_run();
		void write_run();
		std::vector<char> ThreadTask(TaskStatusData taskStatusData);
		//std::vector<char> EncrypterTask(TaskData task_data);
		//std::vector<char> DecrypterTask(TaskData task_data);
	};

	inline void FileDataHelper::before_run()
	{
		std::size_t fileSize = _FileByteSize_;
		std::size_t fileWhereOffset = 0;
		auto iterator_key = _SymmetricSecretKeyData_.begin();

		while ( fileSize > _EachFileBlock_MegaByteSize_)
		{
			if (iterator_key == _SymmetricSecretKeyData_.end())
			{
				iterator_key = _SymmetricSecretKeyData_.begin();
			}
			
			TasksStatusDataDeque.push_back
			(
				TaskStatusData { *iterator_key, _EachFileBlock_MegaByteSize_, fileWhereOffset }
			);

			fileSize -= _EachFileBlock_MegaByteSize_;
			fileWhereOffset += _EachFileBlock_MegaByteSize_;
			++iterator_key;
		}

		iterator_key = _SymmetricSecretKeyData_.begin();
		TasksStatusDataDeque.push_back
		(
			TaskStatusData { *iterator_key ,fileSize ,fileWhereOffset }
		);

		this->push_future_thread = std::thread(&FileDataHelper::read_run, std::ref(*this));
		this->pop_future_thread = std::thread(&FileDataHelper::write_run, std::ref(*this));
	}

	inline void FileDataHelper::read_run()
	{
		while (!TasksStatusDataDeque.empty())
		{
			if (CurrentThreadTaskCount.load() < _RunThreadTaskCount_)
			{
				++(this->CurrentThreadTaskCount);
				_FileDataWithAsyncDeque_.push_back( std::async(std::launch::async, &FileDataHelper::ThreadTask, std::ref(*this), TasksStatusDataDeque.front()) );
				TasksStatusDataDeque.pop_front();
			}
		}
		
		is_processing_operation_done = true;
	}

	inline void FileDataHelper::write_run()
	{
		std::ofstream ofs;
		ofs.open(_OutputFileName_, std::ios::out | std::ios::binary);
		
		if (!ofs.is_open())
			my_cpp2020_assert(false, "Error when open to a output file: failed to access.", std::source_location::current());

		if (_ChoiseWorkerMode_ == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
		{
			std::vector<char> fileData;
			while (!is_processing_operation_done)
			{
				if (!_FileDataWithAsyncDeque_.empty())
				{
					fileData = _FileDataWithAsyncDeque_.front().get();
					ofs.write(fileData.data(), fileData.size());
					_FileDataWithAsyncDeque_.pop_front();
				}
			}

			while (!_FileDataWithAsyncDeque_.empty())
			{
				fileData = _FileDataWithAsyncDeque_.front().get();
				ofs.write(fileData.data(), fileData.size());
				_FileDataWithAsyncDeque_.pop_front();
			}
		}
		else if (_ChoiseWorkerMode_ == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
		{
			std::vector<char> fileData;
			std::streamsize writedCount = 0;
			int alignmentCount = _FileByteSize_ % 64;
			
			while (!is_processing_operation_done)
			{
				if (_FileDataWithAsyncDeque_.size() > 1)
				{
					fileData = _FileDataWithAsyncDeque_.front().get();

					writedCount = ofs.rdbuf()->sputn(fileData.data(), fileData.size());

					if(writedCount != fileData.size())
						my_cpp2020_assert(false, "Error when writing to a file: file data size does not match !", std::source_location::current());

					_FileDataWithAsyncDeque_.pop_front();
				}
			}

			while (_FileDataWithAsyncDeque_.size() > 1)
			{
				fileData = _FileDataWithAsyncDeque_.front().get();

				//ofs.write(fileData.data(), fileData.size());
				writedCount = ofs.rdbuf()->sputn(fileData.data(), fileData.size());
				
				if(writedCount != fileData.size())
					my_cpp2020_assert(false, "Error when writing to a file: file data size does not match !", std::source_location::current());

				_FileDataWithAsyncDeque_.pop_front();
			}
			fileData = _FileDataWithAsyncDeque_.front().get();

			unsigned int filePaddedByteDataSize = 64 - alignmentCount;
			while (--filePaddedByteDataSize)
			{
				fileData.pop_back();
			}

			//ofs.write(fileData.data(), fileData.size());
			writedCount = ofs.rdbuf()->sputn(fileData.data(), fileData.size());
			
			if(writedCount != fileData.size())
				my_cpp2020_assert(false, "Error when writing to a file: file data size does not match !", std::source_location::current());
		}
		else
		{
			std::cout << "Wrong worker is selected" << std::endl;
			abort();
		}
		ofs.close();
	}

	inline std::vector<char> FileDataHelper::ThreadTask(TaskStatusData taskStatusData)
	{
		std::vector<char> fileData;
		std::streamsize readedCount = 0;
		//fileData.reserve(taskStatusData._Status_FileBiockSize_);
		fileData.resize(taskStatusData._Status_FileBiockSize_);
		
		std::ifstream ifs;
		ifs.open(_InputFileName_, std::ios::in | std::ios::binary);

		if (!ifs.is_open())
		{
			my_cpp2020_assert(false, "Error when open to a input file: failed to access.", std::source_location::current());
		}
		else
		{
			ifs.seekg(taskStatusData._Status_FileDataOffest_);
			
			//ifs.read(&fileData[0], taskStatusData._Status_FileBiockSize_);
			readedCount = ifs.rdbuf()->sgetn(&fileData[0], taskStatusData._Status_FileBiockSize_);

			ifs.close();
		}

		if(readedCount != taskStatusData._Status_FileBiockSize_)
			my_cpp2020_assert(false, "Error when reading to a file: file data size does not match !", std::source_location::current());

		std::size_t index = 0;
		switch (_ChoiseWorkerMode_)
		{
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				if (fileData.size() != taskStatusData._Status_FileBiockSize_)
					my_cpp2020_assert(false, "Error when operating data to a file: Corruption occurs after by data encryption !", std::source_location::current());

				index = taskStatusData._Status_FileBiockSize_ % 64;

				if (index != 0)
				{
					index = 64 - index;
					std::random_device HardwareRandomDevice;
					CommonSecurity::RNG_Xoshiro::xoshiro256 RandomGeneraterBySecureSeed( CommonSecurity::GenerateSecureRandomNumberSeed<std::size_t>( HardwareRandomDevice ) );
					CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::size_t> UniformDistribution(0, 255);
					while (index--)
					{
						auto randomInteger = static_cast<std::uint32_t>(UniformDistribution(RandomGeneraterBySecureSeed));
						char filePaddingByteData{ static_cast<char>(randomInteger) };
						fileData.push_back(filePaddingByteData);
					}
				}
				break;
			}
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				index = taskStatusData._Status_FileBiockSize_ % 65;
				
				if (index != 0)
					my_cpp2020_assert(false, "Error when operating data to a file: Corruption occurs after by data decryption !", std::source_location::current());

				break;
			}
			default:
			{
				std::cout << "Wrong worker is selected" << std::endl;
				abort();
				break;
			}
		}

		/*
			Use custom symmetric encryption and decryption algorithms: OaldresPuzzle-Cryptic 隐秘的奥尔德雷斯之谜
			使用自定义的对称加密和解密算法：隐秘的奥尔德雷斯之谜
		*/

		if (_ChoiseWorkerMode_ == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
		{
			Cryptograph::Implementation::Encrypter custom_encrypter;
			custom_encrypter.Main(fileData, taskStatusData._Status_SymmetricSecretKey_);
		}
		else if (_ChoiseWorkerMode_ == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
		{
			Cryptograph::Implementation::Decrypter custom_decrypter;
			custom_decrypter.Main(fileData, taskStatusData._Status_SymmetricSecretKey_);
		}

		--(this->CurrentThreadTaskCount);
		return fileData;
	}

}  // namespace CrypticDataThreadingWrapper
