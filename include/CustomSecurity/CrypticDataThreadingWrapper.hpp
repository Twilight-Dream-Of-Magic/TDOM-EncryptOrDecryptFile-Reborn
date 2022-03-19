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
			std::vector<std::byte> _Status_Key;
			std::size_t  _Status_FileBiockSize;
			std::size_t  _Status_FileDataOffest;
			TaskStatusData(std::vector<std::byte>& key, std::size_t FileBiockSize, std::size_t FileWhere)
			{
				_Status_Key = key;
				_Status_FileBiockSize = FileBiockSize;
				_Status_FileDataOffest = FileWhere;
			}
		};
		
	public:
		FileDataHelper
		(
			std::deque<std::vector<std::byte>>& key,
			const std::filesystem::path inputFileName, const std::filesystem::path outputFileName,
			std::size_t fileSize,
			const Cryptograph::CommonModule::CryptionMode2MCAC4_FDW choiseWorker,
			std::size_t planRunThread = 128, std::size_t fileBlock_MetaByteSizeCount = 8
		)
		{
			_Key = key;
			_InputFileName = inputFileName;
			_OutputFileName = outputFileName;
			_FileSize = fileSize;
			_OneFileBlock_MegaByteSize = 1024 * 16;
			_ChoiseWorker = choiseWorker;
			switch (_ChoiseWorker)
			{
				case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
					_OneFileBlock_MegaByteSize = _OneFileBlock_MegaByteSize * 64;
					break;
				case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
					_OneFileBlock_MegaByteSize = _OneFileBlock_MegaByteSize * 65;
					break;
			}
		
			if(planRunThread <= std::thread::hardware_concurrency() / 2)
			{
				_PlanRunThread = planRunThread;
			}
			else
			{
				_PlanRunThread = planRunThread / 4;
			}

			_EachFileBlock_MegaByteSize = _OneFileBlock_MegaByteSize * fileBlock_MetaByteSizeCount;
		}

		~FileDataHelper()
		{
			if (push_future.joinable())
			{
				push_future.join();
			}
			if (pop_future.joinable())
			{
				pop_future.join();
			}
		}

		void launch_work()
		{
			before_run();
		}

		FileDataHelper() = delete;
		FileDataHelper(FileDataHelper& _object) = delete;

	protected:
		std::thread push_future;
		std::thread pop_future;
		std::atomic<bool> is_push_done = false;
		std::atomic<bool> is_pop_done = false;
		std::atomic<int> ThreadCount = 0;

		std::deque<TaskStatusData> TasksStatusDataDeque;
		std::deque<std::vector<std::byte>> _Key;
		std::deque<std::future<std::vector<char>>> _FileData;

	private:

		//1024 * 16  解密*65/加密*64
		std::size_t _OneFileBlock_MegaByteSize;
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW _ChoiseWorker;
		std::filesystem::path _InputFileName;
		std::filesystem::path _OutputFileName;
		std::size_t _FileSize;
		
		//256
		std::size_t _PlanRunThread;
		
		//8 MetaByte, 如果加密的时候需要改动，解密的时候也一样需要改动
		std::size_t _EachFileBlock_MegaByteSize;

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
		unsigned long filesize = std::filesystem::file_size(_InputFileName);
		unsigned long fileWhereOffset = 0;
		auto iterator_key = _Key.begin();

		while ( filesize > _EachFileBlock_MegaByteSize)
		{
			if (iterator_key == _Key.end())
			{
				iterator_key = _Key.begin();
			}
			
			TasksStatusDataDeque.push_back
			(
				TaskStatusData { *iterator_key, _EachFileBlock_MegaByteSize, fileWhereOffset }
			);

			filesize = filesize - _EachFileBlock_MegaByteSize;
			fileWhereOffset += _EachFileBlock_MegaByteSize;
			++iterator_key;
		}

		iterator_key = _Key.begin();
		TasksStatusDataDeque.push_back
		(
			TaskStatusData { *iterator_key ,filesize ,fileWhereOffset }
		);

		this->push_future = std::thread(&FileDataHelper::read_run, std::ref(*this));
		this->pop_future = std::thread(&FileDataHelper::write_run, std::ref(*this));
	}

	inline void FileDataHelper::read_run()
	{
		while (!TasksStatusDataDeque.empty())
		{
			if (ThreadCount.load() < _PlanRunThread)
			{
				++(this->ThreadCount);
				_FileData.push_back(std::async(std::launch::async, &FileDataHelper::ThreadTask, std::ref(*this), TasksStatusDataDeque.front()));
				TasksStatusDataDeque.pop_front();
			}
		}
		
		is_push_done = true;
	}

	inline void FileDataHelper::write_run()
	{
		std::ofstream ofs;
		
		ofs.open(_OutputFileName, std::ios::out | std::ios::binary);
		if (!ofs.is_open())
		{
			std::runtime_error access_file_is_failed("Failed to access the output file !");
			throw access_file_is_failed;
		}
		if (_ChoiseWorker == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
		{
			std::vector<char> Filedata;
			while (!is_push_done)
			{
				if (!_FileData.empty())
				{
					Filedata = _FileData.front().get();
					ofs.write(Filedata.data(), Filedata.size());
					_FileData.pop_front();
				}
			}

			while (!_FileData.empty())
			{
				Filedata = _FileData.front().get();
				ofs.write(Filedata.data(), Filedata.size());
				_FileData.pop_front();
			}
		}
		else if (_ChoiseWorker == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
		{
			std::vector<char> Filedata;
			std::streamsize writedCount = 0;
			int AlignmentCount = _FileSize % 64;
			
			while (!is_push_done)
			{
				if (_FileData.size() > 1)
				{
					Filedata = _FileData.front().get();

					writedCount = ofs.rdbuf()->sputn(Filedata.data(), Filedata.size());
					if(writedCount != Filedata.size())
					{
						std::runtime_error writing_file_has_been_error("Error while writing size a file !");
						throw writing_file_has_been_error;
					}
					_FileData.pop_front();
				}
			}

			while (_FileData.size() > 1)
			{
				Filedata = _FileData.front().get();

				//ofs.write(Filedata.data(), Filedata.size());
				writedCount = ofs.rdbuf()->sputn(Filedata.data(), Filedata.size());
				if(writedCount != Filedata.size())
				{
					std::runtime_error writing_file_has_been_error("Error while writing size a file !");
					throw writing_file_has_been_error;
				}
				_FileData.pop_front();
			}
			Filedata = _FileData.front().get();

			int index = 64 - AlignmentCount;
			while (index--)
			{
				Filedata.pop_back();
			}

			//ofs.write(Filedata.data(), Filedata.size());
			writedCount = ofs.rdbuf()->sputn(Filedata.data(), Filedata.size());
			if(writedCount != Filedata.size())
			{
				std::runtime_error writing_file_has_been_error("Error while writing size a file !");
				throw writing_file_has_been_error;
			}
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
		std::vector<char> Filedata;
		std::streamsize readedCount = 0;
		//Filedata.reserve(task_data.m_FileBiockSize);
		Filedata.resize(taskStatusData._Status_FileBiockSize);
		std::ifstream ifs;

		ifs.open(_InputFileName, std::ios::in | std::ios::binary);
		if (!ifs.is_open())
		{
			std::runtime_error access_file_is_failed("Failed to access the input file !");
			throw access_file_is_failed;
		}
		else
		{
			ifs.seekg(taskStatusData._Status_FileDataOffest);
			
			//ifs.read(&Filedata[0], taskStatusData._Status_FileBiockSize);
			readedCount = ifs.rdbuf()->sgetn(&Filedata[0], taskStatusData._Status_FileBiockSize);
			if (readedCount != taskStatusData._Status_FileBiockSize)
			{
				std::runtime_error reading_file_has_been_error("Error while reading size a file !");
				throw reading_file_has_been_error;
			}
			ifs.close();
		}

		if (Filedata.size()!= taskStatusData._Status_FileBiockSize)
		{
			std::runtime_error corruption_occurs_data_by_encrypted("Corruption occurs after by data encryption !");
			throw corruption_occurs_data_by_encrypted;
		}

		std::size_t index;
		switch (_ChoiseWorker)
		{
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				index = taskStatusData._Status_FileBiockSize % 64;
				if (index != 0)
				{
					index = 64 - index;
					CommonSecurity::RNG_Xoshiro::xoshiro256 RandomGeneraterByReallyTime(std::chrono::system_clock::now().time_since_epoch().count());
					CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::size_t> number_distribution(0, 255);
					while (index--)
					{
						auto integer = static_cast<std::uint32_t>(number_distribution(RandomGeneraterByReallyTime));
						char temporaryData{ static_cast<char>(integer) };
						Filedata.push_back(temporaryData);
					}
				}
				break;
			}
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				index = taskStatusData._Status_FileBiockSize % 65;
				if (index != 0)
				{
					std::runtime_error corruption_occurs_data_by_decrypted("Corruption occurs after by data decryption !");
					throw corruption_occurs_data_by_decrypted;
				}
				break;
			}
			default:
			{
				std::cout << "Wrong worker is selected" << std::endl;
				abort();
				break;
			}
		}

		if (_ChoiseWorker == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
		{
			Cryptograph::Implementation::Encrypter custom_encrypter;
			custom_encrypter.Main(Filedata, taskStatusData._Status_Key);
		}
		else if (_ChoiseWorker == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
		{
			Cryptograph::Implementation::Decrypter custom_decrypter;
			custom_decrypter.Main(Filedata, taskStatusData._Status_Key);
		}
		else
		{
			std::cout << "Wrong worker is selected" << std::endl;
			abort();
		}

		--(this->ThreadCount);
		return Filedata;
	}

}  // namespace CrypticDataThreadingWrapper