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

namespace CrypticDataThreadingWrapper::Implementation
{
	#ifndef EODF_PROJECT_DEPRECATED_EXPERIMENTAL_CODEBLOCK_IMPLEMENTATION
	
	namespace SharedDataSpace
	{
		struct SharedData
		{
			// 文件数据处理之前，需要转换为std::byte类型，然后给线程池push数据进行(加密或者解密)处理
			// The file data needs to be converted to std::byte type before processing, and then give the thread pool push data to be processed (encrypted or decrypted)
			std::deque<std::vector<std::byte>> FileDataBytes;

			// 线程池launchTask之前，需要提供std::byte类型数据的密码流
			// Before the thread pool launchTask, you need to provide a cipher stream of std::byte type data
			std::deque<std::vector<std::byte>> PasswordData;

			// 文件数据处理之后，由线程池不断push
			// After the file data is processed, it is continuously pushed by the thread pool
			std::deque<std::vector<std::byte>> ProcessedData;

			SharedData() = default;
			~SharedData() = default;

			SharedData( SharedData&& _object ) : FileDataBytes( _object.FileDataBytes ), PasswordData( _object.PasswordData ), ProcessedData( _object.ProcessedData ) {}

			SharedData( SharedData& _object )
			{
				SharedData( std::move( _object ) );
			}

			SharedData operator=( SharedData& _object )
			{
				auto _moved_object = SharedData( std::move( _object ) );
				return _moved_object;
			}
		};

		struct ThreadStatus
		{
			//SharedData::FileDataBytes是否还有数据输入
			//调用void ThreadTasksManager::setFileDataTransferred()之后，设置ThreadStatus::FileDataTransferred为true，表示没有文件输入
			std::atomic<bool> FileDataTransferred = false;

			std::atomic<bool> AllTaskIsDone = false;

			// 正在进行的线程任务数量
			// Number of ongoing threaded tasks
			std::atomic<int> ThreadedTaskCount = 0;
		};

		ThreadStatus thread_status;
	}  // namespace SharedDataSpace

	class ThreadedTask
	{
	public:
		std::vector<std::byte> getResult()
		{
			return temporaryResult.get();
		}

		ThreadedTask( Cryptograph::CommonModule::CryptionMode2MCAC4_FDW choise, std::vector<std::byte>& filedata, std::vector<std::byte>& password_data ) : file_data( filedata ), password_data( password_data )
		{
			switch ( choise )
			{
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
				taskFunction = std::bind( &ThreadedTask::EncrypterTask, std::ref( *this ) );
				break;
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
				taskFunction = std::bind( &ThreadedTask::DecrypterTask, std::ref( *this ) );
				break;
			}
		}

		~ThreadedTask() = default;
		void runTask();

	private:
		std::vector<std::byte>&					 EncrypterTask();
		std::vector<std::byte>&					 DecrypterTask();
		std::vector<std::byte>					 file_data;
		std::vector<std::byte>					 password_data;
		std::future<std::vector<std::byte>&>	 temporaryResult;
		std::function<std::vector<std::byte>&()> taskFunction;
	};

	std::vector<std::byte>& ThreadedTask::EncrypterTask()
	{
		Cryptograph::Implementation::Encrypter Worker;
		std::vector<std::byte>&				   data = Worker.Main( file_data, password_data );
		SharedDataSpace::thread_status.ThreadedTaskCount--;
		return data;
	}

	std::vector<std::byte>& ThreadedTask::DecrypterTask()
	{
		Cryptograph::Implementation::Decrypter Worker;
		std::vector<std::byte>&				   data = Worker.Main( file_data, password_data );
		SharedDataSpace::thread_status.ThreadedTaskCount--;
		return data;
	}

	void ThreadedTask::runTask()
	{
		SharedDataSpace::thread_status.ThreadedTaskCount++;
		temporaryResult = std::async( std::launch::async, std::ref( taskFunction ) );
	}
	
	#endif

}  // namespace CrypticDataThreadingWrapper::Implementation

namespace CrypticDataThreadingWrapper
{
	using namespace CrypticDataThreadingWrapper::Implementation;
	
	#ifndef EODF_PROJECT_DEPRECATED_EXPERIMENTAL_CODEBLOCK_IMPLEMENTATION
	
	class ThreadTasksManager
	{

	private:
		std::queue<Implementation::ThreadedTask*> TaskQueue;
		std::queue<Implementation::ThreadedTask*> WaitQueue;
		std::atomic_bool						  wait_done = false;
		int										  Task_Max_Size = 16;
		std::thread								  WaitThread;
		std::thread								  TaskThread;

		void DoWaitingData( Cryptograph::CommonModule::CryptionMode2MCAC4_FDW choise , SharedDataSpace::SharedData& SharedDataObject );
		void DoExecutingTask( SharedDataSpace::SharedData& SharedDataObject );

	public:
		// 选择线程池的工作任务
		// Selecting tasks for the thread pool
		void launchTask( Cryptograph::CommonModule::CryptionMode2MCAC4_FDW choise , SharedDataSpace::SharedData& SharedDataObject );

		// 设置线程池的最大任务数量
		// Set the maximum number of tasks for the thread pool
		void setTaskMaxCount( int num );

		// 设置文件数据传输完成，线程池可以开始工作
		// Set the file data transfer to complete and the thread pool can currently to working
		void setFileDataTransferred();

		// 设置文件数据传输需要继续传输，线程池当前不可以开始工作，而且需要等待文件传输完成
		// Set the file data transfer to continue, the thread pool cannot currently to working, and it needs to wait for the file transfer to complete
		void resetFileDataTransferred();

		// 阻塞当前线程，让全部任务在前台等待
		// Block the current thread and let all tasks wait in the foreground
		void TasksDoJoin();

		// 分离当前线程，让全部任务在后台进行
		// Detach the current thread and let all tasks take place in the background
		void TasksDoDetach();

		// 获取线程池运行状态
		// Get the thread pool running status
		bool getAllTaskStatus();

		// 获取线程池正在运行的任务数量
		// Get the number of running tasks in the thread pool
		int getThreadTaskCount();

		ThreadTasksManager() = default;
		~ThreadTasksManager() = default;
	};

	void ThreadTasksManager::DoWaitingData( Cryptograph::CommonModule::CryptionMode2MCAC4_FDW choise, SharedDataSpace::SharedData& SharedDataObject )
	{
		//std::cout << std::this_thread::get_id() << std::endl;

		auto passwordDataIterator = SharedDataObject.PasswordData.begin();

		//std::cout << "wait data begin" << std::endl;

		while ( ( !SharedDataSpace::thread_status.FileDataTransferred.load() ) || ( !SharedDataObject.FileDataBytes.empty() ) )
		{
			if ( !SharedDataObject.FileDataBytes.empty() )
			{
				WaitQueue.push( new ThreadedTask( choise, SharedDataObject.FileDataBytes.front(), *passwordDataIterator ) );
				SharedDataObject.FileDataBytes.pop_front();
				passwordDataIterator++;
				if ( passwordDataIterator == SharedDataObject.PasswordData.end() )
				{
					passwordDataIterator = SharedDataObject.PasswordData.begin();
				}
				//std::cout << "waiting data" << std::endl;
			}
		}
		wait_done = true;
		//std::cout << "wait data end" << std::endl;
	}

	void ThreadTasksManager::DoExecutingTask(SharedDataSpace::SharedData& SharedDataObject)
	{
		//std::cout << std::this_thread::get_id() << std::endl;
		while ( ( !SharedDataSpace::thread_status.FileDataTransferred ) || ( !WaitQueue.empty() ) || ( !wait_done ) )
		{
			if ( SharedDataSpace::thread_status.ThreadedTaskCount.load() < Task_Max_Size )
			{
				if ( !WaitQueue.empty() )
				{
					WaitQueue.front()->runTask();
					TaskQueue.push( WaitQueue.front() );
					WaitQueue.pop();
					//std::cout << "wait pop" << std::endl;
					//std::cout << "task push" << std::endl;
				}
			}

			if ( TaskQueue.size() > Task_Max_Size )
			{
				SharedDataObject.ProcessedData.push_back( TaskQueue.front()->getResult() );
				delete TaskQueue.front();
				TaskQueue.pop();
				//std::cout << "task pop" << std::endl;
			}
		}

		while ( !TaskQueue.empty() )
		{
			SharedDataObject.ProcessedData.push_back( TaskQueue.front()->getResult() );
			delete TaskQueue.front();
			TaskQueue.pop();
			//std::cout << "task pop" << std::endl;
		}
		//std::cout << "task done" << std::endl;
		SharedDataSpace::thread_status.AllTaskIsDone = true;
	}

	void ThreadTasksManager::launchTask( Cryptograph::CommonModule::CryptionMode2MCAC4_FDW choise , SharedDataSpace::SharedData& SharedDataObject)
	{
		WaitThread = std::thread( &ThreadTasksManager::DoWaitingData, std::ref( *this ), choise, std::ref(SharedDataObject) );
		TaskThread = std::thread( &ThreadTasksManager::DoExecutingTask, std::ref( *this ), std::ref(SharedDataObject) );
	}

	void CrypticDataThreadingWrapper::ThreadTasksManager::setTaskMaxCount( int num )
	{
		Task_Max_Size = num;
	}

	void CrypticDataThreadingWrapper::ThreadTasksManager::setFileDataTransferred()
	{
		SharedDataSpace::thread_status.FileDataTransferred.store( true );
	}

	void CrypticDataThreadingWrapper::ThreadTasksManager::resetFileDataTransferred()
	{
		SharedDataSpace::thread_status.FileDataTransferred.store( false );
	}

	void CrypticDataThreadingWrapper::ThreadTasksManager::TasksDoJoin()
	{
		WaitThread.join();
		TaskThread.join();
		SharedDataSpace::thread_status.AllTaskIsDone.store( true );
	}

	void CrypticDataThreadingWrapper::ThreadTasksManager::TasksDoDetach()
	{
		if ( WaitThread.joinable() )
		{
			WaitThread.detach();
		}
		if ( TaskThread.joinable() )
		{
			TaskThread.detach();
		}

		while ( true )
		{
			bool taskStatus = this->getAllTaskStatus();
			if ( taskStatus )
			{
				break;
			}
		}
	}

	bool CrypticDataThreadingWrapper::ThreadTasksManager::getAllTaskStatus()
	{
		return SharedDataSpace::thread_status.AllTaskIsDone.load();
	}

	int CrypticDataThreadingWrapper::ThreadTasksManager::getThreadTaskCount()
	{
		return SharedDataSpace::thread_status.ThreadedTaskCount.load();
	}
	
	#endif
	
}  // namespace CrypticDataThreadingWrapper
