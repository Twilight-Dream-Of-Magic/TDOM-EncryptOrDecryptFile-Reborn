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

#if __cplusplus >= 202002L

#include "../../ThreadSafeQueue.hpp"

namespace ThreadingToolkit::Pool::Version1
{
	class ThreadPool final
	{

	private:

		class ThreadWorker
		{

		private:

			std::size_t _worker_id;
			ThreadPool* _pool_pointer;

		public:

			ThreadWorker(ThreadPool *pool_pointer, const std::size_t worker_id)
				: _pool_pointer(pool_pointer), _worker_id(worker_id)
			{
			}

			void operator()()
			{
				while (_pool_pointer->_pool_is_working)
				{
					{
						auto unique_locker { std::unique_lock( _pool_pointer->_conditional_mutex ) };

						while (_pool_pointer->_thread_safe_queue.empty() && _pool_pointer->_pool_is_working)
						{
						
							if (_pool_pointer->_wait_exit_thread_number > 0)
							{
								_pool_pointer->_wait_exit_thread_number--;

								if (_pool_pointer->_live_thread_number.load() > _pool_pointer->_minimum_thread_number)
								{
									_pool_pointer->_live_thread_number--;
									return;
								}
							}
							else
							{
								_pool_pointer->_conditional.wait(unique_locker);
							}
						}
					}

					// Dequeue generic wrapper function
					auto removed_queue_item = _pool_pointer->_thread_safe_queue.try_pop();

					if (removed_queue_item.has_value())
					{
						_pool_pointer->_busy_thread_number++;
						std::function<void()> worker_function { std::move( removed_queue_item.value() ) };
						worker_function();
						_pool_pointer->_busy_thread_number--;
					}
				}
			}
		};

		const std::size_t _need_wait_task_number = 10;
		const std::size_t _default_thread_vary_number = 10;

		// Minimum number of threads
		std::size_t _minimum_thread_number;
		// Maximum number of threads
		std::size_t _maximum_thread_number;

		std::atomic<std::size_t> _live_thread_number;
		std::size_t _wait_exit_thread_number;
		std::atomic<std::size_t> _busy_thread_number;
		bool _pool_is_working = false;
		ThreadSafeQueue<std::function<void()>, std::mutex> _thread_safe_queue;
		std::vector<std::thread> _thread_objects;
		std::mutex _conditional_mutex;
		std::condition_variable _conditional;
		std::thread _adjust_thread;

		void adjust_thread(void)
		{
			while (this->_pool_is_working)
			{
				std::this_thread::sleep_for(std::chrono::seconds(5));
				std::unique_lock<std::mutex> unique_locker(_conditional_mutex, std::defer_lock);
				unique_locker.lock();
				std::size_t queue_size = _thread_safe_queue.size();
				std::size_t _current_live_thread_number = this->_live_thread_number.load();
				unique_locker.unlock();
				std::size_t _current_busy_thread_number = this->_busy_thread_number.load();

				if(queue_size >= _need_wait_task_number && _current_live_thread_number < _maximum_thread_number)
				{
					unique_locker.lock();
					std::size_t loop_counter = 0;
					for
					(
						std::size_t index = 0;
						index < _maximum_thread_number && loop_counter < _default_thread_vary_number && _current_live_thread_number < _maximum_thread_number;
						++index
					)
					{
						if(_thread_objects[index].get_id() == std::thread::id())
						{
							_thread_objects[index] = std::thread( ThreadWorker( this, index ) );
							loop_counter++;
							this->_live_thread_number++;
						}
					}
					unique_locker.unlock();
				}

				if((_busy_thread_number * 2) < _current_live_thread_number && _current_live_thread_number > _minimum_thread_number)
				{
					unique_locker.lock();
					_wait_exit_thread_number = _default_thread_vary_number;
					unique_locker.unlock();
					_conditional.notify_all();
				}
			}
		}

		public:
			
		ThreadPool(const std::size_t minimum_thread_number, const std::size_t maximum_thread_number)
			: _minimum_thread_number(minimum_thread_number), _maximum_thread_number(maximum_thread_number),
				_live_thread_number(minimum_thread_number),
				_thread_objects(std::vector<std::thread>(maximum_thread_number)), _pool_is_working(true),
				_wait_exit_thread_number(0)
		{
			if(_maximum_thread_number > std::thread::hardware_concurrency())
			{
				_maximum_thread_number = maximum_thread_number / 4;
			}
			else
			{
				_maximum_thread_number = maximum_thread_number / 2;
			}

		}

		~ThreadPool() = default;

		ThreadPool(const ThreadPool& _object) = delete;
		ThreadPool(ThreadPool&& _object) = delete;

		ThreadPool& operator=(const ThreadPool& _object) = delete;
		ThreadPool& operator=(ThreadPool&& _object) = delete;

		// Initialize the thread pool and prepare threads without tasks
		bool initialize()
		{
			if(_minimum_thread_number == 0)
			{
				return false;
			}
			else
			{
				for (std::size_t index = 0; index < _minimum_thread_number; ++index)
				{
					_thread_objects[index] = std::thread( ThreadWorker( this, index ) );
				}
				_adjust_thread = std::move( std::thread( &ThreadPool::adjust_thread, this ) );

				return true;
			}
		}

		// Wait until the thread finishes its current task and stops the thread pool.
		void finished()
		{
			_pool_is_working = false;
			if (_adjust_thread.joinable())
			{
				_adjust_thread.join();
			}

			_conditional.notify_all();

			for (std::size_t index = 0; index < _thread_objects.size(); ++index)
			{
				if (_thread_objects[index].joinable())
				{
					_thread_objects[index].join();
				}
			}
		}

		// Submit a function, then wrap that function as a task and have the thread pool start asynchronous execution.
		template<typename FunctionType, typename... FunctionTypeArgs> requires std::invocable<FunctionType, FunctionTypeArgs...>
		auto submit(FunctionType&& function, FunctionTypeArgs&&... function_args) -> std::future<decltype( function(function_args...) )>
		{
			// Create a function with bounded parameters ready to execute
			std::function<decltype( function(function_args...) )()> functional_object = std::bind( std::forward<FunctionType>( function ), std::forward<FunctionTypeArgs>( function_args )... );

			// First, the function object is encapsulated first time as a std::packed_task, and then encapsulated a second time as a std::shared_ptr to be copyable for constructive/assignment.
			auto function_task_pointer = std::make_shared<std::packaged_task<decltype( function(function_args...) )()>>(functional_object);

			// Encapsulate std::packed_task, for the third time, into a function that returns an (void type)
			std::function<void()> wrapper_functional_object = [function_task_pointer]()
			{
				(*function_task_pointer)();
			};

			// Enqueue generic wrapper function
			_thread_safe_queue.push(wrapper_functional_object);

			// Wake up one thread if its waiting
			_conditional.notify_one();

			// Return future from promise
			return function_task_pointer->get_future();
		}
	};
}

#endif
