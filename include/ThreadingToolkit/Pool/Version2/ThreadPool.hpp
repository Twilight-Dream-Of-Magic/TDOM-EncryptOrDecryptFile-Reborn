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

namespace ThreadingToolkit::Pool::Version2
{
	template <typename Type>
	struct my_future_type : std::future<Type>
	{
		struct promise_type : std::promise<Type>
		{
			std::future<Type> get_return_object() { return this->get_future(); }
			std::suspend_never initial_suspend() { return {}; }
			std::suspend_never final_suspend() noexcept { return {}; }
			void return_void() {}
			void unhandled_exception() {}
		};

		// Construct future object may after destruction of promise_type
		// So get furure before this time point
		my_future_type(std::future<Type>&& future_task_object): std::future<Type>(std::move(future_task_object)) {}

	#ifdef _MSC_VER
		my_future_type() = default;
	#endif
	};

	class ThreadPool
	{

	public:

		//Singleton
		static ThreadPool& get_instance(std::size_t thread_number)
		{
			static ThreadPool pool_object { thread_number };
			return pool_object;
		}

		void submit_coroutine(std::coroutine_handle<> coroutine_handle)
		{
			_thread_safe_queue_coroutine_handle.push(coroutine_handle);
		}

		template <typename Type>
		struct my_awaitable
		{
			using PromiseType = my_future_type<Type>::promise_type;
			bool await_ready()
			{ 
				return false; 
			}
			void await_suspend(std::coroutine_handle<PromiseType> coroutine_handle)
			{
				_coroutine_handle = coroutine_handle;
				ThreadPool::get_instance(0).submit_coroutine(coroutine_handle);
			}
			std::coroutine_handle<PromiseType> await_resume() {return _coroutine_handle;}
        
			std::coroutine_handle<PromiseType> _coroutine_handle = nullptr;
		};

		template <std::invocable CallableFunctionType>
		my_future_type<std::invoke_result_t<CallableFunctionType>> submit(CallableFunctionType taskFunction)
		{
			using ResultType = std::invoke_result_t<CallableFunctionType>;
			using PromiseType = my_future_type<ResultType>::promise_type;
			std::coroutine_handle<PromiseType> have_result_coroutine_handle = co_await my_awaitable<ResultType>();

			if constexpr (std::is_void_v<ResultType>)
			{
				taskFunction();
			}
			else
			{
				have_result_coroutine_handle.promise().set_value(taskFunction());
			}
		}

	private:

		void worker()
		{
			while (auto task = _thread_safe_queue_coroutine_handle.pull())
			{
				task.value().resume();
			}
		}

		ThreadPool(std::size_t thread_number)
		{
            for (int index = 0; index < thread_number; ++index)
            {
                _joinable_thread_objects.emplace
				(
					_joinable_thread_objects.end(),
					std::jthread
					(
						[this]
						{
							this->worker();
						}
					)
				);
            }
		}

		~ThreadPool()
		{
			recycle_queue(_thread_safe_queue_coroutine_handle);
		}

		SimpleThreadSafeQueue<std::coroutine_handle<>> _thread_safe_queue_coroutine_handle;
		std::deque<std::jthread> _joinable_thread_objects;

		void recycle_queue(SimpleThreadSafeQueue<std::coroutine_handle<>>& thread_safe_queue)
		{
			auto& queue = thread_safe_queue.recycle();
			while (!_joinable_thread_objects.empty())
			{
				_joinable_thread_objects.pop_front();
			}

			// Add threads are shutdowned here

			while (!queue.empty())
			{
				queue.front().destroy();
				queue.pop_front();
			}
		}

	};
}

#endif