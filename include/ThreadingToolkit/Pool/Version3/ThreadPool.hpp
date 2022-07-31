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

//https://gist.github.com/MichaEiler/99c3ed529d4fd19c4289fd04672a1a7c

namespace ThreadingToolkit::Pool::Version3
{
    class ThreadPool;

	namespace Implementation
	{
        class fire_once_event;

        class fire_once_event
        {

        public:
            void set()
            {
                std::cout << "" << std::endl;
                _flag.test_and_set();
                _flag.notify_all();
                std::cout << "" << std::endl;
            }

            bool test()
            {
                return _flag.test();
            }

            void wait()
            {
                std::cout << "" << std::endl;
                _flag.wait(false);
                std::cout << "" << std::endl;
            }

        private:
            std::atomic_flag _flag;

        };

        struct task_promise;

        class [[nodiscard]] task;

        struct task_promise
        {
            struct final_awaitable
            {
                bool await_ready() const noexcept { return false; }

                std::coroutine_handle<> await_suspend(std::coroutine_handle<task_promise> awaitable_coroutine) noexcept
                {
                    return awaitable_coroutine.promise()._task_promise_coroutine_handle;
                }

                void await_resume() noexcept {}
            };

            task get_return_object() noexcept;
            std::suspend_always initial_suspend() const noexcept { return {}; }
            auto final_suspend() const noexcept { return final_awaitable(); }
            void return_void() noexcept {}
            void unhandled_exception() noexcept { exit(1); }

            void set_continuation(std::coroutine_handle<> continuation) noexcept
            {
                _task_promise_coroutine_handle = continuation;
            }

        private:
            std::coroutine_handle<> _task_promise_coroutine_handle = std::noop_coroutine();
        };

        class [[nodiscard]] task
        {
        public:
            using promise_type = task_promise;

            explicit task(std::coroutine_handle<task_promise> handle)
                : _task_coroutine_handle(handle)
            {
            }

            ~task()
            {
                if (_task_coroutine_handle)
                {
                    _task_coroutine_handle.destroy();
                }
            }

            auto operator co_await() noexcept
            {
                struct awaiter
                {
                    bool await_ready() const noexcept 
                    {
                        return !_awaiter_coroutine_handle || _awaiter_coroutine_handle.done();
                    }

                    std::coroutine_handle<> await_suspend( std::coroutine_handle<> awaiting_coroutine) noexcept
                    {
                        _awaiter_coroutine_handle.promise().set_continuation( awaiting_coroutine );
                        return _awaiter_coroutine_handle;
                    }

                    void await_resume() noexcept {}

                    std::coroutine_handle<task_promise> _awaiter_coroutine_handle;
                };
                return awaiter { _task_coroutine_handle };
            }

        private:
            std::coroutine_handle<task_promise> _task_coroutine_handle;
        };

        struct sync_wait_task_promise;

        class [[nodiscard]] sync_wait_task;

        class [[nodiscard]] sync_wait_task
        {

        public:
            using promise_type = sync_wait_task_promise;

            sync_wait_task(std::coroutine_handle<sync_wait_task_promise> coroutine_handle)
                : _coroutine_handle(coroutine_handle)
            {
            }

            ~sync_wait_task()
            {
                if (_coroutine_handle)
                {
                    _coroutine_handle.destroy();
                }
            }

            void run(fire_once_event& event);

        private:
            std::coroutine_handle<sync_wait_task_promise> _coroutine_handle;

        };

        struct sync_wait_task_promise
        {
            std::suspend_always initial_suspend() const noexcept { return {}; }

            auto final_suspend() const noexcept
            {
                struct awaiter
                {
                    bool await_ready() const noexcept { return false; }

                    void await_suspend(std::coroutine_handle<sync_wait_task_promise> coroutine_handle) const noexcept
                    {
                        fire_once_event* const pointer_once_event = coroutine_handle.promise()._once_event;
                        if (pointer_once_event)
                        {
                            pointer_once_event->set();
                        }
                    }

                    void await_resume() noexcept {}
                };
                return awaiter();
            }

            fire_once_event* _once_event = nullptr;

            sync_wait_task get_return_object() noexcept;

            void return_void() noexcept {}
            void unhandled_exception() noexcept { exit(1); }
        };

        inline task task_promise::get_return_object() noexcept
        {
            return task { std::coroutine_handle<task_promise>::from_promise(*this) };
        }

        inline sync_wait_task sync_wait_task_promise::get_return_object() noexcept
        {
            return sync_wait_task { std::coroutine_handle<sync_wait_task_promise>::from_promise(*this) };
        }

        inline void sync_wait_task::run(fire_once_event& event)
        {
            _coroutine_handle.promise()._once_event = &event;
            _coroutine_handle.resume();
        }

        inline sync_wait_task make_sync_wait_task(task& task_object)
        {
            co_await task_object;
        }

        inline void sync_wait(task& task_object, fire_once_event& once_event)
        {
            auto wait_task = make_sync_wait_task(task_object);
            wait_task.run(once_event);
            once_event.wait();
        }
	}

    class ThreadPool
    {

    public:
        explicit ThreadPool(const std::size_t thread_number)
        {
            std::size_t _thread_number = thread_number;

			if(_thread_number > std::thread::hardware_concurrency())
			{
				_thread_number = thread_number / 4;
			}
			else
			{
				_thread_number = thread_number / 2;
			}

            if(_list_threads.size() == 0)
            {
                launch(_thread_number);
            }
        }

        ~ThreadPool()
        {
            if(_do_stop_thread == false)
            {
                shutdown();
            }
        }

        void launch(const std::size_t thread_number)
        {
            for (std::size_t index = 0; index < thread_number; ++index)
            {
                std::jthread worker_thread
                (
                    [this]() 
                    {
                        this->thread_loop();
                    }
                
                );
                _list_threads.push_back( std::move( worker_thread ) );
            }
        }

        //C++ 2020 coroutine_handle awaitable expression
        auto schedule()
        {
            struct awaiter
            {
                ThreadPool* _pointer_thread_pool;

                constexpr bool await_ready() const noexcept { return false; }
                constexpr void await_resume() const noexcept { }
                void await_suspend(std::coroutine_handle<> coroutine_handle) const noexcept
                {
                    _pointer_thread_pool->submit_task(coroutine_handle);
                }
            };
            return awaiter{this};
        }

    private:
        std::list<std::jthread> _list_threads;

        std::mutex _condition_mutex;
        std::condition_variable _conditional_variable;
        std::deque<std::coroutine_handle<>> _deque_coroutine_handles;

        bool _do_stop_thread = false;

        void thread_loop()
        {
            using namespace Implementation;

            while (!_do_stop_thread)
            {
                std::unique_lock<std::mutex> lock(_condition_mutex);

                while (!_do_stop_thread && _deque_coroutine_handles.size() == 0)
                {
                    _conditional_variable.wait_for(lock, std::chrono::microseconds(100));
                }

                if (_do_stop_thread)
                {
                    break;
                }

                auto& current_coroutine_handle = _deque_coroutine_handles.front();
                _deque_coroutine_handles.pop_front();
                current_coroutine_handle.resume();
            }
        }

        void submit_task(std::coroutine_handle<> coroutine_handle) noexcept
        {
            std::unique_lock<std::mutex> lock(_condition_mutex);
            _deque_coroutine_handles.push_back(coroutine_handle);
            _conditional_variable.notify_one();
        }

        void shutdown()
        {
            _do_stop_thread = true;
            while (_list_threads.size() > 0)
            {
                std::jthread& worker_thread = _list_threads.back();
                if (worker_thread.joinable())
                {
                    worker_thread.join();
                }
                _list_threads.pop_front();
            }
        }
    };

    /*

    //Example code

    task run_async_print(ThreadPool& pool, fire_once_event& once_event)
    {
        co_await pool.schedule();
        std::cout << "This is a hello from thread: " << std::this_thread::get_id() << "\n";
        once_event.set();
    }

    int main()
    {
        fire_once_event once_event;
        std::cout << "The main thread id is: " << std::this_thread::get_id() << "\n";
        ThreadPool pool{8};
        task task_object = run_async_print(pool);
        Implementation::sync_wait(task_object, once_event);
    }

    */
}

#endif
