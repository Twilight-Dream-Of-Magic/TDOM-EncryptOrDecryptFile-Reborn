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

namespace ThreadingToolkit::Timed
{
    class ExecutorWithThread final
    {
        
    public:

        void setTimerTask(const std::function<void()>& task)
        {
            if(_thread_object.get_id() == std::this_thread::get_id())
            {
                throw std::runtime_error("ExecutorWithThread setTimerTask() Error: You can't do this in the main thread, and you need to recreate the thread object after you stop the task's timer!");
            }
            else if (!_is_running.load())
            {
                throw std::runtime_error("ExecutorWithThread setTimerTask() Error: The timer for the task function is running. You need to stop the timer and restart the timer.");
            }
            _function_object.operator=(std::move(task));
        }

        void startTimer(long long ms)
        {
            if(_thread_object.get_id() == std::this_thread::get_id())
            {
                throw std::runtime_error("ExecutorWithThread startTimer() Error: You can't do this in the main thread, and you need to recreate the thread object after you stop the task's timer!");
            }
            else if(_function_object == nullptr)
            {
                throw std::runtime_error("ExecutorWithThread startTimer() Error: Task functions must not be null.");
            }
            else if(_is_running.load())
            {
                throw std::runtime_error("ExecutorWithThread startTimer() Error: The timer for the task function is running. You need to stop the timer and restart the timer.");
            }

            _is_running.store(true);
            _thread_object = std::thread
            (
                [this, ms]() 
                {
                    while (_is_running)
                    {
                        {
                            std::unique_lock locker(_conditional_mutex);
                            _conditional_timer.wait_for
                            (
                                locker, 
                                std::chrono::milliseconds(ms),
                                [this]
                                { 
                                    return !_is_running; 
                                }
                            );
                        }

                        if (!_is_running)
                        {
                            return;
                        }

                        _function_object();
                    }
                }
            ); 
        }

        void stopTimer()
        {
            if(_thread_object.get_id() == std::this_thread::get_id())
            {
                throw std::runtime_error("ExecutorWithThread stopTimer() Error: You can't do this in the main thread, and you need to recreate the thread object after you stop the task's timer!");
            }

            _is_running.store(false);
            _conditional_timer.notify_one();
            if (_thread_object.joinable())
            {
                _thread_object.join();
            }
        }

        bool isRunning() const
        {
            return _is_running;
        }

        ExecutorWithThread(const ExecutorWithThread&) = delete;
        ExecutorWithThread(ExecutorWithThread&&) = delete;
        ExecutorWithThread& operator=(const ExecutorWithThread&) = delete;
        ExecutorWithThread& operator=(ExecutorWithThread&&) = delete;

        ExecutorWithThread()
            : _function_object(),
            _is_running(false),
            _conditional_mutex(),
            _conditional_timer(),
            _thread_object() 
        {
        }

        explicit ExecutorWithThread(const std::function<void()>& task)
            : _function_object(task),
            _is_running(false),
            _conditional_mutex(),
            _conditional_timer(),
            _thread_object() 
        {
        }

        ~ExecutorWithThread()
        {
            stopTimer();
        }

    private:

        std::function<void()> _function_object;
        std::atomic<bool> _is_running;
        std::mutex _conditional_mutex;
        std::condition_variable _conditional_timer;
        std::thread _thread_object;

    };

    class ExecutorWithThread2 final
    {

      public:
        ExecutorWithThread2() : _is_expired(true), _is_try_to_expire(false)
        {
        }

        ExecutorWithThread2(const ExecutorWithThread2&  other)
        {
            _is_expired.store(other._is_expired.load());
            _is_try_to_expire.store(other._is_try_to_expire.load());
        }
        ~ExecutorWithThread2()
        {
            DoExpireTask();
            // std::cout << "timer destructed!" << std::endl;
        }

        void DoUnexpiredTask(int interval, std::function<void()> task)
        {
            if (_is_expired == false)
            {
                // std::cout << "timer is currently running, please expire it first..." << std::endl;
                return;
            }
            _is_expired.store(false);
            std::thread
            (
                [this, interval, task]()
                {
                    // std::cout << "ExecutorWithThread: start task..." << std::endl;
                    while (!_is_try_to_expire.load())
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(interval));
                        task();
                    }
                    // std::cout << "ExecutorWithThread: stop task..." << std::endl;
                    {
                        std::lock_guard<std::mutex> locker(mutex_);
                        _is_expired.store(true);
                        _expired_conditional.notify_one();
                    }
                }
            ).detach();
        }

        void DoExpireTask()
        {
            if (_is_expired.load())
            {
                return;
            }

            if (_is_try_to_expire.load())
            {
                // std::cout << "timer is trying to expire, please wait..." << std::endl;
                return;
            }
            _is_try_to_expire.store(true);
            {
                std::unique_lock<std::mutex> locker(mutex_);
                _expired_conditional.wait(locker, [this] { return _is_expired == true; });
                if (_is_expired == true)
                {
                    // std::cout << "timer expired!" << std::endl;
                    _is_try_to_expire.store(false);
                }
            }
        }

        template <typename CallableType, class... CallableArgumentTypes>
        void SyncWait(int after, CallableType &&function, CallableArgumentTypes &&... function_args)
        {
            std::function<typename std::invoke_result<CallableType(CallableArgumentTypes...)>::type()> task;
            task = std::bind(std::forward<CallableType>(function), std::forward<CallableArgumentTypes>(function_args)...);
            std::this_thread::sleep_for(std::chrono::milliseconds(after));
            task();
        }
        template <typename CallableType, class... CallableArgumentTypes>
        void AsyncWait(int after, CallableType &&function, CallableArgumentTypes &&... function_args)
        {
            std::function<typename std::invoke_result<CallableType(CallableArgumentTypes...)>::type()> task;
            task = std::bind(std::forward<CallableType>(function), std::forward<CallableArgumentTypes>(function_args)...);

            std::thread
            (
                [after, task]() 
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(after));
                    task();
                }
            ).detach();
        }

      private:
        std::atomic<bool> _is_expired;
        std::atomic<bool> _is_try_to_expire;
        std::mutex mutex_;
        std::condition_variable _expired_conditional;
    };

} // namespace ThreadingToolkit::Timed
