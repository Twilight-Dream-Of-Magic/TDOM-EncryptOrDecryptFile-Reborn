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

namespace ThreadingToolkit::Wrapper
{
	template<typename FunctionType, typename... FunctionTypeArgs> requires std::invocable<FunctionType, FunctionTypeArgs...>
	auto AsyncTask_SyncWrapper(FunctionType&& function, FunctionTypeArgs&&... functionArgs)
	{
		using ReturnType = std::invoke_result_t<FunctionType, FunctionTypeArgs...>;
		std::future<decltype( function(functionArgs...) )> futureTask = std::async(function, std::forward<FunctionTypeArgs>( functionArgs )...);

		try
		{
			if(futureTask.wait_for(std::chrono::milliseconds(0)) == std::future_status::deferred)
			{
				std::cout << "This task function works in synchronous mode" << std::endl;
				std::cout << "Executing synchronization tasks !" << std::endl;
				if constexpr(std::is_same_v<ReturnType, void>)
				{
					futureTask.get();
					std::cout << "Executed synchronization tasks." << std::endl;
					return;
				}
				else
				{
					auto task_return_value = futureTask.get();
					std::cout << "Executed synchronization tasks." << std::endl;
					return task_return_value;
				}
			}
			else
			{
				std::future_status futureTaskStatus = std::future_status::deferred;

				auto waitTask_asyncFunction = [&]() -> void {

					futureTaskStatus = futureTask.wait_for(std::chrono::milliseconds(0));

					std::cout << '.';
					std::cout.flush();
				};

				std::cout << "This task function works in asynchronous mode" << std::endl;
				std::cout << "Asynchronous tasks are waiting !" << std::endl;

				ThreadingToolkit::Timed::ExecutorWithThread timedTask_asyncFunction(waitTask_asyncFunction);
				timedTask_asyncFunction.startTimer(10000);

				while (futureTaskStatus != std::future_status::ready)
				{
					if(futureTaskStatus == std::future_status::ready)
					{
						timedTask_asyncFunction.stopTimer();
						break;
					}
					else if(futureTaskStatus == std::future_status::deferred)
					{
						timedTask_asyncFunction.stopTimer();
						break;
					}
				}

				if constexpr(std::is_same_v<ReturnType, void>)
				{
					futureTask.get();
					std::cout << "Asynchronous tasks(Return type is void) have been completed" << std::endl;
					return;
				}
				else
				{
					std::cout << "Asynchronous tasks(Return type is value) have been completed" << std::endl;
					return futureTask.get();
				}
			}
		}
		catch ( const std::exception& except )
		{
			std::cerr << "[Error] The exception message to execution of the task is: " << except.what() << std::endl;
		}
	}
}

#endif