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

#ifndef SUPPORT_LINRARY_HPP
#define SUPPORT_LINRARY_HPP

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <string_view>

#include <typeinfo>
#include <type_traits>

#include <algorithm>
#include <iomanip>
#include <utility>
#include <stdexcept>
#include <chrono>
#include <limits>
#include <bitset>
#include <random>
#include <codecvt>
#include <new>
#include <memory>

#if __cplusplus >= 201703L

#include <charconv>
#include <optional>
#include <filesystem>
#include <span>
#include <numeric>

#endif

#if __cplusplus >= 202002L

#include <bit>
#include <ranges>
#include <coroutine>
#include <source_location>
#include <numbers>

#endif

#include <iterator>
#include <array>
#include <vector>
#include <list>
#include <stack>
#include <queue>
#include <deque>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>

//Multi-Threading-Devlopment-ISO-C++ Standard Libary
#include <atomic>
#include <thread>
#include <mutex>
#include <future>
#include <functional>
#include <condition_variable>

#if __cplusplus >= 201703L

#include <shared_mutex>

#endif

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <ctime>

#define NAMESPACE_BEGIN( This_Name ) namespace This_Name {
#define NAMESPACE_END }

#if defined(USE_MEMORY_TRACKER_CODE)

namespace MemoryTrackMap
{
    using AllocationMapType = std::unordered_map<void*, std::size_t>;

    static AllocationMapType MemoryAllocationMapStandard;
    static AllocationMapType MemoryAllocationMapArray;
}

class MemoryTrackUsageInfo
{

public:

    static MemoryTrackUsageInfo& get_instance()
    {
        static MemoryTrackUsageInfo instance = MemoryTrackUsageInfo();
        return instance;
    }

    MemoryTrackUsageInfo(const MemoryTrackUsageInfo& other) = delete;

    MemoryTrackUsageInfo& operator=(const MemoryTrackUsageInfo& other) = delete;

    MemoryTrackUsageInfo& operator=(const MemoryTrackUsageInfo&& other) = delete;

    MemoryTrackUsageInfo(const MemoryTrackUsageInfo&& other) = delete;

    void SetIsTracked(bool&& value)
    {
        MemoryAllocationIsTracked = value;
    }

    void* track_memory_with_new_operator(size_t size, MemoryTrackMap::AllocationMapType& memory_track_map) throw(...);
    void track_memory_with_delete_operator(void* memory_pointer, MemoryTrackMap::AllocationMapType& memory_track_map) throw(...);

    ~MemoryTrackUsageInfo() = default;

private:

    std::size_t TotalMallocatedMemorySpace { 0 };
    std::size_t TotalFreedMemorySpace { 0 };

    /* IMPORTANT: set true when your app starts */
    bool MemoryAllocationIsTracked { false };

    MemoryTrackUsageInfo() = default;
};

/**
 * Use the std::map for new memory allocations to keep track of the size.
 **/
inline void* MemoryTrackUsageInfo::track_memory_with_new_operator(size_t size, MemoryTrackMap::AllocationMapType& memory_track_map) throw(...)
{
    bool& _MemoryAllocationIsTracked { MemoryAllocationIsTracked };

    if(size == 0)
    {
        throw std::runtime_error("Error, This is an invalied memory operation, The size of the registered memory cannot be equal to zero!");
    }

    void* memory_pointer = nullptr;

    if (_MemoryAllocationIsTracked)
    {
        std::size_t& _TotalMallocatedMemorySpace { TotalMallocatedMemorySpace };

        _TotalMallocatedMemorySpace += size;
        memory_pointer = std::malloc(size);

        #ifdef PRINT_MEMORY_TRACKING_INFORATION
        std::cout << "\n\n\n\n\n*********************************************************************************************************************\n";
        std::cout << "[Caution level inforamtion]" << std::endl;
        std::cout << "Heap memory space is allocated." << std::endl; 
        std::cout << "Current total used: " << _TotalMallocatedMemorySpace << " byte" << std::endl;
        std::cout << "[Memory space debug inforamtion]" <<std::endl; 
        std::cout << "This pointer type size is: " << sizeof(unsigned long(memory_pointer)) << "\nThe memory address of object is: " << memory_pointer << "\nThe registered size is: " << size << std::endl;
        std::cout << "\n*********************************************************************************************************************\n\n\n\n\n";
        #endif

        _MemoryAllocationIsTracked = false;

        memory_track_map.insert(std::pair<void*, std::size_t>(memory_pointer, size));

        _MemoryAllocationIsTracked = true;
    }
    else
    {
        memory_pointer = std::malloc(size);
    }

    if (memory_pointer == nullptr)
    {
        throw std::bad_alloc();
    }
    else
    {
        return memory_pointer;
    }
}

/**
 * Deletes something from the allocated new memory space recorded with std::map.
 **/

inline void MemoryTrackUsageInfo::track_memory_with_delete_operator(void* memory_pointer, MemoryTrackMap::AllocationMapType& memory_track_map) throw(...)
{
    bool& _MemoryAllocationIsTracked { MemoryAllocationIsTracked };

    if (_MemoryAllocationIsTracked)
    {
        size_t size = 0;

        auto map_iterator = memory_track_map.find(memory_pointer);
        if(map_iterator != memory_track_map.end())
        {
            size = (*map_iterator).second;
        }
        else
        {
            std::cerr << "Error, this is an invalid pointer and the function exits immediately." << std::endl;
            return;
        }
        
        if(size == 0)
        {
            throw std::runtime_error("Error, this is an invalied memory operation, The size of the unregistered memory cannot be equal to zero!");
        }

        std::size_t& _TotalMallocatedMemorySpace { TotalMallocatedMemorySpace };
        std::size_t& _TotalFreedMemorySpace { TotalFreedMemorySpace };
        
        _TotalMallocatedMemorySpace -= size;
       
        _TotalFreedMemorySpace += size;

        _MemoryAllocationIsTracked = false;

        if(memory_pointer != nullptr)
        {
            memory_track_map.erase(memory_pointer);
        }
        _MemoryAllocationIsTracked = true;

        #ifdef PRINT_MEMORY_TRACKING_INFORATION
        std::cout << "\n\n\n\n\n*********************************************************************************************************************\n";
        std::cout << "[Caution level inforamtion]" << std::endl;
        std::cout << "Heap memory space is deallocated." << std::endl;
        std::cout << "Current total used: " << _TotalMallocatedMemorySpace << " byte" << std::endl;
        std::cout << "Current total restored: " << _TotalFreedMemorySpace << " byte" << std::endl;
        std::cout << "[Memory space debug inforamtion]" << std::endl;
        std::cout << "This pointer type size is: " << sizeof(unsigned long(memory_pointer)) << "\nThe memory address of object is: " << memory_pointer << "\nThe unregistered size is: " << size << std::endl;
        std::cout << "\n*********************************************************************************************************************\n\n\n\n\n";
        #endif
    }

    std::free(memory_pointer);
    memory_pointer = nullptr;
}

inline void* operator new(std::size_t object_size)
{
    auto& memory_track_information_singleton = MemoryTrackUsageInfo::get_instance();
    return memory_track_information_singleton.track_memory_with_new_operator(object_size, MemoryTrackMap::MemoryAllocationMapStandard);
}

inline void* operator new[](std::size_t object_array_size)
{
    auto& memory_track_information_singleton = MemoryTrackUsageInfo::get_instance();
    return memory_track_information_singleton.track_memory_with_new_operator(object_array_size, MemoryTrackMap::MemoryAllocationMapArray);
}

inline void operator delete(void* pointer_value)
{
    auto& memory_track_information_singleton = MemoryTrackUsageInfo::get_instance();
    memory_track_information_singleton.track_memory_with_delete_operator(pointer_value, MemoryTrackMap::MemoryAllocationMapStandard);
}

inline void operator delete[](void* pointer_with_array_value)
{
    auto& memory_track_information_singleton = MemoryTrackUsageInfo::get_instance();
    memory_track_information_singleton.track_memory_with_delete_operator(pointer_with_array_value, MemoryTrackMap::MemoryAllocationMapArray);
}

#endif // USE_MEMORY_TRACKER_CODE

static constexpr size_t CURRENT_SYSTEM_BITS = (std::numeric_limits<unsigned char>::digits * sizeof(void*));

inline void my_cpp2020_assert(const bool JudgmentCondition, const char* ErrorMessage, std::source_location AssertExceptionDetailTrackingObject)
{
    if(!JudgmentCondition)
    {
        std::cout << "The error message is(错误信息是):\n" << ErrorMessage << std::endl;

        std::cout << "Oh, crap, some of the code already doesn't match the conditions at runtime.(哦，糟糕，有些代码在运行时已经不匹配条件。)\n\n\n" << std::endl;
        std::cout << "Here is the trace before the assertion occurred(下面是发生断言之前的追踪信息):\n\n" << std::endl;
        std::cout << "The condition determines the code file that appears to be a mismatch(条件判断出现不匹配的代码文件):\n" << AssertExceptionDetailTrackingObject.file_name() << std::endl;
        std::cout << "Name of the function where this assertion is located(该断言所在的函数的名字):\n" << AssertExceptionDetailTrackingObject.function_name() << std::endl;
        std::cout << "Number of lines of code where the assertion is located(该断言所在的代码行数):\n" << AssertExceptionDetailTrackingObject.line() << std::endl;
        std::cout << "Number of columns of code where the assertion is located(该断言所在的代码列数):\n" << AssertExceptionDetailTrackingObject.column() << std::endl;
        
        throw std::runtime_error(ErrorMessage);
    }
    else
    {
        return;
    }
}

namespace NoCompilerOptimize
{
    namespace CallbackFunction
    {
        using memory_set_no_optimize_function_pointer_type = void* (*)(void*, int, size_t);

        /*
            Pointer to memset is volatile so that compiler must de-reference the pointer and can't assume that it points to any function in particular (such as memset, which it then might further "optimize")
            指向memset的指针是不稳定的，因此编译器必须取消对该指针的引用，不能假定它指向任何特定的函数（例如memset，然后它可能进一步 "优化"）。
        */
        inline static volatile memory_set_no_optimize_function_pointer_type memory_set_no_optimize_function_pointer = memset;
    }
}

// Reference code: https://github.com/openssl/openssl/blob/master/crypto/mem_clr.c
inline void memory_set_no_optimize_function(void* buffer_pointer, int value, size_t size)
{
	NoCompilerOptimize::CallbackFunction::memory_set_no_optimize_function_pointer(buffer_pointer, value, size);
}

#endif // !SUPPORT_LINRARY_H
