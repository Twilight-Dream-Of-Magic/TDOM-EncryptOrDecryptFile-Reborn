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

#ifndef SUPPORT_LIBRARY_HPP
#define SUPPORT_LIBRARY_HPP

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
//#include <complex>

#if __cplusplus >= 201703L

#include <charconv>
#include <optional>
#include <filesystem>
#include <numeric>

#endif

#if __cplusplus >= 202002L

#include <bit>
#include <ranges>
#include <coroutine>
#include <source_location>
#include <numbers>
#include <concepts>
#include <span>

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

//Multi-Threading-Development-ISO-C++ Standard Library
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

#if defined(NULL)
#undef NULL

	#if __cplusplus >= 201103L
	#define NULL (nullptr)
	#else
	#define NULL 0
	#endif

#endif

namespace CommonToolkit
{
	// false value attached to a dependent name (for static_assert)
	template <class>
	inline constexpr bool Dependent_Always_Failed = false;
	// true value attached to a dependent name (for static_assert)
	template <class>
	inline constexpr bool Dependent_Always_Succeed = true;

	template<class T> struct dependent_always_true : std::true_type {};
	template<class T> struct dependent_always_false : std::false_type {};

	using OneByte = unsigned char;
	using TwoByte = unsigned short int;
	using FourByte = unsigned int;
	using EightByte = unsigned long long int;

	using SpanOneByte = std::span<std::byte, 1>;
	using SpanTwoByte = std::span<std::byte, 2>;
	using SpanFourByte = std::span<std::byte, 4>;
	using SpanEightByte = std::span<std::byte, 8>;

	#if __cpp_static_assert >= 200410L && __cplusplus <= 201402L
	#define CPP2020_BIT_CAST_ENABLE_IF_TYPE( TO, FROM ) typename std::enable_if< sizeof( TO ) == sizeof( FROM ) && std::is_trivially_copyable<FROM>::value && std::is_trivially_copyable<TO>::value, TO >::type
	#else
	#define CPP2020_BIT_CAST_ENABLE_IF_TYPE( TO, FROM ) TO
	#endif

	#if __cpp_static_assert >= 201411L && !defined(CPP2020_BIT_CAST_ENABLE_IF_TYPE)
	#define CPP2020_BIT_CAST_STATIC_ASSERTS( TO, FROM ) \
	do \
	{ \
		static_assert( sizeof( TO ) == sizeof( FROM ) ); \
		static_assert( std::is_trivially_copyable<TO>::value ); \
		static_assert( std::is_trivially_copyable<FROM>::value ); \
	} while ( false )
	#else
	#define CPP2020_BIT_CAST_STATIC_ASSERTS( TO, FROM )
	#endif

	#if defined( __cpp_concepts ) && __cpp_concepts >= 201507 && !defined(CPP2020_BIT_CAST_STATIC_ASSERTS) && !defined(CPP2020_BIT_CAST_ENABLE_IF_TYPE)
	#define CPP2020_BIT_CAST_CONCEPTS( TO, FROM ) requires sizeof( TO ) == sizeof( FROM ) && std::is_trivially_copyable<TO>::value && std::is_trivially_copyable<FROM>::value
	#else
	#define CPP2020_BIT_CAST_CONCEPTS( TO, FROM )
	#endif

	#if defined(__cpp_lib_bit_cast)

	using std::bit_cast;

	#elif __cplusplus >= 201103L && __cplusplus < 202002L

	#if __cpp_constexpr >= 201304L
	#define CPP2020_BIT_CAST_USE_CONSTANT_EXPRSSION constexpr
	#else
	#define CPP2020_BIT_CAST_USE_CONSTANT_EXPRSSION
	#endif

	/*
    
		Implement and call the bit_cast function and perform explicit and implicit comparison experiments

		bit_cast function (c++ source code):

		@source-code@
		template <class To, class From,
		std::enable_if_t
		<
			std::conjunction_v
			<
				std::bool_constant<sizeof(To) == sizeof(From)>, std::is_trivially_copyable<To>, std::is_trivially_copyable<From>
			>,
			int> = 0
		>
		[[nodiscard]]  To bit_cast_implicit(const From& Value) noexcept {
			return __builtin_bit_cast(To, Value);
		}

		template <class To, class From>
		std::enable_if_t<
			sizeof(To) == sizeof(From) &&
			std::is_trivially_copyable_v<From> &&
			std::is_trivially_copyable_v<To>,
			To>
		// constexpr support needs compiler magic
		bit_cast_explicit(const From& src) noexcept
		{
			static_assert(std::is_trivially_constructible_v<To>,
				"This implementation additionally requires "
				"destination type to be trivially constructible");
    
			To dst;
			std::memcpy(&dst, &src, sizeof(To));
			return dst;
		}
		@/source-code@
    
		Power by https://godbolt.org/

		'gcc -std=c++17 -Wall -Wextra -fsigned-char -Og'
    
		Not use pointer (c++ source code) ：

		@source-code@
		double value = 1.23456789;
		long long pointer = bit_cast_implicit<long long>(value);
		std::cout << pointer << std::endl;

		float value2 = 2.1345f;
		int pointer2 = bit_cast_explicit<int>(value2);
		std::cout << pointer2 << std::endl;
		@/source-code@
    
		Not use pointer (Assembly code and definition of the calling function):

		long long bit_cast_implicit<long long, double, 0>(double const&):
			mov     rax, QWORD PTR [rdi]
			ret
		std::enable_if<(((sizeof (int))==(sizeof (float)))&&(is_trivially_copyable_v<float>))&&(is_trivially_copyable_v<int>), int>::type bit_cast_explicit<int, float>(float const&):
			mov     eax, DWORD PTR [rdi]
			ret

		main:
		call    long long* bit_cast_implicit<long long*, double*, 0>(double* const&)
		mov     rsi, QWORD PTR [rax]

		call    std::enable_if<(((sizeof (int*))==(sizeof (float*)))&&(is_trivially_copyable_v<float*>))&&(is_trivially_copyable_v<int*>), int*>::type bit_cast_explicit<int*, float*>(float* const&)
		mov     esi, DWORD PTR [rax]
    
		Use pointer (c++ source code) :

		@source-code@
		double value = 1.23456789;
		long long* pointer = bit_cast_implicit<long long*>(&value);
		std::cout << *pointer << std::endl;

		float value2 = 2.1345f;
		int* pointer2 = bit_cast_explicit<int*>(&value2);
		std::cout << *pointer2 << std::endl;
		@/source-code@

		Use pointer (Assembly code and definition of the calling function):

		long long* bit_cast_implicit<long long*, double*, 0>(double* const&):
			mov     rax, QWORD PTR [rdi]
			ret
		std::enable_if<(((sizeof (int*))==(sizeof (float*)))&&(is_trivially_copyable_v<float*>))&&(is_trivially_copyable_v<int*>), int*>::type bit_cast_explicit<int*, float*>(float* const&):
			mov     rax, QWORD PTR [rdi]
			ret

		main:
		call    long long bit_cast_implicit<long long, double, 0>(double const&)
		mov     rsi, rax
		call    std::enable_if<(((sizeof (int))==(sizeof (float)))&&(is_trivially_copyable_v<float>))&&(is_trivially_copyable_v<int>), int>::type bit_cast_explicit<int, float>(float const&)
		mov     esi, eax

	*/
	template<typename To, typename From>
	CPP2020_BIT_CAST_CONCEPTS(TO, FROM)
	CPP2020_BIT_CAST_ENABLE_IF_TYPE(To, From) bit_cast(const From& from_storage) noexcept
	{
	  CPP2020_BIT_CAST_STATIC_ASSERTS(To, From);
  
	  typename std::aligned_storage<sizeof(To), alignof(To)>::type to_storage;
	  std::memcpy(&to_storage, &from_storage, sizeof(To));  // Above `constexpr` is optimistic, fails here.
	  return reinterpret_cast<To&>(to_storage);
	  // More common implementation:
	  // std::remove_const_t<To> to{};
	  // std::memcpy(&to, &from, sizeof(To));  // Above `constexpr` is optimistic, fails here.
	  // return to;
	}

	#else

	#error "The compiler you are using does not support the c++ 2020 std::bit_cast function!"

	#endif

	#undef CPP2020_BIT_CAST_ENABLE_IF_TYPE
	#undef CPP2020_BIT_CAST_STATIC_ASSERTS
	#undef CPP2020_BIT_CAST_CONCEPTS

}

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

#if __cplusplus >= 202002L

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

#endif

#define __STDC_WANT_LIB_EXT1__ 1

static inline void* (* const volatile memory_set_no_optimize_function_pointer)(void*, int, size_t) = memset;

struct MemorySetUitl
{
	/**
	 * @brief The function copies the value of @a value (converted to an unsigned char)
	 * into each of the first @a count characters of the object pointed to by @a dest.
	 * The purpose of this function is to make sensitive information stored in the object inaccessible.
	 * @param buffer_pointer to the object to fill
	 * @param value: character fill byte
	 * @param size: count number of bytes to fill
	 * @return a copy of dest
	 * @note C++ proposal: http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1315r6.html
	 * @note The intention is that the memory store is always performed (i.e., never elided),
	 *		 regardless of optimizations. This is in contrast to calls to the memset function.
	 */
	inline volatile void* fill_memory_byte_no_optimize_implementation(void* buffer_pointer, const int byte_value, size_t size)
	{
		if(buffer_pointer == nullptr)
			return nullptr;

		#if __cplusplus >= 201103L && defined(__STDC_WANT_LIB_EXT1__) && __STDC_WANT_LIB_EXT1__ == 1 && defined(__STDC_LIB_EXT1__)
			memset_s(buffer_pointer, byte_value, 0, size);
		#elif !defined(__STDC_WANT_LIB_EXT1__) && !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)

		/*
			Pointer to memset is volatile so that compiler must de-reference the pointer and can't assume that it points to any function in particular (such as memset, which it then might further "optimize")
			指向memset的指针是不稳定的，因此编译器必须取消对该指针的引用，不能假定它指向任何特定的函数（例如memset，然后它可能进一步 "优化"）。
		
			New Reference code: https://github.com/peterlauro/memset_explicit/blob/main/include/cstring.h
			Old Reference code: https://github.com/openssl/openssl/blob/master/crypto/mem_clr.c
		*/
		volatile void* memory_set_volatile_pointer = std::memset(buffer_pointer, byte_value, size);

		// https://stackoverflow.com/questions/50428450/what-does-asm-volatile-pause-memory-do
		// https://preshing.com/20120625/memory-ordering-at-compile-time/
		// when -O2 or -O3 is on
		// the following line prevents the compiler to optimize away the call of memset
		// https://stackoverflow.com/questions/14449141/the-difference-between-asm-asm-volatile-and-clobbering-memory
		// compiler barrier:
		// - the linux inline assembler is not allowed to be used by the project coding rules
		// asm volatile ("" ::: "memory");
		// - the windows compiler intrinsic _ReadWriteBarrier is deprecated
		//	https://docs.microsoft.com/en-us/cpp/intrinsics/readwritebarrier?view=msvc-160
		//
		// the msvc /std:c++17 /Ot - without a compiler_barrier doesn't optimize away the call of memset
		// the linux g++ 9.3.0 -O2 - without a compiler_barrier the call of memset is optimized away
		//
		// std::atomic_thread_fence:
		// gcc 9.3.0 -std=c++17 -O2 generates mfence asm instruction; the call of memset is not optimized away
		// std::atomic_signal_fence:
		// gcc 9.3.0 -std=c++17 -O2 no mfence asm instruction is generated,
		// however the call of memset is not optimized away too
		
		#if __cplusplus >= 201402L

		std::atomic_signal_fence(std::memory_order_seq_cst);

		#endif

		return memory_set_volatile_pointer;

		#elif __cplusplus >= 201103L

		if(byte_value > -1 && byte_value < 256)
		{
			static volatile unsigned char* volatile current_pointer = (volatile unsigned char *)buffer_pointer;
			do
			{
				memory_set_no_optimize_function_pointer((unsigned char *)current_pointer, byte_value, size);
			} while(*current_pointer != byte_value);

			return buffer_pointer;
		}
		else if(byte_value > -129 && byte_value < 128)
		{
			static volatile char* volatile current_pointer = (volatile char *)buffer_pointer;
			do
			{
				memory_set_no_optimize_function_pointer((char *)current_pointer, byte_value, size);
			} while(*current_pointer != byte_value);

			return buffer_pointer;
		}

		return nullptr;

		#elif __cplusplus == 199711L

		if(size == 0)
		   return nullptr;
		static volatile char* volatile current_pointer = (volatile char*)buffer_pointer;

		
		if(byte_value > -1 && byte_value < 256)
		{
			static volatile unsigned char* volatile current_pointer = (volatile unsigned char*)buffer_pointer;
			while (size--)
			{
				if(*current_pointer != byte_value)
					*current_pointer ^= ( *current_pointer ^ byte_value );
			}

			return buffer_pointer;
		}
		else if(byte_value > -129 && byte_value < 128)
		{
			static volatile char* volatile current_pointer = (volatile char*)buffer_pointer;
			while (size--)
			{
				if(*current_pointer != byte_value)
					*current_pointer ^= ( *current_pointer ^ byte_value );
			}

			return buffer_pointer;
		}

		return nullptr;

		#endif
	}

	inline volatile void fill_memory(void* buffer_pointer, const int byte_value, size_t size)
	{
		volatile void* check_pointer = nullptr;
		check_pointer = this->fill_memory_byte_no_optimize_implementation(buffer_pointer, byte_value, size);

		if(check_pointer == nullptr)
		{
			throw std::runtime_error("Support-Library: Force Memory Fill Has Been \"Optimization\" !");
		}
	}
};

/**
 * @brief Copies the value of @a ch (converted to an unsigned char) into each byte of
 *		  the object pointed to by @a dest.
 *		  The purpose of this function is to make sensitive information stored
 *		  in the object inaccessible.
 * @param TriviallyCopyableType the type of object
 * @param that reference to the object to fill
 * @param value: character fill byte
 * @note C++ proposal: http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1315r6.html
 * @note The intention is that the memory store is always performed (i.e., never elided),
 *		 regardless of optimizations. This is in contrast to calls to the memset function.
 */
template<typename TriviallyCopyableType,
std::enable_if_t<std::is_trivially_copyable_v<TriviallyCopyableType> && !std::is_pointer_v<TriviallyCopyableType>>* = nullptr>
void memory_set_explicit_call(TriviallyCopyableType& that_object, int value) noexcept
{
	MemorySetUitl MemorySetUitlObject;
	MemorySetUitlObject.fill_memory(std::addressof(that_object), value, sizeof(that_object));
}

template<int byte_value>
static inline volatile void* memory_set_no_optimize_function(void* buffer_pointer, size_t size)
{
	if(buffer_pointer == nullptr)
		return nullptr;
	
	if(size > 0)
	{
		if constexpr(byte_value > -1 && byte_value < 256)
		{
			const std::vector<unsigned char> fill_memory_datas(size, byte_value);
			
			#if __cplusplus >= 202002L

			std::span<unsigned char> memory_data_span_view{ (unsigned char *)buffer_pointer, (unsigned char *)buffer_pointer + size };
			volatile void* check_pointer = std::memmove(memory_data_span_view.data(), fill_memory_datas.data(), size);
			
			if(memory_data_span_view[0] != (unsigned char)byte_value || memory_data_span_view[memory_data_span_view.size() - 1] != (unsigned char)byte_value || check_pointer == nullptr)
				return nullptr;
			else
			{
				check_pointer = nullptr;
				return buffer_pointer;
			}

			#else

			volatile void* check_pointer = std::memmove((unsigned char *)buffer_pointer, fill_memory_datas.data(), size);
			if(buffer_pointer == check_pointer)
				return buffer_pointer;
			else
				return nullptr;

			#endif
		}
		else if constexpr(byte_value > -129 && byte_value < 128)
		{
			const std::vector<char> fill_memory_datas(size, byte_value);
			
			#if __cplusplus >= 202002L

			std::span<char> memory_data_span_view{ (char *)buffer_pointer, (char *)buffer_pointer + size };
			volatile void* check_pointer = std::memmove(memory_data_span_view.data(), fill_memory_datas.data(), size);
			
			if(memory_data_span_view[0] != (char)byte_value || memory_data_span_view[memory_data_span_view.size() - 1] != (char)byte_value || check_pointer == nullptr)
				return nullptr;
			else
			{
				check_pointer = nullptr;
				return buffer_pointer;
			}

			#else

			volatile void* check_pointer = std::memmove((char *)buffer_pointer, fill_memory_datas.data(), size);
			if(buffer_pointer == check_pointer)
				return buffer_pointer;
			else
				return nullptr;

			#endif
		}
		else
		{
			static_assert(CommonToolkit::Dependent_Always_Failed<byte_value>, "Byte number is out of range!");
		}
		
		return nullptr;
	}
	else
	{
		return nullptr;
	}
}

#if defined(__STDC_WANT_LIB_EXT1__)
#undef __STDC_WANT_LIB_EXT1__
#endif

// Try to allocate a temporary memory size.
std::optional<std::size_t> try_allocate_temporary_memory_size(std::size_t memory_byte_size)
{
	std::size_t temporary_memory_byte_size = 0;

	if(memory_byte_size == 0)
		return std::nullopt;
	else if(memory_byte_size % 8 != 0)
	{
		std::size_t modulus_value = memory_byte_size % 8;
		if( (memory_byte_size + modulus_value) >= std::numeric_limits<std::size_t>::min() )
			memory_byte_size -= modulus_value;
		else if ( (memory_byte_size - modulus_value) <= std::numeric_limits<std::size_t>::max() )
			memory_byte_size += modulus_value;
	}

	temporary_memory_byte_size = memory_byte_size;

	char* byte_pointer = nullptr;
	while(byte_pointer == nullptr)
	{
		byte_pointer = (char*) ::operator new[](memory_byte_size, std::nothrow);
		if(byte_pointer == nullptr)
		{
			memory_byte_size -= memory_byte_size / 8;
			temporary_memory_byte_size = memory_byte_size;
		}
	}
	::operator delete[]( (void*) byte_pointer, std::nothrow);

	return temporary_memory_byte_size;
}

#endif // !SUPPORT_LIBRARY_H