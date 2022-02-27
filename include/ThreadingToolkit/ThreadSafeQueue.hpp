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

#include "AuxiliaryDeclaration.hpp"

namespace ThreadingToolkit::TypeTraits
{
	//Is thread resource mutex class
	template <typename Type>
	struct is_mutex
	{
		static const bool value = 
		#if __cplusplus >= 201703L
			std::is_same_v<std::decay_t<Type>, std::shared_mutex> ||
			std::is_same_v<std::decay_t<Type>, std::shared_timed_mutex> ||
		#endif
			std::is_same_v<std::decay_t<Type>, std::mutex> ||
			std::is_same_v<std::decay_t<Type>, std::timed_mutex> ||
			std::is_same_v<std::decay_t<Type>, std::recursive_mutex> ||
			std::is_same_v<std::decay_t<Type>, std::recursive_timed_mutex>;
	};

	template<typename Type>
	inline constexpr bool is_mutex_v = is_mutex<Type>::value;
}

namespace ThreadingToolkit
{
	template<typename ThisItemType, typename MutexType>
	class ThreadSafeQueue
	{

	public:

		using ContainerType = std::deque<ThisItemType>;

		using value_type = typename ContainerType::value_type;
		using size_type = typename ContainerType::size_type;
		using reference = typename ContainerType::reference;
		using const_reference = typename ContainerType::const_reference;

		static_assert(std::is_same_v<ThisItemType, value_type>, "ThreadSafeQueue-Class ThisItemType is error: container adapters require consistent types");
		static_assert(TypeTraits::is_mutex_v<MutexType>, "ThreadSafeQueue-Class (MutexType is error: The type must be of class std::mutex !)");

		/* Constructor function 1 */
		ThreadSafeQueue() noexcept( std::is_nothrow_default_constructible_v<ContainerType> ) {}

		/* Constructor function 2 */
		explicit ThreadSafeQueue (const ContainerType& container) noexcept (
			std::is_nothrow_copy_constructible_v<ContainerType>
		) : _deque { container }
		{
		}

		/* Constructor function 3 */
		explicit ThreadSafeQueue (const ContainerType&& container) noexcept (
			std::is_nothrow_move_constructible_v<ContainerType>
		) : _deque { std::exchange( container, {} ) }
		{
		}

		/* Constructor function 4 */
		ThreadSafeQueue (const ThreadSafeQueue& other_object) noexcept (
			std::is_nothrow_copy_constructible_v<ContainerType>
		)
		{
			auto spin_lock_with_scoped { std::scoped_lock(other_object._conditional_mutex) };
			_deque = other_object._deque;
		}

		/* Constructor function 5 */
		ThreadSafeQueue (const ThreadSafeQueue&& other_object) noexcept (
			std::is_nothrow_move_constructible_v<ContainerType>
		)
		{
			auto spin_lock_with_scoped { std::scoped_lock(other_object._conditional_mutex) };
			_deque = std::exchange( other_object._deque, {} );
		}

		/* Constructor function 6 */
		template<class AllocatorType>
		explicit ThreadSafeQueue(const AllocatorType& allocator) noexcept (
				std::is_nothrow_constructible_v<ContainerType, const AllocatorType>    
		) : _deque { allocator }
		{
		  static_assert(std::uses_allocator_v<ContainerType, AllocatorType>, "ThreadSafeQueue-Function: Constructor function 6: AllocatorType must be compatibile with ContainerType !");
		}

		/* Constructor function 7 */
		template<class AllocatorType>
		ThreadSafeQueue(const ContainerType& container, const AllocatorType& allocator)
			: _deque { container, allocator }
		{
			static_assert(std::uses_allocator_v<ContainerType, AllocatorType>, "ThreadSafeQueue-Function: Constructor function 7: AllocatorType must be compatibile with ContainerType !");
		}

		/* Constructor function 8 */
		template<class AllocatorType>
		ThreadSafeQueue(const ContainerType&& container, const AllocatorType& allocator) noexcept (
			std::is_nothrow_constructible_v<ContainerType, ContainerType, const AllocatorType>
		) : _deque ( std::exchange( container, {} ), allocator )
		{
			static_assert(std::uses_allocator_v<ContainerType, AllocatorType>, "ThreadSafeQueue-Function: Constructor function 8: AllocatorType must be compatibile with ContainerType !");
		}

		/* Constructor function 9 */
		template<class AllocatorType>
		ThreadSafeQueue(const ThreadSafeQueue& other_object, const AllocatorType& allocator)
			: _deque ( allocator )
		{
			static_assert(std::uses_allocator_v<ContainerType, AllocatorType>, "ThreadSafeQueue-Function: Constructor function 9: AllocatorType must be compatibile with ContainerType !");

			auto spin_lock_with_scoped { std::scoped_lock(other_object._conditional_mutex) };
			_deque = ContainerType( other_object._deque, allocator );
		}

		/* Constructor function 10 */
		template<class AllocatorType>
		ThreadSafeQueue(const ThreadSafeQueue&& other_object, const AllocatorType& allocator) noexcept (
			std::is_nothrow_constructible_v<ContainerType, ContainerType, const AllocatorType&>
		) : _deque ( allocator )
		{
			static_assert(std::uses_allocator_v<ContainerType, AllocatorType>, "ThreadSafeQueue-Function: Constructor function 10: AllocatorType must be compatibile with ContainerType !");

			auto spin_lock_with_scoped { std::scoped_lock(other_object._conditional_mutex) };
			_deque = ContainerType( std::exchange( other_object._deque, {} ), allocator );
		}

		/* Member function operator= 1 */
		ThreadSafeQueue operator=(const ThreadSafeQueue& other_object) noexcept (
			std::is_nothrow_copy_assignable_v<ContainerType>	
		)
		{

			{
				auto spin_lock_with_scoped { std::scoped_lock( _conditional_mutex, other_object._conditional_mutex ) };
				_deque = other_object._deque;
			}

			_conditional.notify_all();
			return *this;
		}

		/* Member function operator= 2 */
		ThreadSafeQueue operator=(const ThreadSafeQueue&& other_object) noexcept (
			std::is_nothrow_move_assignable_v<ContainerType>
		)
		{

			{
				auto spin_lock_with_scoped { std::scoped_lock( _conditional_mutex, other_object._conditional_mutex ) };
				_deque = std::exchange( other_object._deque, {} );
			}

			_conditional.notify_all();
			return *this;
		}

		/* Destructor function */
		~ThreadSafeQueue() = default;

		/* Member functions: empty */
		[[nodiscard]] auto empty() const noexcept (
			noexcept( std::declval<ContainerType>().empty() )
		)
		{

			auto spin_lock_with_scoped { std::scoped_lock( _conditional_mutex ) };
			return _deque.empty();
		}

		/* Member functions: size */
		[[nodiscard]] auto size() const noexcept (
			noexcept( std::declval<ContainerType>().size() )
		)
		{
			auto spin_lock_with_scoped { std::scoped_lock( _conditional_mutex ) };
			return _deque.size();
		}

		/* Member functions: max_size */
		[[nodiscard]] auto max_size() const noexcept (
			noexcept( std::declval<ContainerType>().max_size() )
		)
		{
			auto spin_lock_with_scoped { std::scoped_lock( _conditional_mutex ) };
			return _deque.max_size();
		}

		/* Member functions: push */
		template<typename UniversalType>
		void push(UniversalType&& queue_item)
		{

			{
				auto spin_lock_with_scoped { std::scoped_lock(_conditional_mutex) };
				_deque.push_back( queue_item );
			}
			_conditional.notify_one();
		}

		/* Member functions: emplace */
		template<typename... TypeArgs>
		void emplace(TypeArgs&&... object_args)
		{
			{
				ThisItemType new_queue_item { std::forward<TypeArgs>(object_args)... };
				auto spin_lock_with_scoped { std::scoped_lock(_conditional_mutex) };
				_deque.emplace( _deque.end(), std::move( new_queue_item ) );
			}
			_conditional.notify_one();
		}

		/* Member functions: pop */
		ThisItemType pop()
		{
			auto unique_locker { std::unique_lock(_conditional_mutex) };
			while (_deque.empty())
			{
				_conditional.wait( unique_locker );
			}
			ThisItemType result { std::move( _deque.front() ) };
			_deque.pop_front();
			return result;
		}

		/* Member functions: try_pop */
		std::optional<ThisItemType> try_pop()
		{
			auto spin_lock_with_scoped { std::scoped_lock(_conditional_mutex) };
			if (_deque.empty())
			{
				return std::nullopt;
			}
			ThisItemType result { std::move( _deque.front() ) };
			_deque.pop_front();
			return result;
		}

		/* Member functions: swap */
		void swap(ThreadSafeQueue& other_object) noexcept (
			std::is_nothrow_swappable_v<ContainerType>
		)
		{
			auto spin_lock_with_scoped { std::scoped_lock(_conditional_mutex, other_object._conditional_mutex) };
			_deque.swap( other_object._deque );
			_conditional.notify_all();
			other_object._conditional.notify_all();
		}

		/* Member functions: resize 1 */
		void resize(size_type count)
		{
			auto spin_lock_with_scoped { std::scoped_lock(_conditional_mutex) };
			_deque.resize( count );
		}

		/* Member functions: resize 2 */
		void resize(size_type count, const value_type& value)
		{

			{
				auto spin_lock_with_scoped { std::scoped_lock(_conditional_mutex) };
				_deque.resize( count, value );
			}
			_conditional.notify_all();
		}

		/* Member functions: clear */
		void clear() noexcept
		{
			this->_function_clear();
		}

		/* Member functions: clear_and_count */
		[[nodiscard]] size_type clear_and_count() noexcept
		{
			return this->_function_clear();
		}

		/* Member functions: clear_and_push_and_count */
		template<typename UniversalType>
		size_type clear_and_push_and_count(UniversalType&& queue_item)
		{

			size_type cleared_count = this->_function_clear();

			std::unique_lock locker( _conditional_mutex, std::defer_lock );

			if(this->size() == 0 && locker.try_lock_for(std::chrono::seconds(3)))
			{
				_deque.push_back( queue_item );
			}

			if(locker.owns_lock())
			{
				locker.unlock();
			}

			_conditional.notify_one();
			return cleared_count == 0 ? 0 : cleared_count;
		}

		/* Member functions: clear_and_count_and_emplace */
		template<typename... TypeArgs>
		size_type clear_and_count_and_emplace(TypeArgs&&... object_args)
		{
			size_type cleared_count = this->_function_clear();

			std::unique_lock locker( _conditional_mutex, std::defer_lock );

			if(this->size() == 0 && locker.try_lock_for(std::chrono::seconds(3)))
			{
				ThisItemType new_queue_item { std::forward<TypeArgs>(object_args)... };
				_deque.emplace( _deque.end(), std::move( new_queue_item ) );
			}

			if(locker.owns_lock())
			{
				locker.unlock();
			}

			_conditional.notify_one();
			return cleared_count == 0 ? 0 : cleared_count;
		}

	protected:

		size_type _function_clear() noexcept (
			noexcept( std::declval<ContainerType>().clear() )
			&& noexcept( std::declval<ContainerType>().size() )
		)
		{
			ContainerType _null_default_object {};
			{
				auto spin_lock_with_scoped { std::scoped_lock( _conditional_mutex ) };
				std::swap( _null_default_object, _deque );
				return _null_default_object.size();
			}
		}

	private:

		ContainerType _deque {};

		mutable std::conditional_t<
			std::is_same_v<MutexType, std::mutex>,
			std::condition_variable,
			std::condition_variable_any
		> _conditional {};

		mutable MutexType _conditional_mutex;

	};

	template<typename Type>
	class SimpleThreadSafeQueue
	{

	public:

		void push(Type object)
		{
			std::unique_lock<std::mutex> locker(_conditional_mutex);
			_deque.emplace(_deque.end(), object);
			_conditional.notify_one();
		}

		std::optional<Type> pull()
		{
			std::unique_lock<std::mutex> locker(_conditional_mutex);
			_conditional.wait
			(
				locker,
				[_thread_safe_queue = this]
				{
					return _thread_safe_queue->_must_return_nullptr.test() || !_thread_safe_queue->_deque.empty();
				}
			);

			if(_must_return_nullptr.test())
			{
				return {};
			}

			Type result_object = _deque.front();
			_deque.pop_front();
			return result_object;
		}

		SimpleThreadSafeQueue() {}
		~SimpleThreadSafeQueue()
		{
			recycle();
		}

	private:

		std::deque<Type>& recycle()
		{
			// Even flag should under lock
			// https://stackoverflow.com/a/38148447/4144109
			std::unique_lock<std::mutex> locker(_conditional_mutex);
			_must_return_nullptr.test_and_set();
			_conditional.notify_all();

			// No element will be taken from the queue
			// So we return the queue in case the caller need them
			// WARNING: put may happen after this operation, caller should think about this

			return _deque;
		}

		std::deque<Type> _deque;
		std::mutex _conditional_mutex;
		std::condition_variable _conditional;
		std::atomic_flag _must_return_nullptr;

		friend class ThreadingToolkit::Pool::Version2::ThreadPool;
	};
}

#endif
