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

#include "Support-Library.hpp"

namespace MySupport_Library
{
	namespace Types
	{
		//Definition my renamed c++ keyword new types
		using my_sbyte_type = signed char;
		using my_ssi_type = signed short int;
		using my_si_type = signed int;
		using my_sli_type = signed long int;
		using my_slli_type = signed long long int;

		using my_byte_type = unsigned char;
		using my_usi_type = unsigned short int;
		using my_ui_type = unsigned int;
		using my_uli_type = unsigned long int;
		using my_ulli_type = unsigned long long int;

		using my_csbyte_type = const signed char;
		using my_cssi_type = const signed short int;
		using my_csi_type = const signed int;
		using my_csli_type = const signed long int;
		using my_cslli_type = const signed long long int;

		using my_cbyte_type = const unsigned char;
		using my_cusi_type = const unsigned short int;
		using my_cui_type = const unsigned int;
		using my_culi_type = const unsigned long int;
		using my_culli_type = const unsigned long long int;
	}

	/**
	* 包含功能未完善和仿照现有需求来提出的类型实现，或者没有进行测试的自定义类型
	* Include type implementations that are not fully functional and modeled after existing requirements, or custom types that have not been tested
	*/
	namespace ExperimentalExtensions
	{
	
		/*
		//C++ Function the return type definition to last with using standard 2011
		//Definition Template Generics Apply of C++ Function pointer And Function pointer array
		//Make to the New type need C++ standard 2017
		template<typename Return_Type, typename ...Args>
		struct MY_FP_ARGS
		{
		using my_fp_args = auto (*my_function_args_pointer)(Args args...) -> decltype(Return_Type); //My function args pointer
		}

		//C++ Function the return type definition to last with using standard 2011
		//Definition Template Generics Apply of C++ Function pointer And Function pointer array
		//Make to the New type need C++ standard 2017
		template<typename Return_Type>
		struct MY_FP
		{
		using my_fp = auto (*my_function_pointer)(void) -> decltype(Return_Type); //My Function pointer
		}

		//C++ Function the return type definition to last with using standard 2011
		//Definition Template Generics Apply of C++ Function pointer And Function pointer array
		//Make to the New type need C++ standard 2017
		template<typename Return_Type, size_t ArraySize, typename ...Args>
		struct MY_FPA_ARGS
		{
		using my_fpa_args = auto (*my_function_args_pointer_array[ArraySize])(Args args...) -> decltype(Return_Type); //My function args pointer array
		}

		//C++ Function the return type definition to last with using standard 2011
		//Definition Template Generics Apply of C++ Function pointer And Function pointer array
		//Make to the New type need C++ standard 2017
		template<typename Return_Type, size_t ArraySize>
		struct MY_FPA
		{
		using my_fpa = auto (*my_function_pointer_array[ArraySize])(void) -> decltype(Return_Type); //My function pointer array
		}
		*/

		// Use the feature function of the C++17 standard: this multi-structure in the namespace of the parameter pack
		namespace MyPointerFunction
		{
			struct MyAction //This is a pointer function, However this does not return any value, and does not use the Argument package or the Parameter package.
			{
				typedef void (*Action)(void);
			};

			template<typename... TypeArgs> // This is Argument package or Parameter package for use custom pointer function, However this does not return any value.
			struct MyAction_Args
			{
				//Define a the pointer function, then Argument package or Parameter package to unpacking it.
				typedef void (*Action_Args)(TypeArgs... args);
				typedef void (*Action_ConstantArgs)(const TypeArgs... args);
				typedef void (*Action_ReferArgs)(TypeArgs&... args);
				typedef void (*Action_ConstantReferArgs)(const TypeArgs&... args);
			};

			template<typename ReturnType> //This is a pointer function, But this requires a return value of the type, and does not use the Argument package or the Parameter package.
			struct MyFunction
			{
				typedef ReturnType(*Function)(void);
			};

			template < typename ReturnType, typename... TypeArgs> //This is Argument package or Parameter package for use custom pointer function, But this requires a return value of the type
			struct MyFunction_Args
			{
				//Define a the pointer function, then Argument package or Parameter package to unpacking it.
				typedef ReturnType(*Function_Args)(TypeArgs... args);
				typedef ReturnType(*Function_ConstantArgs)(const TypeArgs... args);
				typedef ReturnType(*Function_ReferArgs)(TypeArgs&... args);
				typedef ReturnType(*Function_ConstantReferArgs)(const TypeArgs&... args);
			};
		}

		/*
		template<typename Return_Type, typename ...Args>
		struct my_unary_function
		{
			Args arguments_type;
			Return_Type result_type;
		};

		template<typename Return_type, typename ...Args>
		class my_pointer_to_unary_function : public my_unary_function<Return_Type, Args>
		{
			protected:
			typedef Return_type(*MyPointerFunction)(Args& args...);

			public:
			explicit my_pointer_to_unary_function( Return_type(*pFunc)(const Args& args...) ) : MyPointerFunction (pFunc) {}
			Return_type operator() (Args& args...) const
			{
				return pFunc(args);
			}
		};

		template<typename Return_Type>
		Return_Type calledAction ( Return_Type(*pFunc)(void) )
		{
			return my_pointer_to_unary_function<Return_Type, void> (pFunc)(void);
		}

		template<typename Return_Type, typename ...Args>
		Return_Type calledFunc( Return_Type(*pFunc)(), const Args&... args)
		{
			return my_pointer_to_unary_function<Return_Type, Args> (pFunc)(args...);
		}

		*/

		namespace MemoryOperation
		{
			template<class Type>
			concept can_addressof_type = std::is_object_v<Type> && std::is_same_v<std::add_pointer_t<std::remove_cvref_t<Type>>, Type*>;

			template<class Type>
			concept can_addressof_type2 = !std::is_object_v<Type> && std::is_same_v<std::add_pointer_t<std::remove_cvref_t<Type>>, Type*>;

			template<class Type> requires can_addressof_type<Type>
			Type* addressof(Type& object) noexcept
			{
				return reinterpret_cast<Type*>(&const_cast<char&>(reinterpret_cast<const volatile char&>(object)));
			}

			template<class Type> requires can_addressof_type2<Type>
			Type* addressof(Type& object) noexcept
			{
				return &object;
			}

			static inline void copy_small(Types::my_byte_type* Destination, const Types::my_byte_type* Source, size_t BlockSize)
			{
				if (BlockSize >= 8)
				{
					*(std::bit_cast<Types::my_ulli_type*>(Destination)) = *(std::bit_cast<const Types::my_ulli_type*>(Source));
					return;
				}
				if (BlockSize >= 4)
				{
					*(std::bit_cast<Types::my_ui_type*>(Destination)) = *(std::bit_cast<const Types::my_ui_type*>(Source));
					Destination += 4;
					Source += 4;
				}
				if (BlockSize & 2)
				{
					*(std::bit_cast<Types::my_usi_type*>(Destination)) = *(std::bit_cast<const Types::my_usi_type*>(Source));
					Destination += 2;
					Source += 2;
				}
				if (BlockSize & 1)
					*Destination = *Source;
			}

			static inline void copy512(Types::my_ulli_type* Destination, const Types::my_ulli_type* Source, size_t BlockSize)
			{
				size_t chunks;
				size_t offset;

				chunks = BlockSize >> 3;
				offset = BlockSize - (chunks << 3);

				while (chunks--)
				{
					*Destination++ = *Source++;
					*Destination++ = *Source++;
					*Destination++ = *Source++;
					*Destination++ = *Source++;
					*Destination++ = *Source++;
					*Destination++ = *Source++;
					*Destination++ = *Source++;
					*Destination++ = *Source++;
				}

				while (offset--)
				{
					*Destination++ = *Source++;
				}
			}

			template<size_t SIZE>
			void* MemoryDataCopy(void* Destination, void* Source)
			{
				static_assert(!std::is_same_v<decltype(Destination), std::nullptr_t>, "DataCopy: The memory address (pointer) of your data is invalid!");
				static_assert(!std::is_same_v<decltype(Source), std::nullptr_t>, "DataCopy: The memory address (pointer2) of your data is invalid!");

				size_t BlockSize = SIZE;
				Types::my_byte_type* DestinationWord8 = nullptr;
				const Types::my_byte_type* SourceWord8 = nullptr;
				size_t Word64;
				size_t aligned_size;

				DestinationWord8 = reinterpret_cast<Types::my_byte_type*>(Destination);
				SourceWord8 = reinterpret_cast<const Types::my_byte_type*>(Source);
				Word64 = BlockSize >> 3;
				if (BlockSize > 8)
				{
					copy512((Types::my_ulli_type*)Destination, (const Types::my_ulli_type*)Source, Word64);
					return (Destination);
				}
				aligned_size = Word64 << 3;
				BlockSize -= aligned_size;
				DestinationWord8 += aligned_size;
				SourceWord8 += aligned_size;
				copy_small(DestinationWord8, SourceWord8, BlockSize);
				return (Destination);
			}

			template<size_t SIZE>
			int MemoryDataComparison_Fixed(const void* data_pointer, const void* data_pointer2)
			{
				static_assert(!std::is_same_v<decltype(data_pointer), std::nullptr_t>, "DataComparison: The memory address (pointer) of your data is invalid!");
				static_assert(!std::is_same_v<decltype(data_pointer2), std::nullptr_t>, "DataComparison: The memory address (pointer2) of your data is invalid!");

				Types::my_byte_type* pointer = std::bit_cast<Types::my_byte_type*>(data_pointer);
				Types::my_byte_type* pointer2 = std::bit_cast<Types::my_byte_type*>(data_pointer2);
				Types::my_byte_type* differences = *pointer - *pointer2;
				return differences ? differences : MemoryDataComparison_Fixed<SIZE - 1>(pointer + 1, pointer2 + 1);
			}

			template<>
			inline int MemoryDataComparison_Fixed<0>(const void*, const void*)
			{
				return 0;
			}

			template < class Type >
			class Allocator
			{
				public:
					using value_type = Type;
					using pointer = Type*;
					using reference = Type&;
					using const_pointer = const Type*;
					using const_reference = const Type&;
					using size_type = size_t;
					using difference_type = std::ptrdiff_t;

					// default
					Allocator() throw() {}

					Allocator(Allocator const &alloc) throw() { static_cast<void>(alloc); }

					~Allocator() throw() {}

					// copy
					template < class U >
					Allocator(Allocator<U> const &alloc) throw() { static_cast<void>(alloc); }

					// rebind allocator to type U
					template < class U >
					struct rebind { typedef Allocator<U> other; };
            
					pointer address(reference value) const { return &value; }

					const_pointer address(const_reference value) const { return &value; }

					size_type max_size() const throw()
					{
						size_type const big(18446744073709551615U);
						return (big / sizeof(value_type));
					}

					pointer allocate(size_type size_value)
					{
						pointer ret;

						// allocate memory with global new
						ret = reinterpret_cast<pointer>(::operator new(size_value * sizeof(value_type)));
						return ret;
					}

					void deallocate(pointer pointer_value, size_type size_value)
					{
						static_cast<void>(size_value);

						// deallocate memory with global delete
						::operator delete(static_cast<void *>(pointer_value));
					}

					void construct(pointer pointer_value, const_reference const_reference_value)
					{
						static_cast<void>(const_reference_value);
						new (reinterpret_cast<void *>(pointer_value)) value_type(const_reference_value);
					}

					void destroy(pointer pointer_value)
					{
						// destroy objects by calling their destructor
						pointer_value->~value_type();
					}
			};
		}

		namespace Serializable
		{
			//  POD Type
			template <typename Type> requires std::is_trivially_copyable_v<Type>
			void Serialize(std::ostream& os, const Type& value)
			{
				os.write(std::bit_cast<char*>(&value), sizeof(Type));
			}

			//  Container Type
			template <typename Type, typename std::enable_if_t<
				std::is_same_v<typename Type::iterator, decltype(std::declval<Type>().begin())> &&
				std::is_same_v<typename Type::iterator, decltype(std::declval<Type>().end())>, int> N = 0>
			void Serialize(std::ostream& os, const Type& container_object)
			{
                unsigned int size = container_object.size();
                os.write(std::bit_cast<const char*>(&size), sizeof(size));
                for (auto& value : container_object)
                {
                    Serialize(os, value);
                }
			}

			//  POD Type
			template <typename Type> requires std::is_trivially_copyable_v<Type>
			void Deserialize(std::istream& is, Type& value)
			{
				is.read(std::bit_cast<char*>(&value), sizeof(Type));
			}

			//  Container Type
			template <typename Type, typename std::enable_if_t<
				std::is_same_v<typename Type::iterator, decltype(std::declval<Type>().begin())> &&
				std::is_same_v<typename Type::iterator, decltype(std::declval<Type>().end())>, int> N = 0>
			void Deserialize(std::istream& is, Type& container_object)
			{
                unsigned int size = 0;
                is.read(std::bit_cast<char*>(&size), sizeof(unsigned int));
                container_object.resize(size);
                for (auto& value : container_object)
                {
                    Deserialize(is, value);
                }
			}
		}

		#if __cplusplus >= 202002L && defined(CPP2020_SIMPLERANGE_COPIED)

		//Source Code Possible Implementation With https://en.cppreference.com/w/cpp/algorithm/ranges
		namespace CPP2020_SimpleRange
		{
			template<class I, class O>
			struct in_out_result
			{
				[[no_unique_address]] I in;
				[[no_unique_address]] O out;
 
				template<class I2, class O2> requires std::convertible_to<const I&, I2> && std::convertible_to<const O&, O2>
				constexpr operator in_out_result<I2, O2>() const &
				{
					return {in, out};
				}
 
				template<class I2, class O2>
				requires std::convertible_to<I, I2> && std::convertible_to<O, O2>
				constexpr operator in_out_result<I2, O2>() &&
				{
					return {std::move(in), std::move(out)};
				}
			};

			struct copy_fn
			{
				// ALIAS TEMPLATE copy_result
				template <class _In, class _Out>
				using copy_result = ExperimentalExtensions::CPP2020_SimpleRange::in_out_result<_In, _Out>;

				template< std::input_iterator I, std::sentinel_for<I> S, std::weakly_incrementable O > requires std::indirectly_copyable<I, O>
				constexpr copy_result<I, O> operator()(I first, S last, O result) const
				{
					for (; first != last; ++first, (void)++result)
					{
						*result = *first;
					}
					return { std::move(first), std::move(result) };
				}

				template< std::ranges::input_range R, std::weakly_incrementable O > requires std::indirectly_copyable<std::ranges::iterator_t<R>, O>
				constexpr copy_result<std::ranges::borrowed_iterator_t<R>, O> operator()(R&& r, O result) const
				{
					return (*this)(std::ranges::begin(r), std::ranges::end(r), std::move(result));
				}
			};

			inline constexpr copy_fn copy;

			struct copy_backward_fn
			{
				// ALIAS TEMPLATE copy_backward_result
				template <class _In, class _Out>
				using copy_backward_result = ExperimentalExtensions::CPP2020_SimpleRange::in_out_result<_In, _Out>;

				template<std::bidirectional_iterator I1, std::sentinel_for<I1> S1, std::bidirectional_iterator I2> requires std::indirectly_copyable<I1, I2>
				constexpr copy_backward_result<I1, I2>
				operator()(I1 first, S1 last, I2 result) const
				{
					I1 last1{ std::ranges::next(first, std::move(last)) };
					for (I1 i{ last1 }; i != first; *--result = *--i);
					return { std::move(last1), std::move(result) };
				}

				template<std::ranges::bidirectional_range R, std::bidirectional_iterator I>
				requires std::indirectly_copyable<std::ranges::iterator_t<R>, I>
				constexpr copy_backward_result<std::ranges::borrowed_iterator_t<R>, I>
				operator()(R&& r, I result) const
				{
					return (*this)(std::ranges::begin(r), std::ranges::end(r), std::move(result));
				}
			};

			inline constexpr copy_backward_fn copy_backward{};

			struct copy_if_fn
			{
				// ALIAS TEMPLATE copy_if_result
				template <class _In, class _Out>
				using copy_if_result = ExperimentalExtensions::CPP2020_SimpleRange::in_out_result<_In, _Out>;

				template< std::input_iterator I, std::sentinel_for<I> S, std::weakly_incrementable O,
				class Proj = std::identity,
				std::indirect_unary_predicate<std::projected<I, Proj>> Pred > requires std::indirectly_copyable<I, O>
				constexpr copy_if_result<I, O> operator()(I first, S last, O result, Pred pred, Proj proj = {}) const
				{
					for (; first != last; ++first)
					{
						if (std::invoke(pred, std::invoke(proj, *first)))
						{
							*result = *first;
							++result;
						}
					}

					return { std::move(first), std::move(result) };
				}

				template< std::ranges::input_range R, std::weakly_incrementable O,
				class Proj = std::identity,
				std::indirect_unary_predicate<
				std::projected<std::ranges::iterator_t<R>, Proj>> Pred > requires std::indirectly_copyable<std::ranges::iterator_t<R>, O>
				constexpr copy_if_result<std::ranges::borrowed_iterator_t<R>, O> operator()(R&& r, O result, Pred pred, Proj proj = {}) const
				{
					return (*this)(std::ranges::begin(r), std::ranges::end(r),
						std::move(result),
						std::ref(pred), std::ref(proj));
				}
			};

			inline constexpr copy_if_fn copy_if;

			struct move_fn
			{
				// ALIAS TEMPLATE move_result
				template <class _In, class _Out>
				using move_result = ExperimentalExtensions::CPP2020_SimpleRange::in_out_result<_In, _Out>;

				template<std::input_iterator I, std::sentinel_for<I> S, std::weakly_incrementable O> requires std::indirectly_movable<I, O>
				constexpr std::ranges::move_result<I, O>
				operator()(I first, S last, O result) const
				{
					for (; first != last; ++first, ++result)
						*result = std::ranges::iter_move(first);
					return { std::move(first), std::move(result) };
				}
				template<std::ranges::input_range R, std::weakly_incrementable O> requires std::indirectly_movable<std::ranges::iterator_t<R>, O>
				constexpr std::ranges::move_result<std::ranges::borrowed_iterator_t<R>, O>
				operator()(R&& r, O result) const
				{
					return (*this)(std::ranges::begin(r), std::ranges::end(r), std::move(result));
				}
			};

			inline constexpr move_fn move{};

			
			struct move_backward_fn
			{
				// ALIAS TEMPLATE copy_backward_result
				template <class _In, class _Out>
				using move_backward_result = ExperimentalExtensions::CPP2020_SimpleRange::in_out_result<_In, _Out>;

				template<std::bidirectional_iterator I1, std::sentinel_for<I1> S1, std::bidirectional_iterator I2> requires std::indirectly_movable<I1, I2>
				constexpr move_backward_result<I1, I2>
				operator()(I1 first, S1 last, I2 result) const
				{
					auto i{ last };
					for (; i != first; *--result = std::ranges::iter_move(--i));
					return { std::move(last), std::move(result) };
				}

				template<std::ranges::bidirectional_range R, std::bidirectional_iterator I> requires std::indirectly_movable<std::ranges::iterator_t<R>, I>
				constexpr move_backward_result<std::ranges::borrowed_iterator_t<R>, I>
				operator()(R&& r, I result) const
				{
					return (*this)(std::ranges::begin(r), std::ranges::end(r), std::move(result));
				}
			};

			inline constexpr move_backward_fn move_backward{};
		}

		#endif
	}
}