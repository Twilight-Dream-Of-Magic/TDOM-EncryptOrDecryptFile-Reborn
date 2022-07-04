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

//通用安全工具
//Common Security Tools
namespace CommonSecurity
{
	//using namespace UtilTools::DataFormating;

	//Function to left shift (number) by (count) bits
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	inline IntegerType Binary_SafeLeftShift( IntegerType NumberValue, IntegerType MoveShiftCount, bool AllowOverBitwise = false )
	{
		constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;

		if ( MoveShiftCount > 0 )
		{
			if ( MoveShiftCount > BitDigits && AllowOverBitwise == false )
			{
				MoveShiftCount = BitDigits;
			}
			return static_cast<IntegerType>( NumberValue << MoveShiftCount );
		}
		else if ( MoveShiftCount == 0 )
		{
			return NumberValue;
		}
		else if ( MoveShiftCount < 0 )
		{
			return Binary_RightShift<IntegerType>( NumberValue, ~MoveShiftCount + 1 );
		}
	}

	//Function to right shift (number) by (count) bits
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	inline IntegerType Binary_SafeRightShift( IntegerType NumberValue, IntegerType MoveShiftCount, bool AllowOverBitwise = false )
	{
		constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;

		if ( MoveShiftCount > 0 )
		{
			if ( MoveShiftCount > BitDigits && AllowOverBitwise == false )
			{
				MoveShiftCount = BitDigits;
			}
			return static_cast<IntegerType>( NumberValue >> MoveShiftCount );
		}
		else if ( MoveShiftCount == 0 )
		{
			return NumberValue;
		}
		else if ( MoveShiftCount < 0 )
		{
			return Binary_LeftShift<IntegerType>( NumberValue, ~MoveShiftCount + 1 );
		}
	}

	//Function to left rotate (number) by (count) bits
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	inline IntegerType Binary_LeftRotateMove( IntegerType NumberValue, IntegerType RotationCount )
	{
		constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;
		const auto	   MoveFromRemainder = RotationCount % BitDigits;
		if ( MoveFromRemainder > 0 )
		{
			return static_cast<IntegerType>( static_cast<IntegerType>( NumberValue << MoveFromRemainder ) | static_cast<IntegerType>( NumberValue >> ( BitDigits - MoveFromRemainder ) ) );
		}
		else if ( MoveFromRemainder == 0 )
		{
			return NumberValue;
		}
		else
		{
			return Binary_LeftRotateMove<IntegerType>( NumberValue, ~MoveFromRemainder + 1 );
		}
	}

	//Function to right rotate (number) by (count) bits
	template <typename IntegerType>
	requires std::is_integral_v<IntegerType>
	inline IntegerType Binary_RightRotateMove( IntegerType NumberValue, IntegerType RotationCount )
	{
		constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;
		const auto	   MoveFromRemainder = RotationCount % BitDigits;
		if ( MoveFromRemainder > 0 )
		{
			return static_cast<IntegerType>( static_cast<IntegerType>( NumberValue >> MoveFromRemainder ) | static_cast<IntegerType>( NumberValue << ( BitDigits - MoveFromRemainder ) ) );
		}
		else if ( MoveFromRemainder == 0 )
		{
			return NumberValue;
		}
		else
		{
			return Binary_RightRotateMove<IntegerType>( NumberValue, ~MoveFromRemainder + 1 );
		}
	}

	#if 0

	template <size_t BitDigits>
	inline void BinarySet_LeftRotateMove( std::bitset<BitDigits>& binaryData, size_t RotationCount )
	{
		const size_t MoveFromRemainder = RotationCount % BitDigits;
		( ( binaryData << RotationCount ) | ( binaryData >> ( BitDigits - MoveFromRemainder ) ) );
	}

	template <size_t BitDigits>
	inline void BinarySet_RightRotateMove( std::bitset<BitDigits>& binaryData, size_t RotationCount )
	{
		const size_t MoveFromRemainder = RotationCount % BitDigits;
		( ( binaryData >> RotationCount ) | ( binaryData << ( BitDigits - MoveFromRemainder ) ) );
	}

	#endif

	namespace RNG_SimpleImplementation
	{
		class ExampleGenerator
		{

		private:

			int compute_number( void )
			{
				//1103515245 is magic number
				_SEED_NUMBER_ = ( _SEED_NUMBER_ * 0x41c64e6dU + 0x3039U ) & 0x7fffffff;
				return _SEED_NUMBER_;
			}
	
		public:

			static unsigned int _SEED_NUMBER_;

			explicit ExampleGenerator()
			{
				_SEED_NUMBER_ = 1;
			}

			ExampleGenerator( std::random_device& random_device_object )
			{
				_SEED_NUMBER_ = random_device_object();
			}

			ExampleGenerator( int seed_number )
			{
				_SEED_NUMBER_ = seed_number;
			}

			~ExampleGenerator()
			{
				_SEED_NUMBER_ = 0;
			}

			void seed( int seed_number )
			{
				_SEED_NUMBER_ = static_cast<unsigned int>( seed_number & 0x7fffffffU );
			}

			int operator()()
			{
				return this->compute_number();
			}

			static constexpr int min()
			{
				return std::numeric_limits<int>::min();
			}

			static constexpr int max()
			{
				return std::numeric_limits<int>::max();
			}

			ExampleGenerator(ExampleGenerator& _object) = delete;
			ExampleGenerator& operator=(const ExampleGenerator& _object) = delete;
		};

		class ExampleGenerator2
		{

		private:

			int compute_number( int& seed_number )
			{
				seed_number = seed_number * 214013 + 2531011;
				return (seed_number >> 16) & 0x7fff;
			}
	
		public:

			static int _SEED_NUMBER_;

			explicit ExampleGenerator2()
			{
				_SEED_NUMBER_ = 1;
			}

			ExampleGenerator2( std::random_device& random_device_object )
			{
				_SEED_NUMBER_ = random_device_object();
			}

			ExampleGenerator2( unsigned int seed_number )
			{
				_SEED_NUMBER_ = seed_number;
			}

			~ExampleGenerator2()
			{
				_SEED_NUMBER_ = 0;
			}

			void seed( int seed_number )
			{
				_SEED_NUMBER_ = static_cast<unsigned int>( seed_number & 0x7fffU );
			}

			int operator()()
			{
				int one_number = compute_number(_SEED_NUMBER_);
				int two_number = compute_number(_SEED_NUMBER_);
				return (one_number | (two_number << 15) );
			}

			static constexpr int min()
			{
				return 0x0;
			}

			static constexpr int max()
			{
				return 0x7fff;
			}

			ExampleGenerator2(ExampleGenerator2& _object) = delete;
			ExampleGenerator2& operator=(const ExampleGenerator2& _object) = delete;
		};

		/*
			An improved random number generation package. 
			In addition to the standard rand()/srand() like interface, this package also has a special state info interface.
			The initial_state() routine is called with a seed, an array of bytes, and a count of how many bytes are being passed in;
			this array is then initialized to contain information for random number generation with that much state information. 
			Good sizes for the amount of state information are 32, 64, 128, and 256 bytes.
			The state can be switched by calling the change_state() function with the same array as was initialized with initial_state().
			By default, the package runs with 128 bytes of state information and generates far better random numbers than a linear congruential generator.  
			If the amount of state information is less than 32 bytes, a simple linear congruential R.N.G. is used.
			Internally, the state information is treated as an array of longs; 
			the zeroth element of the array is the type of R.N.G. being used (small integer); the remainder of the array is the state information for the R.N.G.
			Thus, 32 bytes of state information will give 7 longs worth of state information, which will allow a degree seven polynomial.
			(Note: The zeroth word of state information also has some other information stored in it; see setstate for details).
			The random number generation technique is a linear feedback shift register approach, employing trinomials
			(since there are fewer terms to sum up that way).  In this approach, the least significant bit of all the numbers in the state table will act as a linear feedback shift register,
			and will have period 2^deg - 1 (where deg is the degree of the polynomial being used, assuming that the polynomial is irreducible and primitive).
			The higher order bits will have longer periods, since their values are also influenced by pseudo-random carries out of the lower bits. 
			The total period of the generator is approximately deg*(2**deg - 1); thus doubling the amount of state information has a vast influence on the period of the generator.
			Note: The deg*(2**deg - 1) is an approximation only good for large deg, when the period of the shift register is the dominant factor.
			With deg equal to seven, the period is actually much longer than the 7*(2**7 - 1) predicted by this formula.
			
			Reference code:

			https://sourceware.org/git/?p=glibc.git

			https://code.woboq.org/userspace/glibc/stdlib/stdlib.h.html
			https://code.woboq.org/userspace/glibc/stdlib/rand.c.html
			https://code.woboq.org/userspace/glibc/stdlib/rand_r.c.html
			https://code.woboq.org/userspace/glibc/stdlib/random.c.html
			https://code.woboq.org/userspace/glibc/stdlib/random_r.c.html

		*/
		class GNU_C_LibraryGenerator
		{
			static constexpr std::uint32_t _BREAK_BYTE_0_ = 8;
			static constexpr std::uint32_t _BREAK_BYTE_1_ = 32;
			static constexpr std::uint32_t _BREAK_BYTE_2_ = 64;
			static constexpr std::uint32_t _BREAK_BYTE_3_ = 128;
			static constexpr std::uint32_t _BREAK_BYTE_4_ = 256;

			std::deque<std::pair<unsigned int, std::span<const char>>> state_argument_double_queue;

			enum class RandomMathPolynomialType : unsigned int
			{
				//linearCongruential
				TYPE_0 = 0,

				//_00_
				TYPE_1 = 1,

				//_01_
				TYPE_2 = 2,

				//_02_
				TYPE_3 = 3,

				//_03_
				TYPE_4 = 4,

				/* Array versions of the above information to make code run faster. Relies on fact that TYPE_i == i.  */
				LIMIT_TYPES = 5
			};
			
			/*
				For each of the currently supported random number generators,
				we have a break value on the amount of state information
				(you need at least this many bytes of state info to support this random number generator),
				a degree for the polynomial (actually a trinomial) that the R.N.G. is based on,
				and separation between the two lower order coefficients of the trinomial.
			*/
			struct RandomMathPolynomialTypeConfigData
			{
				static constexpr std::array<std::uint32_t, 2> _LINEAR_CONGRUENTIAL_ {0, 0};

				//Math Polynomial: x(^)7 + x(^)3 + 1
				static constexpr std::array<std::uint32_t, 2> _00_ {7, 3};

				//Math Polynomial: x(^)15 + x + 1
				static constexpr std::array<std::uint32_t, 2> _01_ {15, 1};

				//Math Polynomial: x(^)31 + x(^)3 + 1
				static constexpr std::array<std::uint32_t, 2> _02_ {31, 3};

				//Math Polynomial: x(^)63 + x + 1
				static constexpr std::array<std::uint32_t, 2> _03_ {63, 1};

				static constexpr std::array<std::uint32_t, 2> lookup(RandomMathPolynomialType math_polynomial_type)
				{
					switch (math_polynomial_type)
					{
						case RandomMathPolynomialType::TYPE_0:
							return _LINEAR_CONGRUENTIAL_;
							break;
						case RandomMathPolynomialType::TYPE_1:
							return _00_;
							break;
						case RandomMathPolynomialType::TYPE_2:
							return _01_;
							break;
						case RandomMathPolynomialType::TYPE_3:
							return _02_;
							break;
						case RandomMathPolynomialType::TYPE_4:
							return _03_;
							break;
						default:
							break;
					}
				}

				static constexpr std::pair<std::uint32_t, std::uint32_t> info(RandomMathPolynomialType math_polynomial_type)
				{
					auto polynomial_type_config_data = lookup(math_polynomial_type);

					/*
						std::pair<std::uint32_t, std::uint32_t> math_polynomial_info( polynomial_type_config_data[0], polynomial_type_config_data[1] );
						//auto& [degree_value, separation_value] = math_polynomial_info;
					*/

					return std::pair<std::uint32_t, std::uint32_t>( polynomial_type_config_data[0], polynomial_type_config_data[1] );
				}
			};

			struct RandomStateData
			{

				/*
					The following things are the pointer to the state information table, the type of the current generator,
					the degree of the current polynomial being used, and the separation between the two pointers.
					Note that for efficiency of random, we remember the first location of the state information, not the zeroth.
					Hence it is valid to access state[-1], which is used to store the type of the R.N.G.
					Also, we remember the last location, 
					since this is more efficient than indexing every time to find the address of the last element to see if the front and rear pointers have wrapped. 
				*/

				/* Front pointer. (Iterator pointer a) */
				int32_t* front_pointer = nullptr;
				/* Rear pointer. (Iterator pointer b) */
				int32_t* rear_pointer = nullptr;
				/* Array of state values. */
				int32_t* left_boundaries_state_element_pointer = nullptr;
				/* Pointer behind state table. */
				int32_t* right_boundaries_state_element_pointer = nullptr;

				/* Type of random number generator. */
				RandomMathPolynomialType math_polynomial_type;
				
				/* Degree of random number generator. */
				int degree = 0;
				 /* Degree of random number generator. */
				int separation = 0;

				/* Initially, everything is set up as if from:
				   initial_state(1, bytes_state, 128);
				   Note that this initialization takes advantage of the fact that seed_random advances the front and rear pointers 10*rand_deg times,
				   and hence the rear pointer which starts at 0 will also end up at zero;
				   thus the zeroth element of the state information,
				   which contains info about the current position of the rear pointer is just
					(MAX_TYPES * (rear_pointer - state)) + TYPE_3 == TYPE_3.

					std::array<std::int32_t, 31 + 1> StateDataTable
					{
						static_cast<std::int32_t>(RandomMathPolynomialType::TYPE_3),
						-1726662223, 379960547, 1735697613, 1040273694, 1313901226,
						1627687941, -179304937, -2073333483, 1780058412, -1989503057,
						-615974602, 344556628, 939512070, -1249116260, 1507946756,
						-812545463, 154635395, 1388815473, -1926676823, 525320961,
						-1009028674, 968117788, -123449607, 1284210865, 435012392,
						-2017506339, -911064859, -370259173, 1132637927, 1398500161,
						-205601318
					};
				*/

				std::vector<std::int32_t> StateDataTable = std::vector<std::int32_t>(1, 0x00);

				void change_state_table(unsigned int seed_number, bool is_initial_mode)
				{
					std::int32_t word = seed_number;

					std::span<int32_t> update_state_span(left_boundaries_state_element_pointer, left_boundaries_state_element_pointer + this->degree);

					for(std::size_t index = 0; index < this->degree; ++index)
					{
						/* 
							This does:
							state[index] = (16807 * state[index - 1]) update% 2147483647;
							but avoids overflowing 31 bits.
						*/

						int high_part = word / 127773;
						int low_part = word % 127773;
						word = 16807 * low_part - 2836 * high_part;

						if(word < 0)
							word += std::numeric_limits<int>::max();

						if(is_initial_mode)
						{
							update_state_span[index] += word;
							this->StateDataTable[index] = update_state_span[index];
						}
						else
						{
							update_state_span[index] += word;
							this->StateDataTable[index] += update_state_span[index];
						}
					}

					if(this->math_polynomial_type != RandomMathPolynomialType::TYPE_0)
					{
						left_boundaries_state_element_pointer = StateDataTable.data() + 1;
						right_boundaries_state_element_pointer = &(StateDataTable[std::ranges::size(StateDataTable) - 1]) + 1;

						this->front_pointer = &(this->StateDataTable[this->separation]);
						this->rear_pointer = &(this->StateDataTable[0]);
					}
				}

				RandomStateData(RandomMathPolynomialType math_polynomial_type_value)
					:
					math_polynomial_type(math_polynomial_type_value)
				{
					const auto& [degree_value, separation_value] = RandomMathPolynomialTypeConfigData::info(math_polynomial_type_value);

					degree = degree_value;
					separation = separation_value;

					if(this->math_polynomial_type != RandomMathPolynomialType::TYPE_0)
					{
						StateDataTable[0] = static_cast<std::int32_t>(math_polynomial_type);
						StateDataTable.resize(degree);

						front_pointer = StateDataTable.data() + (degree + 1);
						rear_pointer = StateDataTable.data() + 1;

						left_boundaries_state_element_pointer = StateDataTable.data() + 1;
						right_boundaries_state_element_pointer = &(StateDataTable[std::ranges::size(StateDataTable) - 1]) + 1;
					}
				}

				~RandomStateData()
				{
					front_pointer = nullptr;
					rear_pointer = nullptr;
					left_boundaries_state_element_pointer = nullptr;
					right_boundaries_state_element_pointer = nullptr;
					degree = 0;
					separation = 0;

					if(this->math_polynomial_type != RandomMathPolynomialType::TYPE_0)
					{
						StateDataTable.clear();
						StateDataTable.shrink_to_fit();
					}
				}
			};

			RandomStateData unsafe_random_state;

		private:

			/*
				If we are using the trivial TYPE_0 R.N.G., just do the old linear congruential bit.
				Otherwise, we do our fancy trinomial stuff, which is the same in all the other cases due to all the global variables that have been set up.
				The basic operation is to add the number at the rear pointer into the one at the front pointer.
				Then both pointers are advanced to the next location cyclically in the table.
				The value returned is the sum generated, reduced to 31 bits by throwing away the "least random" low bit.
				Note: The code takes advantage of the fact that both the front and rear pointers can't wrap on the same call by not testing the rear pointer if the front one has wrapped.
				Returns a 31-bit random number.
			*/
			bool compute_number(RandomStateData& random_state_buffer, int& result_number)
			{
				if(std::addressof(random_state_buffer) == nullptr || std::addressof(result_number) == nullptr)
					return false;

				int32_t* left_boundaries_state_element_pointer = random_state_buffer.left_boundaries_state_element_pointer;

				if(random_state_buffer.math_polynomial_type == RandomMathPolynomialType::TYPE_0)
				{
					//1103515245 is magic number
					std::int32_t value = ( (left_boundaries_state_element_pointer[0] * 0x41c64e6dU) + 0x3039U ) & 0x7fffffff;
					left_boundaries_state_element_pointer[0] = value;
					result_number = value;
				}
				else
				{
					std::int32_t* front_pointer = random_state_buffer.front_pointer;
					std::int32_t* rear_pointer = random_state_buffer.rear_pointer;

					std::int32_t* right_boundaries_state_element_pointer = random_state_buffer.right_boundaries_state_element_pointer;
					
					std::uint32_t value = *front_pointer += static_cast<std::uint32_t>(*rear_pointer);

					/* Chunking least random bit.  */
					result_number = value >> 1;
					++front_pointer;
					if(front_pointer >= right_boundaries_state_element_pointer)
					{
						front_pointer = left_boundaries_state_element_pointer;
						++rear_pointer;
					}
					else
					{
						++rear_pointer;
						if(rear_pointer >= right_boundaries_state_element_pointer)
							rear_pointer = left_boundaries_state_element_pointer;
					}

					random_state_buffer.front_pointer = front_pointer;
					random_state_buffer.rear_pointer = rear_pointer;
				}

				return true;
			}

			/*
				Initialize the random number generator based on the given seed.
				If the type is the trivial no-state-information type, just remember the seed.
				Otherwise, initializes RandomStateData::DataTable[] based on the given "seed" via a linear congruential generator.
				Then, the pointers are set to known locations that are exactly rand_sep places apart.
				Lastly, it cycles the state information a given number of times to get rid of any initial dependencies introduced by the L.C.R.N.G.
				Note that the initialization of RandomStateData::DataTable[] for default usage relies on values produced by this routine.
			*/
			bool compute_seed_random(std::pair<unsigned int, std::span<const char>>& state_argument, RandomStateData& random_state_buffer, bool is_update_mode)
			{
				if(&random_state_buffer == nullptr)
					return false;

				if(random_state_buffer.math_polynomial_type >= RandomMathPolynomialType::LIMIT_TYPES)
					return false;

				auto& [seed, bytes_state_span] = state_argument;

				std::int32_t* word_state_pointer = std::bit_cast<std::int32_t*>( bytes_state_span.data() ) + 1;
				
				random_state_buffer.left_boundaries_state_element_pointer = word_state_pointer;
				random_state_buffer.right_boundaries_state_element_pointer = &( word_state_pointer[random_state_buffer.degree] );

				/* We must make sure the seed is not 0. Take arbitrarily 1 in this case.  */
				if(seed == 0)
					seed = 1;

				random_state_buffer.left_boundaries_state_element_pointer[0] = seed;

				state_argument_double_queue.push_back(state_argument);

				random_state_buffer.change_state_table(seed, !is_update_mode);

				if(random_state_buffer.math_polynomial_type == RandomMathPolynomialType::TYPE_0)
					return true;

				std::int32_t keyword_counter = random_state_buffer.degree;

				keyword_counter *= 10;
				while (--keyword_counter >= 0)
				{
					std::int32_t discard_result_number;
					this->compute_number(random_state_buffer, discard_result_number);
				}

				return true;
			}

			/*
				Initialize the state information in the given array of bytes_state_size bytes for future random number generation. 
				Based on the number of bytes we are given, 
				and the break values for the different R.N.G.'s,
				we choose the best (largest) one we can and set things up for it. 
				seed_random is then called to initialize the state information. 
				Note that on return from seed_random, 
				we set state[-1] to be the type multiplexed with the current value of the rear pointer;
				this is so successive calls to initstate won't lose this information and will be able to restart with update_state.
				Note: The first thing we do is save the current state, if any, just like
				update_state so that it doesn't matter when initial_state is called.
				Returns true-value on success, false-value on failure.
			*/
			std::optional<RandomStateData> _initial_state_(std::pair<unsigned int, std::span<const char>>& state_argument, RandomStateData& new_random_state_buffer)
			{
				auto& bytes_state_span = state_argument.second;

				if(&new_random_state_buffer == nullptr || bytes_state_span.empty() || bytes_state_span.data() == nullptr)
					return std::nullopt;

				std::size_t bytes_state_size = bytes_state_span.size();

				RandomStateData old_random_state_buffer(unsafe_random_state);

				RandomMathPolynomialType new_math_polynomial_type = RandomMathPolynomialType::LIMIT_TYPES;
				if(bytes_state_size >= _BREAK_BYTE_3_)
					new_math_polynomial_type = bytes_state_size < _BREAK_BYTE_4_ ? RandomMathPolynomialType::TYPE_3 : RandomMathPolynomialType::TYPE_4;
				else if(bytes_state_size < _BREAK_BYTE_0_)
						return std::nullopt;
				else if(bytes_state_size < _BREAK_BYTE_1_)
					new_math_polynomial_type = RandomMathPolynomialType::TYPE_0;
				else
					new_math_polynomial_type = bytes_state_size < _BREAK_BYTE_2_ ? RandomMathPolynomialType::TYPE_1 : RandomMathPolynomialType::TYPE_2;

				const auto& [degree_value, separation_value] = RandomMathPolynomialTypeConfigData::info(new_math_polynomial_type);
				new_random_state_buffer.math_polynomial_type = new_math_polynomial_type;
				new_random_state_buffer.degree = degree_value;
				new_random_state_buffer.separation = separation_value;

				this->compute_seed_random(state_argument, new_random_state_buffer, false);

				return old_random_state_buffer;
			}

			/*
				Restore the state from the given state array.
				Note: It is important that we also remember the locations of the pointers in the current state information,
				and restore the locations of the pointers from the old state information.
				This is done by multiplexing the pointer location into the zeroth word of the state information.
				Note that due to the order in which things are done, 
				it is OK to call update_state with the same state as the current state
				Returns true-value on success, false-value on failure. 
			*/
			bool _update_state_(std::pair<unsigned int, std::span<const char>>& state_argument, RandomStateData& random_state_buffer)
			{
				auto& bytes_state_span = state_argument.second;

				if(&random_state_buffer == nullptr || bytes_state_span.empty() || bytes_state_span.data() == nullptr)
					return false;

				std::size_t bytes_state_size = bytes_state_span.size();

				RandomMathPolynomialType update_math_polynomial_type = RandomMathPolynomialType::LIMIT_TYPES;
				if(bytes_state_size >= _BREAK_BYTE_3_)
					update_math_polynomial_type = bytes_state_size < _BREAK_BYTE_4_ ? RandomMathPolynomialType::TYPE_3 : RandomMathPolynomialType::TYPE_4;
				else if(bytes_state_size < _BREAK_BYTE_0_)
						return false;
				else if(bytes_state_size < _BREAK_BYTE_1_)
					update_math_polynomial_type = RandomMathPolynomialType::TYPE_0;
				else
					update_math_polynomial_type = bytes_state_size < _BREAK_BYTE_2_ ? RandomMathPolynomialType::TYPE_1 : RandomMathPolynomialType::TYPE_2;
				
				if(update_math_polynomial_type < RandomMathPolynomialType::TYPE_0 || update_math_polynomial_type > RandomMathPolynomialType::TYPE_4)
					return false;

				const auto& [degree_value, separation_value] = RandomMathPolynomialTypeConfigData::info(update_math_polynomial_type);
				random_state_buffer.math_polynomial_type = update_math_polynomial_type;
				random_state_buffer.degree = degree_value;
				random_state_buffer.separation = separation_value;

				this->compute_seed_random(state_argument, random_state_buffer, true);

				return true;
			}

		public:

			std::atomic<bool> is_use_busy = false;

			void seed( std::random_device& device )
			{
				is_use_busy.wait(true, std::memory_order::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order::memory_order_seq_cst);

				std::uint32_t seed_number = device();

				this->seed( seed_number );

				is_use_busy.store(false, std::memory_order::memory_order_relaxed);

				is_use_busy.notify_all();
			}

			void seed( int seed_number )
			{
				is_use_busy.wait(true, std::memory_order::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order::memory_order_seq_cst);

				if(!state_argument_double_queue.empty())
				{
					std::pair<unsigned int, std::span<const char>> state_argument = state_argument_double_queue.back();
					state_argument_double_queue.pop_back();
					state_argument.first = seed_number;

					this->compute_seed_random(state_argument, unsafe_random_state, false);
				}
				else
				{
					unsafe_random_state.change_state_table(seed_number, true);
				}

				is_use_busy.store(false, std::memory_order::memory_order_relaxed);

				is_use_busy.notify_all();
			}

			int operator()()
			{
				is_use_busy.wait(true, std::memory_order::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order::memory_order_seq_cst);

				std::int32_t result_number = 0;
				this->compute_number(unsafe_random_state, result_number);

				is_use_busy.store(false, std::memory_order::memory_order_relaxed);

				is_use_busy.notify_all();

				return result_number;
			}

			/*
				Initialize the random number generator to use state buffer (STATEBUFFFER),
				of length (STATELENTH), and seed it with SEED. 
				Optimal lengths are 8, 16, 32, 64, 128 and 256, the bigger the better;
				values less than 8 will cause an error and values greater than 256 will be rounded down.

				Initialize the state information in the given array of N bytes for future random number generation.
				Based on the number of bytes we are given, and the break values for the different R.N.G.'s,
				we choose the best (largest) one we can and set things up for it.
				'seed_random' is then called to initialize the state information.
				Note that on return from 'seed_random', we set state[-1] to be the type multiplexed with the current value of the rear pointer;
				this is so successive calls to initial_state won't lose this information and will be able to restart with update_state.
				Note: The first thing we do is save the current state, if any, just like change_state so that it doesn't matter when initstate is called.
			*/
			std::optional<std::pair<RandomStateData, RandomStateData>> initial_state(std::pair<unsigned int, std::span<const char>>& state_argument)
			{
				is_use_busy.wait(true, std::memory_order::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order::memory_order_seq_cst);

				auto random_state_data = this->_initial_state_(state_argument, this->unsafe_random_state);

				is_use_busy.store(false, std::memory_order::memory_order_relaxed);

				is_use_busy.notify_all();

				if(random_state_data.has_value())
				{
					auto& old_random_state_data = random_state_data.value();
					auto& new_random_state_data = this->unsafe_random_state;
					return std::make_pair(old_random_state_data, new_random_state_data);
				}
				else
				{
					return std::nullopt;
				}
			}

			/*
				Switch the random number generator to state buffer (STATEBUFFFER),
				which should have been previously initialized by `initial_state'. 

				Restore the state from the given state array.
				Note: It is important that we also remember the locations of the pointers in the current state information, 
				and restore the locations of the pointers from the old state information.
				This is done by multiplexing the pointer location into the zeroth word of the state information.
				Note that due to the order in which things are done,
				it is OK to call update_state with the same state as the current state
			*/
			std::optional<RandomStateData> update_state(std::pair<unsigned int, std::span<const char>>& state_argument, RandomStateData& default_random_state_data)
			{
				is_use_busy.wait(true, std::memory_order::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order::memory_order_seq_cst);

				bool is_done = this->_update_state_(state_argument, default_random_state_data);

				is_use_busy.store(false, std::memory_order::memory_order_relaxed);

				is_use_busy.notify_all();

				if(is_done)
					return this->unsafe_random_state;
				else
					return std::nullopt;
			}

			void change_state(RandomStateData& initialized_random_state_data)
			{
				is_use_busy.wait(true, std::memory_order::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order::memory_order_seq_cst);

				unsafe_random_state = initialized_random_state_data;

				is_use_busy.store(false, std::memory_order::memory_order_relaxed);

				is_use_busy.notify_all();
			}

			auto access_history_state_argument()
			{
				return state_argument_double_queue;
			}

			RandomStateData build_default_random_state_data(unsigned int type_number)
			{
				return RandomStateData(static_cast<RandomMathPolynomialType>(type_number));
			}

			int easy_compute_number( std::random_device& device )
			{
				is_use_busy.wait(true, std::memory_order::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order::memory_order_seq_cst);

				std::uint32_t seed_number = device();

				auto result_random_number = this->easy_compute_number( seed_number );

				is_use_busy.store(false, std::memory_order::memory_order_relaxed);

				is_use_busy.notify_all();

				return result_random_number;
			}

			int easy_compute_number( unsigned int& seed_number )
			{
				is_use_busy.wait(true, std::memory_order::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order::memory_order_seq_cst);

				if(seed_number == 0)
					seed_number = 1;

				unsigned int update_value = seed_number;
				int result_random_number = 0;

				//1103515245 is magic number
				update_value = ( update_value * 0x41c64e6dU + 0x3039U );
				result_random_number = static_cast<unsigned int>( ( update_value / 0x1001e ) % 0x800 );

				update_value = ( update_value * 0x41c64e6dU + 0x3039U );
				result_random_number <<= 10;
				result_random_number ^= static_cast<unsigned int>( ( update_value / 0x1001e ) % 0x400 );

				update_value = ( update_value * 0x41c64e6dU + 0x3039U );
				result_random_number <<= 10;
				result_random_number ^= static_cast<unsigned int>( ( update_value / 0x1001e ) % 0x400 );

				seed_number = update_value;

				is_use_busy.store(false, std::memory_order::memory_order_relaxed);

				is_use_busy.notify_all();

				return result_random_number;
			}

			GNU_C_LibraryGenerator(unsigned int type_number)
				:
				unsafe_random_state(static_cast<RandomMathPolynomialType>(type_number))
			{
				if(type_number < static_cast<unsigned int>(RandomMathPolynomialType::TYPE_0) || type_number > static_cast<unsigned int>(RandomMathPolynomialType::TYPE_4))
					my_cpp2020_assert(false,"", std::source_location::current());
			}

			~GNU_C_LibraryGenerator() = default;

		};
	}

	/*
		Reference source code: https://github.com/Reputeless/Xoshiro-cpp/
		https://gist.github.com/wreien/442e6f89f125f9b4a9919299a7536fd5
		Rudimentary C++20 xoshiro256** uniform random bit generator implementation
	*/
	namespace RNG_Xoshiro
	{
		// An implementation of xoshiro256** (https://vigna.di.unimi.it/xorshift/)
		// wrapped to fit the C++11 RandomNumberGenerator requirements.
		// This allows us to use it with all the other facilities in <random>.
		//
		// Credits go to David Blackman and Sebastiano Vigna.
		//
		// TODO: make generic? (parameterise scrambler/width/hyperparameters/etc.)
		// Not as easy to do nicely as it might sound,
		// and this as it is is good enough for my purposes.
		struct xoshiro256
		{
			static constexpr int num_state_words = 4;
			using state_type = std::uint64_t[ num_state_words ];
			using result_type = std::uint64_t;

			// cannot initialize with an all-zero state
			constexpr xoshiro256() noexcept : state { 12, 34, 56, 78 } {}

			// using SplitMix64 generator to initialize the state;
			// using a different generator helps prevent seed correlation
			explicit constexpr xoshiro256( result_type s ) noexcept
			{
				auto splitmix64 = [ x = s ]() mutable {
					auto z = ( x += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;
					return z ^ ( z >> 31 );
				};
				std::ranges::generate( state, splitmix64 );
			}

			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			explicit constexpr xoshiro256( SeedSeq& q )
			{
				std::uint32_t temp_state[ num_state_words * 2 ];
				q.generate( std::begin( temp_state ), std::end( temp_state ) );
				for ( int i = 0; i < num_state_words; ++i )
				{
					state[ i ] = temp_state[ i * 2 ];
					state[ i ] <<= 32;
					state[ i ] |= temp_state[ i * 2 + 1 ];
				}
			}

			constexpr void seed() noexcept
			{
				*this = xoshiro256();
			}
			constexpr void seed( result_type s ) noexcept
			{
				*this = xoshiro256( s );
			}
			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			constexpr void seed( SeedSeq& q )
			{
				*this = xoshiro256( q );
			}

			void seed( std::random_device device ) noexcept
			{
				*this = xoshiro256( device() );
			}

			static constexpr result_type min() noexcept
			{
				return std::numeric_limits<result_type>::min();
			}
			static constexpr result_type max() noexcept
			{
				return std::numeric_limits<result_type>::max();
			}

			constexpr result_type operator()() noexcept
			{
				// xorshiro256+:
				// const auto result = state[0] + state[3];\
				// xorshiro256++:
				// const auto result = std::rotl(state[0] + state[3], 23) + state[0];

				// xorshiro256**:
				const auto result = std::rotl( state[ 1 ] * 5, 7 ) * 9;
				const auto t = state[ 1 ] << 17;

				state[ 2 ] ^= state[ 0 ];
				state[ 3 ] ^= state[ 1 ];
				state[ 1 ] ^= state[ 2 ];
				state[ 0 ] ^= state[ 3 ];

				state[ 2 ] ^= t;
				state[ 3 ] = std::rotl( state[ 3 ], 45 );

				return result;
			}

			constexpr void discard( unsigned long long z ) noexcept
			{
				while ( z-- )
					operator()();
			}

			// jump 2^128 steps;
			// use it to create 2^128 non-overlapping sequences for parallel computations
			constexpr void jump() noexcept
			{
				constexpr std::uint64_t jump_table[] = {
					0x180ec6d33cfd0aba,
					0xd5a61266f0c9392c,
					0xa9582618e03fc9aa,
					0x39abdc4529b1661c,
				};

				state_type s {};
				for ( int i = 0; i < std::ssize( jump_table ); i++ )
				{
					for ( int b = 0; b < 64; b++ )
					{
						if ( jump_table[ i ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							s[ 0 ] ^= state[ 0 ];
							s[ 1 ] ^= state[ 1 ];
							s[ 2 ] ^= state[ 2 ];
							s[ 3 ] ^= state[ 3 ];
						}
						operator()();
					}
				}

				state[ 0 ] = s[ 0 ];
				state[ 1 ] = s[ 1 ];
				state[ 2 ] = s[ 2 ];
				state[ 3 ] = s[ 3 ];
			}

			// jump 2^192 steps;
			// use it to create 2^64 starting points,
			// from which jump() can create 2^64 non-overlapping sequences
			constexpr void long_jump() noexcept
			{
				constexpr std::uint64_t long_jump_table[] = {
					0x76e15d3efefdcbbf,
					0xc5004e441c522fb3,
					0x77710069854ee241,
					0x39109bb02acbe635,
				};

				state_type s {};
				for ( int i = 0; i < std::ssize( long_jump_table ); i++ )
				{
					for ( int b = 0; b < 64; b++ )
					{
						if ( long_jump_table[ i ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							s[ 0 ] ^= state[ 0 ];
							s[ 1 ] ^= state[ 1 ];
							s[ 2 ] ^= state[ 2 ];
							s[ 3 ] ^= state[ 3 ];
						}
						operator()();
					}
				}

				state[ 0 ] = s[ 0 ];
				state[ 1 ] = s[ 1 ];
				state[ 2 ] = s[ 2 ];
				state[ 3 ] = s[ 3 ];
			}

			constexpr bool operator==( const xoshiro256& ) const noexcept = default;

			template <typename CharT, typename Traits>
			friend std::basic_ostream<CharT, Traits>& operator<<( std::basic_ostream<CharT, Traits>& os, const xoshiro256& e )
			{
				os << e.state[ 0 ];
				for ( int i = 1; i < num_state_words; ++i )
				{
					os.put( os.widen( ' ' ) );
					os << e.state[ i ];
				}
				return os;
			}

			template <typename CharT, typename Traits>
			friend std::basic_istream<CharT, Traits&> operator>>( std::basic_istream<CharT, Traits>& is, xoshiro256& e )
			{
				xoshiro256 r;
				// TODO: what if ' ' is not considered whitespace?
				// Maybe more appropriate is to `.get` each space
				for ( auto& s : r.state )
					is >> s;
				if ( is )
					e = r;
				return is;
			}

		private:
			state_type state;
		};

	}  // namespace RNG_Xoshiro

	/*
		C++20 isaac cryptographically secure pseudorandom number generator implementation
		ISAAC (indirection, shift, accumulate, add, and count) is a cryptographically secure pseudorandom number generator and a stream cipher designed by Robert J. Jenkins Jr. in 1993.[1]
		The reference implementation source code was dedicated to the public domain.[2]
		https://en.wikipedia.org/wiki/ISAAC_(cipher)
		http://rosettacode.org/wiki/The_ISAAC_Cipher

		This work is derived from the ISAAC random number generator, created by Bob Jenkins,
		which he has generously put in the public domain. 
		All design credit goes to Bob Jenkins.
		Details of the algorithm, and the original C source can be found at 
		http://burtleburtle.net/bob/rand/isaacafa.html.
		This work is a C++ translation and re-packaging of the original C code to make it meet the requirements for a random number engine,
		as specified in paragraph 26.5.1.4 of the C++ language standard. 
		As such, it can be used in conjunction with other elements in the random number generation facility,
		such as distributions and engine adaptors. Created by David Curtis, 2016. Public Domain.

		Plus versions of the ISAAC and ISAAC64 algorithms, referenced by Twilight-Dream from Bob Jenkins' paper, upgrade the original algorithms and implement them.

		A cryptographically secure pseudorandom number generator (CSPRNG) or cryptographic pseudorandom number generator (CPRNG)[1] is a pseudorandom number generator (PRNG) with properties that make it suitable for use in cryptography.
		It is also loosely known as a cryptographic random number generator (CRNG) (see Random number generation § "True" vs. pseudo-random numbers).[2][3]

		Most cryptographic applications require random numbers, for example:
		key generation
		nonces
		salts in certain signature schemes, including ECDSA, RSASSA-PSS
		The "quality" of the randomness required for these applications varies. For example, creating a nonce in some protocols needs only uniqueness.
		On the other hand, the generation of a master key requires a higher quality, such as more entropy.
		And in the case of one-time pads, the information-theoretic guarantee of perfect secrecy only holds if the key material comes from a true random source with high entropy, and thus any kind of pseudorandom number generator is insufficient.

		Ideally, the generation of random numbers in CSPRNGs uses entropy obtained from a high-quality source, generally the operating system's randomness API.
		However, unexpected correlations have been found in several such ostensibly independent processes.
		From an information-theoretic point of view, the amount of randomness, the entropy that can be generated, is equal to the entropy provided by the system.
		But sometimes, in practical situations, more random numbers are needed than there is entropy available.
		Also, the processes to extract randomness from a running system are slow in actual practice. In such instances, a CSPRNG can sometimes be used.
		A CSPRNG can "stretch" the available entropy over more bits.
		https://en.wikipedia.org/wiki/Cryptographically-secure_pseudorandom_number_generator

		Reference source code:
		https://github.com/edgeofmagic/ISAAC-engine/
		https://github.com/rubycon/isaac.js/blob/master/isaac.js

		Reference paper:
		http://eprint.iacr.org/2006/438.pdf
	*/
	namespace RNG_ISAAC
	{

		/*
			RNG_ISAAC_BASE contains code common to isaac and isaac64.
			It uses CRTP (a.k.a. 'static polymorphism') to invoke specialized methods in the derived class templates,
			avoiding the cost of virtual method invocations and allowing those methods to be placed inline by the compiler.
			Applications should not specialize or instantiate this template directly.
		*/

		template<class Derived, std::size_t Alpha, class T>
		class RNG_ISAAC_BASE
		{
		public:
			using result_type = T;

		protected:
			static constexpr std::size_t state_size = 1 << Alpha;

			static constexpr result_type default_seed = 0;

			explicit RNG_ISAAC_BASE(result_type seed_number)
			{
				seed(seed_number);
			}
	
			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			explicit RNG_ISAAC_BASE( SeedSeq& number_sequence )
			{
				seed(number_sequence);
			}
	
			RNG_ISAAC_BASE(const std::vector<result_type>& seed_vector)
			{
				seed(seed_vector);
			}
	
			template<class IteratorType>
			RNG_ISAAC_BASE
			(
				IteratorType begin,
				IteratorType end,
				typename std::enable_if
				<
						std::is_integral<typename std::iterator_traits<IteratorType>::value_type>::value &&
						std::is_unsigned<typename std::iterator_traits<IteratorType>::value_type>::value
				>::type* = nullptr
			)
			{
				seed(begin, end);
			}
	
			RNG_ISAAC_BASE(std::random_device& random_device_object)
			{
				seed(random_device_object);
			}

			RNG_ISAAC_BASE(const RNG_ISAAC_BASE& other)
			{
				for (std::size_t index = 0; index < state_size; ++index)
				{
					issac_base_member_result[index] = other.issac_base_member_result[index];
					issac_base_member_memory[index] = other.issac_base_member_memory[index];
				}
				issac_base_member_register_a = other.issac_base_member_register_a;
				issac_base_member_register_b = other.issac_base_member_register_b;
				issac_base_member_register_c = other.issac_base_member_register_c;
				issac_base_member_counter = other.issac_base_member_counter;
			}

		public:

			static constexpr result_type min()
			{
				return std::numeric_limits<result_type>::min();
			}
			static constexpr result_type max()
			{
				return std::numeric_limits<result_type>::max();
			}
	
			inline void seed(result_type seed_number = default_seed)
			{
				for (std::size_t index = 0; index < state_size; ++index)
				{
					issac_base_member_result[index] = seed_number;
				}
				init();
			}
	
			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			constexpr void seed( SeedSeq& number_sequence )
			{
				std::array<result_type, state_size> seed_array;
				number_sequence.generate(seed_array.begin(), seed_array.end());
				for (std::size_t index = 0; index < state_size; ++index)
				{
					issac_base_member_result[index] = seed_array[index];
				}
				init();
			}

			template<class IteratorType>
			inline typename std::enable_if
			<
				std::is_integral<typename std::iterator_traits<IteratorType>::value_type>::value &&
				std::is_unsigned<typename std::iterator_traits<IteratorType>::value_type>::value, void
			>::type
			seed(IteratorType begin, IteratorType end)
			{
				IteratorType iterator = begin;
				for (std::size_t index = 0; index < state_size; ++index)
				{
					if (iterator == end)
					{
						iterator = begin;
					}
					issac_base_member_result[index] = *iterator;
					++iterator;
				}
				init();
			}
	
			void seed(std::random_device& random_device_object)
			{
				std::vector<result_type> seed_vec;
				seed_vec.reserve(state_size);
				for (std::size_t round = 0; round < state_size; ++round)
				{
					result_type value;
					value = random_device_object();
					std::size_t bytes_filled{sizeof(std::random_device::result_type)};
					while(bytes_filled < sizeof(result_type))
					{
						value <<= (sizeof(std::random_device::result_type) * 8);
						value |= random_device_object();
						bytes_filled += sizeof(std::random_device::result_type);
					}
					seed_vec.push_back(value);
				}
				seed(seed_vec.begin(), seed_vec.end());
			}

			inline result_type operator()()
			{
				return (!issac_base_member_counter--) ? (do_isaac(), issac_base_member_counter = state_size - 1, issac_base_member_result[issac_base_member_counter]) : issac_base_member_result[issac_base_member_counter];
			}
	
			inline void discard(unsigned long long z)
			{
				for (; z; --z) operator()();
			}

			friend bool operator==(const RNG_ISAAC_BASE& left, const RNG_ISAAC_BASE& right)
			{
				bool equal = true;
				if (left.issac_base_member_register_a != right.issac_base_member_register_a || left.issac_base_member_register_b != right.issac_base_member_register_b || left.issac_base_member_register_c != right.issac_base_member_register_c || left.issac_base_member_counter != right.issac_base_member_counter)
				{
					equal = false;
				}
				else
				{
					for (std::size_t index = 0; index < state_size; ++index)
					{
						if (left.issac_base_member_result[index] != right.issac_base_member_result[index] || left.issac_base_member_memory[index] != right.issac_base_member_memory[index])
						{
							equal = false;
							break;
						}
					}
				}
				return equal;
			}

			friend bool operator!=(const RNG_ISAAC_BASE& left, const RNG_ISAAC_BASE& right)
			{
				return !(left == right);
			}

			template <class CharT, class Traits>
			friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const RNG_ISAAC_BASE& isaac_base_object)
			{
				auto format_flags = os.flags();
				os.flags(std::ios_base::dec | std::ios_base::left);
				CharT sp = os.widen(' ');
				os.fill(sp);
				os << isaac_base_object.issac_base_member_counter;

				for (std::size_t index = 0; index < state_size; ++index)
				{
					os << sp << isaac_base_object.issac_base_member_result[index];
				}

				for (std::size_t index = 0; index < state_size; ++index)
				{
					os << sp << isaac_base_object.issac_base_member_memory[index];
				}
				os << sp << isaac_base_object.issac_base_member_register_a << sp << isaac_base_object.issac_base_member_register_b << sp << isaac_base_object.issac_base_member_register_c;

				os.flags(format_flags);
				return os;
			}
	
			template <class CharT, class Traits>
			friend std::basic_istream<CharT, Traits>&
			operator>>(std::basic_istream<CharT, Traits>& is, RNG_ISAAC_BASE& isaac_base_object)
			{
				bool failed = false;
				result_type temporary_result[state_size];
				result_type temporary_memory[state_size];
				result_type temporary_register_a = 0;
				result_type temporary_register_b = 0;
				result_type temporary_register_c = 0;
				std::size_t temporary_register_counter = 0;
		
				auto format_flags = is.flags();
				is.flags(std::ios_base::dec | std::ios_base::skipws);
		
				is >> temporary_register_counter;
				if (is.fail())
				{
					failed = true;
				}
				
				std::size_t process_counter = 0;

				while (process_counter != 5)
				{
					for (std::size_t index = 0; index < state_size; ++index)
					{
						is >> temporary_result[index];
						if (is.fail())
						{
							failed = true;
							break;
						}
					}

					++process_counter;

					for (std::size_t index = 0; index < state_size; ++index)
					{
						is >> temporary_memory[index];
						if (is.fail())
						{
							failed = true;
							break;
						}
					}

					++process_counter;

					is >> temporary_register_a;
					if (is.fail())
					{
						failed = true;
						break;
					}

					++process_counter;

					is >> temporary_register_b;
					if (is.fail())
					{
						failed = true;
						break;
					}

					++process_counter;

					is >> temporary_register_c;
					if (is.fail())
					{
						failed = true;
						break;
					}

					++process_counter;
				}
		
				if (!failed)
				{
					for (std::size_t i = 0; i < state_size; ++i)
					{
						isaac_base_object.issac_base_member_result[i] = temporary_result[i];
						isaac_base_object.issac_base_member_memory[i] = temporary_memory[i];
					}
					isaac_base_object.issac_base_member_register_a = temporary_register_a;
					isaac_base_object.issac_base_member_register_b = temporary_register_b;
					isaac_base_object.issac_base_member_register_c = temporary_register_c;
					isaac_base_object.issac_base_member_counter = temporary_register_counter;
				}
				else
				{
					is.setstate(std::ios::failbit); // should already be set, just making certain
				}

				is.flags(format_flags);
				return is;
			}

		protected:

			void init()
			{
				result_type a = golden();
				result_type b = golden();
				result_type c = golden();
				result_type d = golden();
				result_type e = golden();
				result_type f = golden();
				result_type g = golden();
				result_type h = golden();
		
				issac_base_member_register_a = 0;
				issac_base_member_register_b = 0;
				issac_base_member_register_c = 0;
				
				/* scramble it */
				for (std::size_t index = 0; index < 4; ++index)
				{
					mix(a,b,c,d,e,f,g,h);
				}
		
				/* initialize using the contents of issac_base_member_result[] as the seed */
				for (std::size_t index = 0; index < state_size; index += 8)
				{
					a += issac_base_member_result[index];
					b += issac_base_member_result[index+1];
					c += issac_base_member_result[index+2];
					d += issac_base_member_result[index+3];
					e += issac_base_member_result[index+4];
					f += issac_base_member_result[index+5];
					g += issac_base_member_result[index+6];
					h += issac_base_member_result[index+7];
			
					mix(a,b,c,d,e,f,g,h);
			
					issac_base_member_memory[index] = a;
					issac_base_member_memory[index+1] = b;
					issac_base_member_memory[index+2] = c;
					issac_base_member_memory[index+3] = d;
					issac_base_member_memory[index+4] = e;
					issac_base_member_memory[index+5] = f;
					issac_base_member_memory[index+6] = g;
					issac_base_member_memory[index+7] = h;
				}
		
				/* do a second pass to make all of the seed affect all of issac_base_member_memory */
				for (std::size_t index = 0; index < state_size; index += 8)
				{
					a += issac_base_member_memory[index];
					b += issac_base_member_memory[index+1];
					c += issac_base_member_memory[index+2];
					d += issac_base_member_memory[index+3];
					e += issac_base_member_memory[index+4];
					f += issac_base_member_memory[index+5];
					g += issac_base_member_memory[index+6];
					h += issac_base_member_memory[index+7];
			
					mix(a,b,c,d,e,f,g,h);
			
					issac_base_member_memory[index] = a;
					issac_base_member_memory[index+1] = b;
					issac_base_member_memory[index+2] = c;
					issac_base_member_memory[index+3] = d;
					issac_base_member_memory[index+4] = e;
					issac_base_member_memory[index+5] = f;
					issac_base_member_memory[index+6] = g;
					issac_base_member_memory[index+7] = h;
				}

				/* fill in the first set of results */
				do_isaac();

				/* prepare to use the first set of results */
				issac_base_member_counter = state_size;
			}
	
			inline void do_isaac()
			{
				static_cast<Derived*>(this)->derived_implementation_isaac();
			}
	
			inline result_type golden()
			{
				return static_cast<Derived*>(this)->derived_implementation_golden_number();
			}
	
			inline void mix(result_type& a, result_type& b, result_type& c, result_type& d, result_type& e, result_type& f, result_type& g, result_type& h)
			{
				static_cast<Derived*>(this)->derived_implementation_mix(a, b, c, d, e, f, g, h);
			}
	
			result_type issac_base_member_result[state_size];
			result_type issac_base_member_memory[state_size];
			result_type issac_base_member_register_a;
			result_type issac_base_member_register_b;
			result_type issac_base_member_register_c;
			std::size_t issac_base_member_counter;
		};


		template<std::size_t Alpha = 8>
		class isaac : public RNG_ISAAC_BASE<isaac<Alpha>, Alpha, std::uint32_t>
		{
		public:

			using base = RNG_ISAAC_BASE<isaac, Alpha, std::uint32_t>;
	
			friend class RNG_ISAAC_BASE<isaac, Alpha, std::uint32_t>;
	
			using result_type = std::uint32_t;
	
			explicit isaac(result_type s = base::default_seed)
			:
			base::RNG_ISAAC_BASE(s)
			{}

			template <typename SeedSeq> 
			requires( not std::convertible_to<SeedSeq, result_type> )
			explicit isaac(SeedSeq& q)
			:
			base::RNG_ISAAC_BASE(q)
			{}
	
			template<class IteratorType>
			isaac
			(
				IteratorType begin,
				IteratorType end,
				typename std::enable_if
				<
						std::is_integral<typename std::iterator_traits<IteratorType>::value_type>::value &&
						std::is_unsigned<typename std::iterator_traits<IteratorType>::value_type>::value
				>::type * = nullptr
			)
			:
			base::RNG_ISAAC_BASE(begin, end)
			{}

			isaac(std::random_device& random_device_object)
			:
			base::RNG_ISAAC_BASE(random_device_object)
			{}

			isaac(const isaac& rhs)
			:
			base::RNG_ISAAC_BASE(static_cast<const base&>(rhs))
			{}

		private:
	
			static constexpr result_type derived_implementation_golden_number()
			{
				/* the golden ratio */
				return static_cast<std::uint32_t>(0x9e3779b9);
			}

			inline void derived_implementation_mix
			(
				result_type& a,
				result_type& b,
				result_type& c,
				result_type& d,
				result_type& e,
				result_type& f,
				result_type& g,
				result_type& h
			)
			{
				a ^= b << 11;
				d += a;
				b += c;

				b ^= c >> 2;
				e += b;
				c += d;

				c ^= d << 8;
				f += c;
				d += e;

				d ^= e >> 16;
				g += d;
				e += f;

				e ^= f << 10;
				h += e;
				f += g;

				f ^= g >> 4;
				a += f;
				g += h;

				g ^= h << 8;
				b += g;
				h += a;

				h ^= a >> 9;
				c += h;
				a += b;
			}

			/*
				ISAAC (Indirection, Shift, Accumulate, Add, and Count) generates 32-bit random numbers.
				Averaged out, it requires 18.75 machine cycles to generate each 32-bit value.
				Cycles are guaranteed to be at least 2(^)40 values long, and they are 2(^)8295 values long on average.
				The results are uniformly distributed, unbiased, and unpredictable unless you know the seed.
			*/

			//Use ISAAC+ Algorithm (32 bit)?
			#if 1

			void derived_implementation_isaac()
			{
				/*
					Modulo a power of two, the following works (assuming twos complement representation):

					i mod n == i & (n-1) when n is a power of two and mod is the aforementioned positive mod.
					(FYI: modulus is the common mathematical term for the "divisor" when a modulo operation is considered).

					return i & (n-1);

					auto lambda_Modulo = [](result_type value, result_type modulo_value)
					{
						return modulo_value & ( modulo_value - 1) ? value % modulo_value : value & ( modulo_value - 1);
					};
				*/

				result_type index = 0, x = 0, y = 0, state_random_value = 0;
				
				result_type accumulate = this->issac_base_member_register_a;
				result_type bit_result = this->issac_base_member_register_b + (++(this->issac_base_member_register_c)); //b ← (c + 1)

				for (index = 0; index < this->state_size; ++index)
				{
					//x ← state[index]
					x = this->issac_base_member_memory[index];
					/*
						//barrel shift
					
						function(a, index)
						{
							if index ≡ 0 mod 4
								return a ^= a << 13
							if index ≡ 1 mod 4
								return a ^= a << 6
							if index ≡ 2 mod 4
								return a ^= a << 2
							if index ≡ 3 mod 4
								return a ^= a << 16
						}
				
						mix_index ← function(a, index);
					*/
					switch (index & 3)
					{
						case 0:
							accumulate ^= accumulate << 13;
							break;
						case 1:
							accumulate ^= accumulate >>  6;
							break;
						case 2:
							accumulate ^= accumulate <<  2;
							break;
						case 3:
							accumulate ^= accumulate >> 16;
							break;
					}
					// a(mix_index) + state[index] + 128 mod 256
					accumulate += this->issac_base_member_memory[ (index + this->state_size / 2) & (this->state_size - 1) ];
					//state[index] ← a(mix_index) ⊕ b + (state[x] >>> 2) mod 256
					//y == state[index]
					state_random_value = this->issac_base_member_memory[ Binary_RightRotateMove<result_type>(x, 2) & (this->state_size - 1) ];
					y = accumulate ^ bit_result + state_random_value;
					this->issac_base_member_memory[index] = y;
					//result[index] ← x + a(mix_index) ⊕ (state[state[index]] >>> 10) mod 256
					//b == result[index]
					state_random_value = this->issac_base_member_memory[ Binary_RightRotateMove<result_type>(y, 10) & (this->state_size - 1) ];
					bit_result = x + accumulate ^ state_random_value;
					this->issac_base_member_result[index] = bit_result;
				}
			}

			#else

			//Diffusion of integer numbers by indirection memory address
			//通过指示性内存地址扩散整数
			inline result_type diffusion_with_indirection_memory_address(result_type* memory_pointer, result_type current_value)
			{
				/*
					Modulo a power of two, the following works (assuming twos complement representation):

					i mod n == i & (n-1) when n is a power of two and mod is the aforementioned positive mod.
					(FYI: modulus is the common mathematical term for the "divisor" when a modulo operation is considered).

					return i & (n-1);
				*/

				constexpr result_type mask = (this->state_size - 1) << 2;
				//access state[index]
				return *reinterpret_cast<result_type*>( reinterpret_cast<std::uint8_t*>( memory_pointer ) + ( current_value & mask ) );
			}

			inline void RNG_do_step
			(
				const result_type mix,
				result_type& a,
				result_type& b,
				result_type*& old_memory_array,
				result_type*& update_memory_array,
				result_type*& new_memory_array,
				result_type*& current_result_array,
				result_type& x,
				result_type& y
			)
			{
				//x ← state[index]
				//x == state[index]
				x = *update_memory_array;
				/*
				This should use the modulo operation to address memory with state values, because this->state_size is a value that belongs to a power of 2.
				So assuming that Alpha is an 8-bit state, the value of this->state_size is: "1 << 8 == 256"
				And after understanding the bit manipulation, we know that the calculation of the power of 2 is: "2 & (number - 1)".
				So the ISAAC paper gives the calculation of "state[index] + 128 mod 256, and the derivation should be: state[index + (this->state_size / 2) & (this-> state_size - 1)]"
				
				This is the same as the initialization part of the previous for loop
				new_memory_array_address = new_memory_array = update_memory_array + (this->state_size / 2);
				*/
				//a ← function(a, mix_index) + state[index] + 128 mod 256
				a = (a^(mix)) + *(new_memory_array++);
				//state[index] ← a + b + (state[x] >> 2) mod 256
				//y == state[index]
				*(update_memory_array++) = y = a + b + diffusion_with_indirection_memory_address(old_memory_array, x);
				//result[index] ← x + (state[state[index]] >> 10) mod 256
				//b == result[index]
				*(current_result_array++) = b = x + diffusion_with_indirection_memory_address(old_memory_array, y >> Alpha);
			}

			void derived_implementation_isaac()
			{
				result_type x = 0;
				result_type y = 0;

				result_type* update_memory_array = nullptr;
				result_type* new_memory_array = nullptr;
				result_type* new_memory_array_address = nullptr;
		
				result_type* old_memory_array = this->issac_base_member_memory;
				result_type* current_result_array = this->issac_base_member_result;
				result_type a = this->issac_base_member_register_a;
				result_type b = this->issac_base_member_register_b + (++(this->issac_base_member_register_c)); //b ← (c + 1)

				for (update_memory_array = old_memory_array, new_memory_array_address = new_memory_array = update_memory_array + (this->state_size/2); update_memory_array < new_memory_array_address; )
				{
					RNG_do_step( a << 13, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step( a >> 6 , a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step( a << 2 , a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step( a >> 16, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
				}
				for (new_memory_array = old_memory_array; new_memory_array < new_memory_array_address; )
				{
					RNG_do_step( a << 13, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step( a >> 6 , a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step( a << 2 , a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step( a >> 16, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
				}
				this->issac_base_member_register_b = b;
				this->issac_base_member_register_a = a;
			}

			#endif
		};

		template<std::size_t Alpha = 8>
		class isaac64 : public RNG_ISAAC_BASE<isaac64<Alpha>, Alpha, std::uint64_t>
		{
		public:
	
			using result_type = std::uint64_t;

			using base = RNG_ISAAC_BASE<isaac64, Alpha, std::uint64_t>;

			friend class RNG_ISAAC_BASE<isaac64, Alpha, std::uint64_t>;
	
			explicit isaac64(result_type s = base::default_seed)
			:
			base::RNG_ISAAC_BASE(s)
			{}

			template<class SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			explicit isaac64(SeedSeq& q)
			:
			base::RNG_ISAAC_BASE(q)
			{}
	
			template<class IteratorType>
			isaac64
			(
				IteratorType begin,
				IteratorType end,
				typename std::enable_if
				<
						std::is_integral<typename std::iterator_traits<IteratorType>::value_type>::value &&
						std::is_unsigned<typename std::iterator_traits<IteratorType>::value_type>::value
				>::type * = nullptr
			)
			:
			base::RNG_ISAAC_BASE(begin, end)
			{}

			isaac64(std::random_device& random_device_object)
			:
			base::RNG_ISAAC_BASE(random_device_object)
			{}

			isaac64(const isaac64& rhs)
			:
			base::RNG_ISAAC_BASE(static_cast<const base&>(rhs))
			{}

		private:

			static constexpr result_type derived_implementation_golden_number()
			{
				/* the golden ratio */
				return static_cast<std::uint64_t>(0x9e3779b97f4a7c13);
			}

			inline void derived_implementation_mix
			(
				result_type& a,
				result_type& b,
				result_type& c,
				result_type& d,
				result_type& e,
				result_type& f,
				result_type& g,
				result_type& h
			)
			{
			   a -= e;
			   f ^= h >> 9;
			   h += a;

			   b -= f;
			   g ^= a << 9;
			   a += b;

			   c -= g;
			   h ^= b >> 23;
			   b += c;

			   d -= h;
			   a ^= c << 15;
			   c += d;

			   e -= a;
			   b ^= d >> 14;
			   d += e;

			   f -= b;
			   c ^= e << 20;
			   e += f;

			   g -= c;
			   d ^= f >> 17;
			   f += g;

			   h -= d;
			   e ^= g << 14;
			   g += h;
			}

			/*
				ISAAC-64 generates a different sequence than ISAAC, but it uses the same principles. It uses 64-bit arithmetic.
				It generates a 64-bit result every 19 instructions. All cycles are at least 2(^)72 values, and the average cycle length is 2(^)16583.

				The following files implement ISAAC-64. 
				The constants were tuned for a 64-bit machine, and a complement was thrown in so that all-zero states become nonzero faster.
			*/

			//Use ISAAC+ Algorithm (64 bit)?
			#if 1

			void derived_implementation_isaac()
			{
				/*
					Modulo a power of two, the following works (assuming twos complement representation):

					i mod n == i & (n-1) when n is a power of two and mod is the aforementioned positive mod.
					(FYI: modulus is the common mathematical term for the "divisor" when a modulo operation is considered).

					return i & (n-1);

					auto lambda_Modulo = [](result_type value, result_type modulo_value)
					{
						return modulo_value & ( modulo_value - 1) ? value % modulo_value : value & ( modulo_value - 1);
					};
				*/

				result_type index = 0, x = 0, y = 0, state_random_value = 0;
				
				result_type accumulate = this->issac_base_member_register_a;
				result_type bit_result = this->issac_base_member_register_b + (++(this->issac_base_member_register_c)); //b ← (c + 1)

				for (index = 0; index < this->state_size; ++index)
				{
					//x ← state[index]
					x = this->issac_base_member_memory[index];
					/*
						//barrel shift
					
						function(a, index)
						{
							if index ≡ 0 mod 4
								return a ^= ~(a << 21)
							if index ≡ 1 mod 4
								return a ^= a << 5
							if index ≡ 2 mod 4
								return a ^= a << 12
							if index ≡ 3 mod 4
								return a ^= a << 33
						}
				
						mix_index ← function(a, index);
					*/
					switch (index & 3)
					{
						case 0:
							accumulate ^= ~(accumulate << 21);
							break;
						case 1:
							accumulate ^= accumulate >>  5;
							break;
						case 2:
							accumulate ^= accumulate << 12;
							break;
						case 3:
							accumulate ^= accumulate >> 33;
							break;
					}
					// a(mix_index) + state[index] + 128 mod 256
					accumulate += this->issac_base_member_memory[ (index + this->state_size / 2) & (this->state_size - 1) ];
					//state[index] ← a(mix_index) ⊕ b + (state[x] >>> 2) mod 256
					//y == state[index]
					state_random_value = this->issac_base_member_memory[ Binary_RightRotateMove<result_type>(x, 2) & (this->state_size - 1) ];
					y = accumulate ^ bit_result + state_random_value;
					this->issac_base_member_memory[index] = y;
					//result[index] ← x + a(mix_index) ⊕ (state[state[index]] >>> 10) mod 256
					//b == result[index]
					state_random_value = this->issac_base_member_memory[ Binary_RightRotateMove<result_type>(y, 10) & (this->state_size - 1) ];
					bit_result = x + accumulate ^ state_random_value;
					this->issac_base_member_result[index] = bit_result;
				}
			}

			#else

			//Diffusion of integer numbers by indirection memory address
			//通过指示性内存地址扩散整数
			inline result_type diffusion_with_indirection_memory_address(result_type* memory_pointer, result_type current_value)
			{
				/*
					Modulo a power of two, the following works (assuming twos complement representation):

					i mod n == i & (n-1) when n is a power of two and mod is the aforementioned positive mod.
					(FYI: modulus is the common mathematical term for the "divisor" when a modulo operation is considered).

					return i & (n-1);
				*/

				//access state[index]
				constexpr result_type mask = (this->state_size - 1) << 3;
				return *reinterpret_cast<result_type*>( reinterpret_cast<std::uint8_t*>( memory_pointer ) + ( current_value & mask ) );
			}

			inline void RNG_do_step
			(
				const result_type mix,
				result_type& a,
				result_type& b,
				result_type*& old_memory_array,
				result_type*& update_memory_array,
				result_type*& new_memory_array,
				result_type*& current_result_array,
				result_type& x,
				result_type& y
			)
			{
				//x ← state[index]
				//x == state[index]
				x = *update_memory_array;

				/*
				This should use the modulo operation to address memory with state values, because this->state_size is a value that belongs to a power of 2.
				So assuming that Alpha is an 8-bit state, the value of this->state_size is: "1 << 8 == 256"
				And after understanding the bit manipulation, we know that the calculation of the power of 2 is: "2 & (number - 1)".
				So the ISAAC paper gives the calculation of "state[index] + 128 mod 256, and the derivation should be: state[index + (this->state_size / 2) & (this-> state_size - 1)]"
				
				This is the same as the initialization part of the previous for loop
				new_memory_array_address = new_memory_array = update_memory_array + (this->state_size / 2);
				*/
				//a ← function(a, mix_index) + state[index] + 128 mod 256
				a = (a^(mix)) + *(new_memory_array++);
				//state[index] ← a + b + (state[x] >> 2) mod 512
				//y == state[index]
				*(update_memory_array++) = y = a + b + diffusion_with_indirection_memory_address(old_memory_array, x);
				//result[index] ← x + (state[state[index]] >> 10) mod 512
				//b == result[index]
				*(current_result_array++) = b = x + diffusion_with_indirection_memory_address(old_memory_array, y >> Alpha);
			}

			void derived_implementation_isaac()
			{
				result_type x = 0;
				result_type y = 0;

				result_type* update_memory_array = nullptr;
				result_type* new_memory_array = nullptr;
				result_type* new_memory_array_address = nullptr;
		
				result_type* old_memory_array = this->issac_base_member_memory;
				result_type* current_result_array = this->issac_base_member_result;
				result_type a = this->issac_base_member_register_a;
				result_type b = this->issac_base_member_register_b + (++(this->issac_base_member_register_c)); //b ← (c + 1)

				for (update_memory_array = old_memory_array, new_memory_array_address = new_memory_array = update_memory_array + (this->state_size / 2); update_memory_array < new_memory_array_address; )
				{
					RNG_do_step(~(a ^ (a << 21)), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step(a ^ (a >> 5), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step(a ^ (a << 12), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step(a ^ (a >> 33), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
				}
				for (new_memory_array = old_memory_array; new_memory_array < new_memory_array_address; )
				{
					RNG_do_step(~(a ^ (a << 21)), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step(a ^ (a >> 5), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step(a ^ (a << 12), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step(a ^ (a >> 33), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
				}
				this->issac_base_member_register_b = b;
				this->issac_base_member_register_a = a;
			}

			#endif
		};
	}

	/*
		A counter-based random number generation (CBRNG, also known as a counter-based pseudo-random number generator, or CBPRNG) is a kind of pseudorandom number generator that uses only an integer counter as its internal state.
		
		Improved version from Middle Square Method, invented by John Von Neumann.

		Reference papers: https://arxiv.org/abs/1704.00358 and https://arxiv.org/abs/2004.06278

		Reference source code: https://github.com/Shiroechi/Litdex.Security.RNG/blob/main/Source/Security/RNG/PRNG/MiddleSquareWeylSequence.cs
	*/
	namespace RNG_NumberSquare_TakeMiddle
	{
		class ImprovedJohnVonNeumannAlgorithm
		{

		private:
			std::uint64_t _resultRandomNumber;
			std::uint64_t _sequenceWeylSequence;
			std::uint64_t _oddNumber;
			RNG_SimpleImplementation::GNU_C_LibraryGenerator _simpleImplementationGenerator;

		public:

			void reseed()
			{
				std::vector<std::uint8_t> random_byte_datas(16, 0x00);

				/*
					Xorshift random number generators, also called shift-register generators, are a class of pseudorandom number generators that were discovered by George Marsaglia.[1]
					They are a subset of linear-feedback shift registers (LFSRs) which allow a particularly efficient implementation in software without using excessively sparse polynomials.[2]
					They generate the next number in their sequence by repeatedly taking the exclusive or of a number with a bit-shifted version of itself.
					This makes them execute extremely efficiently on modern computer architectures, but does not benefit efficiency in a hardware implementation.
					Like all LFSRs, the parameters have to be chosen very carefully in order to achieve a long period.[3]
					For execution in software, xorshift generators are among the fastest non-cryptographically-secure random number generators, requiring very small code and state.
					However, they do not pass every statistical test without further refinement.
					This weakness is well-known and is amended (as pointed out by Marsaglia in the original paper) by combining them with a non-linear function, resulting e.g. in a xorshift+ or xorshift* generator.
					A native C implementation of a xorshift+ generator that passes all tests from the BigCrush suite (with an order of magnitude fewer failures than Mersenne Twister or WELL) typically takes fewer than 10 clock cycles on x86 to generate a random number, thanks to instruction pipelining.[4]
					The scramblers known as + and * still leave weakness in the low bits,[5] so they're intended for floating point use, as conversion of a random number to floating point discards the low bits.
					For general purpose, the scrambler ** (pronounced 'starstar') makes the LFSR generators pass in all bits.
					Because plain xorshift generators (without a non-linear step) fail some statistical tests, they have been accused of being unreliable
					https://en.wikipedia.org/wiki/Xorshift
				*/

				std::size_t undefine_behavior_number;
				std::size_t xorshift_random_seed = _resultRandomNumber;

				if(_resultRandomNumber == 0)
					undefine_behavior_number = 0;

				_oddNumber = static_cast<std::uint64_t>(_simpleImplementationGenerator() << 32);
				while ((_oddNumber & 1) == 0)
				{
					auto difference = _oddNumber - std::numeric_limits<std::uint64_t>::min();
					auto difference2 = std::numeric_limits<std::uint64_t>::max() - _oddNumber;
					if(difference > difference2)
						_oddNumber -= 1;
					else if(difference < difference2)
						_oddNumber += 1;
					else
					{
						//其实无状态的XOR-Shift算法它的每一个步骤都在切换多个或者一个比特位，即移动比特位之后进行exclusive-or操作
						//In fact, the stateless XOR-Shift algorithm performs an exclusive-or operation after toggling multiple or one bit, i.e., shifting bits
						if constexpr(CURRENT_SYSTEM_BITS == 32)
						{
							//Use xorshift32

							xorshift_random_seed ^= (xorshift_random_seed << 13);
							xorshift_random_seed ^= (xorshift_random_seed >> 17);
							xorshift_random_seed ^= (xorshift_random_seed << 5);

							undefine_behavior_number = xorshift_random_seed;

							undefine_behavior_number ^= (undefine_behavior_number << 13);
							undefine_behavior_number ^= (undefine_behavior_number >> 17);
							undefine_behavior_number ^= (undefine_behavior_number << 5);
						}
						else
						{
							//Use xorshift64

							xorshift_random_seed ^= (xorshift_random_seed << 13);
							xorshift_random_seed ^= (xorshift_random_seed >> 7);
							xorshift_random_seed ^= (xorshift_random_seed << 17);

							undefine_behavior_number = xorshift_random_seed;

							undefine_behavior_number ^= (undefine_behavior_number << 13);
							undefine_behavior_number ^= (undefine_behavior_number >> 7);
							undefine_behavior_number ^= (undefine_behavior_number << 17);
						}

						//Toggles an odd number of bits in an odd position, so an even number becomes an odd number
						//切换一个奇数位置的比特位，所以偶数变成了奇数
						_oddNumber ^= static_cast<std::uint64_t>(1 << static_cast<std::size_t>(undefine_behavior_number & (CURRENT_SYSTEM_BITS - 1)) );
					}
				}

				//Use xorshift128

				std::array<std::uint32_t, 4> xorshift128_state { undefine_behavior_number, undefine_behavior_number -= _oddNumber, xorshift_random_seed , xorshift_random_seed -= _oddNumber };

				std::uint32_t t = xorshift128_state[3];
				std::uint32_t s = xorshift128_state[0];
				xorshift128_state[3] = xorshift128_state[2];
				xorshift128_state[2] = xorshift128_state[1];
				xorshift128_state[1] = s;

				t ^= (t << 11);
				t ^= (t >> 8);

				xorshift128_state[0] = t ^ s ^ (s >> 19);

				_simpleImplementationGenerator.seed( xorshift128_state[0] );

				for( auto& byte : random_byte_datas )
				{
					byte = static_cast<std::uint8_t>( _simpleImplementationGenerator() );
				}

				std::span random_byte_datas_span{ random_byte_datas };
				CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>( random_byte_datas_span, &_sequenceWeylSequence );
				CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>( random_byte_datas_span.subspan(8, 8), &_resultRandomNumber );
			}

			void seed(std::random_device& random_device_object)
			{
				std::uint32_t seed_value = random_device_object();
				this->seed(seed_value);
			}

			void seed(unsigned int seed_value)
			{
				_resultRandomNumber = seed_value;
				_sequenceWeylSequence = seed_value;
				_simpleImplementationGenerator.seed(seed_value);
			}

			unsigned int operator()()
			{
				_resultRandomNumber *= _resultRandomNumber;
				_resultRandomNumber += (_sequenceWeylSequence += _oddNumber);
				_resultRandomNumber = std::rotr(_resultRandomNumber, 32);
				return static_cast<unsigned int>(_resultRandomNumber);
			}

			static constexpr unsigned int min()
			{
				return std::numeric_limits<unsigned int>::min();
			}

			static constexpr unsigned int max()
			{
				return std::numeric_limits<unsigned int>::max();
			}

			ImprovedJohnVonNeumannAlgorithm
			(
				unsigned int seed_value = 0,
				unsigned int random_state_mode = 0
			)
				:
				_simpleImplementationGenerator(random_state_mode),
				_oddNumber(0xb5ad4eceda1ce2a9)
			{
				this->seed(seed_value);
			}

			~ImprovedJohnVonNeumannAlgorithm()
			{
				_resultRandomNumber = 0;
				_sequenceWeylSequence = 0;
				_oddNumber = 0;
			}
		};

		/*
			The squares RNG was derived using ideas from “Middle-Square Weyl Sequence RNG”[7].
			The msws generator uses a half-square implementation.
			That is, only half of the actual square is computed. 
			The upper bits of this half square are the “middle” that is returned.
			These middle bits are easily obtained by either rotating or shifting the result.
			The middle square provides the randomization. 
			Uniformity and period length are obtained by adding in a Weyl sequence.
			For the squares RNG, we replaced the Weyl sequence (w += s) with a counter multiplied by a key. 
			This turns out to be in effect the same thing.
			Mathematically, (w += s) is equivalent to w = i * s mod 2(^)64 for i = 0 to 2(^)64 − 1. 
			That is, i * s will produce the same sequence as (w += s).
			In place of i and s, we use a counter and a key. 
			So, if we add counter * key to a square, we should see the same effect as adding a Weyl sequence. 
			The output will be uniform and 264 random numbers will be available per key(^)1.
			In the squares RNG, several rounds of squaring and adding are computed and the result is returned. 
			Four rounds have been shown to be sufficient to pass the statistical tests.
		*/
		namespace ExampleCode
		{
			template<typename NumberType>
			requires std::unsigned_integral<NumberType> || std::signed_integral<NumberType>
			NumberType simple_power2(NumberType number)
			{
				return number * number;
			}
			
			static inline uint32_t squares32bit(uint64_t counter, uint64_t key)
			{
				std::uint64_t x, y, z;
				y = x = counter * key; z = y + key;
				simple_power2(x) + y; x = (x>>32) | (x<<32); /* round 1 */
				simple_power2(x) + z; x = (x>>32) | (x<<32); /* round 2 */
				simple_power2(x) + y; x = (x>>32) | (x<<32); /* round 3 */
				return (simple_power2(x) + z) >> 32; /* round 4 */
			}

			static inline uint64_t squares64bit(uint64_t counter, uint64_t key)
			{
				std::uint64_t t, x, y, z;
				y = x = counter * key; z = y + key;
				simple_power2(x) + y; x = (x>>32) | (x<<32); /* round 1 */
				simple_power2(x) + z; x = (x>>32) | (x<<32); /* round 2 */
				simple_power2(x) + y; x = (x>>32) | (x<<32); /* round 3 */
				t = x = simple_power2(x) + z; x = (x>>32) | (x<<32); /* round 4 */
				return t ^ ((simple_power2(x) + y) >> 32); /* round 5 */
			}
		}

		class ImprovedJohnVonNeumannAlgorithmWithKey
		{

		private:
			std::uint64_t _keyWord;
			std::uint64_t _counterWord;
			ImprovedJohnVonNeumannAlgorithm _improvedJohnVonNeumannAlgorithmObject;

			unsigned int compute_number(unsigned long long counter_word, unsigned long long key_word)
			{
				unsigned long long a = 0, b = 0, c = 0;
				
				b = a = counter_word * key_word;
				c = b + key_word;

				a = (a * a) + b;
				a = std::rotr(a, 32);

				a = (a * a) + c;
				a = std::rotr(a, 32);

				a = (a * a) + b;
				a = std::rotr(a, 32);

				return static_cast<unsigned int>( ((a * a) + c) >> 32);
			}

		public:

			void reseed()
			{
				_improvedJohnVonNeumannAlgorithmObject.reseed();
				_keyWord = _improvedJohnVonNeumannAlgorithmObject();
				_counterWord = 0;
			}

			void seed(unsigned long long counter_word, unsigned long long key_word)
			{
				_counterWord = counter_word;

				if(key_word != 0)
					_keyWord = key_word;
				else
				{
					_improvedJohnVonNeumannAlgorithmObject.seed(key_word);
					_keyWord = _improvedJohnVonNeumannAlgorithmObject();
				}
			}

			unsigned int operator()()
			{
				++_counterWord;
				return this->compute_number(_counterWord, _keyWord);
			}

			static constexpr unsigned int min()
			{
				return std::numeric_limits<unsigned int>::min();
			}

			static constexpr unsigned int max()
			{
				return std::numeric_limits<unsigned int>::max();
			}

			ImprovedJohnVonNeumannAlgorithmWithKey
			(
				unsigned long long counter_word = 0,
				unsigned long long key_word = 0,
				unsigned int seed_value = 0,
				unsigned int random_state_mode = 0
			)
				: _improvedJohnVonNeumannAlgorithmObject(seed_value, random_state_mode)
			{
				_keyWord = 0xc58efd154ce32f6d;
				_counterWord = 0;
			}

			~ImprovedJohnVonNeumannAlgorithmWithKey()
			{
				_keyWord = 0;
				_counterWord = 0;
			}
		};
	}

	namespace ShufflingRangeDataDetails
	{
		//将一个统一的随机数发生器包装成一个随机数发生器
		//Wrap a Uniform random number generator as an Random number generator
		template <class DifferenceType, class URNG_Type>
		requires std::uniform_random_bit_generator<std::remove_reference_t<URNG_Type>>
		class WARP_URNG_AS_AN_RNG
		{

		public:

			using Type0 = std::make_unsigned_t<DifferenceType>;
			using Type1 = typename URNG_Type::result_type;

			using UnsignedDifferenceType = std::conditional_t<sizeof( Type1 ) < sizeof( Type0 ), Type0, Type1>;

			explicit WARP_URNG_AS_AN_RNG( URNG_Type& _Func ) : URNG_TypeReference( _Func ), RandomBits( CHAR_BIT * sizeof( UnsignedDifferenceType ) ), RandomBitMask( UnsignedDifferenceType( -1 ) )
			{
				for ( ; ( URNG_Type::max )() - ( URNG_Type::min )() < RandomBitMask; RandomBitMask >>= 1 )
				{
					--RandomBits;
				}
			}

			// adapt URNG_Type closed range to [0, DifferenceTypeIndex)
			DifferenceType operator()( DifferenceType DifferenceTypeIndex )
			{
				for ( ;; )
				{											  // try a sample random value
					UnsignedDifferenceType ResultObject = 0;  // random bits
					UnsignedDifferenceType MaskInRange = 0;	  // 2^N - 1, ResultObject is within [0, MaskInRange]

					while ( MaskInRange < UnsignedDifferenceType( DifferenceTypeIndex - 1 ) )
					{									  // need more random bits
						ResultObject <<= RandomBits - 1;  // avoid full shift
						ResultObject <<= 1;
						ResultObject |= FindBits();
						MaskInRange <<= RandomBits - 1;	 // avoid full shift
						MaskInRange <<= 1;
						MaskInRange |= RandomBitMask;
					}

					// ResultObject is [0, MaskInRange], DifferenceTypeIndex - 1 <= MaskInRange, return if unbiased
					if ( ResultObject / DifferenceTypeIndex < MaskInRange / DifferenceTypeIndex || MaskInRange % DifferenceTypeIndex == UnsignedDifferenceType( DifferenceTypeIndex - 1 ) )
					{
						return static_cast<DifferenceType>( ResultObject % DifferenceTypeIndex );
					}
				}
			}

			UnsignedDifferenceType FindAllBits()
			{
				UnsignedDifferenceType ResultObject = 0;

				for ( size_t NumberIndex = 0; NumberIndex < CHAR_BIT * sizeof( UnsignedDifferenceType ); NumberIndex += RandomBits )
				{									  // don't mask away any bits
					ResultObject <<= RandomBits - 1;  // avoid full shift
					ResultObject <<= 1;
					ResultObject |= FindBits();
				}

				return ResultObject;
			}

			WARP_URNG_AS_AN_RNG( const WARP_URNG_AS_AN_RNG& ) = delete;
			WARP_URNG_AS_AN_RNG& operator=( const WARP_URNG_AS_AN_RNG& ) = delete;

		private:

			// return a random value within [0, RandomBitMask]
			UnsignedDifferenceType FindBits()
			{
				for ( ;; )
				{  // repeat until random value is in range
					UnsignedDifferenceType _Val = URNG_TypeReference() - ( URNG_Type::min )();

					if ( _Val <= RandomBitMask )
					{
						return _Val;
					}
				}
			}

			URNG_Type&			   URNG_TypeReference;	// reference to URNG
			size_t				   RandomBits;			// number of random bits generated by _Get_bits()
			UnsignedDifferenceType RandomBitMask;		// 2^RandomBits - 1
		};

		// uniform integer distribution
		template <class IntegerType>
		requires std::is_integral_v<IntegerType>
		class UniformInteger
		{
		public:
			using result_type = IntegerType;

			// parameter package
			struct param_type
			{
				using distribution_type = UniformInteger;

				param_type()
				{
					InitialParamType( 0, 9 );
				}

				explicit param_type( result_type MinimumValue0, result_type MaximumValue0 = 9 )
				{
					InitialParamType( MinimumValue0, MaximumValue0 );
				}

				[[nodiscard]] bool operator==( const param_type& _Right ) const
				{
					return MinimumValue == _Right.MinimumValue && MaximumValue == _Right.MaximumValue;
				}

				[[nodiscard]] bool operator!=( const param_type& _Right ) const
				{
					return !( *this == _Right );
				}

				[[nodiscard]] result_type a() const
				{
					return MinimumValue;
				}

				[[nodiscard]] result_type b() const
				{
					return MaximumValue;
				}

				void InitialParamType( IntegerType MinimumValue0, IntegerType MaximumValue0 )
				{	// set internal state

					my_cpp2020_assert( MinimumValue0 <= MaximumValue0, "invalid min and max arguments for uniform_int", std::source_location::current() );

					MinimumValue = MinimumValue0;
					MaximumValue = MaximumValue0;
				}

				result_type MinimumValue;
				result_type MaximumValue;
			};

			UniformInteger() : _ParamObject_( 0, 9 ) {}

			explicit UniformInteger( IntegerType MinimumValue0, IntegerType MaximumValue0 = 9 ) : _ParamObject_( MinimumValue0, MaximumValue0 ) {}

			explicit UniformInteger( const param_type& _ParamObject_0 ) : _ParamObject_( _ParamObject_0 ) {}

			[[nodiscard]] result_type a() const
			{
				return _ParamObject_.a();
			}

			[[nodiscard]] result_type b() const
			{
				return _ParamObject_.b();
			}

			[[nodiscard]] param_type param() const
			{
				return _ParamObject_;
			}

			void param( const param_type& _ParamObject_0 )
			{  // set parameter package
				_ParamObject_ = _ParamObject_0;
			}

			[[nodiscard]] result_type( min )() const
			{
				return _ParamObject_.MinimumValue;
			}

			[[nodiscard]] result_type( max )() const
			{
				return _ParamObject_.MaximumValue;
			}

			void reset() {}	 // clear internal state

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject ) const
			{
				return RND_CalculationValue( RNG_EngineObject, _ParamObject_.MinimumValue, _ParamObject_.MaximumValue );
			}

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject, const param_type& _ParamObject_0 ) const
			{
				return RND_CalculationValue( RNG_EngineObject, _ParamObject_0.MinimumValue, _ParamObject_0.MaximumValue );
			}

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject, result_type _Nx ) const
			{
				return RND_CalculationValue( RNG_EngineObject, 0, _Nx - 1 );
			}

			template <class _Elem, class _Traits>
			std::basic_istream<_Elem, _Traits>& Read( std::basic_istream<_Elem, _Traits>& Istr )
			{  // read state from Istr
				IntegerType MinimumValue0;
				IntegerType MaximumValue0;
				Istr >> MinimumValue0 >> MaximumValue0;
				_ParamObject_.InitialParamType( MinimumValue0, MaximumValue0 );
				return Istr;
			}

			// write state to Ostr
			template <class _Elem, class _Traits>
			std::basic_ostream<_Elem, _Traits>& Write( std::basic_ostream<_Elem, _Traits>& Ostr ) const
			{
				return Ostr << _ParamObject_.MinimumValue << ' ' << _ParamObject_.MaximumValue;
			}

		private:

			using UnsignedIntegerType = std::make_unsigned_t<IntegerType>;

			// compute next value in range [MinimumValue, MaximumValue]
			template <class RandomNumberGenerator_EngineType>
			result_type RND_CalculationValue( RandomNumberGenerator_EngineType& RNG_EngineObject, IntegerType MinimumValue, IntegerType MaximumValue ) const
			{
				WARP_URNG_AS_AN_RNG<UnsignedIntegerType, RandomNumberGenerator_EngineType> _Generator( RNG_EngineObject );

				const UnsignedIntegerType _UnsignedMinimunValue_ = AdjustNumber( static_cast<UnsignedIntegerType>( MinimumValue ) );
				const UnsignedIntegerType _UnsignedMaximunValue_ = AdjustNumber( static_cast<UnsignedIntegerType>( MaximumValue ) );

				UnsignedIntegerType UnsignedIntegerResult;

				if ( _UnsignedMaximunValue_ - _UnsignedMinimunValue_ == static_cast<UnsignedIntegerType>( -1 ) )
				{
					UnsignedIntegerResult = static_cast<UnsignedIntegerType>( _Generator.FindAllBits() );
				}
				else
				{
					UnsignedIntegerResult = static_cast<UnsignedIntegerType>( _Generator( static_cast<UnsignedIntegerType>( _UnsignedMaximunValue_ - _UnsignedMinimunValue_ + 1 ) ) );
				}

				return static_cast<IntegerType>( AdjustNumber( static_cast<UnsignedIntegerType>( UnsignedIntegerResult + _UnsignedMinimunValue_ ) ) );
			}

			// convert signed ranges to unsigned ranges and vice versa
			static UnsignedIntegerType AdjustNumber( UnsignedIntegerType UnsignedInegerValue )
			{
				if constexpr ( std::is_signed_v<IntegerType> )
				{
					const UnsignedIntegerType NumberAdjuster = ( static_cast<UnsignedIntegerType>( -1 ) >> 1 ) + 1;	 // 2^(N-1)

					if ( UnsignedInegerValue < NumberAdjuster )
					{
						return static_cast<UnsignedIntegerType>( UnsignedInegerValue + NumberAdjuster );
					}
					else
					{
						return static_cast<UnsignedIntegerType>( UnsignedInegerValue - NumberAdjuster );
					}
				}
				else
				{  // IntegerType is already unsigned, do nothing
					return UnsignedInegerValue;
				}
			}

			param_type _ParamObject_;
		};

		// read state from _Istr
		template <class _Elem, class _Traits, class Type>
		std::basic_istream<_Elem, _Traits>& operator>>(std::basic_istream<_Elem, _Traits>& _Istr, UniformInteger<Type>& _Dist)
		{
			return _Dist.Read(_Istr);
		}

		// write state to _Ostr
		template <class _Elem, class _Traits, class Type>
		std::basic_ostream<_Elem, _Traits>& operator<<(std::basic_ostream<_Elem, _Traits>& _Ostr, const UniformInteger<Type>& _Dist)
		{
			return _Dist.Write(_Ostr);
		}

		// uniform integer distribution
		template <class IntegerType>
		class UniformIntegerDistribution : public UniformInteger<IntegerType>
		{

		public:

			using _BaseType = UniformInteger<IntegerType>;
			using _ParamBaseType = typename _BaseType::param_type;
			using result_type = typename _BaseType::result_type;

			// parameter package
			struct param_type : _ParamBaseType
			{
				using distribution_type = UniformIntegerDistribution;

				param_type() : _ParamBaseType(0, (std::numeric_limits<IntegerType>::max)()) {}

				explicit param_type(result_type _Min0, result_type _Max0 = (std::numeric_limits<IntegerType>::max)()) : _ParamBaseType(_Min0, _Max0) {}

				param_type(const _ParamBaseType& _Right) : _ParamBaseType(_Right) {}
			};

			UniformIntegerDistribution() : _BaseType(0, (std::numeric_limits<IntegerType>::max)()) {}

			explicit UniformIntegerDistribution(IntegerType _Min0, IntegerType _Max0 = (std::numeric_limits<IntegerType>::max)()) : _BaseType(_Min0, _Max0) {}

			explicit UniformIntegerDistribution(const param_type& _ParamObject) : _BaseType(_ParamObject) {}
		};
	}

	template<typename RNG_Type>
	requires std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
	struct PseudoRandomNumberEngine
	{
		//Whether the pseudo-random is initialized by seed
		static inline bool PseudoRandomIsInitialBySeed = false;
		static inline RNG_Type random_generator;

		//C++ 初始化伪随机数的种子
		//C++ Initialize the seed of the pseudo-random number
		template <std::integral IntegerType>
		void InitialBySeed( IntegerType seedNumber, bool ResetFlag = false )
		{
			if ( ResetFlag == true )
				PseudoRandomIsInitialBySeed = false;

			if ( PseudoRandomIsInitialBySeed == false )
			{
				random_generator.seed( seedNumber );
				PseudoRandomIsInitialBySeed = true;
			}
		}

		template<std::integral IntegerType, typename IteratorType>
		void InitialBySeed( IteratorType begin, IteratorType end, IntegerType seedNumber, bool ResetFlag = false )
		{
			static_assert(std::convertible_to<std::iter_value_t<IteratorType>, IntegerType>, "");

			if ( ResetFlag == true )
				PseudoRandomIsInitialBySeed = false;

			if ( PseudoRandomIsInitialBySeed == false )
			{
				random_generator.seed( begin, end );
				PseudoRandomIsInitialBySeed = true;
			}
		}

		template<std::integral IntegerType, typename SeedSeq>
		void InitialBySeed( SeedSeq seedNumberSequence, bool ResetFlag = false )
		{
			static_assert(not std::convertible_to<SeedSeq, IntegerType>, "");

			if ( ResetFlag == true )
				PseudoRandomIsInitialBySeed = false;

			if ( PseudoRandomIsInitialBySeed == false )
			{
				random_generator.seed( seedNumberSequence );
				PseudoRandomIsInitialBySeed = true;
			}
		}

		//C++ 生成伪随机数
		//C++ generates random numbers
		template <typename IntegerType>
		requires std::integral<IntegerType>
		IntegerType GenerateNumber( IntegerType minimum, IntegerType maximum, bool is_nonlinear_mode)
		{
			if ( PseudoRandomIsInitialBySeed == true )
			{
				if (minimum > 0)
					minimum = std::numeric_limits<IntegerType>::min();
				if (maximum < 0)
					maximum = std::numeric_limits<IntegerType>::max();

				if (!is_nonlinear_mode)
				{
					static ShufflingRangeDataDetails::UniformIntegerDistribution<IntegerType> number_distribution( minimum, maximum );
					
					if constexpr(std::signed_integral<IntegerType>)
					{
						auto random_unsigned_number = number_distribution( random_generator );
						auto random_unsigned_number2 = number_distribution( random_generator );

						if (minimum < 0)
						{
							auto can_be_subtracted_count = minimum;
								~can_be_subtracted_count;
							
							RegenerateNumber:

							while(random_unsigned_number > can_be_subtracted_count - 1 || random_unsigned_number == 0)
								random_unsigned_number = number_distribution( random_generator );

							while(random_unsigned_number2 > can_be_subtracted_count - 1 || random_unsigned_number2 == 0)
								random_unsigned_number2 = number_distribution( random_generator );

							if (random_unsigned_number == random_unsigned_number2)
								goto RegenerateNumber;

							if (random_unsigned_number > random_unsigned_number2)
								return 0 - random_unsigned_number;
							else if (random_unsigned_number < random_unsigned_number2)
								return 0 - random_unsigned_number2;
						}

						return number_distribution( random_generator );
					}
					else
						return number_distribution( random_generator );
				}
				else
				{
					IntegerType random_number = 0, random_number2 = 0;

					if ( maximum == std::numeric_limits<IntegerType>::max() )
						maximum -= 1;

					auto lambda_GenerateNumberAtIntervals = [&random_number, &random_number2, &minimum](const IntegerType middle_number)
					{
						for( random_number = random_generator(); random_number < minimum || random_number > middle_number; )
						{
							random_number = random_generator();
						}

						for( random_number2 = random_generator(); random_number2 < minimum || random_number2 > middle_number + 1; )
						{
							random_number2 = random_generator();
						}
					};

					if ( (maximum & 1) == 1 )
					{
						auto middle_number = (maximum + 1) >> 1;

						lambda_GenerateNumberAtIntervals(middle_number);

						auto range_count = random_number + random_number2;

						if (range_count == maximum)
							return middle_number - 1;
						else if (range_count < middle_number)
							return middle_number - range_count - 1;
						else
							return maximum - range_count + middle_number - 1;
					}
					else
					{
						auto middle_number = maximum >> 1;

						lambda_GenerateNumberAtIntervals(middle_number);

						auto range_count = random_number + random_number2;

						if(range_count < middle_number)
							return middle_number - range_count - 1;
						else
							return maximum - range_count + middle_number - 1;
					}
				}
			}
		}
	};

	//针对容器内容进行洗牌
	//Shuffling against container content
	struct UnifromShuffleRangeImplement
	{
		//RNG is random number generator
		template<std::random_access_iterator RandomAccessIteratorType, std::sentinel_for<RandomAccessIteratorType> SentinelIteratorType, typename RNG_Type>
		requires std::permutable<RandomAccessIteratorType> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		RandomAccessIteratorType operator()(RandomAccessIteratorType first, SentinelIteratorType last, RNG_Type&& functionRNG)
		{
			using iterator_difference_t = std::iter_difference_t<RandomAccessIteratorType>;
			using number_distribution_t = ShufflingRangeDataDetails::UniformIntegerDistribution<iterator_difference_t>;
			using number_distribution_param_t = typename number_distribution_t::param_type;

			number_distribution_t number_distribution_object;
			const auto distance { last - first };

			for(iterator_difference_t index{1}; index < distance; ++index)
			{
				std::ranges::iter_swap(first + index, first + number_distribution_object(functionRNG, number_distribution_param_t(0, index)));
			}
			return std::ranges::next(first, last);
		}

		template <std::ranges::random_access_range RandomAccessRangeType, typename RNG_Type>
		requires std::permutable<std::ranges::iterator_t<RandomAccessRangeType>> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		std::ranges::borrowed_iterator_t<RandomAccessRangeType> operator()( RandomAccessRangeType&& range, RNG_Type&& functionRNG )
		{
			return this->operator()( std::ranges::begin( range ), std::ranges::end( range ), std::forward<RNG_Type>( functionRNG ) );
		}

		template<std::random_access_iterator RandomAccessIteratorType, typename RNG_Type>
		requires std::permutable<RandomAccessIteratorType> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		void KnuthShuffle(RandomAccessIteratorType begin, RandomAccessIteratorType end, RNG_Type&& functionRNG)
		{
			for ( std::iter_difference_t<RandomAccessIteratorType> difference_value = end - begin - 1; difference_value >= 1; --difference_value )
			{
				std::size_t iterator_offset = functionRNG() % ( difference_value + 1 );
				if ( iterator_offset != difference_value )
				{
					std::iter_swap( begin + iterator_offset, begin + difference_value );
				}
			}
		}

		template<std::ranges::random_access_range RandomAccessRangeType, typename RNG_Type>
		requires std::permutable<std::ranges::iterator_t<RandomAccessRangeType>> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		void KnuthShuffle(RandomAccessRangeType&& range, RNG_Type&& functionRNG)
		{
			return (*this).KnuthShuffle(std::ranges::begin(range), std::ranges::end( range ), std::forward<RNG_Type>( functionRNG ));
		}
	};

	inline UnifromShuffleRangeImplement ShuffleRangeData;
	
	#if 0

	template < typename IntegerType >
	requires std::is_integral_v<IntegerType>
	std::vector<IntegerType> VectorContainerDataWithRandomAccess( IntegerType randomSeed, const IntegerType needAccessCount, const std::vector<IntegerType>& inputDataContainer )
	{
		IntegerType container_size = inputDataContainer.size();

		if ( container_size == 0 )
		{
			return std::vector<IntegerType>{};
		}
		else
		{
			//复制过的容器
			//Copied containers
			std::vector<IntegerType> copiedContainer;

			//对源容器的内容进行复制一次，然后三次插入原容器的内容到复制的容器
			//The contents of the source container are copied once and then the contents of the original container are inserted three times into the copied container
			std::copy( inputDataContainer.begin(), inputDataContainer.end(), std::back_inserter( copiedContainer ) );
			copiedContainer.insert( copiedContainer.end(), inputDataContainer.begin(), inputDataContainer.end() );
			copiedContainer.insert( copiedContainer.end(), inputDataContainer.begin(), inputDataContainer.end() );
			copiedContainer.insert( copiedContainer.end(), inputDataContainer.begin(), inputDataContainer.end() );

			IntegerType copied_container_size = copiedContainer.size();

			//copied_container_size == container.size() * 4
			IntegerType firstIndex = 0;
			IntegerType lastIndex = container_size * 4 - 1;

			//copied_container_size * 4 / 2  == container.size() * 2
			IntegerType middleIndex = container_size * 2;
			IntegerType middleIndex2 = container_size * 2;

			//生成的乱序的容器数据
			//Generated disordered container data
			std::vector<IntegerType> outputRandomDataContainer;

			//伪随机数
			//Pseudo random number
			IntegerType				 pseudoRandomNumber = 0;
			std::vector<IntegerType> pseudoRandomNumbers;

			PseudoRandomNumberEngine<std::mt19937> PRNE;
			PRNE.InitialBySeed<IntegerType>( randomSeed, false );

			std::mt19937 random_number_generator { randomSeed };

			ShuffleRangeData(copiedContainer, random_number_generator);

			for ( IntegerType index = 0; index < copied_container_size; index++ )
			{
				pseudoRandomNumber = PRNE.GenerateNumber<IntegerType>( firstIndex, lastIndex );
				pseudoRandomNumbers.push_back( pseudoRandomNumber );
			}

			//运行循环次数
			//RTNOC (Run The Number Of Cycles)
			const IntegerType RTONC = std::numeric_limits<IntegerType>::max();

			//被访问的数据
			//Accessed data
			IntegerType accessedData = 0;

			//需要减少几倍的容器访问次数
			//Need to reduce the number of container accesses by a factor of several
			IntegerType OxO = 1;

			//这一轮进行容器访问的剩余次数
			//Remaining number of container accesses performed this round
			IntegerType accessRemaining = needAccessCount;

			//进入无限循环
			//Enter the infinite loop
			for ( IntegerType loopCount = 0; loopCount < RTONC; ++loopCount )
			{
				IntegerType currentElement = copiedContainer.at( middleIndex );
				IntegerType currentElement2 = copiedContainer.at( middleIndex2 );

				if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
				{
					pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] < pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex ] : pseudoRandomNumbers[ middleIndex2 ];

					if ( pseudoRandomNumber % 13 == 0 )
					{
						random_number_generator.seed(pseudoRandomNumbers[ middleIndex ]);
						ShuffleRangeData(copiedContainer.begin(), copiedContainer.end(), random_number_generator);
					}
					else if ( pseudoRandomNumber % 15 == 0 )
					{
						random_number_generator.seed(pseudoRandomNumbers[ middleIndex2 ]);
						ShuffleRangeData(copiedContainer.begin(), copiedContainer.end(), random_number_generator);
					}
				}

				//当前已经访问到容器数据尾部
				//The tail of the container data is currently being accessed
				if ( middleIndex == firstIndex )
				{
					outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement );
					middleIndex = copied_container_size / 2;
				}

				if ( middleIndex2 == firstIndex )
				{
					outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement2 );
					middleIndex2 = copied_container_size / 2;
				}

				//当前已经访问到容器数据首部
				//The container data head is currently being accessed
				if ( middleIndex == lastIndex )
				{
					outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement );
					middleIndex = copied_container_size / 2;
				}

				if ( middleIndex2 == lastIndex )
				{
					outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement2 );
					middleIndex2 = copied_container_size / 2;
				}

				//当前的这一轮容器的访问次数已使用完毕
				//The current round of container accesses has been used up
				if ( accessRemaining == 0 )
				{
					//继续下一轮容器访问
					//Continue to next round of container access
					if ( OxO == 1 )
					{
						accessRemaining = needAccessCount;
					}
					OxO *= 2;
					accessRemaining /= OxO;

					//输出容器的元素数量是否等于输入容器的元素数量的四倍？
					//Is the number of elements of the output container equal to four times the number of elements of the input container?
					if ( outputRandomDataContainer.size() == inputDataContainer.size() * 4 )
					{
						//退出无限循环
						//Exit the infinite loop
						break;
					}

					if ( accessRemaining == 0 )
					{
						continue;
					}
				}
				else
				{
					//输出容器的元素数量是否不等于输入容器的元素数量的两倍？
					//Is the number of elements of the output container not equal to twice the number of elements of the input container?
					if ( outputRandomDataContainer.size() != inputDataContainer.size() * 4 || outputRandomDataContainer.size() < inputDataContainer.size() * 4 )
					{
						outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement );
					}
					if ( outputRandomDataContainer.size() != inputDataContainer.size() * 4 || outputRandomDataContainer.size() < inputDataContainer.size() * 4 )
					{
						outputRandomDataContainer.insert( outputRandomDataContainer.begin(), currentElement2 );
					}
				}

				//当前这个数是奇数还是偶数
				//Is the current number odd or is it even?
				if ( ( currentElement & 1 ) != 0 )
				{
					if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
					{
						pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] > pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex2 ] : pseudoRandomNumbers[ middleIndex ];
						middleIndex -= pseudoRandomNumber;
					}

					//当前访问超出范围
					//The current access is out of range?
					if ( ( middleIndex > pseudoRandomNumbers.size() ) || 0 < middleIndex )
					{
						middleIndex = PRNE.GenerateNumber<IntegerType>( firstIndex, lastIndex );
					}
					else
					{
						if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
						{
							accessRemaining = 0;
							continue;
						}
						currentElement = copiedContainer[ middleIndex ];
						accessedData = currentElement;
						outputRandomDataContainer.insert( outputRandomDataContainer.begin(), accessedData );
					}

					//当前这个数是奇数还是偶数
					//Is the current number odd or is it even?
					if ( ( accessRemaining & 1 ) != 0 )
					{
						accessRemaining--;

						if ( pseudoRandomNumber % 7 == 0 )
						{
							//向左旋转容器中的元素位置
							//Rotate the position of the elements in the container to the left (C++ 2020)
							std::ranges::rotate( copiedContainer, copiedContainer.begin() + accessedData );

							if ( pseudoRandomNumber % 5 == 0 )
							{
								random_number_generator.seed(randomSeed);
								ShuffleRangeData(copiedContainer.begin(), copiedContainer.end(), random_number_generator);
							}
						}
					}
					else
					{
						if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
						{
							pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] == pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex2 ] : pseudoRandomNumbers[ middleIndex ];
							middleIndex += pseudoRandomNumber;
						}

						//当前访问超出范围
						//The current access is out of range?
						if ( ( middleIndex > pseudoRandomNumbers.size() ) || 0 < middleIndex )
						{
							middleIndex = ShuffleRangeData<IntegerType>( firstIndex, lastIndex );
						}
						else
						{
							if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
							{
								accessRemaining = 0;
								continue;
							}
							currentElement = copiedContainer[ middleIndex ];
							accessedData = currentElement;
							outputRandomDataContainer.insert( outputRandomDataContainer.begin(), accessedData );
						}

						if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
						{
							accessRemaining = 0;
							continue;
						}

						accessRemaining--;

						if ( pseudoRandomNumber % 1 == 0 )
						{
							//向右旋转容器中的元素位置
							//Rotate the position of the elements in the container to the right (C++ 2020)
							std::ranges::rotate( copiedContainer, copiedContainer.end() - accessedData );

							if ( pseudoRandomNumber % 3 == 0 )
							{
								random_number_generator.seed(randomSeed);
								ShuffleRangeData(copiedContainer.begin(), copiedContainer.end(), random_number_generator);
							}
						}
					}
				}
				else
				{
					middleIndex = pseudoRandomNumber;
				}

				//当前这个数是偶数还是奇数
				//Is the current number even or odd?
				if ( ( currentElement2 & 1 ) == 0 )
				{
					if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
					{
						pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] == pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex ] : pseudoRandomNumbers[ middleIndex2 ];
						middleIndex2 += pseudoRandomNumber;
					}

					//当前访问超出范围
					//The current access is out of range?
					if ( ( middleIndex2 > pseudoRandomNumbers.size() ) || 0 < middleIndex2 )
					{
						middleIndex2 = PRNE.GenerateNumber<IntegerType>( firstIndex, lastIndex );
					}
					else
					{
						if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
						{
							accessRemaining = 0;
							continue;
						}
						currentElement2 = copiedContainer[ middleIndex2 ];
						accessedData = currentElement2;
						outputRandomDataContainer.insert( outputRandomDataContainer.begin(), accessedData );
					}

					//当前这个数是偶数还是奇数
					//Is the current number even or odd?
					if ( ( accessRemaining & 1 ) == 0 )
					{
						accessRemaining--;

						if ( pseudoRandomNumber % 2 == 0 )
						{
							//向右旋转容器中的元素位置
							//Rotate the position of the elements in the container to the right (C++ 2020)
							std::ranges::rotate( copiedContainer, copiedContainer.end() - accessedData );

							if ( pseudoRandomNumber % 8 == 0 )
							{
								ShuffleRangeData<IntegerType, IntegerType>( randomSeed, copiedContainer );
							}
						}
					}
					else
					{
						if ( accessRemaining != 0 && outputRandomDataContainer.size() != copied_container_size || outputRandomDataContainer.size() < copied_container_size )
						{
							pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] < pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex2 ] : pseudoRandomNumbers[ middleIndex ];
							middleIndex2 -= pseudoRandomNumber;
						}

						//当前访问超出范围
						//The current access is out of range?
						if ( ( middleIndex2 > pseudoRandomNumbers.size() ) || 0 < middleIndex2 )
						{
							middleIndex2 = PRNE.GenerateNumber<IntegerType>( firstIndex, lastIndex );
						}
						else
						{
							if ( accessRemaining == 0 || outputRandomDataContainer.size() == copied_container_size )
							{
								accessRemaining = 0;
								continue;
							}
							currentElement2 = copiedContainer[ middleIndex2 ];
							accessedData = currentElement2;
							outputRandomDataContainer.insert( outputRandomDataContainer.begin(), accessedData );
						}

						accessRemaining--;

						if ( pseudoRandomNumber % 4 == 0 )
						{
							//向左旋转容器中的元素位置
							//Rotate the position of the elements in the container to the left (C++ 2020)
							std::ranges::rotate( copiedContainer, copiedContainer.begin() + accessedData );

							if ( pseudoRandomNumber % 6 == 0 )
							{
								ShuffleRangeData<IntegerType, IntegerType>( randomSeed, copiedContainer );
							}
						}
					}
				}
				else
				{
					middleIndex2 = pseudoRandomNumber;
				}

				pseudoRandomNumber = pseudoRandomNumbers[ middleIndex ] > pseudoRandomNumbers[ middleIndex2 ] ? pseudoRandomNumbers[ middleIndex ] : pseudoRandomNumbers[ middleIndex2 ];

				if ( pseudoRandomNumber % 10 == 0 )
				{
					//反转容器中的元素位置
					//Reverses the position of the elements in the container (C++ 2020)
					std::ranges::reverse( copiedContainer.begin(), copiedContainer.end() );

					if ( pseudoRandomNumber % 12 == 0 )
					{
						ShuffleRangeData<IntegerType, IntegerType>( randomSeed, copiedContainer );
					}
				}
			}

			return outputRandomDataContainer;
		}
	}

	#endif
}  // namespace CommonSecurity

namespace Cryptograph
{
	inline void Exclusive_OR( std::byte& Data, const std::byte& Key )
	{
		Data ^= Key;
	}

	inline void Equivalence_OR( std::byte& Data, const std::byte& Key )
	{
		Data ^= Key;
		Data = ~Data;
	}

	inline void BitCirculation_Left( std::byte& Data, const std::byte& Key, unsigned int move_bit )
	{
		Data = ( Data << move_bit ) | ( Data >> ( 8 - move_bit ) );
		//Key = ( Key << move_bit ) | ( Key >> ( 8 - move_bit ) );
	}

	inline void BitCirculation_Right( std::byte& Data, const std::byte& Key, unsigned int move_bit )
	{
		Data = ( Data >> move_bit ) | ( Data << ( 8 - move_bit ) );
		//Key = ( Key >> move_bit ) | ( Key << ( 8 - move_bit ) );
	}

	inline void BitToggle( std::byte& Data, unsigned int position )
	{
		constexpr std::byte Mask{ 1 };

		Data ^= ( Mask << position );
	}
}  // namespace Cryptograph

namespace Cryptograph::CommonModule
{
	/**
	* MCA - Multiple Cryptography Algorithm
	*/

	/*
		//ENUM: Check Or Verify File Data IS Valid Or Invalid For Worker
		enum class CVFD_IsValidOrInvalid4Worker
		{
			MCA_CHECK_FILE_STRUCT,
			MCA_VERIFY_FILE_HASH
		};
	*/

	//ENUM: Cryption Mode To Multiple Cryptography Algorithm Core For File Data Worker
	enum class CryptionMode2MCAC4_FDW
	{
		MCA_ENCRYPTER,
		MCA_DECRYPTER,
		MCA_ENCODER,
		MCA_DECODER,
		MCA_PERMUTATION,
		MCA_PERMUTATION_REVERSE
	};
}

namespace Cryptograph::Bitset
{
	template<std::size_t BitsetSize>
	inline void Exclusive_OR(std::bitset<BitsetSize>& bits, const std::bitset<BitsetSize>& other_bits)
	{
		bits ^= other_bits;
	}

	template<std::size_t BitsetSize>
	inline void Equivalence_OR(std::bitset<BitsetSize>& bits, const std::bitset<BitsetSize>& other_bits)
	{
		bits ^= other_bits;
		bits = ~bits;
	}

	template<size_t BitsetSize>
	inline void BitLeftCircularShift(const std::bitset<BitsetSize>& bits, std::size_t shift_count, std::bitset<BitsetSize>& result_bits)
	{
					auto rotate_move_remainder = shift_count % BitsetSize;  // Limit count to range [0,N)
					auto part_bits = bits << shift_count;
					auto part2_bits = bits >> (BitsetSize - rotate_move_remainder);
					result_bits = part_bits | part2_bits;
		/*
			  result_bits = (bits << count | bits >> (BitsetSize - count));
			The shifted bits ^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^ The wrapped bits
		*/
	}

	template<size_t BitsetSize>
	inline void BitRightCircularShift(const std::bitset<BitsetSize>& bits, std::size_t shift_count, std::bitset<BitsetSize>& result_bits )
	{
					auto rotate_move_remainder = shift_count % BitsetSize;  // Limit count to range [0,N)
					auto part_bits = bits >> shift_count;
					auto part2_bits = bits << (BitsetSize - rotate_move_remainder);
					result_bits = part_bits | part2_bits;
		/*
			  result_bits = (bits >> count | bits << (BitsetSize - count));
			The shifted bits ^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^ The wrapped bits
		*/
	}

	template<size_t BitsetSize>
	inline void BitToggle( std::bitset<BitsetSize>& bits, std::size_t index )
	{
		constexpr std::bitset<BitsetSize> Mask{ 1 };

		index %= BitsetSize;  // Limit count to range [0,N)
		bits ^= ( Mask << index );
	}

	template<std::size_t SIZE>
	struct bitset_size
	{
		bitset_size(const std::bitset<SIZE>&)
		{
		}
		static constexpr std::size_t BITSET_SIZE = SIZE;
	};

	template<std::size_t BinaryDataCopySize, std::size_t SplitPosition_OnePartSize, std::size_t SplitPosition_TwoPartSize = BinaryDataCopySize - SplitPosition_OnePartSize>
	inline std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> SplitBitset(const std::bitset<BinaryDataCopySize>& BinaryData)
	{
		constexpr std::size_t BinaryDataSize = decltype(bitset_size{ BinaryData })::BITSET_SIZE;

		//invalied_split_binary
		static_assert(BinaryDataCopySize != 0 && BinaryDataSize != 0, "Unexpected logic error: Binary data size BinaryData.size() must not be 0!\n源二进制数据大小BinaryData.size()不得为0");

		//invalied_split_binary
		static_assert(BinaryDataSize == BinaryDataCopySize,"Unexpected logic error: The source data size BinaryData.size() does not match the template parameter BitsetCopySize \n源数据大小BinaryData.size()与模板参数BinaryDataCopySize不一致");

		if constexpr(SplitPosition_OnePartSize + SplitPosition_TwoPartSize != BinaryDataSize)
		{
			//invalied_split_binary
			static_assert(CommonToolkit::Dependent_Always_Failed<decltype(BinaryDataCopySize)>,"Unexpected logic error: The size of the two target binary data comes from the total size of the source binary data after the split is completed, where one or both of the subsizes are not and range complementary. \n两个目标二进制数据的大小，来自于分割完成之后源二进制数据的总大小，其中有一个或者两个的子大小是不和范围互补的");
		}
		else if constexpr(SplitPosition_OnePartSize >= BinaryDataSize || SplitPosition_TwoPartSize >= BinaryDataSize)
		{
			//invalied_split_binary
			static_assert(CommonToolkit::Dependent_Always_Failed<decltype(SplitPosition_OnePartSize)>, "Unexpected logic error: Binary data split point position out of range!\n二进制数据分割点位置超出范围");
		}
		else
		{
			using WordType = std::conditional_t<BinaryDataSize <= std::numeric_limits<unsigned long>::digits, unsigned long, unsigned long long>;

			if constexpr(SplitPosition_OnePartSize <= std::numeric_limits<unsigned long long>::digits && SplitPosition_TwoPartSize <= std::numeric_limits<unsigned long long>::digits)
			{
				//Example binary data:
				//A is: 0001'1010'0110'0111'0011'0010'0100(Digits size is 26 bit)
				//B is: 13
				//A with B split to C and D:
				//C is: 0001'101'0011'0011
				//D is: 0010'011'0010'0100
			
				/*
					The process of implementation:
						High Digit Binary data calculation:
							Step 1: 0000'0000'0000'0000'1101'0011'0011 = 0001'1010'0110'0111'0011'0010'0100 >> 13 (Bit Right Shift)
							Step 2: 0000'1101'0011'0011 and 0000'0000'0000'0000'1101'0011'0011 It's actually the same!
						Low Digit Binary data calculation:
							Step 1: SelectedBinaryDigit = ~(1 << index)
							If index is 14, Then 0000'0000'0000'0010'0000'0000'0000 = 0000'0000'0000'0000'0000'0000'0001 << 14 (Bit Left Shift)
							Step 2: SelectedBinaryDigit = 1111'1111'1111'1101'1111'1111'1111 = ~0000'0000'0000'0010'0000'0000'0000 (Bit Not)
							Step 3: 0001'1010'0110'0101'0011'0010'0100 = 0001'1010'0110'0111'0011'0010'0100 & 1111'1111'1111'1101'1111'1111'1111 (Bit And)
							Step 4: Repeat the above steps until all binary data high bit 1s are changed to data bit 0
				*/

				/*
				//Reset binary HighDigitPart bit
				//复位二进制高位部分位
				for(unsigned long long index = BitsetCopySize; index != 0 && index != SplitPosition_TwoPartSize; --index )
				{
					unsigned long long BitsetDataPosition = 1 << index;
					unsigned long long BitsetDataPositionMask = ~BitsetDataPosition;
					LowDigitPartDataWithInteger = LowDigitPartDataWithInteger & BitsetDataPositionMask;
				}

				//Reset binary LowDigitPart bit
				//复位二进制低位部分位
				for(unsigned long long index = SplitPosition_OnePartSize; index != 0 && index != BitsetCopySize + 1; ++index )
				{
					unsigned long long BitsetDataPosition = 1 << index;
					unsigned long long BitsetDataPositionMask = ~BitsetDataPosition;
					HighDigitPartDataWithInteger = HighDigitPartDataWithInteger & BitsetDataPositionMask;
				}
				*/

				std::bitset<BinaryDataCopySize> BitsetDataCopy { BinaryData };

				if constexpr(SplitPosition_OnePartSize == SplitPosition_TwoPartSize)
				{
					WordType BitsetDataWithInteger;


					if constexpr(BinaryDataCopySize <= sizeof(WordType) * std::numeric_limits<unsigned char>::digits)
					{
						if constexpr(std::same_as<WordType, unsigned long long>)
							BitsetDataWithInteger = BitsetDataCopy.to_ullong();
						else
							BitsetDataWithInteger = BitsetDataCopy.to_ulong();

						//Discard binary LowDigitPart bits
						//丢弃二进制低位部分位数
						WordType HighDigitPartDataWithInteger = BitsetDataWithInteger >> SplitPosition_OnePartSize;

						//Discard binary HighDigitPart bits
						//丢弃二进制高位部分位数
						WordType LowDigitPartDataWithInteger = BitsetDataWithInteger << SplitPosition_TwoPartSize;
						LowDigitPartDataWithInteger = LowDigitPartDataWithInteger >> SplitPosition_TwoPartSize;

						std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ HighDigitPartDataWithInteger };
						std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ LowDigitPartDataWithInteger };
						return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
					}
					else
					{
						std::string BinaryDataString = BinaryData.to_string();

						std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ BinaryDataString.substr(0, SplitPosition_OnePartSize) };
						std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ BinaryDataString.substr(SplitPosition_OnePartSize, SplitPosition_TwoPartSize) };
						return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
					}

				}
				else
				{
					/*
					
						10 <-> 1010
						11 <-> 1011

						Source Binary Data:
						0000 0000 0001 0100 1110 0011 1001 1100

						1010011100
						01110011100

						Bit Right Shift (Logic):
						0000 0000 0000 0000 0000 0010 1001 1100 = 0000 0000 0001 0100 1110 0011 1001 1100 >> 11

						Bits Right Rotate:
						0111 0011 1000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0010 1001 1100 = (0000 0000 0001 0100 1110 0011 1001 1100  >> 11) | (0000 0000 0001 0100 1110 0011 1001 1100 << 32 - 11)

						Bit Right Shift (Logic):
						0001 1100 1110 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 = 0111 0011 1000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0010 1001 1100 >> 10

						Bits Left Rotate:
						0000 0000 0000 0000 0000 0011 1001 1100 = (0001 1100 1110 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  << (10 + 11)) | (0001 1100 1110 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 >> 32 - (10 + 11))

						0000000000000-01010011100

						Target Binary Pair:
						1010011100
						01110011100
					
					*/

					if constexpr(SplitPosition_OnePartSize < SplitPosition_TwoPartSize)
					{
						if constexpr( BinaryDataCopySize <= (sizeof(WordType) * std::numeric_limits<unsigned char>::digits) )
						{
							WordType BitsetDataWithInteger = 0;
							WordType HighDigitPartDataWithInteger = 0;
							WordType LowDigitPartDataWithInteger = 0;

							if constexpr(std::same_as<WordType, unsigned long long>)
								BitsetDataWithInteger = BitsetDataCopy.to_ullong();
							else
								BitsetDataWithInteger = BitsetDataCopy.to_ulong();

							//Discard binary LowDigitPart bits
							//丢弃二进制低位部分位数
							HighDigitPartDataWithInteger = BitsetDataWithInteger >> SplitPosition_TwoPartSize;

							//By right (circular shift) rotation, the low bits of binary data are moved to the high bits (and reversed)
							//Facilitates discarding the original high bits of data
							//通过右(循环移位)旋转，将二进制的低位比特的数据，移动至高位(并且反向)
							//便于丢弃原高位比特的数据
							LowDigitPartDataWithInteger = std::rotr(BitsetDataWithInteger, SplitPosition_TwoPartSize);

							//Discard the original high bits of data
							//丢弃原高位比特的数据
							LowDigitPartDataWithInteger = LowDigitPartDataWithInteger >> SplitPosition_OnePartSize;
						
							//By left (circular shift) rotation, the high bits of the binary data are moved to the low bits (and reversed)
							//Used to recover the original low bits of data
							//通过左(循环移位)旋转，将二进制的高位比特的数据，移动至低位(并且反向)
							//用于恢复原低位比特的数据
							LowDigitPartDataWithInteger = std::rotl(LowDigitPartDataWithInteger, SplitPosition_OnePartSize + SplitPosition_TwoPartSize);

							std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ HighDigitPartDataWithInteger };
							std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ LowDigitPartDataWithInteger };
							return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
						}
						else
						{
							std::string BinaryDataString = BinaryData.to_string();

							std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ BinaryDataString.substr(0, SplitPosition_OnePartSize) };
							std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ BinaryDataString.substr(SplitPosition_OnePartSize, SplitPosition_TwoPartSize) };
							return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
						}
					}
					if constexpr(SplitPosition_OnePartSize > SplitPosition_TwoPartSize)
					{
						if constexpr( BinaryDataCopySize <= (sizeof(WordType) * std::numeric_limits<unsigned char>::digits) )
						{
							WordType BitsetDataWithInteger = 0;
							WordType HighDigitPartDataWithInteger = 0;
							WordType LowDigitPartDataWithInteger = 0;

							if constexpr(std::same_as<WordType, unsigned long long>)
								BitsetDataWithInteger = BitsetDataCopy.to_ullong();
							else
								BitsetDataWithInteger = BitsetDataCopy.to_ulong();

							//Discard binary LowDigitPart bits
							//丢弃二进制低位部分位数
							HighDigitPartDataWithInteger = BitsetDataWithInteger >> SplitPosition_TwoPartSize;

							//By right (circular shift) rotation, the low bits of binary data are moved to the high bits (and reversed)
							//Facilitates discarding the original high bits of data
							//通过右(循环移位)旋转，将二进制的低位比特的数据，移动至高位(并且反向)
							//便于丢弃原高位比特的数据
							LowDigitPartDataWithInteger = std::rotr(BitsetDataWithInteger, SplitPosition_TwoPartSize);

							//Discard the original high bits of data
							//丢弃原高位比特的数据
							LowDigitPartDataWithInteger = LowDigitPartDataWithInteger >> SplitPosition_OnePartSize;
						
							//By left (circular shift) rotation, the high bits of the binary data are moved to the low bits (and reversed)
							//Used to recover the original low bits of data
							//通过左(循环移位)旋转，将二进制的高位比特的数据，移动至低位(并且反向)
							//用于恢复原低位比特的数据
							LowDigitPartDataWithInteger = std::rotl(LowDigitPartDataWithInteger, SplitPosition_OnePartSize + SplitPosition_TwoPartSize);

							std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ HighDigitPartDataWithInteger };
							std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ LowDigitPartDataWithInteger };
							return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
						}
						else
						{
							std::string BinaryDataString = BinaryData.to_string();

							std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData{ BinaryDataString.substr(0, SplitPosition_OnePartSize) };
							std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData{ BinaryDataString.substr(SplitPosition_OnePartSize, SplitPosition_TwoPartSize) };
							return std::pair<std::bitset<SplitPosition_OnePartSize>, std::bitset<SplitPosition_TwoPartSize>> { HighDigitPartBitsetData, LowDigitPartBitsetData };
						}
					}
				}
			}
			else
			{
				std::bitset<SplitPosition_OnePartSize> HighDigitPartBitsetData;
				std::bitset<SplitPosition_TwoPartSize> LowDigitPartBitsetData;

				for(std::size_t index = 0; index != BinaryData.size(); ++index)
				{
					if(index < SplitPosition_OnePartSize)
					{
						if(BinaryData.operator[](index))
						{
							LowDigitPartBitsetData.operator[](index) = BinaryData.operator[](index);
						}
					}
					else
					{
						if(BinaryData.operator[](index))
						{
							HighDigitPartBitsetData.operator[](index - SplitPosition_OnePartSize) = BinaryData.operator[](index);
						}
					}
				}
			}
		}
	}

	template <std::size_t BitsetSize, std::size_t BitsetSize2 >
	inline std::bitset <BitsetSize + BitsetSize2> ConcatenateBitset( const std::bitset<BitsetSize>& leftBinaryData, const std::bitset<BitsetSize2>& rightBinaryData, bool isNeedSwapTwoPart )
	{
		constexpr unsigned long long ConcatenateBinarySize = BitsetSize + BitsetSize2;

		//invalied_concat_binary
		static_assert(decltype(bitset_size{ leftBinaryData })::BITSET_SIZE != 0 && decltype(bitset_size{ rightBinaryData })::BITSET_SIZE != 0, "Unexpected logic error: The size of the two parts of the binary data that need to be concatenated, the size of their bits, cannot have either one of them be 0 or both of them be 0!\n需要的串接的两个部分的二进制数据，它们的位数的大小，不能有任意一个是0或者两个都是0");

		constexpr unsigned long long ConcatenateBinarySize2 = decltype(bitset_size{ leftBinaryData })::BITSET_SIZE + decltype(bitset_size{ rightBinaryData })::BITSET_SIZE;

		//invalied_concat_binary
		static_assert(ConcatenateBinarySize == ConcatenateBinarySize2, "Unexpected logic error: The source data size leftBinaryData.size() + rightBinaryData.size() does not match the result of the template parameter BitsetSize + BitsetSize2!\n源数据大小 leftBinaryData.size() + rightBinaryData.size() 与模板参数 BitsetSize + BitsetSize2 的结果不一致");

		using WordType = std::conditional_t<ConcatenateBinarySize <= std::numeric_limits<unsigned long>::digits, unsigned long, unsigned long long>;

		if constexpr(ConcatenateBinarySize <= std::numeric_limits<unsigned long long>::digits)
		{
			//Example binary data:
			//A is: 0000'1101'0011'0011(Digits size is 13 bit)
			//B is: 0001'0011'0010'0100(Digits size is 13 bit)

			//C from A concate B: 0001'1010'0110'0111'0011'0010'0100

			/*
			The process of implementation:
				Binary data calculation:
					Step 1: 0001'1010'0110'0110'0000'0000'0000 = 0000'1101'0011'0011 << 13 (Bit Left Shift)
					Step 2: 0001'0011'0010'0100 and 0000'0000'0000'0001'0011'0010'0100, It's actually the same!
					Step 3: 0001'1010'0110'0111'0011'0010'0100 = 0001'1010'0110'0110'0000'0000'0000 | 0000'0000'0000'0001'0011'0010'0100 (Bit Or)
			*/

			//Discard binary HighDigitPart bit and Reset binary LowDigitPart bit, then Set binary LowDigitPart bit.
			//丢弃二进制高位部分的位数并重置二进制低位部分的位数，然后设置二进制低位部分的位数。

			if(!isNeedSwapTwoPart)
			{
				WordType ConcatenatedBinaryDataWithInteger = leftBinaryData.to_ullong() << leftBinaryData.size() | rightBinaryData.to_ullong();

				std::bitset<ConcatenateBinarySize> ConcatenatedBitset( ConcatenatedBinaryDataWithInteger );
				return ConcatenatedBitset;
			}
			else
			{
				WordType ConcatenatedBinaryDataWithInteger = rightBinaryData.to_ullong() << rightBinaryData.size() | leftBinaryData.to_ullong();

				std::bitset<ConcatenateBinarySize> ConcatenatedBitset( ConcatenatedBinaryDataWithInteger );
				return ConcatenatedBitset;
			}
		}
		else
		{
			if(!isNeedSwapTwoPart)
			{
				//Binary string concat
				std::string binaryDataString = leftBinaryData.to_string() + rightBinaryData.to_string();
				return std::bitset<ConcatenateBinarySize>( binaryDataString );
			}
			else
			{
				//Binary string concat
				std::string binaryDataString = rightBinaryData.to_string() + leftBinaryData.to_string();
				return std::bitset<ConcatenateBinarySize>( binaryDataString );
			}
		}
	}

	inline std::bitset<64> ClassicByteArrayToBitset64Bit(const std::vector<unsigned char>& ByteArray)
	{
		unsigned long long TemporaryInteger = 0;
		if(ByteArray.size() != sizeof(TemporaryInteger))
		{
			std::length_error conversion_type_data_is_undefined_behaviour("This object CharacterArray size is not equal 8 !");
			throw conversion_type_data_is_undefined_behaviour;
		}
		std::memcpy(&TemporaryInteger, ByteArray.data(), sizeof(TemporaryInteger));
		std::bitset<64> Bitset64Object(TemporaryInteger);
		return Bitset64Object;
	}

	inline std::vector<unsigned char> ClassicByteArrayFromBitset64Bit(const std::bitset<64>& Bitset64Object)
	{
		unsigned long long TemporaryInteger { Bitset64Object.to_ullong() };
		std::vector<unsigned char> ByteArray { reinterpret_cast<unsigned char *>( &TemporaryInteger ), reinterpret_cast<unsigned char *>( &TemporaryInteger + 1 ) };
		return ByteArray;
	}
}