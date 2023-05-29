#pragma once

/*
 * Random-Number Utilities (randutil)
 *	   Addresses common issues with C++11 random number generation.
 *	   Makes good seeding easier, and makes using RNGs easy while retaining
 *	   all the power.
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2022 Melissa E. O'Neill
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef RANDUTILS_HPP
#define RANDUTILS_HPP 1

/*
* This header includes three class templates that can help make C++11
* random number generation easier to use.
*
* randutils::seed_sequence_fe
*
*	 Fixed-Entropy Seed sequence
*
*	 Provides a replacement for std::seed_seq that avoids problems with bias,
*	 performs better in empirical statistical tests, and executes faster in
*	 normal-sized use cases.
*
*	 In normal use, it's accessed via one of the following type aliases
*
*		 randutils::seed_sequence_fe128
*		 randutils::seed_sequence_fe256
*
*	 It's discussed in detail at
*		 http://www.pcg-random.org/posts/developing-a-seed_seq-alternative.html
*	 and the motivation for its creation (what's wrong with std::seed_seq) here
*		 http://www.pcg-random.org/posts/cpp-seeding-surprises.html
*
*
* randutils::auto_seeded
*
*	 Extends a seed sequence class with a nondeterministic default constructor.
*	 Uses a variety of local sources of entropy to portably initialize any
*	 seed sequence to a good default state.
*
*	 In normal use, it's accessed via one of the following type aliases, which
*	 use seed_sequence_fe128 and seed_sequence_fe256 above.
*
*		 randutils::auto_seed_128
*		 randutils::auto_seed_256
*
*	 It's discussed in detail at
*		 http://www.pcg-random.org/posts/simple-portable-cpp-seed-entropy.html
*	 and its motivation (why you can't just use std::random_device) here
*		 http://www.pcg-random.org/posts/cpps-random_device.html
*
*
* randutils::random_generator
*
*	 An Easy-to-Use Random API
*
*	 Provides all the power of C++11's random number facility in an easy-to
*	 use wrapper.
*
*	 In normal use, it's accessed via one of the following type aliases, which
*	 also use auto_seed_256 by default
*
*		 randutils::default_rng
*		 randutils::mt19937_rng
*
*	 It's discussed in detail at
*		 http://www.pcg-random.org/posts/ease-of-use-without-loss-of-power.html
*/

//#include <cstddef>
//#include <cstdint>
//#include <cstdlib>
//
//#include <random>
//#include <array>
//#include <functional>	 // for std::hash
//#include <initializer_list>
//#include <utility>
//#include <type_traits>
//#include <iterator>
//#include <chrono>
//#include <thread>
//#include <algorithm>

// Ugly platform-specific code for auto_seeded

#if !defined(RANDOM_UTILS_CPU_ENTROPY) && defined(__has_builtin)
	#if __has_builtin(__builtin_readcyclecounter) && !defined(__aarch64__)
		#define RANDOM_UTILS_CPU_ENTROPY __builtin_readcyclecounter()
	#endif
#endif
#if !defined(RANDOM_UTILS_CPU_ENTROPY)
	#if __i386__
		#if __GNUC__
			#define RANDOM_UTILS_CPU_ENTROPY __builtin_ia32_rdtsc()
		#else
			#include <immintrin.h>
			#define RANDOM_UTILS_CPU_ENTROPY __rdtsc()
		#endif
	#else
		#define RANDOM_UTILS_CPU_ENTROPY 0
	#endif
#endif

#if defined(RANDOM_UTILS_GETPID)
	// Already defined externally
#elif defined(_WIN64) || defined(_WIN32)
	#include <process.h>
	#define RANDOM_UTILS_GETPID _getpid()
#elif defined(__unix__) || defined(__unix) \
	  || (defined(__APPLE__) && defined(__MACH__))
	#include <unistd.h>
	#define RANDOM_UTILS_GETPID getpid()
#else
	#define RANDOM_UTILS_GETPID 0
#endif

#if __cpp_constexpr >= 201304L
	#define RANDOM_UTILS_GENERALIZED_CONSTEXPR constexpr
#else
	#define RANDOM_UTILS_GENERALIZED_CONSTEXPR
#endif



namespace CommonSecurity::SecureRandomUtils
{

	//////////////////////////////////////////////////////////////////////////////
	//
	// seed_sequence_fe
	//
	//////////////////////////////////////////////////////////////////////////////

	/*
	* seed_sequence_fe implements a fixed-entropy seed sequence; it conforms to all
	* the requirements of a Seed Sequence concept.
	*
	* seed_sequence_fe<N> implements a seed sequence which seeds based on a store of
	* N * 32 bits of entropy.	Typically, it would be initialized with N or more
	* integers.
	*
	* seed_sequence_fe128 and seed_sequence_fe256 are provided as convenience typedefs for
	* 128- and 256-bit entropy stores respectively.  These variants outperform
	* std::seed_seq, while being better mixing the bits it is provided as entropy.
	* In almost all common use cases, they serve as better drop-in replacements
	* for seed_seq.
	*
	* Technical details
	*
	* Assuming it constructed with M seed integers as input, it exhibits the
	* following properties
	*
	* * Diffusion/Avalanche:  A single-bit change in any of the M inputs has a
	*	 50% chance of flipping every bit in the bitstream produced by generate.
	*	 Initializing the N-word entropy store with M words requires O(N * M)
	*	 time precisely because of the avalanche requirements.	Once constructed,
	*	 calls to generate are linear in the number of words generated.
	*
	* * Bias freedom/Bijection: If M == N, the state of the entropy store is a
	*	 bijection from the M inputs (i.e., no states occur twice, none are
	*	 omitted). If M > N the number of times each state can occur is the same
	*	 (each state occurs 2**(32*(M-N)) times, where ** is the power function).
	*	 If M < N, some states cannot occur (bias) but no state occurs more
	*	 than once (it's impossible to avoid bias if M < N; ideally N should not
	*	 be chosen so that it is more than M).
	*
	*	 Likewise, the generate function has similar properties (with the entropy
	*	 store as the input data).	If more outputs are requested than there is
	*	 entropy, some outputs cannot occur.  For example, the Mersenne Twister
	*	 will request 624 outputs, to initialize it's 19937-bit state, which is
	*	 much larger than a 128-bit or 256-bit entropy pool.  But in practice,
	*	 limiting the Mersenne Twister to 2**128 possible initializations gives
	*	 us enough initializations to give a unique initialization to trillions
	*	 of computers for billions of years.  If you really have 624 words of
	*	 *real* high-quality entropy you want to use, you probably don't need
	*	 an entropy mixer like this class at all.  But if you *really* want to,
	*	 nothing is stopping you from creating a randutils::seed_sequence_fe<624>.
	*
	* * As a consequence of the above properties, if all parts of the provided
	*	 seed data are kept constant except one, and the remaining part is varied
	*	 through K different states, K different output sequences will be produced.
	*
	* * Also, because the amount of entropy stored is fixed, this class never
	*	 performs dynamic allocation and is free of the possibility of generating
	*	 an exception.
	*
	* Ideas used to implement this code include hashing, a simple PCG generator
	* based on an MCG base with an XorShift output function and permutation
	* functions on tuples.
	*
	* More detail at
	*	   http://www.pcg-random.org/posts/developing-a-seed_seq-alternative.html
	*/

	template
	<
		size_t count = 4, typename IntRep = uint32_t,
		size_t mix_rounds = 1 + (count <= 2)
	>
	struct seed_sequence_fe
	{

	public:
		// types
		typedef IntRep result_type;

	private:
		static constexpr uint32_t INIT_A = 0x43b0d7e5;
		static constexpr uint32_t MULT_A = 0x931e8875;

		static constexpr uint32_t INIT_B = 0x8b51f9dd;
		static constexpr uint32_t MULT_B = 0x58f38ded;

		static constexpr uint32_t MIX_MULT_L = 0xca01f9dd;
		static constexpr uint32_t MIX_MULT_R = 0x4973f715;
		static constexpr uint32_t XSHIFT = sizeof(IntRep)*8/2;

		RANDOM_UTILS_GENERALIZED_CONSTEXPR
		static IntRep fast_exponential(IntRep x, IntRep power)
		{
			IntRep result = IntRep(1);
			IntRep multiplier = x;
			while (power != IntRep(0))
			{
				IntRep thismult = power & IntRep(1) ? multiplier : IntRep(1);
				result *= thismult;
				power >>= 1;
				multiplier *= multiplier;
			}
			return result;
		}

		std::array<IntRep, count> _hash_mixer_;

		template <typename InputIter>
		void mix_entropy(InputIter begin, InputIter end);

	public:
		seed_sequence_fe(const seed_sequence_fe&)	  = delete;
		void operator=(const seed_sequence_fe&)	 = delete;

		template <typename T>
		seed_sequence_fe(std::initializer_list<T> init)
		{
			seed(init.begin(), init.end());
		}

		template <typename InputIter>
		seed_sequence_fe(InputIter begin, InputIter end)
		{
			seed(begin, end);
		}

		// generating functions
		template <typename RandomAccessIterator>
		void generate(RandomAccessIterator first, RandomAccessIterator last) const;

		static constexpr size_t size()
		{
			return count;
		}

		template <typename OutputIterator>
		void param(OutputIterator dest) const;

		template <typename InputIter>
		void seed(InputIter begin, InputIter end)
		{
			mix_entropy(begin, end);
			// For very small sizes, we do some additional mixing.
			// For normal sizes, this loop never performs any iterations.
			for (size_t i = 1; i < mix_rounds; ++i)
				stir();
		}

		seed_sequence_fe& stir()
		{
			mix_entropy(_hash_mixer_.begin(), _hash_mixer_.end());
			return *this;
		}

	};

	template <size_t count, typename IntRep, size_t r>
	template <typename InputIter>
	void seed_sequence_fe<count, IntRep, r>::mix_entropy(InputIter begin, InputIter end)
	{
		auto hash_const = INIT_A;
		auto hash = [&](IntRep value)
		{
			value ^= hash_const;
			hash_const *= MULT_A;
			value *= hash_const;
			value ^= value >> XSHIFT;
			return value;
		};

		auto mix = [](IntRep x, IntRep y)
		{
			IntRep result = MIX_MULT_L*x - MIX_MULT_R*y;
			result ^= result >> XSHIFT;
			return result;
		};

		InputIter current = begin;
		for (auto& elem : _hash_mixer_)
		{
			if (current != end)
				elem = hash(*current++);
			else
				elem = hash(0U);
		}

		for (auto& src : _hash_mixer_)
			for (auto& dest : _hash_mixer_)
				if (&src != &dest)
					dest = mix(dest,hash(src));

		for (; current != end; ++current)
			for (auto& dest : _hash_mixer_)
				dest = mix(dest,hash(*current));
	}

	template <size_t count, typename IntRep, size_t mix_rounds>
	template <typename OutputIterator>
	void seed_sequence_fe<count,IntRep,mix_rounds>::param(OutputIterator dest) const
	{
		const IntRep INV_A = fast_exponential(MULT_A, IntRep(-1));
		const IntRep MIX_INV_L = fast_exponential(MIX_MULT_L, IntRep(-1));

		auto mixer_copy = _hash_mixer_;
		for (size_t round = 0; round < mix_rounds; ++round) {
			// Advance to the final value.	We'll backtrack from that.
			auto hash_const = INIT_A*fast_exponential(MULT_A, IntRep(count * count));

			for (auto src = mixer_copy.rbegin(); src != mixer_copy.rend(); ++src)
				for (auto dest = mixer_copy.rbegin(); dest != mixer_copy.rend(); ++dest)
					if (src != dest)
					{
						IntRep revhashed = *src;
						auto mult_const = hash_const;
						hash_const *= INV_A;
						revhashed ^= hash_const;
						revhashed *= mult_const;
						revhashed ^= revhashed >> XSHIFT;
						IntRep unmixed = *dest;
						unmixed ^= unmixed >> XSHIFT;
						unmixed += MIX_MULT_R*revhashed;
						unmixed *= MIX_INV_L;
						*dest = unmixed;
					}

			for (auto r_iterator = mixer_copy.rbegin(); r_iterator != mixer_copy.rend(); ++r_iterator)
			{
				IntRep unhashed = *r_iterator;
				unhashed ^= unhashed >> XSHIFT;
				unhashed *= fast_exponential(hash_const, IntRep(-1));
				hash_const *= INV_A;
				unhashed ^= hash_const;
				*r_iterator = unhashed;
			}
		}
		std::copy(mixer_copy.begin(), mixer_copy.end(), dest);
	}


	template <size_t count, typename IntRep, size_t mix_rounds>
	template <typename RandomAccessIterator>
	void seed_sequence_fe<count,IntRep,mix_rounds>::generate
	(
			RandomAccessIterator dest_begin,
			RandomAccessIterator dest_end
	) const
	{
		auto src_begin = _hash_mixer_.begin();
		auto src_end   = _hash_mixer_.end();
		auto src	   = src_begin;
		auto hash_const = INIT_B;
		for (auto dest = dest_begin; dest != dest_end; ++dest)
		{
			auto data_value = *src;
			if (++src == src_end)
				src = src_begin;
			data_value ^= hash_const;
			hash_const *= MULT_B;
			data_value *= hash_const;
			data_value ^= data_value >> XSHIFT;
			*dest = data_value;
		}
	}

	using seed_sequence_fe128 = seed_sequence_fe<4, uint32_t>;
	using seed_sequence_fe256 = seed_sequence_fe<8, uint32_t>;


	//////////////////////////////////////////////////////////////////////////////
	//
	// auto_seeded
	//
	//////////////////////////////////////////////////////////////////////////////

	/*
	 * randutils::auto_seeded
	 *
	 *	 Extends a seed sequence class with a nondeterministic default constructor.
	 *	 Uses a variety of local sources of entropy to portably initialize any
	 *	 seed sequence to a good default state.
	 *
	 *	 In normal use, it's accessed via one of the following type aliases,
	 *   which use seed_sequence_fe128 and seed_sequence_fe256 above.
	 *
	 *		 randutils::auto_seed_128
	 *		 randutils::auto_seed_256
	 *
	 *	 It's discussed in detail at
	 *		 http://www.pcg-random.org/posts/simple-portable-cpp-seed-entropy.html
	 *	 and its motivation (why you can't just use std::random_device) here
	 *		 http://www.pcg-random.org/posts/cpps-random_device.html
	 */

	template <typename SeedSequence>
	class auto_seeded : public SeedSequence
	{
		using default_seeds = std::array<uint32_t, 13>;

		template <typename T>
		static uint32_t shift_to_32bit_integer(T value)
		{
			if (sizeof(T) <= 4)
				return uint32_t(value);
			else
			{
				uint64_t result = uint64_t(value);
				result *= 0xbc2ad017d719504d;
				return uint32_t(result ^ (result >> 32));
			}
		}

		template <typename T>
		static uint32_t hash(T&& value)
		{
			return shift_to_32bit_integer
			(
				std::hash<typename std::remove_reference<typename std::remove_cv<T>::type>::type>{}
				(
					std::forward<T>(value)
				)
			);
		}

		static constexpr uint32_t fnv(uint32_t hash, const char* pos)
		{
			return *pos == '\0' ? hash : fnv((hash * 16777619U) ^ *pos, pos+1);
		}

		default_seeds local_entropy()
		{
			// This is a constant that changes every time we compile the code
			constexpr uint32_t compile_stamp =
				fnv(2166136261U, __DATE__ __TIME__ __FILE__);

			// Some people think you shouldn't use the random device much because on some platforms it could be expensive to call or "use up" vital system-wide entropy,
			// so we just call it once.
			static uint32_t random_int = std::random_device{}();

			// The heap can vary from run to run as well.
			void* malloc_address = malloc(sizeof(int));
			free(malloc_address);
			auto heap  = hash(malloc_address);
			auto stack = hash(&malloc_address);

			// Every call, we increment our random int.
			// We don't care about race conditons.
			// The more, the merrier.
			random_int += 0xedf19156;

			// Classic seed, the time.
			// It ought to change, especially since this is (hopefully) nanosecond resolution time.
			auto hitime = std::chrono::high_resolution_clock::now().time_since_epoch().count();

			// Address of the thing being initialized.
			// That can mean that different seed sequences in different places in memory will be different.
			// Even for the same object, it may vary from run to run in systems with ASLR,
			// such as OS X, but on Linux it might not unless we compile with -fPIC -pic.
			auto self_data = hash(this);

			// The address of the time function.
			// It should hopefully be in  a system library that hopefully isn't always in the same place
			// (might not change until system is rebooted though)
			auto time_function_code = hash(&std::chrono::high_resolution_clock::now);

			// The address of the exit function.
			// It should hopefully be in a system library that hopefully isn't always in the same place
			// (might not change until system is rebooted though).
			// Hopefully it's in a different library from time_func.
			auto exit_function_code = hash(&_Exit);

			// The address of a local function.
			// That may be in a totally different part of memory.
			// On OS X it'll vary from run to run thanks to ASLR, on Linux it might not unless we compile with -fPIC -pic.
			// Need the cast because it's an overloaded function and we need to pick the right one.
			auto self_function_code = hash( static_cast<uint32_t (*)(uint64_t)>( &auto_seeded::shift_to_32bit_integer ) );

			// Hash our thread id.
			// It seems to vary from run to run on OS X, not so much on Linux.
			auto thread_id	= hash(std::this_thread::get_id());

			// Hash of the ID of a type.
			// May or may not vary, depending on implementation.
			#if __cpp_rtti || __GXX_RTTI
			auto type_id   = shift_to_32bit_integer(typeid(*this).hash_code());
			#else
			uint32_t type_id   = 0;
			#endif

			// Platform-specific entropy
			auto pid = shift_to_32bit_integer(RANDOM_UTILS_GETPID);
			auto cpu = shift_to_32bit_integer(RANDOM_UTILS_CPU_ENTROPY);

			return
			{
				{
					random_int, shift_to_32bit_integer(hitime), stack, heap, self_data,
					self_function_code, exit_function_code, time_function_code, thread_id, type_id, pid,
					cpu, compile_stamp
				}
			};
		}


	public:
		using SeedSequence::SeedSequence;

		using base_seed_sequence = SeedSequence;

		const base_seed_sequence& base() const
		{
			return *this;
		}

		base_seed_sequence& base()
		{
			return *this;
		}

		auto_seeded(default_seeds seeds)
			: SeedSequence(seeds.begin(), seeds.end())
		{
			// Nothing else to do
		}

		auto_seeded()
			: auto_seeded(local_entropy())
		{
			// Nothing else to do
		}
	};

	using auto_seed_128 = auto_seeded<seed_sequence_fe128>;
	using auto_seed_256 = auto_seeded<seed_sequence_fe256>;


	//////////////////////////////////////////////////////////////////////////////
	//
	// uniform_distribution
	//
	//////////////////////////////////////////////////////////////////////////////

	/*
	 * This template typedef provides either
	 *	  - uniform_int_distribution, or
	 *	  - uniform_real_distribution
	 * depending on the provided type
	 */

	template <typename Numeric>
	using UniformDistributionType = typename std::conditional
	<
		std::is_integral<Numeric>::value,
		CommonSecurity::RND::UniformIntegerDistribution<Numeric>,
		CommonSecurity::RND::UniformRealNumberDistribution<Numeric> 
	>::type;

	//////////////////////////////////////////////////////////////////////////////
	//
	// random_generator
	//
	//////////////////////////////////////////////////////////////////////////////

	/*
	 * randutils::random_generator
	 *
	 *	 An Easy-to-Use Random API
	 *
	 *	 Provides all the power of C++11's random number facility in an easy-to
	 *	 use wrapper.
	 *
	 *	 In normal use, it's accessed via one of the following type aliases, which
	 *	 also use auto_seed_256 by default
	 *
	 *		 randutils::default_rng
	 *		 randutils::mt19937_rng
	 *
	 *	 It's discussed in detail at
	 *		 http://www.pcg-random.org/posts/ease-of-use-without-loss-of-power.html
	 */

	template
	<
		typename RandomEngine = std::default_random_engine,
		typename DefaultSeedSequence = auto_seed_256
	>
	class random_generator
	{

	public:
		using engine_type		= RandomEngine;
		using default_seed_type = DefaultSeedSequence;

	private:
		engine_type _random_engine_;

		// This SFINAE(Substitution failure is not an error) evilness provides a mechanism to cast classes that aren't themselves (technically)
		// Seed Seqeuences but derive from a seed sequence to be passed to functions that require actual Seed Squences.
		// To do so, the class should provide a the type base_seed_sequence and a base() member function.

		template <typename T>
		static constexpr bool has_base_seed_sequence(typename T::base_seed_sequence*)
		{
			return true;
		}

		template <typename T>
		static constexpr bool has_base_seed_sequence(...)
		{
			return false;
		}

		template <typename SeedSequenceBased>
		static auto seed_sequence_cast
		(
			SeedSequenceBased&& seed_sequence,
			typename std::enable_if<has_base_seed_sequence<SeedSequenceBased>(0)>::type* = 0
		) -> decltype(seed_sequence.base())
		{
			return seed_sequence.base();
		}

		template <typename SeedSequence>
		static SeedSequence seed_sequence_cast
		(
			SeedSequence&& seed_sequence,
			typename std::enable_if<!has_base_seed_sequence<SeedSequence>(0)>::type* = 0
		)
		{
			return seed_sequence;
		}

	public:
		template
		<
			typename Seeding = default_seed_type,
			typename... Params
		>
		random_generator(Seeding&& seeding = default_seed_type{})
			: 
			_random_engine_
			{
				seed_sequence_cast(std::forward<Seeding>(seeding))
			}
		{
			// Nothing (else) to do
		}

		// Work around Clang DR777 bug in Clang 3.6 and earlier by adding a
		// redundant overload rather than mixing parameter packs and default
		// arguments.
		//	   https://llvm.org/bugs/show_bug.cgi?id=23029
		template
		<
			typename Seeding,
			typename... Params
		>
		random_generator(Seeding&& seeding, Params&&... params)
			: 
			_random_engine_
			{
				seed_sequence_cast(std::forward<Seeding>(seeding)),
				std::forward<Params>(params)...
			}
		{
			// Nothing (else) to do
		}

		template
		<
			typename Seeding = default_seed_type,
			typename... Params
		>
		void seed(Seeding&& seeding = default_seed_type{})
		{
			_random_engine_.seed(seed_sequence_cast(seeding));
		}

		// Work around Clang DR777 bug in Clang 3.6 and earlier by adding a
		// redundant overload rather than mixing parameter packs and default
		// arguments.
		//	   https://llvm.org/bugs/show_bug.cgi?id=23029
		template
		<
			typename Seeding,
			typename... Params
		>
		void seed(Seeding&& seeding, Params&&... params)
		{
			_random_engine_.seed(seed_sequence_cast(seeding), std::forward<Params>(params)...);
		}


		RandomEngine& engine()
		{
			return _random_engine_;
		}

		template
		<
			typename ResultType,
			template <typename> class ND_Type = std::normal_distribution,
			typename... Params
		>
		ResultType variate(Params&&... params)
		{
			ND_Type<ResultType> dist(std::forward<Params>(params)...);

			return dist(_random_engine_);
		}

		template <typename Numeric>
		Numeric uniform(Numeric lower, Numeric upper)
		{
			return variate<Numeric,UniformDistributionType>(lower, upper);
		}

		template
		<
			typename Iter,
			typename... Params
		>
		void generate(Iter first, Iter last, Params&&... params)
		{
			using result_type = typename std::remove_reference<decltype(*(first))>::type;

			UniformDistributionType<result_type> dist(std::forward<Params>(params)...);

			std::generate(first, last, [&]{ return dist(_random_engine_); });
		}

		template
		<
			typename Range,
			typename... Params
		>
		void generate(Range&& range, Params&&... params)
		{
			generate<UniformDistributionType>
			(
				std::begin(range),
				std::end(range),
				std::forward<Params>(params)...
			);
		}

		template <typename Iter>
		void shuffle(Iter first, Iter last)
		{
			CommonSecurity::ShuffleRangeData(first, last, _random_engine_);
		}

		template <typename Range>
		void shuffle(Range&& range)
		{
			shuffle(std::begin(range), std::end(range));
		}

		template <typename Iter>
		Iter choose(Iter first, Iter last)
		{
			auto dist = std::distance(first, last);
			if (dist < 2)
				return first;
			using distance_type = decltype(dist);
			distance_type choice = uniform(distance_type(0), --dist);
			std::advance(first, choice);
			return first;
		}

		template <typename Range>
		auto choose(Range&& range) -> decltype(std::begin(range))
		{
			return choose(std::begin(range), std::end(range));
		}


		template <typename Range>
		auto pick(Range&& range) -> decltype(*std::begin(range))
		{
			return *choose(std::begin(range), std::end(range));
		}

		template <typename T>
		auto pick(std::initializer_list<T> range) -> decltype(*range.begin())
		{
			return *choose(range.begin(), range.end());
		}

		template <typename Size, typename Iter>
		Iter sample(Size to_go, Iter first, Iter last)
		{
			auto total = std::distance(first, last);
			using value_type = decltype(*first);

			return std::stable_partition
			(
				first, last,
				[&](const value_type&)
				{
					--total;
					using distance_type = decltype(total);
					distance_type zero{};
					if (uniform(zero, total) < to_go)
					{
						--to_go;
						return true;
					}
					else
					{
						return false;
					}
				 }
			);
		}

		template <typename Size, typename Range>
		auto sample(Size to_go, Range&& range) -> decltype(std::begin(range))
		{
			return sample(to_go, std::begin(range), std::end(range));
		}
	};

	using default_rng = random_generator<std::default_random_engine>;
	using mt19937_rng = random_generator<std::mt19937>;

}

#undef RANDOM_UTILS_CPU_ENTROPY
#undef RANDOM_UTILS_GENERALIZED_CONSTEXPR
#undef RANDOM_UTILS_GETPID

#endif // RANDUTILS_HPP

namespace CommonSecurity
{
	//生成安全的随机数
	//Generate secure random number
	inline auto GenerateSecureRandomNumber(std::random_device& true_hardware_random_device)
	{
		//This is current timestamp
		//当前时间戳
		auto system_clock_current_timestamp = std::chrono::duration_cast<std::chrono::seconds>
		(
			std::chrono::system_clock::now().time_since_epoch()
		).count();
		
		auto high_resolution_clock_current_timestamp = std::chrono::duration_cast<std::chrono::microseconds>
		(
			std::chrono::high_resolution_clock::now().time_since_epoch()
		).count();


		/*return static_cast<std::uint64_t>(true_hardware_random_device())
			^ static_cast<std::uint64_t>(system_clock_current_timestamp)
			^ static_cast<std::uint64_t>(high_resolution_clock_current_timestamp);*/

		/*return static_cast<std::uint32_t>(true_hardware_random_device())
			^ static_cast<std::uint32_t>(system_clock_current_timestamp)
			^ static_cast<std::uint32_t>(high_resolution_clock_current_timestamp >> 32)
			^ static_cast<std::uint32_t>(high_resolution_clock_current_timestamp)
			^ static_cast<std::uint32_t>(system_clock_current_timestamp >> 32);*/

		return static_cast<std::uint64_t>(true_hardware_random_device())
			^ static_cast<std::uint64_t>(system_clock_current_timestamp)
			^ static_cast<std::uint64_t>(high_resolution_clock_current_timestamp >> 32)
			^ static_cast<std::uint64_t>(high_resolution_clock_current_timestamp)
			^ static_cast<std::uint64_t>(system_clock_current_timestamp >> 32);
	}

	//生成安全的随机数种子
	//Generate secure random number seeds
	template<typename RandomNumberSeedType> requires std::integral<RandomNumberSeedType>
	inline RandomNumberSeedType GenerateSecureRandomNumberSeed(std::random_device& true_hardware_random_device)
	{
		/*
			RandomNumberSeedType random_number_value = CURRENT_SYSTEM_BITS == 64
			? static_cast<RandomNumberSeedType>( GenerateSecureRandomNumber(true_hardware_random_device) ) ^ static_cast<RandomNumberSeedType>( GenerateSecureRandomNumber(true_hardware_random_device) >> 32)
			: static_cast<RandomNumberSeedType>( GenerateSecureRandomNumber(true_hardware_random_device) );
		*/
		
		RandomNumberSeedType random_number_value = static_cast<RandomNumberSeedType>( GenerateSecureRandomNumber(true_hardware_random_device) );

		return random_number_value;
	}

	//生成安全的随机数种子序列
	//Generate a secure sequence of random number seeds
	template<typename RandomNumberSeedType> requires std::integral<RandomNumberSeedType>
	inline std::vector<RandomNumberSeedType> GenerateSecureRandomNumberSeedSequence(std::size_t size)
	{
		using namespace CommonSecurity::SecureRandomUtils;
		using seed_sequence_fe_type = seed_sequence_fe<64, RandomNumberSeedType>;
		using auto_seed_type = auto_seeded<seed_sequence_fe_type>;
		
		if(size == 0)
			size = 1;

		std::vector<RandomNumberSeedType> random_number_seed_sequence(size, 0);

		auto_seed_type seeder;
		seeder.generate(random_number_seed_sequence.begin(), random_number_seed_sequence.end());

		return random_number_seed_sequence;
	}

	template<std::integral DataType>
	struct UniformRandomBitGenerator
	{
	public:
		using result_type = DataType;

		static constexpr DataType max() { return std::numeric_limits<DataType>::max(); }
		static constexpr DataType min() { return std::numeric_limits<DataType>::min(); }
	};

	namespace RNG_SimpleImplementation
	{
		class ExampleGenerator : UniformRandomBitGenerator<int>
		{

		private:

			using result_type =  UniformRandomBitGenerator<int>::result_type;

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
				_SEED_NUMBER_ = GenerateSecureRandomNumberSeed<unsigned int>(random_device_object);
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
				_SEED_NUMBER_ = GenerateSecureRandomNumberSeed<int>(random_device_object);
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
				is_use_busy.wait(true, std::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order_seq_cst);

				std::uint32_t seed_number = device();

				this->seed( seed_number );

				is_use_busy.store(false, std::memory_order_relaxed);

				is_use_busy.notify_all();
			}

			void seed( int seed_number )
			{
				is_use_busy.wait(true, std::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order_seq_cst);

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

				is_use_busy.store(false, std::memory_order_relaxed);

				is_use_busy.notify_all();
			}

			int operator()()
			{
				is_use_busy.wait(true, std::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order_seq_cst);

				std::int32_t result_number = 0;
				this->compute_number(unsafe_random_state, result_number);

				is_use_busy.store(false, std::memory_order_relaxed);

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
				is_use_busy.wait(true, std::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order_seq_cst);

				auto random_state_data = this->_initial_state_(state_argument, this->unsafe_random_state);

				is_use_busy.store(false, std::memory_order_relaxed);

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
				is_use_busy.wait(true, std::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order_seq_cst);

				bool is_done = this->_update_state_(state_argument, default_random_state_data);

				is_use_busy.store(false, std::memory_order_relaxed);

				is_use_busy.notify_all();

				if(is_done)
					return this->unsafe_random_state;
				else
					return std::nullopt;
			}

			void change_state(RandomStateData& initialized_random_state_data)
			{
				is_use_busy.wait(true, std::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order_seq_cst);

				unsafe_random_state = initialized_random_state_data;

				is_use_busy.store(false, std::memory_order_relaxed);

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

			int easy_compute_number( std::random_device& random_device_object )
			{
				is_use_busy.wait(true, std::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order_seq_cst);

				auto seed_number = GenerateSecureRandomNumberSeed<unsigned int>(random_device_object);

				auto result_random_number = this->easy_compute_number( seed_number );

				is_use_busy.store(false, std::memory_order_relaxed);

				is_use_busy.notify_all();

				return result_random_number;
			}

			int easy_compute_number( unsigned int& seed_number )
			{
				is_use_busy.wait(true, std::memory_order_seq_cst);

				is_use_busy.store(true, std::memory_order_seq_cst);

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

				is_use_busy.store(false, std::memory_order_relaxed);

				is_use_busy.notify_all();

				return result_random_number;
			}

			GNU_C_LibraryGenerator(unsigned int type_number)
				:
				unsafe_random_state(static_cast<RandomMathPolynomialType>(type_number))
			{
				if(type_number < static_cast<unsigned int>(RandomMathPolynomialType::TYPE_0) || type_number > static_cast<unsigned int>(RandomMathPolynomialType::TYPE_4))
					my_cpp2020_assert(false,"Select the non-existent enumeration to represent the binary polynomial", std::source_location::current());
			}

			~GNU_C_LibraryGenerator() = default;

		};
	}

	/*
		Reference source code:
		
		Rudimentary C++20 xoshiro256** uniform random bit generator implementation:
		https://github.com/Reputeless/Xoshiro-cpp/
		
		A C++ implementation of SplitMix:
		https://gist.github.com/imneme/6179748664e88ef3c34860f44309fc71
		
		https://gist.github.com/wreien/442e6f89f125f9b4a9919299a7536fd5 (Removed public share)
	*/
	namespace RNG_Xorshiro
	{
		/*
			golden ratio is 0x9e3779b97f4a7c13 with 64 bit number
		*/

		// An implementation of xorshiro (https://vigna.di.unimi.it/xorshift/)
		// wrapped to fit the C++11 RandomNumberGenerator requirements.
		// This allows us to use it with all the other facilities in <random>.
		//
		// Credits go to David Blackman and Sebastiano Vigna.
		//
		// TODO: make generic? (parameterise scrambler/width/hyperparameters/etc.)
		// Not as easy to do nicely as it might sound,
		// and this as it is is good enough for my purposes.

		struct xorshiro128 : UniformRandomBitGenerator<std::uint64_t>
		{
			static constexpr std::uint32_t num_state_words = 2;
			using state_type = std::array<std::uint64_t, num_state_words>;

			using result_type =  UniformRandomBitGenerator<std::uint64_t>::result_type;

			// cannot initialize with an all-zero state
			constexpr xorshiro128() noexcept
				: state { 12, 34 }
			{
			}

			// using SplitMix64 generator to initialize the state;
			// using a different generator helps prevent seed correlation
			explicit constexpr xorshiro128( result_type seed ) noexcept
			{
				auto splitmix64 = [ seed_value = seed ]() mutable {
					auto z = ( seed_value += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;
					return z ^ ( z >> 31 );
				};
				std::ranges::generate( state, splitmix64 );
			}

			explicit xorshiro128( std::initializer_list<result_type> initializer_list_args )
			{
				*this = xorshiro128(initializer_list_args.begin(), initializer_list_args.end());
			}

			template <std::input_or_output_iterator SeedDataIteratorType>
			requires
			( 
				not std::convertible_to<SeedDataIteratorType, result_type>
			)
			explicit xorshiro128( SeedDataIteratorType&& begin, SeedDataIteratorType&& end )
			{
				std::vector<result_type> seed_vector { begin, end };
				this->generate_number_state_seeds( seed_vector );
				seed_vector.clear();
				seed_vector.shrink_to_fit();
			}

			explicit xorshiro128( std::span<const result_type> seed_span )
			{
				this->generate_number_state_seeds( seed_span );
			}

			explicit xorshiro128( std::seed_seq& s_q )
			{
				this->generate_number_state_seeds(s_q);
			}

			constexpr void seed() noexcept
			{
				*this = xorshiro128();
			}
			constexpr void seed( result_type s ) noexcept
			{
				*this = xorshiro128( s );
			}
			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			constexpr void seed( SeedSeq& q )
			{
				*this = xorshiro128( q );
			}

			constexpr result_type operator()() noexcept
			{
				// xorshiro128+:
				/*
					const auto a = state[0];
					auto b = state[1];
					const auto result = a + b;

					b ^= a;
					state[0] = rotl(a, 24) ^ b ^ (b << 16); // a, b
					state[1] = rotl(b, 37); // c
				*/
			
				// xorshiro128++:
				/*
					const auto a = state[0];
					auto b = state[1];
					const auto result = std::rotl(a + b, 17) + a;

					b ^= a;
					state[0] = std::rotl(a, 49) ^ b ^ (b << 21); // a, b
					state[1] = std::rotl(b, 28); // c
				*/

				// xorshiro128**:
				const auto a = state[0];
				auto b = state[1];
				const auto result = std::rotl(a * 5, 7) * 9;

				b ^= a;
				state[0] = std::rotl(a, 24) ^ b ^ (b << 16); // a, b
				state[1] = std::rotl(b, 37); // c

				return result;
			}

			constexpr void discard( std::uint64_t round ) noexcept
			{
				if(round == 0)
					return;

				while ( round-- )
					operator()();
			}

			/*
				This is the jump function for the generator. 
				It is equivalent to 2^64 calls to operator()();
				It can be used to generate 2^64 non-overlapping subsequences for parallel computations.
			*/
			constexpr void jump() noexcept
			{
				constexpr std::uint64_t jump_table[] = {
					0xdf900294d8f554a5, 0x170865df4b3201fc
				};

				state_type temporary_state {};
				for ( std::uint32_t jump_table_index = 0; jump_table_index < std::ssize( jump_table ); jump_table_index++ )
				{
					for ( std::uint32_t b = 0; b < 64; b++ )
					{
						if ( jump_table[ jump_table_index ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							temporary_state[ 0 ] ^= state[ 0 ];
							temporary_state[ 1 ] ^= state[ 1 ];
						}
						operator()();
					}
				}

				temporary_state[ 0 ] = state[ 0 ];
				temporary_state[ 1 ] = state[ 1 ];
			}

			/*
				This is the long-jump function for the generator.
				It is equivalent to 2^96 calls to operator()();
				It can be used to generate 2^32 starting points,
				From each of which jump() will generate 2^32 non-overlapping subsequences for parallel distributed computations. 
			*/
			constexpr void long_jump() noexcept
			{
				constexpr std::uint64_t long_jump_table[] = {
					0xd2a98b26625eee7b, 0xdddf9b1090aa7ac1
				};

				state_type temporary_state {};
				for ( std::uint32_t long_jump_table_index = 0; long_jump_table_index < std::ssize( long_jump_table ); long_jump_table_index++ )
				{
					for ( std::uint32_t b = 0; b < 64; b++ )
					{
						if ( long_jump_table[ long_jump_table_index ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							temporary_state[ 0 ] ^= state[ 0 ];
							temporary_state[ 1 ] ^= state[ 1 ];

						}
						operator()();
					}
				}

				temporary_state[ 0 ] = state[ 0 ];
				temporary_state[ 1 ] = state[ 1 ];

			}

			constexpr bool operator==( const xorshiro128& ) const noexcept = default;

			template <typename CharT, typename Traits>
			friend std::basic_ostream<CharT, Traits>& operator<<( std::basic_ostream<CharT, Traits>& os, const xorshiro128& e )
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
			friend std::basic_istream<CharT, Traits&> operator>>( std::basic_istream<CharT, Traits>& is, xorshiro128& e )
			{
				xorshiro128 r;
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

			void generate_number_state_seeds(std::seed_seq& s_q)
			{
				std::uint32_t this_temparory_state[ num_state_words * 2 ];
				s_q.generate( std::begin( this_temparory_state ), std::end( this_temparory_state ) );
				for ( std::uint32_t index = 0; index < num_state_words; ++index )
				{
					state[ index ] = this_temparory_state[ index * 2 ];
					state[ index ] <<= 32;
					state[ index ] |= this_temparory_state[ index * 2 + 1 ];
				}
			}

			void generate_number_state_seeds(std::span<const result_type> seed_span)
			{
				std::uint32_t this_temparory_state[ num_state_words * 2 ];

				auto seed_span_begin = seed_span.begin();
				auto seed_span_end = seed_span.end();
				result_type seed = 0;
				auto splitmix64 = [&seed_span_begin, &seed_span_end, &seed]() mutable {
					
					auto z = (seed += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;

					if(seed_span_begin != seed_span_end)
					{
						++seed_span_begin;
					}

					return z ^ ( z >> 31 );
				};
				std::ranges::generate( this_temparory_state, splitmix64 );
				seed = 0;

				for ( std::uint32_t index = 0; index < num_state_words; ++index )
				{
					state[ index ] = this_temparory_state[ index * 2 ];
					state[ index ] <<= 32;
					state[ index ] |= this_temparory_state[ index * 2 + 1 ];
				}
			}
		};

		struct xorshiro256 : UniformRandomBitGenerator<std::uint64_t>
		{
			static constexpr std::uint32_t num_state_words = 4;
			using state_type = std::array<std::uint64_t, num_state_words>;

			using result_type =  UniformRandomBitGenerator<std::uint64_t>::result_type;

			// cannot initialize with an all-zero state
			constexpr xorshiro256() noexcept
				: state { 12, 34 }
			{
			}

			// using SplitMix64 generator to initialize the state;
			// using a different generator helps prevent seed correlation
			explicit constexpr xorshiro256( result_type seed ) noexcept
			{
				auto splitmix64 = [ seed_value = seed ]() mutable {
					auto z = ( seed_value += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;
					return z ^ ( z >> 31 );
				};
				std::ranges::generate( state, splitmix64 );
			}

			explicit xorshiro256( std::initializer_list<result_type> initializer_list_args )
			{
				*this = xorshiro256(initializer_list_args.begin(), initializer_list_args.end());
			}

			template <std::input_or_output_iterator SeedDataIteratorType>
			requires
			( 
				not std::convertible_to<SeedDataIteratorType, result_type>
			)
			explicit xorshiro256( SeedDataIteratorType&& begin, SeedDataIteratorType&& end )
			{
				std::vector<result_type> seed_vector { begin, end };
				this->generate_number_state_seeds( seed_vector );
				seed_vector.clear();
				seed_vector.shrink_to_fit();
			}

			explicit xorshiro256( std::span<const result_type> seed_span )
			{
				this->generate_number_state_seeds( seed_span );
			}

			explicit xorshiro256( std::seed_seq& s_q )
			{
				this->generate_number_state_seeds(s_q);
			}

			constexpr void seed() noexcept
			{
				*this = xorshiro256();
			}
			constexpr void seed( result_type s ) noexcept
			{
				*this = xorshiro256( s );
			}
			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			constexpr void seed( SeedSeq& q )
			{
				*this = xorshiro256( q );
			}

			constexpr result_type operator()() noexcept
			{
				// xorshiro256+:
				// const auto result = state[0] + state[3];
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

			constexpr void discard( std::uint64_t round ) noexcept
			{
				if(round == 0)
					return;

				while ( round-- )
					operator()();
			}

			/*
				This is the jump function for the generator.
				It is equivalent to 2^128 calls to operator()();
				It can be used to generate 2^128 non-overlapping subsequences for parallel computations.
			*/
			constexpr void jump() noexcept
			{
				constexpr std::uint64_t jump_table[] = {
					0x180ec6d33cfd0aba,
					0xd5a61266f0c9392c,
					0xa9582618e03fc9aa,
					0x39abdc4529b1661c,
				};

				state_type temporary_state {};
				for ( std::uint32_t jump_table_index = 0; jump_table_index < std::ssize( jump_table ); jump_table_index++ )
				{
					for ( std::uint32_t b = 0; b < 64; b++ )
					{
						if ( jump_table[ jump_table_index ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							temporary_state[ 0 ] ^= state[ 0 ];
							temporary_state[ 1 ] ^= state[ 1 ];
							temporary_state[ 2 ] ^= state[ 2 ];
							temporary_state[ 3 ] ^= state[ 3 ];
						}
						operator()();
					}
				}

				state[ 0 ] = temporary_state[ 0 ];
				state[ 1 ] = temporary_state[ 1 ];
				state[ 2 ] = temporary_state[ 2 ];
				state[ 3 ] = temporary_state[ 3 ];
			}

			/*
				This is the jump function for the generator.
				It is equivalent to 2^192 calls to operator()();
				It can be used to generate 2^64 starting points,
				From each of which jump() will generate 2^64 non-overlapping subsequences for parallel distributed computations.
			*/
			constexpr void long_jump() noexcept
			{
				constexpr std::uint64_t long_jump_table[] = {
					0x76e15d3efefdcbbf,
					0xc5004e441c522fb3,
					0x77710069854ee241,
					0x39109bb02acbe635,
				};

				state_type temporary_state {};
				for ( std::uint32_t long_jump_table_index = 0; long_jump_table_index < std::ssize( long_jump_table ); long_jump_table_index++ )
				{
					for ( std::uint32_t b = 0; b < 64; b++ )
					{
						if ( long_jump_table[ long_jump_table_index ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							temporary_state[ 0 ] ^= state[ 0 ];
							temporary_state[ 1 ] ^= state[ 1 ];
							temporary_state[ 2 ] ^= state[ 2 ];
							temporary_state[ 3 ] ^= state[ 3 ];
						}
						operator()();
					}
				}

				state[ 0 ] = temporary_state[ 0 ];
				state[ 1 ] = temporary_state[ 1 ];
				state[ 2 ] = temporary_state[ 2 ];
				state[ 3 ] = temporary_state[ 3 ];
			}

			constexpr bool operator==( const xorshiro256& ) const noexcept = default;

			template <typename CharT, typename Traits>
			friend std::basic_ostream<CharT, Traits>& operator<<( std::basic_ostream<CharT, Traits>& os, const xorshiro256& e )
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
			friend std::basic_istream<CharT, Traits&> operator>>( std::basic_istream<CharT, Traits>& is, xorshiro256& e )
			{
				xorshiro256 r;
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

			void generate_number_state_seeds(std::seed_seq& s_q)
			{
				std::uint32_t this_temparory_state[ num_state_words * 2 ];
				s_q.generate( std::begin( this_temparory_state ), std::end( this_temparory_state ) );
				for ( std::uint32_t index = 0; index < num_state_words; ++index )
				{
					state[ index ] = this_temparory_state[ index * 2 ];
					state[ index ] <<= 32;
					state[ index ] |= this_temparory_state[ index * 2 + 1 ];
				}
			}

			void generate_number_state_seeds(std::span<const result_type> seed_span)
			{
				std::uint32_t this_temparory_state[ num_state_words * 2 ];

				auto seed_span_begin = seed_span.begin();
				auto seed_span_end = seed_span.end();
				result_type seed = 0;
				auto splitmix64 = [&seed_span_begin, &seed_span_end, &seed]() mutable {
					
					auto z = (seed += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;

					if(seed_span_begin != seed_span_end)
					{
						++seed_span_begin;
					}

					return z ^ ( z >> 31 );
				};
				std::ranges::generate( this_temparory_state, splitmix64 );
				seed = 0;

				for ( std::uint32_t index = 0; index < num_state_words; ++index )
				{
					state[ index ] = this_temparory_state[ index * 2 ];
					state[ index ] <<= 32;
					state[ index ] |= this_temparory_state[ index * 2 + 1 ];
				}
			}
		};

		struct xorshiro512 : UniformRandomBitGenerator<std::uint64_t>
		{
			static constexpr std::uint32_t num_state_words = 8;
			using state_type = std::array<std::uint64_t, num_state_words>;

			using result_type =  UniformRandomBitGenerator<std::uint64_t>::result_type;

			std::size_t state_position = 0;

			// cannot initialize with an all-zero state
			constexpr xorshiro512() noexcept
				: state { 12, 34 }
			{
			}

			// using SplitMix64 generator to initialize the state;
			// using a different generator helps prevent seed correlation
			explicit constexpr xorshiro512( result_type seed ) noexcept
			{
				auto splitmix64 = [ seed_value = seed ]() mutable {
					auto z = ( seed_value += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;
					return z ^ ( z >> 31 );
				};
				std::ranges::generate( state, splitmix64 );
			}

			explicit xorshiro512( std::initializer_list<result_type> initializer_list_args )
			{
				*this = xorshiro512(initializer_list_args.begin(), initializer_list_args.end());
			}

			template <std::input_or_output_iterator SeedDataIteratorType>
			requires
			( 
				not std::convertible_to<SeedDataIteratorType, result_type>
			)
			explicit xorshiro512( SeedDataIteratorType&& begin, SeedDataIteratorType&& end )
			{
				std::vector<result_type> seed_vector { begin, end };
				this->generate_number_state_seeds( seed_vector );
				seed_vector.clear();
				seed_vector.shrink_to_fit();
			}

			explicit xorshiro512( std::span<const result_type> seed_span )
			{
				this->generate_number_state_seeds( seed_span );
			}

			explicit xorshiro512( std::seed_seq& s_q )
			{
				this->generate_number_state_seeds(s_q);
			}

			constexpr void seed() noexcept
			{
				*this = xorshiro512();
			}
			constexpr void seed( result_type s ) noexcept
			{
				*this = xorshiro512( s );
			}
			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			constexpr void seed( SeedSeq& q )
			{
				*this = xorshiro512( q );
			}

			constexpr result_type operator()() noexcept
			{
				const std::size_t this_state_position = this->state_position;
				this->state_position = (this->state_position + 1) & 15;
				
				// xorshiro512+:
				// const auto result = s[0] + s[2];
				// xorshiro512++:
				// const auto result = std::rotl(s[0] + s[2], 17) + s[2];

				// xorshiro512**:
				const auto result = std::rotl(state[1] * 5, 7) * 9;

				const auto t = state[1] << 11;

				state[2] ^= state[0];
				state[5] ^= state[1];
				state[1] ^= state[2];
				state[7] ^= state[3];
				state[3] ^= state[4];
				state[4] ^= state[5];
				state[0] ^= state[6];
				state[6] ^= state[7];

				state[6] ^= t;

				state[7] = std::rotl(state[7], 21);

				return result;
			}

			constexpr void discard( std::uint64_t round ) noexcept
			{
				if(round == 0)
					return;

				while ( round-- )
					operator()();
			}

			/*
				This is the jump function for the generator.
				It is equivalent to 2^256 calls to operator()();
				It can be used to generate 2^256 non-overlapping subsequences for parallel computations.
			*/
			constexpr void jump() noexcept
			{
				constexpr std::uint64_t jump_table[] = {
					0x33ed89b6e7a353f9, 0x760083d7955323be,
					0x2837f2fbb5f22fae, 0x4b8c5674d309511c,
					0xb11ac47a7ba28c25, 0xf1be7667092bcc1c,
					0x53851efdb6df0aaf, 0x1ebbc8b23eaf25db
				};

				state_type temporary_state {};
				for ( std::uint32_t jump_table_index = 0; jump_table_index < std::ssize( jump_table ); jump_table_index++ )
				{
					for ( std::uint32_t b = 0; b < 64; b++ )
					{
						if ( jump_table[ jump_table_index ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							temporary_state[ 0 ] ^= state[ 0 ];
							temporary_state[ 1 ] ^= state[ 1 ];
							temporary_state[ 2 ] ^= state[ 2 ];
							temporary_state[ 3 ] ^= state[ 3 ];
							temporary_state[ 4 ] ^= state[ 4 ];
							temporary_state[ 5 ] ^= state[ 5 ];
							temporary_state[ 6 ] ^= state[ 6 ];
							temporary_state[ 7 ] ^= state[ 7 ];
						}
						operator()();
					}
				}

				temporary_state[ 0 ] = state[ 0 ];
				temporary_state[ 1 ] = state[ 1 ];
				temporary_state[ 2 ] = state[ 2 ];
				temporary_state[ 3 ] = state[ 3 ];
				temporary_state[ 4 ] = state[ 4 ];
				temporary_state[ 5 ] = state[ 5 ];
				temporary_state[ 6 ] = state[ 6 ];
				temporary_state[ 7 ] = state[ 7 ];
			}

			/*
				This is the long-jump function for the generator.
				It is equivalent to 2^384 calls to operator()();
				It can be used to generate 2^128 starting points,
				from each of which jump() will generate 2^128 non-overlapping subsequences for parallel distributed computations.
			*/
			constexpr void long_jump() noexcept
			{
				constexpr std::uint64_t long_jump_table[] = {
					0x11467fef8f921d28, 0xa2a819f2e79c8ea8,
					0xa8299fc284b3959a, 0xb4d347340ca63ee1,
					0x1cb0940bedbff6ce, 0xd956c5c4fa1f8e17,
					0x915e38fd4eda93bc, 0x5b3ccdfa5d7daca5
				};

				state_type temporary_state {};
				for ( std::uint32_t long_jump_table_index = 0; long_jump_table_index < std::ssize( long_jump_table ); long_jump_table_index++ )
				{
					for ( std::uint32_t b = 0; b < 64; b++ )
					{
						if ( long_jump_table[ long_jump_table_index ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							temporary_state[ 0 ] ^= state[ 0 ];
							temporary_state[ 1 ] ^= state[ 1 ];
							temporary_state[ 2 ] ^= state[ 2 ];
							temporary_state[ 3 ] ^= state[ 3 ];
							temporary_state[ 4 ] ^= state[ 4 ];
							temporary_state[ 5 ] ^= state[ 5 ];
							temporary_state[ 6 ] ^= state[ 6 ];
							temporary_state[ 7 ] ^= state[ 7 ];

						}
						operator()();
					}
				}

				temporary_state[ 0 ] = state[ 0 ];
				temporary_state[ 1 ] = state[ 1 ];
				temporary_state[ 2 ] = state[ 2 ];
				temporary_state[ 3 ] = state[ 3 ];
				temporary_state[ 4 ] = state[ 4 ];
				temporary_state[ 5 ] = state[ 5 ];
				temporary_state[ 6 ] = state[ 6 ];
				temporary_state[ 7 ] = state[ 7 ];
			}

		private:
			state_type state;

			void generate_number_state_seeds(std::seed_seq& s_q)
			{
				std::uint32_t this_temparory_state[ num_state_words * 2 ];
				s_q.generate( std::begin( this_temparory_state ), std::end( this_temparory_state ) );
				for ( std::uint32_t index = 0; index < num_state_words; ++index )
				{
					state[ index ] = this_temparory_state[ index * 2 ];
					state[ index ] <<= 32;
					state[ index ] |= this_temparory_state[ index * 2 + 1 ];
				}
			}

			void generate_number_state_seeds(std::span<const result_type> seed_span)
			{
				std::uint32_t this_temparory_state[ num_state_words * 2 ];

				auto seed_span_begin = seed_span.begin();
				auto seed_span_end = seed_span.end();
				result_type seed = 0;
				auto splitmix64 = [&seed_span_begin, &seed_span_end, &seed]() mutable {
					
					auto z = (seed += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;

					if(seed_span_begin != seed_span_end)
					{
						++seed_span_begin;
					}

					return z ^ ( z >> 31 );
				};
				std::ranges::generate( this_temparory_state, splitmix64 );
				seed = 0;

				for ( std::uint32_t index = 0; index < num_state_words; ++index )
				{
					state[ index ] = this_temparory_state[ index * 2 ];
					state[ index ] <<= 32;
					state[ index ] |= this_temparory_state[ index * 2 + 1 ];
				}
			}
		};

		struct xorshiro1024 : UniformRandomBitGenerator<std::uint64_t>
		{
			static constexpr std::uint32_t num_state_words = 16;
			using state_type = std::array<std::uint64_t, num_state_words>;

			using result_type =  UniformRandomBitGenerator<std::uint64_t>::result_type;

			std::size_t state_position = 0;

			// cannot initialize with an all-zero state
			constexpr xorshiro1024() noexcept
				: state { 12, 34 }
			{
			}

			// using SplitMix64 generator to initialize the state;
			// using a different generator helps prevent seed correlation
			explicit constexpr xorshiro1024( result_type seed ) noexcept
			{
				auto splitmix64 = [ seed_value = seed ]() mutable {
					auto z = ( seed_value += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;
					return z ^ ( z >> 31 );
				};
				std::ranges::generate( state, splitmix64 );
			}

			explicit xorshiro1024( std::initializer_list<result_type> initializer_list_args )
			{
				*this = xorshiro1024(initializer_list_args.begin(), initializer_list_args.end());
			}

			template <std::input_or_output_iterator SeedDataIteratorType>
			requires
			( 
				not std::convertible_to<SeedDataIteratorType, result_type>
			)
			explicit xorshiro1024( SeedDataIteratorType&& begin, SeedDataIteratorType&& end )
			{
				std::vector<result_type> seed_vector { begin, end };
				this->generate_number_state_seeds( seed_vector );
				seed_vector.clear();
				seed_vector.shrink_to_fit();
			}

			explicit xorshiro1024( std::span<const result_type> seed_span )
			{
				this->generate_number_state_seeds( seed_span );
			}

			explicit xorshiro1024( std::seed_seq& s_q )
			{
				this->generate_number_state_seeds(s_q);
			}

			constexpr void seed() noexcept
			{
				*this = xorshiro1024();
			}
			constexpr void seed( result_type s ) noexcept
			{
				*this = xorshiro1024( s );
			}
			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			constexpr void seed( SeedSeq& q )
			{
				*this = xorshiro1024( q );
			}

			constexpr result_type operator()() noexcept
			{
				const std::size_t this_state_position = this->state_position;
				this->state_position = (this->state_position + 1) & 15;
				
				// xorshiro1024++:
				// const auto result = std::rotl(a + b, 23) + a;
				// xorshiro1024*:
				// const auto result = a * 0x9e3779b97f4a7c13;

				// xorshiro1024**:
				const auto a = state[ this->state_position ];
				const auto result = std::rotl( a * 5, 7 ) * 9;
				auto b = state[ this_state_position ];

				b ^= a;
				state[this_state_position] = std::rotl( a, 25 ) ^ b ^ (b << 27);
				state[this->state_position] = std::rotl( b, 36 );

				return result;
			}

			constexpr void discard( std::uint64_t round ) noexcept
			{
				if(round == 0)
					return;

				while ( round-- )
					operator()();
			}

			/*
				This is the jump function for the generator.
				It is equivalent to 2^512 calls to operator()();
				It can be used to generate 2^512 non-overlapping subsequences for parallel computations.
			*/
			constexpr void jump() noexcept
			{
				constexpr std::uint64_t jump_table[] = {
					0x931197d8e3177f17, 0xb59422e0b9138c5f,
					0xf06a6afb49d668bb, 0xacb8a6412c8a1401,
					0x12304ec85f0b3468, 0xb7dfe7079209891e,
					0x405b7eec77d9eb14, 0x34ead68280c44e4a,
					0xe0e4ba3e0ac9e366, 0x8f46eda8348905b7,
					0x328bf4dbad90d6ff, 0xc8fd6fb31c9effc3,
					0xe899d452d4b67652, 0x45f387286ade3205,
					0x03864f454a8920bd, 0xa68fa28725b1b384
				};

				state_type temporary_state {};
				for ( std::uint32_t jump_table_index = 0; jump_table_index < std::ssize( jump_table ); jump_table_index++ )
				{
					for ( std::uint32_t b = 0; b < 64; b++ )
					{
						if ( jump_table[ jump_table_index ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							temporary_state[ 0 ] ^= state[ 0 ];
							temporary_state[ 1 ] ^= state[ 1 ];
							temporary_state[ 2 ] ^= state[ 2 ];
							temporary_state[ 3 ] ^= state[ 3 ];
							temporary_state[ 4 ] ^= state[ 4 ];
							temporary_state[ 5 ] ^= state[ 5 ];
							temporary_state[ 6 ] ^= state[ 6 ];
							temporary_state[ 7 ] ^= state[ 7 ];
							temporary_state[ 8 ] ^= state[ 8 ];
							temporary_state[ 9 ] ^= state[ 9 ];
							temporary_state[ 10 ] ^= state[ 10 ];
							temporary_state[ 11 ] ^= state[ 11 ];
							temporary_state[ 12 ] ^= state[ 12 ];
							temporary_state[ 13 ] ^= state[ 13 ];
							temporary_state[ 14 ] ^= state[ 14 ];
							temporary_state[ 15 ] ^= state[ 15 ];
						}
						operator()();
					}
				}

				temporary_state[ 0 ] = state[ 0 ];
				temporary_state[ 1 ] = state[ 1 ];
				temporary_state[ 2 ] = state[ 2 ];
				temporary_state[ 3 ] = state[ 3 ];
				temporary_state[ 4 ] = state[ 4 ];
				temporary_state[ 5 ] = state[ 5 ];
				temporary_state[ 6 ] = state[ 6 ];
				temporary_state[ 7 ] = state[ 7 ];
				temporary_state[ 8 ] = state[ 8 ];
				temporary_state[ 9 ] = state[ 9 ];
				temporary_state[ 10 ] = state[ 10 ];
				temporary_state[ 11 ] = state[ 11 ];
				temporary_state[ 12 ] = state[ 12 ];
				temporary_state[ 13 ] = state[ 13 ];
				temporary_state[ 14 ] = state[ 14 ];
				temporary_state[ 15 ] = state[ 15 ];
			}

			/*
				This is the long-jump function for the generator.
				It is equivalent to 2^768 calls to operator()();
				It can be used to generate 2^256 starting points,
				from each of which jump() will generate 2^256 non-overlapping subsequences for parallel distributed computations.
			*/
			constexpr void long_jump() noexcept
			{
				constexpr std::uint64_t long_jump_table[] = {
					0x7374156360bbf00f, 0x4630c2efa3b3c1f6,
					0x6654183a892786b1, 0x94f7bfcbfb0f1661,
					0x27d8243d3d13eb2d, 0x9701730f3dfb300f,
					0x2f293baae6f604ad, 0xa661831cb60cd8b6,
					0x68280c77d9fe008c, 0x50554160f5ba9459,
					0x2fc20b17ec7b2a9a, 0x49189bbdc8ec9f8f,
					0x92a65bca41852cc1, 0xf46820dd0509c12a,
					0x52b00c35fbf92185, 0x1e5b3b7f589e03c1
				};

				state_type temporary_state {};
				for ( std::uint32_t long_jump_table_index = 0; long_jump_table_index < std::ssize( long_jump_table ); long_jump_table_index++ )
				{
					for ( std::uint32_t b = 0; b < 64; b++ )
					{
						if ( long_jump_table[ long_jump_table_index ] & ( static_cast<std::uint64_t>( 1 ) << b ) )
						{
							temporary_state[ 0 ] ^= state[ 0 ];
							temporary_state[ 1 ] ^= state[ 1 ];
							temporary_state[ 2 ] ^= state[ 2 ];
							temporary_state[ 3 ] ^= state[ 3 ];
							temporary_state[ 4 ] ^= state[ 4 ];
							temporary_state[ 5 ] ^= state[ 5 ];
							temporary_state[ 6 ] ^= state[ 6 ];
							temporary_state[ 7 ] ^= state[ 7 ];
							temporary_state[ 8 ] ^= state[ 8 ];
							temporary_state[ 9 ] ^= state[ 9 ];
							temporary_state[ 10 ] ^= state[ 10 ];
							temporary_state[ 11 ] ^= state[ 11 ];
							temporary_state[ 12 ] ^= state[ 12 ];
							temporary_state[ 13 ] ^= state[ 13 ];
							temporary_state[ 14 ] ^= state[ 14 ];
							temporary_state[ 15 ] ^= state[ 15 ];

						}
						operator()();
					}
				}

				temporary_state[ 0 ] = state[ 0 ];
				temporary_state[ 1 ] = state[ 1 ];
				temporary_state[ 2 ] = state[ 2 ];
				temporary_state[ 3 ] = state[ 3 ];
				temporary_state[ 4 ] = state[ 4 ];
				temporary_state[ 5 ] = state[ 5 ];
				temporary_state[ 6 ] = state[ 6 ];
				temporary_state[ 7 ] = state[ 7 ];
				temporary_state[ 8 ] = state[ 8 ];
				temporary_state[ 9 ] = state[ 9 ];
				temporary_state[ 10 ] = state[ 10 ];
				temporary_state[ 11 ] = state[ 11 ];
				temporary_state[ 12 ] = state[ 12 ];
				temporary_state[ 13 ] = state[ 13 ];
				temporary_state[ 14 ] = state[ 14 ];
				temporary_state[ 15 ] = state[ 15 ];
			}

		private:
			state_type state;

			void generate_number_state_seeds(std::seed_seq& s_q)
			{
				std::uint32_t this_temparory_state[ num_state_words * 2 ];
				s_q.generate( std::begin( this_temparory_state ), std::end( this_temparory_state ) );
				for ( std::uint32_t index = 0; index < num_state_words; ++index )
				{
					state[ index ] = this_temparory_state[ index * 2 ];
					state[ index ] <<= 32;
					state[ index ] |= this_temparory_state[ index * 2 + 1 ];
				}
			}

			void generate_number_state_seeds(std::span<const result_type> seed_span)
			{
				std::uint32_t this_temparory_state[ num_state_words * 2 ];

				auto seed_span_begin = seed_span.begin();
				auto seed_span_end = seed_span.end();
				result_type seed = 0;
				auto splitmix64 = [&seed_span_begin, &seed_span_end, &seed]() mutable {
					
					auto z = (seed += 0x9e3779b97f4a7c15 );
					z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9;
					z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111eb;

					if(seed_span_begin != seed_span_end)
					{
						++seed_span_begin;
					}

					return z ^ ( z >> 31 );
				};
				std::ranges::generate( this_temparory_state, splitmix64 );
				seed = 0;

				for ( std::uint32_t index = 0; index < num_state_words; ++index )
				{
					state[ index ] = this_temparory_state[ index * 2 ];
					state[ index ] <<= 32;
					state[ index ] |= this_temparory_state[ index * 2 + 1 ];
				}
			}
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
			RNG_ISAAC contains code common to isaac and isaac64.
			It uses CRTP (a.k.a. 'static polymorphism') to invoke specialized methods in the derived class templates,
			avoiding the cost of virtual method invocations and allowing those methods to be placed inline by the compiler.
			Applications should not specialize or instantiate this template directly.
		*/

		template<std::size_t Alpha, class T>
		class RNG_ISAAC
		{
		public:
			static constexpr std::size_t state_size = 1 << Alpha;

			using result_type = T;

			static constexpr T max() { return std::numeric_limits<T>::max(); }
			static constexpr T min() { return std::numeric_limits<T>::min(); }

			static constexpr result_type default_seed = 0;

			RNG_ISAAC()
			{
				seed(default_seed);
			}

			explicit RNG_ISAAC(result_type seed_number)
				: issac_base_member_counter(state_size)
			{
				seed(seed_number);
			}

			template <typename SeedSeq>
			requires( not std::convertible_to<SeedSeq, result_type> )
			explicit RNG_ISAAC( SeedSeq& number_sequence )
				: issac_base_member_counter(state_size)
			{
				seed(number_sequence);
			}
	
			RNG_ISAAC(const std::vector<result_type>& seed_vector)
				: issac_base_member_counter(state_size)
			{
				seed(seed_vector);
			}
	
			template<class IteratorType>
			RNG_ISAAC
			(
				IteratorType begin,
				IteratorType end,
				typename std::enable_if
				<
						std::is_integral<typename std::iterator_traits<IteratorType>::value_type>::value &&
						std::is_unsigned<typename std::iterator_traits<IteratorType>::value_type>::value
				>::type* = nullptr
			)
			: issac_base_member_counter(state_size)
			{
				seed(begin, end);
			}
	
			RNG_ISAAC(std::random_device& random_device_object)
				: issac_base_member_counter(state_size)
			{
				seed(random_device_object);
			}

			RNG_ISAAC(const RNG_ISAAC& other)
				: issac_base_member_counter(state_size)
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
	
			inline void seed(result_type seed_number)
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
				std::seed_seq my_seed_sequence(number_sequence.begin(), number_sequence.end());
				std::array<result_type, state_size> seed_array;
				my_seed_sequence.generate(seed_array.begin(), seed_array.end());
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
				std::vector<result_type> random_seed_vector;
				random_seed_vector.reserve(state_size);
				for (std::size_t round = 0; round < state_size; ++round)
				{
					result_type seed_number_value = GenerateSecureRandomNumberSeed<result_type>(random_device_object);

					std::size_t bytes_filled{sizeof(std::random_device::result_type)};
					while(bytes_filled < sizeof(result_type))
					{
						result_type seed_number_value2 = GenerateSecureRandomNumberSeed<result_type>(random_device_object);

						seed_number_value <<= (sizeof(std::random_device::result_type) * 8);
						seed_number_value |= seed_number_value2;
						bytes_filled += sizeof(std::random_device::result_type);
					}
					random_seed_vector.push_back(seed_number_value);
				}
				seed(random_seed_vector.begin(), random_seed_vector.end());
			}

			inline result_type operator()()
			{
				if(issac_base_member_counter - 1 == std::numeric_limits<std::size_t>::max())
					issac_base_member_counter = state_size - 1;

				return (!issac_base_member_counter--) ? (do_isaac(), issac_base_member_result[issac_base_member_counter]) : issac_base_member_result[issac_base_member_counter];
			}
	
			inline void discard(unsigned long long z)
			{
				for (; z; --z) operator()();
			}

			friend bool operator==(const RNG_ISAAC& left, const RNG_ISAAC& right)
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

			friend bool operator!=(const RNG_ISAAC& left, const RNG_ISAAC& right)
			{
				return !(left == right);
			}

			template <class CharT, class Traits>
			friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const RNG_ISAAC& isaac_base_object)
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
			operator>>(std::basic_istream<CharT, Traits>& is, RNG_ISAAC& isaac_base_object)
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

			~RNG_ISAAC() = default;

		private:

			/*
				ISAAC (Indirection, Shift, Accumulate, Add, and Count) generates 32-bit random numbers.
				Averaged out, it requires 18.75 machine cycles to generate each 32-bit value.
				Cycles are guaranteed to be at least 2(^)40 values long, and they are 2(^)8295 values long on average.
				The results are uniformly distributed, unbiased, and unpredictable unless you know the seed.
			*/

			//Use ISAAC+ Algorithm (32 bit)?
			#if 1

			void implementation_isaac()
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

			void implementation_isaac()
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

			/*
				ISAAC-64 generates a different sequence than ISAAC, but it uses the same principles. It uses 64-bit arithmetic.
				It generates a 64-bit result every 19 instructions. All cycles are at least 2(^)72 values, and the average cycle length is 2(^)16583.

				The following files implement ISAAC-64. 
				The constants were tuned for a 64-bit machine, and a complement was thrown in so that all-zero states become nonzero faster.
			*/

			//Use ISAAC+ Algorithm (64 bit)?
			#if 1

			void implementation_isaac64()
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
			inline result_type diffusion_with_indirection_memory_address64(result_type* memory_pointer, result_type current_value)
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

			inline void RNG_do_step64
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
				*(update_memory_array++) = y = a + b + diffusion_with_indirection_memory_address64(old_memory_array, x);
				//result[index] ← x + (state[state[index]] >> 10) mod 512
				//b == result[index]
				*(current_result_array++) = b = x + diffusion_with_indirection_memory_address64(old_memory_array, y >> Alpha);
			}

			void implementation_isaac64()
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
					RNG_do_step64(~(a ^ (a << 21)), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step64(a ^ (a >> 5), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step64(a ^ (a << 12), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step64(a ^ (a >> 33), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
				}
				for (new_memory_array = old_memory_array; new_memory_array < new_memory_array_address; )
				{
					RNG_do_step64(~(a ^ (a << 21)), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step64(a ^ (a >> 5), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step64(a ^ (a << 12), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					RNG_do_step64(a ^ (a >> 33), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
				}
				this->issac_base_member_register_b = b;
				this->issac_base_member_register_a = a;
			}

			#endif

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
			}

			inline void do_isaac()
			{
				if constexpr(std::same_as<result_type,std::uint32_t>)
					this->implementation_isaac();
				else if constexpr(std::same_as<result_type,std::uint64_t>)
					this->implementation_isaac64();
			}

			/* the golden ratio */
			inline result_type golden()
			{
				if constexpr(std::same_as<result_type,std::uint32_t>)
					return static_cast<std::uint32_t>(0x9e3779b9);
				else if constexpr(std::same_as<result_type,std::uint64_t>)
					return static_cast<std::uint64_t>(0x9e3779b97f4a7c13);
			}
	
			inline void mix(result_type& a, result_type& b, result_type& c, result_type& d, result_type& e, result_type& f, result_type& g, result_type& h)
			{
				if constexpr(std::same_as<result_type,std::uint32_t>)
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
				else if constexpr(std::same_as<result_type,std::uint64_t>)
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
			}
	
			std::array<result_type, state_size> issac_base_member_result {};
			std::array<result_type, state_size> issac_base_member_memory {};
			result_type issac_base_member_register_a = 0;
			result_type issac_base_member_register_b = 0;
			result_type issac_base_member_register_c = 0;
			std::size_t	issac_base_member_counter = 0;
		};

		template<std::size_t Alpha = 8>
		using isaac = RNG_ISAAC<Alpha, std::uint32_t>;

		template<std::size_t Alpha = 8>
		using isaac64 = RNG_ISAAC<Alpha, std::uint64_t>;
	}

	/*
		A counter-based random number generation (CBRNG, also known as a counter-based pseudo-random number generator, or CBPRNG) 
		is a kind of pseudorandom number generator that uses only an integer counter as its internal state.
		
		Improved version from Middle Square Method, invented by John Von Neumann.

		Reference papers: https://arxiv.org/abs/1704.00358 and https://arxiv.org/abs/2004.06278

		Reference source code:
		https://github.com/DoumanAsh/squares-rnd/blob/master/src/lib.rs
		https://github.com/bootes16/simple_prng/blob/master/include/middle_sq_weyl.h
		https://github.com/Shiroechi/Litdex.Security.RNG/blob/main/Source/Security/RNG/PRNG/MiddleSquareWeylSequence.cs
	*/
	namespace RNG_NumberSquare_TakeMiddle
	{
		template <typename NumberType>
		/*
			Implements the Middle Square Weyle Sequence psuedo random number generator.
			The templated type size determines the output size range. Sort of.
			The range doesn't work terribly well for anything by char, doesn't give a good
			spread of values for large types like int.
			PRNG algorithm from: https://en.wikipedia.org/wiki/Middle-square_method.
		*/
		class JohnVonNeumannAlgorithm
		{

		private:

			std::uint64_t odd_number_accumulator {0xb5ad4eceda1ce2a9ULL};
			std::uint64_t result_random_number {0};
			std::uint64_t weyl_sequence {0};

			// Bitmask only really matters for char to ensure it serves 7-bit values.
			static constexpr const bool is_char = std::is_signed<NumberType>::value && (sizeof(NumberType) == 1);
			static constexpr const NumberType bitmask = is_char ? 0x7f : (std::same_as<NumberType, std::uint32_t> ? 0xffffffffU : 0xffffffffffffffffU );

		public:

			using result_type = NumberType;

			static constexpr NumberType max() { return std::numeric_limits<NumberType>::max(); }
			static constexpr NumberType min() { return std::numeric_limits<NumberType>::min(); }

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
			void random_seed(std::size_t a, std::size_t b)
			{
				//a: counter
				//b: key

				std::size_t number = std::rotr(b, 32);
				std::size_t xorshift_random_seed = this->result_random_number;

				this->odd_number_accumulator = static_cast<std::uint64_t>( std::rotl(a, 32) );
				while ((this->odd_number_accumulator & 1) == 0)
				{
					auto difference = odd_number_accumulator - std::numeric_limits<std::uint64_t>::min();
					auto difference2 = std::numeric_limits<std::uint64_t>::max() - this->odd_number_accumulator;
					if(difference > difference2)
						this->odd_number_accumulator -= 1;
					else if(difference < difference2)
						this->odd_number_accumulator += 1;
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

							number = xorshift_random_seed;

							number ^= (number << 13);
							number ^= (number >> 17);
							number ^= (number << 5);
						}
						else
						{
							//Use xorshift64

							xorshift_random_seed ^= (xorshift_random_seed << 13);
							xorshift_random_seed ^= (xorshift_random_seed >> 7);
							xorshift_random_seed ^= (xorshift_random_seed << 17);

							number = xorshift_random_seed;

							number ^= (number << 13);
							number ^= (number >> 7);
							number ^= (number << 17);
						}

						//Toggles an odd number of bits in an odd position, so an even number becomes an odd number
						//切换一个奇数位置的比特位，所以偶数变成了奇数
						this->odd_number_accumulator ^= static_cast<std::uint64_t>(1 << static_cast<std::size_t>(number & (CURRENT_SYSTEM_BITS - 1)) );
					}
				}

				//Use xorshift128

				std::array<std::uint32_t, 4> xorshift128_state { number, number -= this->odd_number_accumulator, xorshift_random_seed , xorshift_random_seed -= this->odd_number_accumulator };

				std::uint32_t t = xorshift128_state[3];
				std::uint32_t s = xorshift128_state[0];
				xorshift128_state[3] = xorshift128_state[2];
				xorshift128_state[2] = xorshift128_state[1];
				xorshift128_state[1] = s;

				t ^= (t << 11);
				t ^= (t >> 8);

				xorshift128_state[0] = t ^ s ^ (s >> 19);

				this->weyl_sequence ^= xorshift128_state[0];
				this->result_random_number += xorshift128_state[1];
				this->weyl_sequence += (xorshift128_state[3] - xorshift128_state[2]);
				this->result_random_number ^= (xorshift128_state[2] - xorshift128_state[3]);
			}
			
			void random_seed(RNG_SimpleImplementation::GNU_C_LibraryGenerator& simple_implementation_generator)
			{
				std::vector random_seed_vector = GenerateSecureRandomNumberSeedSequence<std::uint64_t>(32);
				std::seed_seq random_seed_sequence_obejct(random_seed_vector.begin(), random_seed_vector.end());
				std::mt19937_64 pseudo_random_generator_object(random_seed_sequence_obejct);

				simple_implementation_generator.seed( static_cast<int>(random_seed_vector.back()) ^ static_cast<int>(random_seed_vector.back() >> 32));

				this->weyl_sequence = pseudo_random_generator_object();
				this->result_random_number = pseudo_random_generator_object() ^ simple_implementation_generator();
			}

			void seed(NumberType seed)
			{
				reset();
				if (seed == 0) 
					return;
				this->result_random_number = seed * seed;
				this->weyl_sequence += this->odd_number_accumulator;
				this->result_random_number += this->weyl_sequence;
				this->result_random_number = std::rotr(this->result_random_number, 32);
			}

			//Using hardware devices to generate true random numbers
			//As the seed value for this PRNG generator
			//使用硬件设备生成真随机数
			//作为这个PRNG生成器的种子数值
			void seed(std::random_device& random_device_object)
			{
				NumberType seed_value = GenerateSecureRandomNumberSeed<NumberType>(random_device_object);

				this->seed(seed_value);
			}

			void reset()
			{
				this->result_random_number = this->weyl_sequence = 0;
			}

			NumberType operator()()
			{
				this->result_random_number *= this->result_random_number;
				this->weyl_sequence += this->odd_number_accumulator;
				this->result_random_number += this->weyl_sequence;
				this->result_random_number = std::rotr(this->result_random_number, 32);
				this->result_random_number += is_char;
				return static_cast<NumberType>(this->result_random_number & bitmask);
			}

			JohnVonNeumannAlgorithm() = default;

			JohnVonNeumannAlgorithm(NumberType seed)
			{
				this->seed(seed);
			}

			JohnVonNeumannAlgorithm(NumberType seed, NumberType accumulator)
			{
				this->odd_number_accumulator = ((accumulator & 1) == 1) ? accumulator : accumulator + 1;
				this->seed(seed);
			}

			~JohnVonNeumannAlgorithm()
			{
				this->reset();
			}
		};

		template <typename NumberType>
		/*
			The squares RNG was derived using ideas from “Middle-Square Weyl Sequence RNG”[7].
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
		class ImprovedJohnVonNeumannAlgorithm : UniformRandomBitGenerator<NumberType>
		{

		private:

			std::uint64_t state_key {0x5d8491e219f6537dULL};
			std::uint64_t state_counter {0};

			template<typename Type>
			requires std::unsigned_integral<Type> || std::signed_integral<Type>
			static inline Type simple_self_power(Type number)
			{
				return number * number;
			}
			
			/*
				@param counter;
				Integer counter which acts as state. Should be increased to generate new number.

				@param key;
				Integer which in general should be irregular bit pattern with approximately equal
				number of zeros and ones. Generally should be constant, but can be changed when new range of random numbers is required.

				@return random state 32 bit number
			*/
			static inline uint32_t squares32bit(uint64_t counter, uint64_t key)
			{
				std::uint64_t x, y, z;
				y = x = counter * key; z = y + key;
				x = simple_self_power(x) + y; x = std::rotr(x, 32); /* round 1 */
				x = simple_self_power(x) + z; x = std::rotr(x, 32); /* round 2 */
				x = simple_self_power(x) + y; x = std::rotr(x, 32); /* round 3 */
				return (simple_self_power(x) + z) >> 32; /* round 4 */
			}

			/*
				@param counter;
				Integer counter which acts as state. Should be increased to generate new number.

				@param key;
				Integer which in general should be irregular bit pattern with approximately equal
				number of zeros and ones. Generally should be constant, but can be changed when new range of random numbers is required.

				@return random state 64 bit number
			*/
			static inline uint64_t squares64bit(uint64_t counter, uint64_t key)
			{
				std::uint64_t t, x, y, z;
				y = x = counter * key; z = y + key;
				x = simple_self_power(x) + y; x = std::rotr(x, 32); /* round 1 */
				x = simple_self_power(x) + z; x = std::rotr(x, 32); /* round 2 */
				x = simple_self_power(x) + y; x = std::rotr(x, 32); /* round 3 */
				t = x = simple_self_power(x) + z; x = std::rotr(x, 32); /* round 4 */
				return t ^ ((simple_self_power(x) + y) >> 32); /* round 5 */
			}

			//high part of 32 bit integer multiplication
			static inline std::uint32_t multiplication32bit_hightpart(std::uint32_t a, std::uint32_t b)
			{
				return static_cast<std::uint32_t>( (static_cast<std::uint64_t>(a) * static_cast<std::uint64_t>(b)) >> 32 );
			}

			static inline void multiplication64bit(std::uint64_t a, std::uint64_t b, std::uint64_t& high_part, std::uint64_t& low_part)
			{
				#ifdef __SIZEOF_INT128__ // GNU C

				unsigned __int128 result =  a * (unsigned __int128)b;

				low_part = (std::uint64_t)result;
				high_part = result >> 64;

				#else

				//32bit
				uint64_t a_lo = (uint64_t)(uint32_t)a;
				uint64_t a_hi = a >> 32;
				uint64_t b_lo = (uint64_t)(uint32_t)b;
				uint64_t b_hi = b >> 32;

				//64bit
				uint64_t p0 = a_lo * b_lo;
				uint64_t p1 = a_lo * b_hi;
				uint64_t p2 = a_hi * b_lo;
				uint64_t p3 = a_hi * b_hi;

				uint32_t carry = (uint32_t)(((p0 >> 32) + (uint32_t)p1 + (uint32_t)p2) >> 32);

				low_part = p0 + (p1 << 32) + (p2 << 32);
				high_part = p3 + (p1 >> 32) + (p2 >> 32) + carry;

				#endif
			}

			//high part of 64 bit integer multiplication
			static inline std::uint64_t multiplication64bit_hightpart(std::uint64_t a, std::uint64_t b)
			{
				std::uint64_t high_part = 0;
				std::uint64_t low_part = 0;
				multiplication64bit(a, b, high_part, low_part);
				low_part = 0;
				return high_part;
			}

			/*
				We used the parameters “counter” and “key” to be consistent with Philox parameters. 
				This generator would be used in a similar way as Philox.
				After computing the square, a rotation (circular shift) by 32 bits is performed. 
				This is done to position the random data into the lower 32 bits which results in a better randomization on the next round.

				The key should be an irregular bit pattern with roughly half ones and half zeros. 
				A utility in the software download is provided to create such keys. 
				The keys are chosen so the the upper 8 digits are different and also that the lower 8 digits are different. 
				Different digits assure sufficient change when adding (counter * key) on each invocation of the RNG. 
				The digits are also chosen randomly. 
				This helps assure that the streams generated will produce relatively random, statistically independent data. 
				The “different digits”method of initialization was created for the msws RNG in 2017.
				It has proved to be an effective means of initializing the Weyl sequence. 
				There have been no reported failures with the msws RNG when using this initialization. 
				The key utility in the squares RNG software download creates keys using the same different digits method.

				//http://squaresrng.wixsite.com/rand
			*/

			std::uint32_t generate32bit()
			{
				++(this->state_counter);
				return squares32bit(this->state_counter, this->state_key);
			}

			std::uint64_t generate64bit()
			{
				++(this->state_counter);
				return squares64bit(this->state_counter, this->state_key);
			}

		public:

			using result_type =  UniformRandomBitGenerator<NumberType>::result_type;

			void set_counter(std::uint64_t counter)
			{
				this->state_counter = counter;
			}

			std::uint64_t get_counter()
			{
				return this->state_counter;
			}

			//generation number in range 0...number
			std::uint32_t number32bit_range(std::uint32_t number)
			{
				//https://lemire.me/blog/2016/06/30/fast-random-shuffling/
				std::uint32_t result = this->generate32bit();
				std::uint32_t high_part = this->multiplication32bit_hightpart(result, number);
				std::uint32_t low_part = result * number;

				if(low_part < number)
				{
					while (low_part < ( -(number) % number) )
					{
						result = this->generate32bit();
						high_part = this->multiplication32bit_hightpart(result, number);
						low_part = result * number;
					}
				}

				return high_part;
			}

			//generation number in range 0...number
			std::uint64_t number64bit_range(std::uint64_t number)
			{
				//https://lemire.me/blog/2016/06/30/fast-random-shuffling/
				std::uint64_t result = this->generate32bit();
				std::uint64_t high_part = this->multiplication64bit_hightpart(result, number);
				std::uint64_t low_part = result * number;

				if(low_part < number)
				{
					while (low_part < ( -(number) % number) )
					{
						result = this->generate32bit();
						high_part = this->multiplication64bit_hightpart(result, number);
						low_part = result * number;
					}
				}

				return high_part;
			}

			void random_seed(JohnVonNeumannAlgorithm<NumberType>& improved_johnvon_neumann_algorithm_object)
			{
				improved_johnvon_neumann_algorithm_object.random_seed(this->state_counter, this->state_key);
				this->state_key = improved_johnvon_neumann_algorithm_object();
				this->state_counter = 0;
			}

			void seed(std::uint64_t seed)
			{
				this->state_key = seed;
				this->state_counter = 0;
			}

			//Using hardware devices to generate true random numbers
			//As the seed value for this CBRNG generator
			//使用硬件设备生成真随机数
			//作为这个CBRNG生成器的种子数值
			void seed(std::random_device& random_device_object)
			{
				std::uint64_t seed_value = GenerateSecureRandomNumberSeed<std::uint64_t>(random_device_object);

				this->seed(seed_value);
			}

			void reset()
			{
				this->state_key = 0x5d8491e219f6537dULL;
				this->state_counter = 0;
			}

			NumberType operator()()
			{
				if constexpr(std::same_as<NumberType, std::uint32_t>)
				{
					return this->generate32bit();
				}
				else if constexpr(std::same_as<NumberType, std::uint64_t>)
				{
					return this->generate64bit();
				}
				else
				{
					static_assert(CommonToolkit::Dependent_Always_Failed<NumberType>, "");
				}
			}

			ImprovedJohnVonNeumannAlgorithm() {}

			ImprovedJohnVonNeumannAlgorithm(std::uint64_t counter)
				:
				state_counter(counter)
			{
				
			}

			ImprovedJohnVonNeumannAlgorithm(std::uint64_t counter, std::uint64_t key)
				:
				state_counter(counter), state_key(key)
			{
				
			}
		};
	}

	namespace RNG_LC
	{
		template <typename T>
		//numbers[n] = a * numbers[n - 1] + b (modulus 2^bits)
		//a is a special multiplicative factor and b is a special additive factor
		class LinearCongruential;

		template<>
		struct LinearCongruential<std::uint32_t>
		{

			using result_type = std::uint32_t;

		private:

			result_type number = 0;

		public:

			result_type operator()()
			{
				return number = number * 1664525U + 1013904223U;
			}

			void seed(std::uint32_t seed)
			{
				if(seed == 0)
					seed = 1;

				number = seed;
			}

			static constexpr result_type min()  
			{ 
				return std::numeric_limits<std::uint32_t>::min();
			}

			static constexpr result_type max()
			{
				return std::numeric_limits<std::uint32_t>::max();
			};

			LinearCongruential() : number(1U) {};
			~LinearCongruential() { number = 0U; }

		};

		template<>
		struct LinearCongruential<std::uint64_t>
		{

			using result_type = std::uint64_t;

		private:
			
			result_type number = 0;

		public:

			result_type operator()()
			{
				//64-bit Linear Congruential Generator
				//http://nuclear.llnl.gov/CNP/rng/rngman/node4.html
				return number = number * 2862933555777941757ULL + 3037000493ULL; 
			}

			void seed(std::uint64_t seed)
			{
				if(seed == 0)
					seed = 1;

				number = seed;
			}

			static constexpr result_type min()  
			{ 
				return std::numeric_limits<std::uint64_t>::min();
			}

			static constexpr result_type max()
			{
				return std::numeric_limits<std::uint64_t>::max();
			};

			LinearCongruential() : number(1ULL) {};
			~LinearCongruential() { number = 0ULL; }

		};

		template<>
		class LinearCongruential<float>
		{

		private:

			std::uint32_t number = 0;

		public:

			float operator()()
			{
				number = number * 1664525U + 1013904223U;

				std::uint32_t integer = (number >> 9) | 0x3F800000U;
				float single_floating = 0.0F;

				::memmove(&single_floating, &integer, sizeof(float));

				return single_floating - 1.0F;
			}

			void seed(std::uint32_t seed)
			{
				if(seed == 0)
					seed = 1;

				number = seed;
			}

			static constexpr float min()  
			{ 
				return std::numeric_limits<float>::min();
			}

			static constexpr float max()
			{
				return std::numeric_limits<float>::max();
			};

			LinearCongruential() : number(1U) {};
			~LinearCongruential() { number = 0U; }

		};

		template<>
		class LinearCongruential<double>
		{

		private:

			std::uint64_t number = 0;

		public:

			double operator()()
			{
				//64-bit Linear Congruential Generator
				//http://nuclear.llnl.gov/CNP/rng/rngman/node4.html
				number = number * 2862933555777941757ULL + 3037000493ULL;

				std::uint32_t integer = (number >> 12) | (0x3FF00000ULL << 32);
				double double_floating = 0.0;

				::memmove(&double_floating, &integer, sizeof(double));

				return double_floating - 1.0;
			}

			void seed(std::uint64_t seed)
			{
				if(seed == 0)
					seed = 1;

				number = seed;
			}

			static constexpr double min()  
			{ 
				return std::numeric_limits<double>::min();
			}

			static constexpr double max()
			{
				return std::numeric_limits<double>::max();
			};

			LinearCongruential() : number(1ULL) {};
			~LinearCongruential() { number = 0ULL; }

		};
	}
}