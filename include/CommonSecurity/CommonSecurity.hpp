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
	
	/*
		Deterministic Random Bit Generators
		https://csrc.nist.gov/glossary/term/deterministic_random_bit_generator
	*/
	namespace DRBG
	{

	}

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

	struct FileDataCrypticModuleAdapter
	{
		std::string						   FileDataHashString;
		std::size_t						   FileDataBlockCount = 8;
		std::deque<std::vector<std::byte>> FileDataBytes;
		std::deque<std::vector<char>>	   FileDataCharacters;

		std::atomic<std::size_t> fileDataByteReadedCount = 0;
		std::atomic<std::size_t> fileDataByteWritedCount = 0;
		std::atomic<bool>		 allFileDataIsReaded = false;
		std::atomic<bool>		 allFileDataIsWrited = false;
		std::atomic<bool>		 dataCovertingToBytes = false;
		std::atomic<bool>		 dataCovertingFromBytes = false;

		void ResetStatus()
		{
			FileDataHashString.clear();
			fileDataByteReadedCount.store( 0 );
			fileDataByteWritedCount.store( 0 );
			allFileDataIsReaded.store( false );
			allFileDataIsWrited.store( false );
			dataCovertingToBytes.store( false );
			dataCovertingFromBytes.store( false );
		}

		void ClearData()
		{
			FileDataBytes.clear();
			FileDataCharacters.clear();
		}

		std::deque<std::vector<std::byte>> ToBytes( std::deque<std::vector<char>>& FileDataBlock )
		{
			if ( FileDataBlock.size() > 0 )
			{
				if ( FileDataBlock.front().size() == 0 && FileDataBlock.back().size() == 0 )
				{
					return std::deque<std::vector<std::byte>>( 0 );
				}

				std::deque<std::vector<std::byte>> answer;
				for ( std::size_t dataBlockNumber = 0; dataBlockNumber < FileDataBlockCount; ++dataBlockNumber )
				{
					std::vector<char>	   dataBlockIn( std::move( FileDataBlock[ dataBlockNumber ] ) );
					std::vector<std::byte> dataBlockOut;
					dataBlockOut.reserve(dataBlockIn.size());

					for ( char& dataIn : dataBlockIn )
					{
						std::byte dataOut = static_cast<std::byte>( static_cast<unsigned char>( dataIn ) );
						dataBlockOut.push_back( std::move( dataOut ) );
					}
					std::vector<char>().swap( dataBlockIn );
					answer.push_back( std::move( dataBlockOut ) );
				}
				std::deque<std::vector<char>>().swap( FileDataBlock );
				return answer;
			}
			return std::deque<std::vector<std::byte>>( 0 );
		}

		std::deque<std::vector<char>> FromBytes( std::deque<std::vector<std::byte>>& FileDataBlock )
		{
			if ( FileDataBlock.size() > 0 )
			{
				if ( FileDataBlock.front().size() == 0 && FileDataBlock.back().size() == 0 )
				{
					return std::deque<std::vector<char>>( 0 );
				}

				std::deque<std::vector<char>> answer;
				for ( std::size_t dataBlockNumber = 0; dataBlockNumber < FileDataBlockCount; ++dataBlockNumber )
				{
					std::vector<std::byte> dataBlockIn( std::move( FileDataBlock[ dataBlockNumber ] ) );
					std::vector<char>	   dataBlockOut;
					dataBlockOut.reserve(dataBlockIn.size());

					for ( std::byte& dataIn : dataBlockIn )
					{
						char	  dataOut = static_cast<char>( static_cast<unsigned char>( dataIn ) );
						dataBlockOut.push_back( std::move( dataOut ) );
					}
					std::vector<std::byte>().swap( dataBlockIn );
					answer.push_back( std::move( dataBlockOut ) );
				}
				std::deque<std::vector<std::byte>>().swap( FileDataBlock );
				return answer;
			}
			return std::deque<std::vector<char>>( 0 );
		}

		FileDataCrypticModuleAdapter() = default;
		~FileDataCrypticModuleAdapter() = default;
	};

	inline void ConvertingInputDataAndTransmission( std::unique_ptr<FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlocks )
	{
		if ( FDCM_Adapter_Pointer != nullptr )
		{
			auto						  NativePointer = FDCM_Adapter_Pointer.get();
			FileDataCrypticModuleAdapter& AssociatedObjects = ( *NativePointer );
			AssociatedObjects.FileDataBlockCount = pointerWithFileDataBlocks->size();

			AssociatedObjects.dataCovertingToBytes.store( true );
			AssociatedObjects.FileDataBytes = std::move( AssociatedObjects.ToBytes( *pointerWithFileDataBlocks ) );
			AssociatedObjects.dataCovertingToBytes.store( false );
			AssociatedObjects.dataCovertingToBytes.notify_one();
		}
	}

	inline void ConvertingOutputDataAndTransmission( std::unique_ptr<FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<std::byte>>* pointerWithFileDataBlocks )
	{
		if ( FDCM_Adapter_Pointer->dataCovertingFromBytes.load() == true )
		{
			FDCM_Adapter_Pointer->dataCovertingFromBytes.wait( true );
		}

		if ( FDCM_Adapter_Pointer != nullptr )
		{
			auto						  NativePointer = FDCM_Adapter_Pointer.get();
			FileDataCrypticModuleAdapter& AssociatedObjects = ( *NativePointer );
			AssociatedObjects.FileDataBlockCount = pointerWithFileDataBlocks->size();

			AssociatedObjects.dataCovertingFromBytes.store( true );
			AssociatedObjects.FileDataCharacters = std::move( AssociatedObjects.FromBytes( *pointerWithFileDataBlocks ) );
			AssociatedObjects.dataCovertingFromBytes.store( false );
			AssociatedObjects.dataCovertingFromBytes.notify_one();
		}
	}

	inline void ConversionBufferData_Input( std::unique_ptr<FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<char>>* pointerWithFileDataBlocks )
	{
		std::chrono::duration<double> TimeSpent;

		if ( FDCM_Adapter_Pointer->dataCovertingToBytes.load() == true )
		{
			FDCM_Adapter_Pointer->dataCovertingToBytes.wait( true );
		}

		std::cout << "Note that the read-in file data is of type char and needs to be converted to std::byte.\n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
		auto convertTypeDataWithStartTime = std::chrono::system_clock::now();

		std::future<void> futureTask_convertingBufferData = std::async( std::launch::async, CommonModule::ConvertingInputDataAndTransmission, std::ref( FDCM_Adapter_Pointer ), pointerWithFileDataBlocks );

	ConvertingBufferDataFlag:

		std::future_status futureTaskStatus_convertingBufferData = futureTask_convertingBufferData.wait_for( std::chrono::seconds( 1 ) );
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

		if ( futureTaskStatus_convertingBufferData != std::future_status::ready )
		{
			goto ConvertingBufferDataFlag;
		}

		auto convertTypeDataWithEndTime = std::chrono::system_clock::now();
		TimeSpent = convertTypeDataWithEndTime - convertTypeDataWithStartTime;
		std::cout << "The file data has been converted, the time has been spent: " << TimeSpent.count() << " seconds \n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
	}

	inline void ConversionBufferData_Output( std::unique_ptr<FileDataCrypticModuleAdapter>& FDCM_Adapter_Pointer, std::deque<std::vector<std::byte>>* pointerWithFileDataBlocks )
	{
		std::chrono::duration<double> TimeSpent;

		if ( FDCM_Adapter_Pointer->dataCovertingToBytes.load() == true )
		{
			FDCM_Adapter_Pointer->dataCovertingToBytes.wait( true );
		}

		std::cout << "Note that the write-out file data is about std::byte type and needs to be converted to char type.\n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
		auto convertTypeDataWithStartTime = std::chrono::system_clock::now();

		std::future<void> futureTask_convertingBufferData = std::async( std::launch::async, CommonModule::ConvertingOutputDataAndTransmission, std::ref( FDCM_Adapter_Pointer ), pointerWithFileDataBlocks );

	ConvertingBufferDataFlag:

		std::future_status futureTaskStatus_convertingBufferData = futureTask_convertingBufferData.wait_for( std::chrono::seconds( 1 ) );
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

		if ( futureTaskStatus_convertingBufferData != std::future_status::ready )
		{
			goto ConvertingBufferDataFlag;
		}

		auto convertTypeDataWithEndTime = std::chrono::system_clock::now();
		TimeSpent = convertTypeDataWithEndTime - convertTypeDataWithStartTime;
		std::cout << "The file data has been converted, the time has been spent: " << TimeSpent.count() << " seconds \n"
					<< "Current Thread ID: " << std::this_thread::get_id() << std::endl;
	}

	namespace Adapters 
	{
		#if __cpp_lib_byte

		inline void characterToByte(const std::vector<char>& input , std::vector<std::byte>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (char characterData : input)
			{
				output.push_back( static_cast<std::byte>(static_cast<unsigned char>(characterData)) );
			}
		}

		inline void characterFromByte(const std::vector<std::byte>& input, std::vector<char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (std::byte byteData : input)
			{
				output.push_back( static_cast<char>(static_cast<unsigned char>(byteData)) );
			}
		}

		inline void classicByteToByte(const std::vector<unsigned char>& input , std::vector<std::byte>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (unsigned char characterData : input)
			{
				output.push_back( static_cast<std::byte>(characterData) );
			}
		}

		inline void classicByteFromByte(const std::vector<std::byte>& input, std::vector<unsigned char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (std::byte byteData : input)
			{
				output.push_back( static_cast<unsigned char>(byteData) );
			}
		}

		#endif

		inline void characterToClassicByte(const std::vector<char>& input , std::vector<unsigned char>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (char characterData : input)
			{
				output.push_back( static_cast<unsigned char>(characterData) );
			}
		}

		inline void characterFromClassicByte(const std::vector<unsigned char>& input, std::vector<char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (unsigned char byteData : input)
			{
				output.push_back( static_cast<char>(byteData) );
			}
		}
	}

}  // namespace Cryptograph::CommonModule

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