#pragma once

namespace CustomSecurity::DataObfuscator
{
	namespace MathTools
	{
		inline uint32_t GreatestCommonDvisor(std::uint32_t number_a, std::uint32_t number_b)
		{
			#if __cpp_lib_gcd_lcm
				return std::gcd(number_a, number_b);
			#else
				std::uint32_t modulus_number = number_b, difference_number = 0;
				std::int32_t answer = 1;

				while (number_a > 1)
				{
					auto floor_number = static_cast<std::int32_t>( std::floor(number_a / modulus_number) );
					auto temporary_number = modulus_number;

					modulus_number = modulus_number % number_a;
					number_a = temporary_number;
					temporary_number = difference_number;
					difference_number = answer - floor_number * difference_number;
					answer = temporary_number;
				}

				if(answer < 0)
					answer += modulus_number;

				return answer;
			#endif
		}

		inline std::uint32_t MultiplicationOfWithGaloisField( std::uint32_t number_a, std::uint32_t number_b, std::uint32_t primitive_polynomial_value = 0x011B )
		{
			/* accumulator for the product of the multiplication */
			std::uint32_t answer = 0x00;

			while( number_a && number_b )
			{
				/* if the polynomial for b has a constant term, add the corresponding a to p */
				if(number_b & 0x01)
				{
					/* addition in GF(2^m) is an XOR of the polynomial coefficients */
					answer ^= number_a;
				}

				/* modulo: if a has a nonzero term x^7, then must be reduced when it becomes x^8 */
				if(number_a & 0x80)
				{
					/* subtract the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) – you can change it but it must be irreducible */
					number_a = number_a << 0x01 ^ primitive_polynomial_value;
				}
				else
				{
					/* equivalent to a*x */
					number_a = number_a << 0x01;
				}

				number_a &= 0xFF;
				number_b >>= 0x01;
			}
			return answer;
		}

		inline std::uint32_t PowerOfWithGaloisField( std::uint32_t number, std::uint32_t count, std::uint32_t primitive_polynomial_value = 0x011B )
		{
			std::uint32_t answer = 0x01;

			while(count)
			{
				if(count & 0x01)
				{
					answer = MultiplicationOfWithGaloisField(answer, number, primitive_polynomial_value);
				}

				number = MultiplicationOfWithGaloisField(number, number, primitive_polynomial_value);

				count >>= 0x01;
			}

			return answer;
		}

		inline std::uint32_t InverseOfWithGaloisField(std::uint32_t number, std::uint32_t primitive_polynomial_value = 0x011B)
		{
			// 0 has no inverse; the inverse of 256 in GF(257) is 256, which means 0 takes modulo 256.
			// The inverse of 1 is always 1
			// 0没有逆数；GF(257)中256的逆数是256，也就是0取模256。
			// 1的逆数总是1

			if(number < 2)
				return number;

			//Bad GF(257) <-> 0x0101
			if(primitive_polynomial_value == 0x0101)
				return GreatestCommonDvisor(number, primitive_polynomial_value);

			return PowerOfWithGaloisField(number, 0xFE, primitive_polynomial_value);
		}

		template<std::integral IntegralType>
		inline bool CheckParityBits(const IntegralType& IntegralTypeData)
		{
			//True is odd parity, False is even parity.

			#if __cpp_lib_bitops

			return (std::popcount(IntegralTypeData) & 1) == 1;

			#else

			constexpr std::size_t shift_bit_limlt = sizeof(IntegralType) * std::numeric_limits<IntegralType>::digits;

			Type answer = 0;
			answer = IntegralTypeData ^ (IntegralTypeData >> 1);
			for(std::size_t shift_bit = 2; shift_bit <= shift_bit_limlt / 2; shift_bit <<= 1)
			{
				answer = IntegralTypeData ^ (IntegralTypeData >> shift_bit);
			}

			return answer & 1 ? true : false;

			#endif
		}
	}

	namespace HashFunction
	{
		template<typename HashResultType>
		requires std::same_as<HashResultType, std::string> || std::same_as<HashResultType, std::span<std::uint8_t>> 
		void ComputeMixBlakeHash
		(
			std::span<std::uint8_t> DataRanges,
			std::size_t HashBitSize,
			HashResultType& HashedResultData
		)
		{
			if( DataRanges.empty() )
				return;

			if(HashBitSize == 0)
				return;

			std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools> MainHasherPointer = std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools>();

			auto& MainHasherObject = *(MainHasherPointer.get());

			std::vector<std::uint8_t> HashedDataRanges(HashBitSize / 8, static_cast<std::uint8_t>(0x00));
			MainHasherObject.GenerateBlake2Hashed(DataRanges, HashedDataRanges, true, HashedDataRanges.size() * 8);

			std::vector<std::uint8_t> HashedDataRanges2(HashBitSize / 8, static_cast<std::uint8_t>(0x00));
			MainHasherObject.GenerateBlake3ModificationHashed(HashedDataRanges, HashedDataRanges2, HashedDataRanges2.size() * 8);

			std::ranges::transform
			(
				HashedDataRanges.begin(),
				HashedDataRanges.end(),
				HashedDataRanges2.begin(),
				HashedDataRanges2.end(),
				HashedDataRanges.begin(),
				[](std::uint8_t left, std::uint8_t right) -> std::uint8_t
				{
					return left ^ right;
				}
			);

			HashedDataRanges2.clear();
			HashedDataRanges2.shrink_to_fit();

			if constexpr(std::same_as<HashResultType, std::span<std::uint8_t>>)
			{
				HashedResultData = HashedDataRanges;
			}
			else
			{
				HashedResultData = UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString( HashedDataRanges );

				HashedDataRanges.clear();
				HashedDataRanges.shrink_to_fit();
			}
		}
	}

	namespace SubstitutionBox
	{
		/*
			In Euclidean geometry, an affine transformation, or an affinity (from the Latin, affinis, "connected with"),
			is a geometric transformation that preserves lines and parallelism (but not necessarily distances and angles).
			More generally, an affine transformation is an automorphism of an affine space (Euclidean spaces are specific affine spaces),
			that is, a function which maps an affine space onto itself while preserving both the dimension of any affine subspaces
			(meaning that it sends points to points, lines to lines, planes to planes, and so on) and the ratios of the lengths of parallel line segments.
			Consequently, sets of parallel affine subspaces remain parallel after an affine transformation.
			An affine transformation does not necessarily preserve angles between lines or distances between points,
			though it does preserve ratios of distances between points lying on a straight line.
			X is the point set of an affine space, then every affine transformation on X can be represented as the composition of a linear transformation on X and a translation of X.
			Unlike a purely linear transformation, an affine transformation need not preserve the origin of the affine space.
			Thus, every linear transformation is affine, but not every affine transformation is linear.
			Examples of affine transformations include translation, scaling, homothety, similarity, reflection, rotation, shear mapping, and compositions of them in any combination and sequence.
			Viewing an affine space as the complement of a hyperplane at infinity of a projective space,
			the affine transformations are the projective transformations of that projective space that leave the hyperplane at infinity invariant, restricted to the complement of that hyperplane.
			在欧几里得几何学中，仿射变换或仿生力（来自拉丁文affinis，"与之相连"）。
			是一种保留线和平行度的几何变换（但不一定是距离和角度）。
			更一般地说，仿射变换是仿射空间的一种自动变形（欧几里得空间是特定的仿射空间）。
			也就是说，一个将仿射空间映射到自身的函数，同时保留了任何仿射子空间的维度（意味着它将点对点，线对线，平面对平面，等等）和平行线段的长度比。
			因此，平行的仿射子空间的集合在仿生变换之后仍然是平行的。
			仿射变换不一定保留线与线之间的角度或点与点之间的距离。
			尽管它确实保留了位于直线上的各点之间的距离比。
			X是一个仿射空间的点集，那么X上的每个仿射变换都可以表示为X上的线性变换和X的平移的组合。
			与纯粹的线性变换不同，仿射变换不需要保留仿射空间的原点。
			因此，每个线性变换都是仿射的，但不是每个仿射变换都是线性的。
			仿射变换的例子包括平移、缩放、同构、相似、反射、旋转、剪切映射，以及它们在任何组合和序列中的组合。
			把一个仿射空间看作是投影空间无穷远处的超平面的补充。
			仿射变换是该投射空间的投射变换，这些变换使无限远处的超平面不变，并限制在该超平面的补体上。
			https://en.wikipedia.org/wiki/Affine_transformation
		*/
		std::uint8_t NybergSubstitutionBoxValueWithAffineTransformation(std::uint8_t ByteData, std::uint8_t MultiplicationNumber, std::uint8_t AdditionNumber)
		{
			auto lambda_ThisLeftRotateMove = [](const std::uint8_t& ByteData, const std::uint8_t& shift_count) -> std::uint8_t
			{
				return (ByteData << shift_count | ByteData >> (8 - shift_count));
			};

			for(std::size_t shift_count = 0x08; shift_count > 0x00; shift_count--)
			{
				if(MultiplicationNumber >> shift_count & 0x01)
				{
					AdditionNumber ^= lambda_ThisLeftRotateMove(ByteData, static_cast<std::uint8_t>(shift_count)) & 255;
				}
			}

			return AdditionNumber;
		}

		void PermutationSubstitutionBox(std::span<std::uint8_t> WorkingByteSubstitutionBox)
		{
			using namespace CustomSecurity::ByteSubstitutionBoxToolkit;

			my_cpp2020_assert(WorkingByteSubstitutionBox.size() == 256, "This is not a byte-SubstitutionBox, or this byte-SubstitutionBox is not a standard size!", std::source_location::current());

			/*
				A Portable C++ 11 Program Code From:
				Anomalies and Vector Space Search: Tools for S-Box Analysis (Full Version)
				How “Structured” is a Random S-box:
				https://eprint.iacr.org/2019/528.pdf

				GJB Search Implementation and TU-decomposition.zip
				https://who.rocq.inria.fr/Leo.Perrin/code/tu_code.zip
			*/
			auto lambda_special_multiplication = [](std::uint8_t byte_data) -> std::uint8_t
			{
				return ( byte_data & 8 ^ 42) * 6 ^ ( byte_data & 4 ^ 2 * ( byte_data ) & 6) * 9 ^ byte_data & 2;
			};

			auto lambda_permutation_byte = [&lambda_special_multiplication](std::uint8_t byte_data) -> std::uint8_t
			{
                std::array substitution_choose_array{ 1, 221, 146, 79, 147, 153, 11, 68, 214, 215, 78, 220, 152, 10, 69 };
				
				/*
				
					std::int32_t line_counter = 0, accumulator = 2;
					while ((byte_data) && (line_counter++, accumulator != byte_data )) 
					{ 
						accumulator = (accumulator << 1) ^ (accumulator >> 7) * 0x11d;
					}
				*/
				std::uint8_t accumulator = 2, line_counter = 0;
				while ( (byte_data) && (line_counter++, accumulator ^ byte_data) )
				{
					accumulator = 2 * accumulator ^ accumulator / 128 * 285;
				}
				return (line_counter % 17 ? lambda_special_multiplication(16 - line_counter % 17) ^ substitution_choose_array[line_counter / 17] : lambda_special_multiplication(16 - line_counter / 17) ) ^ 252;
			};

			std::ranges::transform
			(
				WorkingByteSubstitutionBox.rbegin(), 
				WorkingByteSubstitutionBox.rend(), 
				WorkingByteSubstitutionBox.rbegin(),
				[&lambda_permutation_byte](const std::uint8_t& byte) -> std::uint8_t
				{ 
					return lambda_permutation_byte(byte);
				}
			);
		}

		//A secure key dependent dynamic substitution method for symmetric cryptosystems
		//https://peerj.com/articles/cs-587/
		std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> GeneratorAlgorithm(const std::span<std::uint8_t> BytesKey)
		{
			my_cpp2020_assert(BytesKey.size() == 16, "Invalied key size!", std::source_location::current());

			auto lambda_NibbleSwap_HexadecimalString = [](const std::string& byte_hexadecimal) -> std::string
			{
				std::string result_string = "";
				std::size_t loop_counter = 0;
				std::size_t string_index = 0;
				do
				{
					std::string left_string = byte_hexadecimal.substr(string_index, 1);
					std::string right_string = byte_hexadecimal.substr(string_index + 1, 1);
					result_string.append(right_string + left_string);
					string_index += 2;
					++loop_counter;
				}
				while(loop_counter <= 7);

				return result_string;
			};

			auto lambda_ExclusiveOR_BinaryString = [](const std::string& left_string, const std::string& right_string, std::string& result_string) -> void
			{
				if(left_string.size() != right_string.size())
				{
					return;
				}

				for(std::size_t index = 0; index < left_string.size() && index < right_string.size(); ++index)
				{
					if(left_string[index] == right_string[index])
					{
						result_string.push_back('0');
					}
					else
					{
						result_string.push_back('1');
					}
				}
			};

			/*
				Step 1:
				16 characters of 128 bits input encryption key (K) are converted into binary form.
				Then after counting 1s from 128-bits binary sequence, the left circular shift operation is applied on binary key according to the total number of ones.
				The left circular shift permutation, has denoted with symbol “<<K128”. This permutation is dynamic which creates resistance against different attacks
			*/

			std::string ProcessKey_HexadecimalString = UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString(BytesKey);
			std::string ProcessKey_BitString = UtilTools::DataFormating::Hexadecimal_Binary::FromHexadecimal(ProcessKey_HexadecimalString, UtilTools::DataFormating::AlphabetFormat::UPPER_CASE);
			ProcessKey_HexadecimalString.clear();

			//Character size of each hexadecimal format string (index)
			std::size_t HexadecimalCharacterOffest = 0;

			std::size_t DataByteSubstitutionBoxIndex = 0;

			std::string LeftCircularShift_BinaryString = "";
			std::string LeftHalfPart_BinaryString = "";
			std::string RightHalfPart_BinaryString = "";

			std::vector<std::string> RandomByte_HexadecimalStrings(257, "");
			std::vector<std::string> DataByteSubstitutionBox_HexadecimalStrings(257, "");

			std::size_t AlgorithmLoopCounter = 0;

			do
			{
				//Count all one-bit of the binary bits
				std::size_t MoveBitCount = std::ranges::count(ProcessKey_BitString.begin(), ProcessKey_BitString.end(), '1');
				LeftCircularShift_BinaryString =  ProcessKey_BitString.substr(MoveBitCount, 128 - MoveBitCount) + ProcessKey_BitString.substr(0, MoveBitCount);

				/*
					Step 2:
					128-bits key is partitioned into left and right halves each having binary length of 64 bits.
				*/
				LeftHalfPart_BinaryString = LeftCircularShift_BinaryString.substr(0, 64);
				RightHalfPart_BinaryString = LeftCircularShift_BinaryString.substr(64, 64);

				/*
					Step 3:
					Both halves are denoted as LeftKey64, RightKey64 and XOR operation is applied on two halves of key.
					After performing XOR operation, the resultant 64-bits are stored at right side,
					however the previous right-half with 64-bits are swapped to left side to be considered as new left-half with 64 bits LeftKey64' = RightKey64
				*/
				std::string Temporary_BinaryString = RightHalfPart_BinaryString;
				std::string ExclusiveOR_BinaryString = "";
				lambda_ExclusiveOR_BinaryString(LeftHalfPart_BinaryString, RightHalfPart_BinaryString, ExclusiveOR_BinaryString);

				/*
					Step 4:
					Right side 64-bits are converted into 8-bytes in hexadecimal form as:
					hexadecimal(RightKey') = k1k2k3k4k5k6k7k8.
					Where k1k2k3k4k5k6k7k8 = x1y1x2y2x3y3x4y4x5y5x6y6x7y7x8y8
				*/

				std::string CurrentExclusiveOR_HexadecimalString = UtilTools::DataFormating::Hexadecimal_Binary::ToHexadecimal(ExclusiveOR_BinaryString, UtilTools::DataFormating::AlphabetFormat::UPPER_CASE);

				/*
					Step 5:
					After that, nibble swap is performed on each byte of right-half that is given as:
					x1y1x2y2x3y3x4y4x5y5x6y6x7y7x8y8 = y1x1y2x2y3x3y4x4y5x5y6x6y7x7y8x8
					Nibble swap helps to break patterns to create non-linear values of S-box. 
				*/

				std::string RandomBytesNibbleSwaped_HexadecimalString = lambda_NibbleSwap_HexadecimalString(CurrentExclusiveOR_HexadecimalString);

				/*
					Step 6:
					All the 8-bytes of right-half are stored in an array followed by a loop for placing these bytes into the Subsitiution-Box as:
					y1x1y2x2y3x3y4x4y5x5y6x6y7x7y8x8 = S1S2S3S4S5S6S7S8.
					After that, a conditional statement is used to ensure the uniqueness of S-box values to avoid any duplication.
					After storing hexadecimal values of right-half in S-box, the right half is reconverted into binary (64-bits) as: (RightKey) = y1x1y2x2y3x3y4x4y5x5y6x6y7x7y8x8.
					After that, both left and right halves rejoin here to make 128-bits binary sequence, and then control moves back to the step-1as: Key128 = RightKey + LeftKey.
					After that, all the operations are performed in previous order until the unique 256 values in hex form are stored in S-box.
					All the steps are controlled by the conditional statements under conditional loop which continue to run until the generation of dynamic S-box with 256 unique values.
				*/
				std::string RandomBytesNibbleSwaped_BinaryString = UtilTools::DataFormating::Hexadecimal_Binary::FromHexadecimal(RandomBytesNibbleSwaped_HexadecimalString, UtilTools::DataFormating::AlphabetFormat::UPPER_CASE);
				ProcessKey_BitString = Temporary_BinaryString + RandomBytesNibbleSwaped_BinaryString;

				std::size_t RandomBytesIndex = 0;
				do
				{
					RandomByte_HexadecimalStrings[RandomBytesIndex] = RandomBytesNibbleSwaped_HexadecimalString.substr(HexadecimalCharacterOffest, 2);

					HexadecimalCharacterOffest += 2;

					if(HexadecimalCharacterOffest == 16)
					{
						HexadecimalCharacterOffest = 0;
					}

					//How many byte comparisons were made previously?
					std::size_t ByteComparisonRound = 0;

					//SubstitutionBox byte(hexadecimal string) index for comparison rounds.
					std::size_t SubstitutionBoxIndex_ForComparisonRound = 0;
					for(SubstitutionBoxIndex_ForComparisonRound = 0; SubstitutionBoxIndex_ForComparisonRound <= DataByteSubstitutionBoxIndex; ++SubstitutionBoxIndex_ForComparisonRound)
					{
						++ByteComparisonRound;
						//Compare byte(hexadecimal string) is same
						if(RandomByte_HexadecimalStrings[RandomBytesIndex] == DataByteSubstitutionBox_HexadecimalStrings[SubstitutionBoxIndex_ForComparisonRound])
						{
							break;
						}
					}

					//Update SBox byte(hexadecimal string)
					if(ByteComparisonRound == SubstitutionBoxIndex_ForComparisonRound)
					{
						DataByteSubstitutionBox_HexadecimalStrings[SubstitutionBoxIndex_ForComparisonRound] = RandomByte_HexadecimalStrings[RandomBytesIndex];

						++DataByteSubstitutionBoxIndex;
						if(DataByteSubstitutionBoxIndex > 255)
						{
							break;
						}
					}
					++RandomBytesIndex;

				}
				while(RandomBytesIndex <= 7);
				++AlgorithmLoopCounter;

			} while(AlgorithmLoopCounter <= 300);

			/*
				Step 7:
				A new loop is used to generate inverse S-box.
				For this purpose, indexes and values of generated S-box are swapped with each other to create inverse S-box.
			*/

			RandomByte_HexadecimalStrings.clear();
			RandomByte_HexadecimalStrings.shrink_to_fit();

			std::string DataByteSubstitutionBox_Concatenated;

			for(const auto& Byte_HexadecimalString : DataByteSubstitutionBox_HexadecimalStrings)
			{
				DataByteSubstitutionBox_Concatenated.append(Byte_HexadecimalString);
			}

			DataByteSubstitutionBox_HexadecimalStrings.clear();
			DataByteSubstitutionBox_HexadecimalStrings.shrink_to_fit();

			std::vector<std::uint8_t> ByteDataSubstitutionBox = UtilTools::DataFormating::ASCII_Hexadecmial::hexadecimalString2ByteArray(DataByteSubstitutionBox_Concatenated);
			std::vector<std::uint8_t> InvertedByteDataSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);

			DataByteSubstitutionBox_Concatenated.clear();
			DataByteSubstitutionBox_Concatenated.shrink_to_fit();

			//std::size_t NL_Value = CustomSecurity::ByteSubstitutionBoxToolkit::HelperFunctions::SubstitutionBoxNonlinearityDegree(ByteDataSubstitutionBox, ByteDataSubstitutionBox.size() >> 5, ByteDataSubstitutionBox.size() >> 5);

			for(std::size_t SubstitutionBoxIndex = 0; SubstitutionBoxIndex < 256; ++SubstitutionBoxIndex)
			{
				std::uint8_t ValueOfSubstitutionBox = ByteDataSubstitutionBox[SubstitutionBoxIndex];
				InvertedByteDataSubstitutionBox[ValueOfSubstitutionBox] = SubstitutionBoxIndex;
			}

			return std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> { ByteDataSubstitutionBox, InvertedByteDataSubstitutionBox };
		}

		//A Simple and Efficient Key-Dependent S-Box Design Using Fisher-Yates Shuffle Technique And Chaos Map
		std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> GeneratorAlgorithm2(std::span<double> random_float_numbers)
		{
			std::vector<std::uint8_t> ByteDataSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(ByteDataSubstitutionBox.begin(), ByteDataSubstitutionBox.end(), 0, 1);
			std::vector<std::uint8_t> InvertedByteDataSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);

			for(std::size_t round_counter = 0; round_counter < random_float_numbers.size(); ++round_counter)
			{
				std::size_t index1 = 0;
				std::size_t index2 = 0;
				for(std::size_t element_counter = 1; element_counter < 256; ++element_counter)
				{
					auto random_float_number = random_float_numbers[round_counter];
					index1 = ByteDataSubstitutionBox.size() - element_counter;
					index2 = static_cast<std::size_t>( ::floor(random_float_number * static_cast<std::size_t>(10000000000)) ) % index1 + 1;
					std::swap(ByteDataSubstitutionBox[index1 - 1], ByteDataSubstitutionBox[index2 - 1]);
					
					if(round_counter < random_float_numbers.size())
					{
						++round_counter;
					}
					else
					{
						break;
					}
				}
			}

			for(std::size_t SubstitutionBoxIndex = 0; SubstitutionBoxIndex < 256; ++SubstitutionBoxIndex)
			{
				std::uint8_t ValueOfSubstitutionBox = ByteDataSubstitutionBox[SubstitutionBoxIndex];
				InvertedByteDataSubstitutionBox[ValueOfSubstitutionBox] = SubstitutionBoxIndex;
			}

			return std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> { ByteDataSubstitutionBox, InvertedByteDataSubstitutionBox };
		}
	}

	/*
		Rules for working with custom data obfuscators
		数据混淆器的工作规则
	*/
	enum class CustomDataObfuscatorWorkingRule : std::uint8_t
	{
		BIDIRECTIONALITY_THEN_UPDATE = 0,
		BIDIRECTIONALITY = 1,
		UNIDIRECTIONALITY_ENCODE = 2,
		UNIDIRECTIONALITY_DECODE = 3,
		UNIDIRECTIONALITY_ENCODE_THEN_UPDATE = 4,
		UNIDIRECTIONALITY_DECODE_THEN_UPDATE = 5,
		ONE_TIME_USE = 6
	};

	template<std::size_t Currrent_System_Bits_Size_Value>
	struct PseudoRandomNumberEngine;

	template<>
	struct PseudoRandomNumberEngine<32>
	{
		std::unique_ptr<CommonSecurity::RNG_ISAAC::isaac<8>> PRNG_Pointer = std::make_unique<CommonSecurity::RNG_ISAAC::isaac<8>>();
		std::unique_ptr<CommonSecurity::RNG_ISAAC::isaac<8>> PRNG_Pointer2 = std::make_unique<CommonSecurity::RNG_ISAAC::isaac<8>>();
	};

	template<>
	struct PseudoRandomNumberEngine<64>
	{
		std::unique_ptr<CommonSecurity::RNG_ISAAC::isaac64<8>> PRNG_Pointer = std::make_unique<CommonSecurity::RNG_ISAAC::isaac64<8>>();
		std::unique_ptr<CommonSecurity::RNG_ISAAC::isaac64<8>> PRNG_Pointer2 = std::make_unique<CommonSecurity::RNG_ISAAC::isaac64<8>>();
	};

	template<bool IsCompileTime>
	struct CustomDataObfuscatorResult;

	template<>
	struct CustomDataObfuscatorResult<true>
	{
		std::array<std::uint8_t, 256> ByteSubstitutionBoxForEncoding = CommonToolkit::make_array<std::uint8_t, 256>();
		std::array<std::uint8_t, 256> ByteSubstitutionBoxForDecoding = CommonToolkit::make_array<std::uint8_t, 256>();
		std::string HashOfTheByteSubstitutionBoxForEncoding;
		std::string HashOfTheByteSubstitutionBoxForDecoding;

		CustomDataObfuscatorResult() = default;
		~CustomDataObfuscatorResult() = default;
	};

	template<>
	struct CustomDataObfuscatorResult<false>
	{
		std::vector<std::uint8_t> ByteSubstitutionBoxForEncoding;
		std::vector<std::uint8_t> ByteSubstitutionBoxForDecoding;
		std::string HashOfTheByteSubstitutionBoxForEncoding;
		std::string HashOfTheByteSubstitutionBoxForDecoding;

		CustomDataObfuscatorResult()
			:
			ByteSubstitutionBoxForEncoding(256, 0x00), ByteSubstitutionBoxForDecoding(256, 0x00)
		{
			
		}
		~CustomDataObfuscatorResult() = default;
	};

	//Reference code from: https://github.com/CharCoding/SBox-Analyzer
	//Website: https://charcoding.github.io/SBox-Analyzer/

	/*
		Unidirectionality/Bidirectionality data obfuscator
		单向性/双向性数据混淆器

		Description: Obfuscation of ordered data
		Used to generate unordered data as key parameters when calling symmetric encryption and decryption functions (passcoders) that need to provide key parameters but only have the data.

		Warning: The data generated by this obfuscator should not be used directly as a key for symmetric encryption functions, but as an aid to cryptographically approved general security techniques
		For example: other key derivation functions or additional implementation details of key derivation functions to use

		说明：对有序数据进行混淆处理
		用于调用对称加密解密函数（密码器）时，需要提供密钥参数但是只有拥有数据的情况，进行生成无序数据来作为密钥参数

		警告：对于该混淆器生成的数据，不应该直接作为对称加密函数的密钥，应该作为密码学认可的通用的安全技术的辅助工具
		比如：其他密钥派生函数或者密钥派生函数额外实现细节去使用
	*/
	template<bool IsCompileTime>
	class CustomDataObfuscator;

	//IsCompileTime = true

	template<>
	class CustomDataObfuscator<true> : public PseudoRandomNumberEngine<CURRENT_SYSTEM_BITS>
	{

	private:

		/*
			1. Affine Transformation:
			x' = (x × MultiplicationNumber0(Byte Hexadecimal Format) mod 0x0101) ⊕ AdditionNumber0(Byte Hexadecimal Format)

			2. Galois Field Inversion:
			Using Galois field value(Binary 8bit format) <-> GF(std::pow(2, 8)):
				Example value:
					Bad: 
					257 <-> 000100000001 <-> 0x0101

					Good:
					283 <-> 000100011011 <-> 0x011B
					285 <-> 000100011101 <-> 0x011D
					299 <-> 000100101011 <-> 0x012B
					301 <-> 000100101101 <-> 0x012D
					313 <-> 000100111001 <-> 0x0139
					319 <-> 000100111111 <-> 0x013F
					333 <-> 000101001101 <-> 0x014D
					351 <-> 000101011111 <-> 0x015F
					355 <-> 000101100011 <-> 0x0163
					357 <-> 000101100101 <-> 0x0165
					361 <-> 000101101001 <-> 0x0169
					369 <-> 000101110001 <-> 0x0171
					375 <-> 000101110111 <-> 0x0177
					379 <-> 000101111011 <-> 0x017B
					391 <-> 000110000111 <-> 0x0187
					395 <-> 000110001011 <-> 0x018B
					397 <-> 000110001101 <-> 0x018D
					415 <-> 000110011111 <-> 0x019F
					419 <-> 000110100011 <-> 0x01A3
					425 <-> 000110101001 <-> 0x01A9
					433 <-> 000110110001 <-> 0x01B1
					445 <-> 000110111101 <-> 0x01BD
					451 <-> 000111000011 <-> 0x01C3
					463 <-> 000111001111 <-> 0x01CF
					471 <-> 000111010111 <-> 0x01D7
					477 <-> 000111011101 <-> 0x01DD
					487 <-> 000111100111 <-> 0x01E7
					499 <-> 000111110011 <-> 0x01F3
					501 <-> 000111110101 <-> 0x01F5
					505 <-> 000111111001 <-> 0x01F9


			x'' = x'-1      if x' ≠ 0
				  0         if x' = 0

			3.Affine Transformation:
			x''' = (x'' × MultiplicationNumber1(Byte Hexadecimal Format) mod 0x0101) ⊕ AdditionNumber1(Byte Hexadecimal Format)

		*/
		struct AffineTransformationParameters
		{
			//About this definition of inline class members with C++ 2017 standard
			//https://stackoverflow.com/questions/12855649/how-can-i-initialize-a-static-const-vector-that-is-a-class-member-in-c11
			//Galois Field (2^8) Irreducible Primitive Polynomial Values
			static constexpr std::array<std::uint32_t, 31> GaloisFieldValues
			{ 
					//Bad Value
					0x0101,

					//Good Values
					0x011B, 0x011D, 0x012B, 0x012D, 0x0139, 0x013F,
					0x014D, 0x015F, 0x0163, 0x0165, 0x0169, 0x0171,
					0x0177, 0x017B, 0x0187, 0x018B, 0x018D, 0x019F,
					0x01A3, 0x01A9, 0x01B1, 0x01BD, 0x01C3, 0x01CF,
					0x01D7, 0x01DD, 0x01E7, 0x01F3, 0x01F5, 0x01F9
			};

			std::uint32_t GaloisFieldValue = 0;

			std::uint8_t MultiplicationNumber = 0;
			std::uint8_t MultiplicationNumber2 = 0;
			std::uint8_t AdditionNumber = 0;
			std::uint8_t AdditionNumber2 = 0;

			const bool Unlimit_GF_257;

			AffineTransformationParameters
			(
				bool UnlimitValue_GF_257 = false
			)
				: Unlimit_GF_257(UnlimitValue_GF_257)
			{
				
			}
		};

		AffineTransformationParameters ThisAffineTransformationParameters;

		static constexpr std::array<std::array<std::uint8_t, 16>, 16> OrderedByteBox
		{
			{
				{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
				{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
				{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F },
				{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F },
				{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F },
				{ 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F },
				{ 0x60, 0x61, 0x62, 0x03, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F },
				{ 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F },
				{ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F },
				{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F },
				{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF },
				{ 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF },
				{ 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF },
				{ 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF },
				{ 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF },
				{ 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF },
			}
		};

		std::array<std::array<std::uint8_t, 16>, 16> WorkingByteSubstitutionBox2D { OrderedByteBox };

		std::array<std::uint8_t, 256> WorkedByteSubstitutionBox;
		std::array<std::uint8_t, 256> WorkedInvertedByteSubstitutionBox;

		std::uint32_t X_RandomNumberGeneratorSeed = 0, Y_RandomNumberGeneratorSeed = 0;

		void Array1DTransform2D(std::array<std::uint8_t, 256>& Array1D, std::array<std::array<std::uint8_t, 16>, 16>& Array2D)
		{
			/*for( std::size_t row_index = 0; row_index < Array2D.size(); ++row_index )
			{
				auto& ByteSubstitutionBoxData = Array2D[row_index];
				for( std::size_t column_index = 0; column_index < ByteSubstitutionBoxData.size(); ++column_index )
				{
					 ByteSubstitutionBoxData[ column_index ] = Array1D[ row_index * ByteSubstitutionBoxData.size() + column_index  ];
				}
			}*/

			CommonToolkit::ProcessingDataBlock::splitter(Array1D, Array2D, 16, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Copy);
		}

		void Array2DTransform1D(std::array<std::array<std::uint8_t, 16>, 16>& Array2D, std::array<std::uint8_t, 256>& Array1D)
		{
			/*for( std::size_t row_index = 0; row_index < Array2D.size(); ++row_index )
			{
				auto& ByteSubstitutionBoxData = Array2D[row_index];
				for( std::size_t column_index = 0; column_index < ByteSubstitutionBoxData.size(); ++column_index )
				{
					Array1D[ row_index * ByteSubstitutionBoxData.size() + column_index  ] = ByteSubstitutionBoxData[ column_index ];
				}
			}*/

			CommonToolkit::ProcessingDataBlock::merger(Array2D, Array1D, CommonToolkit::ProcessingDataBlock::Merger::WorkMode::Copy);
		}

		void ShuffleByteSubstitutionBox(std::array<std::uint8_t, 256>& ByteSubstitutionBox)
		{
			auto& RandomNumberGenerator = *(PRNG_Pointer.get());
			auto& RandomNumberGenerator2 = *(PRNG_Pointer2.get());

			CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> random_number_distribution(0, ByteSubstitutionBox.size() - 1);

			// ranges random rotation to the left
			std::ranges::rotate(ByteSubstitutionBox.begin(), ByteSubstitutionBox.begin() + random_number_distribution(RandomNumberGenerator),ByteSubstitutionBox.end());

			CommonSecurity::ShuffleRangeData.KnuthShuffle(ByteSubstitutionBox.begin(), ByteSubstitutionBox.end(), RandomNumberGenerator);
			CommonSecurity::ShuffleRangeData.KnuthShuffle(ByteSubstitutionBox.begin(), ByteSubstitutionBox.end(), RandomNumberGenerator2);

			// ranges random rotation to the right
			std::ranges::rotate(ByteSubstitutionBox.rbegin(), ByteSubstitutionBox.rbegin() + random_number_distribution(RandomNumberGenerator2), ByteSubstitutionBox.rend());
		}

		#if 0

		void ShuffleByteSubstitutionBox(std::array<std::array<std::uint8_t, 16>, 16>& ByteSubstitutionBox2D)
		{
			//ShuffleRangeRows
			CommonSecurity::ShuffleRangeData(ByteSubstitutionBox2D.begin(), ByteSubstitutionBox2D.end(), RandomNumberGenerator);

			//ShuffleRangeColumns
			for( auto& Byte16Array : ByteSubstitutionBox2D )
			{
				RandomNumberGenerator.seed( X_RandomNumberGeneratorSeed ^ Y_RandomNumberGeneratorSeed );
				CommonSecurity::ShuffleRangeData(Byte16Array.begin(), Byte16Array.end(), RandomNumberGenerator);
				RandomNumberGenerator2.seed( ~( X_RandomNumberGeneratorSeed ^ Y_RandomNumberGeneratorSeed ) );
				CommonSecurity::ShuffleRangeData(Byte16Array.begin(), Byte16Array.end(), RandomNumberGenerator2);
				Y_RandomNumberGeneratorSeed ^= RandomNumberGenerator();
				X_RandomNumberGeneratorSeed ^= RandomNumberGenerator2();
			}

			//ShuffleRangeRows
			RandomNumberGenerator.seed( Y_RandomNumberGeneratorSeed );
			CommonSecurity::ShuffleRangeData(ByteSubstitutionBox2D.begin(), ByteSubstitutionBox2D.end(), RandomNumberGenerator2);
		}

		#endif

		void GenerateByteSubstitutionBox(std::array<std::uint8_t, 256>& WorkingByteSubstitutionBox)
		{
			using namespace SubstitutionBox;

			std::array<std::uint8_t, 256> Box = CommonToolkit::make_array<std::uint8_t, 256>();
			
			for(std::size_t index = 255; index >= 0; --index)
			{
				auto value_a = NybergSubstitutionBoxValueWithAffineTransformation
				(
					index,
					ThisAffineTransformationParameters.MultiplicationNumber,
					ThisAffineTransformationParameters.AdditionNumber
				);

				auto value_b = MathTools::InverseOfWithGaloisField
				(
					value_a,
					ThisAffineTransformationParameters.GaloisFieldValue
				);

				Box[index] = NybergSubstitutionBoxValueWithAffineTransformation
				(
					value_b,
					ThisAffineTransformationParameters.MultiplicationNumber2,
					ThisAffineTransformationParameters.AdditionNumber2
				);

				if(index == 0)
					break;
			}

			Box.swap(WorkingByteSubstitutionBox);
		}

		std::array<std::uint8_t, 256> GenerateAESBox()
		{
			using namespace SubstitutionBox;

			std::array<std::uint8_t, 256> AESBox = CommonToolkit::make_array<std::uint8_t, 256>();

			for(auto& ByteData : std::ranges::subrange( AESBox.rbegin(), AESBox.rend() ) )
			{
				ByteData = NybergSubstitutionBoxValueWithAffineTransformation( static_cast<std::uint8_t>( MathTools::InverseOfWithGaloisField(ByteData) ), 0x1F, 0x63);
			}

			return AESBox;
		}

		std::array<std::uint8_t, 256> GenerateInvertAESBox()
		{
			using namespace SubstitutionBox;

			std::array<std::uint8_t, 256> InvertAESBox = CommonToolkit::make_array<std::uint8_t, 256>();

			for(auto& ByteData : InvertAESBox)
			{
				ByteData = static_cast<std::uint8_t>( MathTools::InverseOfWithGaloisField( NybergSubstitutionBoxValueWithAffineTransformation(ByteData, 0x4A, 0x05) ) );
			}

			return InvertAESBox;
		}

		void BuildBox()
		{
			using namespace SubstitutionBox;
			using namespace CustomSecurity::ByteSubstitutionBoxToolkit;
			
			std::array<std::uint8_t, 256> WorkingByteSubstitutionBox = CommonToolkit::make_array<std::uint8_t, 256>();
			std::int32_t SubstitutionBox_NonlinearityDegree = 0;
			std::int32_t SubstitutionBox_TemporaryNonlinearityDegree = 0;
			
			//pow(2, 8) == 256
			//log(2, 256) == 8
			std::size_t LogarithmicNumberOfTwoBased = static_cast<std::size_t>(::log2(WorkingByteSubstitutionBox.size()));

			auto SubstitutionBox_NonlinearityDegree_ResultPair = HelperFunctions::SubstitutionBoxNonlinearityDegree(WorkingByteSubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
			SubstitutionBox_NonlinearityDegree = SubstitutionBox_NonlinearityDegree_ResultPair.first;

			while(true)
			{
				Array2DTransform1D(WorkingByteSubstitutionBox2D, WorkingByteSubstitutionBox);

				RebuildByteSubstitutionBoxFlag:

				PermutationSubstitutionBox(WorkingByteSubstitutionBox);

				Array1DTransform2D(WorkingByteSubstitutionBox, WorkingByteSubstitutionBox2D);

				if(std::ranges::equal(WorkingByteSubstitutionBox2D, OrderedByteBox))
				{
					goto RebuildByteSubstitutionBoxFlag;
				}

				SubstitutionBox_NonlinearityDegree_ResultPair = HelperFunctions::SubstitutionBoxNonlinearityDegree(WorkingByteSubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
				SubstitutionBox_TemporaryNonlinearityDegree = SubstitutionBox_NonlinearityDegree_ResultPair.first;

				SubstitutionBox_NonlinearityDegree = std::max(SubstitutionBox_NonlinearityDegree, SubstitutionBox_TemporaryNonlinearityDegree);

				/*
					Note: The strictest byte-substitution box nonlinearity should be between 100 and 120
					Because of my setting here, the limit is relaxed for slightly more results. But it may be unsafe
					注意：最严格的字节代换盒非线性程度应该是100至120之间
					因为我这里的设置，为了结果稍微多一点，所以放松了限制。但是可能会不安全
				*/
				if(SubstitutionBox_NonlinearityDegree > 95 && SubstitutionBox_NonlinearityDegree <= 120)
				{
					std::ranges::copy(WorkingByteSubstitutionBox.begin(), WorkingByteSubstitutionBox.end(), WorkedByteSubstitutionBox.begin());

					break;
				}
				else
				{
					//Do not delete this line of code!!!
					//不要删除这行代码！
					ShuffleThisAffineTransformationParameters();

					GenerateByteSubstitutionBox(WorkingByteSubstitutionBox);
				}

				PermutationSubstitutionBox(WorkingByteSubstitutionBox);

				Array1DTransform2D(WorkingByteSubstitutionBox, WorkingByteSubstitutionBox2D);;
			}
		}

		void BuildInvertBox()
		{
			if( WorkedByteSubstitutionBox == std::array<std::uint8_t, 256>() )
				return;

			while(true)
			{
				//Build invert byte substitution box by building completed byte substitution box
				//通过建立已完成的字节替换盒来建立反转的字节替换盒
				for(std::size_t index = 0; index < 256; ++index)
				{
					std::uint8_t value = WorkedByteSubstitutionBox[index];
					WorkedInvertedByteSubstitutionBox[value] = index;
				}

				std::array<std::array<std::uint8_t, 16>, 16> WorkedByteSubstitutionBox2D = OrderedByteBox;
				Array1DTransform2D(WorkedByteSubstitutionBox, WorkedByteSubstitutionBox2D);

				std::array<std::array<std::uint8_t, 16>, 16> WorkedInvertedByteSubstitutionBox2D = OrderedByteBox;
				Array1DTransform2D(WorkedInvertedByteSubstitutionBox, WorkedInvertedByteSubstitutionBox2D);

				std::size_t ErrorDataCounter = 0;

				//Test building completed substitution box and invert byte substitution box
				//测试建立完成的替换盒和反转字节替换盒
				for(std::size_t index = 0; index < 256; ++index)
				{
					auto Encoded = WorkedByteSubstitutionBox2D[index / 16][index % 16];
					auto Decoded = WorkedInvertedByteSubstitutionBox2D[Encoded / 16][Encoded % 16];

					if(static_cast<std::uint8_t>(index) != Decoded)
					{
						//Build Failure
						++ErrorDataCounter;
					}
				}

				if(ErrorDataCounter == 0)
				{
					//Build Success
					break;
				}
				else
				{
					std::array<std::uint8_t, 256> OrderedByteBox1D = std::array<std::uint8_t, 256>();
					CommonToolkit::numbers_sequence_generator<true>(OrderedByteBox1D.begin(), OrderedByteBox1D.end(), 0, 1);

					//Rebuild byte substitution box
					//重建字节替换盒

					WorkedByteSubstitutionBox = OrderedByteBox1D;
					this->ShuffleByteSubstitutionBox(WorkedByteSubstitutionBox);
					WorkedInvertedByteSubstitutionBox = OrderedByteBox1D;
					this->BuildBox();
				}
			}
		}

		bool CheckThisAffineTransformationParameters()
		{
			if(!MathTools::CheckParityBits(ThisAffineTransformationParameters.MultiplicationNumber))
			{
				//std::string ErrorMessage = "First affine transformation multiplier " + std::to_string(ThisAffineTransformationParameters.MultiplicationNumber) + " cannot be divisible by x + 1.";
				return false;
				//my_cpp2020_assert(false, ErrorMessage.c_str(), std::source_location::current());
			}

			if(!MathTools::CheckParityBits(ThisAffineTransformationParameters.MultiplicationNumber2))
			{
				//std::string ErrorMessage2 = "Second affine transformation multiplier " + std::to_string(ThisAffineTransformationParameters.MultiplicationNumber2) + " cannot be divisible by x + 1.";
				return false;
				//my_cpp2020_assert(false, ErrorMessage2.c_str(), std::source_location::current());
			}

			return true;
		}

		void ShuffleThisAffineTransformationParameters()
		{
			auto& RandomNumberGenerator = *(PRNG_Pointer.get());
			auto& RandomNumberGenerator2 = *(PRNG_Pointer2.get());

			CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> random_number_distribution( ThisAffineTransformationParameters.Unlimit_GF_257 ? 0 : 1, 30);
			CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> random_number_distribution2(0, 255);

			// Check if the new parameters of the affine transformation are valid
			// If it is valid, skip this Do-While loop
			// Otherwise invalid, update the parameters of the current affine transformation randomly again.
			// 检查仿生变换的新参数是否有效
			// 如果有效，则跳过这个Do-While循环
			// 否则无效，则重新随机更新当前仿生变换的参数。
			do
			{
				auto random_number_a = random_number_distribution2(RandomNumberGenerator);
				auto random_number_b = random_number_distribution2(RandomNumberGenerator);
				auto random_number_c = random_number_distribution2(RandomNumberGenerator2);
				auto random_number_d = random_number_distribution2(RandomNumberGenerator2);

				ThisAffineTransformationParameters.MultiplicationNumber = random_number_a ^= ( 1 << (random_number_c & 7));
				ThisAffineTransformationParameters.MultiplicationNumber2 = random_number_b ^= ( 1 << (random_number_d & 7));

				// Multipliers number must have an odd number of set bits
				// 乘法器必须有奇数的设置位
				// Random_Number(0~255) -> MathTools::CheckParityBits() -> static_cast<int>() -> Exclusive_OR 1 -> Exclusive_OR Random_Number
				ThisAffineTransformationParameters.MultiplicationNumber ^= static_cast<int>( MathTools::CheckParityBits(ThisAffineTransformationParameters.MultiplicationNumber) ) ^ 1;
				ThisAffineTransformationParameters.MultiplicationNumber2 ^= static_cast<int>( MathTools::CheckParityBits(ThisAffineTransformationParameters.MultiplicationNumber2) ) ^ 1;

				ThisAffineTransformationParameters.AdditionNumber = random_number_c;
				ThisAffineTransformationParameters.AdditionNumber2 = random_number_d;
				
			} while (!CheckThisAffineTransformationParameters());

			std::uint32_t random_number = random_number_distribution(RandomNumberGenerator);
			std::uint32_t random_number2 = random_number_distribution(RandomNumberGenerator2);

			if( ( (random_number & 1) == 0) && ( (random_number2 & 1) == 0) )
			{
				ThisAffineTransformationParameters.GaloisFieldValue = AffineTransformationParameters::GaloisFieldValues[random_number];
			}
			if( ( (random_number & 1) == 0) && ( (random_number2 & 1) != 0) )
			{
				ThisAffineTransformationParameters.GaloisFieldValue = AffineTransformationParameters::GaloisFieldValues[random_number];
			}
			if( ( (random_number & 1) != 0) && ( (random_number2 & 1) == 0) )
			{
				ThisAffineTransformationParameters.GaloisFieldValue = AffineTransformationParameters::GaloisFieldValues[random_number2];
			}
			if( ( (random_number & 1) != 0) && ( (random_number2 & 1) != 0) )
			{
				ThisAffineTransformationParameters.GaloisFieldValue = AffineTransformationParameters::GaloisFieldValues[random_number2];
			}
		}

		bool CheckEncodingAndDecodingTable
		(
			std::array<std::uint8_t, 256>& OrderedByteBox1D,
			std::array<std::uint8_t, 256>& WorkedByteSubstitutionBox,
			std::array<std::uint8_t, 256>& WorkedInvertedByteSubstitutionBox
		)
		{
			if( WorkedByteSubstitutionBox != std::array<std::uint8_t, 256>() && WorkedInvertedByteSubstitutionBox != std::array<std::uint8_t, 256>() )
			{
				if(WorkedByteSubstitutionBox == OrderedByteBox1D && WorkedInvertedByteSubstitutionBox == OrderedByteBox1D)
				{
					return false;
				}
				else
				{
					return true;
				}
			}
			else
			{
				return false;
			}
		}

		void EncoderOrDecoder
		(
			std::span<std::uint8_t> ProvidedData,
			CustomDataObfuscatorResult<true>& CDO_ResultObject,
			bool IsEncodeOrDecodeMode
		)
		{
			std::array<std::array<std::uint8_t, 16>, 16> WorkedByteSubstitutionBox2D = OrderedByteBox;
			Array1DTransform2D(CDO_ResultObject.ByteSubstitutionBoxForEncoding, WorkedByteSubstitutionBox2D);

			std::array<std::array<std::uint8_t, 16>, 16> WorkedInvertedByteSubstitutionBox2D = OrderedByteBox;
			Array1DTransform2D(CDO_ResultObject.ByteSubstitutionBoxForDecoding, WorkedInvertedByteSubstitutionBox2D);

			auto lambda_EncodeTransfrom = [](const std::array<std::array<std::uint8_t, 16>, 16>& WorkedByteSubstitutionBox2D, const std::uint8_t& ByteData) -> std::uint8_t 
			{ 
				return WorkedByteSubstitutionBox2D[ByteData / 16][ByteData % 16];
			};

			auto lambda_DecodeTransfrom = [](const std::array<std::array<std::uint8_t, 16>, 16>& WorkedInvertedByteSubstitutionBox2D, const std::uint8_t& ByteData) -> std::uint8_t 
			{ 
				return WorkedInvertedByteSubstitutionBox2D[ByteData / 16][ByteData % 16];
			};

			if(IsEncodeOrDecodeMode)
			{
				for
				(
					auto first_position = ProvidedData.begin(), last_position = ProvidedData.end();
					first_position != last_position;
					first_position++
				)
				{
					*first_position = lambda_EncodeTransfrom(WorkedByteSubstitutionBox2D, *first_position);
				}
			}
			else
			{
				for
				(
					auto last_position = ProvidedData.rbegin(), first_position = ProvidedData.rend();
					last_position != first_position;
					last_position++
				)
				{
					*last_position = lambda_DecodeTransfrom(WorkedInvertedByteSubstitutionBox2D, *last_position);
				}
			}
		}

	public:
		void UpdateSubstitutionBox(bool SubstitutionBoxOnly)
		{
			std::array<std::uint8_t, 256> OrderedByteBox1D = std::array<std::uint8_t, 256>();
			CommonToolkit::numbers_sequence_generator<true>(OrderedByteBox1D.begin(), OrderedByteBox1D.end(), 0, 1);

			std::array<std::uint8_t, 256> WorkingByteSubstitutionBox = std::array<std::uint8_t, 256>();
			WorkedByteSubstitutionBox.swap(WorkingByteSubstitutionBox);

			//Directly update the old parameters of the affine transformation
			//直接更新仿生变换的旧参数
			ShuffleThisAffineTransformationParameters();

			//Whether to update only the byte-substitute box for encoding?
			//If yes, update the byte-substitution box for encoding
			//Otherwise, update the byte-substitution box for encoding and the byte-substitution box for decoding
			//是否只更新编码用的字节代换盒？
			//如果是，更新编码用的字节代换盒
			//否则，则更新编码用的字节代换盒以及更新解码用的字节代换盒
			if(SubstitutionBoxOnly)
			{
				while(WorkingByteSubstitutionBox == WorkedByteSubstitutionBox || WorkingByteSubstitutionBox == OrderedByteBox1D)
				{
					BuildBox();
				}
			}
			else
			{
				while(WorkingByteSubstitutionBox == WorkedByteSubstitutionBox || WorkingByteSubstitutionBox == OrderedByteBox1D)
				{
					BuildBox();
				}

				BuildInvertBox();
			}
		}

		CustomDataObfuscatorResult<true> ExportEncodingAndDecodingTable(CustomDataObfuscatorWorkingRule WorkingRule)
		{
			CustomDataObfuscatorResult<true> CDO_ResultObject;

			std::array<std::uint8_t, 256> OrderedByteBox1D = std::array<std::uint8_t, 256>();
			CommonToolkit::numbers_sequence_generator<true>(OrderedByteBox1D.begin(), OrderedByteBox1D.end(), 0, 1);

			bool IsValidDataTable = CheckEncodingAndDecodingTable(OrderedByteBox1D, this->WorkedByteSubstitutionBox, this->WorkedInvertedByteSubstitutionBox);

			if(!IsValidDataTable)
			{
				BuildBox();
				BuildInvertBox();
			}

			//导出生成编码/解码表
			//Export generated completed encoding/decoding table
			switch (WorkingRule)
			{
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY_THEN_UPDATE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					this->WorkedByteSubstitutionBox = OrderedByteBox1D;
					this->WorkedInvertedByteSubstitutionBox = OrderedByteBox1D;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_ENCODE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = OrderedByteBox1D;
					this->WorkedByteSubstitutionBox = OrderedByteBox1D;
					this->WorkedInvertedByteSubstitutionBox = OrderedByteBox1D;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_DECODE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = OrderedByteBox1D;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					this->WorkedByteSubstitutionBox = OrderedByteBox1D;
					this->WorkedInvertedByteSubstitutionBox = OrderedByteBox1D;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_ENCODE_THEN_UPDATE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = OrderedByteBox1D;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_DECODE_THEN_UPDATE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = OrderedByteBox1D;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::ONE_TIME_USE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					this->WorkedByteSubstitutionBox = std::array<std::uint8_t, 256>();
					this->WorkedInvertedByteSubstitutionBox = std::array<std::uint8_t, 256>();
					break;
				}
				default:
					break;
			}

			//生成编码/解码表的Blake2 mix Blake3 HASH
			//Blake2 mix Blake3 HASH for generating encoding/decoding tables
			HashFunction::ComputeMixBlakeHash(CDO_ResultObject.ByteSubstitutionBoxForEncoding, 1024, CDO_ResultObject.HashOfTheByteSubstitutionBoxForEncoding);
			HashFunction::ComputeMixBlakeHash(CDO_ResultObject.ByteSubstitutionBoxForDecoding, 1024, CDO_ResultObject.HashOfTheByteSubstitutionBoxForDecoding);

			return CDO_ResultObject;
		}

		bool ImportAndEncodeOrDecode
		(
			std::span<std::uint8_t> ProvidedData,
			CustomDataObfuscatorResult<true>& CDO_ResultObject,
			CustomDataObfuscatorWorkingRule WorkingRule,
			bool IsEncodeOrDecodeMode
		)
		{
			bool IsChangedData = false;

			//验证之前生成完成的编码/解码表的Blake2 mix Blake3 HASH
			//Verify the Blake2 mix Blake3 HASH of the previously generated completed encoding/decoding table
			{
				bool IsSameHashString = false;
				std::string HashedString = "";

				CDO_ResultObject.HashOfTheByteSubstitutionBoxForEncoding.shrink_to_fit();
				CDO_ResultObject.HashOfTheByteSubstitutionBoxForDecoding.shrink_to_fit();

				HashFunction::ComputeMixBlakeHash(CDO_ResultObject.ByteSubstitutionBoxForEncoding, 1024, HashedString);

				HashedString.shrink_to_fit();
				
				IsSameHashString = HashedString == CDO_ResultObject.HashOfTheByteSubstitutionBoxForEncoding;
				if(!IsSameHashString)
					return IsChangedData;
				else
					HashedString.clear();

				HashFunction::ComputeMixBlakeHash(CDO_ResultObject.ByteSubstitutionBoxForDecoding, 1024, HashedString);

				HashedString.shrink_to_fit();

				IsSameHashString = HashedString == CDO_ResultObject.HashOfTheByteSubstitutionBoxForDecoding;
				if(!IsSameHashString)
					return IsChangedData;
				else
					HashedString.clear();

				HashedString.shrink_to_fit();
			}

			//导入生成的编码/解码表
			//Import generated completed encoding/decoding table

			std::array<std::uint8_t, 256> OrderedByteBox1D = std::array<std::uint8_t, 256>();
			CommonToolkit::numbers_sequence_generator<true>(OrderedByteBox1D.begin(), OrderedByteBox1D.end(), 0, 1);

			bool IsValidDataTable = CheckEncodingAndDecodingTable(OrderedByteBox1D, CDO_ResultObject.ByteSubstitutionBoxForEncoding, CDO_ResultObject.ByteSubstitutionBoxForDecoding);

			switch (WorkingRule)
			{
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY_THEN_UPDATE:
				{
					if(IsValidDataTable)
					{
						this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, IsEncodeOrDecodeMode);
						this->UpdateSubstitutionBox(true);
						IsChangedData = true;
					}
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY:
				{
					if(IsValidDataTable)
					{
						this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, IsEncodeOrDecodeMode);
						IsChangedData = true;
					}
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_ENCODE:
				{
					if(IsValidDataTable)
					{
						if(CDO_ResultObject.ByteSubstitutionBoxForEncoding == OrderedByteBox1D)
							IsChangedData = false;
						else
							this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, true);
					}
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_DECODE:
				{
					if(IsValidDataTable)
					{
						if(CDO_ResultObject.ByteSubstitutionBoxForDecoding == OrderedByteBox1D)
							IsChangedData = false;
						else
							this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, false);
					}
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_ENCODE_THEN_UPDATE:
				{
					if(IsValidDataTable)
					{
						if(CDO_ResultObject.ByteSubstitutionBoxForEncoding == OrderedByteBox1D)
							IsChangedData = false;
						else
						{
							this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, true);
							this->UpdateSubstitutionBox(true);
						}
					}
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_DECODE_THEN_UPDATE:
				{
					if(IsValidDataTable)
					{
						if(CDO_ResultObject.ByteSubstitutionBoxForDecoding == OrderedByteBox1D)
							IsChangedData = false;
						else
						{
							this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, false);
							this->UpdateSubstitutionBox(false);
							this->WorkedByteSubstitutionBox = OrderedByteBox1D;
						}
					}
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::ONE_TIME_USE:
				{
					if(IsValidDataTable)
					{
						this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, IsEncodeOrDecodeMode);
						CDO_ResultObject.ByteSubstitutionBoxForEncoding.fill(0x00);
						CDO_ResultObject.ByteSubstitutionBoxForDecoding.fill(0x00);
					}
					else
						IsChangedData = false;
				}
				default:
					break;
			}

			return IsChangedData;
		}

		CustomDataObfuscator
		(
			bool UnlimitValue_GF_257 = false
		)
			: ThisAffineTransformationParameters(UnlimitValue_GF_257)
		{
			auto& RandomNumberGenerator = *(PRNG_Pointer.get());
			auto& RandomNumberGenerator2 = *(PRNG_Pointer2.get());

			std::random_device random_device_object;

			RandomNumberGenerator.seed( random_device_object );
			RandomNumberGenerator2.seed( random_device_object );

			ShuffleThisAffineTransformationParameters();

			BuildBox();
		}

		CustomDataObfuscator
		(
			std::size_t X_Seed,
			std::size_t Y_Seed,
			bool UnlimitValue_GF_257 = false
		)
			: ThisAffineTransformationParameters(UnlimitValue_GF_257)
		{
			auto& RandomNumberGenerator = *(PRNG_Pointer.get());
			auto& RandomNumberGenerator2 = *(PRNG_Pointer2.get());

			RandomNumberGenerator.seed( X_Seed );
			RandomNumberGenerator2.seed( Y_Seed );

			ShuffleThisAffineTransformationParameters();

			BuildBox();
		}

		~CustomDataObfuscator()
		{
			PRNG_Pointer.reset();
			PRNG_Pointer2.reset();
		}
	};

	

	//IsCompileTime = false

	template<>
	class CustomDataObfuscator<false> : public PseudoRandomNumberEngine<CURRENT_SYSTEM_BITS>
	{

	private:

		/*
			1. Affine Transformation:
			x' = (x × MultiplicationNumber0(Byte Hexadecimal Format) mod 0x0101) ⊕ AdditionNumber0(Byte Hexadecimal Format)

			2. Galois Field Inversion:
			Using Galois field value(Binary 8bit format) <-> GF(std::pow(2, 8)):
				Example value:
					Bad: 
					257 <-> 000100000001 <-> 0x0101

					Good:
					283 <-> 000100011011 <-> 0x011B
					285 <-> 000100011101 <-> 0x011D
					299 <-> 000100101011 <-> 0x012B
					301 <-> 000100101101 <-> 0x012D
					313 <-> 000100111001 <-> 0x0139
					319 <-> 000100111111 <-> 0x013F
					333 <-> 000101001101 <-> 0x014D
					351 <-> 000101011111 <-> 0x015F
					355 <-> 000101100011 <-> 0x0163
					357 <-> 000101100101 <-> 0x0165
					361 <-> 000101101001 <-> 0x0169
					369 <-> 000101110001 <-> 0x0171
					375 <-> 000101110111 <-> 0x0177
					379 <-> 000101111011 <-> 0x017B
					391 <-> 000110000111 <-> 0x0187
					395 <-> 000110001011 <-> 0x018B
					397 <-> 000110001101 <-> 0x018D
					415 <-> 000110011111 <-> 0x019F
					419 <-> 000110100011 <-> 0x01A3
					425 <-> 000110101001 <-> 0x01A9
					433 <-> 000110110001 <-> 0x01B1
					445 <-> 000110111101 <-> 0x01BD
					451 <-> 000111000011 <-> 0x01C3
					463 <-> 000111001111 <-> 0x01CF
					471 <-> 000111010111 <-> 0x01D7
					477 <-> 000111011101 <-> 0x01DD
					487 <-> 000111100111 <-> 0x01E7
					499 <-> 000111110011 <-> 0x01F3
					501 <-> 000111110101 <-> 0x01F5
					505 <-> 000111111001 <-> 0x01F9


			x'' = x'-1      if x' ≠ 0
				  0         if x' = 0

			3.Affine Transformation:
			x''' = (x'' × MultiplicationNumber1(Byte Hexadecimal Format) mod 0x0101) ⊕ AdditionNumber1(Byte Hexadecimal Format)

		*/
		struct AffineTransformationParameters
		{
			//About this definition of inline class members with C++ 2017 standard
			//https://stackoverflow.com/questions/12855649/how-can-i-initialize-a-static-const-vector-that-is-a-class-member-in-c11
			//Galois Field (2^8) Irreducible Primitive Polynomial Values
			static const inline std::vector<std::uint32_t> GaloisFieldValues
			{ 
					//Bad Value
					0x0101,

					//Good Values
					0x011B, 0x011D, 0x012B, 0x012D, 0x0139, 0x013F,
					0x014D, 0x015F, 0x0163, 0x0165, 0x0169, 0x0171,
					0x0177, 0x017B, 0x0187, 0x018B, 0x018D, 0x019F,
					0x01A3, 0x01A9, 0x01B1, 0x01BD, 0x01C3, 0x01CF,
					0x01D7, 0x01DD, 0x01E7, 0x01F3, 0x01F5, 0x01F9
			};

			std::uint32_t GaloisFieldValue = 0;

			std::uint8_t MultiplicationNumber = 0;
			std::uint8_t MultiplicationNumber2 = 0;
			std::uint8_t AdditionNumber = 0;
			std::uint8_t AdditionNumber2 = 0;

			const bool Unlimit_GF_257;

			AffineTransformationParameters
			(
				bool UnlimitValue_GF_257 = false
			)
				: Unlimit_GF_257(UnlimitValue_GF_257)
			{
				
			}
		};

		AffineTransformationParameters ThisAffineTransformationParameters;

		static const inline std::vector<std::vector<std::uint8_t>> OrderedByteBox
		{
			{
				{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
				{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
				{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F },
				{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F },
				{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F },
				{ 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F },
				{ 0x60, 0x61, 0x62, 0x03, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F },
				{ 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F },
				{ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F },
				{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F },
				{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF },
				{ 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF },
				{ 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF },
				{ 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF },
				{ 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF },
				{ 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF },
			}
		};

		std::vector<std::vector<std::uint8_t>> WorkingByteSubstitutionBox2D { OrderedByteBox };

		std::vector<std::uint8_t> WorkedByteSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);
		std::vector<std::uint8_t> WorkedInvertedByteSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);

		std::uint32_t X_RandomNumberGeneratorSeed = 0, Y_RandomNumberGeneratorSeed = 0;

		/*template<bool UseSplitter>
		void Array1DTransform2D(const std::array<std::uint8_t, 256>& Array1D, std::array<std::array<std::uint8_t, 16>, 16>& Array2D)
		{
			if constexpr(!UseSplitter)
			{
				for( std::size_t row_index = 0; row_index < Array2D.size(); ++row_index )
				{
					auto& ByteSubstitutionBoxData = Array2D[row_index];
					for( std::size_t column_index = 0; column_index < ByteSubstitutionBoxData.size(); ++column_index )
					{
						 ByteSubstitutionBoxData[ column_index ] = Array1D[ row_index * ByteSubstitutionBoxData.size() + column_index  ];
					}
				}
			}
			else
			{
				CommonToolkit::ProcessingDataBlock::splitter(Array1D, Array2D, 16, CommonToolkit::ProcessingDataBlock::Splitter::WorkMode::Copy);
			}
		}

		template<bool UseMerger>
		void Array2DTransform1D(const std::array<std::array<std::uint8_t, 16>, 16>& Array2D, std::array<std::uint8_t, 256>& Array1D)
		{
			if constexpr(!UseMerger)
			{
				for( std::size_t row_index = 0; row_index < Array2D.size(); ++row_index )
				{
					auto& ByteSubstitutionBoxData = Array2D[row_index];
					for( std::size_t column_index = 0; column_index < ByteSubstitutionBoxData.size(); ++column_index )
					{
						Array1D[ row_index * ByteSubstitutionBoxData.size() + column_index  ] = ByteSubstitutionBoxData[ column_index ];
					}
				}
			}
			else
			{
				CommonToolkit::ProcessingDataBlock::merger(Array2D, Array1D, CommonToolkit::ProcessingDataBlock::Merger::WorkMode::Copy);
			}
		}*/

		void Array1DTransform2D(const std::vector<std::uint8_t>& Array1D, std::vector<std::vector<std::uint8_t>>& Array2D)
		{
			for( std::size_t row_index = 0; row_index < Array2D.size(); ++row_index )
			{
				auto& ByteSubstitutionBoxData = Array2D[row_index];
				for( std::size_t column_index = 0; column_index < ByteSubstitutionBoxData.size(); ++column_index )
				{
					ByteSubstitutionBoxData[ column_index ] = Array1D[ row_index * ByteSubstitutionBoxData.size() + column_index  ];
				}
			}
		}

		void Array2DTransform1D(const std::vector<std::vector<std::uint8_t>>& Array2D, std::vector<std::uint8_t>& Array1D)
		{
			for( std::size_t row_index = 0; row_index < Array2D.size(); ++row_index )
			{
				auto& ByteSubstitutionBoxData = Array2D[row_index];
				for( std::size_t column_index = 0; column_index < ByteSubstitutionBoxData.size(); ++column_index )
				{
					Array1D[ row_index * ByteSubstitutionBoxData.size() + column_index  ] = ByteSubstitutionBoxData[ column_index ];
				}
			}
		}

		void ShuffleByteSubstitutionBox(std::vector<std::uint8_t>& ByteSubstitutionBox)
		{
			auto& RandomNumberGenerator = *(PRNG_Pointer.get());
			auto& RandomNumberGenerator2 = *(PRNG_Pointer2.get());

			CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> random_number_distribution(0, ByteSubstitutionBox.size() - 1);

			// ranges random rotation to the left
			std::ranges::rotate(ByteSubstitutionBox.begin(), ByteSubstitutionBox.begin() + random_number_distribution(RandomNumberGenerator),ByteSubstitutionBox.end());

			CommonSecurity::ShuffleRangeData.KnuthShuffle(ByteSubstitutionBox.begin(), ByteSubstitutionBox.end(), RandomNumberGenerator);
			CommonSecurity::ShuffleRangeData.KnuthShuffle(ByteSubstitutionBox.begin(), ByteSubstitutionBox.end(), RandomNumberGenerator2);

			// ranges random rotation to the right
			std::ranges::rotate(ByteSubstitutionBox.rbegin(), ByteSubstitutionBox.rbegin() + random_number_distribution(RandomNumberGenerator2), ByteSubstitutionBox.rend());
		}

		#if 0

		void ShuffleByteSubstitutionBox(std::vector<std::vector<std::uint8_t>>& ByteSubstitutionBox2D)
		{
			//ShuffleRangeRows
			CommonSecurity::ShuffleRangeData(ByteSubstitutionBox2D.begin(), ByteSubstitutionBox2D.end(), RandomNumberGenerator);

			//ShuffleRangeColumns
			for( auto& Byte16Array : ByteSubstitutionBox2D )
			{
				RandomNumberGenerator.seed( X_RandomNumberGeneratorSeed ^ Y_RandomNumberGeneratorSeed );
				CommonSecurity::ShuffleRangeData(Byte16Array.begin(), Byte16Array.end(), RandomNumberGenerator);
				RandomNumberGenerator2.seed( ~( X_RandomNumberGeneratorSeed ^ Y_RandomNumberGeneratorSeed ) );
				CommonSecurity::ShuffleRangeData(Byte16Array.begin(), Byte16Array.end(), RandomNumberGenerator2);
				Y_RandomNumberGeneratorSeed ^= RandomNumberGenerator();
				X_RandomNumberGeneratorSeed ^= RandomNumberGenerator2();
			}

			//ShuffleRangeRows
			RandomNumberGenerator.seed( Y_RandomNumberGeneratorSeed );
			CommonSecurity::ShuffleRangeData(ByteSubstitutionBox2D.begin(), ByteSubstitutionBox2D.end(), RandomNumberGenerator2);
		}

		#endif

		void GenerateByteSubstitutionBox(std::vector<std::uint8_t>& WorkingByteSubstitutionBox)
		{
			using SubstitutionBox::NybergSubstitutionBoxValueWithAffineTransformation;

			std::vector<std::uint8_t> Box = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(Box.begin(), Box.end(), 0, 1);
			
			for(std::size_t index = 255; index >= 0; --index)
			{
				auto value_a = NybergSubstitutionBoxValueWithAffineTransformation
				(
					index,
					ThisAffineTransformationParameters.MultiplicationNumber,
					ThisAffineTransformationParameters.AdditionNumber
				);

				auto value_b = MathTools::InverseOfWithGaloisField
				(
					value_a,
					ThisAffineTransformationParameters.GaloisFieldValue
				);

				Box[index] = NybergSubstitutionBoxValueWithAffineTransformation
				(
					value_b,
					ThisAffineTransformationParameters.MultiplicationNumber2,
					ThisAffineTransformationParameters.AdditionNumber2
				);

				if(index == 0)
					break;
			}

			Box.swap(WorkingByteSubstitutionBox);
		}

		std::vector<std::uint8_t> GenerateAESBox()
		{
			using SubstitutionBox::NybergSubstitutionBoxValueWithAffineTransformation;

			std::vector<std::uint8_t> AESBox = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(AESBox.begin(), AESBox.end(), 0, 1);

			for(auto& ByteData : std::ranges::subrange( AESBox.rbegin(), AESBox.rend() ) )
			{
				ByteData = NybergSubstitutionBoxValueWithAffineTransformation( static_cast<std::uint8_t>( MathTools::InverseOfWithGaloisField(ByteData) ), 0x1F, 0x63);
			}

			return AESBox;
		}

		std::vector<std::uint8_t> GenerateInvertAESBox()
		{
			using SubstitutionBox::NybergSubstitutionBoxValueWithAffineTransformation;

			std::vector<std::uint8_t> InvertAESBox = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(InvertAESBox.begin(), InvertAESBox.end(), 0, 1);

			for(auto& ByteData : InvertAESBox)
			{
				ByteData = static_cast<std::uint8_t>( MathTools::InverseOfWithGaloisField( NybergSubstitutionBoxValueWithAffineTransformation(ByteData, 0x4A, 0x05) ) );
			}

			return InvertAESBox;
		}

		void BuildBox()
		{
			using SubstitutionBox::PermutationSubstitutionBox;
			using CustomSecurity::ByteSubstitutionBoxToolkit::HelperFunctions::SubstitutionBoxNonlinearityDegree;
			
			std::vector<std::uint8_t> WorkingByteSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(WorkingByteSubstitutionBox.begin(), WorkingByteSubstitutionBox.end(), 0, 1);

			std::int32_t SubstitutionBox_NonlinearityDegree = 0;
			std::int32_t SubstitutionBox_TemporaryNonlinearityDegree = 0;

			//pow(2, 8) == 256
			//log(2, 256) == 8
			std::size_t LogarithmicNumberOfTwoBased = static_cast<std::size_t>(::log2(WorkingByteSubstitutionBox.size()));

			auto SubstitutionBox_NonlinearityDegree_ResultPair = SubstitutionBoxNonlinearityDegree(WorkingByteSubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
			SubstitutionBox_NonlinearityDegree = SubstitutionBox_NonlinearityDegree_ResultPair.first;

			while(true)
			{
				Array2DTransform1D(WorkingByteSubstitutionBox2D, WorkingByteSubstitutionBox);

				RebuildByteSubstitutionBoxFlag:

				PermutationSubstitutionBox(WorkingByteSubstitutionBox);

				Array1DTransform2D(WorkingByteSubstitutionBox, WorkingByteSubstitutionBox2D);

				if(std::ranges::equal(WorkingByteSubstitutionBox2D, OrderedByteBox))
				{
					goto RebuildByteSubstitutionBoxFlag;
				}

				SubstitutionBox_NonlinearityDegree_ResultPair = SubstitutionBoxNonlinearityDegree(WorkingByteSubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased);
				SubstitutionBox_TemporaryNonlinearityDegree = SubstitutionBox_NonlinearityDegree_ResultPair.first;

				SubstitutionBox_NonlinearityDegree = std::max(SubstitutionBox_NonlinearityDegree, SubstitutionBox_TemporaryNonlinearityDegree);

				/*
					Note: The strictest byte-substitution box nonlinearity should be between 100 and 120
					Because of my setting here, the limit is relaxed for slightly more results. But it may be unsafe
					注意：最严格的字节代换盒非线性程度应该是100至120之间
					因为我这里的设置，为了结果稍微多一点，所以放松了限制。但是可能会不安全
				*/
				if(SubstitutionBox_NonlinearityDegree > 95 && SubstitutionBox_NonlinearityDegree <= 120)
				{
					std::ranges::copy(WorkingByteSubstitutionBox.begin(), WorkingByteSubstitutionBox.end(), WorkedByteSubstitutionBox.begin());

					break;
				}
				else
				{
					//Do not delete this line of code!!!
					//不要删除这行代码！
					ShuffleThisAffineTransformationParameters();

					GenerateByteSubstitutionBox(WorkingByteSubstitutionBox);
				}

				PermutationSubstitutionBox(WorkingByteSubstitutionBox);

				Array1DTransform2D(WorkingByteSubstitutionBox, WorkingByteSubstitutionBox2D);
			}
		}

		void BuildInvertBox()
		{
			if( WorkedByteSubstitutionBox == std::vector<std::uint8_t>(256, 0x00) )
				return;

			while(true)
			{
				//Build invert byte substitution box by building completed byte substitution box
				//通过建立已完成的字节替换盒来建立反转的字节替换盒
				for(std::size_t index = 0; index < 256; ++index)
				{
					std::uint8_t value = WorkedByteSubstitutionBox[index];
					WorkedInvertedByteSubstitutionBox[value] = index;
				}

				std::vector<std::vector<std::uint8_t>> WorkedByteSubstitutionBox2D = OrderedByteBox;
				Array1DTransform2D(WorkedByteSubstitutionBox, WorkedByteSubstitutionBox2D);

				std::vector<std::vector<std::uint8_t>> WorkedInvertedByteSubstitutionBox2D = OrderedByteBox;
				Array1DTransform2D(WorkedInvertedByteSubstitutionBox, WorkedInvertedByteSubstitutionBox2D);

				std::size_t ErrorDataCounter = 0;

				//Test building completed substitution box and invert byte substitution box
				//测试建立完成的替换盒和反转字节替换盒
				for(std::size_t index = 0; index < 256; ++index)
				{
					auto Encoded = WorkedByteSubstitutionBox2D[index / 16][index % 16];
					auto Decoded = WorkedInvertedByteSubstitutionBox2D[Encoded / 16][Encoded % 16];

					if(static_cast<std::uint8_t>(index) != Decoded)
					{
						//Build Failure
						++ErrorDataCounter;
					}
				}

				if(ErrorDataCounter == 0)
				{
					//Build Success
					break;
				}
				else
				{
					std::vector<std::uint8_t> OrderedByteBox1D = std::vector<std::uint8_t>(256, 0x00);
					CommonToolkit::numbers_sequence_generator<true>(OrderedByteBox1D.begin(), OrderedByteBox1D.end(), 0, 1);

					//Rebuild byte substitution box
					//重建字节替换盒

					WorkedByteSubstitutionBox = OrderedByteBox1D;
					this->ShuffleByteSubstitutionBox(WorkedByteSubstitutionBox);
					WorkedInvertedByteSubstitutionBox = OrderedByteBox1D;
					this->BuildBox();
				}
			}	
		}

		bool CheckThisAffineTransformationParameters()
		{
			if(!MathTools::CheckParityBits(ThisAffineTransformationParameters.MultiplicationNumber))
			{
				//std::string ErrorMessage = "First affine transformation multiplier " + std::to_string(ThisAffineTransformationParameters.MultiplicationNumber) + " cannot be divisible by x + 1.";
				return false;
				//my_cpp2020_assert(false, ErrorMessage.c_str(), std::source_location::current());
			}

			if(!MathTools::CheckParityBits(ThisAffineTransformationParameters.MultiplicationNumber2))
			{
				//std::string ErrorMessage2 = "Second affine transformation multiplier " + std::to_string(ThisAffineTransformationParameters.MultiplicationNumber2) + " cannot be divisible by x + 1.";
				return false;
				//my_cpp2020_assert(false, ErrorMessage2.c_str(), std::source_location::current());
			}

			return true;
		}

		void ShuffleThisAffineTransformationParameters()
		{
			auto& RandomNumberGenerator = *(PRNG_Pointer.get());
			auto& RandomNumberGenerator2 = *(PRNG_Pointer2.get());

			CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> random_number_distribution( ThisAffineTransformationParameters.Unlimit_GF_257 ? 0 : 1, 30);
			CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> random_number_distribution2(0, 255);

			// Check if the new parameters of the affine transformation are valid
			// If it is valid, skip this Do-While loop
			// Otherwise invalid, update the parameters of the current affine transformation randomly again.
			// 检查仿生变换的新参数是否有效
			// 如果有效，则跳过这个Do-While循环
			// 否则无效，则重新随机更新当前仿生变换的参数。
			do
			{
				auto random_number_a = random_number_distribution2(RandomNumberGenerator);
				auto random_number_b = random_number_distribution2(RandomNumberGenerator);
				auto random_number_c = random_number_distribution2(RandomNumberGenerator2);
				auto random_number_d = random_number_distribution2(RandomNumberGenerator2);

				ThisAffineTransformationParameters.MultiplicationNumber = random_number_a ^= ( 1 << (random_number_c & 7));
				ThisAffineTransformationParameters.MultiplicationNumber2 = random_number_b ^= ( 1 << (random_number_d & 7));

				// Multipliers number must have an odd number of set bits
				// 乘法器必须有奇数的设置位
				// Random_Number(0~255) -> MathTools::CheckParityBits() -> static_cast<int>() -> Exclusive_OR 1 -> Exclusive_OR Random_Number
				ThisAffineTransformationParameters.MultiplicationNumber ^= static_cast<int>( MathTools::CheckParityBits(ThisAffineTransformationParameters.MultiplicationNumber) ) ^ 1;
				ThisAffineTransformationParameters.MultiplicationNumber2 ^= static_cast<int>( MathTools::CheckParityBits(ThisAffineTransformationParameters.MultiplicationNumber2) ) ^ 1;

				ThisAffineTransformationParameters.AdditionNumber = random_number_c;
				ThisAffineTransformationParameters.AdditionNumber2 = random_number_d;
				
			} while (!CheckThisAffineTransformationParameters());

			std::uint32_t random_number = random_number_distribution(RandomNumberGenerator);
			std::uint32_t random_number2 = random_number_distribution(RandomNumberGenerator2);

			if( ( (random_number & 1) == 0) && ( (random_number2 & 1) == 0) )
			{
				ThisAffineTransformationParameters.GaloisFieldValue = AffineTransformationParameters::GaloisFieldValues[random_number];
			}
			if( ( (random_number & 1) == 0) && ( (random_number2 & 1) != 0) )
			{
				ThisAffineTransformationParameters.GaloisFieldValue = AffineTransformationParameters::GaloisFieldValues[random_number];
			}
			if( ( (random_number & 1) != 0) && ( (random_number2 & 1) == 0) )
			{
				ThisAffineTransformationParameters.GaloisFieldValue = AffineTransformationParameters::GaloisFieldValues[random_number2];
			}
			if( ( (random_number & 1) != 0) && ( (random_number2 & 1) != 0) )
			{
				ThisAffineTransformationParameters.GaloisFieldValue = AffineTransformationParameters::GaloisFieldValues[random_number2];
			}
		}

		bool CheckEncodingAndDecodingTable
		(
			std::vector<std::uint8_t>& OrderedByteBox1D,
			std::vector<std::uint8_t>& WorkedByteSubstitutionBox,
			std::vector<std::uint8_t>& WorkedInvertedByteSubstitutionBox
		)
		{
			if( WorkedByteSubstitutionBox != std::vector<std::uint8_t>(256, 0x00) && WorkedInvertedByteSubstitutionBox != std::vector<std::uint8_t>(256, 0x00) )
			{
				if(WorkedByteSubstitutionBox == OrderedByteBox1D && WorkedInvertedByteSubstitutionBox == OrderedByteBox1D)
				{
					return false;
				}
				else
				{
					return true;
				}
			}
			else
			{
				return false;
			}
		}

		void EncoderOrDecoder
		(
			std::span<std::uint8_t> ProvidedData,
			CustomDataObfuscatorResult<false>& CDO_ResultObject,
			bool IsEncodeOrDecodeMode
		)
		{
			std::vector<std::vector<std::uint8_t>> WorkedByteSubstitutionBox2D = OrderedByteBox;
			Array1DTransform2D(CDO_ResultObject.ByteSubstitutionBoxForEncoding, WorkedByteSubstitutionBox2D);

			std::vector<std::vector<std::uint8_t>> WorkedInvertedByteSubstitutionBox2D = OrderedByteBox;
			Array1DTransform2D(CDO_ResultObject.ByteSubstitutionBoxForDecoding, WorkedInvertedByteSubstitutionBox2D);

			auto lambda_EncodeTransfrom = [](const std::vector<std::vector<std::uint8_t>>& WorkedByteSubstitutionBox2D, const std::uint8_t& ByteData) -> std::uint8_t 
			{ 
				return WorkedByteSubstitutionBox2D[ByteData / 16][ByteData % 16];
			};

			auto lambda_DecodeTransfrom = [](const std::vector<std::vector<std::uint8_t>>& WorkedInvertedByteSubstitutionBox2D, const std::uint8_t& ByteData) -> std::uint8_t 
			{ 
				return WorkedInvertedByteSubstitutionBox2D[ByteData / 16][ByteData % 16];
			};

			if(IsEncodeOrDecodeMode)
			{
				for
				(
					auto first_position = ProvidedData.begin(), last_position = ProvidedData.end();
					first_position != last_position;
					first_position++
				)
				{
					*first_position = lambda_EncodeTransfrom(WorkedByteSubstitutionBox2D, *first_position);
				}
			}
			else
			{
				for
				(
					auto last_position = ProvidedData.rbegin(), first_position = ProvidedData.rend();
					last_position != first_position;
					last_position++
				)
				{
					*last_position = lambda_DecodeTransfrom(WorkedInvertedByteSubstitutionBox2D, *last_position);
				}
			}
		}

	public:
		void UpdateSubstitutionBox(bool SubstitutionBoxOnly)
		{
			std::vector<std::uint8_t> OrderedByteBox1D = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(OrderedByteBox1D.begin(), OrderedByteBox1D.end(), 0, 1);

			std::vector<std::uint8_t> WorkingByteSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);
			WorkedByteSubstitutionBox.swap(WorkingByteSubstitutionBox);

			//Directly update the old parameters of the affine transformation
			//直接更新仿生变换的旧参数
			ShuffleThisAffineTransformationParameters();

			//Whether to update only the byte-substitute box for encoding?
			//If yes, update the byte-substitution box for encoding
			//Otherwise, update the byte-substitution box for encoding and the byte-substitution box for decoding
			//是否只更新编码用的字节代换盒？
			//如果是，更新编码用的字节代换盒
			//否则，则更新编码用的字节代换盒以及更新解码用的字节代换盒
			if(SubstitutionBoxOnly)
			{
				while(WorkingByteSubstitutionBox == WorkedByteSubstitutionBox || WorkingByteSubstitutionBox == OrderedByteBox1D)
				{
					BuildBox();
				}
			}
			else
			{
				while(WorkingByteSubstitutionBox == WorkedByteSubstitutionBox || WorkingByteSubstitutionBox == OrderedByteBox1D)
				{
					BuildBox();
				}

				BuildInvertBox();
			}
		}

		CustomDataObfuscatorResult<false> ExportEncodingAndDecodingTable(CustomDataObfuscatorWorkingRule WorkingRule)
		{
			CustomDataObfuscatorResult<false> CDO_ResultObject;

			std::vector<std::uint8_t> OrderedByteBox1D = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(OrderedByteBox1D.begin(), OrderedByteBox1D.end(), 0, 1);

			bool IsValidDataTable = CheckEncodingAndDecodingTable(OrderedByteBox1D, this->WorkedByteSubstitutionBox, this->WorkedInvertedByteSubstitutionBox);

			if(!IsValidDataTable)
			{
				BuildBox();
				BuildInvertBox();
			}

			//导出生成编码/解码表
			//Export generated completed encoding/decoding table
			switch (WorkingRule)
			{
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY_THEN_UPDATE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					this->WorkedByteSubstitutionBox = OrderedByteBox1D;
					this->WorkedInvertedByteSubstitutionBox = OrderedByteBox1D;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_ENCODE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = OrderedByteBox1D;
					this->WorkedByteSubstitutionBox = OrderedByteBox1D;
					this->WorkedInvertedByteSubstitutionBox = OrderedByteBox1D;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_DECODE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = OrderedByteBox1D;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					this->WorkedByteSubstitutionBox = OrderedByteBox1D;
					this->WorkedInvertedByteSubstitutionBox = OrderedByteBox1D;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_ENCODE_THEN_UPDATE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = OrderedByteBox1D;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_DECODE_THEN_UPDATE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = OrderedByteBox1D;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::ONE_TIME_USE:
				{
					CDO_ResultObject.ByteSubstitutionBoxForEncoding = WorkedByteSubstitutionBox;
					CDO_ResultObject.ByteSubstitutionBoxForDecoding = WorkedInvertedByteSubstitutionBox;
					std::ranges::fill(WorkedByteSubstitutionBox, 0x00);
					std::ranges::fill(WorkedByteSubstitutionBox, 0x00);
					break;
				}
				default:
					break;
			}

			//生成编码/解码表的Blake2 mix Blake3 HASH
			//Blake2 mix Blake3 HASH for generating encoding/decoding tables
			HashFunction::ComputeMixBlakeHash(CDO_ResultObject.ByteSubstitutionBoxForEncoding, 1024, CDO_ResultObject.HashOfTheByteSubstitutionBoxForEncoding);
			HashFunction::ComputeMixBlakeHash(CDO_ResultObject.ByteSubstitutionBoxForDecoding, 1024, CDO_ResultObject.HashOfTheByteSubstitutionBoxForDecoding);

			return CDO_ResultObject;
		}

		bool ImportAndEncodeOrDecode
		(
			std::span<std::uint8_t> ProvidedData,
			CustomDataObfuscatorResult<false>& CDO_ResultObject,
			CustomDataObfuscatorWorkingRule WorkingRule,
			bool IsEncodeOrDecodeMode
		)
		{
			bool IsChangedData = false;

			//验证之前生成完成的编码/解码表的Blake2 mix Blake3 HASH
			//Verify the Blake2 mix Blake3 HASH of the previously generated completed encoding/decoding table
			{
				bool IsSameHashString = false;
				std::string HashedString = "";

				CDO_ResultObject.HashOfTheByteSubstitutionBoxForEncoding.shrink_to_fit();
				CDO_ResultObject.HashOfTheByteSubstitutionBoxForDecoding.shrink_to_fit();

				HashFunction::ComputeMixBlakeHash(CDO_ResultObject.ByteSubstitutionBoxForEncoding, 1024, HashedString);

				HashedString.shrink_to_fit();
				
				IsSameHashString = HashedString == CDO_ResultObject.HashOfTheByteSubstitutionBoxForEncoding;
				if(!IsSameHashString)
					return IsChangedData;
				else
					HashedString.clear();

				HashFunction::ComputeMixBlakeHash(CDO_ResultObject.ByteSubstitutionBoxForDecoding, 1024, HashedString);

				HashedString.shrink_to_fit();

				IsSameHashString = HashedString == CDO_ResultObject.HashOfTheByteSubstitutionBoxForDecoding;
				if(!IsSameHashString)
					return IsChangedData;
				else
					HashedString.clear();

				HashedString.shrink_to_fit();
			}

			//导入生成的编码/解码表
			//Import generated completed encoding/decoding table

			std::vector<std::uint8_t> OrderedByteBox1D = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(OrderedByteBox1D.begin(), OrderedByteBox1D.end(), 0, 1);

			bool IsValidDataTable = CheckEncodingAndDecodingTable(OrderedByteBox1D, CDO_ResultObject.ByteSubstitutionBoxForEncoding, CDO_ResultObject.ByteSubstitutionBoxForDecoding);

			switch (WorkingRule)
			{
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY_THEN_UPDATE:
				{
					if(IsValidDataTable)
					{
						this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, IsEncodeOrDecodeMode);
						this->UpdateSubstitutionBox(true);
						IsChangedData = true;
					}
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::BIDIRECTIONALITY:
				{
					if(IsValidDataTable)
					{
						this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, IsEncodeOrDecodeMode);
						IsChangedData = true;
					}
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_ENCODE:
				{
					if(IsValidDataTable)
					{
						if(CDO_ResultObject.ByteSubstitutionBoxForEncoding == OrderedByteBox1D)
							IsChangedData = false;
						else
						{
							this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, true);
							IsChangedData = true;
						}
					}
					break;
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_DECODE:
				{
					if(IsValidDataTable)
					{
						if(CDO_ResultObject.ByteSubstitutionBoxForDecoding == OrderedByteBox1D)
							IsChangedData = false;
						else
						{
							this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, false);
							IsChangedData = true;
						}
					}
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_ENCODE_THEN_UPDATE:
				{
					if(IsValidDataTable)
					{
						if(CDO_ResultObject.ByteSubstitutionBoxForEncoding == OrderedByteBox1D)
							IsChangedData = false;
						else
						{
							this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, true);
							this->UpdateSubstitutionBox(true);
							IsChangedData = true;
						}
					}
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::UNIDIRECTIONALITY_DECODE_THEN_UPDATE:
				{
					if(IsValidDataTable)
					{
						if(CDO_ResultObject.ByteSubstitutionBoxForDecoding == OrderedByteBox1D)
							IsChangedData = false;
						else
						{
							this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, false);
							this->UpdateSubstitutionBox(false);
							this->WorkedByteSubstitutionBox = OrderedByteBox1D;
							IsChangedData = true;
						}
					}
				}
				case CustomSecurity::DataObfuscator::CustomDataObfuscatorWorkingRule::ONE_TIME_USE:
				{
					if(IsValidDataTable)
					{
						this->EncoderOrDecoder(ProvidedData, CDO_ResultObject, IsEncodeOrDecodeMode);
						std::ranges::fill(CDO_ResultObject.ByteSubstitutionBoxForEncoding, 0x00);
						std::ranges::fill(CDO_ResultObject.ByteSubstitutionBoxForDecoding, 0x00);
						IsChangedData = true;
					}
					else
						IsChangedData = false;
				}
				default:
					break;
			}

			return IsChangedData;
		}

		CustomDataObfuscator
		(
			bool UnlimitValue_GF_257 = false
		)
			: ThisAffineTransformationParameters(UnlimitValue_GF_257)
		{
			auto& RandomNumberGenerator = *(PRNG_Pointer.get());
			auto& RandomNumberGenerator2 = *(PRNG_Pointer2.get());

			std::random_device random_device_object;

			RandomNumberGenerator.seed( random_device_object );
			RandomNumberGenerator2.seed( random_device_object );

			ShuffleThisAffineTransformationParameters();

			BuildBox();
		}

		CustomDataObfuscator
		(
			std::size_t X_Seed,
			std::size_t Y_Seed,
			bool UnlimitValue_GF_257 = false
		)
			: ThisAffineTransformationParameters(UnlimitValue_GF_257)
		{
			auto& RandomNumberGenerator = *(PRNG_Pointer.get());
			auto& RandomNumberGenerator2 = *(PRNG_Pointer2.get());

			RandomNumberGenerator.seed( X_Seed );
			RandomNumberGenerator2.seed( Y_Seed );

			ShuffleThisAffineTransformationParameters();

			BuildBox();
		}

		~CustomDataObfuscator()
		{
			PRNG_Pointer.reset();
			PRNG_Pointer2.reset();
		}
	};
}

//#define SUBSTITUTIONBOX_GENERATION_THEORY_EXPERIMENTAL

#ifdef SUBSTITUTIONBOX_GENERATION_THEORY_EXPERIMENTAL

namespace CustomSecurity::SubstitutionBoxGenerationTheoryExperimental
{
	//A Dynamic S-Box Construction and Application Scheme of ZUC Based on Chaotic System
	//一种基于混沌系统的ZUC动态S盒构造及应用方案
	//https://crad.ict.ac.cn/CN/10.7544/issn1000-1239.2020.20200466
	class SubstitutionBoxGeneratorTest
	{

	private:
		CommonSecurity::RNG_ISAAC::isaac64<8> PRNG;

		bool FloatingValueEqual( double left, double right )
		{
			auto is_greater = ( left - right ) > 0.00000000000000001;
			auto is_less = ( left - right ) < 0.00000000000000001;
			if ( is_greater && is_less )
				return true;
			else
				return false;
		}

		void Array1DTransform2D( const std::vector<std::uint8_t>& Array1D, std::vector<std::vector<std::uint8_t>>& Array2D )
		{
			for ( std::size_t row_index = 0; row_index < Array2D.size(); ++row_index )
			{
				auto& ByteSubstitutionBoxData = Array2D[ row_index ];
				for ( std::size_t column_index = 0; column_index < ByteSubstitutionBoxData.size(); ++column_index )
				{
					ByteSubstitutionBoxData[ column_index ] = Array1D[ row_index * ByteSubstitutionBoxData.size() + column_index ];
				}
			}
		}

		void Array2DTransform1D( const std::vector<std::vector<std::uint8_t>>& Array2D, std::vector<std::uint8_t>& Array1D )
		{
			for ( std::size_t row_index = 0; row_index < Array2D.size(); ++row_index )
			{
				auto& ByteSubstitutionBoxData = Array2D[ row_index ];
				for ( std::size_t column_index = 0; column_index < ByteSubstitutionBoxData.size(); ++column_index )
				{
					Array1D[ row_index * ByteSubstitutionBoxData.size() + column_index ] = ByteSubstitutionBoxData[ column_index ];
				}
			}
		}

		/*
			https://en.wikipedia.org/wiki/Tent_map
			Chaos Tent Map:

			When the variable x[n] ∈ (0,1), and q ∈ (0,1)
			The system is in a chaotic state
				
			In the Tent mapping, the system is short period when q = 0.5, so the value of q should be avoided to be 0.5.
			In addition, the initial value of x should also be avoided to be the same as the value of q in order to prevent the system from evolving into a long period system.
			By varying the value of the parameter q, not only the dynamic generation of S-boxes can be achieved, but also the chaotic effect can be enhanced.

			当变量x[n] ∈ (0,1) ,且q ∈(0,1)时
			系统处于混沌状态
				
			Tent映射中 q＝0.5 时,系统呈现短周期状态,因此q值应避免选择0.5
			此外,在应用时x也应避免选取和q值相同的初值,以防止系统演化为长周期系统．
			改变参数q的取值,不仅能够实现动态产生S盒,而且可以增强混乱效果
		*/
		double ChaosSystemTentMap( bool short_loop_state, bool long_loop_state, double input_x, double q = 0.4 )
		{
			//Tent 系统参数选取 q ＝ 0.4
			//System Parameters
			//系统参数

			double output_x = 0.0;

			if ( input_x < 0.0 )
				input_x = 0.0;
			else if ( input_x > 1.0 )
				input_x = 1.0;

			if ( short_loop_state == true && long_loop_state == false && !FloatingValueEqual( q, 0.5 ) )
			{
				q = 0.5;
			}
			else if ( short_loop_state == false && long_loop_state == false && FloatingValueEqual( q, 0.5 ) )
			{
				CommonSecurity::RNG_ISAAC::isaac64<8> prng;

				std::uniform_real_distribution<double> real_distribution( -0.49, 0.49 );

				double value = real_distribution( prng );

				while ( value == 0.0 )
				{
					value = real_distribution( prng );
					q += value;
				}
			}

			if ( short_loop_state == false && long_loop_state == true && !FloatingValueEqual( input_x, q ) )
			{
				input_x = q;
			}
			else if ( short_loop_state == false && long_loop_state == false && FloatingValueEqual( input_x, q ) )
			{
				CommonSecurity::RNG_ISAAC::isaac64<8> prng;

				std::uniform_real_distribution<double> real_distribution( 0.0, 1.0 );

				double value = real_distribution( prng );

				while ( input_x == q )
				{
					input_x = real_distribution( prng );
				}
			}

			/*
				Tent系统的映射方程
				Mapping equations for the Tent system

				if 0.0 ＜ x[n] ≤ q then x[n + 1] = x[n] / q
				if q ＜ x[n] ＜ 1.0 then x[n + 1] = (1 - x[n]) / (1 - q)
					 
				output_x is x[n + 1]
				input_x is x[n]
			*/

			if ( 0.0 < input_x && input_x <= q )
			{
				output_x = input_x / q;
			}
			else if ( q < input_x && input_x < 1.0 )
			{
				output_x = ( 1 - input_x ) / ( 1 - q );
			}

			return output_x;
		}

		/*
			https://en.wikipedia.org/wiki/H%C3%A9non_map
			Chaos Henon Map:

			When the system parameters 1.07 ≤ a ≤ 1.4, b = 0.3
			The system is in a chaotic state

			And when the variable x[n] ∈ (-1.5,1.5), y[n] ∈ (-0.4,0.4)
			The system has the maximum complexity

			当系统参数 1.07 ≤ a ≤ 1.4, 其中a和b是控制参数，当 a = 1.4 和 b = 0.3 时
			系统处于混沌状态

			并且当变量 x[n] ∈ (-1.5,1.5) 和 y[n] ∈ (-0.4,0.4) 时
			该系统复杂度最大
		*/
		std::vector<double> ChaosSystemHenonMap( const std::vector<double>& Array, const std::size_t RoundCount )
		{
			//where the values of x and y in the Henon mapping are kept the same each time, and both come from the sequence X
			//其中令Henon映射中每次x和y的值保持一致,且均来自于序列X
			//OutputArrayY[index] = InputArrayX[index];
			std::vector<double> InputBufferArrayX( Array.begin(), Array.end() );
			std::vector<double> OutputBufferArrayY( Array.begin(), Array.end() );

			/*
				Henon系统的映射方程
				x[n + 1] = 1 + y[n] - a * power(x[n], 2) 
				y[n + 1] = b * x[n]

				InputArray is x
				OutputArray is y
			*/

			for ( std::size_t ExecuteCounter = 1; ExecuteCounter <= RoundCount; ++ExecuteCounter )
			{
				//Chaotic Image Encryption Algorithm Based on Improved Henon Map
				//基于改进Henon映射的混沌图像 加密算法
				//DOI: 10.12677/CSA.2022.122043
				//https://image.hanspub.org/Html/17-1542420_48877.htm
				if constexpr ( true )
				{
					//System control parameters
					//系统控制参数 a∈R，b≠0
					constexpr double a = 1.42769853;
					constexpr double b = 0.31649287;

					//power(10, 8) = 100000000

					for ( std::size_t index = 0; index < Array.size() - 1; ++index )
					{
						//The inverse of the value produced by the traditional Henon map
						//传统的Henon映射产生的数值的倒数
						InputBufferArrayX[ index + 1 ] = 1.0 / ( 1.0 + OutputBufferArrayY[ index ] - a * std::pow( InputBufferArrayX[ index ], 2.0 ) );
						OutputBufferArrayY[ index + 1 ] = 1.0 / ( b * InputBufferArrayX[ index ] );

						//After the transformation, x1∈(-∞,0)∪(0,+∞), y1∈(-∞,0)∪(0,+∞)
						//Where the control parameters a ∈ R and b ≠ 0, and then using the formula
						//Correction of x, y to map the values to (0,1) to obtain the new x, y
						//转换之后， x1∈(−∞,0)∪(0,+∞)，y1∈(−∞,0)∪(0,+∞)
						//其中控制参数 a∈R，b≠0，再利用公式
						//对 x，y 进行修正，将数值映射到 (0,1)，得到新的 x，y
						InputBufferArrayX[ index + 1 ] = InputBufferArrayX[ index + 1 ] * 100000000.0 - std::floor( InputBufferArrayX[ index + 1 ] * 100000000.0 );
						OutputBufferArrayY[ index + 1 ] = OutputBufferArrayY[ index + 1 ] * 100000000.0 - std::floor( OutputBufferArrayY[ index + 1 ] * 100000000.0 );
					}
				}
				else
				{
					//System control parameters
					//系统控制参数
					constexpr double a = 1.4;
					constexpr double b = 0.3;

					for ( std::size_t index = 0; index < Array.size() - 1; ++index )
					{
						//The y-value of the next one has the x and y values of the previous one to be updated.
						//Where the value of x comes from the sequence X
						//下一个的y值，有上一个的x和y值进行更新
						//其中x的值来自于序列X
						InputBufferArrayX[ index + 1 ] = 1.0 + OutputBufferArrayY[ index ] - a * std::pow( InputBufferArrayX[ index ], 2.0 );

						//Take all the y values to form the sequence Y
						//取所有的y值构成序列Y
						OutputBufferArrayY[ index + 1 ] = b * InputBufferArrayX[ index ];
					}
				}
			}

			return OutputBufferArrayY;
		}

		void ReplacementDataWithArnoldAlgorithm( std::vector<unsigned char>& ByteArray1D )
		{
			constexpr std::size_t PageSize = 16;

			std::vector<std::vector<unsigned char>> ByteArray2D( PageSize, std::vector<unsigned char>( PageSize, 0x00 ) );
			this->Array1DTransform2D( ByteArray1D, ByteArray2D );

			/*
				Arnold (cat face) transform equation
				Hint:This should be based on the pseudo-Hadamard transform
				Arnold(猫脸)变换方程
				提示:这个应该是基于伪哈达玛德变换
				https://en.wikipedia.org/wiki/Pseudo-Hadamard_transform
				https://zh.wikipedia.org/zh-cn/%E5%81%BD%E9%98%BF%E9%81%94%E7%91%AA%E8%AE%8A%E6%8F%9B
				
				Forward:
				x′＝x[n] + y[n](mod PageSize)
				y′＝x[n] + 2 * y[n](mod PageSize)
				
				Backward:
				y = y'[n] - a'[n](mod PageSize)
				x = 2 * x'[n] - y'[n](mod PageSize)
				
			*/

			for ( std::size_t RowIndex = 0; RowIndex < ByteArray2D.size(); ++RowIndex )
			{
				for ( std::size_t ColumnIndex = 0; ColumnIndex < ByteArray2D[ RowIndex ].size(); ++ColumnIndex )
				{
					ByteArray2D[ ( RowIndex + ColumnIndex ) % ByteArray2D.size() ][ ( RowIndex * 2 + ColumnIndex ) % ByteArray2D.size() ] = ByteArray2D[ RowIndex ][ ColumnIndex ];
				}
			}

			this->Array2DTransform1D( ByteArray2D, ByteArray1D );
		}

		std::deque<std::vector<unsigned char>> SubstitutionBoxMatrix;

	public:
		bool ScreeningSubstitutionBox( std::span<unsigned char> SubstitutionBox )
		{
			using namespace CustomSecurity::ByteSubstitutionBoxToolkit;

			std::size_t LogarithmicNumberOfTwoBased = static_cast<std::size_t>( ::log2( SubstitutionBox.size() ) );

			//pow(2, 8) == 256
			//log(2, 256) == 8

			auto ByteDataSecurityTestData_TransparencyOrder = HelperFunctions::SubstitutionBoxTransparencyOrder( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );
			auto ByteDataSecurityTestData_SignalToNoiseRatio_DifferentialPowerAnalysis = HelperFunctions::SubstitutionBox_SNR_DPA( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );
			auto ByteDataSecurityTestData_Nonlinearity = HelperFunctions::SubstitutionBoxNonlinearityDegree( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );
			auto ByteDataSecurityTestData_PropagationCharacteristics_StrictAvalancheCriteria = HelperFunctions::SubstitutionBox_PC_SAC( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );
			auto ByteDataSecurityTestData_DeltaUniformity_Robustness = HelperFunctions::SubstitutionBox_DeltaUniformity_Robustness( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );
			auto ByteDataSecurityTestData_AbsoluteValueIndicator = HelperFunctions::SubstitutionBoxAbsoluteValueIndicator( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );
			auto ByteDataSecurityTestData_SumOfSquareValueIndicator = HelperFunctions::SubstitutionBoxSumOfSquareValueIndicator( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );
			auto ByteDataSecurityTestData_AlgebraicDegree = HelperFunctions::SubstitutionBoxAlgebraicDegree( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );
			auto ByteDataSecurityTestData_AlgebraicImmunityDegree = HelperFunctions::SubstitutionBoxAlgebraicImmunityDegree( SubstitutionBox, LogarithmicNumberOfTwoBased, LogarithmicNumberOfTwoBased );

			std::cout << "ByteDataSecurityTestData Transparency Order Is: " << ByteDataSecurityTestData_TransparencyOrder << std::endl;
			std::cout << "ByteDataSecurityTestData Nonlinearity Is: " << ByteDataSecurityTestData_Nonlinearity.first << std::endl;
			std::cout << "ByteDataSecurityTestData Propagation Characteristics Is: " << ByteDataSecurityTestData_PropagationCharacteristics_StrictAvalancheCriteria.first << std::endl;
			std::cout << "ByteDataSecurityTestData Delta Uniformity Is: " << ByteDataSecurityTestData_DeltaUniformity_Robustness.first << std::endl;
			std::cout << "ByteDataSecurityTestData Robustness Is: " << ByteDataSecurityTestData_DeltaUniformity_Robustness.second << std::endl;
			std::cout << "ByteDataSecurityTestData Signal To Noise Ratio/Differential Power Analysis Is: " << ByteDataSecurityTestData_SignalToNoiseRatio_DifferentialPowerAnalysis << std::endl;
			std::cout << "ByteDataSecurityTestData Absolute Value Indicatorer Is: " << ByteDataSecurityTestData_AbsoluteValueIndicator.first << std::endl;
			std::cout << "ByteDataSecurityTestData Sum Of Square Value Indicator Is: " << ByteDataSecurityTestData_SumOfSquareValueIndicator.first << std::endl;
			std::cout << "ByteDataSecurityTestData Algebraic Degree Is: " << ByteDataSecurityTestData_AlgebraicDegree.first << std::endl;
			std::cout << "ByteDataSecurityTestData Algebraic Immunity Degree Is: " << ByteDataSecurityTestData_AlgebraicImmunityDegree.first << std::endl;

			std::cout << std::endl;

			if ( ByteDataSecurityTestData_Nonlinearity.first >= 96 && ByteDataSecurityTestData_Nonlinearity.first <= 120 )
			{
				return true;
			}
			return false;
		}

		void GeneratorAlgorithm( std::vector<unsigned char>& Bytes, const std::size_t ArraySize, double Seed )
		{
		#define MODIFIED_HENON_MAP_ALGORITHM

			//当迭代次数n＝5838,N＝5000,初始值x[0]＝0.3时,获得的混沌系统生成的S盒密码性能较为良好
			std::size_t RoundCount = 5000;

		#if !defined( MODIFIED_HENON_MAP_ALGORITHM )

			//Inverse of ArraySize
			double InverseArraySize = 1.0 / static_cast<double>( ArraySize );

		#endif

			std::uniform_real_distribution<double> RealDistributionNumberRanges( 0.00000001, 0.99999999 );

			std::vector<double> TentMappedArray( ArraySize, Seed );

		#if !defined( MODIFIED_HENON_MAP_ALGORITHM )

			std::vector<double> TentMappedArrayPoint( ArraySize, 0.0 );

		#endif

			TentMappedArray[ 0 ] = this->ChaosSystemTentMap( false, false, Seed );

			for ( std::size_t ExecuteCounter = 0; ExecuteCounter <= RoundCount; ++ExecuteCounter )
			{
				for ( std::size_t index = 1; index < TentMappedArray.size() - 1; ++index )
				{
					TentMappedArray[ index ] = this->ChaosSystemTentMap( false, false, TentMappedArray[ index - 1 ] );

				#if !defined( MODIFIED_HENON_MAP_ALGORITHM )

					TentMappedArrayPoint[ index ] = TentMappedArray[ index ] * InverseArraySize + ( index - 1 ) * InverseArraySize;

				#endif
				}
			}

		#if !defined( MODIFIED_HENON_MAP_ALGORITHM )

			std::vector<double> HenonMappedArrayPoint = this->ChaosSystemHenonMap( TentMappedArrayPoint, RoundCount );

			if ( !std::isnan( HenonMappedArrayPoint[ 0 ] ) && !std::isnan( HenonMappedArrayPoint[ HenonMappedArrayPoint.size() - 1 ] ) )
			{
				for ( std::size_t BytesIndex = 0; BytesIndex < Bytes.size(); ++BytesIndex )
				{
					Bytes[ BytesIndex ] = static_cast<unsigned char>( static_cast<std::size_t>( HenonMappedArrayPoint[ BytesIndex ] * 10000000000.0 ) % 256 );
					++BytesIndex;
				}
			}

			TentMappedArrayPoint.clear();
			TentMappedArrayPoint.shrink_to_fit();

			HenonMappedArrayPoint.clear();
			HenonMappedArrayPoint.shrink_to_fit();

		#else

			std::vector<double> HenonMappedArray = this->ChaosSystemHenonMap( TentMappedArray, RoundCount );

			if ( !std::isnan( HenonMappedArray[ 0 ] ) && !std::isnan( HenonMappedArray[ HenonMappedArray.size() - 1 ] ) )
			{
				for ( std::size_t BytesIndex = 0; BytesIndex < Bytes.size(); ++BytesIndex )
				{
					Bytes[ BytesIndex ] = static_cast<unsigned char>( static_cast<std::size_t>( HenonMappedArray[ BytesIndex ] * static_cast<std::size_t>( 10000000000.0 ) ) % 256 );
					;
				}
			}

			TentMappedArray.clear();
			TentMappedArray.shrink_to_fit();

			HenonMappedArray.clear();
			HenonMappedArray.shrink_to_fit();

		#endif

			/*
			auto[ABox, BBox] = CustomSecurity::DataObfuscator::SubstitutionBox::GeneratorAlgorithm2(HenonMappedArray);

			this->ScreeningSubstitutionBox(ABox);
			this->ScreeningSubstitutionBox(BBox);
			*/

		#if defined( MODIFIED_HENON_MAP_ALGORITHM )
			#undef MODIFIED_HENON_MAP_ALGORITHM
		#endif
		}

		void ApplyGeneratorAlgorithm()
		{
			std::size_t ArraySize = 5838;  //10485760 //5838

			std::vector<unsigned char> Bytes( ArraySize, 0x00 );

			std::unordered_set<unsigned char> UniqueElementBytes;

			std::uniform_real_distribution<double> real_distribution_number_ranges( 0.00000001, 0.99999999 );

			std::size_t CurrentRoundCount = 0;
			while ( SubstitutionBoxMatrix.size() != 16 )
			{
				if ( CurrentRoundCount == 0 )
				{
					//Seed ∈ [0.0, 1.0] Seed ≠ 0.0 and 1.0
					//0.3
					this->GeneratorAlgorithm( Bytes, ArraySize, 0.3 );
				}
				else
				{
					double value = real_distribution_number_ranges( PRNG );

					//0.3
					while ( this->FloatingValueEqual( value, 0.3 ) )
					{
						value = real_distribution_number_ranges( PRNG );
					}
					this->GeneratorAlgorithm( Bytes, ArraySize, value );
				}

				for ( const auto& Byte : Bytes )
				{
					if ( UniqueElementBytes.size() != 256 )
					{
						UniqueElementBytes.emplace( Byte );
					}
					else
					{
						std::vector<unsigned char> SubstitutionBox { UniqueElementBytes.begin(), UniqueElementBytes.end() };
						UniqueElementBytes.clear();

						if ( this->ScreeningSubstitutionBox( SubstitutionBox ) )
						{
							this->ReplacementDataWithArnoldAlgorithm( SubstitutionBox );
							this->ReplacementDataWithArnoldAlgorithm( SubstitutionBox );

							if ( this->ScreeningSubstitutionBox( SubstitutionBox ) )
							{
								SubstitutionBoxMatrix.push_back( SubstitutionBox );
							}
						}
					}
				}

				++CurrentRoundCount;
			}

			std::cout << std::endl;
		}

		void Test()
		{
			///*S盒仿射变换实现*/
			//auto lambda_AffineTransformation = [](int input_byte) -> int
			//{
			//	int A1 = 0xA7;
			//	int output_byte = 0;
			//	int temporary_byte;
			//	int flag;
			//	int flag2;
			//	for (int i = 0; i < 8; i++)
			//	{
			//		flag = (A1 & 0x80) >> 7;
			//		temporary_byte = input_byte & A1;
			//		flag2 = 0;
			//		for (int j = 0; j < 8; j++)
			//		{
			//			flag2 ^= (temporary_byte & 1);
			//			temporary_byte >>= 1;
			//		}
			//		output_byte = output_byte | (flag2 << i);
			//		A1 = (A1 << 1) | flag;
			//	}
			//	output_byte ^= 0xD3;
			//	return output_byte;
			//};

			////模2的伽罗瓦域上的多项式乘法实现
			//auto lambda_GaloisFiniteFieldMultiplication = [](int a, int b) -> int
			//{
			//	int output_byte = 0;
			//	int bit_digit = 0;
			//	while (b)
			//	{
			//		if (b & 1)
			//		{
			//			output_byte ^= a << bit_digit;
			//		}
			//		bit_digit++;
			//		b >>= 1;
			//	}
			//	return output_byte;
			//};

			////模2的伽罗瓦域上的多项式除法实现
			//auto lambda_GaloisFiniteFieldDivision = [](int a, int b, int * round, int * remainder) -> void
			//{
			//	auto lambda_ByteSize = [](int byte) -> int
			//	{
			//		int size = 0;
			//		int compare_byte = 1;
			//		while (true)
			//		{
			//			if (compare_byte >= byte)
			//			{
			//				return size;
			//			}
			//			compare_byte = (compare_byte << 1) + 1;
			//			size++;
			//		}
			//	};

			//	*round = 0;
			//	*remainder = 0;
			//	int distance;
			//	while (1) {
			//		distance = lambda_ByteSize(a) - lambda_ByteSize(b);
			//		if (distance >= 0 && a)
			//		{
			//			a = a ^ (b << distance);
			//			*round = ( *round) | (1 << distance);
			//		}
			//		else
			//		{
			//			*remainder = a;
			//			break;
			//		}
			//	}
			//};

			////模2的伽罗瓦域上求多项式的逆 （采用扩展欧几里德算法）
			//auto lambda_GaloisFiniteFieldInverse = [&lambda_GaloisFiniteFieldDivision, &lambda_GaloisFiniteFieldMultiplication](int leftV, int rightV) -> int
			//{
			//	int x1 = 0, x2 = 1;
			//	int y1 = 1, y2 = 0;
			//	int quotient, remainder, x, y;
			//	while (rightV)
			//	{
			//		lambda_GaloisFiniteFieldDivision(leftV, rightV, &quotient, &remainder);
			//		//x=x2^multiplication(q,x1);
			//		y = y2 ^ lambda_GaloisFiniteFieldMultiplication(quotient, y1);

			//		leftV = rightV;
			//		rightV = remainder;
			//		//x2=x1;
			//		//x1=x;
			//		y2 = y1;
			//		y1 = y;
			//	}
			//	return y2;
			//};

			//

			//std::unordered_set<unsigned char> UniqueElementBytes;

			//for(std::size_t row = 0; row <= 20000; row++)
			//{
			//	for(std::size_t column = 0; column <= 20000; column++)
			//	{
			//		//0x1f5 SM4 Poly
			//
			//		unsigned char value = static_cast<unsigned char>( lambda_AffineTransformation( lambda_GaloisFiniteFieldInverse(0x1f5 , lambda_AffineTransformation( ( (row << 4) | column ) ) ) ) );

			//		//std::cout << std::hex << (int)value << "\t";

			//		UniqueElementBytes.emplace(value);
			//	}
			//}
			//
			//std::vector<unsigned char> TemporarySubstitutionBox1(UniqueElementBytes.begin(), UniqueElementBytes.end());

			std::cout << std::endl;

			//AES Forward Example Modified
			std::vector<unsigned char> TemporarySubstitutionBox1
			{
				0x7E, 0x94, 0xBE, 0x01, 0x1E, 0x72, 0xC1, 0x93, 0x4E, 0xDA, 0xCD, 0x24, 0xA1, 0xCF, 0x88, 0x85,
				0xD3, 0x0E, 0x2C, 0x5D, 0x12, 0x87, 0xE6, 0x11, 0x91, 0xF8, 0xA6, 0x3B, 0x05, 0xB7, 0x36, 0xE2,
				0x1D, 0x0A, 0x46, 0x04, 0x57, 0x6F, 0xEF, 0xC6, 0xFD, 0x56, 0x82, 0x25, 0x32, 0x64, 0xC9, 0xF7,
				0x3C, 0x4A, 0x3D, 0x77, 0xA7, 0xB9, 0x69, 0x31, 0xC3, 0xA4, 0x2F, 0xB6, 0x5A, 0x86, 0x30, 0x29,
				0x7A, 0x95, 0x44, 0x0C, 0x62, 0xBD, 0x43, 0xF0, 0xEA, 0x2B, 0xF6, 0xEE, 0x03, 0x1F, 0x97, 0xAD,
				0xBF, 0x5E, 0x6A, 0xB4, 0x00, 0x79, 0x66, 0xC8, 0x58, 0x9D, 0x73, 0xB5, 0x10, 0x0B, 0xBA, 0x1A,
				0x5F, 0xE8, 0xD1, 0x52, 0xDF, 0x8E, 0x4F, 0x6B, 0x27, 0x16, 0x28, 0x09, 0x40, 0x2D, 0x6C, 0x71,
				0x15, 0x20, 0x13, 0xDC, 0x63, 0xC0, 0xAF, 0x51, 0xD9, 0x59, 0x02, 0x99, 0xEC, 0x6E, 0xD5, 0x98,
				0x7C, 0xFA, 0x3E, 0xA2, 0xD6, 0x67, 0xF2, 0xA8, 0xC5, 0xE5, 0x2A, 0x9C, 0xE0, 0x23, 0x8C, 0xFE,
				0x81, 0xE7, 0x61, 0x92, 0x3A, 0x39, 0x83, 0x19, 0x75, 0x42, 0xCE, 0xFC, 0x8A, 0x33, 0x22, 0x14,
				0x9E, 0x17, 0xDB, 0xF3, 0x74, 0xBC, 0x1B, 0xE3, 0x41, 0x54, 0x48, 0xDE, 0xC7, 0x65, 0x90, 0x2E,
				0x6D, 0x7B, 0x8F, 0xAA, 0x4D, 0xCC, 0x9B, 0xB0, 0x49, 0xBB, 0xC4, 0x7F, 0x1C, 0xAC, 0x4C, 0xB8,
				0x5B, 0xB1, 0x35, 0xD8, 0xA9, 0x50, 0x68, 0x4B, 0xAE, 0xFB, 0xB3, 0x60, 0x53, 0x26, 0xF4, 0x3F,
				0xD2, 0xE9, 0xFF, 0xDD, 0x55, 0x80, 0x70, 0x78, 0xD4, 0x34, 0xD7, 0xB2, 0xC2, 0xF1, 0xF9, 0x08,
				0xCB, 0x84, 0xE4, 0xD0, 0x7D, 0x07, 0x9A, 0x8B, 0x45, 0xA3, 0x21, 0x06, 0x96, 0xE1, 0x5C, 0x0F,
				0x18, 0x9F, 0xED, 0x47, 0xF5, 0x38, 0x8D, 0xA0, 0x37, 0xCA, 0x76, 0x89, 0xAB, 0xEB, 0x0D, 0xA5
			};

			//AES Backward Example Modified
			std::vector<unsigned char> TemporarySubstitutionBox2
			{
				0x08, 0x66, 0xBE, 0xB4, 0x31, 0xC7, 0xAA, 0xB8, 0x22, 0xF3, 0x42, 0xE8, 0x99, 0x46, 0x6C, 0xA8,
				0x51, 0x60, 0xEE, 0x13, 0x3C, 0xC0, 0x58, 0x79, 0x29, 0x24, 0xA9, 0xD4, 0x63, 0xCC, 0xC5, 0x77,
				0x7D, 0x25, 0x6E, 0xB0, 0x52, 0x67, 0xC6, 0x36, 0x56, 0x85, 0x2D, 0xAD, 0x44, 0x74, 0xCB, 0x92,
				0x00, 0xBB, 0x80, 0xE4, 0x40, 0xB1, 0xD7, 0x55, 0xFA, 0x33, 0xA4, 0x98, 0x05, 0x5A, 0xD6, 0x6F,
				0x11, 0xEF, 0x43, 0xFE, 0x21, 0x5D, 0xDF, 0x6B, 0xEB, 0xE5, 0x23, 0x1C, 0x7A, 0x4C, 0x54, 0x03,
				0x04, 0x4D, 0xBC, 0x20, 0x5F, 0xA6, 0xF0, 0x97, 0x69, 0xA1, 0x9F, 0x70, 0x14, 0x72, 0x5C, 0x17,
				0xAF, 0x3A, 0x12, 0x6D, 0x8A, 0x49, 0x6A, 0x3F, 0xCD, 0x68, 0x0B, 0x2B, 0x9E, 0x8D, 0x71, 0xEA,
				0x82, 0xCF, 0x30, 0x32, 0x94, 0x1B, 0xF5, 0x95, 0x1E, 0xF8, 0xD9, 0xC2, 0x2C, 0x9D, 0x3E, 0x37,
				0x9A, 0x0D, 0xB5, 0x0A, 0xF9, 0xE0, 0x57, 0x2E, 0x27, 0xAC, 0xBA, 0x88, 0xDC, 0x38, 0x75, 0x06,
				0xAB, 0x64, 0x73, 0xD3, 0x09, 0xA2, 0xC3, 0x78, 0x84, 0xDA, 0xD8, 0x7E, 0xD0, 0x10, 0xE3, 0x62,
				0x4B, 0x26, 0x7C, 0xF2, 0x48, 0xFD, 0x61, 0xD1, 0x16, 0x91, 0xE2, 0x89, 0x1F, 0xA7, 0x8C, 0xED,
				0x8F, 0xD2, 0x9B, 0x28, 0x81, 0xC9, 0x19, 0xDE, 0x4A, 0x2F, 0xCE, 0xF4, 0x86, 0xA3, 0x47, 0xDD,
				0x65, 0xB2, 0x8E, 0xF6, 0x9C, 0xE7, 0x0E, 0xFB, 0x3D, 0x15, 0xE1, 0x0F, 0x2A, 0x96, 0xD5, 0x90,
				0xA0, 0xF1, 0x8B, 0x59, 0xE6, 0xB6, 0x7F, 0x7B, 0xEC, 0x4E, 0x01, 0x41, 0x93, 0x07, 0xAE, 0x18,
				0xC8, 0x76, 0xBD, 0x4F, 0xB3, 0xFC, 0x87, 0xC4, 0x1A, 0x34, 0x39, 0xFF, 0x83, 0xE9, 0xF7, 0x0C,
				0x02, 0x50, 0xA5, 0x45, 0x5E, 0xB9, 0xBF, 0x35, 0x3B, 0x1D, 0x53, 0x5B, 0xDB, 0xCA, 0xB7, 0xC1
			};

			//ZUC
			std::vector<unsigned char> TemporarySubstitutionBox3
			{
				0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
				0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
				0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
				0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
				0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
				0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
				0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
				0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
				0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
				0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
				0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
				0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
				0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
				0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
				0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
				0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2
			};

			//SM4
			std::vector<unsigned char> TemporarySubstitutionBox4
			{
				0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
				0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 
				0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
				0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
				0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
				0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
				0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
				0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
				0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
				0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
				0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
				0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
				0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
				0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
				0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
				0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
			};

			//AES Forward Example Modified
			std::vector<unsigned char> TemporarySubstitutionBox5
			{
				0x7F, 0x84, 0x01, 0x2B, 0xC3, 0x4E, 0x55, 0x58, 0x21, 0x62, 0x64, 0xF1, 0xE9, 0x81, 0x6F, 0x6D,
				0x50, 0x71, 0x72, 0x61, 0xF2, 0xA9, 0xBB, 0xD7, 0xB7, 0xF8, 0x00, 0x74, 0xF4, 0x05, 0x76, 0x6E,
				0xE8, 0x8F, 0x78, 0x34, 0xF9, 0x28, 0xF3, 0x54, 0x3A, 0x6C, 0x14, 0x02, 0x1D, 0x7B, 0xA8, 0x5E,
				0x98, 0x25, 0x3F, 0x87, 0xC0, 0x8A, 0x79, 0xE2, 0xBA, 0xE5, 0xC1, 0x24, 0xFB, 0x13, 0xF7, 0xCF,
				0xB4, 0x12, 0x07, 0x95, 0xFC, 0x8D, 0xDA, 0x5B, 0x3C, 0x53, 0xD4, 0x09, 0x39, 0x4B, 0xEA, 0x27,
				0xDD, 0xB9, 0x75, 0xB6, 0x49, 0xD5, 0x42, 0x3E, 0xCD, 0xF6, 0x7D, 0x5F, 0x17, 0xA1, 0xEF, 0xD3,
				0x0F, 0x0B, 0x52, 0x2F, 0xDC, 0x46, 0x80, 0x30, 0xA0, 0x99, 0x06, 0x56, 0xFF, 0xE0, 0xB1, 0xB0,
				0x1E, 0x60, 0x32, 0x8E, 0xA3, 0x67, 0x51, 0x7E, 0xBE, 0x15, 0xCA, 0x8C, 0x3B, 0xAB, 0xA4, 0x16,
				0x19, 0xA7, 0xC9, 0x4D, 0x43, 0x94, 0x89, 0xCC, 0x3D, 0x70, 0x85, 0x59, 0x2E, 0xD1, 0xEE, 0x9E,
				0x5D, 0x8B, 0x69, 0x77, 0x29, 0xD2, 0x44, 0x63, 0x5C, 0x82, 0x65, 0x45, 0x36, 0x1A, 0xD0, 0x88,
				0xAD, 0xD6, 0x9F, 0xAC, 0x7A, 0x4F, 0x9B, 0x41, 0xE7, 0x47, 0x2A, 0xB2, 0xE1, 0x0D, 0xDF, 0x97,
				0x26, 0xC5, 0x38, 0x6B, 0xFD, 0x2D, 0xEC, 0xF5, 0xC8, 0x10, 0x93, 0x20, 0x37, 0x9A, 0xAA, 0xA2,
				0xC4, 0xB3, 0xC6, 0xA6, 0x6A, 0xDB, 0x57, 0x0A, 0xAE, 0x9C, 0xE3, 0x08, 0x03, 0x1F, 0xD8, 0x2C,
				0x90, 0xB5, 0x0C, 0x83, 0x40, 0x23, 0x68, 0x91, 0xBC, 0x22, 0x33, 0x66, 0x18, 0xAF, 0x1B, 0xCE,
				0x4C, 0xE4, 0xF0, 0xFE, 0x5A, 0x0E, 0x04, 0x35, 0x11, 0xBD, 0x73, 0xFA, 0xEB, 0x9D, 0x7C, 0x48,
				0x1C, 0xD9, 0x4A, 0xC2, 0xA5, 0xC7, 0x86, 0xED, 0xDE, 0xBF, 0x96, 0xB8, 0x92, 0x31, 0xCB, 0xE6,
			};

			//AES Backward Example Modified
			std::vector<unsigned char> TemporarySubstitutionBox6
			{
				0x7F, 0x5C, 0x2A, 0x79, 0x41, 0x3D, 0xB9, 0xE8, 0x70, 0xCD, 0xF0, 0x2C, 0x9D, 0xDE, 0xDC, 0x80,
				0x6A, 0x42, 0xE6, 0x1D, 0x2B, 0xCC, 0x1A, 0x02, 0xE5, 0x60, 0xD2, 0xAD, 0xC7, 0x61, 0xCB, 0x4B,
				0x9C, 0xBC, 0x23, 0xE7, 0x72, 0xDA, 0x67, 0xFD, 0x57, 0x32, 0x48, 0x88, 0x28, 0x7C, 0xB2, 0x4C,
				0xB0, 0x4F, 0x3B, 0x31, 0xD9, 0xD5, 0xBB, 0x08, 0x8C, 0x63, 0xCF, 0xB5, 0xAA, 0x03, 0x25, 0x94,
				0x6B, 0xC6, 0x27, 0x06, 0x62, 0x49, 0x10, 0x76, 0x2F, 0x5B, 0x98, 0x90, 0xE4, 0x47, 0x07, 0x8B,
				0x65, 0xA9, 0x96, 0x9B, 0x56, 0x84, 0xD4, 0xA7, 0x05, 0xA5, 0xE0, 0x83, 0xF2, 0x4D, 0xEF, 0x54,
				0x1E, 0x93, 0x1B, 0x52, 0x12, 0xEA, 0x89, 0x11, 0x77, 0x00, 0xEE, 0x5A, 0xA4, 0x2D, 0x22, 0x36,
				0xDB, 0x75, 0x0A, 0x9A, 0x09, 0x97, 0x71, 0x13, 0x1F, 0x0E, 0x29, 0x0F, 0xC4, 0xB3, 0xD6, 0x92,
				0xFA, 0xAF, 0x85, 0x43, 0xFC, 0xBA, 0xD0, 0xD7, 0x8F, 0xA2, 0xC9, 0xED, 0xBD, 0xA6, 0x30, 0x69,
				0xF6, 0x33, 0x01, 0x8A, 0x99, 0xD3, 0x66, 0x0D, 0x73, 0x21, 0x7B, 0x45, 0x35, 0x91, 0x9F, 0x86,
				0x53, 0x18, 0x40, 0xD1, 0xAB, 0xC1, 0x6F, 0x6E, 0x78, 0xF9, 0xD8, 0xE9, 0x38, 0x16, 0xFB, 0x51,
				0xC3, 0x81, 0x7E, 0xF4, 0xBF, 0x74, 0x68, 0x5D, 0xC8, 0xDD, 0xA3, 0xA0, 0xBE, 0x7D, 0x2E, 0x15,
				0xA1, 0x17, 0x4A, 0x55, 0x95, 0x5F, 0x9E, 0x8D, 0xF8, 0xAE, 0x64, 0x50, 0x46, 0xC5, 0xCE, 0xF1,
				0xC2, 0xF5, 0xC0, 0xB1, 0xF3, 0x04, 0x34, 0x3A, 0xDF, 0x3F, 0x87, 0x58, 0x7A, 0xFE, 0xB8, 0x82,
				0x59, 0x3E, 0x1C, 0xB7, 0x14, 0x26, 0xE2, 0x0B, 0xE3, 0x6C, 0x44, 0xB4, 0xEB, 0x3C, 0x19, 0x24,
				0xFF, 0xA8, 0xE1, 0x39, 0x37, 0xCA, 0x6D, 0xAC, 0x8E, 0x5E, 0xB6, 0xF7, 0x4E, 0xEC, 0x20, 0x0C,
			};

			this->ScreeningSubstitutionBox( TemporarySubstitutionBox1 );

			this->ScreeningSubstitutionBox( TemporarySubstitutionBox2 );

			this->ScreeningSubstitutionBox( TemporarySubstitutionBox3 );

			this->ScreeningSubstitutionBox( TemporarySubstitutionBox4 );

			this->ScreeningSubstitutionBox( TemporarySubstitutionBox5 );

			this->ScreeningSubstitutionBox( TemporarySubstitutionBox6 );


			/*for (std::size_t execute_counter = 0; execute_counter != 193; ++execute_counter)
				{
					this->ReplacementDataWithArnoldAlgorithm(TemporarySubstitutionBox1);
					this->ReplacementDataWithArnoldAlgorithm(TemporarySubstitutionBox2);

					std::cout << "ArnoldAlgorithm Processing..... " << "Round: " << execute_counter << std::endl;
				}*/

			std::cout << std::endl;
		}
	};

	//Generate Variable Substitution-Boxes Starting from a Key
	//https://www.codeproject.com/Articles/5331410/Generate-Variable-Substitution-Boxes-Starting-from
	template <typename HashProviderType, CommonSecurity::SHA::Hasher::WORKER_MODE HashWorkerMode>
	class SubstitutionBoxGenerationWithHashedKey
	{

	private:
		struct CoreImplementation
		{
			std::unique_ptr<HashProviderType> HashProviderPointer = nullptr;

			/*
				匹配一段范围内的字节数据是否相同
				Match whether the byte data in a range is the same
			*/
			bool ByteSpanViewIsEqual( std::span<const unsigned char> A, std::span<const unsigned char> B, std::size_t need_check_size )
			{
				bool IsEqualSpanRange = false;
				if ( need_check_size <= 0 )
				{
					if ( A.size() == B.size() )
					{
						need_check_size = B.size();
					}
				}
				else
				{
					if ( A.size() < need_check_size || B.size() < need_check_size )
					{
						need_check_size = 0;
					}
				}

				if ( need_check_size > 0 )
				{
					IsEqualSpanRange = true;

					auto Iterator = A.begin();
					auto Iterator2 = B.begin();

					for ( std::size_t counter = 0; counter < need_check_size; ++counter )
					{
						if ( *Iterator != *Iterator2 )
						{
							IsEqualSpanRange = false;
							break;
						}

						++Iterator;
						++Iterator2;
					}
				}

				return IsEqualSpanRange;
			}

			/*
				对源字节序列使用哈希函数，直到找到匹配的目标字节序列
				Use the hash function on the source byte sequence until a matching target byte sequence is found
			*/
			std::vector<unsigned char> FindBytesWithHashValue( const std::vector<unsigned char>& from_source, const std::vector<unsigned char>& to_target )
			{
				auto&					   HashProviderReference = *HashProviderPointer;
				std::vector<unsigned char> ResultHashedValues;
				if constexpr ( std::same_as<HashProviderType, CommonSecurity::SHA::Version2::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512 ) )
				{
					if ( !from_source.empty() && !from_source.empty() && to_target.size() >= to_target.size() )
					{
						std::size_t				   NeedFind = to_target.size();
						auto					   HashedByteArray = HashProviderReference.Hash( { std::bit_cast<std::byte*>( from_source.data() ), from_source.size() } );
						std::vector<unsigned char> TemporaryHashedValues;
						Cryptograph::CommonModule::Adapters::classicByteFromByte( HashedByteArray, TemporaryHashedValues );
						if ( NeedFind > 0 && ( from_source.begin() + NeedFind ) <= from_source.end() && ( to_target.begin() + NeedFind ) <= to_target.end() )
						{
							std::span MemorySpanA { TemporaryHashedValues.begin(), TemporaryHashedValues.end() };
							std::span MemorySpanB { to_target.begin(), to_target.end() };
							while ( !this->ByteSpanViewIsEqual( MemorySpanA, MemorySpanB, NeedFind ) )
							{
								HashedByteArray = HashProviderReference.Hash( { std::bit_cast<std::byte*>( HashedByteArray.data() ), HashedByteArray.size() } );
								TemporaryHashedValues.clear();
								Cryptograph::CommonModule::Adapters::classicByteFromByte( HashedByteArray, TemporaryHashedValues );
								MemorySpanA = { TemporaryHashedValues.begin(), TemporaryHashedValues.end() };
							}
						}

						Cryptograph::CommonModule::Adapters::classicByteFromByte( HashedByteArray, ResultHashedValues );
					}
				}
				else if constexpr ( ( std::same_as<HashProviderType, CommonSecurity::SHA::Version3::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_256 ) ) || ( std::same_as<HashProviderType, CommonSecurity::SHA::Version3::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512 ) ) || ( std::same_as<HashProviderType, CommonSecurity::ChinaShangeYongMiMa3::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3 ) ) )
				{
					if ( !from_source.empty() && !from_source.empty() && to_target.size() >= to_target.size() )
					{
						std::size_t				   NeedFind = to_target.size();
						std::vector<unsigned char> HashedByteArray( HashProviderReference.HashSize(), 0x00 );

						HashProviderReference.StepUpdate( { from_source.begin(), from_source.end() } );
						HashProviderReference.StepFinal( HashedByteArray );

						if ( NeedFind > 0 && ( from_source.begin() + NeedFind ) <= from_source.end() && ( to_target.begin() + NeedFind ) <= to_target.end() )
						{
							std::span MemorySpanA { HashedByteArray.begin(), HashedByteArray.end() };
							std::span MemorySpanB { to_target.begin(), to_target.end() };
							while ( !this->ByteSpanViewIsEqual( MemorySpanA, MemorySpanB, NeedFind ) )
							{
								HashProviderReference.StepUpdate( HashedByteArray );
								HashProviderReference.StepFinal( HashedByteArray );
								MemorySpanA = { HashedByteArray.begin(), HashedByteArray.end() };
							}
						}

						ResultHashedValues = std::move( HashedByteArray );
					}
				}

				return ResultHashedValues;
			}

			/*
				传递一个秘密密钥作为哈希函数参数的数据源
				逐步拼接散列字节数据，并生成字节替换框
					
				Passing a secret key as the data source for the hash function parameters
				Step-by-step stitching of hashed byte data and generation of byte substitution boxes
					
				@param key; Secret byte key
				@param count_left_zeroes; Value range: min is 0 and max is 31

				@return Unique byte data, an array of elements (Substitution box)
			*/
			std::vector<unsigned char> GenerationSubstitutionBox( const std::vector<unsigned char>& key, std::uint32_t count_left_zeroes = 0 )
			{
				if ( count_left_zeroes > 31 )
					count_left_zeroes = 31;

				std::vector<unsigned char> DisorderedUniqueElementByteValues;

				std::vector<unsigned char> OrderedUniqueElementByteValues( 256, 0x00 );
				std::iota( OrderedUniqueElementByteValues.begin() + 1, OrderedUniqueElementByteValues.end(), 1 );

				std::vector<unsigned char> FindingData( count_left_zeroes, 0x00 );

				if ( count_left_zeroes > 0 )
				{
					//使用内存分配的临时数据熵(一次性生成时，才能使用它)
					//Temporary data entropy using memory allocation(Use it only when it is generated at once)
					if constexpr ( false )
					{
						unsigned char* TemporarayByteBuffer = nullptr;

						while ( TemporarayByteBuffer == nullptr )
						{
							TemporarayByteBuffer = new ( std::nothrow ) unsigned char[ count_left_zeroes ];
						}

						std::memmove( FindingData.data(), TemporarayByteBuffer, count_left_zeroes );

						delete TemporarayByteBuffer;
					}
					else
					{
						auto& HashProviderReference = *HashProviderPointer;

						if constexpr ( std::same_as<HashProviderType, CommonSecurity::SHA::Version2::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512 ) )
						{
							auto					   HashedByteArray = HashProviderReference.Hash( { std::bit_cast<std::byte*>( key.data() ), key.size() } );
							std::vector<unsigned char> TemporaryHashedValues;
							Cryptograph::CommonModule::Adapters::classicByteFromByte( HashedByteArray, TemporaryHashedValues );
							std::ranges::copy( TemporaryHashedValues.rbegin(), TemporaryHashedValues.rbegin() + count_left_zeroes, FindingData.begin() );
						}
						else if constexpr ( ( std::same_as<HashProviderType, CommonSecurity::ChinaShangeYongMiMa3::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3 ) ) || ( std::same_as<HashProviderType, CommonSecurity::SHA::Version3::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_256 || HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512 ) ) )
						{
							std::vector<unsigned char> HashedByteArray( HashProviderReference.HashSize(), 0x00 );

							HashProviderReference.StepUpdate( { key.data(), key.size() } );
							HashProviderReference.StepFinal( HashedByteArray );

							std::ranges::copy( HashedByteArray.rbegin(), HashedByteArray.rbegin() + count_left_zeroes, FindingData.begin() );
						}
					}
				}

				std::vector<unsigned char> HashedValues = this->FindBytesWithHashValue( key, FindingData );

				while ( DisorderedUniqueElementByteValues.size() <= 255 )
				{
					HashedValues = this->FindBytesWithHashValue( HashedValues, FindingData );
					std::size_t Position = 0;
					std::size_t Index = 0;

					do
					{
						Position = HashedValues[ count_left_zeroes + Index ] % OrderedUniqueElementByteValues.size();
					} while ( ( count_left_zeroes + Index++ ) < HashedValues.size() && OrderedUniqueElementByteValues[ Position ] == DisorderedUniqueElementByteValues.size() );

					// EXTREMELY rare event
					// (it means that all the bytes of the hashed value are identical and equal to the current substitution position)
					// in this case, take the next position
					// 极其罕见的事件
					// (这意味着哈希值的所有字节都是相同的，并且等于当前的替换位置)
					// 在这种情况下，取下一个位置
					if ( OrderedUniqueElementByteValues[ Position ] == DisorderedUniqueElementByteValues.size() )
					{
						Position = ( Position + 1 ) % OrderedUniqueElementByteValues.size();
					}

					DisorderedUniqueElementByteValues.push_back( OrderedUniqueElementByteValues[ Position ] );
					OrderedUniqueElementByteValues[ Position ] = 0;
					OrderedUniqueElementByteValues.erase( OrderedUniqueElementByteValues.begin() + Position );
				}

				return DisorderedUniqueElementByteValues;
			}

			explicit CoreImplementation( CommonSecurity::SHA::Hasher::WORKER_MODE HashWorkerModeArgument )
			{
				if constexpr ( std::same_as<HashProviderType, CommonSecurity::SHA::Version2::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512 ) )
				{
					HashProviderPointer = std::make_unique<CommonSecurity::SHA::Version2::HashProvider>();
				}
				else if constexpr ( std::same_as<HashProviderType, CommonSecurity::SHA::Version3::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_256 ) )
				{
					HashProviderPointer = std::make_unique<CommonSecurity::SHA::Version3::HashProvider>( 256 );

					auto& HashProviderReference = *HashProviderPointer;
					HashProviderReference.StepInitialize();
				}
				else if constexpr ( std::same_as<HashProviderType, CommonSecurity::SHA::Version3::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512 ) )
				{
					HashProviderPointer = std::make_unique<CommonSecurity::SHA::Version3::HashProvider>( 512 );

					auto& HashProviderReference = *HashProviderPointer;
					HashProviderReference.StepInitialize();
				}
				else if constexpr ( std::same_as<HashProviderType, CommonSecurity::ChinaShangeYongMiMa3::HashProvider> && ( HashWorkerMode == CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3 ) )
				{
					HashProviderPointer = std::make_unique<CommonSecurity::ChinaShangeYongMiMa3::HashProvider>();

					auto& HashProviderReference = *HashProviderPointer;
					HashProviderReference.StepInitialize();
				}
				else
				{
					static_assert( CommonToolkit::Dependent_Always_Failed<CoreImplementation>, "HashMode enumeration does not match HashProviderType!" );
				}
			}

			~CoreImplementation()
			{
				HashProviderPointer.reset();
			}
		};

	public:
		std::pair<std::vector<unsigned char>, std::vector<unsigned char>> GenerationSubstitutionBoxPair( std::vector<unsigned char>& key, std::uint32_t search_difficulty = 1 )
		{
			CoreImplementation		   CoreImplementationObject( HashWorkerMode );
			std::vector<unsigned char> ForwardSubstitutionBox = CoreImplementationObject.GenerationSubstitutionBox( key, search_difficulty );

			std::vector<unsigned char> BackwardSubstitutionBox( 256, 0x00 );

			for ( std::uint32_t index = 0; index < ForwardSubstitutionBox.size(); ++index )
			{
				BackwardSubstitutionBox[ ForwardSubstitutionBox[ index ] ] = static_cast<unsigned char>( index );
			}

			return { ForwardSubstitutionBox, BackwardSubstitutionBox };
		}

		/*
			@param key; Secret byte key
			@param search_difficulty; Using difficulty bigger than 1 makes the alghorithm VERY MUCH slower (2 ~ 31)

			@return Generated pair of substitution box data
		*/
		std::pair<std::vector<unsigned char>, std::vector<unsigned char>> operator()( std::vector<unsigned char>& key, std::uint32_t search_difficulty = 1 )
		{
			return this->GenerationSubstitutionBoxPair( key, search_difficulty );
		}

		SubstitutionBoxGenerationWithHashedKey() = default;
		~SubstitutionBoxGenerationWithHashedKey() = default;
	};

	//An efficient construction of key-dependent substitution box based on chaotic sine map
	//https://journals.sagepub.com/doi/10.1177/1550147719895957
	class SubstitutionBoxGenerationUsingChaoticSineMapWithKey
	{

	private:
		static constexpr double SubstitutionBoxRange = ( 0.99 - 0.1 ) / 255;

		/*
			Experiment analysis:
				
				Earlier studies presented some significant cryptographic properties that strong S-boxes should fulfill such input/output XOR distribution and LAP.
				Consequently, to confirm the robustness of the proposed method, this section presents the comparative analysis of S-box generated using the proposed method and S-boxes presented in prior work.
				Table 3 shows the output S-box, where the initial value x[0]=0.798079790040599 and the control parameter λ=0.99 were used in the S-box construction.

			Keyspace analysis:
				Based on the control parameter analysis of CSM presented in the “Chaotic sine map” section, the S-box construction method based on CSM presented in “The method of constructing key-dependent S-box” section is therefore limited to λ∈(0.87,1) and can be used as a part of the secret key.
				Thus, both control parameter λ and initial value x0 are used together as a secret key to generate dynamic S-box.
				Furthermore, if CSM is implemented in a finite precision system, then keyspace is around 106 bits, where the size of the λ and x0 is 53 bits.
				Thus, the keyspace of the proposed method is good enough according to cryptographic requirements.
		*/

		double InitalValue_X = 0.8;
		double ControlParameters_Lambda = 0.99;

		/*
			The chaotic S-box construction method based on CSM requires secret key K as input, where secret key K is a combination of the two input parameters of CSM, that is, initial value x[0] and control parameter λ.
			Sbox represents the output S-box.

			Step 1. Select the initial input parameters x0 and λ as a secret key to iterate the CSM.

			Step 2. Include zero to final stored values as it has no inverse.

			Step 3. Define the output domain range of the CSM to (0.1,0.99), since values close to zero or one could not be used to start CSM.

			Step 4. Divide the domain range into 255 subdomains of equal length and sequentially label them l[0],l[1],l[1],…,l[254].

			Step 5. Iterate the CSM with the input initial valuex[0] and control parameter λ, and check the output to mark where obtained x[1] value falls, and corresponding subdomain value should be stored in Sbox.
			If the output falls into an already visited subdomain, then ignore that output and keep iterating CSM.

			Step 6. Stop iterating the CSM, when stored values approach to 255 of Sbox.
		*/
		double ChaoticSineMap( const double ControlParameters_Lambda, double floating_value )
		{
			return ControlParameters_Lambda * std::sin( std::numbers::pi * floating_value );
		}

	public:
		template <typename RNG_Type>
		requires std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>> std::pair<std::vector<unsigned char>, std::vector<unsigned char>> WorkerFunction( RNG_Type& PRNG )
		{
			std::uniform_real_distribution InitalValueRange( 0.8000000000000000, 0.9999999999999999 );
			std::uniform_real_distribution ControalParamters_Lambda( 0.870000000000000, 0.9999999999999999 );

			InitalValue_X = InitalValueRange( PRNG );
			ControlParameters_Lambda = ControalParamters_Lambda( PRNG );

			std::unordered_set<unsigned char> SubstitutionBoxValues;

		BuildBoxBeginLoop:

			InitalValue_X = this->ChaoticSineMap( ControlParameters_Lambda, InitalValue_X );

			//value n
			std::size_t SubstitutionBoxValue = 0;

		UpdateLabel:

			double label0 = 0.1 + static_cast<double>( SubstitutionBoxValue * SubstitutionBoxRange );
			double label1 = 0.1 + static_cast<double>( ( SubstitutionBoxValue + 1 ) * SubstitutionBoxRange );

			if ( InitalValue_X >= label0 && InitalValue_X < label1 )
			{
				if ( SubstitutionBoxValues.find( static_cast<unsigned char>( SubstitutionBoxValue ) ) == SubstitutionBoxValues.end() )
				{
					SubstitutionBoxValues.insert( static_cast<unsigned char>( SubstitutionBoxValue ) );

					if ( SubstitutionBoxValues.size() != 256 )
					{
						goto BuildBoxBeginLoop;
					}
					else
					{
						goto BuildBoxEndLoop;
					}
				}
				else
				{
					InitalValue_X = this->ChaoticSineMap( ControlParameters_Lambda, InitalValue_X );
					goto BuildBoxBeginLoop;
				}
			}
			else
			{
				if ( SubstitutionBoxValue + 1 == 256 )
				{
					SubstitutionBoxValue = 0;
					goto BuildBoxBeginLoop;
				}

				SubstitutionBoxValue += 1;
				goto UpdateLabel;
			}

		BuildBoxEndLoop:

			std::vector<unsigned char> ByteDataSubstitutionBox( SubstitutionBoxValues.begin(), SubstitutionBoxValues.end() );
			SubstitutionBoxValues.clear();
			std::vector<unsigned char> InvertedByteDataSubstitutionBox( 256, 0x00 );

			for ( std::size_t SubstitutionBoxIndex = 0; SubstitutionBoxIndex < 256; ++SubstitutionBoxIndex )
			{
				std::uint8_t ValueOfSubstitutionBox = ByteDataSubstitutionBox[ SubstitutionBoxIndex ];
				InvertedByteDataSubstitutionBox[ ValueOfSubstitutionBox ] = SubstitutionBoxIndex;
			}

			return { ByteDataSubstitutionBox, InvertedByteDataSubstitutionBox };
		}

		/*
			Proposed work:
				
				Chaotic sine map
				The sine map is taking as the primary chaotic map for the construction of the proposed S-box.
				The chaotic sine map (CSM) is a widely known one-dimensional (1D) chaotic map.
				It is similar to the Lorenz system from many respects and meets many cryptographic requirements such as complex chaotic behavior,
				sensitivity to initial values, randomness, and unpredictability. Equation (1) defines CSM

				This equation (1):
				Function <-> λ * sin(π * x[n])
				x[n+1]=Function(x[n])

				where x[n]∈(0,1), n=0,1,2,…, λ∈(0,1) is a control parameter, and x[0] is the initial value when n=0.
				The bifurcation and the Lyapunov exponent analyses of the CSM are provided in Figures 2 and 3, respectively.
				Analysis results confirm the chaotic behavior beyond λ=0.87 of the CSM, where orbits {xn}∞n=0 are uniformly distributed between 0 and 1.
				Based on the experiment analysis, the proposed design utilizes a CSM to construct S-box to achieve Shannon’s recommended confusion and diffusion properties.

				The method of constructing key-dependent S-box:
				The proposed method of constructing a key-dependent S-box is based on the mixing property of CSM.
				CSM is an iterative map (start from two input parameters, x[0] and λ) to obtain xn values from equation (1).
				The obtained xn values are converted and are used to construct S-box by defining domain range into 255 subdomains of equal length.
				Moreover, the input parameters (an initial value x0 and a control parameter λ) of the CSM are used as a secret key in the proposed method.

				The flowchart of the method of constructing a key-dependent S-box is shown in Figure 4.
				It takes m input bits and produces n output bits, and generates a sequence of 256 different values between 0 and 255. The proposed method is described below.
		*/
		std::pair<std::vector<unsigned char>, std::vector<unsigned char>> Test()
		{
			double		 Test_InitalValue_X = 0.798079790040599;
			const double Test_ControlParameters_Lambda = 0.9999999999999999;

			std::unordered_set<unsigned char> SubstitutionBoxValues;

		BuildBoxBeginLoop:

			Test_InitalValue_X = this->ChaoticSineMap( Test_ControlParameters_Lambda, Test_InitalValue_X );

			//value n
			std::size_t SubstitutionBoxValue = 0;

		UpdateLabel:

			double label0 = 0.1 + static_cast<double>( SubstitutionBoxValue ) * SubstitutionBoxRange;
			double label1 = 0.1 + static_cast<double>( SubstitutionBoxValue + 1 ) * SubstitutionBoxRange;

			if ( Test_InitalValue_X >= label0 && Test_InitalValue_X < label1 )
			{
				if ( SubstitutionBoxValues.find( static_cast<unsigned char>( SubstitutionBoxValue ) ) == SubstitutionBoxValues.end() )
				{
					SubstitutionBoxValues.insert( static_cast<unsigned char>( SubstitutionBoxValue ) );

					if ( SubstitutionBoxValues.size() != 256 )
					{
						goto BuildBoxBeginLoop;
					}
					else
					{
						goto BuildBoxEndLoop;
					}
				}
				else
				{
					Test_InitalValue_X = this->ChaoticSineMap( Test_ControlParameters_Lambda, Test_InitalValue_X );
					goto BuildBoxBeginLoop;
				}
			}
			else
			{
				if ( SubstitutionBoxValue + 1 == 256 )
				{
					SubstitutionBoxValue = 0;
					goto BuildBoxBeginLoop;
				}

				SubstitutionBoxValue += 1;
				goto UpdateLabel;
			}

		BuildBoxEndLoop:

			std::vector<unsigned char> ByteDataSubstitutionBox( SubstitutionBoxValues.begin(), SubstitutionBoxValues.end() );
			SubstitutionBoxValues.clear();
			std::vector<unsigned char> InvertedByteDataSubstitutionBox( 256, 0x00 );

			for ( std::size_t SubstitutionBoxIndex = 0; SubstitutionBoxIndex < 256; ++SubstitutionBoxIndex )
			{
				std::uint8_t ValueOfSubstitutionBox = ByteDataSubstitutionBox[ SubstitutionBoxIndex ];
				InvertedByteDataSubstitutionBox[ ValueOfSubstitutionBox ] = SubstitutionBoxIndex;
			}

			return { ByteDataSubstitutionBox, InvertedByteDataSubstitutionBox };
		}
	};
} // namespace SubstitutionBoxGenerationTheoryExperimental

#endif