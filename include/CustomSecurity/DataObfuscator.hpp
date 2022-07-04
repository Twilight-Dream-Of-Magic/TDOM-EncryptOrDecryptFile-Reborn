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

	namespace SubsitiutionBox
	{
		/*
			In Euclidean geometry, an affine transformation, or an affinity (from the Latin, affinis, "connected with"),
			is a geometric transformation that preserves lines and parallelism (but not necessarily distances and angles).
			More generally, an affine transformation is an automorphism of an affine space (Euclidean spaces are specific affine spaces),
			that is, a function which maps an affine space onto itself while preserving both the dimension of any affine subspaces (meaning that it sends points to points,
			lines to lines, planes to planes, and so on) and the ratios of the lengths of parallel line segments.
			Consequently, sets of parallel affine subspaces remain parallel after an affine transformation.
			An affine transformation does not necessarily preserve angles between lines or distances between points,
			though it does preserve ratios of distances between points lying on a straight line.
			X is the point set of an affine space, then every affine transformation on X can be represented as the composition of a linear transformation on X and a translation of X.
			Unlike a purely linear transformation, an affine transformation need not preserve the origin of the affine space.
			Thus, every linear transformation is affine, but not every affine transformation is linear.
			Examples of affine transformations include translation, scaling, homothety, similarity, reflection, rotation, shear mapping, and compositions of them in any combination and sequence.
			Viewing an affine space as the complement of a hyperplane at infinity of a projective space,
			the affine transformations are the projective transformations of that projective space that leave the hyperplane at infinity invariant, restricted to the complement of that hyperplane.
			在欧几里得几何学中，仿生变换或仿生力（来自拉丁文affinis，"与之相连"）。
			是一种保留线和平行度的几何变换（但不一定是距离和角度）。
			更一般地说，仿生变换是仿生空间的一种自动变形（欧几里得空间是特定的仿生空间）。
			也就是说，一个将仿生空间映射到自身的函数，同时保留了任何仿生子空间的维度（意味着它将点发送到点。
			线对线，平面对平面，等等）和平行线段的长度比。
			因此，平行的仿生子空间的集合在仿生变换之后仍然是平行的。
			仿射变换不一定保留线与线之间的角度或点与点之间的距离。
			尽管它确实保留了位于直线上的各点之间的距离比。
			X是一个仿生空间的点集，那么X上的每个仿生变换都可以表示为X上的线性变换和X的平移的组合。
			与纯粹的线性变换不同，仿生变换不需要保留仿生空间的原点。
			因此，每个线性变换都是仿生的，但不是每个仿生变换都是线性的。
			仿生变换的例子包括平移、缩放、同构、相似、反射、旋转、剪切映射，以及它们在任何组合和序列中的组合。
			把一个仿生空间看作是投影空间无穷远处的超平面的补充。
			仿生变换是该投射空间的投射变换，这些变换使无限远处的超平面不变，并限制在该超平面的补体上。
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
				[&lambda_permutation_byte](const unsigned char &byte) -> unsigned char 
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

		std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> GeneratorAlgorithm2()
		{
			std::vector<std::uint8_t> ByteDataSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(ByteDataSubstitutionBox.begin(), ByteDataSubstitutionBox.end(), 0, 1);
			std::vector<std::uint8_t> InvertedByteDataSubsitiutionBox = std::vector<std::uint8_t>(256, 0x00);

			std::random_device random_device_object;

			for(std::size_t element_counter = 1; element_counter < 256; ++element_counter)
			{
				auto random_number = random_device_object();
				std::size_t index1 =  ByteDataSubstitutionBox.size() - element_counter;
				std::size_t index2 = static_cast<std::size_t>(std::floor(random_number * static_cast<std::size_t>(10000000000))) % index1 + 1;
				std::swap(ByteDataSubstitutionBox[index1], ByteDataSubstitutionBox[index2]);
			}

			for(std::size_t SubstitutionBoxIndex = 0; SubstitutionBoxIndex < 256; ++SubstitutionBoxIndex)
			{
				std::uint8_t ValueOfSubstitutionBox = ByteDataSubstitutionBox[SubstitutionBoxIndex];
				InvertedByteDataSubsitiutionBox[ValueOfSubstitutionBox] = SubstitutionBoxIndex;
			}

			return std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> { ByteDataSubstitutionBox, InvertedByteDataSubsitiutionBox };
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

			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::uint8_t> random_number_distribution(0, ByteSubstitutionBox.size() - 1);

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
			using namespace SubsitiutionBox;

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
			using namespace SubsitiutionBox;

			std::array<std::uint8_t, 256> AESBox = CommonToolkit::make_array<std::uint8_t, 256>();

			for(auto& ByteData : std::ranges::subrange( AESBox.rbegin(), AESBox.rend() ) )
			{
				ByteData = NybergSubstitutionBoxValueWithAffineTransformation( static_cast<std::uint8_t>( MathTools::InverseOfWithGaloisField(ByteData) ), 0x1F, 0x63);
			}

			return AESBox;
		}

		std::array<std::uint8_t, 256> GenerateInvertAESBox()
		{
			using namespace SubsitiutionBox;

			std::array<std::uint8_t, 256> InvertAESBox = CommonToolkit::make_array<std::uint8_t, 256>();

			for(auto& ByteData : InvertAESBox)
			{
				ByteData = static_cast<std::uint8_t>( MathTools::InverseOfWithGaloisField( NybergSubstitutionBoxValueWithAffineTransformation(ByteData, 0x4A, 0x05) ) );
			}

			return InvertAESBox;
		}

		void BuildBox()
		{
			using namespace SubsitiutionBox;
			using namespace CustomSecurity::ByteSubstitutionBoxToolkit;
			
			std::array<std::uint8_t, 256> WorkingByteSubstitutionBox = CommonToolkit::make_array<std::uint8_t, 256>();
			std::int32_t SubstitutionBox_NonlinearityDegree = 0;
			std::int32_t SubstitutionBox_TemporaryNonlinearityDegree = 0;
			
			//pow(2, 8) == 256
			//log(2, 256) == 8
			std::size_t LogarithmicNumberOfTwoBased = static_cast<std::size_t>(std::log2(WorkingByteSubstitutionBox.size()));

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

			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::uint8_t> random_number_distribution( ThisAffineTransformationParameters.Unlimit_GF_257 ? 0 : 1, 30);
			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::uint8_t> random_number_distribution2(0, 255);

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

				ThisAffineTransformationParameters.AdditionNumber = random_number_c;
				ThisAffineTransformationParameters.AdditionNumber2 = random_number_d;

				// Multipliers number must have an odd number of set bits
				// 乘法器必须有奇数的设置位
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

			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::uint8_t> random_number_distribution(0, ByteSubstitutionBox.size() - 1);

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
			using namespace SubsitiutionBox;

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
			using namespace SubsitiutionBox;

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
			using namespace SubsitiutionBox;

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
			using namespace SubsitiutionBox;
			using namespace CustomSecurity::ByteSubstitutionBoxToolkit;
			
			std::vector<std::uint8_t> WorkingByteSubstitutionBox = std::vector<std::uint8_t>(256, 0x00);
			CommonToolkit::numbers_sequence_generator<true>(WorkingByteSubstitutionBox.begin(), WorkingByteSubstitutionBox.end(), 0, 1);

			std::int32_t SubstitutionBox_NonlinearityDegree = 0;
			std::int32_t SubstitutionBox_TemporaryNonlinearityDegree = 0;

			//pow(2, 8) == 256
			//log(2, 256) == 8
			std::size_t LogarithmicNumberOfTwoBased = static_cast<std::size_t>(std::log2(WorkingByteSubstitutionBox.size()));

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

			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::uint8_t> random_number_distribution( ThisAffineTransformationParameters.Unlimit_GF_257 ? 0 : 1, 30);
			CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution<std::uint8_t> random_number_distribution2(0, 255);

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

				ThisAffineTransformationParameters.AdditionNumber = random_number_c;
				ThisAffineTransformationParameters.AdditionNumber2 = random_number_d;

				// Multipliers number must have an odd number of set bits
				// 乘法器必须有奇数的设置位
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