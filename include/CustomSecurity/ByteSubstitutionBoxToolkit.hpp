#pragma once

/*
	Reference Paper and source code tool kit
	https://hal.inria.fr/hal-01400936
*/
namespace CustomSecurity::ByteSubstitutionBoxToolkit
{
	using AutoFloatingType = std::conditional_t<CURRENT_SYSTEM_BITS == 32, float, double>;

	/*
		In mathematics, a Boolean function is a function whose arguments and result assume values from a two-element set (usually {true, false}, {0,1} or {-1,1}).[1][2]
		Alternative names are switching function, used especially in older computer science literature,[3][4] and truth function (or logical function), used in logic.
		Boolean functions are the subject of Boolean algebra and switching theory.[5]
		A Boolean function takes the form MathFunction : {0, 1}(^)k -> {0, 1}, where {0, 1} is known as the Boolean domain and (k) is a non-negative integer called the arity of the function. 
		In the case where (k) = 0, the "function" is a constant element of {0, 1}.
		A Boolean function with multiple outputs, MathFunction : {0, 1}(^)k -> {0, 1}(^)m with m > 1 is a vectorial or vector-valued Boolean function (an S-box in cryptography).[6]
		There are 2(^)(2 (^) k) different Boolean functions with (k) arguments; equal to the number of different truth tables with 2(^)k entries.
		Every (k)-ary Boolean function can be expressed as a propositional formula in (k) varibales x1, ...... ,xk, and two propositional formulas are logically equivalent if and only if they express the same Boolean function.

		在数学中，布尔函数是一个函数，其参数和结果都是来自一个两元素集合（通常是{真，假}，{0,1}或{-1,1}）的值。
		另一个名字是切换函数，特别是在较早的计算机科学文献中使用，[3][4]和真理函数（或逻辑函数），在逻辑学中使用。
		布尔函数是布尔代数和开关理论的主题[5]。
		布尔函数的形式是MathFunction : {0, 1}(^)k -> {0, 1}，其中{0, 1}被称为布尔域，(k)是一个非负的整数，称为函数的arity。 
		在(k)=0的情况下，"函数 "是{0, 1}的一个常数元素。
		一个有多个输出的布尔函数，MathFunction : {0, 1}(^)k -> {0, 1}(^)m with m > 1 是一个矢量或矢量值的布尔函数（密码学中的S-box）[6] 。
		有2(^)(2 (^) k)个不同的布尔函数，有(k)个参数；等于有2(^)k个条目的不同真值表的数量。
		每个(k)项布尔函数都可以用(k)个变数x1, ...... ,xk，两个命题公式在逻辑上是等价的，当且仅当它们表达相同的布尔函数

		https://en.wikipedia.org/wiki/Boolean_function
	*/

	enum class BalancednessType
	{
		SubstitutionBoxIsBalanced,
		MathBooleanFunctionIsBalanced,
		SubstitutionBoxIsUnbalanced,
		MathBooleanFunctionIsUnbalanced
	};

	class BaseFunctions
	{	

	public:

		/* Representation Functions */

		//线性组合函数核心，对于二进制矩阵(数学布尔函数真值表)使用
		//Linear combinatorial function core, for binary matrices (mathematical Boolean function truth tables) using
		void Exclusive_OR_Elements
		(
			std::vector<std::vector<std::uint8_t>>& matrix_input,
			const std::vector<std::vector<std::uint8_t>>& truth_table,
			std::vector<std::vector<std::uint8_t>>& matrix_output,
			std::uint32_t column_linear_line,
			std::uint32_t column_truth_table
		)
		{
			for(std::uint32_t index = 0; index < Shift_InputSize; ++index)
			{
				matrix_output[index][column_linear_line] = matrix_input[index][column_linear_line] ^ truth_table[index][column_truth_table];
			}
		}

		//Compute the truth table of mathematical Boolean functions for byte substitution boxes
		//计算字节代换盒的数学布尔函数真值表
		std::vector<std::vector<std::uint8_t>> ComputeTruthTable()
		{
			std::vector<std::vector<std::uint8_t>> truth_table_with_math_boolean_function(Shift_InputSize, std::vector<std::uint8_t>(OutputPowerOfTwo, 0));

			for (std::int32_t loop_row = 0; loop_row < Shift_InputSize; ++loop_row)
			{
				for (std::int32_t loop_column = 0; loop_column < OutputPowerOfTwo; ++loop_column)
				{
					truth_table_with_math_boolean_function[loop_row][loop_column] = ByteSubstitutionBoxArray[loop_row] >> (OutputPowerOfTwo - loop_column - 1) & 0x01;
				}
			}

			return truth_table_with_math_boolean_function;
		}

		//Conversion of mathematical Boolean function truth tables to polar form for byte-substitution boxes
		//对字节代换盒的数学布尔函数真值表转换为极值形式
		//Meaningful hint: You need to use the ComputeTruthTable function first and then use this function
		//有意义的提示：你需要先使用ComputeTruthTable函数，然后再使用这个函数
		std::vector<std::vector<std::int32_t>> PolarTruthTableRepresentation
		(
			const std::vector<std::vector<std::uint8_t>>& truth_table_with_math_boolean_function
		)
		{
			std::vector<std::vector<std::int32_t>> polar_truth_table(Shift_InputSize, std::vector<std::int32_t>(OutputPowerOfTwo, 0));

			for (std::int32_t loop_row = 0; loop_row < Shift_InputSize; ++loop_row)
			{
				for (std::int32_t loop_column = 0; loop_column < OutputPowerOfTwo; ++loop_column)
				{
					polar_truth_table[loop_row][loop_column] = ( truth_table_with_math_boolean_function[loop_row][loop_column] == static_cast<std::uint8_t>(0) ) ? 1 : -1;
				}
			}

			return polar_truth_table;
		}

		//Applying linear combinations of mathematical Boolean function truth tables to byte substitution boxes
		//对字节代换盒的数学布尔函数真值表应用线性组合
		//Meaningful hint: You need to use the ComputeTruthTable function first and then use this function
		//有意义的提示：你需要先使用ComputeTruthTable函数，然后再使用这个函数
		std::vector<std::vector<std::uint8_t>> LinearCombinations
		(
			const std::vector<std::vector<std::uint8_t>>& truth_table_with_math_boolean_function
		)
		{
			std::vector<std::vector<std::uint8_t>> linear_lines_truth_table(Shift_InputSize, std::vector<std::uint8_t>(Shift_OutputSize - 1, 0));

			if(OutputPowerOfTwo == 1)
			{
				for(std::uint32_t index = 0; index < Shift_InputSize; index++)
				{
					linear_lines_truth_table[index][0] = truth_table_with_math_boolean_function[index][0];
				}
			}
			else
			{
				for(std::uint32_t index = 0; index < Shift_OutputSize; index++)
				{
					for(std::int32_t index2 = 0; index2 < OutputPowerOfTwo; index2++)
					{
						if(index >> index2 & 0x01)
						{
							Exclusive_OR_Elements
							(
								linear_lines_truth_table,
								truth_table_with_math_boolean_function,
								linear_lines_truth_table,
								index - 1,
								index2
							);
						}
					}
				}
			}

			return linear_lines_truth_table;
		}

		/*
			Meaningful hint: You need to use the LinearCombinations function first and then use this function
			有意义的提示：你需要先使用LinearCombinations函数，然后再使用这个函数。
			
			The Hadamard transform (also known as the Walsh–Hadamard transform, Hadamard–Rademacher–Walsh transform,
			Walsh transform, or Walsh–Fourier transform) is an example of a generalized class of Fourier transforms.
			It performs an orthogonal, symmetric, involutive, linear operation on 2m real numbers
			(or complex, or hypercomplex numbers,although the Hadamard matrices themselves are purely real).
			The Hadamard transform can be regarded as being built out of size-2 discrete Fourier transforms (DFTs),
			and is in fact equivalent to a multidimensional DFT of size 2 × 2 × ⋯ × 2 × 2.
			It decomposes an arbitrary input vector into a superposition of Walsh functions.
			The transform is named for the French mathematician Jacques Hadamard (French: [adamaʁ]),
			the German-American mathematician Hans Rademacher,and the American mathematician Joseph L. Walsh.
			哈达玛德变换（又称沃尔什-哈达玛德变换、哈达玛德-拉德马赫-沃尔什变换、沃尔什变换或沃尔什-傅里叶变换）是傅里叶变换的一个广义类的例子。
			它对2m个实数（或复数，或超复数，尽管Hadamard矩阵本身是纯实数）进行正交的、对称的、渐开线的线性运算。
			哈达玛德变换可以看作是由大小为2的离散傅里叶变换（DFT）建立起来的，实际上相当于大小为2×2×⋯×2×2的多维DFT。
			它将任意输入矢量分解为沃尔什函数的叠加。
			该变换以法国数学家Jacques Hadamard（法语：[adamaʁ]）、德裔美国数学家Hans Rademacher和美国数学家Joseph L. Walsh命名。
			
			https://en.wikipedia.org/wiki/Hadamard_transform
			https://en.wikipedia.org/wiki/Fast_Walsh%E2%80%93Hadamard_transform
		*/
		std::vector<std::vector<std::int32_t>> WalshHadamardTransform
		(
			std::vector<std::vector<std::uint8_t>>& linear_lines_truth_table
		)
		{
			std::int32_t shift_m, half_shift_m, truth_table_index, truth_table_index2, a, b;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1;

			std::vector<std::vector<std::int32_t>> truth_table_with_walsh_hadamard_transformed(rows, std::vector<std::int32_t>(columns, 0));

			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				for(std::uint32_t loop_row = 0; loop_row < rows; ++loop_row)
				{
					truth_table_with_walsh_hadamard_transformed[loop_row][loop_column] = ( linear_lines_truth_table[loop_row][loop_column] == 0 ) ? -1 : 1;
				}

				//做沃尔什-哈达玛德变换
				//Do Walsh Hadamard Transform
				for(std::uint32_t index = 1; index <= InputPowerOfTwo; ++index)
				{
					shift_m = (1 << index);
					half_shift_m = shift_m / 2;

					for(std::int32_t loop_row = 0; loop_row < static_cast<std::int32_t>(rows); loop_row += shift_m)
					{
						truth_table_index = loop_row;
						truth_table_index2 = loop_row + half_shift_m;
						for(std::int32_t index2 = 0; index2 < half_shift_m; ++index2, ++truth_table_index, ++truth_table_index2)
						{
							a = truth_table_with_walsh_hadamard_transformed[truth_table_index][loop_column];
							b = truth_table_with_walsh_hadamard_transformed[truth_table_index2][loop_column];
							truth_table_with_walsh_hadamard_transformed[truth_table_index][loop_column] = a + b;
							truth_table_with_walsh_hadamard_transformed[truth_table_index2][loop_column] = a - b;
						}
					}
				}
			}

			return truth_table_with_walsh_hadamard_transformed;
		}

		//Meaningful hint: You need to use the LinearCombinations function first and then use this function
		//有意义的提示：你需要先使用LinearCombinations函数，然后再使用这个函数。
		std::vector<std::vector<std::int32_t>> WalshHadamardTransformNativeVersion
		(
			const std::unique_ptr< std::unique_ptr<std::uint8_t[]>[] >& linear_lines_truth_table
		)
		{
			std::int32_t answer = 0;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1;

			std::vector<std::vector<std::int32_t>> truth_table_with_walsh_hadamard_transformed(rows, std::vector<std::int32_t>(columns, 0));

			for(std::int32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				for(std::int32_t loop_row = 0; loop_row < rows; loop_row++)
				{
					for(std::int32_t loop_row2 = 0; loop_row2 < rows; loop_row2++)
					{
						answer += ( ( static_cast<std::int32_t>( linear_lines_truth_table[loop_row2][loop_column] ) ^ InnerProduct(loop_row, loop_row2) ) == 1 ) ? -1 : 1;
 					}
					truth_table_with_walsh_hadamard_transformed[loop_row][loop_column] = answer;
					answer = 0;
				}
			}

			return truth_table_with_walsh_hadamard_transformed;
		}

		/*
			Meaningful hint: You need to use the LinearCombinations function first and then use this function
			有意义的提示：你需要先使用LinearCombinations函数，然后再使用这个函数。
			
			Autocorrelation, sometimes known as serial correlation in the discrete time case, is the correlation of a signal with a delayed copy of itself as a function of delay. 
			Informally, it is the similarity between observations as a function of the time lag between them. 
			The analysis of autocorrelation is a mathematical tool for finding repeating patterns,
			such as the presence of a periodic signal obscured by noise, or identifying the missing fundamental frequency in a signal implied by its harmonic frequencies. 
			It is often used in signal processing for analyzing functions or series of values, such as time domain signals.
			Different fields of study define autocorrelation differently, and not all of these definitions are equivalent. In some fields, the term is used interchangeably with autocovariance.
			Unit root processes, trend-stationary processes, autoregressive processes, and moving average processes are specific forms of processes with autocorrelation.
			自相关，在离散时间的情况下有时被称为串行相关，是信号与自身的延迟拷贝的相关性，是延迟的函数。
			非正式地说，它是观察结果之间的相似性作为它们之间的时间滞后的函数。
			自相关的分析是一种寻找重复模式的数学工具，
			如被噪声掩盖的周期性信号的存在，或识别信号中由其谐波频率暗示的缺失的基本频率。
			它经常被用于信号处理中，用于分析函数或数值系列，如时域信号。
			不同的研究领域对自相关的定义不同，而且并非所有这些定义都是等同的。在一些领域，该术语可与自变量互换使用。
			单位根过程、趋势稳定过程、自回归过程和移动平均过程是具有自相关的过程的具体形式。

			https://en.wikipedia.org/wiki/Autocorrelation
		*/
		std::vector<std::vector<std::int32_t>> Autocorrelation
		(
			const std::vector<std::vector<std::uint8_t>>& linear_lines_truth_table
		)
		{
			//This function is not unique, the output is used to give arguments to the (sum-of-squares indicator) function
			//这个函数不是唯一的，输出用于给那个(平方数之和的指标)函数提供参数

			std::int32_t answer = 0;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1;

			std::vector<std::vector<std::int32_t>> already_autocorrelation_value(rows, std::vector<std::int32_t>(columns, 0));

			//Going through all autocorrelation elements
			//穿过所有自相关元素
			for(std::int32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				for(std::int32_t loop_row = 0; loop_row < rows; loop_row++)
				{
					for(std::int32_t loop_row2 = 0; loop_row2 < rows; loop_row2++)
					{
						answer += ( ( static_cast<std::int32_t>( linear_lines_truth_table[loop_row2][loop_column] ) ^ linear_lines_truth_table[loop_row ^ loop_row2][loop_column] ) == 1 ) ? -1 : 1;
 					}
					already_autocorrelation_value[loop_row][loop_column] = answer;
					answer = 0;
				}
			}

			return already_autocorrelation_value;
		}

		//Meaningful hint: You need to use the WalshHadamardTransform function first and then use this function
		//有意义的提示：你需要先使用WalshHadamardTransform函数，然后再使用这个函数。
		std::vector<std::vector<std::int32_t>> AutocorrelationFastVersion
		(
			const std::vector<std::vector<std::int32_t>>& truth_table_with_walsh_hadamard_transformed
		)
		{
			//This function is not unique, the output is used to give arguments to the (sum-of-squares indicator) function
			//这个函数不是唯一的，输出用于给那个(平方数之和的指标)函数提供参数

			std::int32_t shift_m, half_shift_m, truth_table_index, truth_table_index2, a, b;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1;

			std::vector<std::vector<std::int32_t>> already_autocorrelation_value(rows, std::vector<std::int32_t>(columns, 0));

			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				for(std::uint32_t loop_row = 0; loop_row < rows; ++loop_row)
				{
					AutoFloatingType power_of_2_and_truth_table_with_walsh_hadamard_transformed = ::pow(truth_table_with_walsh_hadamard_transformed[loop_row][loop_column], 2);
					already_autocorrelation_value[loop_row][loop_column] = static_cast<std::int32_t>( static_cast<AutoFloatingType>(-1) * power_of_2_and_truth_table_with_walsh_hadamard_transformed );
				}

				//做沃尔什-哈达玛德变换
				//Do Walsh Hadamard Transform
				for(std::uint32_t index = 1; index <= InputPowerOfTwo; ++index)
				{
					shift_m = (1 << index);
					half_shift_m = shift_m / 2;

					for(std::int32_t loop_row = 0; loop_row < static_cast<std::int32_t>(rows); loop_row += shift_m)
					{
						truth_table_index = loop_row;
						truth_table_index2 = loop_row + half_shift_m;
						for(std::int32_t index2 = 0; index2 < half_shift_m; ++index2, ++truth_table_index, ++truth_table_index2)
						{
							a = already_autocorrelation_value[truth_table_index][loop_column];
							b = already_autocorrelation_value[truth_table_index2][loop_column];
							already_autocorrelation_value[truth_table_index][loop_column] = a + b;
							already_autocorrelation_value[truth_table_index2][loop_column] = a - b;
						}
					}
				}

				for(std::uint32_t loop_row = 0; loop_row < rows; ++loop_row)
				{
					already_autocorrelation_value[loop_row][loop_column] /= static_cast<std::int32_t>(Shift_InputSize * -1);
				}
			}

			return already_autocorrelation_value;
		}

		/*
			
			Meaningful hint: You need to use the LinearCombinations function first and then use this function
			有意义的提示：你需要先使用LinearCombinations函数，然后再使用这个函数。

			In mathematics and mathematical logic, Boolean algebra is the branch of algebra in which the values of the variables are the truth values true and false, usually denoted 1 and 0, respectively.
			Instead of elementary algebra, where the values of the variables are numbers and the prime operations are addition and multiplication,
			the main operations of Boolean algebra are the conjunction (and) denoted as ∧, the disjunction (or) denoted as ∨, and the negation (not) denoted as ¬.
			It is thus a formalism for describing logical operations, in the same way that elementary algebra describes numerical operations.
			Boolean algebra was introduced by George Boole in his first book The Mathematical Analysis of Logic [1](1847),
			and set forth more fully in his An Investigation of the Laws of Thought (1854).
			[2] According to Huntington, the term "Boolean algebra" was first suggested by Sheffer in 1913,[3]
			although Charles Sanders Peirce gave the title "A Boolean Algebra with One Constant" to the first chapter of his "The Simplest Mathematics" in 1880.[4]
			Boolean algebra has been fundamental in the development of digital electronics, and is provided for in all modern programming languages. It is also used in set theory and statistics.[5]
			在数学和数理逻辑中，布尔代数是代数的一个分支，其中变量的值是真值真和假，通常分别表示为1和0。
			在初级代数中，变量的值是数字，主要运算是加法和乘法，而布尔代数的主要运算是连词（and），表示为∧，离词（or）表示为∨，否定（not）表示为¬。
			因此，它是一种描述逻辑运算的形式主义，就像初级代数描述数字运算一样。
			布尔代数是由乔治-布尔在他的第一本书《逻辑的数学分析》(1847)中提出的，并在他的《思想规律的研究》(1854)中得到更全面的阐述。
			根据亨廷顿的说法，"布尔代数 "一词是由谢弗在1913年首次提出的，尽管查尔斯-桑德斯-皮尔斯在1880年为他的《最简单的数学》的第一章起了 "有一个常数的布尔代数 "的标题。
			布尔代数在数字电子学的发展中一直是基础，所有现代编程语言都有规定。它也被用于集合理论和统计学。

			https://en.wikipedia.org/wiki/Boolean_algebra

			In Boolean algebra, the algebraic normal form (ANF), ring sum normal form (RSNF or RNF), Zhegalkin normal form, or Reed–Muller expansion is a way of writing logical formulas in one of three subforms:
			The entire formula is purely true or false: {1 , 0}
			One or more variables are ANDed together into a term, then one or more terms are XORed together into ANF. No NOTs are permitted:
			a ⊕ b ⊕ ab ⊕ abc
			or in standard propositional logic symbols:
			a ∨ b ∨ (a ∧ b) ∨ (a ∧ b ∧ c)
			The previous subform with a purely true term:
			1 ⊕ a ⊕ b ⊕ ab ⊕ abc
			Formulas written in ANF are also known as Zhegalkin polynomials (Russian: полиномы Жегалкина) and Positive Polarity (or Parity) Reed–Muller expressions (PPRM).
			在布尔代数中，代数正常形式（ANF）、环和正常形式（RSNF或RNF）、Zhegalkin正常形式或Reed-Muller扩展是以三种子形式之一来写逻辑公式的方法。
			整个公式是纯粹的真或假。{1 , 0}
			一个或多个变量被AND到一起成为一个项，然后一个或多个项被XOR到一起成为ANF。不允许出现NOT。
			a ⊕ b ⊕ ab ⊕ abc
			或者用标准的命题逻辑符号。
			a ∨ b ∨ (a ∧ b) ∨ (a ∧ b ∧ c)
			前面的子表格有一个纯粹的真实项。
			1 ⊕ a ⊕ b ⊕ ab ⊕ abc
			用ANF写的公式也被称为哲加尔金多项式（俄语：полиномы Жегалкина）和正极性（或奇偶性）里德-穆勒表达式（PPRM）。

			https://en.wikipedia.org/wiki/Algebraic_normal_form

		*/
		std::vector<std::vector<std::int32_t>> AlgebraicNormalForm
		(
			const std::vector<std::vector<std::uint8_t>>& linear_lines_truth_table
		)
		{
			std::uint32_t rows = 1 << (InputPowerOfTwo - 1), columns = Shift_OutputSize - 1;
			std::vector<std::int32_t> pointer_u(rows, 0);
			std::vector<std::int32_t> pointer_t(rows, 0);

			std::vector<std::vector<std::int32_t>> already_algebraic_normal_form_value(Shift_InputSize, std::vector<std::int32_t>(Shift_OutputSize - 1, 0));

			for (std::uint32_t loop_column = 0; loop_column < columns; ++loop_column)
			{
				for (std::uint32_t loop_row = 0, index = 0; loop_row < (rows << 1) - 1; ++loop_row, ++index)
				{
					if(index == linear_lines_truth_table[0].size())
						index = 0;
					already_algebraic_normal_form_value[loop_row][loop_column] = static_cast<std::int32_t>( linear_lines_truth_table[loop_row][index] );
				}

				for (std::uint32_t round = 0; round < InputPowerOfTwo; ++round)
				{
					for (std::uint32_t loop_row = 0; loop_row < rows; ++loop_row)
					{
						pointer_t[loop_row] = already_algebraic_normal_form_value[2 * loop_row][loop_column];
						pointer_u[loop_row] = (already_algebraic_normal_form_value[2 * loop_row][loop_column] == already_algebraic_normal_form_value[2 * loop_row + 1][loop_column]) ? 0 : 1;
					}
					for (std::uint32_t loop_row = 0; loop_row < rows; ++loop_row)
					{
						already_algebraic_normal_form_value[loop_row][loop_column] = pointer_t[loop_row];
						already_algebraic_normal_form_value[rows + loop_row][loop_column] = pointer_u[loop_row];
					}
				}
			}

			pointer_u.clear();
			pointer_u.shrink_to_fit();
			pointer_t.clear();
			pointer_t.shrink_to_fit();

			return already_algebraic_normal_form_value;
		}

	protected:

		std::int32_t GetOneBit(std::int32_t data, std::int32_t position)
		{
			return ( (data >> position) & 0x01 );
		}

		std::int32_t SetOneBit(std::int32_t data, std::int32_t position)
		{
			return ( data | (0x01 << position) );
		}

		//Inner product function: input is 2 int-type data, bitLength or M_InputDimension is the length of inner product, counting from 0
		//内积函数：输入为2个int32型数据，bitLength 或 M_InputDimension为内积的长度，从0计数
		std::int32_t InnerProduct(std::int32_t a, std::int32_t b)
		{
			std::uint32_t answer = 0;

			for(std::uint32_t index = 0; index < InputPowerOfTwo; index++)
			{
				answer ^= ( GetOneBit(a, index) & GetOneBit(b, index));
			}
			return answer;
		}

		//Compute the balance of the byte substitution box
		//计算字节代换盒的平衡性
		//Meaningful hint: You need to use the WalshHadamardTransform function first and then use this function
		//有意义的提示：你需要先使用WalshHadamardTransform函数，然后再使用这个函数。
		std::int32_t ComputeBalance
		(
			const std::vector<std::vector<std::int32_t>>& truth_table_with_walsh_hadamard_transformed
		)
		{
			std::uint32_t answer = 0;
			std::uint32_t columns = Shift_OutputSize - 1;;
			
			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				if(truth_table_with_walsh_hadamard_transformed[0][columns] != 0)
					++answer;
			}
			return answer;
		}

		//Meaningful hint: You need to use the ComputeTruthTable function first and then use this function
		//有意义的提示：你需要先使用ComputeTruthTable函数，然后再使用这个函数
		std::int32_t ComputeBalanceNativeVersion(const std::vector<std::uint32_t>& truth_table_with_math_boolean_function)
		{
			//just counts zeros/ones
			//只计算零/一
			std::uint32_t answer = 0;

			for(std::uint32_t index = 0; index < Shift_InputSize; index++)
			{
				if(truth_table_with_math_boolean_function[index] == 0) //count zeros
					answer += 1;
			}

			if( answer == (1 << (InputPowerOfTwo - 1) ) )
				return 0;
			else
				return Shift_InputSize - answer; //number of units
		}

		//You need to calculate the value of byte substitution box balance first, and then check the byte substitution box balance
		//你需要先计算字节替换盒平衡性的值，然后再检查字节替换盒平衡性
		//Meaningful hint: You need to use the ComputeBalance function first and then use this function
		//有意义的提示：你需要先使用ComputeBalance函数，然后再使用这个函数
		BalancednessType CheckBalancednessOfSize(std::int32_t balance_value)
		{
			if(balance_value == 0)
			{
				if(OutputPowerOfTwo > 1)
					return BalancednessType::SubstitutionBoxIsBalanced;
				else
					return BalancednessType::MathBooleanFunctionIsBalanced;
			}
			else
			{
				if(OutputPowerOfTwo > 1)
					return BalancednessType::SubstitutionBoxIsUnbalanced;
				else
					return BalancednessType::MathBooleanFunctionIsUnbalanced;
			}
		}

		/*
			
			Note: I want to give a simple example, for example, the length of the byte substitution box is 256, then you should be the number 1 for binary left shift corresponding multiplier equal to 256, and here the length of the byte substitution box 256 for binary right shift corresponding multiplier plus one.

			Because this left-shift and right-shift operation is calculated must be equal on both sides to be used as a parameter.
			That is, this multiplier is best calculated manually, such as this: (256 == 1 << 8 ) and (8 == 256 >> 5)
			So for this array of length 256, then this parameter should be 8.

			注意事项：我要举一个简单的例子，比如说字节代换盒的长度是256，那么你应该是数字1进行二进制左移相应的倍数等于256，而这里的字节代换盒的长度256进行二进制右移相应的倍数加一。

			因为这个左移和右移的操作算出来必须两边相等才能作为参数。
			也就是这个倍数最好手动计算出来，比如像这样： (256 == 1 << 8 ) 和（8 == 256 >> 5）
			所以对于256长度的这个数组，那么这个参数应该是8。
		
		*/

		//Size of one-dimensional byte substitution box
		//一维字节代换盒的大小
		const std::size_t ByteSubstitutionBoxSize;

		//Value M - InputDimension
		//The size of the "input" byte-substitution box, given to the logarithmic function and in base 2
		//”输入“字节代换盒的大小，给对数函数处理并且以2为基数
		const std::uint32_t InputPowerOfTwo;

		//Value N - OutputDimension
		//The size of the "output" byte-substitution box, given to the logarithmic function and in base 2
		//”输出“字节代换盒的大小，给对数函数处理并且以2为基数
		const std::uint32_t OutputPowerOfTwo;

		//Shift Value M
		//Row dimensions of a matrix of two-dimensional mathematical Boolean functions (This is determined by shifting the previous multiplier in binary, or what can be called a power function calculation with base 2.)
		//二维数学布尔函数的矩阵的行尺寸(根据之前的倍数进行二进制移位确定，或者可以称之为以2为基数的幂函数计算。)
		const std::uint32_t Shift_InputSize;

		//Shift Value N
		//Column dimensions of a matrix of two-dimensional mathematical Boolean functions (This is determined by shifting the previous multiplier in binary, or what can be called a power function calculation with base 2.)
		//二维数学布尔函数的矩阵的列尺寸(根据之前的倍数进行二进制移位确定，或者可以称之为以2为基数的幂函数计算。)
		const std::uint32_t Shift_OutputSize;

		//The binary Hamming weight lookup table (size is determined by the row size or column size of the matrix of the previous 2-D mathematical Boolean function)
		//One of their values (Shift_M or Shift_N) must match the size of the byte substitution box, otherwise the values of M and matrix_rows are illegal.
		//二进制汉明权重查找表(大小根据之前二维数学布尔函数的矩阵的行尺寸或列尺寸确定)
		//它们其中一个值(Shift_M或Shift_N)必须其中匹配字节代换盒的大小，否则M和N的值是非法的。
		std::vector<std::uint32_t> HammingWeightArray;

		std::vector<std::uint32_t> ByteSubstitutionBoxArray;

		/*
			The Hamming weight of a string is the number of symbols that are different from the zero-symbol of the alphabet used.
			It is thus equivalent to the Hamming distance from the all-zero string of the same length. For the most typical case,
			a string of bits, this is the number of 1's in the string, or the digit sum of the binary representation of a given number and the ℓ₁ norm of a bit vector. 
			In this binary case, it is also called the population count,[1] popcount, sideways sum,[2] or bit summation

			一个字符串的汉明权重是指与所用字母表的零符号不同的符号数量。
			因此，它等同于与相同长度的全零字符串的汉明距离。对于最典型的情况。
			对于最典型的情况，即一串比特，它是该串中1的数量，或者是一个给定数字的二进制表示和一个比特向量的ℓ norm的数字之和。 
			在这种二进制的情况下，它也被称为population count，[1] popcount，sideways sum，[2] 或 bit summation。

			https://en.wikipedia.org/wiki/Hamming_weight
		*/
		std::int32_t HammingWeight(std::int32_t number)
		{
			std::int32_t answer = 0;
			while (number > 0)
			{
				answer = answer + (number & 0x01);
				number = number >> 1;
			}
			return answer;
		}

		void HammingWeights(std::vector<std::uint32_t>& hamming_weight_datas, std::size_t hamming_weight_size)
		{
			if(hamming_weight_datas.size() != hamming_weight_size)
				my_cpp2020_assert(false, "The data of this substitution box does not match the size!", std::source_location::current());

			for(std::uint32_t index = 0; index < Shift_InputSize; index++)
			{
				hamming_weight_datas[index] = HammingWeight(index);
			}
		}

		BaseFunctions(std::size_t ByteSubstitutionBoxSizeValue, std::uint32_t M, std::uint32_t N)
			: 
			InputPowerOfTwo(M), OutputPowerOfTwo(N),
			Shift_InputSize(1 << InputPowerOfTwo), Shift_OutputSize(1 << OutputPowerOfTwo),
			ByteSubstitutionBoxSize(ByteSubstitutionBoxSizeValue)
		{
			std::uint32_t HammingWeightArraySize = 0;
			if(Shift_InputSize == ByteSubstitutionBoxSize)
				HammingWeightArraySize = Shift_InputSize;
			else if(Shift_OutputSize == ByteSubstitutionBoxSize)
				HammingWeightArraySize = Shift_OutputSize;
			else
				my_cpp2020_assert(false, "Oops, Shift_InputSize(Rows) number and Shift_OutputSize(Columns) number is not match ByteSubstitutionBoxSize", std::source_location::current());

			HammingWeightArray = std::move(std::vector<std::uint32_t>(HammingWeightArraySize, 0));
			HammingWeights(HammingWeightArray, HammingWeightArraySize);
		}

		~BaseFunctions()
		{
			HammingWeightArray.clear();
			HammingWeightArray.shrink_to_fit();
			ByteSubstitutionBoxArray.clear();
			ByteSubstitutionBoxArray.shrink_to_fit();
		}
	};

	//字节替换盒的代数免疫度分析器
	//Algebraic immunity degree analyzer for byte Substitution boxes
	class AlgebraicImmunityDegreeAnalyzer : public BaseFunctions
	{

	private:

		//The numerical matrix that will be operated by the Boolean function of mathematics
		//将会被数学的布尔函数运算的数字矩阵
		struct NumberMatrix
		{
			const std::int32_t row_number;
			const std::int32_t column_number;

			std::vector<std::vector<int32_t>> number_matrix;

			void SwapColumns(std::int32_t a, std::int32_t b)
			{
				std::vector<int32_t> temporary_row_numbers(row_number, 0);
			
				for(std::int32_t index = 0; index < row_number; ++index)
				{
					temporary_row_numbers[index] = number_matrix[index][a];
				}

				for(std::int32_t index = 0; index < row_number; ++index)
				{
					number_matrix[index][a] = number_matrix[index][b];
				}

				for(std::int32_t index = 0; index < row_number; ++index)
				{
					number_matrix[index][b] = temporary_row_numbers[index];
				}

				temporary_row_numbers.clear();
				temporary_row_numbers.shrink_to_fit();
			}

			void AdditionWithTwoLine(std::int32_t destination_line, std::int32_t source_line)
			{
				for (std::int32_t loop_column = 0; loop_column < column_number; ++loop_column)
				{
					number_matrix[destination_line][loop_column] = ( number_matrix[destination_line][loop_column] + number_matrix[source_line][loop_column] ) & 1;
				}
			}

			NumberMatrix(std::int32_t row_value, std::int32_t column_value)
				:
				row_number(row_value), column_number(column_value),
				number_matrix(row_number, std::vector<std::int32_t>(column_number, 0))
			{
			
			}

			~NumberMatrix()
			{
				for(auto& number_array : number_matrix)
				{
					number_matrix.clear();
					number_array.shrink_to_fit();
				}

				number_matrix.clear();
				number_matrix.shrink_to_fit();
			}
		};

		std::int32_t NumberMatrixPerceqBitValue(std::int32_t a, std::int32_t b)
		{
			std::int32_t answer = 1;

			while ( (a > 0 || b > 0 ) && (answer == 1) )
			{
				if( (a & 1) > (b & 1) )
					answer = 0;
				a >>= 1;
				b >>= 1;
			}
			return answer;
		}

		//Find a table based on Hamming weights, then sort by increasing degree
		//根据汉明权重查找表，然后按照递增程度排序
		void SortIncreasingDegree
		(
			std::vector<std::int32_t>& datas,
			const std::int32_t& size
		)
		{
			for(std::int32_t index = 0; index < size - 1; ++index)
			{
				for(std::int32_t index2 = index + 1; index2 < size; ++index2)
				{
					if(HammingWeightArray[ datas[index2] ] < HammingWeightArray[ datas[index] ])
						std::swap(datas[index2], datas[index]);
				}
			}
		}

		//Build the array of values of the monomials
		//构建单项式的值的阵列
		std::vector<std::int32_t> BuildMonomialValueArray
		(
			std::int32_t number,
			std::int32_t degree,
			std::int32_t& reference_change_number
		)
		{
			reference_change_number = 0;

			//by Frederic Lafitte, from math boolean function
			//作者：弗雷德里克-拉菲特，来自数学布尔函数
			auto ChooseDegree = [](std::int32_t number, std::int32_t degree_value_k) -> std::int32_t
			{
				std::int32_t temporary_number = 1, ratio = 1;
				if( degree_value_k < 0 || degree_value_k > number )
					return 0;

				for( std::int32_t index = 0; index < degree_value_k; ++index )
				{
					temporary_number *= number--;
					ratio *= (degree_value_k - index);
				}
				return temporary_number / ratio;
			};

			for(std::int32_t degree_value_k = 0; degree_value_k <= degree; ++degree_value_k)
			{
				reference_change_number += ChooseDegree(number, degree_value_k);
			}

			std::vector<std::int32_t> answer_datas(reference_change_number, 0);

			std::int32_t size = 1 << number;
			for(std::int32_t answer_datas_index = 0, index = 0; index < size; ++index)
			{
				if(HammingWeightArray[index] <= degree)
					answer_datas[answer_datas_index++] = index;
			}
			return answer_datas;
		}

		//Calculating the supported truth table
		//计算受支持的真值表
		std::vector<std::int32_t> ComputeSupportTruthTable
		(
			const std::vector<std::vector<uint8_t>>& truth_table,
			std::int32_t number,
			std::int32_t& reference_change_number,
			std::int32_t bit
		)
		{
			my_cpp2020_assert( (bit == 0) || (bit == 1), "Numbers are not 0 or 1 in binary format!", std::source_location::current() );

			reference_change_number = 0;
			std::int32_t size = 1 << number;

			for(std::int32_t index = 0; index < size; ++index)
			{
				reference_change_number += ( truth_table[index][0] != bit );
			}

			std::vector<std::int32_t> answer_datas(reference_change_number, 0);
			
			for(std::int32_t degree_value_k = 0, index = 0; index < size; ++index)
			{
				if( truth_table[index][0] != bit )
					answer_datas[degree_value_k++] = index;
			}
			return answer_datas;
		}

		//Build a numerical matrix
		//构建数字矩阵
		void BuildNumberMatrix
		(
			std::unique_ptr<NumberMatrix>& number_matrix,
			const std::vector<std::vector<uint8_t>>& truth_table,
			std::int32_t number,
			std::vector<std::int32_t>& monomial_array,
			std::int32_t size_number_a,
			std::int32_t bit
		)
		{
			my_cpp2020_assert( (bit == 0) || (bit == 1), "Numbers are not 0 or 1 in binary format!", std::source_location::current() );

			std::int32_t size_number_b = 0;
			std::int32_t size = 1 << number;
			auto support_truth_table = ComputeSupportTruthTable(truth_table, number, size_number_b, bit);

			if(size_number_b == 0 || size_number_b == size)
			{
				if(number_matrix != nullptr)
				{
					number_matrix.reset();
					number_matrix = nullptr;
				}
				return;
			}
			else
			{
				number_matrix = (size_number_a > size_number_b) ? std::make_unique<NumberMatrix>(size_number_a, size_number_a) : std::make_unique<NumberMatrix>(size_number_a, size_number_b);

				NumberMatrix& pointer_reference = *(number_matrix.get());

				for (std::int32_t loop_row = 0; loop_row < size_number_a; ++loop_row)
				{
					for (std::int32_t loop_column = 0; loop_column < size_number_b; ++loop_column)
					{
						pointer_reference.number_matrix[loop_row][loop_column] = NumberMatrixPerceqBitValue( monomial_array[loop_row], support_truth_table[loop_column] );
					}
				}	
			}

			support_truth_table.clear();
			support_truth_table.shrink_to_fit();
		}

		//Solution of numerical matrix
		//求解数字矩阵
		std::int32_t SolutionOfNumericalMatrix
		(
			std::unique_ptr<NumberMatrix>& number_matrix_pointer,
			std::vector<std::int32_t>& monomial_array
		)
		{
			my_cpp2020_assert( number_matrix_pointer != nullptr, "The data pointer of the numeric matrix cannot be a null pointer!", std::source_location::current() );

			NumberMatrix& pointer_reference = *(number_matrix_pointer.get());
			std::int32_t matrix_rows = pointer_reference.row_number;
			std::int32_t matrix_columns = pointer_reference.column_number;

			std::unique_ptr<std::int32_t[]> degree_pointer = std::unique_ptr<std::int32_t[]>( new std::int32_t[matrix_rows] );
			std::int32_t answer = 0;

			for(std::int32_t loop_row = 0; loop_row < matrix_rows; ++loop_row)
			{
				degree_pointer[loop_row] = HammingWeightArray[ monomial_array[loop_row] ];
				if(degree_pointer[loop_row] > answer)
					answer = degree_pointer[loop_row];
			}

			std::int32_t processed_lines = 0, zero_lines = 0;
			for(std::int32_t loop_row = 0; loop_row < matrix_rows; ++loop_row)
			{
				for
				(
					std::int32_t loop_column = 0; 
					loop_column < matrix_columns && pointer_reference.number_matrix[loop_row][loop_column] == 0; 
					++loop_column
				)
				{
					if(loop_column == matrix_columns)
					{
						++zero_lines;
						if(degree_pointer[loop_row] < answer && degree_pointer[loop_row] != 0)
							answer = degree_pointer[loop_row];
					}
					else
					{
						++processed_lines;
						if
						(
							loop_row != loop_column &&
							loop_row < matrix_columns &&
							loop_column < matrix_columns
						)
						{
							pointer_reference.SwapColumns(loop_row, loop_column);
						}

						for
						(
							std::int32_t lines = loop_row + 1;
							lines < matrix_rows && loop_row < matrix_columns;
							++lines
						)
						{
							if( loop_row < matrix_columns && pointer_reference.number_matrix[lines][loop_row] != 0)
							{
								pointer_reference.AdditionWithTwoLine(lines, loop_row);
								degree_pointer[lines] = ( degree_pointer[loop_row] > degree_pointer[lines] ) ? degree_pointer[loop_row] : degree_pointer[lines];
							}
						}
					}
				}
			}

			degree_pointer.reset();
			return answer;
		}

	public:

		//by Frederic Lafitte, from math boolean function
		//作者：弗雷德里克-拉菲特，来自数学布尔函数
		//Compute the degree of algebraic immunity of byte substitution boxes
		//计算字节替换盒的代数免疫程度
		//Meaningful hint: You need to use the LinearCombinations function first and then use this function
		//有意义的提示：你需要先使用LinearCombinations函数，然后再使用这个函数。
		std::pair<std::int32_t, std::vector<std::uint32_t>> ComputeWorker
		(
			const std::vector<std::vector<uint8_t>>& linear_lines_truth_table
		)
		{
			std::unique_ptr<NumberMatrix> matrix_pointer = nullptr, matrix2_pointer = nullptr;
			std::int32_t a = 0, b = 0, current_answer = 0, degree_value = 0, Nm = 0;
			std::uint32_t answer = 100000, columns = Shift_OutputSize - 1;
			std::vector<std::uint32_t> boolean_components(columns, 0);

			degree_value = (InputPowerOfTwo >> 1) + (InputPowerOfTwo & 1);
			std::vector<std::int32_t> monomial_datas = BuildMonomialValueArray(InputPowerOfTwo, degree_value, Nm);
			SortIncreasingDegree(monomial_datas, Nm);

			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				 BuildNumberMatrix(matrix_pointer, linear_lines_truth_table, InputPowerOfTwo, monomial_datas, Nm, 0);
				 if(matrix_pointer == nullptr)
					current_answer = 0;
				 else
				 {
					BuildNumberMatrix(matrix2_pointer, linear_lines_truth_table, InputPowerOfTwo, monomial_datas, Nm, 1);
					a = SolutionOfNumericalMatrix(matrix_pointer, monomial_datas);
					b = SolutionOfNumericalMatrix(matrix2_pointer, monomial_datas);
					current_answer = std::min(a, b);
				 }
				 boolean_components[loop_column] = current_answer;
				 answer = current_answer < answer ? current_answer : answer;
			}

			monomial_datas.clear();
			monomial_datas.shrink_to_fit();
			matrix_pointer.reset();
			matrix2_pointer.reset();

			return std::pair<std::uint32_t, std::vector<std::uint32_t>>(answer, boolean_components);
		}

		AlgebraicImmunityDegreeAnalyzer(std::span<std::uint8_t> ByteArray, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
			: BaseFunctions::BaseFunctions(ByteArray.size(), InputSize, OutputSize)
		{
			my_cpp2020_assert( (InputSize != 0) && (OutputSize != 0), "The data size of this substitution box is not empty!", std::source_location::current() );
			ByteSubstitutionBoxArray = std::move(std::vector<std::uint32_t>(ByteArray.begin(), ByteArray.end()));
		}

		~AlgebraicImmunityDegreeAnalyzer() = default;

	};

	struct SecurityEvaluationAnalyzer : public BaseFunctions
	{
		/* Byte Substitution Box Properties Function */

		//Indicator for compute the absolute value of the byte substitution box
		//计算字节代换盒的绝对值的指标
		//Meaningful hint: You need to use the Autocorrelation function first and then use this function
		//有意义的提示：你需要先使用Autocorrelation函数，然后再使用这个函数。
		std::pair<std::uint32_t, std::vector<std::uint32_t>> AbsoluteValueIndicator
		(
			const std::vector<std::vector<std::int32_t>>& already_autocorrelation_value
		)
		{
			// If the answer is the smaller it is, the better.
			std::uint32_t answer = 0, temporary_value = 0, temporary_value2 = 0;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1;
			std::vector<std::uint32_t> boolean_components(columns, 0);

			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				//Disregard first value since it is 2^n
				//不考虑第一个值，因为它是2^n
				temporary_value = std::abs( already_autocorrelation_value[1][loop_column]);
				for(std::uint32_t loop_row = 2; loop_row < rows; loop_row++)
				{
					temporary_value2 = std::abs( already_autocorrelation_value[loop_row][loop_column]);
					temporary_value = std::max(temporary_value2, temporary_value);
				}
				boolean_components[loop_column] = temporary_value;
				answer = std::max(temporary_value, answer);
			}

			return std::pair<std::uint32_t, std::vector<std::uint32_t>>(answer, boolean_components);
		}

		//Indicator for compute the sum of squares of byte substitution boxes
		//计算字节代换盒的平方数之和的指标
		//Meaningful hint: You need to use the Autocorrelation function first and then use this function
		//有意义的提示：你需要先使用Autocorrelation函数，然后再使用这个函数。
		std::pair<std::uint32_t, std::vector<std::uint32_t>> SumOfSquareValueIndicator
		(
			const std::vector<std::vector<std::int32_t>>& already_autocorrelation_value
		)
		{
			// If the answer is the smaller it is, the better.
			std::uint32_t answer = 0, sum = 0;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1;
			std::vector<std::uint32_t> boolean_components(columns, 0);

			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				for(std::uint32_t loop_row = 2; loop_row < rows; loop_row++)
				{
					sum += static_cast<std::uint32_t>( ::pow(already_autocorrelation_value[loop_row][loop_column], 2) );
				}
				boolean_components[loop_column] = sum;
				answer = std::max(sum, answer);
				sum = 0;
			}

			return std::pair<std::uint32_t, std::vector<std::uint32_t>>(answer, boolean_components);
		}

		//Compute the algebraic degree of the byte substitution box
		//计算字节替换盒的代数程度
		//Meaningful hint: You need to use the ComputeAlgebraicNormalForm function first and then use this function
		//有意义的提示：你需要先使用ComputeAlgebraicNormalForm函数，然后再使用这个函数。
		std::pair<std::int32_t, std::vector<std::uint32_t>> ComputeAlgebraicDegree
		(
			const std::vector<std::vector<std::int32_t>>& already_algebraic_normal_form_value
		)
		{
			std::int32_t temporary_value = 0, weight_value = 0, degree_value = 0;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1, answer = 0;
			std::vector<std::uint32_t> boolean_components(columns, 0);

			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				if(already_algebraic_normal_form_value[rows - 1][loop_column] != 0)
					degree_value = InputPowerOfTwo;
				else
				{
					degree_value = 0;
					for(std::uint32_t loop_row = 1; loop_row < (rows - 1); ++loop_row)
					{
						if(already_algebraic_normal_form_value[loop_row][loop_column] != 0)
						{
							weight_value = 0;
							for(temporary_value = loop_row; temporary_value > 0; temporary_value >>= 1)
								weight_value = weight_value + temporary_value % 2;
							degree_value = std::max(weight_value, degree_value);
						}
					}
				}
				boolean_components[loop_column] = static_cast<std::uint32_t>(degree_value);
				answer = std::max(boolean_components[loop_column], answer);
			}

			return std::pair<std::int32_t, std::vector<std::uint32_t>>(static_cast<std::int32_t>(answer), boolean_components);
		}

		//Compute the difference distribution table for byte substitution boxes
		//计算字节替换盒的差异分布表(DDT)
		std::vector<std::vector<std::uint32_t>> ComputeDifferentialDistributionTable()
		{
			std::uint32_t rows = Shift_InputSize;
			std::uint32_t columns = Shift_OutputSize;

			std::vector<std::vector<std::uint32_t>> DD_Matrix(rows, std::vector<std::uint32_t>(columns, 0));

			for (std::uint32_t loop_row = 0; loop_row < rows; ++loop_row)
			{
				for (std::uint32_t loop_column = 0; loop_column < columns; ++loop_column)
				{
					auto& value = DD_Matrix[loop_row ^ loop_column][ ByteSubstitutionBoxArray[loop_row] ^ ByteSubstitutionBoxArray[loop_column] ];
					++value;
				}
			}
			return DD_Matrix;
		}

		//Compute linear approximation table for byte substitution box
		//计算字节替换盒的线性近似表(LAT)
		std::vector<std::vector<std::uint32_t>> ComputeLinearApproximationTable()
		{
			std::uint32_t rows = Shift_InputSize;
			std::uint32_t columns = Shift_OutputSize;

			std::vector<std::vector<std::uint32_t>> LA_Matrix(rows, std::vector<std::uint32_t>(columns, 0));

			for (std::uint32_t index = 0; index < rows; ++index)
			{
				for (std::uint32_t index2 = 0, loops = rows > columns ? columns : rows; index2 < loops; ++index2)
				{
					for(std::uint32_t index3 = 0; index3 < rows; index3 += 8)
					{
						auto& value = LA_Matrix[index][index2];

						//if ((hamming_weight (loop_row2 & loop_row) + hamming_weight(s_box[loop_row2] & loop_column)) % 2 == 0)
						if( ( ( HammingWeightArray[index3 & index] + HammingWeightArray[ ByteSubstitutionBoxArray[index3] & index2 ] ) & 1 ) == 0 )
							++value;

						for(std::uint32_t counter = 1; counter < 8; ++counter )
						{
							if( ( ( HammingWeightArray[ (index3 + counter) & index ] + HammingWeightArray[ ByteSubstitutionBoxArray[index3 + counter] & index2 ] ) & 1 ) == 0 )
								++value;
						}
					}
				}
			}

			return LA_Matrix;
		}

		//Computes the differential approximation probability table for the byte-substitution box
		//计算字节代换盒的微分近似概率表(DAPT)
		std::vector<std::vector<std::uint32_t>> ComputeDifferentialApproximationProbabilityTable()
		{
			std::uint32_t rows = Shift_InputSize;
			std::uint32_t columns = Shift_OutputSize;

			std::vector<std::vector<std::uint32_t>> DAP_Matrix(rows, std::vector<std::uint32_t>(columns, 0));

			for (std::uint32_t loop_row = 1; loop_row < rows; ++loop_row)
			{
				for (std::uint32_t loop_column = 0; loop_column < columns; ++loop_column)
				{
					for(std::uint32_t index = 0; index < rows; ++index)
					{
						if((ByteSubstitutionBoxArray[index] ^ ByteSubstitutionBoxArray[index ^ loop_row]) == loop_column)
							++DAP_Matrix[loop_row][loop_column];
					}
				}
			}

			std::vector<std::uint32_t> DAP_AnswerValueArray(rows * columns, 0);
			for (std::uint32_t loop_row = 1; loop_row < rows; ++loop_row)
			{
				for (std::uint32_t loop_column = 0; loop_column < columns; ++loop_column)
				{
					DAP_AnswerValueArray[loop_row - 1] = std::max(DAP_AnswerValueArray[loop_row - 1], DAP_Matrix[loop_row][loop_column]);
				}
			}

			for( std::size_t loop_row = 0; loop_row < DAP_Matrix.size(); ++loop_row )
			{
				auto& DAP_Array = DAP_Matrix[loop_row];
				for( std::size_t loop_column = 0; loop_column < DAP_Array.size(); ++loop_column )
				{
					DAP_Array[loop_column] = DAP_AnswerValueArray[loop_row * DAP_Array.size() + loop_column];
				}
			}

			DAP_AnswerValueArray.clear();
			DAP_AnswerValueArray.shrink_to_fit();

			std::size_t ZeroValue_DAP_ArrayCounter = 0;
			for(auto last = DAP_Matrix.rbegin(), first = DAP_Matrix.rend(); last != first; ++last)
			{
				if(*last == std::vector<std::uint32_t>(columns, 0))
					++ZeroValue_DAP_ArrayCounter;
			}
			DAP_Matrix.resize(DAP_Matrix.size() - ZeroValue_DAP_ArrayCounter);

			return DAP_Matrix;
		}

		//Computing Robustness to Differential Cryptanalysis
		//计算对差分(微分)密码分析的稳健性
		//Compute delta uniformity
		//计算德尔塔均匀性
		std::pair<std::int32_t, AutoFloatingType> Compute_DeltaUniformity_Robustness()
		{
			std::uint32_t delta_uniformity_value = 0, ratio = 0;
			AutoFloatingType robustness_value = 0.0;
			std::uint32_t rows = Shift_InputSize;
			std::uint32_t columns = Shift_OutputSize;

			auto DD_Matrix = ComputeDifferentialDistributionTable();

			for (std::uint32_t loop_row = 0; loop_row < rows; ++loop_row)
			{
				for (std::uint32_t loop_column = 0; loop_column < columns; ++loop_column )
				{
					if (DD_Matrix[loop_row][loop_column] > delta_uniformity_value && (loop_row != 0 && loop_column != 0))
						delta_uniformity_value = DD_Matrix[loop_row][loop_column];	
				}
			}

			for (std::uint32_t index = 1; index < Shift_OutputSize; ++index)
			{
				if (DD_Matrix [index][0] != 0)
					++ratio;
			}
			robustness_value = (1 - ( ratio / static_cast<AutoFloatingType>(Shift_InputSize) )) * static_cast<AutoFloatingType>( 1 - ( delta_uniformity_value / static_cast<AutoFloatingType>(Shift_InputSize) ) );

			for(auto& DD_Array : DD_Matrix )
			{
				DD_Array.clear();
				DD_Array.shrink_to_fit();
			}

			DD_Matrix.clear();
			DD_Matrix.shrink_to_fit();

			return std::pair<std::int32_t, AutoFloatingType>(delta_uniformity_value, robustness_value);
		}

		//Compute the number of fixed points
		//计算固定点的数量
		std::uint32_t ComputeNumberOfFixedPoints(bool print_console)
		{
			std::uint32_t answer = 0;

			auto print_format = std::cout.flags();

			for (std::uint32_t index = 0; index < Shift_InputSize; index++)
			{
				if ((ByteSubstitutionBoxArray[index] ^ index) == 0)
				{
					answer++;
					if (print_console)
						std::cout << "Fixed point is " << std::hex << ByteSubstitutionBoxArray[index] << std::cout.flags(print_format) << " on position " << index << std::endl;
				}
			}

			return answer;
		}

		//Calculate the number of fixed points on the opposite side
		//计算对面固定点的数量
		std::uint32_t ComputeOppositeNumberOfFixedPoints(bool print_console)
		{
			std::uint32_t answer = 0;

			auto print_format = std::cout.flags();

			for (std::uint32_t index = 0; index < Shift_InputSize; index++)
			{
				if (ByteSubstitutionBoxArray[index] == ( ~index & (Shift_InputSize - 1) ) )
				{
					answer++;
					if (print_console)
						std::cout << "Opposite fixed point is " << std::hex << ByteSubstitutionBoxArray[index] << std::cout.flags(print_format) << " on position " << index << std::endl;
				}
			}

			return answer;
		}

		AutoFloatingType ComputeTransparencyOrderFastVersion()
		{
			AutoFloatingType answer = 0.0f;
			AutoFloatingType temporary_value = 0.0f, sigma_value = 0.0f, sigma2_value = 0.0f, threshold_value = 0.0f;
			AutoFloatingType AdderNumbersOfSigma2 = 0.0f;
			AutoFloatingType DifferenceValue = static_cast<AutoFloatingType>( ( 1 << (2 * OutputPowerOfTwo) ) - Shift_OutputSize );
			AutoFloatingType MultiplicationProduct = static_cast<AutoFloatingType>(OutputPowerOfTwo * Shift_OutputSize);

			for(std::uint32_t index_b = 0; index_b < Shift_OutputSize; ++index_b)
			{
				threshold_value = static_cast<AutoFloatingType>(OutputPowerOfTwo - 2 * HammingWeightArray[index_b]);
				if(threshold_value < 0)
					threshold_value *= (-1.0f);
				threshold_value = (threshold_value - answer) * DifferenceValue;
				
				if(threshold_value >= 0)
				{
					sigma2_value = 0.0f;
					for(std::uint32_t index_a = 1; index_a < Shift_OutputSize; ++index_a)
					{
						sigma_value = 0.0f;
						for(std::uint32_t data_byte_index = 0; data_byte_index < Shift_OutputSize; ++data_byte_index)
						{
							sigma_value += HammingWeightArray[ index_b ^ ( ByteSubstitutionBoxArray[data_byte_index] ^ ByteSubstitutionBoxArray[data_byte_index ^ index_a] ) ];
						}

						AdderNumbersOfSigma2 = MultiplicationProduct - 2 * sigma_value;
						if(sigma_value > threshold_value)
							break;
						temporary_value = threshold_value - (sigma_value / DifferenceValue);

						if(AdderNumbersOfSigma2 < 0)
							AdderNumbersOfSigma2 *= (-1.0f);
						sigma2_value += AdderNumbersOfSigma2;
					}

					//temporary_value = 2 * HammingWeight(index_b);
					temporary_value = 2 * HammingWeightArray[index_b];
					if(answer < std::abs( static_cast<AutoFloatingType>(OutputPowerOfTwo - temporary_value) ) - sigma2_value / DifferenceValue)
						answer = std::abs( static_cast<AutoFloatingType>(OutputPowerOfTwo - temporary_value) ) - sigma2_value / DifferenceValue;
				}
			}

			return answer;
		}

		//Compute the transparency order of byte-substitution box
		//计算字节代换盒的透明度顺序
		AutoFloatingType ComputeTransparencyOrder()
		{
			AutoFloatingType answer = 0.0f;
			AutoFloatingType sigma_value = 0.0f, temporary_value = 0.0f, sigma2_value = 0.0f, sigma3_value = 0.0f;
			AutoFloatingType DifferenceValue = static_cast<AutoFloatingType>( ( 1 << (2 * InputPowerOfTwo) ) - Shift_InputSize );

			if(OutputPowerOfTwo > 1)
				return ComputeTransparencyOrderFastVersion();

			for(std::uint32_t index_b = 0; index_b < Shift_OutputSize; ++index_b)
			{
				sigma_value = 0;
				for(std::uint32_t index_a = 1; index_a < Shift_InputSize; ++index_a)
				{
					sigma2_value = 0;

					//Can go from 1 since, we need Hamming weight to be 1
					//可以从1开始，因为我们需要汉明权重是1
					for(std::uint32_t counter = 1; counter < Shift_OutputSize; counter <<= 1)
					{
						sigma3_value = 0;
						for(std::uint32_t data_byte_index = 0; data_byte_index < Shift_InputSize; ++data_byte_index)
						{
							sigma3_value += static_cast<AutoFloatingType>(1 - 2 * InnerProduct( counter, ByteSubstitutionBoxArray[data_byte_index] ^ ByteSubstitutionBoxArray[data_byte_index ^ index_a] ) );
						}
						sigma2_value += static_cast<AutoFloatingType>(1 - 2 * InnerProduct(counter, index_b) * sigma3_value );
					}

					if(sigma2_value < 0)
						sigma2_value *= (-1);
					sigma_value += sigma2_value;

					temporary_value = 2 * HammingWeightArray[index_b];
					if(answer < std::abs( static_cast<std::int32_t>(OutputPowerOfTwo - temporary_value) ) - sigma2_value / DifferenceValue)
						answer = std::abs( static_cast<std::int32_t>(OutputPowerOfTwo - temporary_value) ) - sigma2_value / DifferenceValue;
				}
			}

			return answer;
		}

		//Compute the number of Hamming branches for byte-substitution boxes
		//计算字节代换盒的汉明分支数量
		std::int32_t ComputeHammingBranchNumber()
		{
			std::uint32_t temporary_branch_number = 0;	
			std::uint32_t branch_number = 10000;

			for (std::uint32_t index = 0; index < Shift_InputSize; index++)
			{
				for (std::uint32_t index2 = 0; index2 < Shift_InputSize; index2++)
				{
					if (index != index2)
					{
						//temporary_branch_number = hamming_weight(index ^ index2) + hamming_weight(ByteSubstitutionBoxPointer[index] ^ ByteSubstitutionBoxPointer[index2]);
						temporary_branch_number = HammingWeightArray[index ^ index2] + HammingWeightArray[ ByteSubstitutionBoxArray[index] ^ ByteSubstitutionBoxArray[index2] ];
						branch_number = std::min(temporary_branch_number, branch_number);
					}
				}
			}
	
			return static_cast<std::int32_t>(branch_number);
		}

		/*
			//Meaningful hint: You need to use the WalshHadamardTransform function first and then use this function
			//有意义的提示：你需要先使用WalshHadamardTransform函数，然后再使用这个函数。
			
			The function of an S-box(substitution box) is to contribute nonlinearity properties to the encryption algorithm. 
			To test how resistant an S-box is against this, the nonlinearity properties will be measure using this nonlinearity test [20,21,22,23].
			The nonlinearity of a Boolean function is defined as the hamming distance between the function and the set of all affine functions. 
			For the linearity criteria, the hamming distance should be minimum in which the NL parameter must be between 100 < NL ≤ 120 otherwise the S-box is vulnerable to linear cryptanalysis. 
			It is also defined as there is no linear mapping between the input and output vector of the S-box. 
			The nonlinearity of the S-box is calculated by creating the Boolean functions, f, and then applying Walsh Hadamard transformation (WHT) to test the correlation between linear functions and the Boolean functions. 
			The larger the degree of the polynomial, n, makes it difficult to compute the nonlinearity
			S-box的功能是为加密算法贡献非线性特性。
			为了测试S-box对此的抵抗力，将使用这个非线性测试来衡量非线性特性[20,21,22,23]。
			布尔函数的非线性被定义为该函数与所有仿射函数集合之间的哈明距离。
			对于线性标准，哈明距离应该是最小的，其中NL参数必须在100 < NL ≤ 120之间，否则S-box就容易受到线性密码分析的影响。
			它也被定义为S-box的输入和输出矢量之间没有线性映射。
			S-box的非线性是通过创建布尔函数f，然后应用Walsh Hadamard变换（WHT）来测试线性函数和布尔函数之间的关联性来计算的。
			多项式的度数n越大，就越难计算出非线性度

			https://www.mdpi.com/2073-8994/12/5/826/htm
		*/

		//Compute the nonlinearity of the byte-substitution box
		//计算字节代换盒的非线性度
		std::pair<std::int32_t, std::vector<std::uint32_t>> ComputeNonlinearity
		(
			const std::vector<std::vector<std::int32_t>>& truth_table_with_walsh_hadamard_transformed
		)
		{
			// If the answer is as big as possible, then better; 
			// but an answer that is too big will result in a byte substitution box that is not invertable
			// And the S-box will be broken by linear cryptanalysis
			std::uint32_t answer = 10000, temporary_value = 0;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1;
			std::vector<std::uint32_t> boolean_components(columns, 0);

			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				if(truth_table_with_walsh_hadamard_transformed[0][loop_column] < 0)
					temporary_value = truth_table_with_walsh_hadamard_transformed[0][loop_column] * -1;

				for(std::uint32_t loop_row = 1; loop_row < rows; loop_row++)
				{
					if(std::abs( truth_table_with_walsh_hadamard_transformed[loop_row][loop_column] ) > temporary_value)
						temporary_value = std::abs( truth_table_with_walsh_hadamard_transformed[loop_row][loop_column] );
				}
				boolean_components[loop_column] = (Shift_InputSize - temporary_value) >> 1;
				answer = std::min(boolean_components[loop_column], answer);
			}

			return std::pair<std::int32_t, std::vector<std::uint32_t>>(static_cast<std::int32_t>(answer), boolean_components);
		}

		/*
			//Meaningful hint: You need to use the WalshHadamardTransform function first and then use this function
			//有意义的提示：你需要先使用WalshHadamardTransform函数，然后再使用这个函数。
			
			In mathematics, the correlation immunity of a Boolean function is a measure of the degree to which its outputs are uncorrelated with some subset of its inputs. 
			Specifically, a Boolean function is said to be correlation-immune of order m if every subset of m or fewer variables in x1, x2, x3 ......, xn is statistically independent of the value of MathFunction(x1, x2, x3 ......, xn).

			When used in a stream cipher as a combining function for linear feedback shift registers, a Boolean function with low-order correlation-immunity is more susceptible to a correlation attack than a function with correlation immunity of high order.

			Siegenthaler showed that the correlation immunity m of a Boolean function of algebraic degree d of n variables satisfies m + d ≤ n;
			for a given set of input variables, this means that a high algebraic degree will restrict the maximum possible correlation immunity.
			Furthermore, if the function is balanced then m + d ≤ n − 1

			在数学中，一个布尔函数的相关免疫性是衡量其输出与输入的某些子集不相关的程度。 
			具体来说，如果x1, x2, x3 ......, xn中的每一个m个或更少的变量子集在统计上都与MathFunction(x1, x2, x3 ......, xn)的值无关，那么就可以说一个布尔函数是m阶的相关免疫。

			当在流密码中作为线性反馈移位寄存器的组合函数使用时，具有低阶相关免疫性的布尔函数比具有高阶相关免疫性的函数更容易受到相关攻击的影响。

			Siegenthaler表明，n个变量的代数级数d的布尔函数的相关免疫力m满足m+d≤n。
			对于一组给定的输入变量，这意味着高代数度将限制最大可能的相关免疫力。
			此外，如果该函数是平衡的，那么m + d ≤ n - 1
			https://en.wikipedia.org/wiki/Correlation_immunity
		*/

		//Compute the correlation immunity of the byte-substitution box
		//计算字节代换盒的相关性抗扰度
		std::pair<std::int32_t, std::vector<std::uint32_t>> ComputeCorrelationImmunity
		(
			const std::vector<std::vector<std::int32_t>>& truth_table_with_walsh_hadamard_transformed
		)
		{
			std::uint32_t answer = 100000, order_hamming_weight = 0;
			std::uint32_t rows = Shift_InputSize, columns = Shift_OutputSize - 1;
			std::vector<std::uint32_t> boolean_components(columns, 0);

			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				order_hamming_weight = 1;

				for(std::uint32_t loop_row = 1; loop_row < rows; loop_row++)
				{
					//if (order == HammingWeight(loop_row) && truth_table_with_walsh_hadamard_transformed[loop_row][loop_column] != 0)
					if(order_hamming_weight == HammingWeightArray[loop_row] && truth_table_with_walsh_hadamard_transformed[loop_row][loop_column] != 0)
					{
						boolean_components[loop_column] = order_hamming_weight - 1;
						break;
					}

					if(loop_row == (rows - 1) && order_hamming_weight <= InputPowerOfTwo)
					{
						loop_row = 1;
						order_hamming_weight++;
					}
					boolean_components[loop_column] = order_hamming_weight - 2;
				}
				answer = std::min(boolean_components[loop_column], answer);
			}

			return std::pair<std::int32_t, std::vector<std::uint32_t>>(static_cast<std::int32_t>(answer), boolean_components);
		}

		//SAC = strict avalanche criteria(严格的雪崩标准)
		//PC = propagation characteristics(传播特性)
		//Compute the degree of (propagation characteristics/strict avalanche criteria) of the byte-substitution box
		//计算字节替换盒的（传播特性/严格的雪崩标准）程度
		std::pair<std::int32_t, bool> Compute_PC_SAC()
		{
			// If the answer is as big as possible, then better
			std::uint32_t order_hamming_weight = 1, count = 0;
			std::vector<std::uint32_t> help_datas(Shift_InputSize, 0);

			//计算公式： 数据雪崩效应 = (二进制数据中翻转的比特位数) / (二进制数据中总比特位数) * 100%
			//Computational formula: Data avalanche effect = (number of bits flipped in binary data) / (total number of bits in binary data) * 100%
			auto ProcessByteSubstitutionBox = []
			(
				const std::span<std::uint32_t>& input_data,
				std::span<std::uint32_t> output_data,
				const std::uint32_t& shift_count,
				const std::uint32_t& columns
			) -> void
			{
				//布尔函数的导数
				//Derivatives of boolean functions
				for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
				{
					//二进制比特翻转操作
					//Binary bits flip operation
					output_data[loop_column] = input_data[loop_column] ^ input_data[loop_column ^ shift_count];
				}
			};

			std::int32_t propagation_characteristics = 0;

			//更新当前顺序的哈明权重
			//Update current order hamming weight
			do
			{
				for(std::uint32_t index = 0; index < Shift_InputSize; index++)
				{
					//if(order_hamming_weight == HammingWeight(index))
					if(order_hamming_weight == HammingWeightArray[index])
					{
						ProcessByteSubstitutionBox(ByteSubstitutionBoxArray, help_datas, index, Shift_InputSize);

						//could be done with truth_table_with_math_boolean_function, truth_table_with_walsh_hadamard_transformed, balance
						//可以用 truth_table_with_math_boolean_function, truth_table_with_walsh_hadamard_transformed, balance来完成
						for(std::uint32_t index2 = 0; index2 < Shift_InputSize; index2++)
						{
							for(std::uint32_t index3 = 0; index3 < Shift_InputSize; index3++)
							{
								if(help_datas[index3] == index2)
									count++;
							}
							
							if(count != 1)
							{
								break;
							}
							count = 0;
						}
					}
				}
				order_hamming_weight++;

			} while (order_hamming_weight <= OutputPowerOfTwo);

			//Set the current order Hamming weight value minus one for the answer
			propagation_characteristics = order_hamming_weight - 1;

			if(static_cast<bool>(propagation_characteristics))
			{
				bool is_strict_avalanche_criterion = true;
				std::cout << "This byte-substitution box: Strict avalanche criterion is satisfied !" << std::endl;
				return std::pair<std::int32_t, bool>(propagation_characteristics, is_strict_avalanche_criterion);
			}
			else
			{
				bool is_strict_avalanche_criterion = false;
				std::cout << "This byte-substitution box: Strict avalanche criterion is not satisfied !" << std::endl;
				return std::pair<std::int32_t, bool>(propagation_characteristics, is_strict_avalanche_criterion);
			}
		}

		//SNR = Signal-to-Noise Ratio(信噪比)
		//DPA = Differential Power Analysis(微分功率分析)
		//Meaningful hint: You need to use the ComputeTruthTable function first and then use this function
		//有意义的提示：你需要先使用ComputeTruthTable函数，然后再使用这个函数
		AutoFloatingType Compute_SNR_DPA
		(
			const std::vector<std::vector<std::uint8_t>>& truth_table_with_math_boolean_function
		)
		{
			AutoFloatingType sum_value = 0.0f, sum2_value = 0.0f, sum3_value = 0.0f;
			std::uint32_t answer_multiplier = (1 << (2 * InputPowerOfTwo) ) * OutputPowerOfTwo;

			for(std::uint32_t index = 0; index < Shift_InputSize; ++index)
			{
				sum2_value = 0.0f;
				for(std::uint32_t index2 = 0; index2 < OutputPowerOfTwo; ++index2)
				{
					sum3_value = 0.0f;
					for(std::uint32_t index3 = 0; index3 < Shift_InputSize; ++index3)
					{
						sum3_value += static_cast<AutoFloatingType>( (1 - 2 * InnerProduct(index3, index) ) * ( 1 - 2 * truth_table_with_math_boolean_function[index3][index2] ) );
					}
					sum2_value += sum3_value;
				}
				sum2_value = sum2_value * sum2_value * sum2_value * sum2_value;
				sum_value += sum2_value;
			}
			sum_value = static_cast<AutoFloatingType>( ::pow(sum_value, static_cast<AutoFloatingType>(-0.5f)) );

			return sum_value * answer_multiplier;
		}

		//Do Kappa Correlation Power Analysis
		//相关性功率分析
		AutoFloatingType DoKappaCorrelationPowerAnalysis()
		{
			//The size of the combination coefficient on the key selection index and index 2
			//关键选择指数和指数2的组合系数的大小
			std::size_t CombinationCoefficientSize = (Shift_InputSize * (Shift_InputSize - 1)) >> 1;

			//Differential power analysis: (This variable name) of times we observe confusion
			//微分功率分析：（此变量名称）我们观察到混乱的次数
			std::size_t ConfusionCounter = 0;

			//Differential power analysis: How many combinatorics coefficients have we computed.
			//微分功率分析：我们计算了多少个组合系数。
			std::size_t CombinationCoefficientCounter = 0;

			//Correlation power analysis: Current number of combination coefficient sum.
			//相关性功率分析：当前的组合系数和的数量。
			std::size_t CombinationCoefficientSumNumber = 0;

			std::vector<AutoFloatingType> ConfusionCharacteristicArray(CombinationCoefficientSize, 0.0f);

			for(std::size_t index = 0; index < Shift_InputSize; ++index)
			{
				for(std::size_t index2 = 1; index2 < Shift_InputSize; ++index2)
				{
					for(std::size_t index3 = 0; index3 < Shift_InputSize; ++index3)
					{
						std::uint32_t byte_value_a = ByteSubstitutionBoxArray[index ^ index3];
						std::uint32_t byte_value_b = ByteSubstitutionBoxArray[index2 ^ index3];

						std::uint32_t CombinationCoefficientNumber = HammingWeightArray[byte_value_a] - HammingWeightArray[byte_value_b];
						CombinationCoefficientNumber *= CombinationCoefficientNumber;
						CombinationCoefficientSumNumber += CombinationCoefficientNumber;
					}

					//Compute confusion coefficient for key index and index2
					//计算关键index和index2的混淆系数
					ConfusionCharacteristicArray[CombinationCoefficientCounter] = static_cast<AutoFloatingType>(CombinationCoefficientSumNumber) / static_cast<AutoFloatingType>(Shift_InputSize);
					++CombinationCoefficientCounter;
					ConfusionCounter = 0;
					CombinationCoefficientSumNumber = 0;
				}
			}

			AutoFloatingType power_value = 0.0f;
			for(std::size_t index = 0; index < CombinationCoefficientSize; ++index)
			{
				if(ConfusionCharacteristicArray[10] != ConfusionCharacteristicArray[index])
				{
					power_value += ConfusionCharacteristicArray[index];
				}
			}

			power_value /= static_cast<AutoFloatingType>(CombinationCoefficientSize);

			AutoFloatingType ConfusionCoefficientVariance = 0.0f;
			for(std::size_t index = 0; index < CombinationCoefficientSize; ++index)
			{
				ConfusionCoefficientVariance += static_cast<AutoFloatingType>( ::pow(ConfusionCharacteristicArray[index] - power_value, 2) );
			}

			ConfusionCoefficientVariance /= static_cast<AutoFloatingType>(CombinationCoefficientSize);

			return ConfusionCoefficientVariance;
		}

		//Do Kappa Differential Power Analysis
		//微分功率分析
		std::pair<std::vector<AutoFloatingType>, std::vector<AutoFloatingType>> DoKappaDifferentialPowerAnalysis(std::uint32_t bit)
		{
			//The size of the combination coefficient on the key selection index and index 2
			//关键选择指数和指数2的组合系数的大小
			std::size_t CombinationCoefficientSize = (Shift_InputSize * (Shift_InputSize - 1)) >> 1;

			//Differential power analysis: (This variable name) of times we observe confusion
			//微分功率分析：（此变量名称）我们观察到混乱的次数
			std::size_t ConfusionCounter = 0;

			//Differential power analysis: How many combinatorics coefficients have we computed.
			//微分功率分析：我们计算了多少个组合系数。
			std::size_t CombinationCoefficientCounter = 0;

			std::vector<AutoFloatingType> ReducedCombinationCoefficientsArray(CombinationCoefficientSize, 0.0f);
			std::vector<AutoFloatingType> FrequencyCoefficientsArray(CombinationCoefficientSize, 0.0f);
			std::vector<AutoFloatingType> ConfusionCharacteristicArray(CombinationCoefficientSize, 0.0f);

			for(std::size_t index = 0; index < Shift_InputSize; ++index)
			{
				for(std::size_t index2 = 0; (index2 < Shift_InputSize) && (index != index2); ++index2)
				{
					for(std::size_t index3 = 0; index3 < Shift_InputSize; ++index3)
					{
						//Isolate desired bit of the byte-substitution box to focus on differential power analysis
						//分离出字节替换盒的所需位，以集中进行微分功率分析
						std::uint32_t single_bit_a = ByteSubstitutionBoxArray[index ^ index3] & bit;
						std::uint32_t single_bit_b = ByteSubstitutionBoxArray[index2 ^ index3] & bit;

						//NOTE: collision coefficient can be produced by replacing '!=' with '=='
						//注意：碰撞系数可以通过用'=='替换'！='来产生
						if(single_bit_a != single_bit_b)
							++ConfusionCounter;
					}

					//Compute confusion coefficient for key index and index2
					//计算关键index和index2的混淆系数
					ConfusionCharacteristicArray[CombinationCoefficientCounter] = static_cast<AutoFloatingType>(ConfusionCounter) / static_cast<AutoFloatingType>(Shift_InputSize);
					++CombinationCoefficientCounter;
					ConfusionCounter = 0;
				}
			}

			std::ranges::sort(ConfusionCharacteristicArray.begin(), ConfusionCharacteristicArray.end(), std::ranges::less());

			for(std::size_t index = 0, index2 = 0, index3 = 0; index < CombinationCoefficientCounter; ++index)
			{
				if(ConfusionCharacteristicArray[index] == ConfusionCharacteristicArray[index + 1])
					++index2;
				else
				{
					ReducedCombinationCoefficientsArray[index3] = ConfusionCharacteristicArray[index];
					FrequencyCoefficientsArray[index3] = static_cast<AutoFloatingType>(index2) / static_cast<AutoFloatingType>(CombinationCoefficientSize);
					index2 = 0;
					++index3;
				}
			}

			return std::pair<std::vector<AutoFloatingType>, std::vector<AutoFloatingType>>(ReducedCombinationCoefficientsArray, FrequencyCoefficientsArray);
		}

		//Compute the coordinate function values of the byte substitution box
		//计算字节替换盒的统筹函数值
		//Meaningful hint: You need to use the ComputeTruthTable function first and then use this function
		//有意义的提示：你需要先使用ComputeTruthTable函数，然后再使用这个函数
		std::vector<std::uint32_t> ComputeCoordinateFunctionValues(const std::vector<std::uint32_t>& truth_table_with_math_boolean_function)
		{
			std::uint32_t columns = Shift_OutputSize - 1;
			std::vector<std::uint32_t> answer_datas(columns, 0);
			
			for(std::uint32_t loop_column = 0; loop_column < columns; loop_column++)
			{
				if(HammingWeightArray[loop_column] == 1)
					answer_datas[loop_column] = truth_table_with_math_boolean_function[loop_column];
			}

			return answer_datas;
		}

		SecurityEvaluationAnalyzer(std::span<std::uint8_t> ByteArray, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
			: BaseFunctions::BaseFunctions(ByteArray.size(), InputSize, OutputSize)
		{
			my_cpp2020_assert( (InputSize != 0) && (OutputSize != 0), "The data size of this substitution box is not empty!", std::source_location::current() );
			ByteSubstitutionBoxArray = std::move(std::vector<std::uint32_t>(ByteArray.begin(), ByteArray.end()));
		}

		~SecurityEvaluationAnalyzer() = default;
	};

	namespace HelperFunctions
	{
		inline void ShowDifferentialDistributionTable(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			auto DifferenceDistributionTable2D = SubstitutionBoxAnalyzer.ComputeDifferentialDistributionTable();

			std::cout << "This Is Byte Substitution Box Differential Distribution Table:" << std::endl;
			std::cout << "************************************************************************************************************************" << std::endl;
			for (auto& DifferenceDistributionTable1D : DifferenceDistributionTable2D)
			{
				for (auto& DifferenceDistributionValue : DifferenceDistributionTable1D)
				{
					std::cout << DifferenceDistributionValue << " ";
				}
				std::cout << std::endl;
			}
			std::cout << "*************************************************************************************************************************" << std::endl;
		}

		inline void ShowLinearApproximationTable(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			auto LinearApproximationTable2D = SubstitutionBoxAnalyzer.ComputeLinearApproximationTable();

			std::cout << "This Is Byte Substitution Box Linear Approximation Table:" << std::endl;
			std::cout << "************************************************************************************************************************" << std::endl;
			for (auto& LinearApproximationTable1D : LinearApproximationTable2D)
			{
				for (auto& LinearApproximationValue: LinearApproximationTable1D)
				{
					std::cout << LinearApproximationValue << " ";
				}
				std::cout << std::endl;
			}
			std::cout << "************************************************************************************************************************" << std::endl;
		}

		inline void ShowDifferentialApproximationProbabilityTable(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);
			auto DifferentialAproximationProbabilityTable2D = SubstitutionBoxAnalyzer.ComputeDifferentialApproximationProbabilityTable();

			std::cout << "This Is Byte Substitution Box Differential Aproximation Probability Table:" << std::endl;
			std::cout << "************************************************************************************************************************" << std::endl;
			for (auto& DifferentialAproximationProbabilityTable1D : DifferentialAproximationProbabilityTable2D)
			{
				for (auto& DifferentialAproximationProbabilityTableValue: DifferentialAproximationProbabilityTable1D)
				{
					std::cout << DifferentialAproximationProbabilityTableValue << " ";
				}
				std::cout << std::endl;
			}
			std::cout << "************************************************************************************************************************" << std::endl;
		}

		inline auto SubstitutionBoxAlgebraicImmunityDegree(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			AlgebraicImmunityDegreeAnalyzer SubstitutionBoxAlgebraicImmunityAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			//Construction 2 arrays in function and Apply all functions
			auto truth_table_with_math_boolean_function = SubstitutionBoxAlgebraicImmunityAnalyzer.ComputeTruthTable();
			auto linear_lines_truth_table = SubstitutionBoxAlgebraicImmunityAnalyzer.LinearCombinations(truth_table_with_math_boolean_function);

			//Generate answer
			auto answer_pair = SubstitutionBoxAlgebraicImmunityAnalyzer.ComputeWorker(linear_lines_truth_table);

			//Deconstruction 2 arrays
			truth_table_with_math_boolean_function.clear();
			truth_table_with_math_boolean_function.shrink_to_fit();
			linear_lines_truth_table.clear();
			linear_lines_truth_table.shrink_to_fit();

			return answer_pair;
		}

		inline AutoFloatingType SubstitutionBoxTransparencyOrder(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			return SubstitutionBoxSecurityEvaluationAnalyzer.ComputeTransparencyOrder();
		}

		inline auto SubstitutionBox_PC_SAC(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			return SubstitutionBoxSecurityEvaluationAnalyzer.Compute_PC_SAC();
		}

		inline AutoFloatingType SubstitutionBox_SNR_DPA(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			//Construction 1 arrays in function and Apply all functions
			auto truth_table_with_math_boolean_function = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeTruthTable();
			AutoFloatingType ratio_value = SubstitutionBoxSecurityEvaluationAnalyzer.Compute_SNR_DPA(truth_table_with_math_boolean_function);

			//Deconstruction 1 arrays
			truth_table_with_math_boolean_function.clear();
			truth_table_with_math_boolean_function.shrink_to_fit();

			return ratio_value;
		}

		inline auto SubstitutionBox_DeltaUniformity_Robustness(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			//std::uint32_t rows = 1 << InputSize, columns = (1 << OutputSize) - 1;

			return SubstitutionBoxSecurityEvaluationAnalyzer.Compute_DeltaUniformity_Robustness();
		}

		inline auto SubstitutionBoxAlgebraicDegree(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			//Construction 2 arrays in function and Apply all functions
			auto truth_table_with_math_boolean_function = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeTruthTable();
			auto linear_lines_truth_table = SubstitutionBoxSecurityEvaluationAnalyzer.LinearCombinations(truth_table_with_math_boolean_function);

			//Generate answer
			auto already_algebraic_normal_form_value = SubstitutionBoxSecurityEvaluationAnalyzer.AlgebraicNormalForm(truth_table_with_math_boolean_function);
			auto answer_pair = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeAlgebraicDegree(already_algebraic_normal_form_value);

			//Deconstruction 2 arrays
			truth_table_with_math_boolean_function.clear();
			truth_table_with_math_boolean_function.shrink_to_fit();
			linear_lines_truth_table.clear();
			linear_lines_truth_table.shrink_to_fit();

			return answer_pair;
		}

		inline auto SubstitutionBoxCorrelationImmunity(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			//Construction 3 arrays in function and Apply all functions
			auto truth_table_with_math_boolean_function = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeTruthTable();
			auto linear_lines_truth_table = SubstitutionBoxSecurityEvaluationAnalyzer.LinearCombinations(truth_table_with_math_boolean_function);
			auto truth_table_with_walsh_hadamard_transformed = SubstitutionBoxSecurityEvaluationAnalyzer.WalshHadamardTransform(linear_lines_truth_table);

			//Generate answer
			auto answer_pair = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeCorrelationImmunity(truth_table_with_walsh_hadamard_transformed);

			//Deconstruction 3 arrays
			truth_table_with_math_boolean_function.clear();
			truth_table_with_math_boolean_function.shrink_to_fit();
			linear_lines_truth_table.clear();
			linear_lines_truth_table.shrink_to_fit();
			truth_table_with_walsh_hadamard_transformed.clear();
			truth_table_with_walsh_hadamard_transformed.shrink_to_fit();

			return answer_pair;
		}

		inline auto SubstitutionBoxNonlinearityDegree(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			//Construction 3 arrays in function and Apply all functions
			auto truth_table_with_math_boolean_function = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeTruthTable();
			auto linear_lines_truth_table = SubstitutionBoxSecurityEvaluationAnalyzer.LinearCombinations(truth_table_with_math_boolean_function);
			auto truth_table_with_walsh_hadamard_transformed = SubstitutionBoxSecurityEvaluationAnalyzer.WalshHadamardTransform(linear_lines_truth_table);

			//Generate answer
			auto answer_pair = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeNonlinearity(truth_table_with_walsh_hadamard_transformed);

			//Deconstruction 3 arrays
			truth_table_with_math_boolean_function.clear();
			truth_table_with_math_boolean_function.shrink_to_fit();
			linear_lines_truth_table.clear();
			linear_lines_truth_table.shrink_to_fit();
			truth_table_with_walsh_hadamard_transformed.clear();
			truth_table_with_walsh_hadamard_transformed.shrink_to_fit();

			return answer_pair;
		}

		inline auto SubstitutionBoxAbsoluteValueIndicator(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			//Construction 4 arrays in function and Apply all functions
			auto truth_table_with_math_boolean_function = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeTruthTable();
			auto linear_lines_truth_table = SubstitutionBoxSecurityEvaluationAnalyzer.LinearCombinations(truth_table_with_math_boolean_function);
			auto truth_table_with_walsh_hadamard_transformed = SubstitutionBoxSecurityEvaluationAnalyzer.WalshHadamardTransform(linear_lines_truth_table);
			auto truth_table_with_autocorrelation = SubstitutionBoxSecurityEvaluationAnalyzer.AutocorrelationFastVersion(truth_table_with_walsh_hadamard_transformed);

			//Generate answer
			auto answer_pair = SubstitutionBoxSecurityEvaluationAnalyzer.AbsoluteValueIndicator(truth_table_with_autocorrelation);

			//Deconstruction 4 arrays
			truth_table_with_math_boolean_function.clear();
			truth_table_with_math_boolean_function.shrink_to_fit();
			linear_lines_truth_table.clear();
			linear_lines_truth_table.shrink_to_fit();
			truth_table_with_walsh_hadamard_transformed.clear();
			truth_table_with_walsh_hadamard_transformed.shrink_to_fit();
			truth_table_with_autocorrelation.clear();
			truth_table_with_autocorrelation.shrink_to_fit();

			return answer_pair;
		}

		inline auto SubstitutionBoxSumOfSquareValueIndicator(std::span<std::uint8_t> ByteSubstitutionBox, const std::uint32_t& InputSize, const std::uint32_t& OutputSize)
		{
			SecurityEvaluationAnalyzer SubstitutionBoxSecurityEvaluationAnalyzer(ByteSubstitutionBox , InputSize, OutputSize);

			//Construction 4 arrays in function and Apply all functions
			auto truth_table_with_math_boolean_function = SubstitutionBoxSecurityEvaluationAnalyzer.ComputeTruthTable();
			auto linear_lines_truth_table = SubstitutionBoxSecurityEvaluationAnalyzer.LinearCombinations(truth_table_with_math_boolean_function);
			auto truth_table_with_walsh_hadamard_transformed = SubstitutionBoxSecurityEvaluationAnalyzer.WalshHadamardTransform(linear_lines_truth_table);
			auto truth_table_with_autocorrelation = SubstitutionBoxSecurityEvaluationAnalyzer.AutocorrelationFastVersion(truth_table_with_walsh_hadamard_transformed);

			//Generate answer
			auto answer_pair = SubstitutionBoxSecurityEvaluationAnalyzer.SumOfSquareValueIndicator(truth_table_with_autocorrelation);

			//Deconstruction 4 arrays
			truth_table_with_math_boolean_function.clear();
			truth_table_with_math_boolean_function.shrink_to_fit();
			linear_lines_truth_table.clear();
			linear_lines_truth_table.shrink_to_fit();
			truth_table_with_walsh_hadamard_transformed.clear();
			truth_table_with_walsh_hadamard_transformed.shrink_to_fit();
			truth_table_with_autocorrelation.clear();
			truth_table_with_autocorrelation.shrink_to_fit();

			return answer_pair;
		}
	}
}