#pragma once

/*
	https://en.wikipedia.org/wiki/XXTEA
	Corrected Block TEA (often referred to as XXTEA) is a block cipher designed to correct weaknesses in the original Block TEA.
	XXTEA is vulnerable to a chosen-plaintext attack requiring 259 queries and negligible work.
	The cipher's designers were Roger Needham and David Wheeler of the Cambridge Computer Laboratory, and the algorithm was presented in an unpublished[clarification needed] technical report in October 1998 (Wheeler and Needham, 1998).
	It is not subject to any patents.
	Formally speaking, XXTEA is a consistent incomplete source-heavy heterogeneous UFN (unbalanced Feistel network) block cipher.
	XXTEA operates on variable-length blocks that are some arbitrary multiple of 32 bits in size (minimum 64 bits).
	The number of full cycles depends on the block size, but there are at least six (rising to 32 for small block sizes).
	The original Block TEA applies the XTEA round function to each word in the block and combines it additively with its leftmost neighbour.
	Slow diffusion rate of the decryption process was immediately exploited to break the cipher. 
	Corrected Block TEA uses a more involved round function which makes use of both immediate neighbours in processing each word in the block.
	XXTEA is likely to be more efficient than XTEA for longer messages.

	Corrected Block TEA（通常被称为XXTEA）是一种块密码，旨在纠正原始Block TEA的弱点。
	XXTEA容易受到选择明文的攻击，需要259次查询和可忽略不计的工作。
	该密码的设计者是剑桥计算机实验室的Roger Needham和David Wheeler，该算法于1998年10月在一份未发表的[澄清需要]技术报告中提出（Wheeler and Needham, 1998）。
	它不受任何专利限制。
	从形式上讲，XXTEA是一种一致的不完全源重异质UFN（不平衡的Feistel网络）区块密码。
	XXTEA在可变长度的块上运行，这些块的大小是32位的任意倍数（最小64位）。
	全周期的数量取决于区块大小，但至少有6个（小区块大小上升到32）。
	原始的块TEA将XTEA圆函数应用于块中的每个字，并将其与最左边的邻居加在一起。
	解密过程的缓慢扩散率立即被利用来破解密码。 
	修正后的区块TEA使用了一个更多的圆形函数，在处理区块中的每个字时利用了两个近邻。
	对于较长的信息，XXTEA可能比XTEA更有效。
*/
namespace CommonSecurity::CorrectedBlockTEA
{
	constexpr std::uint32_t DELTA_VALUE = static_cast<std::uint32_t>(0x9e3779b9);
	
	class DataWorker
	{
		
	private:
		
		std::uint32_t MixValue(std::uint32_t& a, std::uint32_t& b, std::uint32_t& sum, const std::array<std::uint32_t, 4>& keys, std::uint32_t& data_values_index, std::uint32_t& choice_sum)
		{
			auto left_value = ((b >> 5 ^ a << 2) + (a >> 3 ^ b << 4));
			auto right_value = ((sum ^ a) + (keys[(data_values_index & 3) ^ choice_sum] ^ b));
			auto mixed_value = left_value ^ right_value;
			return mixed_value;
		}

	public:

		void operator()(std::uint32_t* data_values, std::uint32_t data_values_size, bool mode, const std::array<std::uint32_t, 4>& keys)
		{
			std::uint32_t a = 0, b = 0, sum = 0;
			std::uint32_t data_values_index;
			std::uint32_t execute_rounds = 0, choice_sum = 0;
			
			if(mode == true)
			{
				//Encoding Part
				execute_rounds = 6 + 52 / data_values_size;
				b = data_values[data_values_size - 1];
				do
				{
					sum += DELTA_VALUE;
					choice_sum = (sum >> 2) & 3;
					for(data_values_index = 0; data_values_index < data_values_size - 1; ++data_values_index)
					{
						a = data_values[data_values_index + 1];
						b = data_values[data_values_index] += MixValue(a, b, sum, keys, data_values_index, choice_sum);
					}
					a = data_values[0];
					b = data_values[data_values_size - 1] += MixValue(a, b, sum, keys, data_values_index, choice_sum);
				} while (--execute_rounds);
			}
			else
			{
				//Decoding Part
				execute_rounds = 6 + 52 / data_values_size;
				sum = execute_rounds * DELTA_VALUE;
				a = data_values[0];
				do
				{
					choice_sum = (sum >> 2) & 3;
					for (data_values_index = data_values_size - 1; data_values_index > 0; --data_values_index)
					{
						b = data_values[data_values_index - 1];
						a = data_values[data_values_index] -= MixValue(a, b, sum, keys, data_values_index, choice_sum);
					}
					b = data_values[data_values_size - 1];
					a = data_values[0] -= MixValue(a, b, sum, keys, data_values_index, choice_sum);
					sum -= DELTA_VALUE;
				} while (--execute_rounds);
			}
		}
		
		DataWorker() = default;
		~DataWorker() = default;
		
	};

	inline DataWorker SuperTEA;
}