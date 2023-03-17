#pragma once

namespace CommonSecurity::Serpent
{
	class OfficialAlgorithm
	{

	private:
		static constexpr std::uint32_t GOLDEN_RATIO = 0x9E3779B9;
		std::array<std::array<std::uint32_t, 4>, 33> Subkeys
		{{
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},

			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},

			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}},
			{{0,0,0,0}}
		}};

		void ForwardBox0(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r3 ^= r0; tv = r1;
			r1 &= r3; tv ^= r2;
			r1 ^= r0; r0 |= r3;
			r0 ^= tv; tv ^= r3;
			r3 ^= r2; r2 |= r1;
			r2 ^= tv; tv = ~tv;
			tv |= r1; r1 ^= r3;
			r1 ^= tv; r3 |= r0;
			r1 ^= r3; tv ^= r3;
			r3 = r0; r0 = r1; r1 = tv;
			tv = 0;
		}

		void BackwardBox0(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r2 = ~r2; tv = r1;
			r1 |= r0; tv = ~tv;
			r1 ^= r2; r2 |= tv;
			r1 ^= r3; r0 ^= tv;
			r2 ^= r0; r0 &= r3;
			tv ^= r0; r0 |= r1;
			r0 ^= r2; r3 ^= tv;
			r2 ^= r1; r3 ^= r0;
			r3 ^= r1;
			r2 &= r3;
			tv ^= r2;
			r2 = r1; r1 = tv;
			tv = 0;
		}

		void ForwardBox1(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r0 = ~r0; r2 = ~r2;
			tv = r0; r0 &= r1;
			r2 ^= r0; r0 |= r3;
			r3 ^= r2; r1 ^= r0;
			r0 ^= tv; tv |= r1;
			r1 ^= r3; r2 |= r0;
			r2 &= tv; r0 ^= r1;
			r1 &= r2;
			r1 ^= r0; r0 &= r2;
			r0 ^= tv;
			tv = r0; r0 = r2; r2 = r3; r3 = r1; r1 = tv;
			tv = 0;
		}

		void BackwardBox1(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			tv = r1; r1 ^= r3;
			r3 &= r1; tv ^= r2;
			r3 ^= r0; r0 |= r1;
			r2 ^= r3; r0 ^= tv;
			r0 |= r2; r1 ^= r3;
			r0 ^= r1; r1 |= r3;
			r1 ^= r0; tv = ~tv;
			tv ^= r1; r1 |= r0;
			r1 ^= r0;
			r1 |= tv;
			r3 ^= r1;
			r1 = r0; r0 = tv; tv = r2; r2 = r3; r3 = tv;
			tv = 0;
		}

		void ForwardBox2(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			tv = r0; r0 &= r2;
			r0 ^= r3; r2 ^= r1;
			r2 ^= r0; r3 |= tv;
			r3 ^= r1; tv ^= r2;
			r1 = r3; r3 |= tv;
			r3 ^= r0; r0 &= r1;
			tv ^= r0; r1 ^= r3;
			r1 ^= tv; tv = ~tv;
			r0 = r2; r2 = r1; r1 = r3; r3 = tv;
			tv = 0;
		}

		void BackwardBox2(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r2 ^= r3; r3 ^= r0;
			tv = r3; r3 &= r2;
			r3 ^= r1; r1 |= r2;
			r1 ^= tv; tv &= r3;
			r2 ^= r3; tv &= r0;
			tv ^= r2; r2 &= r1;
			r2 |= r0; r3 = ~r3;
			r2 ^= r3; r0 ^= r3;
			r0 &= r1; r3 ^= tv;
			r3 ^= r0;
			r0 = r1; r1 = tv;
			tv = 0;
		}

		void ForwardBox3(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			tv = r0; r0 |= r3;
			r3 ^= r1; r1 &= tv;
			tv ^= r2; r2 ^= r3;
			r3 &= r0; tv |= r1;
			r3 ^= tv; r0 ^= r1;
			tv &= r0; r1 ^= r3;
			tv ^= r2; r1 |= r0;
			r1 ^= r2; r0 ^= r3;
			r2 = r1; r1 |= r3;
			r1 ^= r0;
			r0 = r1; r1 = r2; r2 = r3; r3 = tv;
			tv = 0;
		}

		void BackwardBox3(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			tv = r2; r2 ^= r1;
			r0 ^= r2; tv &= r2;
			tv ^= r0; r0 &= r1;
			r1 ^= r3; r3 |= tv;
			r2 ^= r3; r0 ^= r3;
			r1 ^= tv; r3 &= r2;
			r3 ^= r1; r1 ^= r0;
			r1 |= r2; r0 ^= r3;
			r1 ^= tv;
			r0 ^= r1;
			tv = r0; r0 = r2; r2 = r3; r3 = tv;
			tv = 0;
		}

		void ForwardBox4(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r1 ^= r3; r3 = ~r3;
			r2 ^= r3; r3 ^= r0;
			tv = r1; r1 &= r3;
			r1 ^= r2; tv ^= r3;
			r0 ^= tv; r2 &= tv;
			r2 ^= r0; r0 &= r1;
			r3 ^= r0; tv |= r1;
			tv ^= r0; r0 |= r3;
			r0 ^= r2; r2 &= r3;
			r0 = ~r0; tv ^= r2;
			r2 = r0; r0 = r1; r1 = tv;
			tv = 0;
		}

		void BackwardBox4(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			tv = r2; r2 &= r3;
			r2 ^= r1; r1 |= r3;
			r1 &= r0; tv ^= r2;
			tv ^= r1; r1 &= r2;
			r0 = ~r0; r3 ^= tv;
			r1 ^= r3; r3 &= r0;
			r3 ^= r2; r0 ^= r1;
			r2 &= r0; r3 ^= r0;
			r2 ^= tv;
			r2 |= r3; r3 ^= r0;
			r2 ^= r1;
			r1 = r3; r3 = tv;
			tv = 0;
		}

		void ForwardBox5(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r0 ^= r1; r1 ^= r3;
			r3 = ~r3; tv = r1;
			r1 &= r0; r2 ^= r3;
			r1 ^= r2; r2 |= tv;
			tv ^= r3; r3 &= r1;
			r3 ^= r0; tv ^= r1;
			tv ^= r2; r2 ^= r0;
			r0 &= r3; r2 = ~r2;
			r0 ^= tv; tv |= r3;
			r2 ^= tv;
			tv = r0; r0 = r1; r1 = r3; r3 = r2; r2 = tv;
			tv = 0;
		}

		void BackwardBox5(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r1 = ~r1; tv = r3;
			r2 ^= r1; r3 |= r0;
			r3 ^= r2; r2 |= r1;
			r2 &= r0; tv ^= r3;
			r2 ^= tv; tv |= r0;
			tv ^= r1; r1 &= r2;
			r1 ^= r3; tv ^= r2;
			r3 &= tv; tv ^= r1;
			r3 ^= tv; tv = ~tv;
			r3 ^= r0;
			r0 = r1; r1 = tv; tv = r2; r2 = r3; r3 = tv;
			tv = 0;
		}

		void ForwardBox6(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r2 = ~r2; tv = r3;
			r3 &= r0; r0 ^= tv;
			r3 ^= r2; r2 |= tv;
			r1 ^= r3; r2 ^= r0;
			r0 |= r1; r2 ^= r1;
			tv ^= r0; r0 |= r3;
			r0 ^= r2; tv ^= r3;
			tv ^= r0; r3 = ~r3;
			r2 &= tv;
			r2 ^= r3;
			r3 = r2; r2 = tv;
			tv = 0;
		}

		void BackwardBox6(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			r0 ^= r2; tv = r2;
			r2 &= r0; tv ^= r3;
			r2 = ~r2; r3 ^= r1;
			r2 ^= r3; tv |= r0;
			r0 ^= r2; r3 ^= tv;
			tv ^= r1; r1 &= r3;
			r1 ^= r0; r0 ^= r3;
			r0 |= r2; r3 ^= r1;
			tv ^= r0;
			r0 = r1; r1 = r2; r2 = tv;
			tv = 0;
		}

		void ForwardBox7(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			tv = r1; r1 |= r2;
			r1 ^= r3; tv ^= r2;
			r2 ^= r1; r3 |= tv;
			r3 &= r0; tv ^= r2;
			r3 ^= r1; r1 |= tv;
			r1 ^= r0; r0 |= tv;
			r0 ^= r2; r1 ^= tv;
			r2 ^= r1; r1 &= r0;
			r1 ^= tv; r2 = ~r2;
			r2 |= r0;
			tv ^= r2;
			r2 = r1; r1 = r3; r3 = r0; r0 = tv;
			tv = 0;
		}

		void BackwardBox7(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			uint32_t tv;
			tv = r2; r2 ^= r0;
			r0 &= r3; tv |= r3;
			r2 = ~r2; r3 ^= r1;
			r1 |= r0; r0 ^= r2;
			r2 &= tv; r3 &= tv;
			r1 ^= r2; r2 ^= r0;
			r0 |= r2; tv ^= r1;
			r0 ^= r3; r3 ^= tv;
			tv |= r0; r3 ^= r2;
			tv ^= r2;
			r2 = r1; r1 = r0; r0 = r3; r3 = tv;
			tv = 0;
		}

		void ForwardLinearTransform(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d)
		{
			a = std::rotl(a, 13);
			c = std::rotl(c, 3);

			b ^= a ^ c;
			d ^= c ^ (a << 3);

			b = std::rotl(b, 1);
			d = std::rotl(d, 7);

			a ^= b ^ d;
			c ^= d ^ (b << 7);

			a = std::rotl(a, 5);
			c = std::rotl(c, 22);
		}

		void BackwardLinearTransform(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d)
		{
			c = std::rotr(c, 22);
			a = std::rotr(a, 5);

			c ^= d ^ (b << 7);
			a ^= b ^ d;

			d = std::rotr(d, 7);
			b = std::rotr(b, 1);

			d ^= c ^ (a << 3);
			b ^= a ^ c;

			c = std::rotr(c, 3);
			a = std::rotr(a, 13);
		}

		void ExclusiveOR(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d, std::array<std::uint32_t, 4> Keys)
		{
			a ^= Keys[0];
			b ^= Keys[1];
			c ^= Keys[2];
			d ^= Keys[3];
		}

		template<std::uint32_t BoxNumber>
		void ForwardRoundFunction(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d, std::array<std::uint32_t, 4> Keys)
		{
			this->ExclusiveOR(a, b, c, d, Keys);

			if constexpr (BoxNumber == 0)
				this->ForwardBox0(a, b, c, d);
			else if constexpr (BoxNumber == 1)
				this->ForwardBox1(a, b, c, d);
			else if constexpr (BoxNumber == 2)
				this->ForwardBox2(a, b, c, d);
			else if constexpr (BoxNumber == 3)
				this->ForwardBox3(a, b, c, d);
			else if constexpr (BoxNumber == 4)
				this->ForwardBox4(a, b, c, d);
			else if constexpr (BoxNumber == 5)
				this->ForwardBox5(a, b, c, d);
			else if constexpr (BoxNumber == 6)
				this->ForwardBox6(a, b, c, d);
			else if constexpr (BoxNumber == 7)
				this->ForwardBox7(a, b, c, d);
			else
				static_assert(BoxNumber < 8, "");

			this->ForwardLinearTransform(a, b, c, d);
		}

		template<std::uint32_t BoxNumber>
		void BackwardRoundFunction(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d, std::array<std::uint32_t, 4> Keys)
		{
			this->BackwardLinearTransform(a, b, c, d);

			if constexpr (BoxNumber == 0)
				this->BackwardBox0(a, b, c, d);
			else if constexpr (BoxNumber == 1)
				this->BackwardBox1(a, b, c, d);
			else if constexpr (BoxNumber == 2)
				this->BackwardBox2(a, b, c, d);
			else if constexpr (BoxNumber == 3)
				this->BackwardBox3(a, b, c, d);
			else if constexpr (BoxNumber == 4)
				this->BackwardBox4(a, b, c, d);
			else if constexpr (BoxNumber == 5)
				this->BackwardBox5(a, b, c, d);
			else if constexpr (BoxNumber == 6)
				this->BackwardBox6(a, b, c, d);
			else if constexpr (BoxNumber == 7)
				this->BackwardBox7(a, b, c, d);
			else
				static_assert(BoxNumber < 8, "");

			this->ExclusiveOR(a, b, c, d, Keys);
		}

		static constexpr std::array<std::uint32_t, 128> IP_Table
		{
			0,32,64,96,1,33,65,97,2,34,66,98,3,35,67,99,
			4,36,68,100,5,37,69,101,6,38,70,102,7,39,71,103,
			8,40,72,104,9,41,73,105,10,42,74,106,11,43,75,107,
			12,44,76,108,13,45,77,109,14,46,78,110,15,47,79,111,
			16,48,80,112,17,49,81,113,18,50,82,114,19,51,83,115,
			20,52,84,116,21,53,85,117,22,54,86,118,23,55,87,119,
			24,56,88,120,25,57,89,121,26,58,90,122,27,59,91,123,
			28,60,92,124,29,61,93,125,30,62,94,126,31,63,95,127
		};

		static constexpr std::array<std::uint32_t, 128> FP_Table
		{
			0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,
			64,68,72,76,80,84,88,92,96,100,104,108,112,116,120,124,
			1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61,
			65,69,73,77,81,85,89,93,97,101,105,109,113,117,121,125,
			2,6,10,14,18,22,26,30,34,38,42,46,50,54,58,62,
			66,70,74,78,82,86,90,94,98,102,106,110,114,118,122,126,
			3,7,11,15,19,23,27,31,35,39,43,47,51,55,59,63,
			67,71,75,79,83,87,91,95,99,103,107,111,115,119,123,127
		};

		void ApplyPermutation(std::array<std::uint32_t, 128> table, std::span<std::uint32_t> input, std::span<std::uint32_t> output)
		{
			/* Apply the permutation defined by 't' to 'input' and return the result in 'output'. */

			auto SetBit = [](std::span<std::uint32_t> words, std::uint32_t p, std::uint8_t bit) -> void
			{
				/* Set the bit at position 'p' of little-endian word array 'words' to 'bit'. */

				if ( bit )
				{
					words[ p / 32 ] |= ( static_cast<std::uint32_t>(0x1) << (p % 32) );
				}
				else
				{
					words[ p / 32 ] &= ~( static_cast<std::uint32_t>(0x1) << (p % 32) );
				}
			};

			auto GetBit = [](std::span<std::uint32_t> words, std::uint32_t p) -> std::uint8_t
			{
				/* Return the value of the bit at position 'p' in little-endian word array 'words'. */

				return ( std::uint8_t )( ( words[ p / 32 ] & ( ( std::uint32_t )0x1 << p % 32 ) ) >> p % 32 );
			};

			std::uint32_t p;
			for ( p = 0; p < 4; p++ )
			{
				output[ p ] = 0;
			}

			for ( p = 0; p < 128; p++ )
			{
				SetBit( output, p, GetBit( input, table[ p ] ) );
			}
		}

		// Initial Permutation function implementation
		void IP(std::span<std::uint32_t> input, std::span<std::uint32_t> output) {
		  /* Apply the Initial Permutation to 'input', yielding 'output'. */
		  ApplyPermutation(IP_Table, input, output);
		}

		void FP(std::span<std::uint32_t> input, std::span<std::uint32_t> output) {
		  /* Apply the Final Permutation to 'input', yielding 'output'. */
		  ApplyPermutation(FP_Table, input, output);
		}

		// Initial Permutation Inverse function implementation
		void IP_Inverse(std::span<std::uint32_t> output, std::span<std::uint32_t> input) {
		  /* Apply the Initial Permutation in reverse to 'output', yielding 'input'. */
		  ApplyPermutation(FP_Table, output, input);
		}

		// Final Permutation Inverse function implementation
		void FP_Inverse(std::span<std::uint32_t> output, std::span<std::uint32_t> input) {
		  /* Apply the Final Permutation in reverse to 'output', yielding 'input'. */
		  ApplyPermutation(IP_Table, output, input);
		}

		std::uint32_t& AccessSubkey(std::size_t Index)
		{
			return this->Subkeys[Index / this->Subkeys[0].size()][Index % this->Subkeys[0].size()];
		}

	public:

		void KeySchedule(std::span<const std::uint8_t> ByteKeys)
		{
			std::array<std::uint32_t, 8> Keys {};

			//Copy the original key
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(ByteKeys, Keys.data());

			std::uint32_t Index = 0;

			//Short keys with less than 256 bits are mapped to full-length keys of 256 bits by appending one '1' bit to the MSB end
			if(Index < 8)
			{
				Keys[Index++] = 0x00000001;
			}

			//Append as many '0' bits as required to make up 256 bits
			while(Index < 8)
			{
				Keys[Index++] = 0;
			}

			/*
			 * Generate Pre-Subkey
			 */

			std::uint32_t TemporaryKey = 0;

			//Generate the first 8 words of the prekey
			TemporaryKey = Keys[0] ^ Keys[3] ^ Keys[5] ^ Keys[7] ^ GOLDEN_RATIO ^ 0;
			this->Subkeys[0][0] = std::rotl(TemporaryKey, 11);

			TemporaryKey = Keys[1] ^ Keys[4] ^ Keys[6] ^ this->Subkeys[0][0] ^ GOLDEN_RATIO ^ 1;
			this->Subkeys[0][1] = std::rotl(TemporaryKey, 11);

			TemporaryKey = Keys[2] ^ Keys[5] ^ Keys[7] ^ this->Subkeys[0][1] ^ GOLDEN_RATIO ^ 2;
			this->Subkeys[0][2] = std::rotl(TemporaryKey, 11);

			TemporaryKey = Keys[3] ^ Keys[6] ^ this->Subkeys[0][0] ^ this->Subkeys[0][2] ^ GOLDEN_RATIO ^ 3;
			this->Subkeys[0][3] = std::rotl(TemporaryKey, 11);

			TemporaryKey = Keys[4] ^ Keys[7] ^ this->Subkeys[0][1]^ this->Subkeys[0][3] ^ GOLDEN_RATIO ^ 4;
			this->Subkeys[1][0] = std::rotl(TemporaryKey, 11);

			TemporaryKey = Keys[5] ^ this->Subkeys[0][0] ^ this->Subkeys[0][2] ^ this->Subkeys[1][0] ^ GOLDEN_RATIO ^ 5;
			this->Subkeys[1][1] = std::rotl(TemporaryKey, 11);

			TemporaryKey = Keys[6] ^ this->Subkeys[0][1] ^ this->Subkeys[0][3] ^ this->Subkeys[1][1] ^ GOLDEN_RATIO ^ 6;
			this->Subkeys[1][2] = std::rotl(TemporaryKey, 11);

			TemporaryKey = Keys[7] ^ this->Subkeys[0][2] ^ this->Subkeys[1][0]^ this->Subkeys[1][2] ^ GOLDEN_RATIO ^ 7;
			this->Subkeys[1][3] = std::rotl(TemporaryKey, 11);

			/*
			 * Generate Subkey
			 */

			//Expand the prekey using affine recurrence
			for(Index = 8; Index < 132; ++Index)
			{
				TemporaryKey = this->AccessSubkey(Index - 8) ^ this->AccessSubkey(Index - 5)
						^ this->AccessSubkey(Index - 3) ^ this->AccessSubkey(Index - 1) ^ GOLDEN_RATIO ^ Index;
				this->AccessSubkey(Index) = std::rotl(TemporaryKey, 11);
			}

			//The round keys are now calculated from the prekeys using the S-boxes
			for(Index = 0; Index < 128; Index += 32)
			{
				this->ForwardBox3(this->AccessSubkey(Index + 0), this->AccessSubkey(Index + 1), this->AccessSubkey(Index + 2), this->AccessSubkey(Index + 3));
				this->ForwardBox2(this->AccessSubkey(Index + 4), this->AccessSubkey(Index + 5), this->AccessSubkey(Index + 6), this->AccessSubkey(Index + 7));
				this->ForwardBox1(this->AccessSubkey(Index + 8), this->AccessSubkey(Index + 9), this->AccessSubkey(Index + 10), this->AccessSubkey(Index + 11));
				this->ForwardBox0(this->AccessSubkey(Index + 12), this->AccessSubkey(Index + 13), this->AccessSubkey(Index + 14), this->AccessSubkey(Index + 15));
				this->ForwardBox7(this->AccessSubkey(Index + 16), this->AccessSubkey(Index + 17), this->AccessSubkey(Index + 18), this->AccessSubkey(Index + 19));
				this->ForwardBox6(this->AccessSubkey(Index + 20), this->AccessSubkey(Index + 21), this->AccessSubkey(Index + 22), this->AccessSubkey(Index + 23));
				this->ForwardBox5(this->AccessSubkey(Index + 24), this->AccessSubkey(Index + 25), this->AccessSubkey(Index + 26), this->AccessSubkey(Index + 27));
				this->ForwardBox4(this->AccessSubkey(Index + 28), this->AccessSubkey(Index + 29), this->AccessSubkey(Index + 30), this->AccessSubkey(Index + 31));
			}
			
			//Calculate the last round key
			this->ForwardBox3(this->AccessSubkey(128), this->AccessSubkey(129), this->AccessSubkey(130), this->AccessSubkey(131));
		}

		void UpdateKey( std::span<const std::uint8_t> ByteKeys )
		{
			//Check the length of the byte keys
			my_cpp2020_assert
			(
				ByteKeys.size() == 16 || ByteKeys.size() == 24 || ByteKeys.size() == 32,
				"",
				std::source_location::current()
			);

			this->KeySchedule( ByteKeys );
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> InputBlock, std::span<std::uint8_t> OutputBlock)
		{
			if(InputBlock.size() != 16)
				my_cpp2020_assert(false, "", std::source_location::current());
			if(OutputBlock.size() != 16)
				my_cpp2020_assert(false, "", std::source_location::current());

			std::array<std::uint32_t, 4> BufferDatas {};
			std::array<std::uint32_t, 4> BufferDatas2 {};

			//The 16 bytes of plaintext are split into 4 words
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(InputBlock, BufferDatas.data());
			auto& [a, b, c, d] = BufferDatas2;

			IP(BufferDatas, BufferDatas2);

			//The 32 rounds use 8 different S-boxes
			for(std::size_t Index = 0; Index < 32; Index += 8)
			{
				this->ForwardRoundFunction<0>(a, b, c, d, this->Subkeys[Index]);
				this->ForwardRoundFunction<1>(a, b, c, d, this->Subkeys[Index + 1]);
				this->ForwardRoundFunction<2>(a, b, c, d, this->Subkeys[Index + 2]);
				this->ForwardRoundFunction<3>(a, b, c, d, this->Subkeys[Index + 3]);
				this->ForwardRoundFunction<4>(a, b, c, d, this->Subkeys[Index + 4]);
				this->ForwardRoundFunction<5>(a, b, c, d, this->Subkeys[Index + 5]);
				this->ForwardRoundFunction<6>(a, b, c, d, this->Subkeys[Index + 6]);
				this->ForwardRoundFunction<7>(a, b, c, d, this->Subkeys[Index + 7]);
			}

			//In the last round, the linear transformation is replaced by an additional key mixing
			this->BackwardLinearTransform(a, b, c, d);
			this->ExclusiveOR(a, b, c ,d, this->Subkeys[32]);

			FP(BufferDatas2, BufferDatas);

			//The 4 words of ciphertext are then written as 16 bytes
			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(BufferDatas, OutputBlock.data());
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> InputBlock, std::span<std::uint8_t> OutputBlock)
		{
			if(InputBlock.size() != 16)
				my_cpp2020_assert(false, "", std::source_location::current());
			if(OutputBlock.size() != 16)
				my_cpp2020_assert(false, "", std::source_location::current());

			std::array<std::uint32_t, 4> BufferDatas {};
			std::array<std::uint32_t, 4> BufferDatas2 {};

			//The 16 bytes of ciphertext are split into 4 words
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(InputBlock, BufferDatas.data());
			auto& [a, b, c, d] = BufferDatas2;

			FP_Inverse(BufferDatas, BufferDatas2);

			//In the first decryption round, the inverse linear transformation is replaced by an additional key mixing
			this->ExclusiveOR(a, b, c ,d, this->Subkeys[32]);
			this->ForwardLinearTransform(a, b, c, d);
			
			//Decryption is different from encryption in that the inverse of the S-boxes must be used in the reverse order,
			//As well as the inverse linear transformation and reverse order of the subkeys
			for(std::size_t Index = 0; Index < 32; Index += 8)
			{
				this->BackwardRoundFunction<7>(a, b, c, d, this->Subkeys[31 - Index]);
				this->BackwardRoundFunction<6>(a, b, c, d, this->Subkeys[30 - Index]);
				this->BackwardRoundFunction<5>(a, b, c, d, this->Subkeys[29 - Index]);
				this->BackwardRoundFunction<4>(a, b, c, d, this->Subkeys[28 - Index]);
				this->BackwardRoundFunction<3>(a, b, c, d, this->Subkeys[27 - Index]);
				this->BackwardRoundFunction<2>(a, b, c, d, this->Subkeys[26 - Index]);
				this->BackwardRoundFunction<1>(a, b, c, d, this->Subkeys[25 - Index]);
				this->BackwardRoundFunction<0>(a, b, c, d, this->Subkeys[24 - Index]);
			}

			IP_Inverse(BufferDatas2, BufferDatas);

			//The 4 words of plaintext are then written as 16 bytes
			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(BufferDatas, OutputBlock.data());
		}

		OfficialAlgorithm() = default;
		~OfficialAlgorithm() = default;
	};

	class DataWorker128 : public CommonSecurity::BlockCipher128_128
	{

	private:

		OfficialAlgorithm AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.ProcessBlockEncryption(Input, Ouput);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.ProcessBlockDecryption(Input, Ouput);
		}

		DataWorker128() = default;
		virtual ~DataWorker128() = default;

		DataWorker128(DataWorker128& _object) = delete;
		DataWorker128& operator=(const DataWorker128& _object) = delete;
	};

	class DataWorker192 : public CommonSecurity::BlockCipher128_192
	{

	private:

		OfficialAlgorithm AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.ProcessBlockEncryption(Input, Ouput);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.ProcessBlockDecryption(Input, Ouput);
		}

		DataWorker192() = default;
		virtual ~DataWorker192() = default;

		DataWorker192(DataWorker192& _object) = delete;
		DataWorker192& operator=(const DataWorker192& _object) = delete;
	};

	class DataWorker256 : public CommonSecurity::BlockCipher128_256
	{

	private:

		OfficialAlgorithm AlgorithmObject;

	public:

		void KeyExpansion(std::span<const std::uint8_t> BytesKey) override
		{
			AlgorithmObject.KeySchedule(BytesKey);
		}

		void ProcessBlockEncryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.ProcessBlockEncryption(Input, Ouput);
		}

		void ProcessBlockDecryption(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Ouput) override
		{
			AlgorithmObject.ProcessBlockDecryption(Input, Ouput);
		}

		DataWorker256() = default;
		virtual ~DataWorker256() = default;

		DataWorker256(DataWorker256& _object) = delete;
		DataWorker256& operator=(const DataWorker256& _object) = delete;
	};
}