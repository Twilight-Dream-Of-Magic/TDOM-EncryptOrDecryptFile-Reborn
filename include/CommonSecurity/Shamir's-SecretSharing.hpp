#pragma once

/*
	Shamir's Secret Sharing, formulated by Adi Shamir, is one of the first secret sharing schemes in cryptography.
	It is based on polynomial interpolation over galois finite fields.
	https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
	https://www.geeksforgeeks.org/shamirs-secret-sharing-algorithm-cryptography/
*/
namespace CommonSecurity::SecretSharing
{
	class GaloisFiniteField256
	{

	private:
		static constexpr std::array<unsigned char, 256> LogarithmicTable
		{
			0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1a, 0xc6,
			0x03, 0xdf, 0x33, 0xee, 0x1b, 0x68, 0xc7, 0x4b,
			0x04, 0x64, 0xe0, 0x0e, 0x34, 0x8d, 0xef, 0x81,
			0x1c, 0xc1, 0x69, 0xf8, 0xc8, 0x08, 0x4c, 0x71,
			0x05, 0x8a, 0x65, 0x2f, 0xe1, 0x24, 0x0f, 0x21,
			0x35, 0x93, 0x8e, 0xda, 0xf0, 0x12, 0x82, 0x45,
			0x1d, 0xb5, 0xc2, 0x7d, 0x6a, 0x27, 0xf9, 0xb9,
			0xc9, 0x9a, 0x09, 0x78, 0x4d, 0xe4, 0x72, 0xa6,
			0x06, 0xbf, 0x8b, 0x62, 0x66, 0xdd, 0x30, 0xfd,
			0xe2, 0x98, 0x25, 0xb3, 0x10, 0x91, 0x22, 0x88,
			0x36, 0xd0, 0x94, 0xce, 0x8f, 0x96, 0xdb, 0xbd,
			0xf1, 0xd2, 0x13, 0x5c, 0x83, 0x38, 0x46, 0x40,
			0x1e, 0x42, 0xb6, 0xa3, 0xc3, 0x48, 0x7e, 0x6e,
			0x6b, 0x3a, 0x28, 0x54, 0xfa, 0x85, 0xba, 0x3d,
			0xca, 0x5e, 0x9b, 0x9f, 0x0a, 0x15, 0x79, 0x2b,
			0x4e, 0xd4, 0xe5, 0xac, 0x73, 0xf3, 0xa7, 0x57,
			0x07, 0x70, 0xc0, 0xf7, 0x8c, 0x80, 0x63, 0x0d,
			0x67, 0x4a, 0xde, 0xed, 0x31, 0xc5, 0xfe, 0x18,
			0xe3, 0xa5, 0x99, 0x77, 0x26, 0xb8, 0xb4, 0x7c,
			0x11, 0x44, 0x92, 0xd9, 0x23, 0x20, 0x89, 0x2e,
			0x37, 0x3f, 0xd1, 0x5b, 0x95, 0xbc, 0xcf, 0xcd,
			0x90, 0x87, 0x97, 0xb2, 0xdc, 0xfc, 0xbe, 0x61,
			0xf2, 0x56, 0xd3, 0xab, 0x14, 0x2a, 0x5d, 0x9e,
			0x84, 0x3c, 0x39, 0x53, 0x47, 0x6d, 0x41, 0xa2,
			0x1f, 0x2d, 0x43, 0xd8, 0xb7, 0x7b, 0xa4, 0x76,
			0xc4, 0x17, 0x49, 0xec, 0x7f, 0x0c, 0x6f, 0xf6,
			0x6c, 0xa1, 0x3b, 0x52, 0x29, 0x9d, 0x55, 0xaa,
			0xfb, 0x60, 0x86, 0xb1, 0xbb, 0xcc, 0x3e, 0x5a,
			0xcb, 0x59, 0x5f, 0xb0, 0x9c, 0xa9, 0xa0, 0x51,
			0x0b, 0xf5, 0x16, 0xeb, 0x7a, 0x75, 0x2c, 0xd7,
			0x4f, 0xae, 0xd5, 0xe9, 0xe6, 0xe7, 0xad, 0xe8,
			0x74, 0xd6, 0xf4, 0xea, 0xa8, 0x50, 0x58, 0xaf

		};

		static constexpr std::array<unsigned char, 256> ExponentialTable
		{
			0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
			0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26,
			0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9,
			0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0,
			0x9d, 0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35,
			0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23,
			0x46, 0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0,
			0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1,
			0x5f, 0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc,
			0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0,
			0xfd, 0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f,
			0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2,
			0xd9, 0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88,
			0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce,
			0x81, 0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93,
			0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc,
			0x85, 0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9,
			0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54,
			0xa8, 0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa,
			0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73,
			0xe6, 0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e,
			0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff,
			0xe3, 0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4,
			0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41,
			0x82, 0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e,
			0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6,
			0x51, 0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef,
			0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09,
			0x12, 0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5,
			0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16,
			0x2c, 0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83,
			0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x00
		};


		GaloisFiniteField256() = default;

	public:
		std::byte addition_or_subtraction(std::byte left, std::byte right)
		{
			return left ^ right;
		}

		std::byte multiplication(std::byte left, std::byte right)
		{
			if( left == static_cast<std::byte>(0x00) || right == static_cast<std::byte>(0x00) )
				return static_cast<std::byte>(0x00);
			
			auto integer_a = static_cast<std::uint32_t>(left);
			auto integer_b = static_cast<std::uint32_t>(right);

			integer_a = static_cast<std::uint32_t>( LogarithmicTable[integer_a] );
			integer_b = static_cast<std::uint32_t>( LogarithmicTable[integer_b] );

			auto value = static_cast<std::int32_t>(integer_a + integer_b) % 255;

			return static_cast<std::byte>( ExponentialTable[value] );
		}

		std::byte division(std::byte left, std::byte right)
		{
			if( left == static_cast<std::byte>(0x00) )
				return static_cast<std::byte>(0x00);

			if( right == static_cast<std::byte>(0x00) )
				my_cpp2020_assert( false, "GaloisFiniteField256: divide by zero", std::source_location::current() );
			
			auto integer_a = static_cast<std::uint32_t>(left);
			auto integer_b = static_cast<std::uint32_t>(right);

			integer_a = static_cast<std::uint32_t>( LogarithmicTable[integer_a] );
			integer_b = static_cast<std::uint32_t>( LogarithmicTable[integer_b] );

			auto value = static_cast<std::int32_t>(integer_a - integer_b) % 255;
			if(value < 0)
				value += 255;

			return static_cast<std::byte>( ExponentialTable[value] );
		}

		// Returns the value of the polynomial for the given index_value.
		static std::byte evaluation_polynomials(GaloisFiniteField256& this_instance, std::vector<std::byte> polynomials, std::byte index_value)
		{
			std::byte result { 0 };
			
			// special case the origin
			if(index_value == static_cast<std::byte>(0x00))
			{
				return polynomials[0];
			}
			
			// compute the polynomial value using Horner's method.
			for(std::int32_t index = polynomials.size() - 1; index >= 0; index--)
			{
				// do multiplication then addition
				result = this_instance.addition_or_subtraction( this_instance.multiplication(result, index_value), polynomials[index] );
			}

			return result;
		}

		static std::uint32_t compute_degree(std::vector<std::byte> polynomials)
		{
			for(std::size_t index = polynomials.size() - 1; index >= 1; index--)
			{
				if( polynomials[index] != static_cast<std::byte>(0x00) )
					return index;
			}

			return 0;
		}

		// Generate a random polynomial of the given degree, but with the provided intercept value.
		static std::vector<std::byte> generate_polynomials(std::uint32_t degree, std::byte intercept_value)
		{
			using CommonSecurity::DRBG::HMAC::WorkerBasedHAMC;
			using namespace Cryptograph::CommonModule;

			std::vector<std::byte> polynomials(degree + 1, static_cast<std::byte>(0x00));

			CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument;
			HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::BLAKE2;
			HAP_ObjectArgument.generate_hash_bit_size = 512;
			HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;
			HAP_ObjectArgument.inputDataString = "";
			HAP_ObjectArgument.outputHashedHexadecimalString = "";

			WorkerBasedHAMC DRBG(HAP_ObjectArgument);

			DRBG.instantiate_state();
			std::vector<std::uint8_t> random_bytes_data(degree + 1, 0x00); 

			// generate random polynomials until we find one of the given degree
			do
			{
				DRBG.generate_bytes(random_bytes_data);
				Adapters::classicByteToByte(random_bytes_data, polynomials);

			} while (compute_degree(polynomials) != degree);

			// ensure the intercept is set
			polynomials[0] = intercept_value;

			return polynomials;
		}

		// Using the computed Lagrangian function(0), N sample points are extracted and the interpolated values of the given byte_points are returned.
		static std::byte polynomial_interpolation(GaloisFiniteField256& this_instance, std::vector<std::vector<std::byte>> byte_points)
		{
			const std::byte input_value { 0 };
			std::byte output_value { 0 };

			for(std::size_t round = 0; round < byte_points.size(); round++)
			{
				const std::byte axis_x_from_a = byte_points[round][0];
				const std::byte axis_y_from_a = byte_points[round][1];
				
				std::byte lagrangian_basis_value { 1 };

				for(std::size_t round2 = 0; round2 < byte_points.size(); round2++)
				{
					const std::byte axis_x_from_b = byte_points[round2][0];

					if(round != round2)
					{
						// do subtraction then division
						auto that_number = this_instance.addition_or_subtraction(input_value, axis_x_from_b);
						auto denominator_of_that_number = this_instance.addition_or_subtraction(axis_x_from_a, axis_x_from_b);
						auto quotient = this_instance.division(that_number, denominator_of_that_number);

						// do multiplication
						lagrangian_basis_value = this_instance.multiplication(lagrangian_basis_value, quotient);
					}
				}

				// do multiplication then addition
				output_value = this_instance.addition_or_subtraction(output_value, this_instance.multiplication(lagrangian_basis_value, axis_y_from_a) );
			}

			return output_value;
		}

		static GaloisFiniteField256& get_instance()
		{
			static GaloisFiniteField256 instance = GaloisFiniteField256();
			return instance;
		}

		~GaloisFiniteField256() = default;
	};

	class ShamirsAlgorithmScheme
	{

	private:

		GaloisFiniteField256& GF256_Instance = GaloisFiniteField256::get_instance();

		// 阀值： 你需要持有多少个属于这个秘密的部分数据，才能还原为原始的秘密数据？（注意：它必须大于1！）
		// Threshold: How many parts of the data belonging to this secret do you need to hold in order to restore it to the original secret data? (Note: it must be greater than 1!)
		std::uint32_t Value_K = 0;

		// 数量：本次你需要生成多少个属于这个秘密的部分数据？（注意： 它不能大于伽罗瓦有限域的2的8次方的值！）
		// 或者说你知道这个原始的秘密数据，由多少个秘密的部分数据组成吗？
		// Amount: How many partial data belonging to this secret do you need to generate this time? (Note: it cannot be greater than the value of the 8th power of 2 of the Galois finite field!)
		// Or do you know how many secret parts of this original secret data consist of?
		std::uint32_t Value_N = 0;

	public:

		std::map<std::uint32_t, std::vector<std::byte>> hide_secret_byte_with_splitter(const std::vector<std::byte>& secret_bytes)
		{
			// generate byte matrix for secret bytes part
			std::vector< std::vector<std::byte> > byte_matrix( Value_N, std::vector<std::byte>( secret_bytes.size(), static_cast<std::byte>(0x00) ) );

			// for each byte, generate a vector of random polynomials
			for(std::uint32_t index = 0; index < secret_bytes.size(); index++)
			{
				std::vector<std::byte> random_polynomials = GaloisFiniteField256::generate_polynomials( Value_K - 1, secret_bytes[index] );

				//Each secret bytes part's is (random_polynomials id associated with itself)
				for(std::uint32_t id = 1; id <= Value_N; id++)
				{
					// Generate a `secret bytes part` number of (x,y) pairs
					byte_matrix[id - 1][index] = GaloisFiniteField256::evaluation_polynomials(GF256_Instance, random_polynomials, static_cast<std::byte>(id));
				}
			}

			//return as a map of the objects
			std::map<std::uint32_t, std::vector<std::byte>> map_of_hidden_secret_bytes;
			
			for(std::uint32_t map_index = 0, counter = Value_N; counter != 0; --counter )
			{
				if(map_index < byte_matrix.size())
				{
					map_of_hidden_secret_bytes.insert( std::pair<std::uint32_t, std::vector<std::byte>>{ map_index + 1, byte_matrix[map_index] } );
					++map_index;
				}
			}

			return map_of_hidden_secret_bytes;
		}

		std::vector<std::byte> apparent_secret_byte_with_joinner(const std::map<std::uint32_t, std::vector<std::byte>>& map_of_hidden_secret_bytes)
		{
			my_cpp2020_assert( map_of_hidden_secret_bytes.size() > 0, "ShamirsAlgorithmScheme: None of the secret part byte values are provided !", std::source_location::current() );

			//Note: The key of the map is inserted from position 1!
			std::size_t current_secret_bytes_part_size = map_of_hidden_secret_bytes.at(1).size();

			if(map_of_hidden_secret_bytes.size() > 1)
			{
				for(const auto& pair_data : map_of_hidden_secret_bytes)
				{
					my_cpp2020_assert( pair_data.second.size() == current_secret_bytes_part_size , "ShamirsAlgorithmScheme: The length of the secret byte array is not consistent for each part !", std::source_location::current() );
				}
			}

			std::vector<std::byte> secret_bytes( current_secret_bytes_part_size, static_cast<std::byte>(0x00) );

			for(std::uint32_t index = 0; index < secret_bytes.size(); index++)
			{
				//byte matrix point
				std::vector< std::vector<std::byte> > byte_matrix( map_of_hidden_secret_bytes.size(), std::vector<std::byte>(2, static_cast<std::byte>(0x00)) );

				std::size_t index2 = 0;
				for(const auto& pair_data : map_of_hidden_secret_bytes)
				{
					byte_matrix[index2][0] = static_cast<std::byte>(pair_data.first);
					byte_matrix[index2][1] = pair_data.second[index];
					index2++;
				}
				secret_bytes[index] = GaloisFiniteField256::polynomial_interpolation(GF256_Instance, byte_matrix);
			}

			return secret_bytes;
		}

		ShamirsAlgorithmScheme() = delete;

		ShamirsAlgorithmScheme(std::uint32_t K, std::uint32_t N) 
			:
			// value k is the threshold of joinable secret parts
			Value_K(K),
			// value n is the number of secret parts to produce 
			Value_N(N)
		{
			my_cpp2020_assert( Value_K > 1, "ShamirsAlgorithmScheme: The threshold of joinable secret parts must be > 1 !", std::source_location::current() );
			my_cpp2020_assert( Value_N >= Value_K, "ShamirsAlgorithmScheme: Value_N >= Value_K !", std::source_location::current() );
			my_cpp2020_assert( Value_N <= 255, "ShamirsAlgorithmScheme: The number of secret parts to produce > 255 !", std::source_location::current() );
		}

		~ShamirsAlgorithmScheme() = default;
	};
}
