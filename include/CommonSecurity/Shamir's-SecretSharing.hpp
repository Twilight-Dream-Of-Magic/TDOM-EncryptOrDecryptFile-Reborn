#pragma once

/*
	Shamir's Secret Sharing, formulated by Adi Shamir, is one of the first secret sharing schemes in cryptography.
	It is based on polynomial interpolation over galois finite fields.
	https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
	https://www.geeksforgeeks.org/shamirs-secret-sharing-algorithm-cryptography/
*/
namespace CommonSecurity::SecretSharing
{
	/*
		@param K; value k is the threshold of joinable secret parts
		@param N; value n is the number of secret parts to produce
	*/
	template<typename ByteType, std::uint32_t K, std::uint32_t N>
	requires std::is_same_v<ByteType, std::uint8_t> || std::is_same_v<ByteType, std::byte>
	class ShamirsAlgorithmScheme
	{

	private:

		GaloisFiniteField256<ByteType>& GF256_Instance = GaloisFiniteField256<ByteType>::get_instance();

		// 阀值： 你需要持有多少个属于这个秘密的部分数据，才能还原为原始的秘密数据？（注意：它必须大于1！）
		// Threshold: How many parts of the data belonging to this secret do you need to hold in order to restore it to the original secret data? (Note: it must be greater than 1!)
		static constexpr std::uint32_t Threshold = K;

		// 数量：本次你需要生成多少个属于这个秘密的部分数据？（注意： 它不能大于伽罗瓦有限域的2的8次方的值！）
		// 或者说你知道这个原始的秘密数据，由多少个秘密的部分数据组成吗？
		// Amount: How many partial data belonging to this secret do you need to generate this time? (Note: it cannot be greater than the value of the 8th power of 2 of the Galois finite field!)
		// Or do you know how many secret parts of this original secret data consist of?
		static constexpr std::uint32_t Amount = N;

		static std::uint32_t compute_degree(std::vector<ByteType> polynomials)
		{
			for(std::size_t index = polynomials.size() - 1; index >= 1; index--)
			{
				if( polynomials[index] != static_cast<ByteType>(0x00) )
					return index;
			}

			return 0;
		}

		// Generate a random polynomial of the given degree, but with the provided intercept value.
		static std::vector<ByteType> generate_polynomials(std::uint32_t degree, ByteType intercept_value)
		{
			using CommonSecurity::DRBG::HMAC::WorkerBasedHAMC;
			using namespace Cryptograph::CommonModule;

			std::vector<ByteType> polynomials(degree + 1, static_cast<ByteType>(0x00));

			CommonSecurity::DataHashingWrapper::HashersAssistantParameters HAP_ObjectArgument;
			HAP_ObjectArgument.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::BLAKE2;
			HAP_ObjectArgument.generate_hash_bit_size = 512;
			HAP_ObjectArgument.whether_use_hash_extension_bit_mode = false;
			HAP_ObjectArgument.inputDataString = "";
			HAP_ObjectArgument.outputHashedHexadecimalString = "";

			WorkerBasedHAMC DRBG(HAP_ObjectArgument);

			DRBG.instantiate_state(256, "");
			std::vector<std::uint8_t> random_bytes_data(degree + 1, std::uint8_t{0x00}); 

			// generate random polynomials until we find one of the given degree
			do
			{
				DRBG.generate_bytes(random_bytes_data);
				
				if constexpr(std::is_same_v<ByteType, std::byte>)
				{
					Adapters::classicByteToByte(random_bytes_data, polynomials);
				}
				else
				{
					polynomials.assign(random_bytes_data.begin(), random_bytes_data.end());
				}

			} while (compute_degree(polynomials) != degree);

			// ensure the intercept is set
			polynomials[0] = intercept_value;

			return polynomials;
		}

	public:

		std::map<std::uint32_t, std::vector<ByteType>> hide_secret_byte_with_splitter(const std::vector<ByteType>& secret_bytes)
		{
			// generate byte matrix for secret bytes part
			std::vector< std::vector<ByteType> > byte_matrix( Amount, std::vector<ByteType>( secret_bytes.size(), static_cast<ByteType>(0x00) ) );

			// for each byte, generate a vector of random polynomials
			for(std::uint32_t index = 0; index < secret_bytes.size(); index++)
			{
				std::vector<ByteType> random_polynomials = generate_polynomials( Threshold - 1, secret_bytes[index] );

				//Each secret bytes part's is (random_polynomials id associated with itself)
				for(std::uint32_t id = 1; id <= Amount; id++)
				{
					// Generate a `secret bytes part` number of (x,y) pairs
					byte_matrix[id - 1][index] = GaloisFiniteField256<ByteType>::evaluation_polynomials(GF256_Instance, random_polynomials, static_cast<ByteType>(id));
				}
			}

			//return as a map of the objects
			std::map<std::uint32_t, std::vector<ByteType>> map_of_hidden_secret_bytes;
			
			for(std::uint32_t map_index = 0, counter = Amount; counter > 0; --counter )
			{
				if(map_index < byte_matrix.size())
				{
					map_of_hidden_secret_bytes.insert( std::pair<std::uint32_t, std::vector<ByteType>>{ map_index + 1, byte_matrix[map_index] } );
					++map_index;
				}
			}

			return map_of_hidden_secret_bytes;
		}

		std::vector<ByteType> apparent_secret_byte_with_joinner(const std::map<std::uint32_t, std::vector<ByteType>>& map_of_hidden_secret_bytes)
		{
			my_cpp2020_assert( map_of_hidden_secret_bytes.size() > 0, "ShamirsAlgorithmScheme: None of the secret part byte values are provided !", std::source_location::current() );

			//Note: The key of the map is inserted from position 1!
			std::size_t current_secret_bytes_part_size = map_of_hidden_secret_bytes.at(1).size();

			if(map_of_hidden_secret_bytes.size() > 1U)
			{
				for(const auto& pair_data : map_of_hidden_secret_bytes)
				{
					my_cpp2020_assert( pair_data.second.size() == current_secret_bytes_part_size , "ShamirsAlgorithmScheme: The length of the secret byte array is not consistent for each part !", std::source_location::current() );
				}
			}

			std::vector<ByteType> secret_bytes( current_secret_bytes_part_size, static_cast<ByteType>(0x00) );

			for(std::uint32_t index = 0; index < secret_bytes.size(); index++)
			{
				//byte matrix point
				std::vector< std::vector<ByteType> > byte_matrix( map_of_hidden_secret_bytes.size(), std::vector<ByteType>(2, static_cast<ByteType>(0x00)) );

				std::size_t index2 = 0;
				for(const auto& pair_data : map_of_hidden_secret_bytes)
				{
					byte_matrix[index2][0] = static_cast<ByteType>(pair_data.first);
					byte_matrix[index2][1] = pair_data.second[index];
					index2++;
				}
				secret_bytes[index] = GaloisFiniteField256<ByteType>::polynomial_interpolation(GF256_Instance, byte_matrix);
			}

			return secret_bytes;
		}

		ShamirsAlgorithmScheme() 
		{
			static_assert( Threshold > 1, "ShamirsAlgorithmScheme: The threshold of joinable secret parts must be > 1 !" );
			static_assert( Amount >= Threshold, "ShamirsAlgorithmScheme: Amount >= Threshold !" );
			static_assert( Amount <= 255, "ShamirsAlgorithmScheme: The number of secret parts to produce > 255 !" );
		}

		~ShamirsAlgorithmScheme() = default;
	};
}
