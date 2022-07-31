#pragma once

namespace CommonSecurity
{
	/*
		Deterministic Random Bit Generators baesd on HMAC Algorithm
	*/
	namespace DRBG::HMAC
	{
		using CommonSecurity::DataHashingWrapper::HashersAssistantParameters;
		using CommonSecurity::DataHashingWrapper::HMAC_FunctionObject;

		class WorkerBasedHAMC
		{
			
		private:
			HashersAssistantParameters HashersAssistantParametersObject;

			struct CurrentDataState
			{
				/*
				
					Current value
				 
					"The value of hashed block bits, which is updated each time another hashed block bits of output are produced"
				*/
				std::string hash_value_data = std::string(512 / 8 * 2, 0x00); 
				
				/*
					Current key

					"The hashed-block-bit Key, which is updated at least once each time that the DRBG mechanism generates pseudorandom bits."
				*/
				std::string key_data = std::string(512 / 8 * 2, 0x00);
				
				/*
					Reseed counter

					"A counter (reseed_counter) that indicates the number of requests for pseudorandom bits since instantiation or reseeding"
				*/
				std::uint32_t reseed_counter = 0;
			};

			std::unique_ptr<CurrentDataState> CurrentDataStateObjectPointer = nullptr;

			bool update_state
			(
				CurrentDataState& state,
				const std::string& provided_data
			)
			{
				//  a || b is data concatenation operation
				// Example: byte a is 0x01, byte b is 0x02, then a||b is 0x0102

				/*
					1.
					KEY := HMAC( KEY, HASH_VALUE || 0x00 || provided_data );
				*/
				state.key_data = HMAC_FunctionObject(this->HashersAssistantParametersObject, state.hash_value_data + std::string(1, 0x00) + provided_data, this->HashersAssistantParametersObject.generate_hash_bit_size / 8 * 2, state.key_data);

				/*
					2.
					HASH_VALUE := HMAC( KEY, HASH_VALUE );
				*/
				state.hash_value_data = HMAC_FunctionObject(this->HashersAssistantParametersObject, state.hash_value_data, this->HashersAssistantParametersObject.generate_hash_bit_size / 8 * 2, state.key_data);

				/*
					3.
					If ( provided_data == null-pointer or element_length of provided_data is empty )
						then return KEY and HASH_VALUE
					Else
						Continue with the execution steps
				*/
				if(provided_data.empty())
					return false;

				/*
					4.
					KEY := HMAC(KEY, HASH_VALUE || 0x01 || provided_data);
				*/
				state.key_data = HMAC_FunctionObject(this->HashersAssistantParametersObject, state.hash_value_data + std::string(1, 0x01) + provided_data, this->HashersAssistantParametersObject.generate_hash_bit_size / 8 * 2, state.key_data);

				/*
					5.
					HASH_VALUE := HMAC( KEY, HASH_VALUE );
				*/
				state.hash_value_data = HMAC_FunctionObject(this->HashersAssistantParametersObject, state.hash_value_data, this->HashersAssistantParametersObject.generate_hash_bit_size / 8 * 2, state.key_data);

				/*
					6.
					return KEY and HASH_VALUE
				*/
				return true;
			}

		public:
			bool reseed
			(
				std::size_t entropy_data_size = 256,
				std::string personal_optional_data = ""
			)
			{
				using namespace UtilTools::DataFormating;

				if(CurrentDataStateObjectPointer == nullptr)
					return false;

				if(entropy_data_size == 0)
					entropy_data_size = 8;

				std::vector<std::uint32_t> random_seed_numbers_data = CommonSecurity::GenerateSecureRandomNumberSeedSequence<std::uint32_t>(entropy_data_size);
				CommonSecurity::RNG_ISAAC::isaac<8> PRNG(random_seed_numbers_data.begin(), random_seed_numbers_data.end());
				random_seed_numbers_data.clear();
				random_seed_numbers_data.shrink_to_fit();

				std::vector<std::uint32_t> random_numbers_data(entropy_data_size, 0x00);
				
				for( auto& random_number : random_numbers_data)
				{
					random_number = PRNG();
				}

				std::vector<std::uint8_t> entropy_bytes_data = CommonToolkit::IntegerExchangeBytes::MessageUnpacking<std::uint32_t, std::uint8_t>(random_numbers_data.data(), random_numbers_data.size());
				random_numbers_data.clear();
				random_numbers_data.shrink_to_fit();

				entropy_bytes_data.resize(entropy_data_size);
				const std::string& entropy_string_data = ASCII_Hexadecmial::byteArray2HexadecimalString(entropy_bytes_data);

				/*
					1.
					seed_material = entropy_data || optional_data
				*/
				std::string seed_material = entropy_string_data + personal_optional_data;

				/* 
					2.
					( KEY, HASH_VALUE ) = HMAC_DBRG_Update ( seed_material, KEY, HASH_VALUE );
				*/
				bool is_worked = this->update_state(*CurrentDataStateObjectPointer, seed_material);

				if(is_worked == false)
					return false;

				/*
					3.
					reseed_counter = 1
				*/
				CurrentDataStateObjectPointer->reseed_counter = 1;

				return true;
			}

			void instantiate_state(std::size_t entropy_data_size = 256, std::string personal_optional_data = "")
			{
				if(CurrentDataStateObjectPointer == nullptr)
					CurrentDataStateObjectPointer.reset( new CurrentDataState() );

				bool is_worked = this->reseed(entropy_data_size, personal_optional_data);
			}

			bool generate_bytes
			(
				std::vector<unsigned char>& random_bytes_data,
				std::vector<unsigned char> personal_optional_bytes_data = std::vector<unsigned char>()
			)
			{
				using namespace UtilTools::DataFormating;

				constexpr std::uint32_t reseed_interval = 1024;

				if(CurrentDataStateObjectPointer == nullptr)
					return false;
				
				std::string random_string_data = ASCII_Hexadecmial::byteArray2HexadecimalString(random_bytes_data);
				std::string personal_optional_data = ASCII_Hexadecmial::byteArray2HexadecimalString(personal_optional_bytes_data);

				/*
					1.
					If reseed_counter > reseed_interval (1024), then return an indication that a reseed is required
				*/

				if(CurrentDataStateObjectPointer->reseed_counter > reseed_interval)
				{
					return false;
				}

				/*
					2.
					If personal_optional_data != Null
						then ( KEY, HASH_VALUE ) = HMAC_DBRG_Update ( personal_optional_data, KEY, HASH_VALUE );
					Else
						Continue with the execution steps
				*/
				if(!personal_optional_data.empty())
					this->update_state(*CurrentDataStateObjectPointer, personal_optional_data);

				/*
					3.
					temporary_bytes = null-pointer;

					4.
					While ( byte_size( temporary_bytes ) < requested_number_of_bits ) do:
				*/
				char* random_data_pointer = random_string_data.data();
				std::size_t random_data_size = random_string_data.size();
				auto& state = *CurrentDataStateObjectPointer;

				while(random_data_size != 0)
				{
					/*
						4.1
						HASH_VALUE := HMAC( KEY, HASH_VALUE );
					*/
					state.hash_value_data = HMAC_FunctionObject(this->HashersAssistantParametersObject, state.hash_value_data, this->HashersAssistantParametersObject.generate_hash_bit_size / 8, state.key_data);

					/*
						4.2.  temporary_bytes = temporary_bytes || HASH_VALUE

						5.
						returned_bits = Leftmost requested_number_of_bits of temporary_bytes
					*/
					std::size_t updated_random_data_size = random_string_data.size();
					if(updated_random_data_size > this->HashersAssistantParametersObject.generate_hash_bit_size / 8 * 2)
							updated_random_data_size = this->HashersAssistantParametersObject.generate_hash_bit_size / 8 * 2;

					std::ranges::copy(state.hash_value_data.data(), state.hash_value_data.data() + updated_random_data_size * sizeof(std::int8_t), random_data_pointer);

					random_data_pointer += updated_random_data_size;
					random_data_size -= updated_random_data_size;
				}

				/*
					6.
					( KEY, HASH_VALUE ) = HMAC_DBRG_Update ( personal_optional_data, KEY, HASH_VALUE );
				*/
				this->update_state(*CurrentDataStateObjectPointer, personal_optional_data);
				
				/*
					7.
					reseed_counter = reseed_counter + 1
				*/
				++(state.reseed_counter);

				/*
					returned_bits, and the new values of KEY, HASH_VALUE and reseed_counter as the new_working_state
				*/
				personal_optional_data.clear();
				random_bytes_data = ASCII_Hexadecmial::hexadecimalString2ByteArray(random_string_data);
				return true;
			}

			WorkerBasedHAMC(HashersAssistantParameters HAP_ObjectArgument) : HashersAssistantParametersObject(HAP_ObjectArgument)
			{
				if(!this->HashersAssistantParametersObject.inputDataString.empty())
					this->HashersAssistantParametersObject.inputDataString.clear();
				
				if(!this->HashersAssistantParametersObject.outputHashedHexadecimalString.empty())
					this->HashersAssistantParametersObject.outputHashedHexadecimalString.clear();

				if(this->HashersAssistantParametersObject.whether_use_hash_extension_bit_mode == true)
					this->HashersAssistantParametersObject.whether_use_hash_extension_bit_mode = false;

				CommonSecurity::HashProviderBaseTools::HashSize::validate(this->HashersAssistantParametersObject.generate_hash_bit_size, 512);
			}

			~WorkerBasedHAMC()
			{
				if(CurrentDataStateObjectPointer != nullptr)
					CurrentDataStateObjectPointer.reset();
			}
		};
	}
}