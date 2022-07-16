#pragma once

#if 1

/*

	Internet-Drafts are working documents of the Internet Engineering Task Force (IETF).
	Note that other groups may also distribute working documents as Internet-Drafts.
	The list of current Internet-Drafts is at https://datatracker.ietf.org/drafts/current/.

	The eXtended-nonce ChaCha cipher construction (XChaCha) allows for ChaCha-based ciphersuites to accept a 192-bit nonce with similar guarantees to the original construction, except with a much lower probability of nonce misuse occurring.
	This helps for long running TLS connections.
	This also enables XChaCha constructions to be stateless, while retaining the same security assumptions as ChaCha.

	This document defines XChaCha20, which uses HChaCha20 to convert the key and part of the nonce into a subkey, which is in turn used with the remainder of the nonce with ChaCha20 to generate a pseudorandom keystream (e.g. for message encryption).
	This document also defines AEAD_XChaCha20_Poly1305, a variant of [RFC8439] that utilizes the XChaCha20 construction in place of ChaCha20.

	Paper References:
	https://datatracker.ietf.org/doc/html/rfc8439
	https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha

*/
namespace CommonSecurity::StreamDataCryptographic
{
	/*
		Abstract base class for XSalsa20, ChaCha20, XChaCha20 and their variants.

		Variants of Snuffle have two differences: the size of the nonce and the block function that produces a key stream block from a key, a nonce, and a counter. Subclasses of this class
		specifying these two information by overriding "ByteSizeOfNonces" and "ByteSizeOfKeyBlocks" and function "ProcessKeyStreamBlock(std::span<const std::uint8_t> nonce, std::uint32_t counter, std::span<std::uint8_t> block)".
		Concrete implementations of this class are meant to be used to construct an AEAD with "Poly1305".
		The base class of these AEAD constructions is "WorkerBaseWithPoly1305"
		For example, "ExtendedChaCha20" is a subclass of this class and a concrete WorkerBase implementation, and "ExtendedChaCha20WithPoly1305" is a subclass of "WorkerBaseWithPoly1305" and a concrete AEAD construction.
		AEAD and ADAD means Authenticated Encryption with Associated Data and Authenticated Decryption with Associated Data.
	*/
	class WorkerBase
	{

	private:

		std::unique_ptr<RNG_ISAAC::isaac<8>> RNG_Pointer = nullptr;

		/*
			@brief Processes the Encryption/Decryption function.
			@param nonce; The initial vector nonce.
			@param output; The output.
			@param input; The input.
			@param offset; The output's starting offset.
		*/
		void DoProcessFunction(std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> input, std::span<std::uint8_t> output, std::size_t offset = 0)
		{
			std::size_t data_size = input.size();
			std::size_t number_blocks = data_size / ByteSizeOfKeyBlocks() + 1;

			bool is_counter_overflow = false;
			auto& RNG = *(RNG_Pointer.get());
			std::vector<std::uint8_t> shuffle_nonce;

			auto key_stream_block = std::vector<std::uint8_t>(ByteSizeOfKeyBlocks(), 0x00);
			for(std::size_t current_block = 0; current_block < number_blocks; ++current_block)
			{
				std::size_t current_counter = current_block + InitialCounter;

				if(is_counter_overflow)
				{
					if(shuffle_nonce.empty())
						shuffle_nonce = std::vector<std::uint8_t>(nonce.begin(), nonce.end());

					if(RNG_Pointer == nullptr)
					{
						std::uint64_t RNG_Seed = 0;

						//Does it use a true random number generator?
						//是否使用真随机数生成器？
						if constexpr(false)
						{
							std::random_device TRNG;
							RNG_Seed = GenerateSecureRandomNumberSeed<std::uint64_t>(TRNG);
						}
						else
						{
							RNG_Seed = ( static_cast<std::uint32_t>(CurrentInitialKeySpan[0]) + static_cast<std::uint32_t>(CurrentInitialKeySpan[1]) + static_cast<std::uint32_t>(CurrentInitialKeySpan[2]) + static_cast<std::uint32_t>(CurrentInitialKeySpan[3]) ) ^ ( static_cast<std::uint32_t>(CurrentInitialKeySpan[4]) + static_cast<std::uint32_t>(CurrentInitialKeySpan[5]) + static_cast<std::uint32_t>(CurrentInitialKeySpan[6]) + static_cast<std::uint32_t>(CurrentInitialKeySpan[7]) );
						}

						RNG_Pointer = std::make_unique<RNG_ISAAC::isaac<8>>(RNG_Seed);
					}

					CommonSecurity::ShuffleRangeData(shuffle_nonce.begin(), shuffle_nonce.end(), RNG);
					this->ProcessKeyStreamBlock(shuffle_nonce, current_counter, key_stream_block);
					is_counter_overflow = false;
				}
				else
				{
					if(current_counter + 1 == std::numeric_limits<std::uint32_t>::min())
					{
						is_counter_overflow = true;
					}
					this->ProcessKeyStreamBlock(nonce, current_counter, key_stream_block);
				}

				if(current_block == number_blocks - 1)
				{
					std::size_t block_offset = current_block * ByteSizeOfKeyBlocks();
					for(std::size_t position = 0; position < (data_size % ByteSizeOfKeyBlocks()); ++position)
						output[position + offset + block_offset] = input[position + block_offset] ^ key_stream_block[position];
				}
				else
				{
					std::size_t block_offset = current_block * ByteSizeOfKeyBlocks();
					for(std::size_t position = 0; position < ByteSizeOfKeyBlocks(); ++position)
						output[position + offset + block_offset] = input[position + block_offset] ^ key_stream_block[position];
				}
			}
		}

	protected:
		static constexpr std::uint32_t INTEGER_SIZE_OF_KEYS = 8;
		static constexpr std::uint32_t INTEGER_SIZE_OF_BLOCKS = 16;

		// "expand 32-byte k" (4 words constant: "expa", "nd 3", "2-by", and "te k")
		static constexpr std::array<std::uint32_t, 4> SIGMA_TABLE{ 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 };
		std::vector<std::uint8_t> CurrentInitialKey;
		std::span<std::uint8_t> CurrentInitialKeySpan;
		const std::uint32_t InitialCounter;

		/*
			@brief Initializes a new instance of the "WorkerBase" class.
			@param key; The secret key
			@param counter; The initial counter
		*/
		WorkerBase(std::span<std::uint8_t> key, const std::uint32_t& counter)
			:
			CurrentInitialKeySpan(key), InitialCounter(counter)
		{
			std::stringstream error_message_stream;
			error_message_stream << "The byte size of keys must be" << BYTE_SIZE_OF_KEYS;
			my_cpp2020_assert(!CurrentInitialKeySpan.empty() && CurrentInitialKeySpan.size() == BYTE_SIZE_OF_KEYS, error_message_stream.str().c_str(), std::source_location::current());
			CurrentInitialKey.assign(CurrentInitialKeySpan.begin(), CurrentInitialKeySpan.end());
		}

	public:
		static constexpr std::uint32_t BYTE_SIZE_OF_KEYS = INTEGER_SIZE_OF_KEYS * sizeof(std::uint32_t);
		static constexpr std::uint32_t BYTE_SIZE_OF_BLOCKS = INTEGER_SIZE_OF_BLOCKS * sizeof(std::uint32_t);

		/*
			From this function, the Snuffle encryption function can be constructed using the counter mode of operation.
			For example, the ChaCha20 block function and how it can be used to construct the ChaCha20 encryption function are described in section 2.3 and 2.4 of RFC 8439.

			@param nonce; The initialized vector nonce.
			@param counter; The initialized counter
			@param key_stream_block; The key stream block
		*/
		virtual void ProcessKeyStreamBlock(std::span<const std::uint8_t> nonce, std::uint32_t counter, std::span<std::uint8_t> key_stream_block) = 0;

		/*
			The byte size of the nonces.
			Salsa20 uses a 8-byte (64-bit) nonce, ChaCha20 uses a 12-byte (96-bit) nonce, but XSalsa20 and XChaCha20 use a 24-byte (192-bit) nonce.
		*/
		virtual std::uint32_t ByteSizeOfNonces() = 0;

		/*
			The byte size of the stream blocks.
		*/
		constexpr std::uint32_t ByteSizeOfKeyBlocks() { return BYTE_SIZE_OF_BLOCKS; }

		/*
			@brief Check the parameters before calling the "DoProcessFunction" function.
			@param nonce; The initialized vector nonce.
			@param input; The plaintext/ciphertext input.
			@param output; The ciphertext/plaintext output.
		*/
		void ProcessFunction(std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> input, std::span<std::uint8_t> output)
		{
			my_cpp2020_assert(input.size() == output.size(), "The plaintext/ciphertext parameter and the ciphertext/plaintext do not have the same size.", std::source_location::current());

			std::stringstream error_message_stream;
			std::size_t requirement_nonce_byte_size = ByteSizeOfNonces();
			error_message_stream << "Uses " << requirement_nonce_byte_size * 8 << "-bit nonces, but got a " << nonce.size() * 8 << "-bit nonce.\nThe byte size of nonces must be " << requirement_nonce_byte_size;
			my_cpp2020_assert(!nonce.empty() && nonce.size() == requirement_nonce_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			this->DoProcessFunction(nonce, input, output);
		}

		void UpdateKey(std::span<std::uint8_t> update_key)
		{
			if(update_key.size() != BYTE_SIZE_OF_KEYS)
				return;

			std::vector<std::uint8_t> UpdateInitialKey(update_key.begin(), update_key.end());

			if(CurrentInitialKey != UpdateInitialKey)
			{
				CurrentInitialKey = std::move(UpdateInitialKey);
				CurrentInitialKeySpan = std::span<std::uint8_t>(CurrentInitialKey);
			}
		}

		virtual ~WorkerBase()
		{
			RNG_Pointer.reset();
		}
	};

	/*
		Poly1305 one-time MAC based on RFC 7539.
		This is not an implementation of the MAC interface on purpose and it is not equivalent to HMAC.
		The implementation is based on poly1305 implementation by Andrew Moon (https://github.com/floodyberry/poly1305-donna) and released as public domain.
	*/
	class Poly1305
	{

	private:
		static std::vector<std::uint8_t> LastBlock(std::span<const std::uint8_t> buffer, std::size_t index)
		{
			auto block = std::vector<std::uint8_t>(BYTES_OF_MAC_KEY, 0x00);
			std::size_t copy_count = std::min(BYTES_OF_MAC_TAG, buffer.size() - index);
			std::ranges::copy_n(buffer.begin() + index, copy_count, block.begin());

			block[copy_count] = 1;

			return block;
		}

	public:
		static constexpr std::size_t BYTES_OF_MAC_TAG = 16;
		static constexpr std::size_t BYTES_OF_MAC_KEY = 32;

		/*
			@brief Computes the authentication "tag_data" into a destination buffer using the specified "key" and "data".
			@param key_for_mac_span; The secret key.
			@param data_for_mac_span; Compute the source data to be used for the authentication tag
			@param mac_tag_data_span; The byte span to receive the generated authentication tag.
		*/
		static void ComputeMessageAuthenticationCode(std::span<const std::uint8_t> key_span, std::span<const std::uint8_t> data_span, std::span<std::uint8_t> tag_data_span )
		{
			std::stringstream error_message_stream;
			error_message_stream << "The byte size of keys must be " << BYTES_OF_MAC_KEY;
			my_cpp2020_assert(key_span.size() == BYTES_OF_MAC_KEY, error_message_stream.str().c_str(), std::source_location::current());
			error_message_stream.clear();
			error_message_stream << "The byte size of tags must be " << BYTES_OF_MAC_TAG;
			my_cpp2020_assert(tag_data_span.size() == BYTES_OF_MAC_TAG, error_message_stream.str().c_str(), std::source_location::current());

			// Initial state
			std::uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
			std::uint32_t b = 0;

			std::array<std::uint32_t, 8> internal_key;

			CommonToolkit::MemoryDataFormatExchange data_stream_format_exchanger;
			internal_key[0] = data_stream_format_exchanger.Packer_4Byte(key_span.subspan(0, 4));
			internal_key[1] = data_stream_format_exchanger.Packer_4Byte(key_span.subspan(4, 4));
			internal_key[2] = data_stream_format_exchanger.Packer_4Byte(key_span.subspan(8, 4));
			internal_key[3] = data_stream_format_exchanger.Packer_4Byte(key_span.subspan(12, 4));
			internal_key[4] = data_stream_format_exchanger.Packer_4Byte(key_span.subspan(16, 4));
			internal_key[5] = data_stream_format_exchanger.Packer_4Byte(key_span.subspan(20, 4));
			internal_key[6] = data_stream_format_exchanger.Packer_4Byte(key_span.subspan(24, 4));
			internal_key[7] = data_stream_format_exchanger.Packer_4Byte(key_span.subspan(28, 4));

			// Clamp key
			auto t0 = internal_key[0];
			auto t1 = internal_key[1];
			auto t2 = internal_key[2];
			auto t3 = internal_key[3];

			// Precompute multipliers
			std::uint32_t r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
            std::uint32_t r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
            std::uint32_t r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
            std::uint32_t r3 = t2 & 0x3f03fff; t3 >>= 8;
			std::uint32_t r4 = t3 & 0x00fffff;

			std::uint32_t s1 = r1 * 5;
			std::uint32_t s2 = r2 * 5;
			std::uint32_t s3 = r3 * 5;
			std::uint32_t s4 = r4 * 5;

			// Process blocks
			for (std::size_t index = 0; index < data_span.size(); index += BYTES_OF_MAC_TAG)
			{
				bool is_last_block = (data_span.size() - index) < BYTES_OF_MAC_TAG;
				if(is_last_block)
				{
					auto block = Poly1305::LastBlock(data_span, index);
					std::span<const std::uint8_t> block_span { block };

					t0 = data_stream_format_exchanger.Packer_4Byte(block_span.subspan(0, 4));
					t1 = data_stream_format_exchanger.Packer_4Byte(block_span.subspan(4, 4));
					t2 = data_stream_format_exchanger.Packer_4Byte(block_span.subspan(8, 4));
					t3 = data_stream_format_exchanger.Packer_4Byte(block_span.subspan(12, 4));
				}
				else
				{
					t0 = data_stream_format_exchanger.Packer_4Byte(data_span.subspan(index, 4));
					t1 = data_stream_format_exchanger.Packer_4Byte(data_span.subspan(index + 4, 4));
					t2 = data_stream_format_exchanger.Packer_4Byte(data_span.subspan(index + 8, 4));
					t3 = data_stream_format_exchanger.Packer_4Byte(data_span.subspan(index + 12, 4));
				}

				h0 += t0 & 0x3ffffff;
				h1 += static_cast<std::uint32_t>( ( ( static_cast<std::uint64_t>(t1 << 32) | t0 ) >> 26 ) & 0x3ffffff );
				h2 += static_cast<std::uint32_t>( ( ( static_cast<std::uint64_t>(t2 << 32) | t1 ) >> 20 ) & 0x3ffffff );
				h3 += static_cast<std::uint32_t>( ( ( static_cast<std::uint64_t>(t3 << 32) | t2 ) >> 14 ) & 0x3ffffff );
				h4 = is_last_block ? h4 + (t3 >> 8) : h4 + ( (t3 >> 8) | (1 << 24) );

				// d = r * h
                std::uint64_t d0 = static_cast<std::uint64_t>(h0) * r0 + static_cast<std::uint64_t>(h1) * s4 + static_cast<std::uint64_t>(h2) * s3 + static_cast<std::uint64_t>(h3) * s2 + static_cast<std::uint64_t>(h4) * s1;
                std::uint64_t d1 = static_cast<std::uint64_t>(h0) * r1 + static_cast<std::uint64_t>(h1) * r0 + static_cast<std::uint64_t>(h2) * s4 + static_cast<std::uint64_t>(h3) * s3 + static_cast<std::uint64_t>(h4) * s2;
                std::uint64_t d2 = static_cast<std::uint64_t>(h0) * r2 + static_cast<std::uint64_t>(h1) * r1 + static_cast<std::uint64_t>(h2) * r0 + static_cast<std::uint64_t>(h3) * s4 + static_cast<std::uint64_t>(h4) * s3;
                std::uint64_t d3 = static_cast<std::uint64_t>(h0) * r3 + static_cast<std::uint64_t>(h1) * r2 + static_cast<std::uint64_t>(h2) * r1 + static_cast<std::uint64_t>(h3) * r0 + static_cast<std::uint64_t>(h4) * s4;
                std::uint64_t d4 = static_cast<std::uint64_t>(h0) * r4 + static_cast<std::uint64_t>(h1) * r3 + static_cast<std::uint64_t>(h2) * r2 + static_cast<std::uint64_t>(h3) * r1 + static_cast<std::uint64_t>(h4) * r0;

				// Partial reduction mod 2^130-5
				h0 = static_cast<std::uint32_t>(d0) & 0x3ffffff;
				std::uint64_t c = (d0 >> 26);
                d1 += c; h1 = static_cast<std::uint32_t>(d1) & 0x3ffffff; b = static_cast<std::uint32_t>(d1 >> 26);
                d2 += b; h2 = static_cast<std::uint32_t>(d2) & 0x3ffffff; b = static_cast<std::uint32_t>(d2 >> 26);
                d3 += b; h3 = static_cast<std::uint32_t>(d3) & 0x3ffffff; b = static_cast<std::uint32_t>(d3 >> 26);
                d4 += b; h4 = static_cast<std::uint32_t>(d4) & 0x3ffffff; b = static_cast<std::uint32_t>(d4 >> 26);

				h0 += b * 5;
			}

			// Do final reduction mod 2^130-5
			b = h0 >> 26; h0 &= 0x3ffffff;
            h1 += b; b = h1 >> 26; h1 &= 0x3ffffff;
            h2 += b; b = h2 >> 26; h2 &= 0x3ffffff;
            h3 += b; b = h3 >> 26; h3 &= 0x3ffffff;
            h4 += b; b = h4 >> 26; h4 &= 0x3ffffff;
            h0 += b * 5;

			// Compute h - p
            std::uint32_t g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
            std::uint32_t g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
            std::uint32_t g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
            std::uint32_t g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
            std::uint32_t g4 = h4 + b - (1 << 26);

			// Select h if h < p, or h - p if h >= p
            b = (g4 >> ((sizeof(std::uint32_t) * 8) - 1)) - 1; // mask is either 0 (h >= p) or -1 (h < p)
            h0 = (h0 & ~b) | (g0 & b);
            h1 = (h1 & ~b) | (g1 & b);
            h2 = (h2 & ~b) | (g2 & b);
            h3 = (h3 & ~b) | (g3 & b);
            h4 = (h4 & ~b) | (g4 & b);

			// h = h % (2^128)
            std::uint64_t f0 = ((h0) | (h1 << 26)) + static_cast<std::uint64_t>(internal_key[4]);
            std::uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + static_cast<std::uint64_t>(internal_key[5]);
            std::uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + static_cast<std::uint64_t>(internal_key[6]);
            std::uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + static_cast<std::uint64_t>(internal_key[7]);

			// mac = (h + pad) % (2^128)
			auto result = data_stream_format_exchanger.Unpacker_4Byte(f0); f1 += (f0 >> 32);
			std::ranges::copy(result.begin(), result.end(), tag_data_span.begin());
			data_stream_format_exchanger.Unpacker_4Byte(f1); f2 += (f1 >> 32);
			std::ranges::copy(result.begin(), result.end(), tag_data_span.begin() + 4);
			data_stream_format_exchanger.Unpacker_4Byte(f2); f3 += (f2 >> 32);
			std::ranges::copy(result.begin(), result.end(), tag_data_span.begin() + 8);
			data_stream_format_exchanger.Unpacker_4Byte(f3);
			std::ranges::copy(result.begin(), result.end(), tag_data_span.begin() + 12);
		}

		/*
			@brief Computes the authentication "tag_data" into a destination buffer using the specified "key" and "data".
			@param key_for_mac_span; The secret key.
			@param data_for_mac_span; Compute the source data to be used for the authentication tag
			@param mac_tag_data_span; The generated authentication tag.
			@return bool value is verify result.
		*/
		static bool VerifyMessageAuthenticationCode(std::span<const std::uint8_t> key_for_mac_span, std::span<const std::uint8_t> data_for_mac_span, std::span<const std::uint8_t> mac_tag_data_span )
		{
			std::stringstream error_message_stream;
			error_message_stream << "The byte size of tags must be " << BYTES_OF_MAC_TAG;
			my_cpp2020_assert(mac_tag_data_span.size() == BYTES_OF_MAC_TAG, error_message_stream.str().c_str(), std::source_location::current());

			std::array<std::uint8_t, BYTES_OF_MAC_TAG> mac_tag;
			std::span<std::uint8_t> mac_tag_span { mac_tag };
			Poly1305::ComputeMessageAuthenticationCode(key_for_mac_span, data_for_mac_span, mac_tag_span);

			if(std::ranges::equal(mac_tag_span.begin(), mac_tag_span.end(), mac_tag_data_span.begin(), mac_tag_data_span.end()))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	};

	class InterfaceChaCha20 : public WorkerBase
	{

	protected:

		/*
			Sets the initial "state" from "nonce" and "counter".
			ChaCha20 has a different logic than ExtendedChaCha20, because the former uses a 12-byte nonce, but the later uses 24-byte.
			@param state; The stream data cryptographic state.
			@param nonce; The nonce.
			@param counter The counter.
		*/
		virtual void SetInitialState(std::span<std::uint32_t> state, std::span<const std::uint8_t> nonce, const std::uint32_t& counter) = 0;

		void QuarterRound(std::span<std::uint32_t> state_block_argument, std::size_t index, std::size_t index2, std::size_t index3, std::size_t index4)
		{
			my_cpp2020_assert(state_block_argument.size() == 16, "Invalid stream cryptographic status data !", std::source_location::current());

			// Build stream cryptograph quarter rounds of state data
			// 构建流加密器四分之一轮的状态数据
			std::array<std::uint32_t, 4> state_block
			{
				state_block_argument.operator[](index),
				state_block_argument.operator[](index2),
				state_block_argument.operator[](index3),
				state_block_argument.operator[](index4),
			};

			// Reference data from state data
			// 从状态数据中引用数据

			auto& [a, b, c, d] = state_block;

			// Execute data changer to span view
			// 执行数据改变器到跨度视图

			a += b;
			d = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(d ^ a, 16);

			c += d;
			b = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(b ^ c, 12);

			a += b;
			d = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(d ^ a, 8);

			c += d;
			b = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(b ^ c, 7);

			state_block_argument.operator[](index) = state_block.operator[](0);
			state_block_argument.operator[](index2) = state_block.operator[](1);
			state_block_argument.operator[](index3) = state_block.operator[](2);
			state_block_argument.operator[](index4) = state_block.operator[](3);
		}

		void UpdateStateBlock(std::span<std::uint32_t> state_block_argument, std::size_t round_counter = 10)
		{
			// Doing 20 rounds of computation on it (one iteration every 2 rounds)
			// 对它进行20轮计算（每2轮迭代一次）
			for(std::size_t index = 0; index < round_counter; ++index)
			{
				// Odd round
				// For the current state of the round transformation data applied to the columns
				// 对于当前状态的轮变换数据应用到列

				this->QuarterRound(state_block_argument, 0, 4, 8, 12);
				this->QuarterRound(state_block_argument, 1, 5, 9, 13);
				this->QuarterRound(state_block_argument, 2, 6, 10, 14);
				this->QuarterRound(state_block_argument, 3, 7, 11, 15);

				// Even round
				// For the current state of the round transformation data applied to the diagonal
				// 对于当前状态的轮变换数据应用到对角线

				this->QuarterRound(state_block_argument, 0, 5, 10, 15);
				this->QuarterRound(state_block_argument, 1, 6, 11, 12);
				this->QuarterRound(state_block_argument, 2, 7, 8, 13);
				this->QuarterRound(state_block_argument, 3, 4, 9, 14);
			}
		}

	public:
		void ProcessKeyStreamBlock(std::span<const std::uint8_t> nonce, std::uint32_t counter, std::span<std::uint8_t> key_stream_block) override
		{
			std::stringstream error_message_stream;
			std::size_t requirement_key_stream_block_byte_size = this->ByteSizeOfKeyBlocks();
			error_message_stream << "The byte size of key blocks must be " << requirement_key_stream_block_byte_size;
			my_cpp2020_assert(key_stream_block.size() == requirement_key_stream_block_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			// Set the initial state based on https://tools.ietf.org/html/rfc8439#section-2.3
			std::array<std::uint32_t, INTEGER_SIZE_OF_BLOCKS> state;
			this->SetInitialState(state, nonce, counter);

			// Create a copy of the state and then run 20 rounds on it,
            // alternating between "column rounds" and "diagonal rounds"; each round consisting of four quarter-rounds.
			std::array<std::uint32_t, INTEGER_SIZE_OF_BLOCKS> working_state;
			std::ranges::copy(state.begin(), state.end(), working_state.begin());
			this->UpdateStateBlock(working_state);

			// At the end of the rounds, add the result to the original state.
            for (std::size_t index = 0; index < INTEGER_SIZE_OF_BLOCKS; index++)
                state[index] += working_state[index];

			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(state, key_stream_block.data());
		}

		std::uint32_t ByteSizeOfNonces() override
		{
			return 0;
		}

		InterfaceChaCha20(std::span<std::uint8_t> initial_key, const std::uint32_t& initial_counter = 1)
			:
			WorkerBase(initial_key, initial_counter)
		{

		}
	};

	/*
		Base class for "Salsa20" and "ExtendedSalsa20".
	*/
	class InterfaceSalsa20 : public WorkerBase
	{

	protected:

		/*
			Sets the initial "state" from "nonce" and "counter".
			Salsa20 has a different logic than ExtendedSalsa20, because the former uses a 8-byte nonce, but the later uses 24-byte.
			@param state; The stream data cryptographic state.
			@param nonce; The nonce.
			@param counter The counter.
		*/
		virtual void SetInitialState(std::span<std::uint32_t> state, std::span<const std::uint8_t> nonce, const std::uint32_t& counter) = 0;

		void QuarterRound(std::span<std::uint32_t> state_block_argument, std::size_t index, std::size_t index2, std::size_t index3, std::size_t index4)
		{
			my_cpp2020_assert(state_block_argument.size() == 16, "Invalid stream cryptographic status data !", std::source_location::current());

			// Build stream cryptograph quarter rounds of state data
			// 构建流加密器四分之一轮的状态数据
			std::array<std::uint32_t, 4> state_block
			{
				state_block_argument.operator[](index),
				state_block_argument.operator[](index2),
				state_block_argument.operator[](index3),
				state_block_argument.operator[](index4),
			};

			// Reference data from state data
			// 从状态数据中引用数据

			auto& [a, b, c, d] = state_block;

			// Execute data changer to span view
			// 执行数据改变器到跨度视图

			b ^= CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(a + d, 7);

			c ^= CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(b + a, 9);

			d ^= CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(c + b, 13);

			a ^= CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(d + c, 8);

			state_block_argument.operator[](index) = state_block.operator[](0);
			state_block_argument.operator[](index2) = state_block.operator[](1);
			state_block_argument.operator[](index3) = state_block.operator[](2);
			state_block_argument.operator[](index4) = state_block.operator[](3);
		}

		void UpdateStateBlock(std::span<std::uint32_t> state_block_argument, std::size_t round_counter = 10)
		{
			// Doing 20 rounds of computation on it (one iteration every 2 rounds)
			// 对它进行20轮计算（每2轮迭代一次）
			for(std::size_t index = 0; index < round_counter; ++index)
			{
				// Odd round
				// For the current state of the round transformation data applied to the columns
				// 对于当前状态的轮变换数据应用到列

				this->QuarterRound(state_block_argument, 0, 4, 8, 12);
				this->QuarterRound(state_block_argument, 5, 9, 13, 1);
				this->QuarterRound(state_block_argument, 10, 14, 2, 6);
				this->QuarterRound(state_block_argument, 15, 3, 7, 11);

				// Even round
				// For the current state of the round transformation data applied to the row
				// 对于当前状态的轮变换数据应用到行

				this->QuarterRound(state_block_argument, 0, 1, 2, 3);
				this->QuarterRound(state_block_argument, 5, 6, 7, 4);
				this->QuarterRound(state_block_argument, 10, 11, 8, 9);
				this->QuarterRound(state_block_argument, 15, 12, 13, 14);
			}
		}

	public:
		void ProcessKeyStreamBlock(std::span<const std::uint8_t> nonce, std::uint32_t counter, std::span<std::uint8_t> key_stream_block) override
		{
			std::stringstream error_message_stream;
			std::size_t requirement_key_stream_block_byte_size = this->ByteSizeOfKeyBlocks();
			error_message_stream << "The byte size of key blocks must be " << requirement_key_stream_block_byte_size;
			my_cpp2020_assert(key_stream_block.size() == requirement_key_stream_block_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			// Set the initial state based on https://tools.ietf.org/html/rfc8439#section-2.3
			std::array<std::uint32_t, INTEGER_SIZE_OF_BLOCKS> state {};
			this->SetInitialState(state, nonce, counter);

			// Create a copy of the state and then run 20 rounds on it,
            // alternating between "column rounds" and "diagonal rounds"; each round consisting of four quarter-rounds.
			std::array<std::uint32_t, INTEGER_SIZE_OF_BLOCKS> working_state {};
			std::ranges::copy(state.begin(), state.end(), working_state.begin());
			this->UpdateStateBlock(working_state);

			// At the end of the rounds, add the result to the original state.
            for (std::size_t index = 0; index < INTEGER_SIZE_OF_BLOCKS; index++)
                state[index] += working_state[index];

			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(state, key_stream_block.data());
		}

		std::uint32_t ByteSizeOfNonces() override
		{
			return 0;
		}

		InterfaceSalsa20(std::span<std::uint8_t> initial_key, const std::uint32_t& initial_counter = 1)
			:
			WorkerBase(initial_key, initial_counter)
		{

		}
	};

	/*
		A stream cipher based on RFC 8439 (previously RFC 7539) (i.e., uses 96-bit random nonces).
		https://tools.ietf.org/html/rfc8439#section-2.8
		https://tools.ietf.org/html/rfc7539#section-2.8
	*/
	class ChaCha20 : public InterfaceChaCha20
	{

	protected:
		void SetInitialState(std::span<std::uint32_t> state, std::span<const std::uint8_t> nonce, const std::uint32_t& counter) override
		{
			std::stringstream error_message_stream;
			std::size_t requirement_nonce_byte_size = this->ByteSizeOfNonces();
			error_message_stream << "Uses " << requirement_nonce_byte_size * 8 << "-bit nonces, but got a " << nonce.size() * 8 << "-bit nonce.\nThe byte size of nonces must be " << requirement_nonce_byte_size;
			my_cpp2020_assert(!nonce.empty() && nonce.size() == requirement_nonce_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			//Since each word size is 4 byte

			// The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
            // The next eight words (4-11) are taken from the 256-bit key in little-endian order, in 4-byte chunks.

			// Set the ChaCha20 constant.
			state[0] = SIGMA_TABLE[0];
            state[1] = SIGMA_TABLE[1];
            state[2] = SIGMA_TABLE[2];
            state[3] = SIGMA_TABLE[3];

			CommonToolkit::MemoryDataFormatExchange data_state_format_exchanger;

			// Sets the 256-bit Key.
			state[4] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(0, 4));
            state[5] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(4, 4));
            state[6] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(8, 4));
            state[7] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(12, 4));
            state[8] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(16, 4));
            state[9] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(20, 4));
            state[10] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(24, 4));
            state[11] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(28, 4));

			// Word 12 is a block counter. Since each block is 64-byte, a 32-bit word is enough for 256 gigabytes of data. Ref: https://tools.ietf.org/html/rfc8439#section-2.3.
            state[12] = counter;

			// Words 13-15 are a nonce, which must not be repeated for the same key.
            // The 13th word is the first 32 bits of the input nonce taken as a little-endian integer, while the 15th word is the last 32 bits.
            state[13] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(0, 4));
            state[14] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(4, 4));
            state[15] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(8, 4));
		}

	public:
		std::uint32_t ByteSizeOfNonces() override
		{
			return 12;
		}

		ChaCha20(std::span<std::uint8_t> initial_key, const std::uint32_t& initial_counter = 1)
			:
			InterfaceChaCha20(initial_key, initial_counter)
		{

		}
	};

	class ExtendedChaCha20 : public InterfaceChaCha20
	{

	protected:
		void SetInitialState(std::span<std::uint32_t> state, std::span<const std::uint8_t> nonce, const std::uint32_t& counter) override
		{
			std::stringstream error_message_stream;
			std::size_t requirement_nonce_byte_size = this->ByteSizeOfNonces();
			error_message_stream << "Uses " << requirement_nonce_byte_size * 8 << "-bit nonces, but got a " << nonce.size() * 8 << "-bit nonce.\nThe byte size of nonces must be " << requirement_nonce_byte_size;
			my_cpp2020_assert(!nonce.empty() && nonce.size() == requirement_nonce_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			// The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.

			// Set the ChaCha20 constant.
			state[0] = SIGMA_TABLE[0];
            state[1] = SIGMA_TABLE[1];
            state[2] = SIGMA_TABLE[2];
            state[3] = SIGMA_TABLE[3];

			// The next eight words (4-11) are taken from the 256-bit key in little-endian order, in 4-byte chunks; and the first 16 bytes of the 24-byte nonce to obtain the subkey-block.
			std::array<std::uint8_t, BYTE_SIZE_OF_KEYS> subkey_block {};
			std::span<std::uint8_t> subkey_block_span { subkey_block };
			this->HChaCha20(subkey_block_span, nonce);

			CommonToolkit::MemoryDataFormatExchange data_state_format_exchanger;

			// Sets the 256-bit Key.
			state[4] = data_state_format_exchanger.Packer_4Byte(subkey_block_span.subspan(0, 4));
            state[5] = data_state_format_exchanger.Packer_4Byte(subkey_block_span.subspan(4, 4));
            state[6] = data_state_format_exchanger.Packer_4Byte(subkey_block_span.subspan(8, 4));
            state[7] = data_state_format_exchanger.Packer_4Byte(subkey_block_span.subspan(12, 4));
            state[8] = data_state_format_exchanger.Packer_4Byte(subkey_block_span.subspan(16, 4));
            state[9] = data_state_format_exchanger.Packer_4Byte(subkey_block_span.subspan(20, 4));
            state[10] = data_state_format_exchanger.Packer_4Byte(subkey_block_span.subspan(24, 4));
            state[11] = data_state_format_exchanger.Packer_4Byte(subkey_block_span.subspan(28, 4));

			// Word 12 is a block counter.
            state[12] = counter;

            // Word 13 is a prefix of 4 null bytes, since RFC 8439 specifies a 12-byte nonce.
            state[13] = 0;

            // Words 14-15 are the remaining 8-byte nonce (used in HChaCha20). Ref: https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.3.
            state[14] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(16, 4));
            state[15] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(20, 4));
		}

	public:
		void HChaCha20(std::span<std::uint8_t> subkey_block, std::span<const std::uint8_t> nonce)
		{
			CommonToolkit::MemoryDataFormatExchange data_state_format_exchanger;

			std::array<std::uint32_t, INTEGER_SIZE_OF_BLOCKS> state {};

			/* Initial HChaCha20 State Start */

			// Set the ChaCha20 constant.
			state[0] = SIGMA_TABLE[0];
            state[1] = SIGMA_TABLE[1];
            state[2] = SIGMA_TABLE[2];
            state[3] = SIGMA_TABLE[3];

			// Sets the 256-bit Key.
			state[4] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(0, 4));
            state[5] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(4, 4));
            state[6] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(8, 4));
            state[7] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(12, 4));
            state[8] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(16, 4));
            state[9] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(20, 4));
            state[10] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(24, 4));
            state[11] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(28, 4));

			// Set 128-bit Nonce
            state[12] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(0, 4));
            state[13] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(4, 4));
            state[14] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(8, 4));
            state[15] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(12, 4));

			/* Initial HChaCha20 State End */

			/* Update HChaCha20 State Start */

			// State block function
			this->UpdateStateBlock(state);

			state[4] = state[12];
            state[5] = state[13];
            state[6] = state[14];
            state[7] = state[15];

			/* Update HChaCha20 State End */

			std::span<std::uint32_t> state_span { state };

			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(state_span.subspan(0, 8), subkey_block.data());
		}

		std::uint32_t ByteSizeOfNonces() override
		{
			return 24;
		}

		ExtendedChaCha20(std::span<std::uint8_t> initial_key, const std::uint32_t& initial_counter = 1)
			:
			InterfaceChaCha20(initial_key, initial_counter)
		{

		}
	};

	class Salsa20 : public InterfaceSalsa20
	{

	protected:
		void SetInitialState(std::span<std::uint32_t> state, std::span<const std::uint8_t> nonce, const std::uint32_t& counter) override
		{
			std::stringstream error_message_stream;
			std::size_t requirement_nonce_byte_size = this->ByteSizeOfNonces();
			error_message_stream << "Uses " << requirement_nonce_byte_size * 8 << "-bit nonces, but got a " << nonce.size() * 8 << "-bit nonce.\nThe byte size of nonces must be " << requirement_nonce_byte_size;
			my_cpp2020_assert(!nonce.empty() && nonce.size() == requirement_nonce_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			// Reference papers: http://cr.yp.to/snuffle/xsalsa-20081128.pdf under 2. Specification - Review of Salsa20

            // The first four words in diagonal (0,5,10,15) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
            // The next eight words (1,2,3,4,11,12,13,14) are taken from the 256-bit key in little-endian order, in 4-byte chunks.

			// Set the Salsa20 constant.
			state[0] = SIGMA_TABLE[0];
            state[5] = SIGMA_TABLE[1];
            state[10] = SIGMA_TABLE[2];
            state[15] = SIGMA_TABLE[3];

			CommonToolkit::MemoryDataFormatExchange data_state_format_exchanger;

			// Sets the 256-bit Key.
			state[1] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(0, 4));
            state[2] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(4, 4));
            state[3] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(8, 4));
            state[4] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(12, 4));
            state[11] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(16, 4));
            state[12] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(20, 4));
            state[13] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(24, 4));
            state[14] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(28, 4));

			// Words 6-7 is a 64-bit nonce, which must not be repeated for the same key.
			state[6] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(0, 4));
            state[7] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(4, 4));

			// Words 8-9 is a 64-bit block counter, the position of the 512-bit output block.
            state[8] = counter;
            state[9] = 0;
		}

	public:
		std::uint32_t ByteSizeOfNonces() override
		{
			return 8;
		}

		Salsa20(std::span<std::uint8_t> initial_key, const std::uint32_t& initial_counter = 1)
			:
			InterfaceSalsa20(initial_key, initial_counter)
		{

		}
	};

	class ExtendedSalsa20 : public InterfaceSalsa20
	{

	protected:
		void SetInitialState(std::span<std::uint32_t> state, std::span<const std::uint8_t> nonce, const std::uint32_t& counter) override
		{
			std::stringstream error_message_stream;
			std::size_t requirement_nonce_byte_size = this->ByteSizeOfNonces();
			error_message_stream << "Uses " << requirement_nonce_byte_size * 8 << "-bit nonces, but got a " << nonce.size() * 8 << "-bit nonce.\nThe byte size of nonces must be " << requirement_nonce_byte_size;
			my_cpp2020_assert(!nonce.empty() && nonce.size() == requirement_nonce_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			// Reference papers: http://cr.yp.to/snuffle/xsalsa-20081128.pdf under 2. Specification - Definition of XSalsa20

            // The first four words in diagonal (0,5,10,15) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.

			// Set the Salsa20 constant.
			state[0] = SIGMA_TABLE[0];
            state[5] = SIGMA_TABLE[1];
            state[10] = SIGMA_TABLE[2];
            state[15] = SIGMA_TABLE[3];

			// The next eight words (1,2,3,4,11,12,13,14) are taken from the 256-bit key in little-endian order, in 4-byte chunks; and the first 16 bytes of the 24-byte nonce to obtain the subkey-block.
			std::array<std::uint8_t, BYTE_SIZE_OF_KEYS> subkey_block {};
			std::span<std::uint8_t> subkey_block_span { subkey_block };
			this->HSalsa20(subkey_block_span, nonce);

			CommonToolkit::MemoryDataFormatExchange data_state_format_exchanger;

			// Sets the 256-bit Key.
			state[1] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(0, 4));
            state[2] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(4, 4));
            state[3] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(8, 4));
            state[4] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(12, 4));
            state[11] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(16, 4));
            state[12] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(20, 4));
            state[13] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(24, 4));
            state[14] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(28, 4));

			// Words 6-7 is the last 64-bits of the 192-bit nonce, which must not be repeated for the same key.
            state[6] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(16, 4)); // or data_state_format_exchanger.Packer_4Byte(nonce.subspan(0, 4)
            state[7] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(20, 4)); // or data_state_format_exchanger.Packer_4Byte(nonce.subspan(4, 4)

            // Words 8-9 is a 64-bit block counter.
            // TODO: Other implementations uses the nonce, need some tests vectors to validate
            state[8] = counter; // or data_state_format_exchanger.Packer_4Byte(nonce.subspan(8, 4)
            state[9] = 0; // or data_state_format_exchanger.Packer_4Byte(nonce.subspan(12, 4)
		}

	public:
		void HSalsa20(std::span<std::uint8_t> subkey_block, std::span<const std::uint8_t> nonce)
		{
			CommonToolkit::MemoryDataFormatExchange data_state_format_exchanger;

			std::array<std::uint32_t, INTEGER_SIZE_OF_BLOCKS> state {};

			/* Initial HSalsa20 State Start */

			// Set the Salsa20 constant.
			state[0] = SIGMA_TABLE[0];
            state[5] = SIGMA_TABLE[1];
            state[10] = SIGMA_TABLE[2];
            state[15] = SIGMA_TABLE[3];

			// Sets the 256-bit Key.
			state[1] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(0, 4));
            state[2] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(4, 4));
            state[3] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(8, 4));
            state[4] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(12, 4));
            state[11] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(16, 4));
            state[12] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(20, 4));
            state[13] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(24, 4));
            state[14] = data_state_format_exchanger.Packer_4Byte(this->CurrentInitialKeySpan.subspan(28, 4));

			// Set 128-bit Nonce
			state[6] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(0, 4));
            state[7] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(4, 4));
			state[8] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(8, 4));
            state[9] = data_state_format_exchanger.Packer_4Byte(nonce.subspan(12, 4));

			/* Initial HSalsa20 State End */

			/* Update HSalsa20 State Start */

			// State block function
			this->UpdateStateBlock(state);

			state[1] = state[5];
            state[2] = state[10];
            state[3] = state[15];
            state[4] = state[6];
            state[5] = state[7];
            state[6] = state[8];
            state[7] = state[9];

			/* Update HSalsa20 State End */

			std::span<std::uint32_t> state_span { state };

			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(state_span.subspan(0, 8), subkey_block.data());
		}

		std::uint32_t ByteSizeOfNonces() override
		{
			return 24;
		}

		ExtendedSalsa20(std::span<std::uint8_t> initial_key, const std::uint32_t& initial_counter = 1)
			:
			InterfaceSalsa20(initial_key, initial_counter)
		{

		}
	};

	class WorkerBaseWithPoly1305
	{

	private:
		static std::size_t GetPaddedSize(std::span<const std::uint8_t> data, std::size_t size)
		{
			return data.size() % size == 0 ? data.size() : (data.size() + size - data.size() % size);
		}

		static void SetMessageAuthenticationCodeSize(std::span<std::uint8_t> mac_data, std::uint32_t offset, std::uint32_t value)
		{
			std::span<std::uint8_t> sub_mac_data = mac_data.subspan(offset, sizeof(std::uint64_t));
			CommonToolkit::MemoryDataFormatExchange data_stream_format_exchanger;
			std::span<std::uint8_t> result = data_stream_format_exchanger.Unpacker_8Byte(value);
			std::ranges::copy(result.begin(), result.begin(), sub_mac_data.begin());
		}

		/*
			@brief The MAC key is the first 32 bytes(8 word) of the first key stream block.
			@param nonce; The initialized vector nonce.
		*/
		std::vector<std::uint8_t> GenerateKeyForMAC(std::span<const std::uint8_t> nonce)
		{
			std::vector<std::uint8_t> key_stream_block(mac_worker_instance->ByteSizeOfKeyBlocks(), 0x00);
			mac_worker_instance->ProcessKeyStreamBlock(nonce, 0, key_stream_block);

			key_stream_block.resize(32);
			return key_stream_block;
		}

		/*
			Prepares the input to MAC, following RFC 8439, section 2.8.
			https://datatracker.ietf.org/doc/html/rfc8439#section-2.8
			@param ad_bytes; The associated-data bytes.
			@param cipher_text; The cipher-text bytes.
			@return mac_data;
		*/
		std::vector<std::uint8_t> PrepareDataForMAC_WithRfc8439(std::span<const std::uint8_t> ad_bytes, std::span<const std::uint8_t> cipher_text)
		{
			std::size_t associated_data_size = ad_bytes.size();
			std::size_t associated_data_padded_size = WorkerBaseWithPoly1305::GetPaddedSize(ad_bytes, Poly1305::BYTES_OF_MAC_TAG);
			std::size_t cipher_text_size = cipher_text.size();
			std::size_t cipher_text_padded_size =  WorkerBaseWithPoly1305::GetPaddedSize(cipher_text, Poly1305::BYTES_OF_MAC_TAG);

			std::vector<std::uint8_t> mac_data(associated_data_padded_size + cipher_text_padded_size + Poly1305::BYTES_OF_MAC_TAG, 0x00);

			// MAC Content Part
			std::ranges::copy_n(ad_bytes.begin(), associated_data_size, mac_data.begin());
			std::ranges::copy_n(cipher_text.begin(), cipher_text_size, mac_data.begin() + associated_data_padded_size);

			// MAC Size Part
			WorkerBaseWithPoly1305::SetMessageAuthenticationCodeSize(mac_data, associated_data_padded_size + cipher_text_padded_size, associated_data_size);
			WorkerBaseWithPoly1305::SetMessageAuthenticationCodeSize(mac_data, associated_data_padded_size + cipher_text_padded_size + sizeof(std::uint64_t), cipher_text_size);

			return mac_data;
		}

		/*
			Prepares the input to MAC, following RFC 8439, section 2.8.
			https://datatracker.ietf.org/doc/html/rfc8439#section-2.8
			@param mac_data; The resulting mac content
			@param ad_bytes; The associated-data bytes.
			@param associated_data_padded_size; The associated-data padded size.
			@param cipher_text; The cipher-text bytes.
			@param cipher_text_padded_size; The cipher-text padded size.
		*/
		void PrepareDataForMAC_WithRfc8439(std::span<std::uint8_t> mac_data, std::span<const std::uint8_t> ad_bytes, std::size_t associated_data_padded_size, std::span<const std::uint8_t> cipher_text, std::size_t cipher_text_padded_size)
		{
			std::size_t associated_data_size = ad_bytes.size();
			std::size_t cipher_text_size = cipher_text.size();

			// MAC Content Part
			std::ranges::copy_n(ad_bytes.begin(), associated_data_size, mac_data.begin());
			std::ranges::copy_n(cipher_text.begin(), cipher_text_size, mac_data.begin() + associated_data_padded_size);

			// MAC Size Part
			WorkerBaseWithPoly1305::SetMessageAuthenticationCodeSize(mac_data, associated_data_padded_size + cipher_text_padded_size, associated_data_size);
			WorkerBaseWithPoly1305::SetMessageAuthenticationCodeSize(mac_data, associated_data_padded_size + cipher_text_padded_size + sizeof(std::uint64_t), cipher_text_size);
		}

	protected:
		std::unique_ptr<WorkerBase> worker_instance = nullptr;
		std::unique_ptr<WorkerBase> mac_worker_instance = nullptr;

	public:
		void Encrypt(std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> plain_text, std::span<std::uint8_t> cipher_text, std::span<std::uint8_t> tag_data, std::span<std::uint8_t> associated_data = std::span<std::uint8_t>())
		{
			std::stringstream error_message_stream;
			std::size_t requirement_nonce_byte_size = worker_instance->ByteSizeOfNonces();
			error_message_stream << "Uses " << requirement_nonce_byte_size * 8 << "-bit nonces, but got a " << nonce.size() * 8 << "-bit nonce.\nThe byte size of nonces must be " << requirement_nonce_byte_size;
			my_cpp2020_assert(!nonce.empty() && nonce.size() == requirement_nonce_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			worker_instance->ProcessFunction(nonce, plain_text, cipher_text);

			std::vector<std::uint8_t> data_for_mac = this->PrepareDataForMAC_WithRfc8439(associated_data, cipher_text);
			std::vector<std::uint8_t> key_stream_for_mac = this->GenerateKeyForMAC(nonce);

			Poly1305::ComputeMessageAuthenticationCode(key_stream_for_mac, data_for_mac, tag_data);
		}

		void Decrypt(std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> cipher_text, std::span<std::uint8_t> plain_text, std::span<std::uint8_t> tag_data, std::span<std::uint8_t> associated_data = std::span<std::uint8_t>())
		{
			std::stringstream error_message_stream;
			std::size_t requirement_nonce_byte_size = worker_instance->ByteSizeOfNonces();
			error_message_stream << "Uses " << requirement_nonce_byte_size * 8 << "-bit nonces, but got a " << nonce.size() * 8 << "-bit nonce.\nThe byte size of nonces must be " << requirement_nonce_byte_size;
			my_cpp2020_assert(!nonce.empty() && nonce.size() == requirement_nonce_byte_size, error_message_stream.str().c_str(), std::source_location::current());

			std::vector<std::uint8_t> data_for_mac = this->PrepareDataForMAC_WithRfc8439(associated_data, cipher_text);
			std::vector<std::uint8_t> key_stream_for_mac = this->GenerateKeyForMAC(nonce);

			bool is_valid_mac = Poly1305::VerifyMessageAuthenticationCode(key_stream_for_mac, data_for_mac, tag_data);

			if(is_valid_mac)
			{
				worker_instance->ProcessFunction(nonce, cipher_text, plain_text);
			}
			else
			{
				my_cpp2020_assert(false, "Oops, the cipher-text data is broken and the poly1305 message authentication code doesn't match!", std::source_location::current());
			}
		}

		virtual ~WorkerBaseWithPoly1305() = default;
	};

	class ChaCha20WithPoly1305 : public WorkerBaseWithPoly1305
	{

	public:
		ChaCha20WithPoly1305(std::span<std::uint8_t> initial_key)
		{
			worker_instance = std::unique_ptr<ChaCha20>(new ChaCha20(initial_key, 1));
			mac_worker_instance = std::unique_ptr<ChaCha20>(new ChaCha20(initial_key, 0));
		}
	};

	class ExtendedChaCha20WithPoly1305 : public WorkerBaseWithPoly1305
	{

	public:
		ExtendedChaCha20WithPoly1305(std::span<std::uint8_t> initial_key)
		{
			worker_instance = std::unique_ptr<ExtendedChaCha20>(new ExtendedChaCha20(initial_key, 1));
			mac_worker_instance = std::unique_ptr<ExtendedChaCha20>(new ExtendedChaCha20(initial_key, 0));
		}
	};

	namespace Helpers
	{
		std::vector<std::uint8_t> FillRandomByte
		(
			const std::size_t& block_size,
			std::span<std::uint8_t> byte_datas,
			std::size_t& element_remainder
		)
		{
			std::uint64_t RNG_NumberSquare_SeedKey = 0;

			//Does it use a true random number generator?
			//是否使用真随机数生成器？
			if constexpr(false)
			{
				std::random_device random_device_object;
				RNG_NumberSquare_SeedKey = GenerateSecureRandomNumberSeed<std::uint64_t>(random_device_object);
			}
			else
			{
				CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(byte_datas.subspan(0, sizeof(std::uint64_t)), &RNG_NumberSquare_SeedKey);
			}

			auto RNG_NumberSquare_Pointer = std::make_unique<RNG_NumberSquare_TakeMiddle::ImprovedJohnVonNeumannAlgorithmWithKey>
			(
				0,
				RNG_NumberSquare_SeedKey,
				std::rotl(RNG_NumberSquare_SeedKey, CURRENT_SYSTEM_BITS == 32 ? 16 : 32),
				0
			);

			auto& RNG_NumberSquare = *(RNG_NumberSquare_Pointer.get());

			std::vector<std::uint32_t> PRNE_SeedSequence = std::vector<std::uint32_t>(64, 0x00);
			for( auto& seeds : PRNE_SeedSequence )
			{
				seeds = RNG_NumberSquare();
			}

			static CommonSecurity::PseudoRandomNumberEngine<CommonSecurity::RNG_ISAAC::isaac<8>> PRNE;
			PRNE.InitialBySeed(PRNE_SeedSequence.begin(), PRNE_SeedSequence.end(), 0, false);

			PRNE_SeedSequence.clear();
			PRNE_SeedSequence.shrink_to_fit();

			std::vector<std::uint8_t> filled_byte_datas(byte_datas.begin(), byte_datas.end());

			while (element_remainder != block_size)
			{
				filled_byte_datas.push_back( PRNE.GenerateNumber(std::numeric_limits<std::uint8_t>::min(), std::numeric_limits<std::uint8_t>::max(), false) );
				++element_remainder;
			}

			return filled_byte_datas;
		}

		/*
			Align data size
		*/
		template<typename DataWorkerType>
		requires std::derived_from<DataWorkerType, WorkerBase>
		void AlignDataSize
		(
			DataWorkerType& data_worker,
			std::vector<std::uint8_t>& this_key_data,
			std::vector<std::uint8_t>& this_nonce_data
		)
		{
			std::size_t key_element_remainder = std::ranges::size(this_key_data) % (8 * sizeof(std::uint32_t));
			const std::size_t this_byte_size_of_nonces = data_worker.ByteSizeOfNonces();
			std::size_t nonce_element_remainder = std::ranges::size(this_nonce_data) % this_byte_size_of_nonces;

			if(key_element_remainder >= 1 && key_element_remainder <= 16)
			{
				if(this_key_data.size() <= 16)
				{
					this_key_data = FillRandomByte(8 * sizeof(std::uint32_t), this_key_data, key_element_remainder);
				}
				else
				{
					while (key_element_remainder != 0)
					{
						this_key_data.pop_back();
						--key_element_remainder;
					}
				}
			}
			else if(key_element_remainder > 16 && key_element_remainder <= 31)
			{
				this_key_data = FillRandomByte(8 * sizeof(std::uint32_t), this_key_data, key_element_remainder);
			}

			if(nonce_element_remainder >= 1 && nonce_element_remainder <= this_byte_size_of_nonces / 2)
			{
				if(this_nonce_data.size() <= 12)
				{
					this_nonce_data = FillRandomByte(this_byte_size_of_nonces, this_nonce_data, nonce_element_remainder);
				}
				else
				{
					while (nonce_element_remainder != 0)
					{
						this_nonce_data.pop_back();
						--nonce_element_remainder;
					}
				}
			}
			else if(nonce_element_remainder > this_byte_size_of_nonces / 2 && nonce_element_remainder <= this_byte_size_of_nonces - 1)
			{
				this_nonce_data = FillRandomByte(this_byte_size_of_nonces, this_nonce_data, nonce_element_remainder);
			}
		}


		/*
			Stream Data Cryptographic Algorithm Executor With Poly1305
		*/
		template<typename DataWorkerType>
		requires std::derived_from<DataWorkerType, WorkerBase>
		std::vector<std::uint8_t> AlgorithmExecutor
		(
			DataWorkerType data_worker,
			Cryptograph::CommonModule::CryptionMode2MCAC4_FDW worker_mode,
			std::vector<std::uint8_t>& this_message_data,
			std::vector<std::uint8_t>& this_key_data,
			std::vector<std::uint8_t>& this_nonce_data,
			std::deque<std::vector<std::uint8_t>>& this_poly1305_tag_datas,
			std::vector<std::uint8_t> this_associated_data = std::vector<std::uint8_t>()
		)
		{
			if(worker_mode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				my_cpp2020_assert(this_poly1305_tag_datas.empty(), "", std::source_location::current());
			else if(worker_mode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				my_cpp2020_assert(!this_poly1305_tag_datas.empty(), "", std::source_location::current());

			my_cpp2020_assert( worker_mode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER || worker_mode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, "Invalid working mode", std::source_location::current() );

			AlignDataSize(data_worker, this_key_data, this_nonce_data);

			std::deque<std::vector<std::uint8_t>> key_data_double_queue;
			std::deque<std::vector<std::uint8_t>> nonce_data_double_queue;

			if(this_key_data.size() != 8 * sizeof(std::uint32_t))
				CommonToolkit::ProcessingDataBlock::splitter(this_key_data, std::back_inserter(key_data_double_queue), 8 * sizeof(std::uint32_t));
			else
				key_data_double_queue.push_back(this_key_data);

			if(this_nonce_data.size() != data_worker.ByteSizeOfNonces())
				CommonToolkit::ProcessingDataBlock::splitter(this_nonce_data, std::back_inserter(nonce_data_double_queue), data_worker.ByteSizeOfNonces());
			else
				nonce_data_double_queue.push_back(this_nonce_data);

			std::vector<std::uint8_t> this_poly1305_tag_data(16, 0x00);

			std::vector<std::uint8_t> temporary_message_data(this_message_data);
			memory_set_no_optimize_function(this_message_data.data(), 0, this_message_data.size());
			std::vector<std::uint8_t> processed_message_data;

			for
			(
				auto key_first = key_data_double_queue.begin(),
				key_last = key_data_double_queue.end(),
				nonce_first = nonce_data_double_queue.begin(),
				nonce_last = nonce_data_double_queue.end();
				key_first != key_last, nonce_first != nonce_last;
				++key_first, ++nonce_first
			)
			{
				processed_message_data.resize(this_message_data.size());
				if(worker_mode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					data_worker.Encrypt(*nonce_first, temporary_message_data, processed_message_data, this_poly1305_tag_data, this_associated_data);
					this_poly1305_tag_datas.push_back(this_poly1305_tag_data);
				}
				else if(worker_mode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					this_poly1305_tag_data = this_poly1305_tag_datas.back();
					data_worker.Decrypt(*nonce_first, temporary_message_data, processed_message_data, this_poly1305_tag_data, this_associated_data);
					this_poly1305_tag_datas.pop_back();
				}
				temporary_message_data = std::move(processed_message_data);
				data_worker.UpdateKey(*key_first);
			}

			processed_message_data = std::move(temporary_message_data);
			return processed_message_data;
		}

		/*
			Stream Data Cryptographic Algorithm Executor Without Poly1305
		*/
		template<typename DataWorkerType>
		requires std::derived_from<DataWorkerType, WorkerBase>
		std::vector<std::uint8_t> AlgorithmExecutor
		(
			DataWorkerType& data_worker,
			std::vector<std::uint8_t>& this_message_data,
			std::vector<std::uint8_t>& this_key_data,
			std::vector<std::uint8_t>& this_nonce_data
		)
		{
			AlignDataSize(data_worker, this_key_data, this_nonce_data);

			std::deque<std::vector<std::uint8_t>> key_data_double_queue;
			std::deque<std::vector<std::uint8_t>> nonce_data_double_queue;

			if(this_key_data.size() != 8 * sizeof(std::uint32_t))
				CommonToolkit::ProcessingDataBlock::splitter(this_key_data, std::back_inserter(key_data_double_queue), 8 * sizeof(std::uint32_t));
			else
				key_data_double_queue.push_back(this_key_data);

			if(this_nonce_data.size() != data_worker.ByteSizeOfNonces())
				CommonToolkit::ProcessingDataBlock::splitter(this_nonce_data, std::back_inserter(nonce_data_double_queue), data_worker.ByteSizeOfNonces());
			else
				nonce_data_double_queue.push_back(this_nonce_data);

			std::vector<std::uint8_t> temporary_message_data(this_message_data);
			memory_set_no_optimize_function(this_message_data.data(), 0, this_message_data.size());
			std::vector<std::uint8_t> processed_message_data;

			for
			(
				auto key_first = key_data_double_queue.begin(),
				key_last = key_data_double_queue.end(),
				nonce_first = nonce_data_double_queue.begin(),
				nonce_last = nonce_data_double_queue.end();
				key_first != key_last, nonce_first != nonce_last;
				++key_first, ++nonce_first
			)
			{
				processed_message_data.resize(this_message_data.size());
				data_worker.ProcessFunction(*nonce_first, temporary_message_data, processed_message_data);
				temporary_message_data = std::move(processed_message_data);
				data_worker.UpdateKey(*key_first);
			}

			processed_message_data = std::move(temporary_message_data);
			return processed_message_data;
		}

		template<typename DataWorkerType, typename MemoryContinuousArgument, typename MemoryContinuousArgument2, typename MemoryContinuousArgument3>
		requires std::derived_from<DataWorkerType, WorkerBase>
		&& std::constructible_from< std::span<std::uint8_t>, MemoryContinuousArgument>
		&& std::constructible_from< std::span<std::uint8_t>, MemoryContinuousArgument2>
		&& std::constructible_from< std::span<std::uint8_t>, MemoryContinuousArgument3>
		std::vector<std::uint8_t> Helper
		(
			DataWorkerType& data_worker,
			MemoryContinuousArgument&& message_data,
			MemoryContinuousArgument2&& key_data,
			MemoryContinuousArgument3&& nonce_data
		)
		{
			my_cpp2020_assert(std::ranges::size(message_data) != 0, "The size of the message must not be empty (zero)!", std::source_location::current());
			my_cpp2020_assert(std::ranges::size(key_data) != 0, "The size of the key must not be empty (zero)!", std::source_location::current());
			my_cpp2020_assert(std::ranges::size(nonce_data) != 0, "The size of the nonce must not be empty (zero)!", std::source_location::current());

			/*
				About the concept of std::constructible_from at c++ 2020
				关于std::constructible_from在c++ 2020的概念
				It serves to check if it is the list of template parameters on the right that can construct the template type or class on the left.
				If it cannot, then the compilation reports an error, if it can, then the compilation passes.
				它的作用是检查是右侧的模板参数列表，是否能够构造左侧的模板类型或者类。
				如果不能，那么编译报错，如果能，那么编译通过。
			*/

			std::vector<std::uint8_t> this_message_data;
			std::vector<std::uint8_t> this_key_data;
			std::vector<std::uint8_t> this_nonce_data;

			if constexpr
			(
				std::same_as<std::remove_reference_t<MemoryContinuousArgument>, std::vector<std::uint8_t>>
				&& std::same_as<std::remove_reference_t<MemoryContinuousArgument2>, std::vector<std::uint8_t>>
				&& std::same_as<std::remove_reference_t<MemoryContinuousArgument3>, std::vector<std::uint8_t>>
			)
			{
				//Template argument type is :
				//std::vector<std::uint8_t> object;

				this_message_data = std::move(message_data);
				this_key_data = std::move(key_data);
				this_nonce_data = std::move(nonce_data);
			}
			else if constexpr
			(
				EODF_Reborn_CommonToolkit::CPP2020_Concepts::is_array_class_type<MemoryContinuousArgument>
				&& EODF_Reborn_CommonToolkit::CPP2020_Concepts::is_array_class_type<MemoryContinuousArgument2>
				&& EODF_Reborn_CommonToolkit::CPP2020_Concepts::is_array_class_type<MemoryContinuousArgument3>
			)
			{
				//Template argument type is :
				//std::array<std::uint8_t, N> object;

				this_message_data.resize(message_data.size());
				std::ranges::copy(message_data.begin(), message_data.end(), this_message_data.begin());
				this_key_data.resize(key_data.size());
				std::ranges::copy(key_data.begin(), key_data.end(), this_key_data.begin());
				this_nonce_data.resize(nonce_data.size());
				std::ranges::copy(nonce_data.begin(), nonce_data.end(), this_nonce_data.begin());

				memory_set_no_optimize_function(message_data.data(), 0, message_data.size());
				memory_set_no_optimize_function(key_data.data(), 0, key_data.size());
				memory_set_no_optimize_function(nonce_data.data(), 0, message_data.size());
			}
			else if constexpr
			(
				std::same_as<std::remove_all_extents_t<std::remove_reference_t<MemoryContinuousArgument>>, std::uint8_t>
				&& std::same_as<std::remove_all_extents_t<std::remove_reference_t<MemoryContinuousArgument2>>, std::uint8_t>
				&& std::same_as<std::remove_all_extents_t<std::remove_reference_t<MemoryContinuousArgument3>>, std::uint8_t>
			)
			{
				//Template argument type is :
				//std::uint8_t object[];

				std::span<std::uint8_t> message_data_span { message_data };
				std::span<std::uint8_t> key_data_span { key_data };
				std::span<std::uint8_t> nonce_data_span { nonce_data };

				this_message_data.resize(message_data_span.size());
				std::ranges::copy(message_data_span.begin(), message_data_span.end(), this_message_data.begin());
				this_key_data.resize(key_data_span.size());
				std::ranges::copy(key_data_span.begin(), key_data_span.end(), this_key_data.begin());
				this_nonce_data.resize(nonce_data_span.size());
				std::ranges::copy(nonce_data_span.begin(), nonce_data_span.end(), this_nonce_data.begin());

				memory_set_no_optimize_function(std::addressof(message_data), 0, std::ranges::size(message_data));
				memory_set_no_optimize_function(std::addressof(key_data), 0, std::ranges::size(key_data));
				memory_set_no_optimize_function(std::addressof(nonce_data), 0, std::ranges::size(message_data));
			}

			std::vector<std::uint8_t> processed_message_data = AlgorithmExecutor(data_worker, this_message_data, this_key_data, this_nonce_data);

			memory_set_no_optimize_function(this_key_data.data(), 0, this_key_data.size());
			memory_set_no_optimize_function(this_nonce_data.data(), 0, this_nonce_data.size());

			return processed_message_data;
		}
	}
}

#else

namespace CommonSecurity::OldStreamDataCryptographic
{
	class WorkerChaCha20
	{

	private:
		// The 4x4 state matrix of unsigned 32bit words as single dimension array
		// state consists of sixteen 32bit unsiged words
		std::vector<std::uint32_t> state_block = std::vector<std::uint32_t>(16, 0x00);

		//state = constants | key | counter | nonce

		// Inititalise the state with the constant and the supplied key, nonce and counter
		// 用常数和提供的密钥、Nonce和计数器初始化状态
		void FillStateBlocks_Chacha20()
		{
			state_block[0] = magical_constants[0];
			state_block[1] = magical_constants[1];
			state_block[2] = magical_constants[2];
			state_block[3] = magical_constants[3];

			std::random_device based_hardware_number_generator;
			std::mt19937 random_number(based_hardware_number_generator.operator()());
			for(std::size_t index=4; index<16; ++index)
				state_block[index] = random_number.operator()();
			state_block[12] = 0;

			if(state_block[12] == 0 && state_block[13] == 0 && state_block[14] == 0 && state_block[15] == 0)
			{
				//Currently this counter must not be zero!
				//目前这个计数器必须不能为零!
				state_block[12] = 1;
			}
		}

		//state = constants | key | counter | nonce

		// Inititalise the state with the constant and the supplied key, nonce and counter
		// 用常数和提供的密钥、Nonce和计数器初始化状态
		void FillStateBlocks_Chacha20(std::span<std::uint32_t> keys, std::span<std::uint32_t> nonces, std::uint32_t counter = 0)
		{
			state_block[0] = magical_constants[0];
			state_block[1] = magical_constants[1];
			state_block[2] = magical_constants[2];
			state_block[3] = magical_constants[3];

			state_block[4] = keys[0];
			state_block[5] = keys[1];
			state_block[6] = keys[2];
			state_block[7] = keys[3];

			state_block[8] = keys[4];
			state_block[9] = keys[5];
			state_block[10] = keys[6];
			state_block[11] = keys[7];

			state_block[12] = counter;
			state_block[13] = nonces[0];
			state_block[14] = nonces[1];
			state_block[15] = nonces[2];

			if(state_block[12] == 0 && state_block[13] == 0 && state_block[14] == 0 && state_block[15] == 0)
			{
				//Currently this counter must not be zero!
				//目前这个计数器必须不能为零!
				state_block[12] = 1;
			}
		}

		//state = constants | key | counter | nonce

		// Inititalise the state with the constant and the supplied key, nonce and counter
		// 用常数和提供的密钥、Nonce和计数器初始化状态
		void FillStateBlocks_Chacha20(std::span<std::uint8_t> keys, std::span<std::uint8_t> nonces, std::uint32_t counter = 0)
		{
			// Set up the initial value of state according to constant, key, nonce and counter constituents..
			// First four words are the (arbitary although standardised) constants
			// 根据常数、密钥、Nonce和计数器的组成来设置状态的初始值。
			// 前四个字是（任意的，尽管是标准化的）常数

			state_block[0] = magical_constants[0];
			state_block[1] = magical_constants[1];
			state_block[2] = magical_constants[2];
			state_block[3] = magical_constants[3];

			/*
				0: cccccccc    1: cccccccc   2: cccccccc   3: cccccccc
				4: kkkkkkkk    5: kkkkkkkk   6: kkkkkkkk   7: kkkkkkkk
				8: kkkkkkkk    9: kkkkkkkk   10: kkkkkkkk  11: kkkkkkkk
				12: bbbbbbbb   13: nnnnnnnn  14: nnnnnnnn  15: nnnnnnnn

				ChaCha20 State: c=constant k=key b=blockcount n=nonce
			*/

			CommonToolkit::MemoryDataFormatExchange data_format_exchanger;

			// The next 8 words contain the key
			for(std::size_t source_index = 0, target_index = 4; source_index < 32, target_index < 12; source_index += 4, ++target_index)
			{
				std::array<std::uint8_t, 4> temporary_data_array
				{
					keys[source_index],
					keys[source_index + 1],
					keys[source_index + 2],
					keys[source_index + 3],
				};
				state_block[target_index] = data_format_exchanger.Packer_4Byte(temporary_data_array);
			}

			// The next one is the counter
			state_block[12] = counter;

			// The final 3 words are the 'nonce'
			for(std::size_t source_index = 0, target_index = 13; source_index < 32, target_index < 16; source_index += 4, ++target_index)
			{
				std::array<std::uint8_t, 4> temporary_data_array
				{
					nonces[source_index],
					nonces[source_index + 1],
					nonces[source_index + 2],
					nonces[source_index + 3],
				};
				state_block[target_index] = data_format_exchanger.Packer_4Byte(temporary_data_array);
			}

			if(state_block[12] == 0 && state_block[13] == 0 && state_block[14] == 0 && state_block[15] == 0)
			{
				state_block[12] = 1;
			}
		}

		/*
			QuarterRound(state):
			{
				a = state[index];
				b = state[index + 1];
				c = state[index + 2];
				d = state[index + 3];

				a += b; d ^= a; d <<<= 16;
				c += d; b ^= c; b <<<= 12;
				a += b; d ^= a; d <<<= 8;
				c += d; b ^= c; b <<<= 7;
			}

			//Quarter Round Transform
			//四分之一轮变换
		*/
		void QuarterRound(std::span<std::uint32_t> state_block_argument, std::size_t index, std::size_t index2, std::size_t index3, std::size_t index4)
		{
			my_cpp2020_assert(state_block_argument.size() == 16, "Invalid stream cryptographic status data !", std::source_location::current());

			// Build state data
			// 构建状态数据
			// Hiden the class member state_block
			// 隐藏类成员state_block
			std::array<std::uint32_t, 4> state_block
			{
				state_block_argument.operator[](index),
				state_block_argument.operator[](index2),
				state_block_argument.operator[](index3),
				state_block_argument.operator[](index4),
			};

			// Reference data from state data
			// 从状态数据中引用数据

			auto& [a, b, c, d] = state_block;

			// Execute data changer to span view
			// 执行数据改变器到跨度视图

			a += b;
			d ^= a;
			d = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(d, 16);

			c += d;
			b ^= c;
			b = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(b, 12);

			a += b;
			d ^= a;
			d = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(d, 8);

			c += d;
			b ^= c;
			b = CommonSecurity::Binary_LeftRotateMove<std::uint32_t>(b, 7);

			state_block_argument.operator[](index) = state_block.operator[](0);
			state_block_argument.operator[](index2) = state_block.operator[](1);
			state_block_argument.operator[](index3) = state_block.operator[](2);
			state_block_argument.operator[](index4) = state_block.operator[](3);
		}

	protected:
		static constexpr std::array<std::uint32_t, 4> magical_constants
		{
			0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
		};

		/*
			inner_block(state):
			{
				QuarterRound(state, 0, 4, 8, 12);
				QuarterRound(state, 1, 5, 9, 13);
				QuarterRound(state, 2, 6, 10, 14);
				QuarterRound(state, 3, 7, 11, 15);

				QuarterRound(state, 0, 5, 10, 15);
				QuarterRound(state, 1, 6, 11, 12);
				QuarterRound(state, 2, 7, 8, 13);
				QuarterRound(state, 3, 4, 9, 14);
			}
		*/
		void UpdateStateBlock(std::span<std::uint32_t> state_block_argument, std::size_t round_counter = 10)
		{
			// Doing 20 rounds of computation on it (one iteration every 2 rounds)
			// 对它进行20轮计算（每2轮迭代一次）
			for(std::size_t index = 0; index < round_counter; ++index)
			{
				// Odd round
				// For the current state of the round transformation data applied to the row
				// 对于当前状态的轮变换数据应用到行

				this->QuarterRound(state_block_argument, 0, 4, 8, 12);
				this->QuarterRound(state_block_argument, 1, 5, 9, 13);
				this->QuarterRound(state_block_argument, 2, 6, 10, 14);
				this->QuarterRound(state_block_argument, 3, 7, 11, 15);

				// Even round
				// For the current state of the round transformation data applied to the diagonal
				// 对于当前状态的轮变换数据应用到对角线

				this->QuarterRound(state_block_argument, 0, 5, 10, 15);
				this->QuarterRound(state_block_argument, 1, 6, 11, 12);
				this->QuarterRound(state_block_argument, 2, 7, 8, 13);
				this->QuarterRound(state_block_argument, 3, 4, 9, 14);
			}
		}

		void GenerateKeyStream(std::span<std::uint32_t> state_block_argument, std::span<std::uint8_t> key_stream_block)
		{
			// State per 64 byte block
			// 每个64字节块的状态
			std::vector<std::uint32_t> work_state_block = std::vector<std::uint32_t>(16, 0x00);

			/* Apply chacha20 rounds (Generate key-stream function is begin) */

			std::span<std::uint32_t> state_block_span(state_block_argument.begin(), state_block_argument.end());
			std::span<std::uint32_t> work_state_block_span(work_state_block.begin(), work_state_block.end());

			// Make a local copy of the state
			// 制作一个本地的状态副本
			std::ranges::copy(state_block_span.begin(), state_block_span.end(), work_state_block_span.begin());
			/*std::ranges::copy(this->state_block.get(), this->state_block.get() + 16, work_state_block.get());*/

			this->UpdateStateBlock( work_state_block_span );

			CommonToolkit::MemoryDataFormatExchange data_format_exchanger;
			// Add local state and initial state and save as a 64 byte array
			// 添加本地状态和初始状态，并保存为一个64字节的数组
			for (std::size_t index = 0; index < 16; index++)
			{
				std::uint32_t temporary_integer = work_state_block_span.operator[](index) + state_block_span.operator[](index);
				std::span<std::uint8_t> temporary_data_array_span = data_format_exchanger.Unpacker_4Byte(temporary_integer);

				key_stream_block.operator[](index * 4) = temporary_data_array_span.operator[](0);
				key_stream_block.operator[](index * 4 + 1) = temporary_data_array_span.operator[](1);
				key_stream_block.operator[](index * 4 + 2) = temporary_data_array_span.operator[](2);
				key_stream_block.operator[](index * 4 + 3) = temporary_data_array_span.operator[](3);
			}

			/* Apply chacha20 rounds (Generate key-stream function is end) */
		}

	public:

		std::uint32_t GetCounter()
		{
			return state_block[12];
		}

		void SetCounter(std::uint32_t value)
		{
			state_block[12] = value;
		}

		/*
			chacha20_block(key, counter, nonce):
			{
				state = constants | key | counter | nonce
				initial_state = state
				for i=1 upto 10
				{
					inner_block(state)
				}

				state += initial_state
				return serialize(state)
			}

			// and

			poly1305_key_generate(key,nonce):
			{
				counter = 0
				block = chacha20_block(key,counter,nonce)
				return block[0..31]
			}

			// and

			chacha20_encrypt(key, counter, nonce, plaintext):
			{
				for j = 0 upto floor(len(plaintext)/64)-1
				{
					key_stream = chacha20_block(key, counter+j, nonce)
					block = plaintext[(j*64)..(j*64+63)]
					encrypted_message +=  block ^ key_stream
				}
				if ((len(plaintext) % 64) != 0)
				{
					j = floor(len(plaintext)/64)
					key_stream = chacha20_block(key, counter+j, nonce)
					block = plaintext[(j*64)..len(plaintext)-1]
					encrypted_message += (block^key_stream)[0..len(plaintext)%64]
				}
				return encrypted_message
			}

		*/
		template<bool IsPoly1305KeyGenerateMode>
		void ChaCha20_TransformData(std::span<std::uint8_t> buffer, std::size_t start_index, std::size_t end_index)
		{
			if(start_index > end_index)
				return;
			if(start_index == end_index)
				return;

			std::vector<std::uint8_t> key_stream_block = std::vector<std::uint8_t>(64, 0x00);

			if constexpr(IsPoly1305KeyGenerateMode)
			{
				if ( this->state_block.operator[](12) != 0)
				{
					my_cpp2020_assert(false, "The number of the password counter of ChaCha20 must be a value equal to 0 in poly1305-key-generate mode", std::source_location::current());
				}

				this->GenerateKeyStream(this->state_block, key_stream_block);

				buffer = key_stream_block;

				return;
			}
			else
			{
				// ExclusiveOR ing cursor we'll move over the array
				// 独占光标，我们将在数组上移动。
				std::int32_t process_counter = start_index;

				while (process_counter < end_index)
				{
					this->GenerateKeyStream(this->state_block, key_stream_block);

					/*
						process first all 64-bytes data chunks
						and
						process last no 64-bytes length data chunk

						首先处理所有64字节的数据块
						和
						最后处理没有64字节长度的数据块
					*/
					for (std::size_t index = 0; index < 64; index++)
					{
						buffer.operator[](process_counter) ^= key_stream_block.operator[](index);
						++process_counter;
						if(process_counter == buffer.size())
							break;
					}

					/*
						Automatic counter increment
						If the number of counters overflows, the next word (nonce part) is automatically incremented.
						But the nonce part of the 3 words, after which all overflow occurs, then this function forces an exception to be thrown!
						自动增加计数器
						如果计数器数量发生溢出，则自动增加下一个字（nonce部分）。
						但是nonce部分的3个字，之后全部发生溢出，则这个函数强制抛出异常！
					*/
					if ( ++(this->state_block.operator[](12)) == 0)
					{
						std::cout << "Warnning [1/3]: ChaCha20 records the value of the number of counters for processed messages, an arithmetic overflow has occurred, so the first word of the nonce part of the state_block has been changed !" << std::endl;

						if( ++(this->state_block.operator[](13)) == 0)
						{
							std::cout << "Warnning [2/3]: ChaCha20 records the value of the number of counters for processed messages, an arithmetic overflow has occurred, so the second word of the nonce part of the state_block has been changed !" << std::endl;

							if( ++(this->state_block.operator[](14)) == 0)
							{
								std::cout << "Warnning [3/3]: ChaCha20 records the value of the number of counters for processed messages, an arithmetic overflow has occurred, so the third word of the nonce part of the state_block has been changed !" << std::endl;

								if( ++(this->state_block.operator[](15)) == 0 )
								{
									my_cpp2020_assert(false, "Error: The value of the number of counters for processed messages recorded by ChaCha20, Must be a value that cannot be rolled back to the origin!", std::source_location::current());
								}
							}
						}
					}
				}
			}
		}

		//With random number device
		WorkerChaCha20()
		{
			this->FillStateBlocks_Chacha20();
		}

		//With user integer data
		WorkerChaCha20(std::span<std::uint32_t> keys, std::span<std::uint32_t> nonces, std::uint32_t counter = 1)
		{
			// Keys and InitialVectors(nonces) must be correct size
			my_cpp2020_assert( keys.data() != nullptr && keys.size() == 8, "Keys must be a 32 byte/sizeof(std::uint32_t) * 8 (256 bit) array !", std::source_location::current() );
			my_cpp2020_assert( nonces.data() != nullptr && nonces.size() == 3, "Nonces must be a 12 byte/sizeof(std::uint32_t) * 3 (96 bit) array !", std::source_location::current() );

			this->FillStateBlocks_Chacha20(keys, nonces, counter);
		}

		//With user byte data
		WorkerChaCha20( std::span<std::uint8_t> keys, std::span<std::uint8_t> nonces, std::uint32_t counter = 1)
		{
			// Keys and InitialVectors(nonces) must be correct size
			my_cpp2020_assert( keys.data() != nullptr && keys.size() == sizeof(std::uint32_t) * 8, "Keys must be a 32 byte/sizeof(std::uint32_t) * 8 (256 bit) array !", std::source_location::current() );
			my_cpp2020_assert( nonces.data() != nullptr && nonces.size() == sizeof(std::uint32_t) * 3, "Nonces must be a 12 byte/sizeof(std::uint32_t) * 3 (96 bit) array !", std::source_location::current() );

			this->FillStateBlocks_Chacha20(keys, nonces, counter);
		}

		WorkerChaCha20(const WorkerChaCha20& other_worker)
		{
			std::ranges::copy(other_worker.state_block.begin(), other_worker.state_block.end(), this->state_block.begin());
		}

		~WorkerChaCha20() = default;
	};

	/*
		*HChaCha20* is an intermediary step towards XChaCha20 based on the construction and security proof used to create XSalsa20 [11],
		an extended-nonce Salsa20 variant used in NaCl [12].

		HChaCha20 is initialized the same way as the ChaCha cipher,
		except that HChaCha20 uses a 128-bit nonce and has no counter.
		Instead, the block counter is replaced by the first 32 bits of the nonce.

		Consider the two figures below,
		where each non-whitespace character represents one nibble of information about the ChaCha states (all numbers little-endian):

		cccccccc  cccccccc  cccccccc  cccccccc
		kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
		kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
		bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

		ChaCha20 State: c=constant k=key b=blockcount n=nonce

		cccccccc  cccccccc  cccccccc  cccccccc
		kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
		kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
		nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn

		HChaCha20 State: c=constant k=key n=nonce

		After initialization, proceed through the ChaCha rounds as usual.

		Once the 20 ChaCha rounds have been completed,
		the first 128 bits and last 128 bits of the ChaCha state (both little-endian) are concatenated,
		and this 256-bit subkey is returned.
	*/

	class WorkerExtendedChaCha20 : public WorkerChaCha20
	{

	private:
		// The 4x4 state matrix of unsigned 32bit words as single dimension array
		// state consists of sixteen 32bit unsiged words
		std::vector<std::uint32_t> state_block = std::vector<std::uint32_t>(16, 0x00);

		void FillStateBlocks_ExtendedChacha20(std::span<std::uint32_t> keys, std::span<std::uint32_t> nonces)
		{
			state_block[0] = magical_constants[0];
			state_block[1] = magical_constants[1];
			state_block[2] = magical_constants[2];
			state_block[3] = magical_constants[3];

			state_block[4] = keys[0];
			state_block[5] = keys[1];
			state_block[6] = keys[2];
			state_block[7] = keys[3];

			state_block[8] = keys[4];
			state_block[9] = keys[5];
			state_block[10] = keys[6];
			state_block[11] = keys[7];

			state_block[12] = nonces[0];
			state_block[13] = nonces[1];
			state_block[14] = nonces[2];
			state_block[15] = nonces[3];
			//nonce bytes(0~3) <-> one word, bytes(4~7) <-> one word, bytes(8~11) <-> one word, bytes(12~15) <-> one word
		}

		void FillStateBlocks_ExtendedChacha20(std::span<std::uint8_t> keys, std::span<std::uint8_t> nonces)
		{
			/*
				0: cccccccc    1: cccccccc   2: cccccccc   3: cccccccc
				4: kkkkkkkk    5: kkkkkkkk   6: kkkkkkkk   7: kkkkkkkk
				8: kkkkkkkk    9: kkkkkkkk   10: kkkkkkkk  11: kkkkkkkk
				12: nnnnnnnn   13: nnnnnnnn  14: nnnnnnnn  15: nnnnnnnn

				HChaCha20 State: c=constant k=key n=nonce
			*/

			CommonToolkit::MemoryDataFormatExchange data_format_exchanger;

			// The first step 8 words contain the key
			for(std::size_t source_index = 0, target_index = 4; source_index < 32 && target_index < 12; source_index += 4, ++target_index)
			{
				std::array<std::uint8_t, 4> temporary_data_array
				{
					keys[source_index],
					keys[source_index + 1],
					keys[source_index + 2],
					keys[source_index + 3],
				};
				state_block[target_index] = data_format_exchanger.Packer_4Byte(temporary_data_array);
			}

			// The last step 4 words are the 'nonce'
			for(std::size_t source_index = 0, target_index = 12; source_index < 32 && target_index < 16; source_index += 4, ++target_index)
			{
				std::array<std::uint8_t, 4> temporary_data_array
				{
					nonces[source_index],
					nonces[source_index + 1],
					nonces[source_index + 2],
					nonces[source_index + 3],
				};
				state_block[target_index] = data_format_exchanger.Packer_4Byte(temporary_data_array);
			}
			//nonce bytes(0~3) <-> one word, bytes(4~7) <-> one word, bytes(8~11) <-> one word, bytes(12~15) <-> one word
		}

		//Process a pseudorandom keystream block, converting the key and part of the "nonces" into a "subkey_block", and the remainder of the "nonces"
		//处理一个伪随机密钥流块，将密钥和部分 "nonces "转换为 "subkey_block"，以及 "nonces "的剩余部分。
		void HChaCha20(std::span<std::uint32_t> subkey_block)
		{
			my_cpp2020_assert( subkey_block.data() != nullptr && subkey_block.size() == 8, "Subkey-block must be a 32 byte/sizeof(std::uint32_t) * 8 (256 bit) array !", std::source_location::current() );

			std::span<std::uint32_t> state_block_span(this->state_block.begin(), this->state_block.end());
			this->UpdateStateBlock(state_block_span);

			subkey_block.operator[](0) = state_block_span.operator[](12); //HChaCha20 state[4]: key (1 word)
			subkey_block.operator[](1) = state_block_span.operator[](13); //HChaCha20 state[5]: key (1 word)
			subkey_block.operator[](2) = state_block_span.operator[](14); //HChaCha20 state[6]: key (1 word)
			subkey_block.operator[](3) = state_block_span.operator[](15); //HChaCha20 state[7]: key (1 word)
			subkey_block.operator[](4) = state_block_span.operator[](8); //HChaCha20 state[8]: key (1 word)
			subkey_block.operator[](5) = state_block_span.operator[](9); //HChaCha20 state[9]: key (1 word)
			subkey_block.operator[](6) = state_block_span.operator[](10); //HChaCha20 state[10]: key (1 word)
			subkey_block.operator[](7) = state_block_span.operator[](11); //HChaCha20 state[11]: key (1 word)
		}

	public:

		WorkerExtendedChaCha20(std::span<std::uint8_t> keys, std::span<std::uint8_t> nonces)
		{
			// Keys and InitialVectors(nonces) must be correct size
			my_cpp2020_assert( keys.data() != nullptr && keys.size_bytes() == 256 / 8, "Keys must be a 32 byte/sizeof(std::uint32_t) * 8 (256 bit) array !", std::source_location::current() );
			my_cpp2020_assert( nonces.data() != nullptr && nonces.size_bytes() == 192 / 8, "Nonces must be a 24 byte/sizeof(std::uint32_t) * 6 (192 bit) array !", std::source_location::current() );

			this->FillStateBlocks_ExtendedChacha20(keys, nonces);
		}

		WorkerExtendedChaCha20(std::span<std::uint32_t> keys, std::span<std::uint32_t> nonces)
		{
			// Keys and InitialVectors(nonces) must be correct size
			my_cpp2020_assert( keys.data() != nullptr && keys.size_bytes() == 256 / 8, "Keys must be a 32 byte/sizeof(std::uint32_t) * 8 (256 bit) array !", std::source_location::current() );
			my_cpp2020_assert( nonces.data() != nullptr && nonces.size_bytes() == 192 / 8, "Nonces must be a 24 byte/sizeof(std::uint32_t) * 6 (192 bit) array !", std::source_location::current() );

			this->FillStateBlocks_ExtendedChacha20(keys, nonces);
		}

		WorkerExtendedChaCha20(const WorkerExtendedChaCha20& other_worker)
		{
			std::ranges::copy(other_worker.state_block.begin(), other_worker.state_block.end(), this->state_block.begin());
		}

		~WorkerExtendedChaCha20() = default;

		/*
			Extended-nonce ChaCha20

			xchacha20_encrypt(key, nonce, plaintext, blk_ctr = 0):
			{
				subkey = hchacha20(key, nonce[0:15]) //nonce 1 byte ~ 16 byte <-> count: 1 word ~ 4 word

				chacha20_nonce = "\x00\x00\x00\x00" + nonce[16:23] //nonce 17 byte ~ 24 byte <-> count: 5 word ~ 6 word

				return chacha20_encrypt(subkey, chacha20_nonce, plaintext, blk_ctr)
			}

			//The encryption function can also be used for decryption, since the keystream generated by ChaCha20 is just mixed with the plaintext using bitwise XOR.
		*/
		static std::vector<std::uint8_t> ExtendedChaCha20(std::span<std::uint8_t> message_data, std::span<std::uint8_t> key_data, std::span<std::uint8_t> nonce_data, std::uint32_t counter = 1)
		{
			WorkerExtendedChaCha20 extended_chacha20_worker(key_data, nonce_data);

			std::array<std::uint32_t, 8> subkey_block = { 0x0000000, 0x0000000, 0x0000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000 };
			extended_chacha20_worker.HChaCha20(subkey_block);

			//"\x00\x00\x00\x00" bytes(index: 0 ~ 4) <-> one word
			//nonce bytes(16~19) <-> one word, nonce bytes(index: 20 ~ 23) <-> one word
			CommonToolkit::MemoryDataFormatExchange data_format_exchanger;

			std::array<std::uint32_t, 3> chacha20_nonce { 0x0000000, 0x0000000, 0x0000000 };

			for(std::size_t source_index = 16, target_index = 1; (source_index < 24) && (target_index < 3); source_index += 4, ++target_index)
			{
				std::array<std::uint8_t, 4> temporary_data_array
				{
					nonce_data[source_index],
					nonce_data[source_index + 1],
					nonce_data[source_index + 2],
					nonce_data[source_index + 3],
				};
				chacha20_nonce[target_index] = data_format_exchanger.Packer_4Byte(temporary_data_array);
			}

			WorkerChaCha20 chacha20_worker(subkey_block, chacha20_nonce, counter);
			chacha20_worker.ChaCha20_TransformData<false>(message_data, 0, message_data.size());

			return std::vector<std::uint8_t>(message_data.begin(), message_data.end());
		}

		static std::vector<std::uint8_t> ExtendedChaCha20(std::span<std::uint8_t> message_data, std::span<std::uint32_t> key_data, std::span<std::uint32_t> nonce_data, std::uint32_t counter = 1)
		{
			WorkerExtendedChaCha20 extended_chacha20_worker(key_data, nonce_data);

			std::array<std::uint32_t, 8> subkey_block = { 0x0000000, 0x0000000, 0x0000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000 };
			extended_chacha20_worker.HChaCha20(subkey_block);

			//"\x00\x00\x00\x00" bytes(0~4) <-> one word
			//nonce bytes(16~19) <-> one word, nonce bytes(20~23) <-> one word
			std::array<std::uint32_t, 3> chacha20_nonce { 0x00000000, nonce_data[4], nonce_data[5] };

			WorkerChaCha20 chacha20_worker(subkey_block, chacha20_nonce, counter);
			chacha20_worker.ChaCha20_TransformData<false>(message_data, 0, message_data.size());

			return std::vector<std::uint8_t>(message_data.begin(), message_data.end());
		}
	};

	namespace Helpers
	{
		template<std::size_t block_size>
		std::vector<std::uint8_t> FillRandomByte
		(
			std::span<std::uint8_t> byte_datas,
			std::size_t& element_remainder
		)
		{
			std::uint64_t RNG_NumberSquare_SeedKey = 0;

			//Does it use a true random number generator?
			//是否使用真随机数生成器？
			if constexpr(false)
			{
				std::random_device random_device_object;
				RNG_NumberSquare_SeedKey = GenerateSecureRandomNumberSeed<SeedNumberType>(random_device_object);
			}
			else
			{
				CommonToolkit::MessagePacking<SeedNumberType, std::uint8_t>(byte_datas.subspan(0, sizeof(std::uint64_t)), &RNG_NumberSquare_SeedKey);
			}

			auto RNG_NumberSquare_Pointer = std::make_unique<RNG_NumberSquare_TakeMiddle::ImprovedJohnVonNeumannAlgorithmWithKey>
			(
				0,
				RNG_NumberSquare_SeedKey,
				std::rotl(RNG_NumberSquare_SeedKey, CURRENT_SYSTEM_BITS == 32 ? 16 : 32),
				0
			);

			auto& RNG_NumberSquare = *(RNG_NumberSquare_Pointer.get());

			std::vector<std::uint32_t> PRNE_SeedSequence = std::vector<std::uint32_t>(64, 0x00);
			for( auto& seeds : PRNE_SeedSequence )
			{
				seeds = RNG_NumberSquare();
			}

			static CommonSecurity::PseudoRandomNumberEngine<CommonSecurity::RNG_ISAAC::isaac<8>> PRNE;
			PRNE.InitialBySeed(PRNE_SeedSequence.begin(), PRNE_SeedSequence.end(), 0, false);

			PRNE_SeedSequence.clear();
			PRNE_SeedSequence.shrink_to_fit();

			std::vector<std::uint8_t> filled_byte_datas(byte_datas.begin(), byte_datas.end());

			while (element_remainder != block_size)
			{
				filled_byte_datas.push_back( PRNE.GenerateNumber(std::numeric_limits<std::uint8_t>::min(), std::numeric_limits<std::uint8_t>::max(), false) );
				++element_remainder;
			}

			return filled_byte_datas;
		}

		std::vector<std::uint8_t> AlgorithmExecutor
		(
			std::vector<std::uint8_t>& message_data,
			std::vector<std::uint8_t>& key_data,
			std::vector<std::uint8_t>& nonce_data
		)
		{
			std::size_t key_element_remainder = key_data.size() % (8 * sizeof(std::uint32_t));
			std::size_t nonce_element_remainder = nonce_data.size() % (6 * sizeof(std::uint32_t));

			if(key_element_remainder >= 1 && key_element_remainder <= 16)
			{
				if(key_data.size() <= 16)
				{
					key_data = FillRandomByte<8 * sizeof(std::uint32_t)>(key_data, key_element_remainder);
				}
				else
				{
					while (key_element_remainder != 0)
					{
						key_data.pop_back();
						--key_element_remainder;
					}
				}
			}
			else if(key_element_remainder > 16 && key_element_remainder <= 31)
			{
				key_data = FillRandomByte<8 * sizeof(std::uint32_t)>(key_data, key_element_remainder);
			}

			if(nonce_element_remainder >= 1 && nonce_element_remainder <= 12)
			{
				if(nonce_data.size() <= 12)
				{
						nonce_data = FillRandomByte<6 * sizeof(std::uint32_t)>(nonce_data, nonce_element_remainder);
				}
				else
				{
					while (nonce_element_remainder != 0)
					{
						nonce_data.pop_back();
						--nonce_element_remainder;
					}
				}
			}
			else if(nonce_element_remainder > 12 && nonce_element_remainder <= 23)
			{
					nonce_data = FillRandomByte<6 * sizeof(std::uint32_t)>(nonce_data, nonce_element_remainder);
			}

			std::deque<std::vector<std::uint8_t>> key_data_double_queue;
			std::deque<std::vector<std::uint8_t>> nonce_data_double_queue;

			if(key_data.size() != 8 * sizeof(std::uint32_t))
				CommonToolkit::ProcessingDataBlock::splitter(key_data, std::back_inserter(key_data_double_queue), 8 * sizeof(std::uint32_t));
			if(nonce_data.size() != 6 * sizeof(std::uint32_t))
				CommonToolkit::ProcessingDataBlock::splitter(nonce_data, std::back_inserter(nonce_data_double_queue), 6 * sizeof(std::uint32_t));

			std::size_t worker_chacha20_state_counter = 0;

			std::vector<std::uint8_t> processed_message_data;

			for
			(
				auto key_first = key_data_double_queue.begin(),
				key_last = key_data_double_queue.end(),
				nonce_first = nonce_data_double_queue.begin(),
				nonce_last = nonce_data_double_queue.end();
				key_first != key_last, nonce_first != nonce_last;
				++key_first, ++nonce_first, ++worker_chacha20_state_counter
			)
			{
				processed_message_data = WorkerExtendedChaCha20::ExtendedChaCha20(message_data, *key_first, *nonce_first, worker_chacha20_state_counter);
				std::ranges::swap_ranges(message_data, processed_message_data);
			}

			return processed_message_data;
		}
	}
}

#endif
