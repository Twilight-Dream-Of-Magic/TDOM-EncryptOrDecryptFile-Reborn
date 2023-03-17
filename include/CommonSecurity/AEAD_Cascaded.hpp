#pragma once

/*
	关联性数据的认证加密解密模式
	Authenticated encryption-decryption mode for associative data
*/
namespace CommonSecurity::AEAD
{
	namespace BlockCipherMode
	{
		class ApplyIndependentType;
		class ApplyDependentType;
		class AEAD_UseCascaded;

		/*
			There are a number of AEAD modes of operation, each with different properties and trade-offs. 
			Based on your definition of dependency, I can classify some of them as follows:

			Dependent AEAD modes: 
			These modes generate the tag from the plaintext and the associated data with encryption mode; verify the tag from the ciphertext and the associated data with decryption mode, and do not require a number once value. 
			Examples are SIV mode and EAX mode.
			Note: EAX mode and OCB mode is a dependent AEAD mode. The dependency is not based on whether the mode needs a nonce or not, but on how the tag is generated

			Independent AEAD modes: 
			These modes derive the tag from an internal state that is updated by each block of plaintext and associated data, and require a nonce. 
			Examples are GCM mode, CCM mode and ChaCha20-Poly1305 mode.

			Hybrid AEAD modes: 
			These modes combine dependent and independent AEAD modes to achieve nonce misuse-resistance. 
			Examples are GCM-SIV mode and AES-GCM-SIV mode.
		*/

		//Authenticated Encryption/Decryption with Associated Data mode for Ciphers
		enum class WorkMode
		{
			//Counter With Cipher Block Chaining Message Authentication Code; Counter with CBC-MAC
			//Cipher Block Chaining Message Authentication Code
			CCM = 0,

			//Galois Counter Mode
			GALOIS_COUNTER = 1,

			//Encrypt Then Authenticate Then Translate Mode
			EAX = 2,

			//Synthetic Initialization Vector Mode
			SIV = 3,

			//Offset CodeBlock Mode
			OCB = 4
		};

		class CCM;
		class GCM;

		class EAX;
		class SIV;
		class OCB;
		
		/* 
			Independent AEAD modes
		*/
		class IndependentType
		{
			using BlockCipher128_128 = CommonSecurity::BlockCipher128_128;
			using BlockCipher128_256 = CommonSecurity::BlockCipher128_256;

		public:
			virtual void ComputeTag(std::span<const std::uint8_t> Data, std::span<const std::uint8_t> Keys, std::span<std::uint8_t> AuthenticationTag) = 0;
			
			void VerifyTag(std::span<const std::uint8_t> Data, std::span<const std::uint8_t> Keys, std::span<const std::uint8_t> AuthenticationTag)
			{
				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize>
				ComputedTag {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

				this->ComputeTag(Data, Keys, ComputedTag);

				if(std::ranges::equal(ComputedTag.begin(), ComputedTag.end(), AuthenticationTag.begin(), AuthenticationTag.end()) == false)
					my_cpp2020_assert(false, "This ciphertext has been tampered with! The AuthenticationTag calculation and comparison are inconsistent. Please discard the ciphertext immediately!", std::source_location::current());
			}

			IndependentType() = default;
			virtual ~IndependentType() = default;
		};

		/*
			Dependent AEAD modes
		*/
		struct DependentType
		{
			using BlockCipher128_128 = CommonSecurity::BlockCipher128_128;
			using BlockCipher128_256 = CommonSecurity::BlockCipher128_256;
			
			virtual void ProvideAssociativeData(std::span<const std::uint8_t> AssociativeData)
			{
				my_cpp2020_assert(false, "The base class does not implement this function!", std::source_location::current());
			}

			virtual void ProvideNumberOnce(std::span<const std::uint8_t> NumberOnce)
			{
				my_cpp2020_assert(false, "The base class does not implement this function!", std::source_location::current());
			}

			virtual void ProvideKeys(std::span<const std::uint8_t> Keys)
			{
				my_cpp2020_assert(false, "The base class does not implement this function!", std::source_location::current());
			}

			virtual void Encryption(std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<std::uint8_t> AuthenticationTag) = 0;

			virtual void Decryption(std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<const std::uint8_t> AuthenticationTag) = 0;

			DependentType() = default;
			virtual ~DependentType() = default;
		};

		inline void LeftShift_OneBit(std::size_t BlockSize, std::span<const std::uint8_t> input, std::span<std::uint8_t> output)
		{
			int			  i;
			std::uint8_t overflow = 0;

			for ( i = BlockSize - 1; i >= 0; i-- )
			{
				output[ i ] = input[ i ] << 1;
				output[ i ] |= overflow;
				overflow = ( input[ i ] & 0x80 ) ? 0x01 : 0x00;
			}
			return;
		}

		inline void RightShift_OneBit(std::size_t BlockSize, std::span<const std::uint8_t> input, std::span<std::uint8_t> output)
		{
			int			 i;
			std::uint8_t underflow = 0;

			for ( i = 0; i < BlockSize; i++ )
			{
				output[ i ] = input[ i ] >> 1;
				output[ i ] |= underflow;
				underflow = ( input[ i ] & 0x01 ) ? 0x80 : 0x00;
			}
			return;
		}

		//https://www.rfc-editor.org/rfc/rfc4493
		//https://datatracker.ietf.org/doc/html/rfc4493
		struct CMAC
		{
			using BlockCipher128_128 = CommonSecurity::BlockCipher128_128;
			using BlockCipher128_256 = CommonSecurity::BlockCipher128_256;

			//Subkeys
			std::vector<std::uint8_t> K1_128Bit =  std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);
			std::vector<std::uint8_t> K2_128Bit = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);

			std::vector<std::uint8_t> K1_256Bit = std::vector<std::uint8_t>(BlockCipher128_256::KeyBlockByteSize, 0);
			std::vector<std::uint8_t> K2_256Bit = std::vector<std::uint8_t>(BlockCipher128_256::KeyBlockByteSize, 0);

			//Temporary Data Block
			std::vector<std::uint8_t> X_Block = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);
			std::vector<std::uint8_t> Y_Block = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);

			CommonSecurity::AES::DataWorker256 AES_128_256;
			CommonSecurity::AES::DataWorker128 AES_128_128;

			bool IsInitialized = false;

			void Generate_Subkey256Bit
			(
				std::span<const std::uint8_t> Keys,
				std::vector<std::uint8_t>& KeysA,
				std::vector<std::uint8_t>& KeysB
			)
			{
				/* Step 1: AES-128 with key K is applied to an all-zero input block. */

				//Use AES-256

				std::vector<std::uint8_t> InitialVector (BlockCipher128_256::DataBlockByteSize, 0);
				std::vector<std::uint8_t> InitialVector2 (BlockCipher128_256::DataBlockByteSize, 0);
				
				//L = Encrypt({000000000000000......}, Key0)
				//L' = Encrypt(L, Key0)
				AES_128_256.EncryptionWithECB(InitialVector, Keys, InitialVector);
				AES_128_256.EncryptionWithECB(InitialVector, Keys, InitialVector2);

				std::array<std::uint8_t, BlockCipher128_256::KeyBlockByteSize> ModifiedInitialVector {};
				::memcpy(ModifiedInitialVector.data(), InitialVector.data(), InitialVector.size());
				::memcpy(ModifiedInitialVector.data() + 16, InitialVector2.data(), InitialVector2.size());

				constexpr std::uint8_t BitMask = 0x80;

				constexpr std::array<std::uint8_t, BlockCipher128_256::KeyBlockByteSize> DoublingConstantData
				{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
				};

				KeysA.resize(BlockCipher128_256::KeyBlockByteSize);

				/* Step 2: Derive K1. */
				// K1 = L GF_Multiply{GF_{2^n}} K0
				if ((KeysA[0] & BitMask) == 0)
				{
					// If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_256::KeyBlockByteSize, ModifiedInitialVector, KeysA);
				}
				else
				{
					// Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_256::KeyBlockByteSize, ModifiedInitialVector, KeysA);

					KeysA[BlockCipher128_256::KeyBlockByteSize - 1] ^= DoublingConstantData[BlockCipher128_256::KeyBlockByteSize - 1];
				}

				KeysB.resize(BlockCipher128_256::KeyBlockByteSize);

				/* Step 2: Derive K2. */
				// K2 = L Multiply{GF_{2^n}} K0^{2} = (L << 1) Multiply{GF_{2^n}} K0
				if ((KeysB[0] & BitMask) == 0)
				{
					// If the most significant bit of K1 is equal to 0, K2 is the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_256::KeyBlockByteSize, KeysA, KeysB);
				}
				else
				{
					// Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.
					LeftShift_OneBit(BlockCipher128_256::KeyBlockByteSize, KeysA, KeysB);

					KeysB[BlockCipher128_256::KeyBlockByteSize - 1] ^= DoublingConstantData[BlockCipher128_256::KeyBlockByteSize - 1];
				}
			}

			void Generate_Subkey128Bit
			(
				std::span<const std::uint8_t> Keys,
				std::vector<std::uint8_t>& KeysA,
				std::vector<std::uint8_t>& KeysB
			)
			{
				/*
					+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
					+                    Algorithm Generate_Subkey                      +
					+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
					+                                                                   +
					+   Input    : K (128-bit key)                                      +
					+   Output   : K1 (128-bit first subkey)                            +
					+              K2 (128-bit second subkey)                           +
					+-------------------------------------------------------------------+
					+                                                                   +
					+   Constants: const_Zero is 0x00000000000000000000000000000000     +
					+              const_Rb   is 0x00000000000000000000000000000087     +
					+   Variables: L          for output of AES-128 applied to 0^128    +
					+                                                                   +
					+   Step 1.  L := AES-128(K, const_Zero);                           +
					+   Step 2.  if MSB(L) is equal to 0                                +
					+            then    K1 := L << 1;                                  +
					+            else    K1 := (L << 1) XOR const_Rb;                   +
					+   Step 3.  if MSB(K1) is equal to 0                               +
					+            then    K2 := K1 << 1;                                 +
					+            else    K2 := (K1 << 1) XOR const_Rb;                  +
					+   Step 4.  return K1, K2;                                         +
					+                                                                   +
					+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
				*/

				//Use AES-128

				std::vector<std::uint8_t> InitialVector (BlockCipher128_128::DataBlockByteSize, 0);

				/* Step 1: AES-128 with key K is applied to an all-zero input block. */
				// L = Encrypt({000000000000000......}, Key0)

				AES_128_128.EncryptionWithECB(InitialVector, Keys, InitialVector);

				constexpr std::uint8_t BitMask = 0x80;

				constexpr std::array<std::uint8_t, BlockCipher128_128::DataBlockByteSize> DoublingConstantData
				{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
				};

				KeysA.resize(BlockCipher128_128::DataBlockByteSize);

				/* Step 2: Derive K1. */
				// K1 = L GF_Multiply{GF_{2^n}} K0
				if ((KeysA[0] & BitMask) == 0)
				{
					// If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_128::DataBlockByteSize, InitialVector, KeysA);
				}
				else
				{
					// Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_128::DataBlockByteSize, InitialVector, KeysA);

					KeysA[BlockCipher128_256::DataBlockByteSize - 1] ^= DoublingConstantData[BlockCipher128_256::DataBlockByteSize - 1];
				}

				KeysB.resize(BlockCipher128_128::DataBlockByteSize);

				/* Step 2: Derive K2. */
				// K2 = L Multiply{GF_{2^n}} K0^{2} = (L << 1) Multiply{GF_{2^n}} K0
				if ((KeysB[0] & BitMask) == 0)
				{
					// If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
					LeftShift_OneBit(BlockCipher128_128::DataBlockByteSize, KeysA, KeysB);
				}
				else
				{
					// Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.
					LeftShift_OneBit(BlockCipher128_128::DataBlockByteSize, KeysA, KeysB);

					KeysB[BlockCipher128_256::DataBlockByteSize - 1] ^= DoublingConstantData[BlockCipher128_256::DataBlockByteSize - 1];
				}
			}

			void Initialize(std::span<const std::uint8_t> Keys)
			{
				this->Generate_Subkey128Bit(Keys.subspan(0, BlockCipher128_128::KeyBlockByteSize), K1_128Bit, K2_128Bit);

				std::array<std::uint8_t, BlockCipher128_256::KeyBlockByteSize> CipherKeys_256bit {};

				::memcpy(CipherKeys_256bit.data(), K1_128Bit.data(), K1_128Bit.size());
				::memcpy(CipherKeys_256bit.data() + 16, K2_128Bit.data(), K2_128Bit.size());

				this->Generate_Subkey256Bit(CipherKeys_256bit, K1_256Bit, K2_256Bit);

				IsInitialized = true;
			}

			void Update(std::span<const std::uint8_t> Ciphertext)
			{
				/*
					+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
					+                   Algorithm AES-CMAC                              +
					+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
					+                                                                   +
					+   Input    : K    ( 128-bit key )                                 +
					+            : M    ( message to be authenticated )                 +
					+            : len  ( length of the message in octets )             +
					+   Output   : T    ( message authentication code )                 +
					+                                                                   +
					+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
					+   Constants: const_Zero is 0x00000000000000000000000000000000     +
					+              const_Bsize is 16                                    +
					+                                                                   +
					+   Variables: K1, K2 for 128-bit subkeys                           +
					+              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
					+              M_last is the last block xor-ed with K1 or K2        +
					+              n      for number of blocks to be processed          +
					+              r      for number of octets of last block            +
					+              flag   for denoting if last block is complete or not +
					+                                                                   +
					+   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
					+   Step 2.  n := ceil(len/const_Bsize);                            +
					+   Step 3.  if n = 0                                               +
					+            then                                                   +
					+                 n := 1;                                           +
					+                 flag := false;                                    +
					+            else                                                   +
					+                 if len mod const_Bsize is 0                       +
					+                 then flag := true;                                +
					+                 else flag := false;                               +
					+                                                                   +
					+   Step 4.  if flag is true                                        +
					+            then M_last := M_n XOR K1;                             +
					+            else M_last := padding(M_n) XOR K2;                    +
					+   Step 5.  X := const_Zero;                                       +
					+   Step 6.  for i := 1 to n-1 do                                   +
					+                begin                                              +
					+                  Y := X XOR M_i;                                  +
					+                  X := AES-128(K,Y);                               +
					+                end                                                +
					+            Y := M_last XOR X;                                     +
					+            T := AES-128(K,Y);                                     +
					+   Step 7.  return T;                                              +
					+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
				*/

				if (!IsInitialized)
					return;

				std::size_t N = (Ciphertext.size() + BlockCipher128_256::DataBlockByteSize - 1) / BlockCipher128_256::DataBlockByteSize;
				bool Flag = false;

				if(N == 0)
				{
					N = 1;
					Flag = false;
				}
				else
				{
					if((Ciphertext.size() % BlockCipher128_256::DataBlockByteSize) == 0)
						Flag = true;
					else
						Flag = false;
				}

				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> TailDataBlock {};
				if(Flag == true)
				{
					const std::uint8_t* DataBlock = &Ciphertext[BlockCipher128_256::DataBlockByteSize * (N - 1)];

					//Use Subkey1 Do XOR
					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						TailDataBlock[i] = DataBlock[i] ^ K1_128Bit[i];
					}
				}
				else
				{
					std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> Padded {};

					//Do padding
					const std::uint8_t* DataBlock = &Ciphertext[BlockCipher128_256::DataBlockByteSize * (N - 1)];
					const std::size_t DataBlockSize = Ciphertext.size();

					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						if(i < DataBlockSize)
							Padded[i] = DataBlock[i];
						else if(i == DataBlockSize)
							Padded[i] = 0x80;
						else
							Padded[i] = 0x00;
					}

					//Use Subkey2 Do XOR
					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						TailDataBlock[i] = Padded[i] ^ K2_128Bit[i];
					}
				}

				//I use AES-256 (the original version uses AES-128)
				CommonSecurity::AES::DataWorker256 CipherAES;

				for(std::size_t i = 0; i < N - 1; ++i)
				{
					const std::uint8_t* DataBlock = &Ciphertext[BlockCipher128_256::DataBlockByteSize * i];
					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						Y_Block[i] = X_Block[i] ^ DataBlock[i];
						CipherAES.EncryptionWithECB(Y_Block, K1_256Bit, X_Block);
					}
				}

				for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
				{
					Y_Block[i] = TailDataBlock[i] ^ X_Block[i];
				}
			}

			void Finish(std::span<std::uint8_t> AuthenticationTag)
			{
				if (!IsInitialized)
					return;

				//I use AES-256 (the original version uses AES-128)

				AES_128_256.EncryptionWithECB(Y_Block, K2_256Bit, AuthenticationTag);

				this->Reset();
			}

			void Reset()
			{
				memory_set_no_optimize_function<0x00>(K1_128Bit.data(), K1_128Bit.size());
				memory_set_no_optimize_function<0x00>(K2_128Bit.data(), K2_128Bit.size());

				memory_set_no_optimize_function<0x00>(K1_256Bit.data(), K1_128Bit.size());
				memory_set_no_optimize_function<0x00>(K2_256Bit.data(), K2_256Bit.size());

				memory_set_no_optimize_function<0x00>(X_Block.data(), X_Block.size());
				memory_set_no_optimize_function<0x00>(Y_Block.data(), Y_Block.size());

				IsInitialized = false;
			}
		};

		//https://datatracker.ietf.org/doc/rfc3610/
		class CCM : public IndependentType
		{

		public:
			void ComputeTag(std::span<const std::uint8_t> Data, std::span<const std::uint8_t> Keys, std::span<std::uint8_t> AuthenticationTag) override
			{
				//CCM - The counter with cipher block chaining message authentication code; counter with CBC-MAC
				//CBC-MAC  - The cipher block chaining message authentication code

				CMAC CMAC_Object;
				CMAC_Object.Initialize(Keys);
				CMAC_Object.Update(Data);

				std::vector<std::uint8_t> Tag = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);
				CMAC_Object.Finish(Tag);

				std::ranges::copy(Tag.begin(), Tag.end(), AuthenticationTag.begin());
			}

			CCM() = default;
			virtual ~CCM() = default;
		};

		// GaloisHash implements the polynomial authenticator part of GCM as specified
		// in http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
		// Specifically it implements the GHASH function, defined in section 2.3 of that document.
		//
		// In SP-800-38D, GHASH is defined differently and takes only a single data argument.
		// But it is always called with an argument of a certain form:
		// GHASH_H (A || 0^v || C || 0^u || [length(A)]_64 || [length(C)]_64)
		// This mirrors how the gcm-revised-spec.pdf version of GHASH handles its two data arguments.
		// The two GHASH functions therefore differ only in whether the data is formatted inside or outside of the function.
		//
		// WARNING: do not use this as a generic authenticator. 
		// Polynomial authenticators must be used in the correct manner and any use outside of GCM requires careful consideration.
		//
		// WARNING: this code is not constant time. However, in all likelihood, nor is the implementation of AES that is used.
		// https://chromium.googlesource.com/chromium/src/+/32352ad08ee673a4d43e8593ce988b224f6482d3/crypto/ghash.cc
		struct GaloisFiniteField128Hash
		{
			/* GHASH Application Interface */

			void Initialize(std::span<const std::uint8_t> Keys)
			{
				std::uint64_t low_value = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(Keys.subspan(0, 8));
				std::uint64_t high_value = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(Keys.subspan(8, 8));

				FieldElement NumberX { low_value, high_value };

				this->product_table_[0].low = 0;
				this->product_table_[0].high = 0;
				this->product_table_[Reverse(1)] = NumberX;

				for ( std::uint32_t i = 0; i < 16; i += 2 )
				{
					this->product_table_[Reverse(i)] = DoubleExp(product_table_[Reverse(i/2)]);
					this->product_table_[Reverse(i+1)] = Addition(product_table_[Reverse(i)], NumberX);
				}

				IsInitialized = true;
			}

			// Reset prepares to digest a fresh message with the same key. 
			// This is more efficient than creating a fresh object.
			void Reset()
			{
				this->CurrentWorkState = State::HashingAdditionalData;
				this->AbsorbedAdditionalByteCount = 0;
				this->AbsorbedCiphertextBytesCount = 0;
				this->ByteBufferUsed = 0;

				this->NumberY.low = 0;
				this->NumberY.high = 0;

				IsInitialized = false;
			}

			GaloisFiniteField128Hash() = default;


			~GaloisFiniteField128Hash()
			{
				this->Reset();
			}

			// UpdateAdditional hashes in `additional' data.
			// This is data that is not encrypted, but is covered by the authenticator.
			// All additional data must be written before any ciphertext is written.
			void UpdateAdditional(std::span<const std::uint8_t> AdditionalData)
			{
				if(!IsInitialized)
					return;

				if(CurrentWorkState == State::HashingAdditionalData)
				{
					this->AbsorbedAdditionalByteCount += AdditionalData.size();
					this->Update(AdditionalData);
				}
			}

			// UpdateCiphertext hashes in ciphertext to be authenticated
			void UpdateCiphertext(std::span<const std::uint8_t> Ciphertext)
			{
				if(!IsInitialized)
					return;

				if(CurrentWorkState == State::HashingAdditionalData)
				{
					// If there's any remaining additional data it's zero padded to the next full block.
					if(ByteBufferUsed > 0)
					{
						::memset(&ByteBuffer[ByteBufferUsed], 0, sizeof(ByteBuffer) - ByteBufferUsed);
						UpdateBlocks(ByteBuffer.data(), 1);
						ByteBufferUsed = 0;
					}
					CurrentWorkState = State::HashingCiphertext;
				}
					
				if(CurrentWorkState == State::HashingCiphertext)
				{
					AbsorbedCiphertextBytesCount += Ciphertext.size();
					this->Update(Ciphertext);
				}
			}

			// Finish completes the hash computation and writes at most |len| bytes of the result to |output|
			void Finish(std::span<std::uint8_t> HashedData)
			{
				if(!IsInitialized)
					return;

				if(CurrentWorkState != State::Hashed)
				{
					// If there's any remaining data (additional data or ciphertext), it's zero padded to the next full block.
					if(ByteBufferUsed > 0)
					{
						::memset(&ByteBuffer[ByteBufferUsed], 0, sizeof(ByteBuffer) - ByteBufferUsed);
						UpdateBlocks(ByteBuffer.data(), 1);
						ByteBufferUsed = 0;
					}

					CurrentWorkState = State::Hashed;

					// The lengths of the additional data and ciphertext are included as the last block. 
					// The lengths are the number of bits.
					NumberY.low ^= AbsorbedAdditionalByteCount * 8;
					NumberY.high ^= AbsorbedCiphertextBytesCount * 8;
					MultiplyAfterPrecomputation(product_table_, NumberY);

					std::uint8_t* result = nullptr;
					std::array<std::uint8_t, 16> result_array {};

					if(HashedData.size() >= 16)
						result = HashedData.data();
					else
						result = result_array.data();

					std::array<std::uint8_t, 8> low_bytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberY.low);
					std::array<std::uint8_t, 8> high_bytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberY.high);

					::memcpy(result, low_bytes.data(), 8);
					::memcpy(result + 8, high_bytes.data(), 8);

					if(HashedData.size() < 16)
						::memcpy(HashedData.data(), result_array.data(), HashedData.size());
				}

				this->Reset();
			}

			/* GHASH Implementation And Uitl Funtion */

			// Reverse reverses the order of the bits of 4-bit number in |Index0|.
			static std::uint32_t Reverse(std::uint32_t index)
			{
				index = ((index << 2) & 0xc) | ((index >> 2) & 0x3);
				index = ((index << 1) & 0xa) | ((index >> 1) & 0x5);
				return index;
			}

			enum class State : std::uint32_t
			{
				HashingAdditionalData = 0,
				HashingCiphertext = 1,
				Hashed = 2
			};

			struct FieldElement
			{
				std::uint64_t low = 0, high = 0;
				FieldElement()
					:
					low(0), high(0)
				{
					
				}

				explicit FieldElement(std::uint64_t low, std::uint64_t high)
					:
					low(low), high(high) 
				{
				}

				~FieldElement()
				{
					low = 0;
					high = 0;
				}
			};

			//returns |x|+|y|
			static FieldElement Addition(const FieldElement& x, const FieldElement& y)
			{
				FieldElement result { x.low ^ y.low, x.high ^ y.high };
				return result;
			}

			//returns 2*|x|
			static FieldElement DoubleExp(const FieldElement& x)
			{
				bool MostSignificantBit = x.high & 1;

				FieldElement xx {0,0};

				// Because of the bit-ordering, doubling is actually a right shift.
				xx.high = x.high >> 1;
				xx.high |= x.low << 63;
				xx.low = x.low >> 1;

				// If the most-significant bit was set before shifting then it, conceptually, becomes a term of x^128.
				// This is greater than the irreducible polynomial so the result has to be reduced. 
				// The irreducible polynomial is 1+x+x^2+x^7+x^128. 
				// We can subtract that to eliminate the term at x^128 which also means subtracting the other four terms.
				// In characteristic 2 fields, subtraction == addition == XOR.

				if(MostSignificantBit)
					xx.low ^= 0xe100000000000000ULL;

				return xx;
			}

			//sets |x| = 16*|x|
			static void Multiply16(FieldElement& x) 
			{
				bool MostSignificantWord = x.high & 0xf;
				x.high >>= 4;
				x.high |= x.low << 60;
				x.low >>= 4;
				x.low ^= static_cast<std::uint64_t>(ReductionTable[MostSignificantWord]);
			}

			//sets |x| = |x|*h where h is |table[1]| and table[Index0] = Index0*h for Index0=0..15.
			static void MultiplyAfterPrecomputation(std::span<const FieldElement> Table, FieldElement& NumberX)
			{
				FieldElement NumberZ {0,0};

				// In order to efficiently multiply, we use the precomputed table of Index0*key, for Index0 in 0..15, to handle four bits at a time.
				// We could obviously use larger tables for greater speedups but the next convenient table size is 4K, which is a little large.
				// In other fields one would use bit positions spread out across the field in order to reduce the number of doublings required. 
				// However, in characteristic 2 fields, repeated doublings are exceptionally cheap and it's not worth spending more precomputation time to eliminate them.
				for (std::uint32_t i = 0; i < 2; i++)
				{
					std::uint64_t Word64Bit;
					if (i == 0)
					{
						Word64Bit = NumberX.high;
					} else
					{
						Word64Bit = NumberX.low;
					}

					for (std::uint32_t j = 0; j < 64; j += 4)
					{
						Multiply16(NumberZ);
						// The values in |table| are ordered for little-endian bit positions. See
						// The comment in the constructor.
						const FieldElement& NumberT = Table[Word64Bit & 0xf];
						NumberZ.low ^= NumberT.low;
						NumberZ.high ^= NumberT.high;
						Word64Bit >>= 4;
					}
				}

				NumberX = NumberZ;
			}

			// UpdateBlocks processes |num_blocks| 16-bytes blocks from |bytes|.
			void UpdateBlocks(const std::uint8_t* Bytes, size_t count)
			{
				for (size_t i = 0; i < count; i++) 
				{
					NumberY.low ^= CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(std::span<const std::uint8_t>{Bytes,8});
					Bytes += 8;
					NumberY.high ^= CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(std::span<const std::uint8_t>{Bytes,8});
					Bytes += 8;
					MultiplyAfterPrecomputation(product_table_, NumberY);
				}
			}
					
			// Update processes |length| bytes from |bytes| and calls UpdateBlocks on as  much data as possible.
			// It uses |ByteBuffer| to buffer any remaining data and always consumes all of |bytes|.
			void Update(std::span<const std::uint8_t> Bytes)
			{
				const std::uint8_t* Data = Bytes.data();
				std::size_t Size = Bytes.size();

				if(ByteBufferUsed > 0)
				{
					const std::size_t n = ::std::min<std::size_t>(Size, sizeof(ByteBuffer) - ByteBufferUsed);
					::memcpy(&ByteBuffer[ByteBufferUsed], Data, n);

					ByteBufferUsed += n;
					Size -= n;
					Data += n;

					if(ByteBufferUsed == sizeof(ByteBuffer))
					{
						this->UpdateBlocks(ByteBuffer.data(), 1);
						ByteBufferUsed = 0;
					}
				}

				if(Size >= 16)
				{
					const std::size_t n = Size / 16;
					this->UpdateBlocks(Data, n);
					Size -= n*16;
					Data += n*16;
				}

				if(Size > 0)
				{
					::memcpy(ByteBuffer.data(), Data, Size);
					ByteBufferUsed = Size;
				}
			}

			// kReductionTable allows for rapid multiplications by 16.
			// A multiplication by 16 is a right shift by four bits, which results in four bits at 2**128.
			// These terms have to be eliminated by dividing by the irreducible polynomial.
			// In GHASH, the polynomial is such that all the terms occur in the least-significant 8 bits, save for the term at x^128.
			// Therefore we can precompute the value to be added to the field element for each of the 16 bit patterns at 2**128 and the values fit within 12 bits.
			static constexpr std::array<std::uint16_t, 16> ReductionTable
			{
				0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
				0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
			};

			bool IsInitialized = false;
			FieldElement NumberY;
			State CurrentWorkState = State::HashingAdditionalData;
			std::size_t AbsorbedAdditionalByteCount = 0;
			std::size_t AbsorbedCiphertextBytesCount = 0;
			std::array<uint8_t, 16> ByteBuffer {};
			std::size_t ByteBufferUsed = 0;
			std::array<FieldElement, 16> product_table_
			{
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0},
				FieldElement {0,0}
			};
		};

		class GCM : public IndependentType
		{
		public:
			void ComputeTag(std::span<const std::uint8_t> Data, std::span<const std::uint8_t> Keys, std::span<std::uint8_t> AuthenticationTag) override
			{
				//GMAC - The galois message authentication code
				GaloisFiniteField128Hash GHASH;
				GHASH.Initialize( Keys );

				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize>
				AdditionalData { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

				// Generate pseudo-random numbers for AdditionalData using an linear feedback shift register
				std::uint64_t LFSR_Value = 0xACE1U;
				std::uint64_t DoMixRound = std::max<std::uint64_t>( Data.size(), Keys.size() );
				for ( std::size_t Index = 0; Index < DoMixRound; ++Index )
				{
					AdditionalData[ Index % BlockCipher128_256::DataBlockByteSize ] = LFSR_Value & 0xFFU;
					AdditionalData[ Index % BlockCipher128_256::DataBlockByteSize ] ^= Data[ ( Index + 1 ) % Data.size() ] & Keys[ ( Index + 2 ) % Keys.size() ];

					// Bitmask is 100011001000010000000000000000000101 (x^35 + x^31 + x^30 + x^27 + x^22 + x^2 + 1)
					LFSR_Value = ( LFSR_Value >> 1 ) ^ ( -( LFSR_Value & 1U ) & 0x8C8400005U );
				}

				// Non-linear function based on bytes using a combination of simple non-linear functions
				for ( std::size_t Index0 = 0; Index0 < AdditionalData.size(); ++Index0 )
				{
					AdditionalData[ Index0 ] ^= ( ( AdditionalData[ Index0 ] << 4 ) | ( AdditionalData[ Index0 ] >> 4 ) ) & 0xF0U;
					AdditionalData[ Index0 ] ^= ( ( AdditionalData[ Index0 ] << 2 ) | ( AdditionalData[ Index0 ] >> 6 ) ) & 0xCCU;
					AdditionalData[ Index0 ] ^= ( ( AdditionalData[ Index0 ] << 1 ) | ( AdditionalData[ Index0 ] >> 7 ) ) & 0xAAU;
				}

				GHASH.UpdateAdditional( AdditionalData );
				GHASH.UpdateCiphertext( Data );

				GHASH.Finish( AuthenticationTag );
				//GHASH.Reset();
			}

			GCM() = default;
			virtual ~GCM() = default;
		};

		//One-Key CBC MAC Version 2
		//http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
		struct OMAC2
		{
			using BlockCipher128_128 = CommonSecurity::BlockCipher128_128;
			using BlockCipher128_256 = CommonSecurity::BlockCipher128_256;

			//Subkeys
			std::vector<std::uint8_t> K1_128Bit = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);
			std::vector<std::uint8_t> K2_128Bit = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);

			std::vector<std::uint8_t> K1_256Bit = std::vector<std::uint8_t>(BlockCipher128_256::KeyBlockByteSize, 0);
			std::vector<std::uint8_t> K2_256Bit = std::vector<std::uint8_t>(BlockCipher128_256::KeyBlockByteSize, 0);

			//Temporary Data Block
			std::vector<std::uint8_t> X_Block = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);
			std::vector<std::uint8_t> Y_Block = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);

			bool IsInitialized = false;

			CommonSecurity::AES::DataWorker256 AES_128_256;

			CommonSecurity::AES::DataWorker128 AES_128_128;

			void Generate_Subkey256Bit
			(
				std::span<const std::uint8_t> Keys,
				std::vector<std::uint8_t>& KeysA,
				std::vector<std::uint8_t>& KeysB
			)
			{
				/* Step 1: AES-256 with key K is applied to an all-zero input block. */

				//Use AES-256

				std::vector<std::uint8_t> InitialVector (BlockCipher128_256::DataBlockByteSize, 0);
				std::vector<std::uint8_t> InitialVector2 (BlockCipher128_256::DataBlockByteSize, 0);
				
				//L = Encrypt({000000000000000......}, Key0)
				//L' = Encrypt(L, Key0)
				AES_128_256.EncryptionWithECB(InitialVector, Keys, InitialVector);
				AES_128_256.EncryptionWithECB(InitialVector, Keys, InitialVector2);

				std::array<std::uint8_t, BlockCipher128_256::KeyBlockByteSize> ModifiedInitialVector {};
				::memcpy(ModifiedInitialVector.data(), InitialVector.data(), InitialVector.size());
				::memcpy(ModifiedInitialVector.data() + 16, InitialVector2.data(), InitialVector2.size());

				constexpr std::uint8_t BitMask = 0x80;

				constexpr std::array<std::uint8_t, BlockCipher128_256::KeyBlockByteSize> DoublingConstantData
				{
					0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43
				};

				KeysA.resize(BlockCipher128_256::KeyBlockByteSize);

				/* Step 2: Derive K1. */
				// K1 = L GF_Multiply K0
				if ((KeysA[0] & BitMask) == 0)
				{
					// If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_256::KeyBlockByteSize, ModifiedInitialVector, KeysA);
				}
				else
				{
					// Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_256::KeyBlockByteSize, ModifiedInitialVector, KeysA);

					for(std::size_t i = 0; i < BlockCipher128_256::KeyBlockByteSize; i++)
					{
						KeysA[i] ^= DoublingConstantData[i];
					}
				}

				KeysB.resize(BlockCipher128_256::KeyBlockByteSize);

				/* Step 2: Derive K2. */
				// K2 = L Multiply{GF_{2^n}} K1^{-1} = (L >> 1) Multiply{GF_{2^n}} K0 or (L >> 1)
				if ((KeysB[0] & BitMask) == 0)
				{
					// If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
					RightShift_OneBit(BlockCipher128_256::KeyBlockByteSize, ModifiedInitialVector, KeysB);
				}
				else
				{
					// Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.
					RightShift_OneBit(BlockCipher128_256::KeyBlockByteSize, ModifiedInitialVector, KeysB);
					for(std::size_t i = 0; i < BlockCipher128_256::KeyBlockByteSize; i++)
					{
						KeysB[i] ^= DoublingConstantData[i];
					}
				}
			}

			void Generate_Subkey128Bit
			(
				std::span<const std::uint8_t> Keys,
				std::vector<std::uint8_t>& KeysA,
				std::vector<std::uint8_t>& KeysB
			)
			{
				//Use AES-128

				std::vector<std::uint8_t> InitialVector (BlockCipher128_128::DataBlockByteSize, 0);

				/* Step 1: AES-128 with key K is applied to an all-zero input block. */
				// L = Encrypt({000000000000000......}, Key0)

				AES_128_128.EncryptionWithECB(InitialVector, Keys, InitialVector);

				constexpr std::uint8_t BitMask = 0x80;

				constexpr std::array<std::uint8_t, BlockCipher128_128::DataBlockByteSize> DoublingConstantData
				{
					0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43
				};

				KeysA.resize(BlockCipher128_128::DataBlockByteSize);

				/* Step 2: Derive K1. */
				// K1 = L GF_Multiply{GF_{2^n}} K0
				if ((KeysA[0] & BitMask) == 0)
				{
					// If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_128::DataBlockByteSize, InitialVector, KeysA);
				}
				else
				{
					// Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.
					LeftShift_OneBit(BlockCipher128_128::DataBlockByteSize, InitialVector, KeysA);

					for(std::size_t i = 0; i < BlockCipher128_128::DataBlockByteSize; i++)
					{
						KeysA[i] ^= DoublingConstantData[i];
					}
				}

				KeysB.resize(BlockCipher128_128::DataBlockByteSize);

				/* Step 2: Derive K2. */
				// K2 = L Multiply{GF_{2^n}} K1^{-1} = (L >> 1) Multiply{GF_{2^n}} K0 or (L >> 1)
				if ((KeysB[0] & BitMask) == 0)
				{
					// If the most significant bit of K1 is equal to 0, K2 is the right-shift of L by 1 bit.
					RightShift_OneBit(BlockCipher128_128::DataBlockByteSize, InitialVector, KeysB);
				}
				else
				{
					// Otherwise, K2 is the exclusive-OR of const_Rb and the right-shift of K1 by 1 bit.
					RightShift_OneBit(BlockCipher128_128::DataBlockByteSize, InitialVector, KeysB);
					for(std::size_t i = 0; i < BlockCipher128_128::DataBlockByteSize; i++)
					{
						KeysB[i] ^= DoublingConstantData[i];
					}
				}
			}

			void Initialize(std::span<const std::uint8_t> Keys)
			{
				this->Generate_Subkey128Bit(Keys, K1_128Bit, K2_128Bit);

				std::vector<std::uint8_t> CipherKeys_256bit = std::vector<std::uint8_t>(BlockCipher128_256::KeyBlockByteSize, 0);

				::memcpy(CipherKeys_256bit.data(), K1_128Bit.data(), K1_128Bit.size());
				::memcpy(CipherKeys_256bit.data() + 16, K2_128Bit.data(), K2_128Bit.size());

				this->Generate_Subkey256Bit(CipherKeys_256bit, K1_256Bit, K2_256Bit);

				IsInitialized = true;
			}

			void Update(std::span<const std::uint8_t> Ciphertext)
			{
				using namespace CommonSecurity::AES;

				if (!IsInitialized)
					return;

				std::size_t N = (Ciphertext.size() + BlockCipher128_256::DataBlockByteSize - 1) / BlockCipher128_256::DataBlockByteSize;
				bool Flag = false;

				//I use AES-256 (the original version uses AES-128)
				DataWorker256 CipherAES;

				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> Y_Previous_Block {};

				for(std::size_t i = 0; i < N - 1; ++i)
				{
					const std::uint8_t* DataBlock = &Ciphertext[BlockCipher128_256::DataBlockByteSize * i];
					for(std::size_t j = 0; j < BlockCipher128_256::DataBlockByteSize; ++j)
					{
						X_Block[j] = DataBlock[j] ^ Y_Block[j];
						CipherAES.EncryptionWithECB(X_Block, K1_256Bit, Y_Block);
					}

					if(i == N - 2)
					{
						::memcpy(Y_Previous_Block.data(), Y_Block.data(), BlockCipher128_256::DataBlockByteSize);
					}
				}

				if(N == 0)
				{
					N = 1;
					Flag = false;
				}
				else
				{
					if((Ciphertext.size() % BlockCipher128_256::DataBlockByteSize) == 0)
						Flag = true;
					else
						Flag = false;
				}

				if(Flag == true)
				{
					const std::uint8_t* Block1 = &Ciphertext[BlockCipher128_256::DataBlockByteSize * (N - 1)];
					const std::uint8_t* Block2 = &Y_Previous_Block[0];

					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						X_Block[i] = Block1[i] ^ Block2[i];
					}

					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						X_Block[i] ^= K1_128Bit[i];
					}
				}
				else
				{
					std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> Padded {};

					//Do padding
					const std::uint8_t* DataBlock = &Y_Previous_Block[0];
					const std::size_t DataBlockSize = Ciphertext.size();

					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						if(i < DataBlockSize)
							Padded[i] = Ciphertext[i];
						else if(i == DataBlockSize)
							Padded[i] = 0x80;
						else
							Padded[i] = 0x00;
					}

					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						X_Block[i] = Padded[i] ^ DataBlock[i];
					}

					for(std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
					{
						X_Block[i] ^= K2_128Bit[i];
					}
				}
			}

			void Finish(std::span<std::uint8_t> AuthenticationTag)
			{
				using namespace CommonSecurity::AES;

				if (!IsInitialized)
					return;

				//I use AES-256 (the original version uses AES-128)
				DataWorker256 CipherAES;

				CipherAES.EncryptionWithECB(X_Block, K2_256Bit, AuthenticationTag);

				this->Reset();
			}

			void Reset()
			{
				memory_set_no_optimize_function<0x00>(K1_128Bit.data(), K1_128Bit.size());
				memory_set_no_optimize_function<0x00>(K2_128Bit.data(), K2_128Bit.size());

				memory_set_no_optimize_function<0x00>(K1_256Bit.data(), K1_128Bit.size());
				memory_set_no_optimize_function<0x00>(K2_256Bit.data(), K2_256Bit.size());

				memory_set_no_optimize_function<0x00>(X_Block.data(), X_Block.size());
				memory_set_no_optimize_function<0x00>(Y_Block.data(), Y_Block.size());

				IsInitialized = false;
			}
		};

		struct ApplyIndependentType
		{

		private:
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> AuthenticationTag {};

			CommonSecurity::AES::DataWorker256 AES_128_256;

		public:
			void GenerateAuthenticationTag
			(
				std::span<const std::uint8_t> OriginalKeyStream,
				std::span<const std::uint8_t> CipherText,
				std::span<std::uint8_t> GeneratedAuthenticationTag,
				BlockCipherMode::WorkMode Mode
			)
			{
				std::unique_ptr<BlockCipherMode::IndependentType> AEAD_Pointer = nullptr;
				switch ( Mode )
				{
					case BlockCipherMode::WorkMode::CCM:
						AEAD_Pointer = std::make_unique< BlockCipherMode::CCM>();
						break;
					case BlockCipherMode::WorkMode::GALOIS_COUNTER:
						AEAD_Pointer = std::make_unique<CommonSecurity::AEAD::BlockCipherMode::GCM>();
						break;
					default:
						break;
				}

				AEAD_Pointer->ComputeTag(CipherText, OriginalKeyStream, this->AuthenticationTag);

				::memcpy(GeneratedAuthenticationTag.data(), this->AuthenticationTag.data(), this->AuthenticationTag.size());
			}

			void VerificationAuthenticationTag
			(
				std::span<const std::uint8_t> OriginalKeyStream,
				std::span<const std::uint8_t> CipherText,
				std::span<const std::uint8_t> SampleAuthenticationTag,
				BlockCipherMode::WorkMode Mode
			)
			{
				std::unique_ptr<BlockCipherMode::IndependentType> AEAD_Pointer = nullptr;
				switch ( Mode )
				{
					case BlockCipherMode::WorkMode::CCM:
						AEAD_Pointer = std::make_unique<BlockCipherMode::CCM>();
						break;
					case BlockCipherMode::WorkMode::GALOIS_COUNTER:
						AEAD_Pointer = std::make_unique<BlockCipherMode::GCM>();
						break;
					default:
						break;
				}

				AEAD_Pointer->VerifyTag(CipherText, OriginalKeyStream, SampleAuthenticationTag);
			}

			ApplyIndependentType() = default;
			~ApplyIndependentType() = default;
		};
		
	}  // namespace BlockCipherMode

}  // namespace AEAD

namespace CommonSecurity::AEAD::BlockCipherMode
{
	class EAX : public DependentType
	{
		
	private:
		CommonSecurity::AES::DataWorker256 AES_128_256;

		std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ExtraKeys {};
		std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> NumberOnceTag {};
		std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> AssociativeDataTag {};

		bool ProvidedData = false;

		void CounterMode_128_256(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % BlockCipher128_256::KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			auto UniformInteger_Pointer = std::make_unique<CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t>>
			(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
			auto& UniformInteger = *UniformInteger_Pointer;
			
			//Seed, Seed2 = BytesView(Key)
			//NumberOnce = UniformInteger(PRNG)
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			//This algorithm comes from RC4+
			//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
			CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG((PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5));

			std::span<std::uint8_t> OriginalCounterBlock{NumberOnceTag.begin(), NumberOnceTag.end()};
			std::uint64_t NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(OriginalCounterBlock.subspan(0, 8));
			std::uint64_t CounterPart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(OriginalCounterBlock.subspan(8, 8));
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> KeyStream {};

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += BlockCipher128_256::DataBlockByteSize)
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, BlockCipher128_256::KeyBlockByteSize);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(BlockCipher128_256::DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(BlockCipher128_256::DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				AES_128_256.KeyExpansion(KeyBlock);
				AES_128_256.ProcessBlockEncryption(CounterBlock, KeyStream);
					
				for(std::size_t Index = 0; Index < InputDataBlock.size(); ++Index)
				{
					OutputDataBlock[Index] = KeyStream[Index] ^ InputDataBlock[Index];
				}

				if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0)
				{
					++SanityCounterLow;
				}
				else if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0)
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					//Change number once value is uniform random integer
					NumberOncePart = UniformInteger(PRNG);
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += BlockCipher128_256::KeyBlockByteSize;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}

			UniformInteger_Pointer.reset();
		}

	public:
		void Initialize
		(
			std::span<const std::uint8_t> KeyStream,
			std::span<const std::uint8_t> NumberOnce, 
			std::span<const std::uint8_t> AssociativeData
		)
		{
			//EAX - The Encrypt then authenticate then translate
			
			//NumberOnce' = OMAC(Key2, NumberOnce)
			OMAC2 OMAC2_Object;
			OMAC2_Object.Initialize(KeyStream.subspan(0, BlockCipher128_256::DataBlockByteSize));
			OMAC2_Object.Update(NumberOnce);
			OMAC2_Object.Finish(NumberOnceTag);

			//AdditionalHeaderData' = OMAC(Key2, AssociativeHeaderData)
			OMAC2_Object.Initialize(KeyStream.subspan(BlockCipher128_256::DataBlockByteSize, BlockCipher128_256::DataBlockByteSize));
			OMAC2_Object.Update(AssociativeData);
			OMAC2_Object.Finish(AssociativeDataTag);

			::memcpy(ExtraKeys.data(), KeyStream.data() + BlockCipher128_256::DataBlockByteSize * 2, BlockCipher128_256::DataBlockByteSize);

			this->ProvidedData = true;
		}

		void Encryption(std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<std::uint8_t> AuthenticationTag) override
		{
			if(!ProvidedData)
				return;

			OMAC2 OMAC2_Object;
			
			std::array<std::uint8_t, BlockCipher128_256::KeyBlockByteSize> NumberOnceKey {};
			std::vector<std::uint8_t> SubKey1(BlockCipher128_256::DataBlockByteSize, 0);
			std::vector<std::uint8_t> SubKey2(BlockCipher128_256::DataBlockByteSize, 0);
			OMAC2_Object.Generate_Subkey128Bit(NumberOnceTag, SubKey1, SubKey2);
			::memcpy(NumberOnceKey.data(), SubKey1.data(), SubKey1.size());
			::memcpy(NumberOnceKey.data() + SubKey1.size(), SubKey2.data(), SubKey2.size());

			//CipherTextWithCounterMode = CounterModeWithCipher(Key: NumberOnceTag, Data: PlainText)
			CounterMode_128_256(AllInputData, NumberOnceKey, AllOutputData);

			//ProcessedData' = OMAC(Key, CipherTextWithCounterMode)
			OMAC2_Object.Initialize(ExtraKeys);
			OMAC2_Object.Update(AllOutputData);
				
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> DataTag {};
			OMAC2_Object.Finish(DataTag);

			//AuthenticationTag = NumberOnce' XOR ProcessedData' XOR AssociativeDataData'
			for(std::uint8_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
			{
				AuthenticationTag[i] = NumberOnceTag[i] ^ DataTag[i] ^ AssociativeDataTag[i];
			}

			memory_set_no_optimize_function<0x00>(NumberOnceTag.data(), NumberOnceTag.size());
			memory_set_no_optimize_function<0x00>(AssociativeDataTag.data(), AssociativeDataTag.size());

			ProvidedData = false;
		}

		void Decryption(std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<const std::uint8_t> AuthenticationTag) override
		{
			if(!ProvidedData)
				return;

			//ProcessedData' = OMAC(Key, CipherTextWithCounterMode)
			OMAC2 OMAC2_Object;

			std::array<std::uint8_t, BlockCipher128_256::KeyBlockByteSize> NumberOnceKey {};
			std::vector<std::uint8_t> SubKey1(BlockCipher128_256::DataBlockByteSize, 0);
			std::vector<std::uint8_t> SubKey2(BlockCipher128_256::DataBlockByteSize, 0);
			OMAC2_Object.Generate_Subkey128Bit(NumberOnceTag, SubKey1, SubKey2);
			::memcpy(NumberOnceKey.data(), SubKey1.data(), SubKey1.size());
			::memcpy(NumberOnceKey.data() + SubKey1.size(), SubKey2.data(), SubKey2.size());

			OMAC2_Object.Initialize(ExtraKeys);
			OMAC2_Object.Update(AllInputData);
				
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> DataTag {};
			OMAC2_Object.Finish(DataTag);

			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ThisAuthenticationTag {};
			//AuthenticationTag = NumberOnce' XOR ProcessedData' XOR AdditionalHeaderData'
			for(std::uint8_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
			{
				ThisAuthenticationTag[i] = NumberOnceTag[i] ^ DataTag[i] ^ AssociativeDataTag[i];
			}

			ProvidedData = false;

			if(std::ranges::equal(ThisAuthenticationTag.begin(), ThisAuthenticationTag.end(), AuthenticationTag.begin(), AuthenticationTag.end()))
			{
				//PlainText = CounterModeWithCipher(Key: NumberOnceTag, Data: CipherTextWithCounterMode)
				CounterMode_128_256(AllInputData, NumberOnceKey, AllOutputData);
			}
			else
				my_cpp2020_assert(false, "The Encrypt then authenticate then translate Mode: This ciphertext has been tampered with! The tag calculation and comparison are inconsistent. Please discard the ciphertext immediately!", std::source_location::current());
		
			memory_set_no_optimize_function<0x00>(NumberOnceTag.data(), NumberOnceTag.size());
			memory_set_no_optimize_function<0x00>(AssociativeDataTag.data(), AssociativeDataTag.size());
		}

		EAX() = default;
		virtual ~EAX() = default;
	};

	class SIV : public DependentType
	{
		
	private:
		CommonSecurity::AES::DataWorker256 AES_128_256;

		std::span<const std::uint8_t> KeysPart1;
		std::span<const std::uint8_t> KeysPart2;
		std::vector<std::uint8_t> AssociativeData = std::vector<std::uint8_t>();

		bool ProvidedData = false;

		/*
			https://datatracker.ietf.org/doc/rfc5297/
			The S2V operation consists of the doubling and xoring of the outputs of a pseudo random function, CMAC, operating over individual strings in the input vector: S1, S2, ..., Sn.  
			It is bootstrapped by performing CMAC on a 128-bit string of zeros.
			1.If the length of the final string in the vector is greater than or equal to 128 bits, the output of the double/xor chain is xored onto the end of the final input string.  
			That result is input to a final CMAC operation to produce the output V.
			2.If the length of the final string is less than 128 bits, the output of the double/xor chain is doubled once more and it is xored with the final string padded using the padding function pad(X).  
			That result is input to a final CMAC operation to produce the output V.
			
			//The n is data block count, The size of one data block is 128 bits, which is 16 bytes.
			//length(A): returns the number of bits in A.

			S2V(K, AD[1], ..., AD[n]) {
				if n = 0 then
					return V = AES-CMAC(K, <one>)
				fi
				DATA_BLOCK = AES-CMAC(K, <zero>)
				for i = 1 to n-1 do
					DATA_BLOCK = doubling(DATA_BLOCK) xor AES-CMAC(K, AD[i])
				done
				if length(AD[n]) >= 128 then
					T = AD[n] xorend DATA_BLOCK
				else
					T = doubling(DATA_BLOCK) xor pad(AD[n])
				fi
				return V = AES-CMAC(K, T)
			}
		*/
		void BinaryStringToVector(std::span<const std::uint8_t>& Keys, std::vector<std::uint8_t>& AssociativeData, std::span<std::uint8_t> SyntheticInitializationVector) 
		{
			CMAC CMAC_Object;

			if(AssociativeData.empty())
			{
				//return V = AES-CMAC(K, <one>)
				const std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> OneData {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
				CMAC_Object.Initialize(Keys);
				CMAC_Object.Update(OneData);
				CMAC_Object.Finish(SyntheticInitializationVector);
				return;
			}

			//DATA_BLOCK = AES-CMAC(K, <zero>)
			const std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ZeroData {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> TemporaryData {};
			CMAC_Object.Initialize(Keys);
			CMAC_Object.Update(ZeroData);
			CMAC_Object.Finish(TemporaryData);

			constexpr std::uint8_t BitMask = 0x80;

			//For doubling used constant
			constexpr std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> DoublingConstantData
			{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
			};

			//For each doubling result
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> GF_Multiplied {};

			//Find n-1 block offset
			std::size_t EndOffsetIndex = 0;
			if ((AssociativeData.size() % BlockCipher128_256::DataBlockByteSize) != 0)
			{
				std::size_t NumberBlocks = AssociativeData.size() / BlockCipher128_256::DataBlockByteSize;
				EndOffsetIndex = NumberBlocks * BlockCipher128_256::DataBlockByteSize;
			}
			else
			{
				EndOffsetIndex = AssociativeData.size() - BlockCipher128_256::DataBlockByteSize;
			}

			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> DataBlock {};
			for(std::size_t OffsetIndex = 0; OffsetIndex < EndOffsetIndex; OffsetIndex += BlockCipher128_256::DataBlockByteSize)
			{
				CMAC_Object.Initialize(Keys);
				CMAC_Object.Update({AssociativeData.begin() + OffsetIndex, AssociativeData.begin() + OffsetIndex + BlockCipher128_256::DataBlockByteSize});
				CMAC_Object.Finish(DataBlock);

				//DATA_BLOCK' = doubling(DATA_BLOCK)
				//for(std::size_t Index = 0; Index < BlockCipher128_256::DataBlockByteSize; ++Index)
				{
					// K1 = L GF_Multiply{GF_{2^n}} K0
					if ((TemporaryData[0] & BitMask) == 0)
					{
						// If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
						LeftShift_OneBit(BlockCipher128_256::DataBlockByteSize, TemporaryData, GF_Multiplied);
					}
					else
					{
						// Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.
						LeftShift_OneBit(BlockCipher128_256::DataBlockByteSize, TemporaryData, GF_Multiplied);

						GF_Multiplied[BlockCipher128_256::DataBlockByteSize - 1] ^= DoublingConstantData[BlockCipher128_256::DataBlockByteSize - 1];
					}

					::memcpy(TemporaryData.data(), GF_Multiplied.data(), BlockCipher128_256::DataBlockByteSize);
				}

				//DATA_BLOCK = DATA_BLOCK' xor AES-CMAC(K, AD[i])
				for(std::size_t Index = 0; Index < BlockCipher128_256::DataBlockByteSize; ++Index)
				{
					TemporaryData[Index] ^= DataBlock[Index];
				}
			}

			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> TemporaryData2 {};

			//Check if the last block is complete or not (128-bits)
			std::size_t LastBlockSize = AssociativeData.size() - EndOffsetIndex;
			if ( LastBlockSize >= BlockCipher128_256::DataBlockByteSize )
			{
				//T = AD[n] xorend DATA_BLOCK
				for (std::size_t Index = 0; Index < BlockCipher128_256::DataBlockByteSize; ++Index)
				{
					TemporaryData2[Index] = AssociativeData[EndOffsetIndex + Index] ^ TemporaryData[Index];
				}
			}
			else
			{
				//DATA_BLOCK' = doubling(DATA_BLOCK)
				//for(std::size_t Index = 0; Index < BlockCipher128_256::DataBlockByteSize; ++Index)
				{
					// K1 = L GF_Multiply{GF_{2^n}} K0
					if ((TemporaryData[0] & BitMask) == 0)
					{
						// If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
						LeftShift_OneBit(BlockCipher128_256::DataBlockByteSize, TemporaryData, GF_Multiplied);
					}
					else
					{
						// Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.
						LeftShift_OneBit(BlockCipher128_256::DataBlockByteSize, TemporaryData, GF_Multiplied);

						GF_Multiplied[BlockCipher128_256::DataBlockByteSize - 1] ^= DoublingConstantData[BlockCipher128_256::DataBlockByteSize - 1];
					}

					::memcpy(TemporaryData.data(), GF_Multiplied.data(), BlockCipher128_256::DataBlockByteSize);
				}

				//pad(AD[n])
				for(std::size_t Index = 0; BlockCipher128_256::DataBlockByteSize - LastBlockSize; ++Index)
				{
					if(Index == 0)
						AssociativeData.push_back(0x80);
					else
						AssociativeData.push_back(0x00);
				}

				//T = doubling(DATA_BLOCK) xor pad(AD[n])
				for(std::size_t Index = 0; Index < BlockCipher128_256::DataBlockByteSize; ++Index)
				{
					TemporaryData2[Index] = TemporaryData[Index] ^ AssociativeData[EndOffsetIndex];
					++EndOffsetIndex;
				}
			}

			//return V = AES-CMAC(K, T)
			CMAC_Object.Initialize(Keys);
			CMAC_Object.Update(TemporaryData2);
			CMAC_Object.Finish(SyntheticInitializationVector);
		}

		std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> Q_Block {};
		void CounterMode_128_256(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			if((BytesKey.size() % BlockCipher128_256::KeyBlockByteSize != 0) && (!BytesKey.empty()))
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			auto UniformInteger_Pointer = std::make_unique<CommonSecurity::RND::UniformIntegerDistribution<std::uint64_t>>
			(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());
			auto& UniformInteger = *UniformInteger_Pointer;
			
			//Seed, Seed2 = BytesView(Key)
			//NumberOnce = UniformInteger(PRNG)
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			//This algorithm comes from RC4+
			//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
			CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG((PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5));

			std::span<std::uint8_t> OriginalCounterBlock{Q_Block.begin(), Q_Block.end()};
			std::uint64_t NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(OriginalCounterBlock.subspan(0, 8));
			std::uint64_t CounterPart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(OriginalCounterBlock.subspan(8, 8));
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> KeyStream {};

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += BlockCipher128_256::DataBlockByteSize)
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, BlockCipher128_256::KeyBlockByteSize);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(BlockCipher128_256::DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(BlockCipher128_256::DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				AES_128_256.KeyExpansion(KeyBlock);
				AES_128_256.ProcessBlockEncryption(CounterBlock, KeyStream);
					
				for(std::size_t Index = 0; Index < InputDataBlock.size(); ++Index)
				{
					OutputDataBlock[Index] = KeyStream[Index] ^ InputDataBlock[Index];
				}

				if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0)
				{
					++SanityCounterLow;
				}
				else if(SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0)
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					//Change number once value is uniform random integer
					NumberOncePart = UniformInteger(PRNG);
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += BlockCipher128_256::KeyBlockByteSize;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}

			UniformInteger_Pointer.reset();
		}

	public:
		/*
			K1 = leftmost(K, len(K)/2)
			K2 = rightmost(K, len(K)/2)
		*/
		void Initialize
		(
			std::span<const std::uint8_t> Keys,
			std::span<const std::uint8_t> ThisAssociativeData
		)
		{
			//SIV - Synthetic Initialization Vector Mode
			
			this->KeysPart1 = Keys.subspan(0, Keys.size() / 2);
			this->KeysPart2 = Keys.subspan(Keys.size() / 2, Keys.size() / 2);
			
			memory_set_no_optimize_function<0x00>(AssociativeData.data(), AssociativeData.size());
			this->AssociativeData.clear();
			this->AssociativeData = std::vector<std::uint8_t> {ThisAssociativeData.begin(), ThisAssociativeData.end()};

			this->ProvidedData = true;
		}

		/*
			SIV-ENCRYPT(K, P, AD1, ..., ADn) {
				V = S2V(K1, AD[1], ..., AD[n], P)
				Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31) //FFFFFFFFFFFFFFFF 7FFFFFFF7FFFFFFF
				m = (length(P) + 127)/128

				for i = 0 to m-1 do
					X[i] = CTR(K2, Q[i])
				done
				X = leftmost(X0 || ... || X[m-1], length(P))
				C = P xor X

				return V Concatenation C
			}
		*/
		void Encryption(std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<std::uint8_t> AuthenticationTag) override
		{
			if(!ProvidedData)
				return;
			
			//The V_Block is the synthetic initialization vector (AuthenticationTag)
			this->BinaryStringToVector(KeysPart1, AssociativeData, AuthenticationTag);

			//11111111111111111111111111111111 11111111111111111111111111111111 01111111111111111111111111111111 01111111111111111111111111111111
			//FFFFFFFF FFFFFFFF 7FFFFFFF 7FFFFFFF
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ConstantValue
			{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,0xFF};

			//Q = V bitand ConstantValue
			for(std::size_t Index = 0; Index < BlockCipher128_256::DataBlockByteSize; ++Index)
			{
				Q_Block[Index] = AuthenticationTag[Index] & ConstantValue[Index];
			}

			//The X_Block is the long key stream and the method used to generate this data is the counter mode of the block cipher.
			std::vector<std::uint8_t> X_Block (AllInputData.size(), 0); //TODO: Is there a better way than copying the data?

			CounterMode_128_256(X_Block, KeysPart2, X_Block);

			//C = P xor X
			for(std::size_t Index = 0; Index < X_Block.size(); ++Index)
			{
				AllOutputData[Index] = AllInputData[Index] ^ X_Block[Index];
			}
			
			ProvidedData = false;

			memory_set_no_optimize_function<0x00>(AssociativeData.data(), AssociativeData.size());
		}

		/*
			SIV-DECRYPT(K, Z, AD[1], ..., AD[n]) {
				V = leftmost(Z, 128)
				C = rightmost(Z, len(Z)-128)
				
				Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31) //FFFFFFFFFFFFFFFF 7FFFFFFF7FFFFFFF

				m = (length(C) + 127)/128
				for i = 0 to m-1 do
					Xi = CTR(K2, Q[i])
				done
				X = leftmost(X[0] || ... || X[m-1], length(C))
				P = C xor X
				T = S2V(K1, AD[1], ..., AD[n], P)

				if T = V then
					return P
				else
					return error
				fi
			}
		*/
		void Decryption(std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<const std::uint8_t> AuthenticationTag) override
		{
			if(!ProvidedData)
				return;
			
			//11111111111111111111111111111111 11111111111111111111111111111111 01111111111111111111111111111111 01111111111111111111111111111111
			//FFFFFFFF FFFFFFFF 7FFFFFFF 7FFFFFFF
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ConstantValue
			{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,0xFF};

			//Q = V bitand ConstantValue
			for(std::size_t Index = 0; Index < BlockCipher128_256::DataBlockByteSize; ++Index)
			{
				Q_Block[Index] = AuthenticationTag[Index] & ConstantValue[Index];
			}

			//The X_Block is the long key stream and the method used to generate this data is the counter mode of the block cipher.
			std::vector<std::uint8_t> X_Block (AllInputData.size(), 0); //TODO: Is there a better way than copying the data?

			CounterMode_128_256(X_Block, KeysPart2, X_Block);

			//P = C xor X
			for(std::size_t Index = 0; Index < X_Block.size(); ++Index)
			{
				AllOutputData[Index] = AllInputData[Index] ^ X_Block[Index];
			}

			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ThisAuthenticationTag {};
			//The V_Block is the synthetic initialization vector (AuthenticationTag)
			this->BinaryStringToVector(KeysPart1, AssociativeData, ThisAuthenticationTag);

			ProvidedData = false;

			memory_set_no_optimize_function<0x00>(AssociativeData.data(), AssociativeData.size());

			if( !std::ranges::equal(ThisAuthenticationTag.begin(), ThisAuthenticationTag.end(), AuthenticationTag.begin(), AuthenticationTag.end()) )
				my_cpp2020_assert(false, "AEAD Synthetic initialization vector mode: This ciphertext has been tampered with! The AuthenticationTag calculation and comparison are inconsistent. Please discard the ciphertext immediately!", std::source_location::current());
		}

		SIV() = default;
		virtual ~SIV() = default;
	};

	class OCB : public DependentType
	{

	private:
		CommonSecurity::AES::DataWorker256 AES_128_256;

		std::span<const std::uint8_t> AssociativeData;
		std::span<const std::uint8_t> KeyStream;

		static constexpr std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ZeroDataBlock {};
		std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> L_Word {};
		std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> DoubleL_Word {};

		std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> OffsetDeltaData {};
		std::uint64_t Data128BitBlockCountFromAssociativeData = 0;

		bool ProvidedData = true;

		void DouableTransform(std::span<uint32_t> Output, std::span<const uint32_t> Input)
		{
			// Definition of the function:
			// double(S)	= S << 1   if the MSB bit of Input is 0,
			//				= (S << 1) xor 135	otherwise

			std::uint8_t TemporaryByte = (Input[3] & 0x80000000) == 0 ? 0 : 1;

			Output[3] = (Input[3] << 1) | ((Input[2] & 0x80000000) == 0 ? 0 : 1);
			Output[2] = (Input[2] << 1) | ((Input[1] & 0x80000000) == 0 ? 0 : 1);
			Output[1] = (Input[1] << 1) | ((Input[0] & 0x80000000) == 0 ? 0 : 1);
			Output[0] = (Input[0] << 1);

			if (TemporaryByte)
				Output[0] = Output[0] ^ 0x87;
		}

		void Calculate_L(std::span<uint32_t> L, std::span<const uint32_t> L_Dollar, uint8_t Index)
		{
			DouableTransform(L, L_Dollar);
			while ((Index & 0x01) == 0)
			{
				DouableTransform(L, L);
				Index >>= 1;
				if(Index == 0)
					break;
			}
		}

		//∆ Delta Differential Data
		//https://datatracker.ietf.org/doc/html/rfc7253
		//https://www.cs.ucdavis.edu/~rogaway/papers/ae.pdf
		//https://web.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm#versions
		std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> GenerateOffsetDataBlock(std::span<const std::uint8_t> NumberOnceByte)
		{
			//Block size is 128 bit
			//N is selected as 96 bit
			//96 = 1100000
			//Nonce = zeros(127 − abs(N)) concat binarystring(1) concat binarystring(N)
			//Top = Nonce bitand ( ones(122) concat zeros(6) )
			//Bottom = Nonce bitand ( zeros(122) concat ones(6) )

			/*
				TOP DEPENPENDENT VARIABLES
			*/
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> Top {};
			auto NumberOnce = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(NumberOnceByte.data(), 96 / 8 / sizeof(std::uint8_t));

			// Top = 0x00000001 | N (last 6 bits of N is zero)
			// Calculate Top
			Top[3] = 0x0000001;
			Top[2] = NumberOnce[2];
			Top[1] = NumberOnce[1];
			Top[0] = NumberOnce[0] & 0xFFFFFFC0;

			// Bottom = LSB(Nonce[0...31])
			// Calculate Bottom
			std::uint32_t BottomValue = NumberOnce[0] & 0x0000003F;
			
			// K_top = ENCIPHER(K, Top)
			// Calculate K_top
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> KeyedTop {};
			auto TopBytes = CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(Top.data(), Top.size());
			auto KeyedTopBytes = CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(KeyedTop.data(), KeyedTop.size());
			AES_128_256.EncryptionWithECB(TopBytes, KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize, BlockCipher128_256::KeyBlockByteSize), KeyedTopBytes); //Use Key2
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(KeyedTopBytes, KeyedTop.data());

			// Stretch = K_top | (K_top xor (K_top <<< 8))
			// Calculate Stretch
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t) * 2> Stretch {};
			Stretch[7] = KeyedTop[3];
			Stretch[6] = KeyedTop[2];
			Stretch[5] = KeyedTop[1];
			Stretch[4] = KeyedTop[0];
			Stretch[3] = KeyedTop[3] ^ (KeyedTop[3] << 8 | KeyedTop[2] >> 24);
			Stretch[2] = KeyedTop[2] ^ (KeyedTop[2] << 8 | KeyedTop[1] >> 24);
			Stretch[1] = KeyedTop[1] ^ (KeyedTop[1] << 8 | KeyedTop[0] >> 24);
			Stretch[0] = KeyedTop[0] ^ (KeyedTop[0] << 8);

			// Calculate delta = InitializeOffsetDelta(N)
			// The initial value for delta, is the first 128 bits of Stretch <<< Bottom	
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> OffsetDeltaData {};
			if (BottomValue != 0)
				for (std::uint32_t i = 7; i > 3; i--)
					OffsetDeltaData[i - 4] = (Stretch[i] << BottomValue) | (Stretch[i - 1] >> (32 - BottomValue));
			else
				for (std::uint32_t i = 7; i > 3; i--)
					OffsetDeltaData[i - 4] = Stretch[i];

			return OffsetDeltaData;
		}

	public:
		void Initialize
		(
			std::span<const std::uint8_t> Keys,
			std::span<const std::uint8_t> AssociativeData,
			std::span<const std::uint8_t> NumberOnce
		)
		{
			this->KeyStream = Keys;
			this->AssociativeData = AssociativeData;
			this->Data128BitBlockCountFromAssociativeData = AssociativeData.size() / BlockCipher128_256::DataBlockByteSize;
			
			//OCB - Offset CodeBlock Mode

			/*
				KEY DEPENPENDENT VARIABLES
			*/

			// L_* = ENCIPHER(K, zeros(128))
			// Calculate L_star = ENCIPHER(K, 0^128)
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> L {};
			AES_128_256.EncryptionWithECB(ZeroDataBlock, KeyStream.subspan(0, BlockCipher128_256::KeyBlockByteSize), L); //Use Key1

			// L_$ = double(L_*)
			// Calculate L_dollar = DOUABLE_TRRANSFORM(L_star)
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(L, L_Word.data());
			DouableTransform(DoubleL_Word, L_Word);

			this->OffsetDeltaData = this->GenerateOffsetDataBlock(NumberOnce);

			this->ProvidedData = true;
		}

		//https://datatracker.ietf.org/doc/html/rfc7253
		//https://www.cs.ucdavis.edu/~rogaway/papers/ae.pdf
		//https://web.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm
		//https://github.com/furkanturan/Encrypted-Communication-with-OCB-AES-and-X.1035/blob/master/OCB.c
		std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> Auth()
		{
			if(!ProvidedData)
				my_cpp2020_assert(false, "", std::source_location::current());

			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> Temporary {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> TemporaryBytes {};

			// Initialise checksum to 0
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> Checksum {};
			
			// Initialise delta to 0 
			// Different than encryption case, initial value of delta is 0 in auth calculation
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> OffsetDeltaData {};

			auto AssociativeDataWord = CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(this->AssociativeData.data(), this->AssociativeData.size());
			std::span<std::uint32_t> AssociativeDataWordSpan {AssociativeDataWord.begin(), AssociativeDataWord.end()};

			for (std::size_t BlockIndex = 1; BlockIndex <= this->Data128BitBlockCountFromAssociativeData; BlockIndex++)
			{
				std::span<std::uint32_t> AssociativeDataWordSubSpan = AssociativeDataWordSpan.subspan(BlockIndex, 4);

				// Offset = Offset xor Double(L_$)
				// Increment Delta
				Calculate_L(Temporary, DoubleL_Word, std::countr_zero(BlockIndex)); //std::countr_zero is equal ntz(i)
				for (std::uint32_t i = 0; i < 4; i++)
					OffsetDeltaData[i] ^= Temporary[i];

				// T = Offset xor Asssoc
				// Xor delta with associateddata
				for (std::uint32_t i = 0; i < 4; i++)
					Temporary[i] = OffsetDeltaData[i] ^ AssociativeDataWordSubSpan[i];

				// T' = ENCIPHER(K, T)
				// Encrypt Temporary
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(Temporary, TemporaryBytes.data());
				AES_128_256.EncryptionWithECB(TemporaryBytes, KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize * 3, BlockCipher128_256::KeyBlockByteSize), TemporaryBytes); //Use Key4
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(TemporaryBytes, Temporary.data());

				// Checksum = Checksum xor T'
				// Xor encryption output and delta,
				// Accumulate result as authenticationdata
				for (std::uint32_t i = 0; i < 4; i++)
					Checksum[i] ^= Temporary[i];
			}

			return Checksum;
		}

	public:

		void Encryption(std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<std::uint8_t> AuthenticationTag) override
		{
			if(!ProvidedData)
				return;

			/*
				Process any whole blocks
			*/
			
			// Initialise checksum to 0
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> HashValues {};

			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> Temporary {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> TemporaryBytes {};

			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> PlainTextBuffer {};
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> CipherTextBuffer {};

			std::uint64_t ByteOffset = 0;
			std::uint64_t BlockIndex = 0;

			for (BlockIndex = 1; BlockIndex <= AllInputData.size() / BlockCipher128_256::DataBlockByteSize; BlockIndex++)
			{
				auto PlainTextBlock = AllInputData.subspan(ByteOffset, BlockCipher128_256::DataBlockByteSize);
				auto CipherTextBlock = AllOutputData.subspan(ByteOffset, BlockCipher128_256::DataBlockByteSize);

				// Offset = Offset xor Double(L_$, ntz( BlockIndex ))
				// Increment Delta
				Calculate_L(Temporary, DoubleL_Word, std::countr_zero(BlockIndex)); //std::countr_zero is equal ntz(i)
				for (std::uint32_t i = 0; i < 4; i++)
					OffsetDeltaData[i] ^= Temporary[i];

				/*
					Encryption Mode:
					The i is block index and one block size is 16 byte
					CipherText_i = Offset_i xor ENCIPHER(K, PlainText_i xor Offset_i)
				*/

				// T = Offset xor PlainText
				// Xor delta with plain text
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(PlainTextBlock, PlainTextBuffer.data());
				for (std::uint32_t i = 0; i < 4; i++)
					Temporary[i] = OffsetDeltaData[i] ^ PlainTextBuffer[i];

				// T' = ENCIPHER(K, T)
				// Encrypt Temporary
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(Temporary, TemporaryBytes.data());
				AES_128_256.EncryptionWithECB(TemporaryBytes, KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize * 2, BlockCipher128_256::KeyBlockByteSize), TemporaryBytes); //Use Key3
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(TemporaryBytes, Temporary.data());

				// CipherText = Offset xor T'
				//Xor encryption output and delta, output is one 128 bit (16 byte) cypther text block
				for (std::uint32_t i = 0; i < 4; i++)
					CipherTextBuffer[i] = OffsetDeltaData[i] ^ Temporary[i];
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(CipherTextBuffer, CipherTextBlock.data());

				// Calculate Checksum = M1 xor ... xor Mm in each iteration
				for (std::uint32_t i = 0; i < 4; i++)
					HashValues[i] ^= PlainTextBuffer[i];

				ByteOffset += BlockCipher128_256::DataBlockByteSize;
			}

			/*
				Process any final partial block and compute raw tag
			*/

			//Check if the last block is complete or not (128-bits)
			if(AllInputData.size() % BlockCipher128_256::DataBlockByteSize != 0)
			{
				//The size of the last incomplete byte block.
				std::uint64_t LastBlockSize = AllInputData.size() % BlockCipher128_256::DataBlockByteSize;

				// Offset = Offset xor Double(L_$, BlockIndex)
				// Increment Delta
				Calculate_L(Temporary, DoubleL_Word, BlockIndex);
				for (std::uint32_t i = 0; i < 4; i++)
					OffsetDeltaData[i] ^= Temporary[i];

				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> OffsetDeltaDataBytes {};
				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> PadDataBytes {};
				std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> PadData {};
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(OffsetDeltaData, OffsetDeltaDataBytes.data());
				// Calculate Pad = ENCIPHER(K, Delta)
				AES_128_256.EncryptionWithECB(OffsetDeltaDataBytes, KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize * 2, BlockCipher128_256::KeyBlockByteSize), PadDataBytes); //Use Key3
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(PadDataBytes, PadData.data());

				/*
					Encryption Mode:
				*/

				// Pad 10*'s to remaining data bytes
				// 10* means; append a single 1 - bit and then the minimum number of 0 - bits to get the string to be 128 bits
				for (std::uint32_t i = 0; i < BlockCipher128_256::DataBlockByteSize; i++)
				{
					if (i < LastBlockSize)
						TemporaryBytes[BlockCipher128_256::DataBlockByteSize - 1 - i] = AllInputData[AllInputData.size() - LastBlockSize + i];
					else if (i == LastBlockSize)
						TemporaryBytes[BlockCipher128_256::DataBlockByteSize - 1 - i] = 0x80;
					else
						TemporaryBytes[BlockCipher128_256::DataBlockByteSize - 1 - i] = 0x00;
				}

				// Xor pad and padded message
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(TemporaryBytes, Temporary.data());
				for (std::uint32_t i = 0; i < 4; i++)
					PadData[i] ^= Temporary[i];

				// Store entire encrypted last block (not just padded part) to output
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(PadData, PadDataBytes.data());
				for (std::uint32_t j = 0; j < LastBlockSize; j++)
				{
					AllOutputData[AllOutputData.size() - LastBlockSize + j] = PadDataBytes[BlockCipher128_256::DataBlockByteSize - 1 - j];
				}

				// Update Checksum
				for (std::uint32_t i = 0; i < 4; i++)
					HashValues[i] ^= Temporary[i];
			}

			// Offset = Offset xor Double(L_$, BlockIndex)
			// Increment Delta
			Calculate_L(Temporary, DoubleL_Word, BlockIndex);
			for (std::uint32_t i = 0; i < 4; i++)
				OffsetDeltaData[i] ^= Temporary[i];

			//Final = ENCIPHER(K, Checksum xor Offset)
			for (std::uint32_t i = 0; i < 4; i++)
				Temporary[i] = HashValues[i] ^ OffsetDeltaData[i];
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> ThisAuthenticationTag {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> TagBytes {};
			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(Temporary, TagBytes.data());
			AES_128_256.EncryptionWithECB(TagBytes, KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize * 2, BlockCipher128_256::KeyBlockByteSize), TagBytes); //Use Key3
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(TagBytes, ThisAuthenticationTag.data());

			//Auth = Hash(K, A)
			//Tag = Auth xor Final
			Temporary = this->Auth();
			for (std::uint32_t i = 0; i < 4; i++)
				ThisAuthenticationTag[i] ^= Temporary[i];

			ProvidedData = false;

			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(ThisAuthenticationTag, AuthenticationTag.data());
		}

		void Decryption(std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<const std::uint8_t> AuthenticationTag) override
		{
			if(!ProvidedData)
				return;

			/*
				Process any whole blocks
			*/
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> HashValues {};

			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> Temporary {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> TemporaryBytes {};

			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> PlainTextBuffer {};
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> CipherTextBuffer {};

			std::uint64_t ByteOffset = 0;
			std::uint64_t BlockIndex = 0;

			for (BlockIndex = 1; BlockIndex <= AllInputData.size() / BlockCipher128_256::DataBlockByteSize; BlockIndex++)
			{
				auto CipherTextBlock = AllInputData.subspan(ByteOffset, BlockCipher128_256::DataBlockByteSize);
				auto PlainTextBlock = AllOutputData.subspan(ByteOffset, BlockCipher128_256::DataBlockByteSize);

				// Offset = Offset xor Double(L_$, ntz( BlockIndex ))
				// Increment Delta
				Calculate_L(Temporary, DoubleL_Word, std::countr_zero(BlockIndex)); //std::countr_zero is equal ntz(i)
				for (std::uint32_t i = 0; i < 4; i++)
					OffsetDeltaData[i] ^= Temporary[i];

				/*
					Decryption Mode:
					The i is block index and one block size is 16 byte
					PlainText_i = Offset_i xor DECIPHER(K, CipherText_i xor Offset_i)
				*/

				// T = Offset xor CipherText
				// Xor delta with cipher text
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(CipherTextBlock, CipherTextBuffer.data());
				for (std::uint32_t i = 0; i < 4; i++)
					Temporary[i] = OffsetDeltaData[i] ^ CipherTextBuffer[i];

				// T' = DECIPHER(K, T)
				// Decrypt Temporary
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(Temporary, TemporaryBytes.data());
				AES_128_256.DecryptionWithECB(TemporaryBytes, KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize * 2, BlockCipher128_256::KeyBlockByteSize), TemporaryBytes); //Use Key3
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(TemporaryBytes, Temporary.data());

				// PlainText = Offset xor T'
				//Xor encryption output and delta, output is one 128 bit (16 byte) cypther text block
				for (std::uint32_t i = 0; i < 4; i++)
					PlainTextBuffer[i] = OffsetDeltaData[i] ^ Temporary[i];
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(PlainTextBuffer, PlainTextBlock.data());

				// Calculate Checksum = M1 xor ... xor Mm in each iteration
				for (std::uint32_t i = 0; i < 4; i++)
					HashValues[i] ^= PlainTextBuffer[i];

				ByteOffset += BlockCipher128_256::DataBlockByteSize;
			}

			/*
				Process any final partial block and compute raw tag
			*/

			//Check if the last block is complete or not (128-bits)
			if(AllInputData.size() % BlockCipher128_256::DataBlockByteSize != 0)
			{
				//The size of the last incomplete byte block.
				std::uint64_t LastBlockSize = AllInputData.size() % BlockCipher128_256::DataBlockByteSize;
				
				// Offset = Offset xor Double(L_$, BlockIndex)
				// Increment Delta
				Calculate_L(Temporary, DoubleL_Word, BlockIndex);
				for (std::uint32_t i = 0; i < 4; i++)
					OffsetDeltaData[i] ^= Temporary[i];

				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> OffsetDeltaDataBytes {};
				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> PadDataBytes {};
				std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> PadData {};
				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(OffsetDeltaData, OffsetDeltaDataBytes.data());
				// Calculate Pad = ENCIPHER(K, Delta)
				AES_128_256.EncryptionWithECB(OffsetDeltaDataBytes, KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize * 2, BlockCipher128_256::KeyBlockByteSize), PadDataBytes); //Use Key3
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(PadDataBytes, PadData.data());

				/*
					Decryption Mode:
				*/

				// Read remaining bytes from plaintext, and place them to the MSB's of temporary Pad zero's to remaining bytes of the block
				for (std::uint32_t i = 0; i < BlockCipher128_256::DataBlockByteSize; i++)
				{
					if (i < LastBlockSize)
						TemporaryBytes[BlockCipher128_256::DataBlockByteSize - 1 - i] = AllInputData[AllInputData.size() - LastBlockSize + i];
					else
						TemporaryBytes[BlockCipher128_256::DataBlockByteSize - 1 - i] = 0x00;
				}

				// Xor pad and padded message
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(TemporaryBytes, Temporary.data());
				for (std::uint32_t i = 0; i < 4; i++)
					PadData[i] ^= Temporary[i];

				CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(PadData, PadDataBytes.data());
				for (std::uint32_t j = 0; j < BlockCipher128_256::DataBlockByteSize; j++)
				{
					if (j < LastBlockSize)
					{
						// Store only data (not padded) part of encrypted message to output
						AllOutputData[AllOutputData.size() - LastBlockSize + j] = PadDataBytes[BlockCipher128_256::DataBlockByteSize - 1 - j];
						// Update offset one block (will be used in validation)
					}
					// Remaining part should be 10* padded again so that checksum will match
					else if (j == LastBlockSize)
						PadDataBytes[BlockCipher128_256::DataBlockByteSize - 1 - j] = 0x80;
					else
						PadDataBytes[BlockCipher128_256::DataBlockByteSize - 1 - j] = 0x00;
				}

				// Update Checksum
				CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(PadDataBytes, PadData.data());
				for (std::uint32_t i = 0; i < 4; i++)
					HashValues[i] ^= PadData[i];
			}

			// Offset = Offset xor Double(L_$, BlockIndex)
			// Increment Delta
			Calculate_L(Temporary, DoubleL_Word, BlockIndex);
			for (std::uint32_t i = 0; i < 4; i++)
				OffsetDeltaData[i] ^= Temporary[i];

			//Final = ENCIPHER(K, Checksum xor Offset)
			for (std::uint32_t i = 0; i < 4; i++)
				Temporary[i] = HashValues[i] ^ OffsetDeltaData[i];
			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> ThisAuthenticationTag {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> TagBytes {};
			CommonToolkit::MessageUnpacking<std::uint32_t, std::uint8_t>(Temporary, TagBytes.data());
			AES_128_256.EncryptionWithECB(TagBytes, KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize * 2, BlockCipher128_256::KeyBlockByteSize), TagBytes); // Key3
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(TagBytes, ThisAuthenticationTag.data());

			//Auth = Hash(K, A)
			//Tag = Auth xor Final
			Temporary = this->Auth();
			for (std::uint32_t i = 0; i < 4; i++)
				ThisAuthenticationTag[i] ^= Temporary[i];

			ProvidedData = false;

			std::array<std::uint32_t, BlockCipher128_256::DataBlockByteSize / sizeof(std::uint32_t)> AuthenticationTagWords {};
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(AuthenticationTag, AuthenticationTagWords.data());

			if( !std::ranges::equal(ThisAuthenticationTag.begin(), ThisAuthenticationTag.end(), AuthenticationTagWords.begin(), AuthenticationTagWords.end()) )
				my_cpp2020_assert(false, "AEAD Offset code block mode: This ciphertext has been tampered with! The AuthenticationTag calculation and comparison are inconsistent. Please discard the ciphertext immediately!", std::source_location::current());
		}

		OCB() = default;
		virtual ~OCB() = default;
	};

	struct ApplyDependentType
	{
	private:
		std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> AuthenticationTag {};

	public:
		std::unique_ptr<BlockCipherMode::EAX> EAX_Mode_Instance
		(
			std::span<const std::uint8_t> AssociativeData,
			std::span<const std::uint8_t> KeyStream,
			std::span<const std::uint8_t> NumberOnce
		)
		{
			auto EAX_Pointer = std::make_unique<BlockCipherMode::EAX>();

			if(AssociativeData.empty())
			{
				//Seed, Seed2 = BytesView(Key1)
				//NumberOnce = UniformInteger(PRNG)
				std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

				CommonSecurity::RegenerateSeeds2(KeyStream, PRNG_Seed, PRNG_Seed2);

				//This algorithm comes from RC4+
				//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
				CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG( (PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5) );
				CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> UniformIntegerDistribution(0, 255);

				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize * 32> ThisAssociativeData {};

				auto RemainingKeyStream = KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize, KeyStream.size() - BlockCipher128_256::KeyBlockByteSize);

				if(NumberOnce.empty())
				{
					std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> NumberOnceBytes {};
					for( auto& NumberOnceByte : NumberOnceBytes )
					{
						NumberOnceByte = UniformIntegerDistribution(PRNG);
					}

					EAX_Pointer->Initialize(RemainingKeyStream, NumberOnceBytes, ThisAssociativeData);

					return EAX_Pointer;
				}

				for( auto& AssociativeDataByte : ThisAssociativeData )
				{
					AssociativeDataByte = UniformIntegerDistribution(PRNG);
				}

				EAX_Pointer->Initialize(RemainingKeyStream, NumberOnce, ThisAssociativeData);
			}
			else
			{
				EAX_Pointer->Initialize(KeyStream, NumberOnce, AssociativeData);
			}

			return EAX_Pointer;
		}

		std::unique_ptr<BlockCipherMode::SIV> SIV_Mode_Instance
		(
			std::span<const std::uint8_t> AssociativeData,
			std::span<const std::uint8_t> Keys
		)
		{
			auto SIV_Pointer = std::make_unique<BlockCipherMode::SIV>();

			if(AssociativeData.empty())
			{
				std::vector<std::uint8_t> ThisAssociativeData = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);
				SIV_Pointer->Initialize(Keys, ThisAssociativeData);
			}
			else
			{
				SIV_Pointer->Initialize(Keys, AssociativeData);
			}

			return SIV_Pointer;
		}

		std::unique_ptr<BlockCipherMode::OCB> OCB_Mode_Instance
		(
			std::span<const std::uint8_t> AssociativeData,
			std::span<const std::uint8_t> Keys,
			std::span<const std::uint8_t> NumberOnce
		)
		{
			auto OCB_Pointer = std::make_unique<BlockCipherMode::OCB>();

			if(AssociativeData.empty())
			{
				std::vector<std::uint8_t> ThisAssociativeData = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);
				OCB_Pointer->Initialize(Keys, ThisAssociativeData, NumberOnce);
			}
			else
			{
				OCB_Pointer->Initialize(Keys, AssociativeData, NumberOnce);
			}

			return OCB_Pointer;
		}
	};
}

namespace CommonSecurity::CascadedAndUnique
{
	/*
		级联安全密码器模块
		Cascade secure passcoders module / Cascade security cryptograph module
	*/

	enum class PasscoderType : std::uint32_t
	{
		AES = 0,
		TWOFISH = 1,
		SERPENT = 2,
		RC6 = 3,
		CHINA_SHANGYONGMIMA4 = 4
	};

	//CommonSecurity::ChunkedDataPadders<CommonSecurity::ChunkedDataPaddingMode::PKCS7> ChunkedDataPadManager;

	struct UniquePasscoder
	{

	public:
		virtual void Encrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) = 0;
		virtual void Decrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) = 0;

		UniquePasscoder() = default;
		virtual ~UniquePasscoder() = default;

		UniquePasscoder(const UniquePasscoder& _object ) = delete;
		UniquePasscoder& operator=(UniquePasscoder& _object ) = delete;
	};

	struct UniquePasscoderAES : public UniquePasscoder
	{
		CommonSecurity::AES::DataWorker256 aes_worker;

		void Encrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			aes_worker.CTR_StreamModeBasedEncryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		void Decrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			aes_worker.CTR_StreamModeBasedEncryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		UniquePasscoderAES() = default;
		virtual ~UniquePasscoderAES() = default;

		UniquePasscoderAES(const UniquePasscoderAES& _object ) = delete;
		UniquePasscoderAES& operator=(UniquePasscoderAES& _object ) = delete;
	};

	struct UniquePasscoderRC6 : public UniquePasscoder
	{
		CommonSecurity::RC6::DataWorker128_256 rc6_worker;

		void Encrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			rc6_worker.CTR_StreamModeBasedDecryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		void Decrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			rc6_worker.CTR_StreamModeBasedDecryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		UniquePasscoderRC6() = default;
		virtual ~UniquePasscoderRC6() = default;

		UniquePasscoderRC6(const UniquePasscoderRC6& _object ) = delete;
		UniquePasscoderRC6& operator=(UniquePasscoderRC6& _object ) = delete;
	};

	struct UniquePasscoderTwofish : public UniquePasscoder
	{
		CommonSecurity::Twofish::DataWorker256 twofish_worker;

		void Encrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			twofish_worker.CTR_StreamModeBasedEncryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		void Decrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			twofish_worker.CTR_StreamModeBasedEncryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		UniquePasscoderTwofish() = default;
		virtual ~UniquePasscoderTwofish() = default;

		UniquePasscoderTwofish(const UniquePasscoderTwofish& _object ) = delete;
		UniquePasscoderTwofish& operator=(UniquePasscoderTwofish& _object ) = delete;
	};

	struct UniquePasscoderSM4 : public UniquePasscoder
	{
		CommonSecurity::ChinaShangYongMiMa4::DataWorker256 sm4_worker;

		void Encrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			sm4_worker.CTR_StreamModeBasedDecryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		void Decrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			sm4_worker.CTR_StreamModeBasedDecryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		UniquePasscoderSM4() = default;
		virtual ~UniquePasscoderSM4() = default;

		UniquePasscoderSM4(const UniquePasscoderSM4& _object ) = delete;
		UniquePasscoderSM4& operator=(UniquePasscoderSM4& _object ) = delete;
	};

	struct UniquePasscoderSerpent : public UniquePasscoder
	{
		CommonSecurity::RC6::DataWorker128_256 serpent_worker;

		void Encrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			serpent_worker.CTR_StreamModeBasedEncryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		void Decrypt(std::span<const std::uint8_t> AllInputData, std::span<const std::uint8_t> AllKeyBlock, std::span<std::uint8_t> AllOutputData) override
		{
			serpent_worker.CTR_StreamModeBasedEncryptFunction(AllInputData, AllKeyBlock, AllOutputData);
		}

		UniquePasscoderSerpent() = default;
		virtual ~UniquePasscoderSerpent() = default;

		UniquePasscoderSerpent(const UniquePasscoderSerpent& _object ) = delete;
		UniquePasscoderSerpent& operator=(UniquePasscoderSerpent& _object ) = delete;
	};

	/*
		可选的分组算法: AES, Twofish, Rivest cipher 6，Serpent, China Shang Yong Mi Ma 4 (使用计数器模式无需额外填充数据)
		级联的加密-解密方案 配合 关联数据的认证加密解密模式
		Optional groups of algorithms: AES, Twofish, Rivest cipher 6, Serpent, China Shang Yong Mi Ma 4 (using counter mode without additional data filling)
		Cascaded encryption-decryption plan in conjunction with authenticated encryption-decryption mode for associated data
	*/
	class CompositePasscoder
	{

	private:
		friend class CommonSecurity::AEAD::BlockCipherMode::AEAD_UseCascaded;

		using WorkMode = CommonSecurity::AEAD::BlockCipherMode::WorkMode;

		/*
			For Cascade
		*/
		std::vector<PasscoderType> passcoder_sequence;
		std::vector<PasscoderType> reverse_passcoder_sequence;

		/*
			For AEAD
		*/
		CommonSecurity::AEAD::BlockCipherMode::WorkMode AuthenticatedMode = CommonSecurity::AEAD::BlockCipherMode::WorkMode::CCM;
		std::vector<std::uint8_t> AuthenticationTag {};
		std::vector<std::uint8_t> AssociativeData;
		
		UniquePasscoderAES passcoder_aes;
		UniquePasscoderTwofish passcoder_twofish;
		UniquePasscoderRC6 passcoder_rc6;
		UniquePasscoderSM4 passcoder_sm4;
		UniquePasscoderSerpent passcoder_serpent;

		//Encryption (Counter Mode) Of File Data
		void EncryptingData
		(
			std::span<const std::uint8_t> processing_file_data,
			std::deque<std::vector<std::uint8_t>>& BuildedKeyStream,
			std::span<std::uint8_t> processed_file_data
		)
		{
			constexpr auto DataBlockByteSize = CommonSecurity::BlockCipherConstant3::DataBlockByteSize;
			constexpr auto KeyBlockByteSize = CommonSecurity::BlockCipherConstant3::KeyBlockByteSize;
			
			if(processing_file_data.data() != processed_file_data.data())
				std::ranges::copy(processing_file_data.begin(), processing_file_data.end(), processed_file_data.begin());
		
			for( const auto& passcoder : this->passcoder_sequence )
			{
				switch (passcoder)
				{
					//自同步流模式(计数器块) 使用带有加密功能或解密功能的块状密码
					//Self-synchronizing stream mode (counter block) Use block cipher with encryption function or decryption function 
					case PasscoderType::AES:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_aes;

						common_passcoder_reference.Encrypt(processed_file_data, BuildedKeyStream.back(), processed_file_data);

						break;
					}
					case PasscoderType::RC6:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_rc6;

						common_passcoder_reference.Encrypt(processed_file_data, BuildedKeyStream.back(), processed_file_data);
	
						break;
					}
					case PasscoderType::TWOFISH:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_twofish;

						common_passcoder_reference.Encrypt(processed_file_data, BuildedKeyStream.back(), processed_file_data);

						break;
					}
					case PasscoderType::CHINA_SHANGYONGMIMA4:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_sm4;

						common_passcoder_reference.Encrypt(processed_file_data, BuildedKeyStream.back(), processed_file_data);

						break;
					}
					case PasscoderType::SERPENT:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_serpent;

						common_passcoder_reference.Encrypt(processed_file_data, BuildedKeyStream.back(), processed_file_data);

						break;
					}
					default:
						break;
				}

				BuildedKeyStream.pop_back();
			}
		}

		//Decryption (Counter Mode) Of File Data
		void DecryptingData
		(
			std::span<const std::uint8_t> processing_file_data,
			std::deque<std::vector<std::uint8_t>>& BuildedKeyStream,
			std::span<std::uint8_t> processed_file_data
		)
		{
			constexpr auto DataBlockByteSize = CommonSecurity::BlockCipherConstant3::DataBlockByteSize;
			constexpr auto KeyBlockByteSize = CommonSecurity::BlockCipherConstant3::KeyBlockByteSize;
			
			if(processing_file_data.data() != processed_file_data.data())
				std::ranges::copy(processing_file_data.begin(), processing_file_data.end(), processed_file_data.begin());

			for( const auto& passcoder : this->reverse_passcoder_sequence)
			{
				switch (passcoder)
				{
					//自同步流模式(计数器块) 使用带有加密功能或解密功能的块状密码
					//Self-synchronizing stream mode (counter block) Use block cipher with encryption function or decryption function 
					case PasscoderType::AES:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_aes;

						common_passcoder_reference.Decrypt(processed_file_data, BuildedKeyStream.front(), processed_file_data);

						break;
					}
					case PasscoderType::RC6:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_rc6;

						common_passcoder_reference.Decrypt(processed_file_data, BuildedKeyStream.front(), processed_file_data);

						break;
					}
					case PasscoderType::TWOFISH:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_twofish;

						common_passcoder_reference.Decrypt(processed_file_data, BuildedKeyStream.front(), processed_file_data);

						break;
					}
					case PasscoderType::CHINA_SHANGYONGMIMA4:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_sm4;

						common_passcoder_reference.Decrypt(processed_file_data, BuildedKeyStream.front(), processed_file_data);

						break;
					}
					case PasscoderType::SERPENT:
					{
						UniquePasscoder& common_passcoder_reference = passcoder_serpent;

						common_passcoder_reference.Decrypt(processed_file_data, BuildedKeyStream.front(), processed_file_data);

						break;
					}
					default:
						break;
				}

				BuildedKeyStream.pop_front();
			}
		}

	public:
		void SetTag(const std::vector<std::uint8_t>& NewAuthenticationTag)
		{
			if(this->AuthenticationTag != NewAuthenticationTag && NewAuthenticationTag.size() == BlockCipherConstant3::DataBlockByteSize)
				this->AuthenticationTag = NewAuthenticationTag;
		}

		std::vector<std::uint8_t> GetTag()
		{
			return this->AuthenticationTag;
		}

		void ChangePasscoderSequence(std::vector<PasscoderType> PasscoderTypes)
		{
			if(PasscoderTypes.empty())
				return;

			std::uint64_t Size = this->passcoder_sequence.size();
			this->passcoder_sequence = PasscoderTypes;
			std::ranges::reverse(reverse_passcoder_sequence.begin(), reverse_passcoder_sequence.end());

			if(Size != PasscoderTypes.size())
			{
				std::cout << CommonToolkit::from_u8string(u8"警告: 级联加密解密所使用的函数类型顺序已被更改。请立即更新密钥流!") << std::endl;
				std::cout << "Warning: The order of the function types used for cascade encryption and decryption has been changed. Please update the keystream immediately!" << std::endl;
			}
		}

		void ChangeAuthenticatedMode(WorkMode Mode)
		{
			if(AuthenticatedMode != Mode)
				this->AuthenticatedMode = Mode;
		}

		void ChangeAssociativeData(std::span<std::uint8_t> AssociativeData)
		{
			if(!this->AssociativeData.empty())
				::memory_set_no_optimize_function<0x00>(this->AssociativeData.data(), this->AssociativeData.size());
			this->AssociativeData.clear();
			this->AssociativeData.shrink_to_fit();
			this->AssociativeData = {AssociativeData.begin(), AssociativeData.end()};
		}

		std::deque<std::vector<std::uint8_t>> RegenerateBuildedKeyStream
		(
			std::vector<std::string> FourPasswords,
			CommonSecurity::SHA::Hasher::WORKER_MODE HasherMode
		)
		{
			using namespace CommonSecurity::SHA;
			using namespace CommonSecurity::DataHashingWrapper;

			HashTokenForDataParameters HashToken_Parameters;
			HashToken_Parameters.HashersAssistantParameters_Instance.hash_mode = HasherMode;
			HashToken_Parameters.HashersAssistantParameters_Instance.whether_use_hash_extension_bit_mode = true;
			HashToken_Parameters.HashersAssistantParameters_Instance.generate_hash_bit_size = 1024;
			HashToken_Parameters.OriginalPasswordStrings = FourPasswords;
			HashToken_Parameters.NeedHashByteTokenSize = BlockCipherConstant3::KeyBlockByteSize * this->passcoder_sequence.size();
			auto HaveKeyStream = BuildingKeyStream<BlockCipherConstant3::KeyBlockByteSize * 8>(HashToken_Parameters);
			if(HaveKeyStream.has_value())
			{
				return HaveKeyStream.value();
			}
			else
			{
				my_cpp2020_assert(false, "", std::source_location::current());	
			}
		}

		void AEAD_EncryptingData
		(
			const std::vector<std::uint8_t>& processing_file_data,
			std::deque<std::vector<std::uint8_t>> BuildedKeyStream,
			std::vector<std::uint8_t>& processed_file_data
		)
		{
			using CommonSecurity::BlockCipherConstant3;
			using namespace CommonSecurity::KDF;

			for(const auto& KeyBlock : BuildedKeyStream )
			{
				my_cpp2020_assert
				(
					KeyBlock.size() % BlockCipherConstant3::DataBlockByteSize == 0,
					"",
					std::source_location::current()
				);
			}

			Scrypt::Algorithm ScryptKeyDerivationFunctionObject;

			//Returns the tag for the encrypted data
			if(this->AuthenticatedMode != WorkMode::EAX && this->AuthenticatedMode != WorkMode::SIV && this->AuthenticatedMode != WorkMode::OCB)
			{
				/*
					Cascade encryption or decryption using counter mode
				*/
				this->EncryptingData(processing_file_data, BuildedKeyStream, processed_file_data);

				std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools> MainHasherPointer = std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools>();
				auto& MainHasherObject = *(MainHasherPointer.get());

				//Use Blake2(Extension Mode) Hash Any Size Data To 4096 Bits Data

				this->AssociativeData.resize(4096 / 8, static_cast<std::uint8_t>(0x00));
				MainHasherObject.GenerateBlake2Hashed(processed_file_data, this->AssociativeData, true, this->AssociativeData.size() * 8);

				//Associated data to generate keys and "salt" values for random numbers
				std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;
				CommonSecurity::RegenerateSeeds2(this->AssociativeData, PRNG_Seed, PRNG_Seed2);
				std::mt19937_64 PRNG( (PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5) );
				std::vector<std::uint8_t> SaltData(BlockCipherConstant3::KeyBlockByteSize, 0);
				CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> UniformIntegerDistribution(0, 255);
				std::ranges::generate(SaltData.begin(), SaltData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
				std::vector<std::uint8_t> RandomData(BlockCipherConstant3::KeyBlockByteSize, 0);
				std::ranges::generate(RandomData.begin(), RandomData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );

				std::vector<std::uint8_t> GeneratedSecureKeys = ScryptKeyDerivationFunctionObject.GenerateKeys( RandomData, SaltData, BlockCipherConstant3::KeyBlockByteSize * 16, 1024, 16, 32 );

				/*
					Use cipher AES-256 with counter mode to compute authentication tags
				*/

				std::unique_ptr<CommonSecurity::AEAD::BlockCipherMode::ApplyIndependentType> AEAD_Independent_Pointer = std::make_unique<CommonSecurity::AEAD::BlockCipherMode::ApplyIndependentType>();

				this->AuthenticationTag.resize(BlockCipherConstant3::DataBlockByteSize, 0);
				AEAD_Independent_Pointer->GenerateAuthenticationTag(GeneratedSecureKeys, processed_file_data, this->AuthenticationTag, this->AuthenticatedMode);
			}
			else
			{
				/*
					Cascade encryption or decryption using counter mode
				*/
				this->EncryptingData(processing_file_data, BuildedKeyStream, processed_file_data);

				if(this->AssociativeData.empty())
					my_cpp2020_assert(false, "The association data cannot be empty and must be consistent, but the association data does not need to be confidential.", std::source_location::current());

				//Associated data to generate keys and "salt" values for random numbers
				std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;
				CommonSecurity::RegenerateSeeds2(this->AssociativeData, PRNG_Seed, PRNG_Seed2);
				std::mt19937_64 PRNG( (PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5) );
				std::vector<std::uint8_t> SaltData(BlockCipherConstant3::KeyBlockByteSize, 0);
				CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> UniformIntegerDistribution(0, 255);
				std::ranges::generate(SaltData.begin(), SaltData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
				std::vector<std::uint8_t> RandomData(BlockCipherConstant3::KeyBlockByteSize, 0);
				std::ranges::generate(RandomData.begin(), RandomData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );

				std::vector<std::uint8_t> GeneratedSecureKeys = ScryptKeyDerivationFunctionObject.GenerateKeys( RandomData, SaltData, BlockCipherConstant3::KeyBlockByteSize * 16, 1024, 16, 32 );

				std::unique_ptr<CommonSecurity::AEAD::BlockCipherMode::ApplyDependentType> AEAD_Dependent_Pointer = std::make_unique<CommonSecurity::AEAD::BlockCipherMode::ApplyDependentType>();

				this->AuthenticationTag.resize(BlockCipherConstant3::DataBlockByteSize, 0);
				switch (AuthenticatedMode)
				{
					case CommonSecurity::AEAD::BlockCipherMode::WorkMode::EAX:
					{
						std::vector<std::uint8_t> NumberOnceData(GeneratedSecureKeys.size(), 0);
						std::ranges::generate(NumberOnceData.begin(), NumberOnceData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
						auto EAX_Instance = AEAD_Dependent_Pointer->EAX_Mode_Instance(this->AssociativeData, GeneratedSecureKeys, NumberOnceData);
						
						EAX_Instance->Encryption(processed_file_data, processed_file_data, this->AuthenticationTag);
						break;
					}
					case CommonSecurity::AEAD::BlockCipherMode::WorkMode::SIV:
					{
						auto SIV_Instance = AEAD_Dependent_Pointer->SIV_Mode_Instance(this->AssociativeData, GeneratedSecureKeys);
						SIV_Instance->Encryption(processed_file_data, processed_file_data, this->AuthenticationTag);
						break;
					}
					case CommonSecurity::AEAD::BlockCipherMode::WorkMode::OCB:
					{
						std::vector<std::uint8_t> NumberOnceData(GeneratedSecureKeys.size(), 0);
						std::ranges::generate(NumberOnceData.begin(), NumberOnceData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
						auto OCB_Instance = AEAD_Dependent_Pointer->OCB_Mode_Instance(this->AssociativeData, GeneratedSecureKeys, NumberOnceData);
						OCB_Instance->Encryption(processed_file_data, processed_file_data, this->AuthenticationTag);
						break;
					}
					default:
						break;
				}
			}

			memory_set_no_optimize_function<0x00>(this->AssociativeData.data(), this->AssociativeData.size());
			this->AssociativeData.clear();
		}

		void AEAD_DecryptingData
		(
			const std::vector<std::uint8_t>& processing_file_data,
			std::deque<std::vector<std::uint8_t>> BuildedKeyStream,
			std::vector<std::uint8_t>& processed_file_data
		)
		{
			using CommonSecurity::BlockCipherConstant3;
			using namespace CommonSecurity::KDF;

			for(const auto& KeyBlock : BuildedKeyStream )
			{
				my_cpp2020_assert
				(
					KeyBlock.size() % BlockCipherConstant3::DataBlockByteSize == 0,
					"",
					std::source_location::current()
				);
			}

			Scrypt::Algorithm ScryptKeyDerivationFunctionObject;

			//Verify the tag and see if it can be decrypted
			if(this->AuthenticatedMode != WorkMode::EAX && this->AuthenticatedMode != WorkMode::SIV && this->AuthenticatedMode != WorkMode::OCB)
			{
				std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools> MainHasherPointer = std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools>();
				auto& MainHasherObject = *(MainHasherPointer.get());

				//Use Blake2(Extension Mode) Hash Any Size Data To 4096 Bits Data

				this->AssociativeData.resize(4096 / 8, static_cast<std::uint8_t>(0x00));
				MainHasherObject.GenerateBlake2Hashed(processing_file_data, this->AssociativeData, true, this->AssociativeData.size() * 8);

				//Associated data to generate keys and "salt" values for random numbers
				std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;
				CommonSecurity::RegenerateSeeds2(this->AssociativeData, PRNG_Seed, PRNG_Seed2);
				std::mt19937_64 PRNG( (PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5) );
				std::vector<std::uint8_t> SaltData(BlockCipherConstant3::KeyBlockByteSize, 0);
				CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> UniformIntegerDistribution(0, 255);
				std::ranges::generate(SaltData.begin(), SaltData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
				std::vector<std::uint8_t> RandomData(BlockCipherConstant3::KeyBlockByteSize, 0);
				std::ranges::generate(RandomData.begin(), RandomData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );

				std::vector<std::uint8_t> GeneratedSecureKeys = ScryptKeyDerivationFunctionObject.GenerateKeys( RandomData, SaltData, BlockCipherConstant3::KeyBlockByteSize * 16, 1024, 16, 32 );

				/*
					Use cipher AES-256 with counter mode to verify authentication tags
				*/

				std::unique_ptr<CommonSecurity::AEAD::BlockCipherMode::ApplyIndependentType> AEAD_Independent_Pointer = std::make_unique<CommonSecurity::AEAD::BlockCipherMode::ApplyIndependentType>();

				AEAD_Independent_Pointer->VerificationAuthenticationTag(GeneratedSecureKeys, processing_file_data, this->AuthenticationTag, this->AuthenticatedMode);

				/*
					Cascade encryption or decryption using counter mode
				*/
				this->DecryptingData(processing_file_data, BuildedKeyStream, processed_file_data);
			}
			else
			{
				if(this->AssociativeData.empty())
					my_cpp2020_assert(false, "The association data cannot be empty and must be consistent, but the association data does not need to be confidential.", std::source_location::current());

				//Associated data to generate keys and "salt" values for random numbers
				std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;
				CommonSecurity::RegenerateSeeds2(this->AssociativeData, PRNG_Seed, PRNG_Seed2);
				std::mt19937_64 PRNG( (PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5) );
				std::vector<std::uint8_t> SaltData(BlockCipherConstant3::KeyBlockByteSize, 0);
				CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> UniformIntegerDistribution(0, 255);
				std::ranges::generate(SaltData.begin(), SaltData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
				std::vector<std::uint8_t> RandomData(BlockCipherConstant3::KeyBlockByteSize, 0);
				std::ranges::generate(RandomData.begin(), RandomData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );

				std::vector<std::uint8_t> GeneratedSecureKeys = ScryptKeyDerivationFunctionObject.GenerateKeys( RandomData, SaltData, BlockCipherConstant3::KeyBlockByteSize * 16, 1024, 16, 32 );
				
				std::unique_ptr<CommonSecurity::AEAD::BlockCipherMode::ApplyDependentType> AEAD_Dependent_Pointer = std::make_unique<CommonSecurity::AEAD::BlockCipherMode::ApplyDependentType>();

				this->AuthenticationTag.resize(BlockCipherConstant3::DataBlockByteSize, 0);
				switch (AuthenticatedMode)
				{
					case CommonSecurity::AEAD::BlockCipherMode::WorkMode::EAX:
					{
						std::vector<std::uint8_t> NumberOnceData(GeneratedSecureKeys.size(), 0);
						std::ranges::generate(NumberOnceData.begin(), NumberOnceData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
						auto EAX_Instance = AEAD_Dependent_Pointer->EAX_Mode_Instance(this->AssociativeData, GeneratedSecureKeys, NumberOnceData);
						EAX_Instance->Decryption(processing_file_data, processed_file_data, this->AuthenticationTag);
						break;
					}
					case CommonSecurity::AEAD::BlockCipherMode::WorkMode::SIV:
					{
						auto SIV_Instance = AEAD_Dependent_Pointer->SIV_Mode_Instance(this->AssociativeData, GeneratedSecureKeys);
						SIV_Instance->Decryption(processing_file_data, processed_file_data, this->AuthenticationTag);
						break;
					}
					case CommonSecurity::AEAD::BlockCipherMode::WorkMode::OCB:
					{
						std::vector<std::uint8_t> NumberOnceData(GeneratedSecureKeys.size(), 0);
						std::ranges::generate(NumberOnceData.begin(), NumberOnceData.end(), [&UniformIntegerDistribution, &PRNG](){ return UniformIntegerDistribution(PRNG); } );
						auto OCB_Instance = AEAD_Dependent_Pointer->OCB_Mode_Instance(this->AssociativeData, GeneratedSecureKeys, NumberOnceData);
						OCB_Instance->Decryption(processing_file_data, processed_file_data, this->AuthenticationTag);
						break;
					}
					default:
						break;
				}

				/*
					Cascade encryption or decryption using counter mode
				*/
				this->DecryptingData(processed_file_data, BuildedKeyStream, processed_file_data);
			}

			memory_set_no_optimize_function<0x00>(this->AssociativeData.data(), this->AssociativeData.size());
			this->AssociativeData.clear();
		}

		CompositePasscoder(std::vector<PasscoderType> execute_passcoder_sequence, WorkMode Mode)
			: 
			passcoder_sequence(execute_passcoder_sequence), 
			reverse_passcoder_sequence(execute_passcoder_sequence),
			AuthenticatedMode(Mode)
		{
			my_cpp2020_assert
			(
				execute_passcoder_sequence.size() > 1 && execute_passcoder_sequence.size() <= 16,
				"CompositePasscoder: Sequence of the type of algorithm used to execute the cryptograph, the size cannot be zero and cannot exceed the maximum value that can be represented by the PasscoderType enumeration data",
				std::source_location::current()
			);

			std::ranges::reverse(reverse_passcoder_sequence.begin(), reverse_passcoder_sequence.end());
		}

		~CompositePasscoder() = default;
	};
}
