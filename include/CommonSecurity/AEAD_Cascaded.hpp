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
		public:
			using BlockCipher128_128 = CommonSecurity::BlockCipher128_128;
			using BlockCipher128_256 = CommonSecurity::BlockCipher128_256;

		
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

		// -------------------------------------------------------------------------------------
		// Helper: Left shift a 128-bit block by 1 bit in GF(2^128) sense (as in RFC 4493 §2.3).
		// Implementation detail:
		//   - Treat the 16-byte array as a big-endian bitstring; shift left by 1;
		//   - Propagate carry from low-index bytes toward high-index bytes correctly;
		//   - Caller supplies the input as span and receives the result in Output.
		// -------------------------------------------------------------------------------------
		inline void LeftShift_OneBit( std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output )
		{
			const std::size_t ByteSize = Input.size();
			my_cpp2020_assert(Output.size() >= ByteSize, "", std::source_location::current());

			std::uint8_t Carry = 0;
			// Process from the last byte (least significant) backward to the first (most significant).
			for ( std::ptrdiff_t I = static_cast<std::ptrdiff_t>( ByteSize ) - 1; I >= 0; --I )
			{
				const std::uint8_t Current = Input[ static_cast<std::size_t>( I ) ];
				const std::uint8_t NextCarry = static_cast<std::uint8_t>( ( Current & 0x80u ) ? 1u : 0u );
				Output[ static_cast<std::size_t>( I ) ] = static_cast<std::uint8_t>( ( Current << 1 ) | Carry );
				Carry = NextCarry;
			}
		}

		// -------------------------------------------------------------------------------------
		// Helper: Right shift a 128-bit block by 1 bit in GF(2^128) sense (logical right shift).
		// Implementation detail:
		//   - Treat the byte array as a big-endian bitstring; shift right by 1;
		//   - Propagate borrow/transfer of the least-significant bit of each byte into the
		//     most-significant bit of the next byte (i.e., across byte boundaries);
		//   - This is a logical shift: the vacated most-significant bit is filled with 0.
		//   - Caller supplies Input as span and receives result in Output (resized accordingly).
		// -------------------------------------------------------------------------------------
		inline void RightShift_OneBit( std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output )
		{
			const std::size_t ByteSize = Input.size();
			my_cpp2020_assert(Output.size() >= ByteSize, "", std::source_location::current());

			std::uint8_t Carry = 0;	 // Will hold the bit to insert into current byte's MSB.
			// Process from the first byte (most significant) forward to the last (least significant).
			for ( std::size_t I = 0; I < ByteSize; ++I )
			{
				const std::uint8_t Current = Input[ I ];
				// NextCarry is the bit that will be transferred to the next byte's MSB.
				// If Current LSB == 1 -> NextCarry should be 0x80 for the next iteration.
				const std::uint8_t NextCarry = static_cast<std::uint8_t>( ( Current & 0x01u ) ? 0x80u : 0x00u );
				// Shift right one and OR with Carry (which holds previous byte's LSB placed at MSB).
				Output[ I ] = static_cast<std::uint8_t>( ( Current >> 1 ) | Carry );
				Carry = NextCarry;
			}
		}

		// =====================================================================================
		// 1) Uniform CMAC interface (one-shot Update):
		//    Initialize(Key) -> Update(Message) -> Finish(Tag) -> (auto) Reset()
		// =====================================================================================
		struct CMAC
		{
			virtual ~CMAC() = default;
			virtual void Initialize( std::span<const std::uint8_t> Key ) = 0;
			virtual void Update( std::span<const std::uint8_t> Message ) = 0;
			virtual void Finish( std::span<std::uint8_t> Tag ) = 0;
			virtual void Reset() = 0;
		};

		// =====================================================================================
		// 2) Standard CMAC (RFC 4493 / NIST SP 800-38B)
		//    - Uses the user-provided AES key directly (128/192/256-bit);
		//    - Derives subkeys K1/K2 exactly per §2.3 using L = AES_K(0^128);
		//    - One-shot Update (whole message) to keep logic simple and step-aligned.
		// =====================================================================================
		struct CMAC_Standard final : public CMAC
		{
			using Block128 = CommonSecurity::BlockCipher128_128;
			using Block192 = CommonSecurity::BlockCipher128_192;
			using Block256 = CommonSecurity::BlockCipher128_256;
			static constexpr std::size_t BlockSizeBytes = Block128::DataBlockByteSize;	// 16

			// --- State (standard-only) ---
			// K1/K2 are 128-bit subkeys per RFC 4493 §2.3.
			std::vector<std::uint8_t> K1_128Bit = std::vector<std::uint8_t>( BlockSizeBytes, 0 );
			std::vector<std::uint8_t> K2_128Bit = std::vector<std::uint8_t>( BlockSizeBytes, 0 );

			// BlockDataX is the CBC chaining value; BlockDataY is the AES input buffer.
			std::vector<std::uint8_t> BlockDataX = std::vector<std::uint8_t>( BlockSizeBytes, 0 );
			std::vector<std::uint8_t> BlockDataY = std::vector<std::uint8_t>( BlockSizeBytes, 0 );

			// AES workers.
			CommonSecurity::AES::DataWorker256 AES_256 {};
			CommonSecurity::AES::DataWorker192 AES_192 {};
			CommonSecurity::AES::DataWorker128 AES_128 {};

			// Copy of user key (accepts 16/24/32 bytes).
			std::vector<std::uint8_t> UserKeyBytes;
			bool					  IsInitialized = false;

			CMAC_Standard() = default;

			// -----------------------------------------------------------------------------
			// Subkey derivation (RFC 4493 §2.3)
			// Step 1: L := AES_K( 0^128 )
			// Step 2: If MSB(L) = 0 => K1 := L << 1 ; else K1 := (L << 1) XOR Rb  (Rb=0x87)
			// Step 3: If MSB(K1)= 0 => K2 := K1 << 1 ; else K2 := (K1 << 1) XOR Rb
			// Rb corresponds to the reduction polynomial (x^128 + x^7 + x^2 + x + 1) in GF(2^128).
			// -----------------------------------------------------------------------------
			void GenerateSubkey128( std::span<const std::uint8_t> MasterKey, std::vector<std::uint8_t>& K1, std::vector<std::uint8_t>& K2 )
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

				std::array<std::uint8_t, BlockSizeBytes> ZeroBlock {};
				std::array<std::uint8_t, BlockSizeBytes> L {};

				if ( MasterKey.size() == Block128::KeyBlockByteSize )
				{
					AES_128.EncryptionWithECB( ZeroBlock, MasterKey, L );
				}
				else if ( MasterKey.size() == Block192::KeyBlockByteSize )
				{
					AES_192.EncryptionWithECB( ZeroBlock, MasterKey, L );
				}
				else if ( MasterKey.size() == Block256::KeyBlockByteSize )
				{
					AES_256.EncryptionWithECB( ZeroBlock, MasterKey, L );
				}
				else
				{
					my_cpp2020_assert( false, "Unsupported AES key length", std::source_location::current() );
				}

				// Derive K1
				LeftShift_OneBit( std::span<const std::uint8_t>( L.data(), L.size() ), K1 );
				if ( ( L[ 0 ] & 0x80u ) != 0 )
				{
					// When MSB(L)=1, XOR the constant Rb against the least-significant byte
					// (which is at index ByteSize-1 in our big-endian bitstring view).
					K1[ BlockSizeBytes - 1 ] ^= 0x87u;
				}

				// Derive K2
				LeftShift_OneBit( std::span<const std::uint8_t>( K1.data(), K1.size() ), K2 );
				if ( ( K1[ 0 ] & 0x80u ) != 0 )
				{
					K2[ BlockSizeBytes - 1 ] ^= 0x87u;
				}
			}

			// --- API ---
			void Initialize( std::span<const std::uint8_t> Key ) override
			{
				my_cpp2020_assert( Key.size() == Block128::KeyBlockByteSize || Key.size() == Block192::KeyBlockByteSize || Key.size() == Block256::KeyBlockByteSize, "Unsupported AES key length", std::source_location::current() );

				if(IsInitialized)
					Reset();

				GenerateSubkey128( Key, K1_128Bit, K2_128Bit );  // RFC 4493 §2.3

				// Reset chaining buffers.
				//std::fill( BlockDataX.begin(), BlockDataX.end(), 0x00 );
				//std::fill( BlockDataY.begin(), BlockDataY.end(), 0x00 );
				IsInitialized = true;
			}

			// One-shot Update: Message must contain the whole input to be MACed.
			void Update( std::span<const std::uint8_t> Message ) override
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

				if ( !IsInitialized )
					return;

				// Ensure each Update/Finish pair starts with X := 0 (CBC-MAC initial state).
				std::fill(BlockDataX.begin(), BlockDataX.end(), 0x00); 

				//  §2.4 Step 2: n := ceil(len(M)/b); b = 128 bits (16 bytes)
				const std::size_t TotalBytes = Message.size();
				std::size_t		  BlockCount = ( TotalBytes + BlockSizeBytes - 1 ) / BlockSizeBytes;

				//  §2.4 Step 3: If len(M) = 0 OR len(M) not multiple of b → last block is incomplete
				bool LastIsComplete = ( TotalBytes != 0 ) && ( ( TotalBytes % BlockSizeBytes ) == 0 );
				if ( BlockCount == 0 )
				{
					BlockCount = 1;
					LastIsComplete = false;
				}

				//  §2.4 Step 6: For i = 1..n-1:
				//       Y := X XOR M_i
				//       X := AES_K( Y )
				for ( std::size_t BlockIndex = 0; BlockIndex + 1 < BlockCount; ++BlockIndex )
				{
					const std::size_t Offset = BlockIndex * BlockSizeBytes;
					for ( std::size_t ByteIndex = 0; ByteIndex < BlockSizeBytes; ++ByteIndex )
						BlockDataY[ ByteIndex ] = static_cast<std::uint8_t>( BlockDataX[ ByteIndex ] ^ Message[ Offset + ByteIndex ] );

					if ( UserKeyBytes.size() == Block128::KeyBlockByteSize )
					{
						AES_128.EncryptionWithECB( BlockDataY, UserKeyBytes, BlockDataX );
					}
					else if(UserKeyBytes.size() == Block192::KeyBlockByteSize)
					{
						AES_192.EncryptionWithECB( BlockDataY, UserKeyBytes, BlockDataX );
					}
					else if(UserKeyBytes.size() == Block256::KeyBlockByteSize)
					{
						AES_256.EncryptionWithECB( BlockDataY, UserKeyBytes, BlockDataX );
					}
				}

				//  Build M_last ( §2.4 Step 4 ):
				//    If last block is complete:  M_last := M_n XOR K1
				//    Else (incomplete):          M_last := padding(M_n) XOR K2  (10*… padding)
				std::array<std::uint8_t, BlockSizeBytes> MLast {};
				const std::size_t						 LastOffset = ( BlockCount - 1 ) * BlockSizeBytes;

				if ( LastIsComplete )
				{
					for ( std::size_t ByteIndex = 0; ByteIndex < BlockSizeBytes; ++ByteIndex )
						MLast[ ByteIndex ] = static_cast<std::uint8_t>( Message[ LastOffset + ByteIndex ] ^ K1_128Bit[ ByteIndex ] );
				}
				else
				{
					const std::size_t						 Remain = ( TotalBytes >= LastOffset ) ? ( TotalBytes - LastOffset ) : 0;
					std::array<std::uint8_t, BlockSizeBytes> Pad {};
					for ( std::size_t ByteIndex = 0; ByteIndex < Remain; ++ByteIndex )
						Pad[ ByteIndex ] = Message[ LastOffset + ByteIndex ];
					Pad[ Remain ] = 0x80;  // binary 1000000…
					for ( std::size_t ByteIndex = 0; ByteIndex < BlockSizeBytes; ++ByteIndex )
						MLast[ ByteIndex ] = static_cast<std::uint8_t>( Pad[ ByteIndex ] ^ K2_128Bit[ ByteIndex ] );
				}

				//  §2.4 Step 5: Y := M_last XOR X
				for ( std::size_t ByteIndex = 0; ByteIndex < BlockSizeBytes; ++ByteIndex )
					BlockDataY[ ByteIndex ] = static_cast<std::uint8_t>( BlockDataX[ ByteIndex ] ^ MLast[ ByteIndex ] );
			}

			void Finish( std::span<std::uint8_t> Tag ) override
			{
				if ( !IsInitialized )
					return;
				if ( Tag.size() < BlockSizeBytes )
					return;	 // caller must provide at least 16 bytes

				//  §2.4 Step 7: T := AES_K( Y )
				if ( UserKeyBytes.size() == Block128::KeyBlockByteSize )
				{
					AES_128.EncryptionWithECB( BlockDataY, UserKeyBytes, Tag );
				}
				else if(UserKeyBytes.size() == Block192::KeyBlockByteSize)
				{
					AES_192.EncryptionWithECB( BlockDataY, UserKeyBytes, Tag );
				}
				else if(UserKeyBytes.size() == Block256::KeyBlockByteSize)
				{
					AES_256.EncryptionWithECB( BlockDataY, UserKeyBytes, Tag );
				}
			}

			void Reset() override
			{
				if ( !K1_128Bit.empty() )
					memory_set_no_optimize_function<0x00>( K1_128Bit.data(), K1_128Bit.size() );
				if ( !K2_128Bit.empty() )
					memory_set_no_optimize_function<0x00>( K2_128Bit.data(), K2_128Bit.size() );
				if ( !BlockDataX.empty() )
					memory_set_no_optimize_function<0x00>( BlockDataX.data(), BlockDataX.size() );
				if ( !BlockDataY.empty() )
					memory_set_no_optimize_function<0x00>( BlockDataY.data(), BlockDataY.size() );
				if ( !UserKeyBytes.empty() )
					memory_set_no_optimize_function<0x00>( UserKeyBytes.data(), UserKeyBytes.size() );
				IsInitialized = false;
			}
		};

		// =====================================================================================
		// Variant CMAC (domain-separated, CTR-derived dual-key design)
		// -------------------------------------------------------------------------------------
		// Overview:
		//   This CMAC variant derives two independent 256-bit working keys (Left/Right) using
		//   two domain-separated CTR expansions backed by the provided AES master key.
		//   - Left256  := keystream[ 0..31 ]  (used for middle-block processing / update mixing)
		//   - Right256 := keystream[32..63 ]  (used for final tag production / final mixing)
		//
		// Key derivation:
		//   - Two CTR expansions are performed with distinct domain labels and counter blocks.
		//   - Labels are distinct (e.g., LABEL_LEFT=0xA5, LABEL_RIGHT=0x5A) to guarantee domain
		//     separation. The CTR inputs must not be reused for the same master key.
		//
		// MAC flow:
		//   - For every full block except the last: X := AES_{UpdateMixKey}( X XOR M_i ).
		//     UpdateMixKey is derived from the master key combined with Left256/Right256.
		//   - For the final block: if it's complete use Tail16(Left256) XOR; otherwise pad(10*..)
		//     and XOR Tail16(Right256).
		//   - Final tag is computed as AES_{FinalMixKey}( Y ) where FinalMixKey is a derivation
		//     based on the master key and Left256/Right256.
		//
		// Security notes:
		//   - Domain separation of the two CTR expansions is essential — do not reuse labels/counters.
		//   - This construction intentionally departs from RFC4493 (no 128-bit K1/K2). It is an
		//     engineered variant: treat it as a custom MAC and audit before production use.
		//   - The implementation wipes all sensitive derived material in Reset(); Finish() calls
		//     Reset() by default to avoid key material lingering in memory.
		//
		// Usage:
		//   - Initialize(master_key) -> Update(message) -> Finish(tag) [-> Reset() optional]
		// =====================================================================================
		struct CMAC_Variant final : public CMAC
		{
			using Block128 = CommonSecurity::BlockCipher128_128;
			using Block192 = CommonSecurity::BlockCipher128_192;
			using Block256 = CommonSecurity::BlockCipher128_256;
			static constexpr std::size_t BlockSizeBytes = Block128::DataBlockByteSize;	// 16

			// Two 256-bit working keys (Left/Right).
			std::vector<std::uint8_t> K1_256 = std::vector<std::uint8_t>( Block256::KeyBlockByteSize, 0 );   // 32 bytes
			std::vector<std::uint8_t> K2_256 = std::vector<std::uint8_t>( Block256::KeyBlockByteSize, 0 );  // 32 bytes

			std::vector<uint8_t> UpdateMixKey {};
			std::vector<uint8_t> FinalMixKey {};

			// Work buffers (CBC chaining X and AES input Y).
			std::vector<std::uint8_t> BlockDataX = std::vector<std::uint8_t>( BlockSizeBytes, 0 );
			std::vector<std::uint8_t> BlockDataY = std::vector<std::uint8_t>( BlockSizeBytes, 0 );

			// AES workers.
			CommonSecurity::AES::DataWorker256 AES_256 {};
			CommonSecurity::AES::DataWorker192 AES_192 {};
			CommonSecurity::AES::DataWorker128 AES_128 {};

			size_t UserKeyByteSize = 0;
			bool   IsInitialized = false;

			CMAC_Variant() = default;

			// ---------------------------------------------------------------------------------
			// Two-call CTR-based dual-key derivation (domain separated).
			// Each call consumes 32 bytes of input (two 16B counter blocks concatenated)
			// and produces 32 bytes of keystream. Total: 64 bytes -> split into two 256-bit keys.
			//
			// IMPORTANT:
			//   * We are not encrypting "a message" in CTR here; we only use the CTR engine
			//     to expand domain-separated inputs into pseudorandom key material.
			//   * (Key, CounterBlock) pairs MUST be unique; we enforce uniqueness via (label, counter).
			// ---------------------------------------------------------------------------------
			void GenerateVariantDualKeys( std::span<const std::uint8_t> MasterKey, std::vector<std::uint8_t>& KeyLeft256, std::vector<std::uint8_t>& KeyRight256 )
			{
				constexpr std::size_t		 BS = 16;
				std::array<std::uint8_t, 64> Keystream {};	// 4 blocks × 16 = 64 bytes
				std::array<std::uint8_t, 32> Input12 {};
				std::array<std::uint8_t, 32> Input34 {};

				// (ctr1 || ctr2) with label 0xA5 (Left)
				{
					std::array<std::uint8_t, BS> Counter1 {};
					Counter1.fill( 0 );
					Counter1[ 14 ] = 0xA5u;
					Counter1[ 15 ] = 0x01u;
					std::array<std::uint8_t, BS> Counter2 = Counter1;
					Counter2[ 15 ] = 0x02u;
					std::memcpy( Input12.data() + 0, Counter1.data(), BS );
					std::memcpy( Input12.data() + 16, Counter2.data(), BS );
				}
				// (ctr3 || ctr4) with label 0x5A (Right = 0xA5 ^ 0xFF)
				{
					std::array<std::uint8_t, BS> Counter3 {};
					Counter3.fill( 0 );
					Counter3[ 14 ] = static_cast<std::uint8_t>( 0xA5u ^ 0xFFu );
					Counter3[ 15 ] = 0x03u;
					std::array<std::uint8_t, BS> Counter4 = Counter3;
					Counter4[ 15 ] = 0x04u;
					std::memcpy( Input34.data() + 0, Counter3.data(), BS );
					std::memcpy( Input34.data() + 16, Counter4.data(), BS );
				}

				// Two CTR expansions, each outputs 32 bytes (keystream).
				if ( MasterKey.size() == Block128::KeyBlockByteSize )
				{
					AES_128.CTR_StreamModeBasedEncryptFunction( std::span<const std::uint8_t>( Input12.data(), Input12.size() ), MasterKey, std::span<std::uint8_t>( Keystream.data(), 32 ) );
					AES_128.CTR_StreamModeBasedEncryptFunction( std::span<const std::uint8_t>( Input34.data(), Input34.size() ), MasterKey, std::span<std::uint8_t>( Keystream.data() + 32, 32 ) );
				}
				else if ( MasterKey.size() == Block192::KeyBlockByteSize )
				{
					AES_192.CTR_StreamModeBasedEncryptFunction( std::span<const std::uint8_t>( Input12.data(), Input12.size() ), MasterKey, std::span<std::uint8_t>( Keystream.data(), 32 ) );
					AES_192.CTR_StreamModeBasedEncryptFunction( std::span<const std::uint8_t>( Input34.data(), Input34.size() ), MasterKey, std::span<std::uint8_t>( Keystream.data() + 32, 32 ) );
				}
				else if ( MasterKey.size() == Block256::KeyBlockByteSize )
				{
					AES_256.CTR_StreamModeBasedEncryptFunction( std::span<const std::uint8_t>( Input12.data(), Input12.size() ), MasterKey, std::span<std::uint8_t>( Keystream.data(), 32 ) );
					AES_256.CTR_StreamModeBasedEncryptFunction( std::span<const std::uint8_t>( Input34.data(), Input34.size() ), MasterKey, std::span<std::uint8_t>( Keystream.data() + 32, 32 ) );
				}

				KeyLeft256.assign( Keystream.begin(), Keystream.begin() + 32 );
				KeyRight256.assign( Keystream.begin() + 32, Keystream.begin() + 64 );
			}

			// --- API ---
			void Initialize( std::span<const std::uint8_t> Key ) override
			{
				my_cpp2020_assert( Key.size() == Block128::KeyBlockByteSize || Key.size() == Block192::KeyBlockByteSize || Key.size() == Block256::KeyBlockByteSize, "Unsupported AES key length", std::source_location::current() );
				
				if (IsInitialized)
				{
					Reset();
				}

				// 1. Derive two 256-bit working keys (Left/Right) via two CTR calls (domain-separated).
				GenerateVariantDualKeys( Key, K1_256, K2_256 );
				UserKeyByteSize = Key.size();
				
				/*
				 * Rationale for MixKey computation (UpdateMixKey / FinalMixKey)
				 *
				 * This step combines the master key (Key) with the two CTR-derived 256-bit
				 * working keys (K1_256, K2_256) using bitwise NAND and NOR, then XORs the
				 * result back into the master key bytes.  A compact explanation of why this
				 * is both simple and effective:
				 *
				 * 1) Non-linearity without heavy cost
				 *    - NAND: ~(K1 & K2) and NOR: ~(K1 | K2) are non-linear bit-ops (unlike XOR).
				 *      That non-linearity increases resistance against attacks that exploit
				 *      purely linear relationships between derived material.
				 *
				 * 2) Joint dependence on both derived keys
				 *    - Each mix bit is a function of both K1 and K2.  That means an attacker
				 *      must know (or influence) both derived keys to predict which master-key
				 *      bits are flipped; single-key leakage does not trivially reveal the mix.
				 *
				 * 3) Complementary semantics for Update vs Final
				 *    - NAND emphasizes positions where K1 and K2 are both 1; NOR emphasizes
				 *      positions where both are 0.  Using NAND for the update-phase mix and
				 *      NOR for the final-phase mix produces two logically different masks,
				 *      reducing simple algebraic relationships between the two phases.
				 *
				 * 4) Preserves master-key influence while masking it
				 *    - XORing (master_key ^ mask) retains dependence on the original master
				 *      key bytes while flipping bits according to the joint state of K1/K2.
				 *      This is a lightweight way to derive a per-phase AES key that is both
				 *      tied to the master key and strongly influenced by the CTR-derived keys.
				 *
				 * 5) Engineering benefits
				 *    - All operations are cheap bitwise ops (AND/OR/NOT/XOR), constant-time
				 *      friendly (no data-dependent branches), and easy to audit and test.
				 *    - The result is suitable as an AES key or key material fed into AES,
				 *      where AES's internal diffusion amplifies any remaining bit-locality.
				 *
				 * Security notes / caveats
				 *    - Bitwise NAND/NOR by itself offers limited diffusion (each output bit
				 *      depends only on the corresponding input bits). That is acceptable here
				 *      because the mixed bytes are consumed by AES, which provides strong
				 *      permutation/diffusion. If AES were not present, consider a stronger KDF.
				 *    - Be explicit about integer types and truncation: use uint8_t casts to
				 *      avoid surprises from integer promotions (as done in the implementation).
				 *    - Wipe derived material (UpdateMixKey / FinalMixKey / K1_256 / K2_256)
				 *      when no longer needed to avoid sensitive data lingering in memory.
				 *
				 * Alternative / stronger options (if you need higher assurance)
				 *    - Run the concatenation (K1 || K2 || Key || label) through a KDF/AES-CTR
				 *      or a single AES-ECB block to obtain stronger, fuller-bit mixing.
				 *
				 * In short: NAND/NOR + XOR is a lightweight, non-linear, two-key-aware mixing
				 * strategy that is cheap, auditable and—when paired with AES—practically strong
				 * for deriving per-phase AES keys while preserving master-key linkage.
				 */
				// 2. Compute MixKeys
				UpdateMixKey.resize(UserKeyByteSize);
				FinalMixKey.resize( UserKeyByteSize );
				for ( size_t i = 0; i < UserKeyByteSize; ++i )
				{
					UpdateMixKey[ i ] = static_cast<std::uint8_t>( Key[ i ] ^ static_cast<std::uint8_t>( ~( K1_256[ i ] & K2_256[ i ] ) ) );
					FinalMixKey[ i ] = static_cast<std::uint8_t>( Key[ i ] ^ static_cast<std::uint8_t>( ~( K1_256[ i ] | K2_256[ i ] ) ) );
				}

				// Reset chaining buffers.
				//std::fill( BlockDataX.begin(), BlockDataX.end(), 0x00 );
				//std::fill( BlockDataY.begin(), BlockDataY.end(), 0x00 );
				IsInitialized = true;
			}

			// One-shot Update (whole message).
			void Update( std::span<const std::uint8_t> Message ) override
			{
				if ( !IsInitialized )
					return;

				// Ensure each Update/Finish pair starts with X := 0 (CBC-MAC initial state).
				std::fill(BlockDataX.begin(), BlockDataX.end(), 0x00); 

				const std::size_t TotalBytes = Message.size();
				std::size_t		  BlockCount = ( TotalBytes + BlockSizeBytes - 1 ) / BlockSizeBytes;
				bool			  LastIsComplete = ( TotalBytes != 0 ) && ( ( TotalBytes % BlockSizeBytes ) == 0 );
				if ( BlockCount == 0 )
				{
					BlockCount = 1;
					LastIsComplete = false;
				}

				for ( std::size_t BlockIndex = 0; BlockIndex + 1 < BlockCount; ++BlockIndex )
				{
					const std::size_t Offset = BlockIndex * BlockSizeBytes;
					for ( std::size_t ByteIndex = 0; ByteIndex < BlockSizeBytes; ++ByteIndex )
						BlockDataY[ ByteIndex ] = static_cast<std::uint8_t>( BlockDataX[ ByteIndex ] ^ Message[ Offset + ByteIndex ] );

					//Middle block: X = AES_{UpdateMixKey}( Y )
					if ( UserKeyByteSize == Block128::KeyBlockByteSize )
					{
						AES_128.EncryptionWithECB( BlockDataY, UpdateMixKey, BlockDataX );
					}
					else if( UserKeyByteSize == Block192::KeyBlockByteSize )
					{
						AES_192.EncryptionWithECB( BlockDataY, UpdateMixKey, BlockDataX );
					}
					else if( UserKeyByteSize == Block256::KeyBlockByteSize )
					{
						AES_256.EncryptionWithECB( BlockDataY, UpdateMixKey, BlockDataX );
					}
				}

				// Build M_last using the TAIL16 of the 256-bit variant keys (NO 128-bit K1/K2 here):
				//   TailStart = 32 - 16 = 16
				const std::size_t TailStart = Block256::KeyBlockByteSize - BlockSizeBytes;	// 16

				std::array<std::uint8_t, BlockSizeBytes> MLast {};
				const std::size_t						 LastOffset = ( BlockCount - 1 ) * BlockSizeBytes;

				if ( LastIsComplete )
				{
					// Complete final block: M_last = M_n XOR Tail16(Left256)
					for ( std::size_t ByteIndex = 0; ByteIndex < BlockSizeBytes; ++ByteIndex )
						MLast[ ByteIndex ] = static_cast<std::uint8_t>( Message[ LastOffset + ByteIndex ] ^ K1_256[ TailStart + ByteIndex ] );
				}
				else
				{
					// Incomplete final block: padding(10*..) then XOR Tail16(Right256)
					const std::size_t						 Remain = ( TotalBytes >= LastOffset ) ? ( TotalBytes - LastOffset ) : 0;
					std::array<std::uint8_t, BlockSizeBytes> Pad {};
					for ( std::size_t ByteIndex = 0; ByteIndex < Remain; ++ByteIndex )
						Pad[ ByteIndex ] = Message[ LastOffset + ByteIndex ];
					Pad[ Remain ] = 0x80;
					for ( std::size_t ByteIndex = 0; ByteIndex < BlockSizeBytes; ++ByteIndex )
						MLast[ ByteIndex ] = static_cast<std::uint8_t>( Pad[ ByteIndex ] ^ K2_256[ TailStart + ByteIndex ] );
				}

				// Y = X_{n-1} XOR M_last (final AES input held until Finish)
				for ( std::size_t ByteIndex = 0; ByteIndex < BlockSizeBytes; ++ByteIndex )
					BlockDataY[ ByteIndex ] = static_cast<std::uint8_t>( BlockDataX[ ByteIndex ] ^ MLast[ ByteIndex ] );
			}

			void Finish( std::span<std::uint8_t> Tag ) override
			{
				if ( !IsInitialized )
					return;
				if ( Tag.size() < BlockSizeBytes )
					return;

				// Final tag: Tag = AES_{FinalMixKey}( Y )

				if ( UserKeyByteSize == Block128::KeyBlockByteSize )
				{
					AES_128.EncryptionWithECB( BlockDataY, FinalMixKey, Tag );
				}
				else if( UserKeyByteSize == Block192::KeyBlockByteSize )
				{
					AES_192.EncryptionWithECB( BlockDataY, FinalMixKey, Tag );
				}
				else if( UserKeyByteSize == Block256::KeyBlockByteSize )
				{
					AES_256.EncryptionWithECB( BlockDataY, FinalMixKey, Tag );
				}
			}

			void Reset() override
			{
				if ( !K1_256.empty() )
					memory_set_no_optimize_function<0x00>( K1_256.data(), K1_256.size() );
				if ( !K2_256.empty() )
					memory_set_no_optimize_function<0x00>( K2_256.data(), K2_256.size() );
				if ( !UpdateMixKey.empty() )
					memory_set_no_optimize_function<0x00>( UpdateMixKey.data(), UpdateMixKey.size() );
				if ( !FinalMixKey.empty() )
					memory_set_no_optimize_function<0x00>( FinalMixKey.data(), FinalMixKey.size() );
				if ( !BlockDataX.empty() )
					memory_set_no_optimize_function<0x00>( BlockDataX.data(), BlockDataX.size() );
				if ( !BlockDataY.empty() )
					memory_set_no_optimize_function<0x00>( BlockDataY.data(), BlockDataY.size() );
				IsInitialized = false;
				UserKeyByteSize = 0;
			}
		};

		// =====================================================================================
		// 4) Pointer-based Router (bool → concrete implementation)
		//    - Only the chosen implement allocates its buffers.
		//    - You can embed/hold this in your higher-level API (e.g., your CCM sample).
		// =====================================================================================
		struct CMAC_Router final : public CMAC
		{
			std::unique_ptr<CMAC> ImplPointer;

			// Keep the flag for API introspection (PascalCase per your style).
			bool EnableVariantMode = false;

			explicit CMAC_Router( bool EnableVariant )
			{
				SetMode( EnableVariant );
			}

			// Optionally switch at runtime (caller must re-Initialize).
			void SetMode( bool EnableVariant )
			{
				EnableVariantMode = EnableVariant;
				if ( EnableVariant )
					ImplPointer = std::make_unique<CMAC_Variant>();
				else
					ImplPointer = std::make_unique<CMAC_Standard>();
			}

			// Delegate API
			void Initialize( std::span<const std::uint8_t> Key ) override
			{
				ImplPointer->Initialize( Key );
			}
			void Update( std::span<const std::uint8_t> Message ) override
			{
				ImplPointer->Update( Message );
			}
			void Finish( std::span<std::uint8_t> Tag ) override
			{
				ImplPointer->Finish( Tag );
			}
			void Reset() override
			{
				ImplPointer->Reset();
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

				CMAC_Router CMAC_Pointer(false);
				CMAC_Pointer.Initialize(Keys);
				CMAC_Pointer.Update(Data);

				std::vector<std::uint8_t> Tag = std::vector<std::uint8_t>(BlockCipher128_256::DataBlockByteSize, 0);
				CMAC_Pointer.Finish(Tag);

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
		// Reference code:
		// https://chromium.googlesource.com/chromium/src/+/95325bb9/crypto/ghash.cc
		struct GaloisFiniteField128Hash
		{
			/* GHASH Application Interface */

			void Initialize(std::span<const std::uint8_t> Keys)
			{
				std::uint64_t low_value = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(Keys.subspan(0, 8));
				std::uint64_t high_value = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(Keys.subspan(8, 8));

				//from little endian -> from big endian
				low_value = CommonToolkit::ByteSwap::byteswap(low_value);
				high_value = CommonToolkit::ByteSwap::byteswap(high_value);

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

					//to big endian <- to little endian
					NumberY.low = CommonToolkit::ByteSwap::byteswap(NumberY.low);
					NumberY.high = CommonToolkit::ByteSwap::byteswap(NumberY.high);

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

			// Representation notes
			// FieldElement represents an element of GF(2^128) used by GHASH.
			// - The element is stored as two 64-bit words: low (least-significant 64 bits) and high (most-significant 64 bits).
			// - External byte streams (keys / blocks) follow the GHASH / NIST convention (big-endian bit/byte order).
			// - This implementation *converts* incoming bytes to the internal word ordering via explicit byteswap so arithmetic (shifts / doublings) can be implemented as right-shifts on the internal representation.
			// - When producing output bytes we byteswap back to the protocol-expected byte order.
			// NOTE: any change to word/bit mapping must update Multiply16, DoubleExp and the ReductionTable alignment.
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

			// Doubling in GF(2^128) and constant-time reduction note
			// ---------------------------------------------------------------------------
			// Purpose:
			//   Compute 2 * x in GF(2^128) (i.e. multiply the field element by the polynomial 'x').
			//
			// Representation note (VERY IMPORTANT):
			//   In this implementation the internal FieldElement mapping is bit-reversed relative to
			//   the natural mathematical ordering: the bit that represents x^127 is stored in the
			//   least-significant bit of x.high (i.e. x.high & 1). Consequently, a logical "multiply
			//   by x" corresponds to a **right shift by 1** on the (x.high, x.low) pair in this mapping.
			//   This is the reason we test `x.high & 1` rather than testing the most-significant bit
			//   of the 64-bit word.
			//
			// Reduction:
			//   If the bit corresponding to x^127 was set before the shift, the multiplication produces
			//   an x^128 term which must be reduced modulo the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
			//   In characteristic-2 fields reduction is XOR. The constant REDUCTION (0xE100000000000000)
			//   encodes the low-64-bit part of that correction in our internal mapping and is XORed
			//   into the low word when needed.
			//
			// Constant-time note:
			//   To avoid secret-dependent branching we convert the branch into an arithmetic mask:
			//   Mask = 0 - (x.high & 1) yields either 0 or all-ones, so `xx.low ^= (Mask & REDUCTION)`
			//   applies the reduction in a branchless manner.
			// ---------------------------------------------------------------------------
			// returns 2**|x|
			static FieldElement DoubleExp(const FieldElement& x)
			{
				uint64_t MostSignificantBit = x.high & 1;

				FieldElement xx {0,0};

				// Because of the bit-ordering, doubling is actually a right shift.
				xx.high = x.high >> 1;
				xx.high |= x.low << 63;
				xx.low = x.low >> 1;

				// If the MSB (x^127) was set before shifting, the multiplication produces an x^128 term;
				// reduce modulo 1 + x + x^2 + x^7 + x^128 (REDUCTION below encodes the low-64-bit correction).
				// We can subtract that to eliminate the term at x^128 which also means subtracting the other four terms.
				// In characteristic 2 fields, subtraction == addition == XOR.
				constexpr std::uint64_t REDUCTION = 0xE100000000000000ULL;
				const std::uint64_t Mask = static_cast<std::uint64_t>(0) - MostSignificantBit;
				xx.low ^= (Mask & REDUCTION);

				return xx;
			}

			// Note on bit-order and "direction":
			// - Externally GHASH is defined in a big-endian bit ordering.
			// - Internally this implementation uses a word/bit mapping where a logical *multiply by 16*
			//   (i.e. shift-left by 4 in mathematical notation) corresponds to a **right shift by 4**
			//   of our two-word representation (x.high, x.low).  This is due to the chosen low/high
			//   word layout and the way we interpret byte streams (see FieldElement docs).
			//
			// Operation summary:
			// 1) Capture the 4 bits that will "fall off" the MS side of the 128-bit value (MostSignificantNibble).
			// 2) Shift the 128-bit value right by 4 (propagating bits across low/high).
			// 3) Apply a precomputed reduction based on the 4-bit pattern shifted out.
			//    ReductionTable contains per-nibble correction values (stored as 16-bit entries).
			//    We place those correction bits into x.low at the correct offset by shifting << 48.
			//    If you change FieldElement layout or the byteswap semantics, update this alignment.
			//
			// Safety / maintenance:
			// - Ensure ReductionTable entries fit the expected bit-width (here 16-bit) and that
			//   their positioning (<< 48) matches the internal bit mapping.
			// - The assert below helps catch accidental table/layout changes.
			// sets |x| = 16*|x|
			static void Multiply16(FieldElement& x) 
			{
				// 'nibble' is the 4-bit pattern shifted out from the most-significant side.
				const unsigned MostSignificantWord = static_cast<unsigned>(x.high & 0xFu); 

				// Right shift the 128-bit value by 4 bits in-place.
				x.high >>= 4;
				x.high |= (x.low << 60); // move high 4 bits of low into low bits of high
				x.low >>= 4;

				// ReductionTable entries are 16-bit precomputed corrections.
				// We place the correction at bit offset 48 of x.low to match our internal mapping.
				x.low ^= (static_cast<std::uint64_t>(ReductionTable[MostSignificantWord]) << 48);
			}

			// ---------- constant-time unrolled select helper ----------
			static inline std::uint64_t ConstantTimeMaskEqual_8Bit(std::uint8_t a, std::uint8_t b) noexcept 
			{
				// returns 0xFFFF... if a==b else 0
				std::uint8_t x = static_cast<std::uint8_t>(a ^ b); // 0 if equal
				x |= x >> 4;
				x |= x >> 2;
				x |= x >> 1;
				std::uint64_t eq = static_cast<std::uint64_t>((x ^ 1u) & 1u); // 1 if equal, else 0
				return static_cast<std::uint64_t>(0) - eq; // all-ones if equal else 0
			}

			// MultiplyAfterPrecomputation -- table-driven 4-bit window multiplication
			// ----------------------------------------------------------------------------
			// Purpose:
			//   Multiply NumberX by H using a 4-bit precomputed table Table[0..15] where Table[i] = i * H.
			//   We process 128 bits 4 bits at a time (low-order windows first in our internal mapping).
			//
			// Security / performance trade-off:
			//   - By default we perform a constant-time selection of table entries to avoid
			//     data-dependent memory accesses (cache-timing attacks).
			//   - The constexpr flag `FindTableNotConstantTime` can enable a direct indexed lookup
			//     (faster but data-dependent). This is resolved at compile time.
			//
			// Implementation notes:
			//   - Loop `i=0..1` selects Word64Bit = NumberX.high (i==0) then NumberX.low (i==1).
			//     Each inner iteration scans the selected 64-bit word from least-significant nibble
			//     to most-significant nibble (Word64Bit >>= 4).
			//   - Multiply16(NumberZ) advances the accumulator by a 4-bit window (equivalent to *16).
			//   - The table entries and this loop order rely on the internal field bit/word mapping;
			//     any change to endianness / FieldElement layout requires revisiting the reduction alignment
			//     and table ordering.
			// ----------------------------------------------------------------------------
			// sets |x| = |x|*h where h is |table[1]| and table[Index0] = Index0*h for Index0=0..15.
			static void MultiplyAfterPrecomputation(std::span<const FieldElement> Table, FieldElement& NumberX)
			{
				constexpr bool FindTableNotConstantTime = false;

				FieldElement NumberZ {0,0};

				// In order to efficiently multiply, we use the precomputed table of Index0*key, for Index0 in 0..15, to handle four bits at a time.
				// We could obviously use larger tables for greater speedups but the next convenient table size is 4K, which is a little large.
				// In other fields one would use bit positions spread out across the field in order to reduce the number of doublings required. 
				// However, in characteristic 2 fields, repeated doublings are exceptionally cheap and it's not worth spending more precomputation time to eliminate them.
				for (std::uint32_t i = 0; i < 2; i++)
				{
					// Constant-time select
					const std::uint64_t SelectMask = static_cast<std::uint64_t>(0) - static_cast<std::uint64_t>(1u - i);
					std::uint64_t Word64Bit = (NumberX.high & SelectMask) | (NumberX.low & ~SelectMask);

					for (std::uint32_t j = 0; j < 64; j += 4)
					{
						Multiply16(NumberZ);
						// The values in |table| are ordered for little-endian bit positions. 
						// See the comment in the constructor.

						if constexpr(FindTableNotConstantTime)
						{
							const FieldElement& NumberT = Table[Word64Bit & 0xf];
							// XOR into running result
							NumberZ.low ^= NumberT.low;
							NumberZ.high ^= NumberT.high;
						}
						else
						{
							// unrolled constant-time selection of Table[TableIndex]
							const std::uint8_t TableIndex = static_cast<std::uint8_t>(Word64Bit & 0xf);

							FieldElement NumberT {0, 0};

							//Constant-time select + find full table
							const std::uint64_t ValueMask0 = ConstantTimeMaskEqual_8Bit(TableIndex, 0);
							NumberT.low  ^= (Table[0].low  & ValueMask0);
							NumberT.high ^= (Table[0].high & ValueMask0);

							const std::uint64_t ValueMask1 = ConstantTimeMaskEqual_8Bit(TableIndex, 1);
							NumberT.low  ^= (Table[1].low  & ValueMask1);
							NumberT.high ^= (Table[1].high & ValueMask1);

							const std::uint64_t ValueMask2 = ConstantTimeMaskEqual_8Bit(TableIndex, 2);
							NumberT.low  ^= (Table[2].low  & ValueMask2);
							NumberT.high ^= (Table[2].high & ValueMask2);

							const std::uint64_t ValueMask3 = ConstantTimeMaskEqual_8Bit(TableIndex, 3);
							NumberT.low  ^= (Table[3].low  & ValueMask3);
							NumberT.high ^= (Table[3].high & ValueMask3);

							const std::uint64_t ValueMask4 = ConstantTimeMaskEqual_8Bit(TableIndex, 4);
							NumberT.low  ^= (Table[4].low  & ValueMask4);
							NumberT.high ^= (Table[4].high & ValueMask4);

							const std::uint64_t ValueMask5 = ConstantTimeMaskEqual_8Bit(TableIndex, 5);
							NumberT.low  ^= (Table[5].low  & ValueMask5);
							NumberT.high ^= (Table[5].high & ValueMask5);

							const std::uint64_t ValueMask6 = ConstantTimeMaskEqual_8Bit(TableIndex, 6);
							NumberT.low  ^= (Table[6].low  & ValueMask6);
							NumberT.high ^= (Table[6].high & ValueMask6);

							const std::uint64_t ValueMask7 = ConstantTimeMaskEqual_8Bit(TableIndex, 7);
							NumberT.low  ^= (Table[7].low  & ValueMask7);
							NumberT.high ^= (Table[7].high & ValueMask7);

							const std::uint64_t ValueMask8 = ConstantTimeMaskEqual_8Bit(TableIndex, 8);
							NumberT.low  ^= (Table[8].low  & ValueMask8);
							NumberT.high ^= (Table[8].high & ValueMask8);

							const std::uint64_t ValueMask9 = ConstantTimeMaskEqual_8Bit(TableIndex, 9);
							NumberT.low  ^= (Table[9].low  & ValueMask9);
							NumberT.high ^= (Table[9].high & ValueMask9);

							const std::uint64_t ValueMask10 = ConstantTimeMaskEqual_8Bit(TableIndex, 10);
							NumberT.low  ^= (Table[10].low  & ValueMask10);
							NumberT.high ^= (Table[10].high & ValueMask10);

							const std::uint64_t ValueMask11 = ConstantTimeMaskEqual_8Bit(TableIndex, 11);
							NumberT.low  ^= (Table[11].low  & ValueMask11);
							NumberT.high ^= (Table[11].high & ValueMask11);

							const std::uint64_t ValueMask12 = ConstantTimeMaskEqual_8Bit(TableIndex, 12);
							NumberT.low  ^= (Table[12].low  & ValueMask12);
							NumberT.high ^= (Table[12].high & ValueMask12);

							const std::uint64_t ValueMask13 = ConstantTimeMaskEqual_8Bit(TableIndex, 13);
							NumberT.low  ^= (Table[13].low  & ValueMask13);
							NumberT.high ^= (Table[13].high & ValueMask13);

							const std::uint64_t ValueMask14 = ConstantTimeMaskEqual_8Bit(TableIndex, 14);
							NumberT.low  ^= (Table[14].low  & ValueMask14);
							NumberT.high ^= (Table[14].high & ValueMask14);

							const std::uint64_t ValueMask15 = ConstantTimeMaskEqual_8Bit(TableIndex, 15);
							NumberT.low  ^= (Table[15].low  & ValueMask15);
							NumberT.high ^= (Table[15].high & ValueMask15);

							// XOR into running result
							NumberZ.low ^= NumberT.low;
							NumberZ.high ^= NumberT.high;
						}

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
					std::uint64_t low_value = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(std::span<const std::uint8_t>{Bytes,8});
					//from little endian -> from big endian
					low_value = CommonToolkit::ByteSwap::byteswap(low_value);

					NumberY.low ^= low_value;
					Bytes += 8;

					std::uint64_t high_value = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(std::span<const std::uint8_t>{Bytes,8});
					//from little endian -> from big endian
					high_value = CommonToolkit::ByteSwap::byteswap(high_value);

					NumberY.high ^= high_value;
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
				GaloisFiniteField128Hash GHASH {};
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
		// https://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
		// https://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/images/fig5.pdf
		struct OMAC2
		{
			using Cipher128_128 = CommonSecurity::BlockCipher128_128;
			using Cipher128_192 = CommonSecurity::BlockCipher128_192;
			using Cipher128_256 = CommonSecurity::BlockCipher128_256;

			// === Internal state ===
			// Subkeys K1 and K2 are 128-bit masks derived from L = E(K, 0^n) as in Fig. 5
			std::vector<std::uint8_t> K1_128Bit = std::vector<std::uint8_t>( BlockCipher128_256::DataBlockByteSize, 0 );
			std::vector<std::uint8_t> K2_128Bit = std::vector<std::uint8_t>( BlockCipher128_256::DataBlockByteSize, 0 );

			// Work buffers (n = 128 bits)
			std::vector<std::uint8_t> X_Block = std::vector<std::uint8_t>( BlockCipher128_256::DataBlockByteSize, 0 );
			std::vector<std::uint8_t> Y_Block = std::vector<std::uint8_t>( BlockCipher128_256::DataBlockByteSize, 0 );

			// The main AES key K (supports 128, 192, 256 bits)
			std::vector<std::uint8_t> MainKey;

			bool IsInitialized = false;

			// AES workers (project-specific types)
			CommonSecurity::AES::DataWorker128 AES_128_128;
			CommonSecurity::AES::DataWorker192 AES_128_192;
			CommonSecurity::AES::DataWorker256 AES_128_256;

			// === Helper: single-block E(K, ·) selecting AES-128/192/256 by key length ===
			void EncryptBlock_EK( std::span<const std::uint8_t> InputBlock, std::span<const std::uint8_t> Keys, std::span<std::uint8_t> OutputBlock )
			{
				// InputBlock and OutputBlock must be 16 bytes
				std::vector<std::uint8_t> In( InputBlock.begin(), InputBlock.end() );
				std::vector<std::uint8_t> Out( OutputBlock.size(), 0 );

				if ( Keys.size() == Cipher128_128::KeyBlockByteSize )
				{
					AES_128_128.EncryptionWithECB( In, Keys, Out );
				}
				else if ( Keys.size() == Cipher128_192::KeyBlockByteSize )
				{
					AES_128_192.EncryptionWithECB( In, Keys, Out );
				}
				else if ( Keys.size() == Cipher128_256::KeyBlockByteSize )
				{
					AES_128_256.EncryptionWithECB( In, Keys, Out );
				}
				else
				{
					my_cpp2020_assert( false, "OMAC2: invalid AES key length (must be 16/24/32 bytes)", std::source_location::current() );
				}

				::memcpy( OutputBlock.data(), Out.data(), Out.size() );
			}

			// === Subkey derivation per Fig. 5 (no abbreviations) ===
			// Input : K (the main AES key, 128/192/256 bits)
			// Output: K1 = L · u    and    K2 = L · u^{-1}
			void Generate_Subkeys_From_Fig5( std::span<const std::uint8_t> Keys )
			{
				// Step: L ← E(K, 0^n), where n = 128
				std::array<std::uint8_t, BlockCipher128_128::DataBlockByteSize> ZeroBlock {};
				std::array<std::uint8_t, BlockCipher128_128::DataBlockByteSize> L {};
				EncryptBlock_EK( ZeroBlock, Keys, L );

				// Constants exactly as Fig. 5 (n = 128)
				// Constant  (for left shift branch, i.e., multiplication by u)
				constexpr std::array<std::uint8_t, 16> DoublingConstant_Left { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };
				// Constant' (for right shift branch, i.e., multiplication by u^{-1})
				constexpr std::array<std::uint8_t, 16> DoublingConstant_Right { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43 };

				// K1 = L · u : if msb(L)=0 then K1 = L << 1; else K1 = (L << 1) XOR Constant
				K1_128Bit.resize( 16 );
				if ( ( L[ 0 ] & 0x80 ) == 0 )
				{
					LeftShift_OneBit( L, K1_128Bit );
				}
				else
				{
					LeftShift_OneBit( L, K1_128Bit );
					for ( std::size_t i = 0; i < 16; ++i )
						K1_128Bit[ i ] ^= DoublingConstant_Left[ i ];
				}

				// K2 = L · u^{-1} : if lsb(L)=0 then K2 = L >> 1; else K2 = (L >> 1) XOR Constant'
				K2_128Bit.resize( 16 );
				if ( ( L[ 15 ] & 0x01 ) == 0 )
				{
					RightShift_OneBit( L, K2_128Bit );
				}
				else
				{
					RightShift_OneBit( L, K2_128Bit );
					for ( std::size_t i = 0; i < 16; ++i )
						K2_128Bit[ i ] ^= DoublingConstant_Right[ i ];
				}
			}

		public:
			// === Initialize ===
			// Input : Keys = K (128/192/256-bit AES key)
			// Effect: Derive K1 and K2 as per Fig. 5; set Y[0] = 0^n; clear X
			void Initialize( std::span<const std::uint8_t> Keys )
			{
				if ( Keys.size() != 16 && Keys.size() != 24 && Keys.size() != 32 )
					my_cpp2020_assert( false, "OMAC2.Initialize: key must be 16/24/32 bytes (AES-128/192/256)", std::source_location::current() );

				MainKey.assign( Keys.begin(), Keys.end() );

				// Derive subkeys per Fig. 5 (strict)
				Generate_Subkeys_From_Fig5( MainKey );

				// Y[0] ← 0^n
				std::fill( Y_Block.begin(), Y_Block.end(), 0 );
				std::fill( X_Block.begin(), X_Block.end(), 0 );

				IsInitialized = true;
			}

			// Effect: Process M[1..m-1]: Y[i] ← E(K, M[i] XOR Y[i−1]).
			//         Prepare X[m] according to the two branches in Fig. 5:
			//           - If |M[m]| = n      : X[m] ← M[m] XOR Y[m−1] XOR (L · u)
			//           - If |M[m]| < n      : X[m] ← (M[m]10^{n−1−|M[m]|}) XOR Y[m−1] XOR (L · u^{-1})
			void Update(std::span<const std::uint8_t> Ciphertext)
			{
				if (!IsInitialized)
					return;

				// --- rename ugly locals to readable names ---
				const std::size_t block_size = BlockCipher128_256::DataBlockByteSize; // n = 16 bytes
				const std::size_t message_len = Ciphertext.size();

				// number of blocks (ceiling)
				const std::size_t num_blocks = (message_len + block_size - 1) / block_size;
				// number of full blocks before the last block (may be zero)
				const std::size_t num_full_blocks_before_last = (num_blocks >= 1 ? num_blocks - 1 : 0);

				// Local alias to original members to avoid global renaming of class fields.
				// This provides nicer local variable names while keeping X_Block/Y_Block as class members.
				auto &X = X_Block; // previously X_Block
				auto &Y = Y_Block; // previously Y_Block

				// For i = 1 .. m-1: Y[i] = E(K, M[i] XOR Y[i-1])
				for (std::size_t block_index = 0; block_index < num_full_blocks_before_last; ++block_index)
				{
					const std::uint8_t* current_block_ptr = &Ciphertext[block_index * block_size];
					for (std::size_t byte_index = 0; byte_index < block_size; ++byte_index)
						X[byte_index] = current_block_ptr[byte_index] ^ Y[byte_index];

					// Encrypt X with E_K and store into Y (Y <- E(K, X))
					EncryptBlock_EK(X, MainKey, Y);
				}

				// --- construct X[m] according to Fig.5 (two branches) ---
				if (message_len == 0)
				{
					// Case: |M[m]| = 0 (< n)
					// X[m] <- (0x80 || 0x00...0) XOR Y[m-1] XOR (L · u^{-1})
					std::array<std::uint8_t, 16> Padded{};
					Padded[0] = 0x80;
					for (std::size_t b = 0; b < block_size; ++b)
						X[b] = Padded[b] ^ Y[b];
					for (std::size_t b = 0; b < block_size; ++b)
						X[b] ^= K2_128Bit[b]; // XOR L·u^{-1}
					return;
				}

				const std::size_t last_offset = (num_blocks - 1) * block_size;
				const std::size_t last_length = message_len - last_offset;

				if (last_length == block_size)
				{
					// Case: |M[m]| = n  (last block is full block)
					// X[m] <- M[m] XOR Y[m-1] XOR (L · u)
					const std::uint8_t* last_block_ptr = &Ciphertext[last_offset];
					for (std::size_t b = 0; b < block_size; ++b)
						X[b] = (last_block_ptr[b] ^ Y[b]) ^ K1_128Bit[b];
				}
				else
				{
					// Case: |M[m]| < n  (last block is partial)
					// X[m] <- (M[m] || 0x80 || 0x00...) XOR Y[m-1] XOR (L · u^{-1})
					std::array<std::uint8_t, 16> Padded{};
					for (std::size_t b = 0; b < last_length; ++b)
						Padded[b] = Ciphertext[last_offset + b];
					Padded[last_length] = 0x80;
					for (std::size_t b = 0; b < block_size; ++b)
						X[b] = Padded[b] ^ Y[b];
					for (std::size_t b = 0; b < block_size; ++b)
						X[b] ^= K2_128Bit[b];
				}
			}

			// === Finish ===
			// Input : AuthenticationTag (output buffer for tag T, 16 bytes; caller may truncate to t bits)
			// Effect: T ← E(K, X[m]); write to AuthenticationTag; reset internal state
			void Finish( std::span<std::uint8_t> AuthenticationTag )
			{
				if ( !IsInitialized )
					return;

				if ( AuthenticationTag.size() < BlockCipher128_256::DataBlockByteSize )
					my_cpp2020_assert( false, "OMAC2.Finish: tag buffer must be at least 16 bytes", std::source_location::current() );

				EncryptBlock_EK( X_Block, MainKey, AuthenticationTag.subspan( 0, 16 ) );

				// If caller wants t-bit truncation, they should truncate AuthenticationTag accordingly.

				this->Reset();
			}

			void Reset()
			{
				memory_set_no_optimize_function<0x00>( K1_128Bit.data(), K1_128Bit.size() );
				memory_set_no_optimize_function<0x00>( K2_128Bit.data(), K2_128Bit.size() );
				memory_set_no_optimize_function<0x00>( X_Block.data(), X_Block.size() );
				memory_set_no_optimize_function<0x00>( Y_Block.data(), Y_Block.size() );
				memory_set_no_optimize_function<0x00>( MainKey.data(), MainKey.size() );
				MainKey.clear();
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
		std::vector<std::uint8_t> MainKey; // 保存 K（16/24/32 字节）
		CommonSecurity::AES::DataWorker128 AES_128_128;
		CommonSecurity::AES::DataWorker192 AES_128_192;
		CommonSecurity::AES::DataWorker256 AES_128_256;

		std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> NumberOnceTag {};
		std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> AssociativeDataTag {};

		bool ProvidedData = false;

		void CounterMode_128_256(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if(Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is not empty!", std::source_location::current());
			if(Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is not empty", std::source_location::current());
			constexpr std::size_t KeyBlockBytes = 32;
			if ( ( BytesKey.size() % KeyBlockBytes != 0 ) && ( !BytesKey.empty() ) )
				my_cpp2020_assert(false, "Error: The key data block size is not a multiple of 256 bits!", std::source_location::current());
			if(Input.size() != Output.size())
				my_cpp2020_assert(false ,"Error: The input data block size and the output data block size are not equal!", std::source_location::current());
			
			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

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
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan(KeyOffset, KeyBlockBytes);

				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(BlockCipher128_256::DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(BlockCipher128_256::DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				//AES-256
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

					std::array<uint8_t, 16> Seed128Bit {};
					auto PRNG_SeedBytes = CommonToolkit::value_to_bytes<uint64_t,uint8_t>(PRNG_Seed);
					auto PRNG_Seed2Bytes = CommonToolkit::value_to_bytes<uint64_t,uint8_t>(PRNG_Seed2);
					std::memcpy(Seed128Bit.data(), PRNG_SeedBytes.data(), 8);
					std::memcpy(Seed128Bit.data()+8, PRNG_Seed2Bytes.data(), 8);

					// Re-generate NumberOncePart deterministically using PRF (domain-separated)
					// (We cannot call UniformInteger(PRNG) here because PRNG isn't present in this variant.)
					const uint8_t domainR[1] = { 0x52 }; // different domain label for reseed ('R')
					auto GeneratedPRF_Bytes2 = TinySpongeFunction128::PRF(
						BytesKey,
						std::span<const std::uint8_t>( Seed128Bit.data(), Seed128Bit.size() ),
						std::span<const std::uint8_t>( domainR, 1 )
					);
					NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>( std::span<const std::uint8_t>( GeneratedPRF_Bytes2.data(), 8 ) );
					memory_set_no_optimize_function<0x00>(Seed128Bit.data(), Seed128Bit.size());
					memory_set_no_optimize_function<0x00>(GeneratedPRF_Bytes2.data(), GeneratedPRF_Bytes2.size());
				}
				else if(SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL)
				{
					KeyOffset += KeyBlockBytes;
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				//Accumulation counter
				++CounterPart;
			}
		}

		void CounterMode_128_192( std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output )
		{
			if ( Input.empty() )
				my_cpp2020_assert( false, "Error: The input data size is not empty!", std::source_location::current() );
			if ( Output.empty() )
				my_cpp2020_assert( false, "Error: The output data size is not empty", std::source_location::current() );
			// 192-bit key blocks
			constexpr std::size_t KeyBlockBytes = 24;
			if ( ( BytesKey.size() % KeyBlockBytes != 0 ) && ( !BytesKey.empty() ) )
				my_cpp2020_assert( false, "Error: The key data block size is not a multiple of 192 bits!", std::source_location::current() );
			if ( Input.size() != Output.size() )
				my_cpp2020_assert( false, "Error: The input data block size and the output data block size are not equal!", std::source_location::current() );

			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;
			CommonSecurity::RegenerateSeeds( BytesKey, PRNG_Seed, PRNG_Seed2 );

			std::span<std::uint8_t> OriginalCounterBlock { NumberOnceTag.begin(), NumberOnceTag.end() };
			std::uint64_t			NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>( OriginalCounterBlock.subspan( 0, 8 ) );
			std::uint64_t			CounterPart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>( OriginalCounterBlock.subspan( 8, 8 ) );

			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> KeyStream {};

			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for ( std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += BlockCipher128_256::DataBlockByteSize )
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan( KeyOffset, KeyBlockBytes );

				std::span<const std::uint8_t> InputDataBlock = Input.subspan( DataOffset, ::std::min<std::size_t>( BlockCipher128_256::DataBlockByteSize, Input.size() - DataOffset ) );
				std::span<std::uint8_t>		  OutputDataBlock = Output.subspan( DataOffset, ::std::min<std::size_t>( BlockCipher128_256::DataBlockByteSize, Output.size() - DataOffset ) );

				// Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>( NumberOncePart );
				::memcpy( CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size() );

				// Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>( CounterPart );
				::memcpy( CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size() );

				// AES-192
				AES_128_192.KeyExpansion( KeyBlock );
				AES_128_192.ProcessBlockEncryption( CounterBlock, KeyStream );

				for ( std::size_t Index = 0; Index < InputDataBlock.size(); ++Index )
					OutputDataBlock[ Index ] = KeyStream[ Index ] ^ InputDataBlock[ Index ];

				if ( SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0 )
				{
					++SanityCounterLow;
				}
				else if ( SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0 )
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					std::array<uint8_t, 16> Seed128Bit {};
					auto					PRNG_SeedBytes = CommonToolkit::value_to_bytes<uint64_t, uint8_t>( PRNG_Seed );
					auto					PRNG_Seed2Bytes = CommonToolkit::value_to_bytes<uint64_t, uint8_t>( PRNG_Seed2 );
					std::memcpy( Seed128Bit.data(), PRNG_SeedBytes.data(), 8 );
					std::memcpy( Seed128Bit.data() + 8, PRNG_Seed2Bytes.data(), 8 );

					const uint8_t domainR[ 1 ] = { 0x52 };	// reseed domain label
					auto		  GeneratedPRF_Bytes2 = TinySpongeFunction128::PRF( BytesKey, std::span<const std::uint8_t>( Seed128Bit.data(), Seed128Bit.size() ), std::span<const std::uint8_t>( domainR, 1 ) );
					NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>( std::span<const std::uint8_t>( GeneratedPRF_Bytes2.data(), 8 ) );
					memory_set_no_optimize_function<0x00>( Seed128Bit.data(), Seed128Bit.size() );
					memory_set_no_optimize_function<0x00>( GeneratedPRF_Bytes2.data(), GeneratedPRF_Bytes2.size() );
				}
				else if ( SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL )
				{
					KeyOffset += KeyBlockBytes;	 // roll to next 192-bit key block
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				++CounterPart;	// Accumulation counter (low 64 bits)
			}
		}

		void CounterMode_128_128( std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output )
		{
			if ( Input.empty() )
				my_cpp2020_assert( false, "Error: The input data size is not empty!", std::source_location::current() );
			if ( Output.empty() )
				my_cpp2020_assert( false, "Error: The output data size is not empty", std::source_location::current() );
			// 128-bit key blocks
			constexpr std::size_t KeyBlockBytes = 16;
			if ( ( BytesKey.size() % KeyBlockBytes != 0 ) && ( !BytesKey.empty() ) )
				my_cpp2020_assert( false, "Error: The key data block size is not a multiple of 128 bits!", std::source_location::current() );
			if ( Input.size() != Output.size() )
				my_cpp2020_assert( false, "Error: The input data block size and the output data block size are not equal!", std::source_location::current() );

			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;
			CommonSecurity::RegenerateSeeds( BytesKey, PRNG_Seed, PRNG_Seed2 );

			std::span<std::uint8_t> OriginalCounterBlock { NumberOnceTag.begin(), NumberOnceTag.end() };
			std::uint64_t			NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>( OriginalCounterBlock.subspan( 0, 8 ) );
			std::uint64_t			CounterPart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>( OriginalCounterBlock.subspan( 8, 8 ) );

			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> KeyStream {};

			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for ( std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += BlockCipher128_256::DataBlockByteSize )
			{
				std::span<const std::uint8_t> KeyBlock = BytesKey.subspan( KeyOffset, KeyBlockBytes );

				std::span<const std::uint8_t> InputDataBlock = Input.subspan( DataOffset, ::std::min<std::size_t>( BlockCipher128_256::DataBlockByteSize, Input.size() - DataOffset ) );
				std::span<std::uint8_t>		  OutputDataBlock = Output.subspan( DataOffset, ::std::min<std::size_t>( BlockCipher128_256::DataBlockByteSize, Output.size() - DataOffset ) );

				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>( NumberOncePart );
				::memcpy( CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size() );

				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>( CounterPart );
				::memcpy( CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size() );

				// AES-128
				AES_128_128.KeyExpansion( KeyBlock );
				AES_128_128.ProcessBlockEncryption( CounterBlock, KeyStream );

				for ( std::size_t Index = 0; Index < InputDataBlock.size(); ++Index )
					OutputDataBlock[ Index ] = KeyStream[ Index ] ^ InputDataBlock[ Index ];

				if ( SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 != 0 )
				{
					++SanityCounterLow;
				}
				else if ( SanityCounterHigh != std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == 0 )
				{
					++SanityCounterHigh;
					SanityCounterLow = 0;

					std::array<uint8_t, 16> Seed128Bit {};
					auto					PRNG_SeedBytes = CommonToolkit::value_to_bytes<uint64_t, uint8_t>( PRNG_Seed );
					auto					PRNG_Seed2Bytes = CommonToolkit::value_to_bytes<uint64_t, uint8_t>( PRNG_Seed2 );
					std::memcpy( Seed128Bit.data(), PRNG_SeedBytes.data(), 8 );
					std::memcpy( Seed128Bit.data() + 8, PRNG_Seed2Bytes.data(), 8 );

					const uint8_t domainR[ 1 ] = { 0x52 };
					auto		  GeneratedPRF_Bytes2 = TinySpongeFunction128::PRF( BytesKey, std::span<const std::uint8_t>( Seed128Bit.data(), Seed128Bit.size() ), std::span<const std::uint8_t>( domainR, 1 ) );
					NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>( std::span<const std::uint8_t>( GeneratedPRF_Bytes2.data(), 8 ) );
					memory_set_no_optimize_function<0x00>( Seed128Bit.data(), Seed128Bit.size() );
					memory_set_no_optimize_function<0x00>( GeneratedPRF_Bytes2.data(), GeneratedPRF_Bytes2.size() );
				}
				else if ( SanityCounterHigh == std::numeric_limits<std::uint64_t>::max() && SanityCounterLow + 1 == std::numeric_limits<std::uint64_t>::max() / 1048576ULL * 1048575ULL )
				{
					KeyOffset += KeyBlockBytes;	 // roll to next 128-bit key block
					SanityCounterHigh = 0;
					SanityCounterLow = 0;
				}

				++CounterPart;
			}
		}

	public:
		void Initialize( std::span<const std::uint8_t> KeyStream, std::span<const std::uint8_t> NumberOnce, std::span<const std::uint8_t> AssociativeData )
		{
			//EAX - The Encrypt then authenticate then translate

			if ( !( KeyStream.size() == 16 || KeyStream.size() == 24 || KeyStream.size() == 32 ) )
				my_cpp2020_assert( false, "EAX.Initialize: key must be 16/24/32 bytes.", std::source_location::current() );
			MainKey.assign( KeyStream.begin(), KeyStream.end() );

			// EAX 的 OMAC 域分离：0x00 for N，0x01 for H
			OMAC2 OMAC2_Object {};

			// N* = OMAC^0_K(N)
			//NumberOnce' = OMAC(Key2, NumberOnce)
			OMAC2_Object.Initialize( MainKey );
			const uint8_t domain_nonce = 0x00;
			OMAC2_Object.Update( std::span<const uint8_t>( &domain_nonce, 1 ) );
			OMAC2_Object.Update( NumberOnce );
			OMAC2_Object.Finish( NumberOnceTag );

			// H* = OMAC^1_K(H)
			// AdditionalHeaderData' = OMAC(Key2, AssociativeHeaderData)
			OMAC2_Object.Initialize( MainKey );
			const uint8_t domain_aad = 0x01;
			OMAC2_Object.Update( std::span<const uint8_t>( &domain_aad, 1 ) );
			OMAC2_Object.Update( AssociativeData );
			OMAC2_Object.Finish( AssociativeDataTag );

			ProvidedData = true;
		}

		void Encryption( std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<std::uint8_t> AuthenticationTag ) override
		{
			if ( !ProvidedData )
				return;

			// 1) C = CTR_K(N*) (M)
			if ( MainKey.size() == BlockCipher128_128::KeyBlockByteSize )
			{
				CounterMode_128_128( AllInputData, MainKey, AllOutputData );
			}
			else if ( MainKey.size() == BlockCipher128_192::KeyBlockByteSize )
			{
				CounterMode_128_192( AllInputData, MainKey, AllOutputData );
			}
			else if ( MainKey.size() == BlockCipher128_256::KeyBlockByteSize )
			{
				CounterMode_128_256( AllInputData, MainKey, AllOutputData );
			}
			else
			{
				my_cpp2020_assert( false, "EAX.Encryption: invalid AES key length (16/24/32).", std::source_location::current() );
			}

			// 2) C* = OMAC^2_K(C) （域 0x02）
			OMAC2 OMAC2_Object {};
			OMAC2_Object.Initialize( MainKey );
			const uint8_t domain_ct = 0x02;
			OMAC2_Object.Update( std::span<const uint8_t>( &domain_ct, 1 ) );
			OMAC2_Object.Update( AllOutputData );
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> DataTag {};
			OMAC2_Object.Finish( DataTag );

			// 3) Tag = N* XOR H* XOR C*
			for ( std::uint8_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i )
				AuthenticationTag[ i ] = NumberOnceTag[ i ] ^ AssociativeDataTag[ i ] ^ DataTag[ i ];

			// 清理临时与状态
			memory_set_no_optimize_function<0x00>( NumberOnceTag.data(), NumberOnceTag.size() );
			memory_set_no_optimize_function<0x00>( AssociativeDataTag.data(), AssociativeDataTag.size() );

			ProvidedData = false;
		}

		void Decryption( std::span<const std::uint8_t> AllInputData, std::span<std::uint8_t> AllOutputData, std::span<const std::uint8_t> AuthenticationTag ) override
		{
			if ( !ProvidedData )
				return;

			// 1) 计算 C* = OMAC^2_K(C) （域 0x02）
			OMAC2 OMAC2_Object {};
			OMAC2_Object.Initialize( MainKey );
			const uint8_t domain_ct = 0x02;
			OMAC2_Object.Update( std::span<const uint8_t>( &domain_ct, 1 ) );
			OMAC2_Object.Update( AllInputData );
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> DataTag {};
			OMAC2_Object.Finish( DataTag );

			// 2) 组装期望标签 T' = N* XOR H* XOR C*
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ThisAuthenticationTag {};
			for ( std::uint8_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i )
				ThisAuthenticationTag[ i ] = NumberOnceTag[ i ] ^ AssociativeDataTag[ i ] ^ DataTag[ i ];

			uint8_t diff = 0;
			for ( std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i )
				diff |= static_cast<uint8_t>( ThisAuthenticationTag[ i ] ^ AuthenticationTag[ i ] );

			ProvidedData = false;

			if ( diff != 0 )
			{
				my_cpp2020_assert( false, "EAX: authentication failed; ciphertext or tag is invalid.", std::source_location::current() );
			}

			// M = CTR_K(N*)^{-1} (C)
			if ( MainKey.size() == BlockCipher128_128::KeyBlockByteSize )
			{
				CounterMode_128_128( AllInputData, MainKey, AllOutputData );
			}
			else if ( MainKey.size() == BlockCipher128_192::KeyBlockByteSize )
			{
				CounterMode_128_192( AllInputData, MainKey, AllOutputData );
			}
			else if ( MainKey.size() == BlockCipher128_256::KeyBlockByteSize )
			{
				CounterMode_128_256( AllInputData, MainKey, AllOutputData );
			}
			else
			{
				my_cpp2020_assert( false, "EAX.Decryption: invalid AES key length (16/24/32).", std::source_location::current() );
			}

			memory_set_no_optimize_function<0x00>( NumberOnceTag.data(), NumberOnceTag.size() );
			memory_set_no_optimize_function<0x00>( AssociativeDataTag.data(), AssociativeDataTag.size() );
		}

		EAX() = default;
		virtual ~EAX() = default;
	};

	class SIV : public DependentType
	{
		
	private:
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
		void BinaryStringToVector
		(
			std::span<const std::uint8_t>& Keys,
			std::vector<std::uint8_t>& AssociativeData,
			std::span<const std::uint8_t> Plaintext,
			std::span<std::uint8_t> SyntheticInitializationVector
		)
		{
			CMAC_Router CMAC_Pointer( false );

			/* RFC 5297 S2V pseudocode (n == number of strings):
			   if n = 0 then
				   return V = AES-CMAC(K, <one>)
			   DATA_BLOCK = AES-CMAC(K, <zero>)
			   for i = 1 to n-1 do
				   DATA_BLOCK = doubling(DATA_BLOCK) xor AES-CMAC(K, AD[i])
			   if length(Sn) >= 128 then
				   T = Sn xorend DATA_BLOCK
			   else
				   T = doubling(DATA_BLOCK) xor pad(Sn)
			   return V = AES-CMAC(K, T)
			   (Here, AD[*] are the associated-data strings; Sn is the Plaintext.) 
			   */  
			/* RFC 5297 §2.4 */

			/* Special-case: no AD and no Plaintext → V = CMAC(K, <one>) */
			if ( AssociativeData.empty() && Plaintext.empty() )
			{
				/* <one> = 0^127 || 1 */
				const std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> OneData
				{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };

				CMAC_Pointer.Initialize( Keys );
				CMAC_Pointer.Update( OneData );
				CMAC_Pointer.Finish( SyntheticInitializationVector );
				return;
			}

			/* DATA_BLOCK = AES-CMAC(K, <zero>) */
			const std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ZeroData
			{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> DataBlock {};
			CMAC_Pointer.Initialize( Keys );
			CMAC_Pointer.Update( ZeroData );
			CMAC_Pointer.Finish( DataBlock );

			/* for i = 1 to n-1:
			   Fold each AD[i] (here we segment AssociativeData by 16-byte blocks;
			   the final partial block (if any) is hashed with its ACTUAL length,
			   not zero-padded—CMAC does its own padding per RFC 4493). 
			*/
			/* RFC 4493 §2.3 */
			if ( !AssociativeData.empty() )
			{
				constexpr std::uint8_t MSB_MASK = 0x80;
				constexpr std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> Rb
				{
					/* Rb for GF(2^128) doubling constant in CMAC: 0x87 in the LSB byte */   /* RFC 4493 §2.3 */
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x87
				};

				constexpr std::size_t BlockSize  = BlockCipher128_256::DataBlockByteSize; // 16
				const std::size_t     TotalBlocks = (AssociativeData.size() + BlockSize - 1) / BlockSize; // ceil

				std::array<std::uint8_t, BlockSize> CMAC_AD {};
				std::array<std::uint8_t, BlockSize> dblBuf  {};

				for ( std::size_t BlockIndex = 0; BlockIndex < TotalBlocks; ++BlockIndex )
				{
					/* ---- doubling(DATA_BLOCK) ---- */
					if ( ( DataBlock[0] & MSB_MASK ) == 0 )
					{
						LeftShift_OneBit( DataBlock, dblBuf );                 /* left shift by 1 bit */
					}
					else
					{
						LeftShift_OneBit( DataBlock, dblBuf );
						dblBuf[ BlockSize - 1 ] ^= Rb[ BlockSize - 1 ];        /* xor Rb (0x87) if msb set */
					}
					std::memcpy( DataBlock.data(), dblBuf.data(), BlockSize );

					/* ---- CMAC(K, AD[i]) over the EXACT bytes of this segment ----
					   offset = i*16; len = min(16, remaining); DO NOT zero-pad here,
					   pass the actual length to CMAC so that RFC-4493 padding occurs internally.
					*/
					const std::size_t offset = BlockIndex * BlockSize;
					const std::size_t length    = std::min<std::size_t>( BlockSize, AssociativeData.size() - offset );

					CMAC_Pointer.Initialize( Keys );
					CMAC_Pointer.Update( std::span<const std::uint8_t>( AssociativeData.data() + offset, length ) );
					CMAC_Pointer.Finish( CMAC_AD );

					/* ---- DATA_BLOCK ^= CMAC_AD ---- */
					for ( std::size_t i = 0; i < BlockSize; ++i )
						DataBlock[ i ] ^= CMAC_AD[ i ];
				}
			}

			/* Final string Sn is Plaintext.
			   If |Sn| >= 128 bits: T = Sn xorend DATA_BLOCK, else T = doubling(DATA_BLOCK) xor pad(Sn).
			*/
			/* RFC 5297 §2.4 */
			if ( Plaintext.size() >= BlockCipher128_256::DataBlockByteSize )
			{
				/* xorend: XOR only the LAST 16 bytes of Sn with DATA_BLOCK */
				std::vector<std::uint8_t> T( Plaintext.begin(), Plaintext.end() );
				const std::size_t base = T.size() - BlockCipher128_256::DataBlockByteSize;
				for ( std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i )
					T[ base + i ] ^= DataBlock[ i ];

				/* V = AES-CMAC(K, T) */
				CMAC_Pointer.Initialize( Keys );
				CMAC_Pointer.Update( std::span<const std::uint8_t>( T.data(), T.size() ) );
				CMAC_Pointer.Finish( SyntheticInitializationVector );
			}
			else
			{
				/* doubling(DATA_BLOCK) for the short-final-string case */
				constexpr std::uint8_t MSB_MASK = 0x80;
				constexpr std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> Rb
				{
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x87
				};

				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> K1 {};
				if ( ( DataBlock[0] & MSB_MASK ) == 0 )
				{
					LeftShift_OneBit( DataBlock, K1 );
				}
				else
				{
					LeftShift_OneBit( DataBlock, K1 );
					K1[ BlockCipher128_256::DataBlockByteSize - 1 ] ^= Rb[ BlockCipher128_256::DataBlockByteSize - 1 ];
				}

				/* pad(Sn) = Sn || 0x80 || 0x00... up to 16 bytes (CMAC-style one-zero padding) */
				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> Padded {};
				for ( std::size_t i = 0; i < Plaintext.size(); ++i )
					Padded[ i ] = Plaintext[ i ];
				if ( Plaintext.size() < BlockCipher128_256::DataBlockByteSize )
					Padded[ Plaintext.size() ] = 0x80;

				/* T = doubling(DATA_BLOCK) xor pad(Sn) */
				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> T {};
				for ( std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i )
					T[ i ] = static_cast<std::uint8_t>( K1[ i ] ^ Padded[ i ] );

				/* V = AES-CMAC(K, T) */
				CMAC_Pointer.Initialize( Keys );
				CMAC_Pointer.Update( T );
				CMAC_Pointer.Finish( SyntheticInitializationVector );
			}
		}

		std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> Q_Block {};
		void CounterMode(std::span<const std::uint8_t> Input, std::span<const std::uint8_t> BytesKey, std::span<std::uint8_t> Output)
		{
			if (Input.empty())
				my_cpp2020_assert(false, "Error: The input data size is empty!", std::source_location::current());
			if (Output.empty())
				my_cpp2020_assert(false, "Error: The output data size is empty!", std::source_location::current());
			if (Input.size() != Output.size())
				my_cpp2020_assert(false, "Error: The input data block size and the output data block size are not equal!", std::source_location::current());

			std::uint64_t PRNG_Seed = 0, PRNG_Seed2 = 0;

			CommonSecurity::RegenerateSeeds(BytesKey, PRNG_Seed, PRNG_Seed2);

			std::span<std::uint8_t> OriginalCounterBlock{Q_Block.begin(), Q_Block.end()};
			std::uint64_t NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(OriginalCounterBlock.subspan(0, 8));
			std::uint64_t CounterPart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>(OriginalCounterBlock.subspan(8, 8));
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> CounterBlock {};
			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> KeyStream {};

			const size_t bsz = BytesKey.size();
			size_t		 key_block_len = 0;
			if ( ( bsz % BlockCipher128_256::KeyBlockByteSize ) == 0 )
				key_block_len = BlockCipher128_256::KeyBlockByteSize;
			else if ( ( bsz % BlockCipher128_192::KeyBlockByteSize ) == 0 )
				key_block_len = BlockCipher128_192::KeyBlockByteSize;
			else if ( ( bsz % BlockCipher128_128::KeyBlockByteSize ) == 0 )
				key_block_len = BlockCipher128_128::KeyBlockByteSize;
			else
				key_block_len = 0;
			size_t num_keys = ( key_block_len == 0 ) ? 0 : ( bsz / key_block_len );

			//How many times has the keystream been generated?
			std::uint64_t SanityCounterHigh = 0;
			std::uint64_t SanityCounterLow = 0;

			for(std::uint64_t DataOffset = 0, KeyOffset = 0; DataOffset < Input.size() && KeyOffset < BytesKey.size(); DataOffset += BlockCipher128_256::DataBlockByteSize)
			{
				std::span<const std::uint8_t> InputDataBlock = Input.subspan(DataOffset, ::std::min<std::size_t>(BlockCipher128_256::DataBlockByteSize, Input.size() - DataOffset));
				std::span<std::uint8_t> OutputDataBlock = Output.subspan(DataOffset, ::std::min<std::size_t>(BlockCipher128_256::DataBlockByteSize, Output.size() - DataOffset));

				//Build counter block (Number once part)
				auto NumberOncePartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(NumberOncePart);
				::memcpy(CounterBlock.data(), NumberOncePartBytes.data(), NumberOncePartBytes.size());

				//Build counter block (Counter part)
				auto CounterPartBytes = CommonToolkit::value_to_bytes<std::uint64_t, std::uint8_t>(CounterPart);
				::memcpy(CounterBlock.data() + 8, CounterPartBytes.data(), CounterPartBytes.size());

				std::span<const std::uint8_t> KeyBlock;
				if ( key_block_len != 0 && num_keys > 0 )
				{
					size_t KeyIndex = ( KeyOffset / key_block_len ) % num_keys;	// safe index
					KeyBlock = BytesKey.subspan( KeyIndex * key_block_len, key_block_len );
				}
				else
				{
					my_cpp2020_assert( bsz == 16 || bsz == 24 || bsz == 32, "SIV Counter Mode: unsupported BytesKey length when not block-multiple.", std::source_location::current() );
					KeyBlock = BytesKey;
				}

				if (KeyBlock.size() == BlockCipher128_256::KeyBlockByteSize)
				{
					CommonSecurity::AES::DataWorker256 AES_128_256;
					AES_128_256.KeyExpansion(KeyBlock);
					AES_128_256.ProcessBlockEncryption(CounterBlock, KeyStream);
				}
				else if (KeyBlock.size() == BlockCipher128_192::KeyBlockByteSize)
				{
					CommonSecurity::AES::DataWorker192 AES_128_192;
					AES_128_192.KeyExpansion(KeyBlock);
					AES_128_192.ProcessBlockEncryption(CounterBlock, KeyStream);
				}
				else if (KeyBlock.size() == BlockCipher128_128::KeyBlockByteSize)
				{
					CommonSecurity::AES::DataWorker128 AES_128_128;
					AES_128_128.KeyExpansion(KeyBlock);
					AES_128_128.ProcessBlockEncryption(CounterBlock, KeyStream);
				}
				else
				{
					my_cpp2020_assert(false, "SIV - Counter Mode: invalid AES key length (16/24/32).", std::source_location::current());
				}
					
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

					std::array<uint8_t, 16> Seed128Bit {};
					auto PRNG_SeedBytes = CommonToolkit::value_to_bytes<uint64_t,uint8_t>(PRNG_Seed);
					auto PRNG_Seed2Bytes = CommonToolkit::value_to_bytes<uint64_t,uint8_t>(PRNG_Seed2);
					std::memcpy(Seed128Bit.data(), PRNG_SeedBytes.data(), 8);
					std::memcpy(Seed128Bit.data()+8, PRNG_Seed2Bytes.data(), 8);

					// Re-generate NumberOncePart deterministically using PRF (domain-separated)
					// (We cannot call UniformInteger(PRNG) here because PRNG isn't present in this variant.)
					const uint8_t domainR[1] = { 0x52 }; // different domain label for reseed ('R')
					auto GeneratedPRF_Bytes2 = TinySpongeFunction128::PRF(
						BytesKey,
						std::span<const std::uint8_t>( Seed128Bit.data(), Seed128Bit.size() ),
						std::span<const std::uint8_t>( domainR, 1 )
					);
					NumberOncePart = CommonToolkit::value_from_bytes<std::uint64_t, std::uint8_t>( std::span<const std::uint8_t>( GeneratedPRF_Bytes2.data(), 8 ) );
					memory_set_no_optimize_function<0x00>(Seed128Bit.data(), Seed128Bit.size());
					memory_set_no_optimize_function<0x00>(GeneratedPRF_Bytes2.data(), GeneratedPRF_Bytes2.size());
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
					X[i] = AES_CTR(K2, Q[i])
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
			this->BinaryStringToVector(KeysPart1, AssociativeData, AllInputData, AuthenticationTag);

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

			CounterMode(X_Block, KeysPart2, X_Block);

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
					Xi = AES_CTR(K2, Q[i])
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

			CounterMode(X_Block, KeysPart2, X_Block);

			//P = C xor X
			for(std::size_t Index = 0; Index < X_Block.size(); ++Index)
			{
				AllOutputData[Index] = AllInputData[Index] ^ X_Block[Index];
			}

			std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> ThisAuthenticationTag {};
			//The V_Block is the synthetic initialization vector (AuthenticationTag)
			this->BinaryStringToVector(KeysPart1, AssociativeData, AllOutputData, ThisAuthenticationTag);

			ProvidedData = false;

			memory_set_no_optimize_function<0x00>(AssociativeData.data(), AssociativeData.size());

			uint8_t diff = 0;
			for (std::size_t i = 0; i < BlockCipher128_256::DataBlockByteSize; ++i)
				diff |= static_cast<uint8_t>(ThisAuthenticationTag[i] ^ AuthenticationTag[i]);
			
			if (diff != 0)
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

		void DoubleTransform(std::span<uint32_t> Output, std::span<const uint32_t> Input)
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
			DoubleTransform(L, L_Dollar);
			while ((Index & 0x01) == 0)
			{
				DoubleTransform(L, L);
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
			// Calculate L_dollar = DOUBLE_TRRANSFORM(L_star)
			CommonToolkit::MessagePacking<std::uint32_t, std::uint8_t>(L, L_Word.data());
			DoubleTransform(DoubleL_Word, L_Word);

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

				std::array<uint8_t, 16> Seed128Bit {};
				auto PRNG_SeedBytes = CommonToolkit::value_to_bytes<uint64_t,uint8_t>(PRNG_Seed);
				auto PRNG_Seed2Bytes = CommonToolkit::value_to_bytes<uint64_t,uint8_t>(PRNG_Seed2);
				std::memcpy(Seed128Bit.data(), PRNG_SeedBytes.data(), 8);
				std::memcpy(Seed128Bit.data()+8, PRNG_Seed2Bytes.data(), 8);

				std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize * 32> ThisAssociativeData {};

				auto RemainingKeyStream = KeyStream.subspan(BlockCipher128_256::KeyBlockByteSize, KeyStream.size() - BlockCipher128_256::KeyBlockByteSize);

				if(NumberOnce.empty())
				{
					std::uint64_t PRNG_Seed3 = 0, PRNG_Seed4 = 0;

					CommonSecurity::RegenerateSeeds2(Seed128Bit, PRNG_Seed3, PRNG_Seed4);
					auto PRNG_Seed3Bytes = CommonToolkit::value_to_bytes<uint64_t,uint8_t>(PRNG_Seed3);
					auto PRNG_Seed4Bytes = CommonToolkit::value_to_bytes<uint64_t,uint8_t>(PRNG_Seed4);
					std::memcpy(Seed128Bit.data(), PRNG_Seed3Bytes.data(), 8);
					std::memcpy(Seed128Bit.data()+8, PRNG_Seed4Bytes.data(), 8);

					std::array<std::uint8_t, BlockCipher128_256::DataBlockByteSize> NumberOnceBytes {};
					std::memcpy(NumberOnceBytes.data(), Seed128Bit.data(),BlockCipher128_256::DataBlockByteSize);

					EAX_Pointer->Initialize(RemainingKeyStream, NumberOnceBytes, ThisAssociativeData);

					return EAX_Pointer;
				}

				//This algorithm comes from RC4+
				//(PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5)
				CommonSecurity::RNG_Xorshiro::xorshiro1024 PRNG( (PRNG_Seed << 3) ^ (PRNG_Seed2 >> 5) + (PRNG_Seed2 << 3) ^ (PRNG_Seed >> 5) );
				CommonSecurity::RND::UniformIntegerDistribution<std::uint8_t> UniformIntegerDistribution(0, 255);

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
		
		UniquePasscoderAES passcoder_aes {};
		UniquePasscoderTwofish passcoder_twofish {};
		UniquePasscoderRC6 passcoder_rc6 {};
		UniquePasscoderSM4 passcoder_sm4 {};
		UniquePasscoderSerpent passcoder_serpent {};

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

			HashTokenForDataParameters HashToken_Parameters {};
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

			Scrypt::Algorithm ScryptKeyDerivationFunctionObject {};

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
				CommonSecurity::RegenerateSeeds(this->AssociativeData, PRNG_Seed, PRNG_Seed2);
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
				CommonSecurity::RegenerateSeeds(this->AssociativeData, PRNG_Seed, PRNG_Seed2);
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

			Scrypt::Algorithm ScryptKeyDerivationFunctionObject {};

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
				CommonSecurity::RegenerateSeeds(this->AssociativeData, PRNG_Seed, PRNG_Seed2);
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
				CommonSecurity::RegenerateSeeds(this->AssociativeData, PRNG_Seed, PRNG_Seed2);
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
