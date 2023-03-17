#pragma once

/*
	Reference code:
	https://github.dev/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
	https://github.dev/BLAKE3-team/BLAKE3/blob/master/c/blake3_impl.h
	https://github.dev/BLAKE3-team/BLAKE3/blob/master/c/blake3_impl.c
	https://github.dev/oconnor663/blake3_reference_impl_c/blob/main/reference_impl.c
	https://github.dev/raftario/BLAKE3.NET/blob/master/BLAKE3/BLAKE3.cs
	
	Information:
	The automatic adaptation of the Blake3 hash algorithm for 32-bit and 64-bit systems was modified by Twilight-Dream with reference to the Blake2 hashing algorithm.
	Warning and Caution:
	The results of the Blake3 algorithm hash have been tested in 64 and 32 bit OS mode.
	I may have made a variant of this algorithm, so if you are concerned about this security issue, please do not use it.
	
	信息：
	Blake3哈希算法的32位和64位系统的自动适应，由Twilight-Dream修改，并参考了Blake2哈希算法。
	警告和注意：
	已经在64和32位操作系统模式，进行试验Blake3算法哈希结果。
	我可能做出了该算法的变种，如果你担心这项安全问题，请不要使用它。
*/

// Refactoring core code
namespace CommonSecurity::Blake3
{
	//由Twilight-Dream修改，使用变体模式
	//Modified by Twilight-Dream, using variant mode
	inline constexpr bool UseVariantMode = false;

	//Generated hash size is a 32 byte or 64 byte
	inline constexpr std::size_t BLAKE3_GENERATED_SIZE = (UseVariantMode == true && CURRENT_SYSTEM_BITS == 64) ? 64 : 32;

	//Key size is a 32 byte or 64 byte
	inline constexpr std::size_t BLAKE3_KEY_SIZE = (UseVariantMode == true && CURRENT_SYSTEM_BITS == 64) ? 64 : 32;

	//Hash data block size is a 64 byte or 128 byte
	inline constexpr std::size_t BLAKE3_BLOCK_SIZE = (UseVariantMode == true && CURRENT_SYSTEM_BITS == 64) ? 128 : 64;

	//Hash memory chunk size is 1 kilo-byte
	inline constexpr std::size_t BLAKE3_CHUNK_SIZE = 1024;

	//Hash state flags
	inline constexpr std::uint8_t CHUNK_START = 1 << 0;
	inline constexpr std::uint8_t CHUNK_END = 1 << 1;
	inline constexpr std::uint8_t PARENT = 1 << 2;
	inline constexpr std::uint8_t ROOT = 1 << 3;
	inline constexpr std::uint8_t KEYED_HASH = 1 << 4;
	inline constexpr std::uint8_t DERIVE_KEY_CONTEXT = 1 << 5;
	inline constexpr std::uint8_t DERIVE_KEY_MATERIAL = 1 << 6;
	
	namespace Core
	{
		using HashProviderBaseTools::Blake::HashConstants;
		
		using WordType = std::conditional_t<UseVariantMode == false, CommonToolkit::FourByte, std::conditional_t<CURRENT_SYSTEM_BITS == 32, CommonToolkit::FourByte, CommonToolkit::EightByte>>;

		static constexpr inline WordType LookupInitialVectorValue(std::size_t index)
		{
			return HashConstants<WordType>::INITIAL_VECTOR[index];
		}

		//For each round of hashing execution, the permute table of the message data index
		//对于每一轮散列的执行，信息数据索引的permute表
		static constexpr size_t MESSGAE_INDICES_PERMUTATION[ 16 ] { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

		// The mixing function, HashMixer, which mixes either a column or a diagonal.
		inline void HashMixer
		(
			CommonSecurity::Blake3::Core::WordType state[ 16 ],
			size_t a, size_t b, size_t c, size_t d,
			CommonSecurity::Blake3::Core::WordType message_x,
			CommonSecurity::Blake3::Core::WordType message_y
		)
		{
			using CommonSecurity::Blake3::UseVariantMode;
			using CommonSecurity::Blake3::Core::WordType;

			if constexpr (UseVariantMode == true && std::is_same_v<WordType, CommonToolkit::EightByte> && CURRENT_SYSTEM_BITS == 64)
			{
				state[ a ] = state[ a ] + state[ b ] + message_x;
				state[ d ] = CommonSecurity::Binary_RightRotateMove( state[ d ] ^ state[ a ], 32 );
				state[ c ] = state[ c ] + state[ d ];
				state[ b ] = CommonSecurity::Binary_RightRotateMove( state[ b ] ^ state[ c ], 24 );
				state[ a ] = state[ a ] + state[ b ] + message_y;
				state[ d ] = CommonSecurity::Binary_RightRotateMove( state[ d ] ^ state[ a ], 16 );
				state[ c ] = state[ c ] + state[ d ];
				state[ b ] = CommonSecurity::Binary_RightRotateMove( state[ b ] ^ state[ c ], 63 );
			}
			else
			{
				state[ a ] = state[ a ] + state[ b ] + message_x;
				state[ d ] = CommonSecurity::Binary_RightRotateMove( state[ d ] ^ state[ a ], 16 );
				state[ c ] = state[ c ] + state[ d ];
				state[ b ] = CommonSecurity::Binary_RightRotateMove( state[ b ] ^ state[ c ], 12 );
				state[ a ] = state[ a ] + state[ b ] + message_y;
				state[ d ] = CommonSecurity::Binary_RightRotateMove( state[ d ] ^ state[ a ], 8 );
				state[ c ] = state[ c ] + state[ d ];
				state[ b ] = CommonSecurity::Binary_RightRotateMove( state[ b ] ^ state[ c ], 7 );
			}
		}

		inline void HashRoundFunction( CommonSecurity::Blake3::Core::WordType state[ 16 ], CommonSecurity::Blake3::Core::WordType messages[ 16 ] )
		{
			// Mix the columns.
			HashMixer( state, 0, 4, 8, 12, messages[ 0 ], messages[ 1 ] );
			HashMixer( state, 1, 5, 9, 13, messages[ 2 ], messages[ 3 ] );
			HashMixer( state, 2, 6, 10, 14, messages[ 4 ], messages[ 5 ] );
			HashMixer( state, 3, 7, 11, 15, messages[ 6 ], messages[ 7 ] );

			// Mix the diagonals.
			HashMixer( state, 0, 5, 10, 15, messages[ 8 ], messages[ 9 ] );
			HashMixer( state, 1, 6, 11, 12, messages[ 10 ], messages[ 11 ] );
			HashMixer( state, 2, 7, 8, 13, messages[ 12 ], messages[ 13 ] );
			HashMixer( state, 3, 4, 9, 14, messages[ 14 ], messages[ 15 ] );
		}

		inline void HashPermuteDataFunction( CommonSecurity::Blake3::Core::WordType messages[ 16 ] )
		{
			using CommonSecurity::Blake3::Core::WordType;

			WordType permuted[ 16 ];
			for ( size_t i = 0; i < 16; i++ )
			{
				permuted[ i ] = messages[ MESSGAE_INDICES_PERMUTATION[ i ] ];
			}
			memcpy( messages, permuted, sizeof( permuted ) );
		}

		inline void MainCompressData
		(
			const CommonSecurity::Blake3::Core::WordType chaining_value[ 8 ],
			const CommonSecurity::Blake3::Core::WordType current_block_words[ 16 ],
			uint64_t counter,
			CommonSecurity::Blake3::Core::WordType block_size,
			uint32_t flags,
			CommonSecurity::Blake3::Core::WordType result_words[ 16 ]
		)
		{
			using CommonSecurity::Blake3::Core::WordType;

			CommonSecurity::Blake3::Core::WordType state[ 16 ] =
			{
				chaining_value[ 0 ],
				chaining_value[ 1 ],
				chaining_value[ 2 ],
				chaining_value[ 3 ],
				chaining_value[ 4 ],
				chaining_value[ 5 ],
				chaining_value[ 6 ],
				chaining_value[ 7 ],
				CommonSecurity::Blake3::Core::LookupInitialVectorValue(0),
				CommonSecurity::Blake3::Core::LookupInitialVectorValue(1),
				CommonSecurity::Blake3::Core::LookupInitialVectorValue(2),
				CommonSecurity::Blake3::Core::LookupInitialVectorValue(3), 
				( WordType )counter,
				( WordType )( counter >> 32 ),
				block_size,
				flags,
			};
			CommonSecurity::Blake3::Core::WordType block[ 16 ];
			memcpy( block, current_block_words, sizeof( block ) );

			HashRoundFunction( state, block );	 // round 1
			HashPermuteDataFunction( block );
			HashRoundFunction( state, block );	 // round 2
			HashPermuteDataFunction( block );
			HashRoundFunction( state, block );	 // round 3
			HashPermuteDataFunction( block );
			HashRoundFunction( state, block );	 // round 4
			HashPermuteDataFunction( block );
			HashRoundFunction( state, block );	 // round 5
			HashPermuteDataFunction( block );
			HashRoundFunction( state, block );	 // round 6
			HashPermuteDataFunction( block );
			HashRoundFunction( state, block );	 // round 7

			for ( size_t i = 0; i < 8; i++ )
			{
				state[ i ] ^= state[ i + 8 ];
				state[ i + 8 ] ^= chaining_value[ i ];
			}

			memcpy( result_words, state, sizeof( state ) );
		}

		inline void words_from_little_endian_bytes( const void* bytes, size_t bytes_size, CommonSecurity::Blake3::Core::WordType* result_words )
		{
			using CommonSecurity::Blake3::Core::WordType;

			my_cpp2020_assert( bytes_size % sizeof(WordType) == 0, "", std::source_location::current() );

			::memcpy(result_words, bytes, bytes_size);

			if constexpr(std::endian::native == std::endian::big)
			{
				for(std::size_t index = 0, word_size = bytes_size / sizeof(WordType); index < word_size; index++)
				{
					result_words[index] = CommonToolkit::ByteSwap::byteswap(result_words[index]);
				}
			}
		}

		// Each chunk or parent node can produce either an 8-word chaining value or, by setting the ROOT flag, any number of final output bytes.
		// The Output struct captures the state just prior to choosing between those two possibilities.
		struct HashDataGenerater
		{
			CommonSecurity::Blake3::Core::WordType current_chaining_value[ 8 ];
			CommonSecurity::Blake3::Core::WordType current_block_words[ 16 ];
			uint64_t counter;
			CommonSecurity::Blake3::Core::WordType block_size;
			uint32_t flags;

			static void GenerateChainingValue( const HashDataGenerater* self, CommonSecurity::Blake3::Core::WordType generated_words[ 8 ] )
			{
				using CommonSecurity::Blake3::Core::WordType;

				WordType buffer_size_16[ 16 ];
				MainCompressData( self->current_chaining_value, self->current_block_words, self->counter, self->block_size, self->flags, buffer_size_16 );
				memcpy( generated_words, buffer_size_16, 8 * sizeof(WordType) );
			}

			static void GenerateRootNodeBytes( const HashDataGenerater* self, void* generated_byte_pointer, size_t generated_byte_size )
			{
				using CommonSecurity::Blake3::Core::WordType;

				uint8_t* temporary_bytes_pointer = ( uint8_t* )generated_byte_pointer;
				uint64_t cuurent_block_counter = 0;
				while ( generated_byte_size > 0 )
				{
					WordType words[ 16 ];
					MainCompressData( self->current_chaining_value, self->current_block_words, cuurent_block_counter, self->block_size, self->flags | ROOT, words );
					for ( size_t word = 0; word < 16; word++ )
					{
						for ( int byte = 0; byte < sizeof(WordType); byte++ )
						{
							if ( generated_byte_size == 0 )
							{
								return;
							}
							*temporary_bytes_pointer = ( uint8_t )( words[ word ] >> ( 8 * byte ) );
							temporary_bytes_pointer++;
							generated_byte_size--;
						}
					}
					cuurent_block_counter++;
				}
			}
		};

		inline static HashDataGenerater HashData_GenerateParentNode
		(
			const CommonSecurity::Blake3::Core::WordType left_child_cv[ 8 ],
			const CommonSecurity::Blake3::Core::WordType right_child_cv[ 8 ],
			const CommonSecurity::Blake3::Core::WordType key_words[ 8 ],
			uint32_t flags
		)
		{
			HashDataGenerater result_object;
			memcpy( result_object.current_chaining_value, key_words, sizeof( result_object.current_chaining_value ) );
			memcpy( &result_object.current_block_words[ 0 ], left_child_cv, 8 * 4 );
			memcpy( &result_object.current_block_words[ 8 ], right_child_cv, 8 * 4 );
			result_object.counter = 0;				   // Always 0 for parent nodes.
			result_object.block_size = BLAKE3_BLOCK_SIZE;  // Always BLAKE3_BLOCK_LEN (64) for parent nodes.
			result_object.flags = PARENT | flags;
			return result_object;
		}

		inline static void HashData_GenerateParentNode_ChainingValue
		(
			const CommonSecurity::Blake3::Core::WordType left_child_cv[ 8 ],
			const CommonSecurity::Blake3::Core::WordType right_child_cv[ 8 ],
			const CommonSecurity::Blake3::Core::WordType key_words[ 8 ],
			uint32_t flags,
			CommonSecurity::Blake3::Core::WordType result_words[ 8 ]
		)
		{
			HashDataGenerater parent_node = HashData_GenerateParentNode( left_child_cv, right_child_cv, key_words, flags );
			// We only write to `result_words` after we've read the inputs. That makes it safe for `result_words` to alias an input, which we do below.
			HashDataGenerater::GenerateChainingValue( &parent_node, result_words );
		}

		// An incremental hasher that can accept any number of writes.
		class HashWorker
		{

		private:

			struct HashInternalChunkState
			{
				CommonSecurity::Blake3::Core::WordType chaining_value[ 8 ];
				uint64_t chunk_counter;
				uint8_t	 block[ BLAKE3_BLOCK_SIZE ];
				uint8_t	 block_size;
				uint8_t	 blocks_compressed;
				uint32_t flags;

				void ChunkStateInitial(const CommonSecurity::Blake3::Core::WordType key_words[ 8 ], uint64_t chunk_counter, uint32_t flags )
				{
					memcpy( this->chaining_value, key_words, sizeof( this->chaining_value ) );
					this->chunk_counter = chunk_counter;
					memory_set_no_optimize_function<0x00>( this->block, sizeof( this->block ) );
					this->block_size = 0;
					this->blocks_compressed = 0;
					this->flags = flags;
				}

				size_t ChunkStateSize() const
				{
					return BLAKE3_BLOCK_SIZE * ( size_t )(this->blocks_compressed) + ( size_t )(this->block_size);
				}

				CommonSecurity::Blake3::Core::WordType RequestState_StartFlag() const
				{
					if ( this->blocks_compressed == 0 )
					{
						return CHUNK_START;
					}
					else
					{
						return 0;
					}
				}

				void ChunkStateUpdate(const void* input, size_t input_size )
				{
					const uint8_t* temporary_bytes_pointer = ( const uint8_t* )input;
					while ( input_size > 0 )
					{
						// If the block buffer is full, compress it and clear it.
						// More input is coming, so this compression is not CHUNK_END.
						if ( this->block_size == BLAKE3_BLOCK_SIZE )
						{
							CommonSecurity::Blake3::Core::WordType current_block_words[ 16 ];
							words_from_little_endian_bytes( this->block, BLAKE3_BLOCK_SIZE, current_block_words );
							CommonSecurity::Blake3::Core::WordType out16[ 16 ];
							MainCompressData( this->chaining_value, current_block_words, this->chunk_counter, BLAKE3_BLOCK_SIZE, this->flags | RequestState_StartFlag(), out16 );
							memcpy( this->chaining_value, out16, sizeof( this->chaining_value ) );
							this->blocks_compressed++;
							memory_set_no_optimize_function<0x00>( this->block, sizeof( this->block ) );
							this->block_size = 0;
						}

						// Copy input bytes into the block buffer.
						size_t want = BLAKE3_BLOCK_SIZE - ( size_t )(this->block_size);
						size_t take = want;
						if ( input_size < want )
						{
							take = input_size;
						}
						memcpy( &this->block[ ( size_t )this->block_size ], temporary_bytes_pointer, take );
						this->block_size += ( uint8_t )take;
						temporary_bytes_pointer += take;
						input_size -= take;
					}
				}

				static HashDataGenerater ChunkStateFinalize(const HashInternalChunkState* self)
				{
					HashDataGenerater result_object;
					memcpy( result_object.current_chaining_value, self->chaining_value, sizeof( result_object.current_chaining_value ) );
					words_from_little_endian_bytes( self->block, sizeof( self->block ), result_object.current_block_words );
					result_object.counter = self->chunk_counter;
					result_object.block_size = ( CommonSecurity::Blake3::Core::WordType )self->block_size;
					result_object.flags = self->flags | self->RequestState_StartFlag() | CHUNK_END;
					return result_object;
				}
			};

			HashInternalChunkState chunk_state;

		protected:

			void internal_initial_function( HashWorker* self, const CommonSecurity::Blake3::Core::WordType key_words[ 8 ], uint32_t flags )
			{
				self->chunk_state.ChunkStateInitial(key_words, 0, flags );
				memcpy( self->key_words, key_words, sizeof( self->key_words ) );
				self->cv_stack_size = 0;
				self->flags = flags;
			}

		public:

			CommonSecurity::Blake3::Core::WordType			key_words[ 8 ];
			CommonSecurity::Blake3::Core::WordType			cv_stack[ 8 * 54 ];	 // Space for 54 subtree chaining values:
			uint8_t				cv_stack_size;		 // 2^54 * CHUNK_LEN = 2^64
			uint32_t			flags;

			std::size_t hash_size_with_bit = 0;

			void HasherPushStack( HashWorker* self, const CommonSecurity::Blake3::Core::WordType cv[ 8 ] )
			{
				memcpy( &self->cv_stack[ ( size_t )self->cv_stack_size * 8 ], cv, 8 * 4 );
				self->cv_stack_size++;
			}

			// Returns a pointer to the popped CV, which is valid until the next push.
			const CommonSecurity::Blake3::Core::WordType* HasherPopStack( HashWorker* self )
			{
				self->cv_stack_size--;
				return &self->cv_stack[ ( size_t )self->cv_stack_size * 8 ];
			}

			// Section 5.1.2 of the BLAKE3 spec explains this algorithm in more detail.
			void HasherAppendChunkChainingValue( HashWorker* self, CommonSecurity::Blake3::Core::WordType new_cv[ 8 ], uint64_t total_chunks )
			{
				// This chunk might complete some subtrees. For each completed subtree, its
				// left child will be the current top entry in the CV stack, and its right
				// child will be the current value of `new_cv`. Pop each left child off the
				// stack, merge it with `new_cv`, and overwrite `new_cv` with the result.
				// After all these merges, push the final value of `new_cv` onto the stack.
				// The number of completed subtrees is given by the number of trailing 0-bits
				// in the new total number of chunks.
				while ( ( total_chunks & 1 ) == 0 )
				{
					HashData_GenerateParentNode_ChainingValue( HasherPopStack( self ), new_cv, self->key_words, self->flags, new_cv );
					total_chunks >>= 1;
				}
				HasherPushStack( self, new_cv );
			}

			// Add input to the hash state. This can be called any number of times.
			void HasherUpdate(HashWorker* self, const void* input, size_t input_size )
			{
				const uint8_t* temporary_bytes_pointer = ( const uint8_t* )input;
				while ( input_size > 0 )
				{
					// If the current chunk is complete, finalize it and reset the chunk state.
					// More input is coming, so this chunk is not ROOT.
					if ( self->chunk_state.ChunkStateSize() == BLAKE3_CHUNK_SIZE )
					{
						HashDataGenerater chunk_output = HashInternalChunkState::ChunkStateFinalize(&self->chunk_state);
						CommonSecurity::Blake3::Core::WordType chunk_cv[ 8 ];
						HashDataGenerater::GenerateChainingValue( &chunk_output, chunk_cv );
						uint64_t total_chunks = self->chunk_state.chunk_counter + 1;
						HasherAppendChunkChainingValue( self, chunk_cv, total_chunks );
						self->chunk_state.ChunkStateInitial( self->key_words, total_chunks, self->flags );
					}

					// Compress input bytes into the current chunk state.
					size_t want = BLAKE3_CHUNK_SIZE - self->chunk_state.ChunkStateSize();
					size_t take = want;
					if ( input_size < want )
					{
						take = input_size;
					}
					self->chunk_state.ChunkStateUpdate( temporary_bytes_pointer, take );
					temporary_bytes_pointer += take;
					input_size -= take;
				}
			}

			// Finalize the hash and write any number of output bytes.
			void HasherFinalize(const HashWorker* self, void* generated_bytes_pointer, size_t generated_bytes_size )
			{
				if(generated_bytes_pointer == nullptr || (generated_bytes_size * 8) != this->hash_size_with_bit)
					return;

				// Starting with the output from the current chunk, compute all the parent chaining values along the right edge of the tree, until we have the root output.
				HashDataGenerater current_output = HashInternalChunkState::ChunkStateFinalize(&self->chunk_state);
				size_t parent_nodes_remaining = ( size_t )self->cv_stack_size;
				while ( parent_nodes_remaining > 0 )
				{
					parent_nodes_remaining--;
					CommonSecurity::Blake3::Core::WordType current_cv[ 8 ];
					HashDataGenerater::GenerateChainingValue( &current_output, current_cv );
					current_output = HashData_GenerateParentNode( &(self->cv_stack[ parent_nodes_remaining * 8 ]), current_cv, self->key_words, self->flags );
				}
				HashDataGenerater::GenerateRootNodeBytes( &current_output, generated_bytes_pointer, generated_bytes_size );
			}

			void Clear()
			{
				using CommonSecurity::Blake3::Core::WordType;

				volatile void* CheckPointer = nullptr;

				CheckPointer = memory_set_no_optimize_function<0x00>(std::data(cv_stack), std::size(cv_stack) * sizeof(WordType));
				CheckPointer = nullptr;
				this->cv_stack_size = 0x00;

				CheckPointer = memory_set_no_optimize_function<0x00>(std::data(key_words), std::size(key_words) * sizeof(WordType));
				CheckPointer = nullptr;

				this->flags = 0;
			}

			// Construct a new `Hasher` for the regular hash function.
			void HasherInitial( HashWorker* self )
			{
				using CommonSecurity::Blake3::Core::WordType;
				using CommonSecurity::Blake3::Core::HashConstants;

				internal_initial_function( self, HashConstants<WordType>::INITIAL_VECTOR.data(), 0 );
			}

			// Construct a new `Hasher` for the keyed hash function.
			void HasherInitialKeyed( HashWorker* self, const uint8_t key[ BLAKE3_KEY_SIZE ] )
			{
				CommonSecurity::Blake3::Core::WordType key_words[ 8 ];
				words_from_little_endian_bytes( key, BLAKE3_KEY_SIZE, key_words );
				internal_initial_function( self, key_words, KEYED_HASH );
			}

			// Construct a new `Hasher` for the key derivation function.
			// The context string should be hardcoded, globally unique, and application-specific.
			void HasherInitialDeriveKey( HashWorker* self, const char* context )
			{
				using CommonSecurity::Blake3::Core::WordType;
				using CommonSecurity::Blake3::Core::HashConstants;

				HashWorker context_hasher;
				internal_initial_function( &context_hasher, HashConstants<WordType>::INITIAL_VECTOR.data(), DERIVE_KEY_CONTEXT );
				HasherUpdate( &context_hasher, context, strlen( context ) );
				uint8_t context_key[ BLAKE3_KEY_SIZE ];
				HasherFinalize( &context_hasher, context_key, BLAKE3_KEY_SIZE );
				WordType context_key_words[ 8 ];
				words_from_little_endian_bytes( context_key, BLAKE3_KEY_SIZE, context_key_words );
				internal_initial_function( self, context_key_words, DERIVE_KEY_MATERIAL );
			}

			HashWorker()
			{
				volatile void* CheckPointer = nullptr;
				
				CheckPointer = memory_set_no_optimize_function<0x00>(std::data(cv_stack), std::size(cv_stack) * sizeof(WordType));
				CheckPointer = nullptr;
				
				HasherInitial(this);
			}

			HashWorker
			(
				CommonSecurity::Blake3::Core::WordType chaining_value_or_keys[8],
				std::uint32_t hash_state_flags
			)
			{
				using CommonSecurity::Blake3::Core::WordType;
				using CommonSecurity::Blake3::Core::HashConstants;
		
				volatile void* CheckPointer = nullptr;
				
				CheckPointer = memory_set_no_optimize_function<0x00>(std::data(cv_stack), std::size(cv_stack) * sizeof(WordType));
				CheckPointer = nullptr;

				internal_initial_function( this, chaining_value_or_keys, hash_state_flags );
			}
		};
	}

	class HashProvider : public CommonSecurity::HashProviderBaseTools::InterfaceHashProvider
	{

	private:

		Core::HashWorker CoreWorkerObject;

	public:

		inline void UpdateStringKey(const std::string& string_key)
		{
			using CommonSecurity::Blake3::Core::WordType;

			if( string_key.empty() )
			{
				return;
			}

			if( string_key.size() != BLAKE3_KEY_SIZE )
			{
				std::cout << "The string key you given is an invalid size!" << std::endl;
				return;
			}

			std::array<std::uint8_t, BLAKE3_KEY_SIZE> bytes_key;

			for(std::size_t bytes_index = 0; bytes_index < bytes_key.size(); ++bytes_index)
			{
				bytes_key[bytes_index] = static_cast<std::uint8_t>(string_key[bytes_index]);
			}

			CoreWorkerObject.HasherInitialDeriveKey(&CoreWorkerObject, string_key.data());
		}

		inline void UpdateBytesKey(const std::span<std::uint8_t>& bytes_key)
		{
			if( bytes_key.empty() )
			{
				return;
			}

			if( bytes_key.size() != BLAKE3_KEY_SIZE )
			{
				std::cout << "The bytes key you given is an invalid size!" << std::endl;
				return;
			}

			CoreWorkerObject.HasherInitialKeyed(&CoreWorkerObject, bytes_key.data());
		}

		inline void StepInitialize() override
		{
			this->CoreWorkerObject.Clear();
		}

		inline void StepUpdate( const std::span<const std::uint8_t> data_value_vector ) override
		{
			std::vector<std::uint8_t> bytes_buffer(data_value_vector.begin(), data_value_vector.end());
			
			this->CoreWorkerObject.HasherUpdate(&CoreWorkerObject, bytes_buffer.data(), bytes_buffer.size());

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(bytes_buffer.data(), bytes_buffer.size());

			CheckPointer = nullptr;
		}

		inline void StepFinal( std::span<std::uint8_t> hash_value_vector ) override
		{
			if(hash_value_vector.empty() || (hash_value_vector.size() % 4) != 0 || (hash_value_vector.size() % 8) != 0)
				return;
			
			this->CoreWorkerObject.HasherFinalize(&CoreWorkerObject, hash_value_vector.data(), hash_value_vector.size());
		}

		inline std::size_t HashSize() const override
		{
			return this->CoreWorkerObject.hash_size_with_bit;
		}

		inline void Clear() override
		{
			this->CoreWorkerObject.Clear();
		}

		HashProvider( std::size_t hashsize )
		{
			if(hashsize == 0 || (hashsize % 4) != 0 || (hashsize % 8) != 0)
				my_cpp2020_assert(false, "", std::source_location::current());
			else
			{
				this->CoreWorkerObject = Core::HashWorker();
				this->CoreWorkerObject.hash_size_with_bit = hashsize;
			}
		}

		HashProvider( const HashProvider& other )
		{
			this->CoreWorkerObject = (other.CoreWorkerObject);
			this->CoreWorkerObject.hash_size_with_bit = this->CoreWorkerObject.hash_size_with_bit;
		}

		~HashProvider()
		{
			this->Clear();
		}
	};
}
