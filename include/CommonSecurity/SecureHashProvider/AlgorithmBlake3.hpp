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
	The results of the Blake3 algorithm hash have been tested in 64 and 32 bit OS mode
	I may have made a variant of this algorithm, so if you are concerned about this security issue, please do not use it.
	
	信息：
	Blake3哈希算法的32位和64位系统的自动适应，由Twilight-Dream修改，并参考了Blake2哈希算法。
	警告和注意：
	已经在64和32位操作系统模式，进行试验Blake3算法哈希结果
	我可能做出了该算法的变种，如果你担心这项安全问题，请不要使用它。
*/

namespace CommonSecurity::Blake3
{
	//由Twilight-Dream修改，使用变体模式
	//Modified by Twilight-Dream, using variant mode
	inline constexpr bool UseVariantMode = false;

	inline constexpr std::size_t _GeneratedHashBytesSize_()
	{
		if(UseVariantMode)
			return CURRENT_SYSTEM_BITS == 32 ? 32 : 64;
		else
			return 32;
	}

	inline constexpr std::size_t _HashBlockBytesSize_()
	{
		if(UseVariantMode)
			return CURRENT_SYSTEM_BITS == 32 ? 64 : 128;
		else
			return 64;
	}

	inline constexpr std::size_t _KeyBytesSize_()
	{
		if(UseVariantMode)
			return CURRENT_SYSTEM_BITS == 32 ? 32 : 64;
		else
			return 32;
	}

	namespace Core
	{
		using HashProviderBaseTools::Blake::HashConstants;
		
		using WordType = std::conditional_t<UseVariantMode == false, CommonToolkit::FourByte, std::conditional_t<CURRENT_SYSTEM_BITS == 32, CommonToolkit::FourByte, CommonToolkit::EightByte>>;

		//Generated hash size is a 64 byte or 128 byte
		inline constexpr std::size_t GeneratedHashBytesSize = _GeneratedHashBytesSize_();

		//Hash data block size is a 64 byte or 128 byte
		inline constexpr std::size_t HashBlockBytesSize = _HashBlockBytesSize_();
		
		//Key size is a 32 byte or 64 byte
		inline constexpr std::size_t KeyBytesSize = _KeyBytesSize_();
		
		//Hash memory chunk size is 1 kilo-byte
		inline constexpr std::size_t HashChunkBytesSize = 1024;

		inline constexpr std::uint8_t FlagChunkStart = 1 << 0;
		inline constexpr std::uint8_t FlagChunkEnd = 1 << 1;
		inline constexpr std::uint8_t FlagParent = 1 << 2;
		inline constexpr std::uint8_t FlagRoot = 1 << 3;
		inline constexpr std::uint8_t FlagKeyedHash = 1 << 4;
		inline constexpr std::uint8_t FlagDeriveKeyContext = 1 << 5;
        inline constexpr std::uint8_t FlagDeriveKeyMaterial = 1 << 6;

		//For each round of hashing execution, the permute table of the message data index
		//对于每一轮散列的执行，信息数据索引的permute表
		inline constexpr std::array<std::array<std::uint8_t, 16>, 7> SIGMA_VECTOR_NEW
		{
			{
				{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
				{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
				{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
				{ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
				{ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
				{ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
				{ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
			},
		};

		namespace Functions
		{
			template<typename Type> requires std::same_as<Type, WordType>
			using ThisWordArray16Type = std::array<Type, 16>;

			static inline void HashValueMixer(const std::array<std::uint8_t, 16>& MessageScheduleIndices, std::size_t SigmaVectorIndex, WordType& ValueA, WordType& ValueB, WordType& ValueC, WordType& ValueD, const ThisWordArray16Type<WordType>& Message)
			{
				#define HASH_BLAKE3_WITH_RIGHT_ROTATION_BIT_32_64(Word, BitShiftCount) \
				( (Word >> BitShiftCount) | (Word << (std::numeric_limits<Core::WordType>::digits - BitShiftCount) ) )  \

				if constexpr(CURRENT_SYSTEM_BITS == 64)
				{
					ValueA = ValueA + ValueB + Message[MessageScheduleIndices[2 * SigmaVectorIndex]];
					ValueD = CommonSecurity::Binary_RightRotateMove(ValueD ^ ValueA, 32);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove(ValueB ^ ValueC, 24);

					ValueA = ValueA + ValueB + Message[MessageScheduleIndices[2 * SigmaVectorIndex + 1]];
					ValueD = CommonSecurity::Binary_RightRotateMove(ValueD ^ ValueA, 16);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove(ValueB ^ ValueC, 63);
				}
				else
				{
					ValueA = ValueA + ValueB + Message[MessageScheduleIndices[2 * SigmaVectorIndex]];
					ValueD = CommonSecurity::Binary_RightRotateMove(ValueD ^ ValueA, 16);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove(ValueB ^ ValueC, 12);

					ValueA = ValueA + ValueB + Message[MessageScheduleIndices[2 * SigmaVectorIndex + 1]];
					ValueD = CommonSecurity::Binary_RightRotateMove(ValueD ^ ValueA, 8);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove(ValueB ^ ValueC, 7);
				}

				#undef HASH_BLAKE3_WITH_RIGHT_ROTATION_BIT64
			}

			static inline void HashValueRound(std::size_t RoundNumber, const ThisWordArray16Type<WordType>& Message, ThisWordArray16Type<WordType>& CurrentInitialVector)
			{
				auto&
				[
					StateValue, StateValue2, StateValue3, StateValue4,
					StateValue5, StateValue6, StateValue7, StateValue8,
					StateValue9, StateValue10, StateValue11, StateValue12,
					StateValue13, StateValue14, StateValue15, StateValue16
				] = CurrentInitialVector;

				auto& MessageScheduleIndices = SIGMA_VECTOR_NEW[RoundNumber];

				//Mix the columns

				HashValueMixer(MessageScheduleIndices, 0, StateValue, StateValue5, StateValue9, StateValue13, Message);
				HashValueMixer(MessageScheduleIndices, 1, StateValue2, StateValue6, StateValue10, StateValue14, Message);
				HashValueMixer(MessageScheduleIndices, 2, StateValue3, StateValue7, StateValue11, StateValue15, Message);
				HashValueMixer(MessageScheduleIndices, 3, StateValue4, StateValue8, StateValue12, StateValue16, Message);

				//Mix the diagonals.

				HashValueMixer(MessageScheduleIndices, 4, StateValue, StateValue6, StateValue11, StateValue16, Message);
				HashValueMixer(MessageScheduleIndices, 5, StateValue2, StateValue7, StateValue12, StateValue13, Message);
				HashValueMixer(MessageScheduleIndices, 6, StateValue3, StateValue8, StateValue9, StateValue14, Message);
				HashValueMixer(MessageScheduleIndices, 7, StateValue4, StateValue5, StateValue10, StateValue15, Message);
			}

			static constexpr inline WordType LookupInitialVectorValue(std::size_t index)
			{
				return HashConstants<WordType>::INITIAL_VECTOR[index];
			}

			template<typename Type>
			static std::vector<Type>
			MemoryDataSlice(Type* data_pointer, std::size_t data_offset_index, std::size_t data_size)
			{
				if(data_pointer == nullptr || data_size == 0)
					return std::vector<Type>();

				static_assert(std::is_trivially_copyable_v<Type>, "MemoryData Type is not trivial copyable !");

				#if __cplusplus >= 202002L

				//std::vector<Type> memory_data_sliced(data_size, 0x00);
				//std::ranges::copy_n(data_pointer + data_offset_index, data_size, memory_data_sliced.data() + 0);
				//return memory_data_sliced;

				std::span<Type> memory_data_span(data_pointer + data_offset_index, data_size);

				std::vector<Type> memory_data_sliced(memory_data_span.begin(), memory_data_span.end());

				return memory_data_sliced;

				#else

				std::vector<Type> memory_data_sliced(data_size, 0x00);
				
				std::memmove(memory_data_sliced.data(), data_pointer + data_offset_index * sizeof(Type), data_size * sizeof(Type));

				return memory_data_sliced;

				#endif
			}
		}
	}
}

//Refactoring core code
namespace CommonSecurity::Blake3
{
	class HashDataCompresser
	{

	private:

		std::mutex conditional_mutex;

	public:

		std::array<Core::WordType, 16>
		operator()
		(
			std::array<Core::WordType, 8> chaining_value,
			std::array<Core::WordType, 16> data_block_words,
			std::uint64_t counter,
			std::size_t block_size,
			std::uint32_t state_flags
		)
		{
			auto spin_lock_with_scoped { std::scoped_lock(this->conditional_mutex) };
			
			/*
			std::array<Core::WordType, 16> state_data = std::array<Core::WordType, 16>();

			state_data[0] = chaining_value[0];
			state_data[1] = chaining_value[1];
			state_data[2] = chaining_value[2];
			state_data[3] = chaining_value[3];
			state_data[4] = chaining_value[4];
			state_data[5] = chaining_value[5];
			state_data[6] = chaining_value[6];
			state_data[7] = chaining_value[7];
			state_data[8] = Core::Functions::LookupInitialVectorValue(0);
			state_data[9] = Core::Functions::LookupInitialVectorValue(1);
			state_data[10] = Core::Functions::LookupInitialVectorValue(2);
			state_data[11] = Core::Functions::LookupInitialVectorValue(3);
			state_data[12] = static_cast<std::uint32_t>(counter);
			state_data[13] = static_cast<std::uint32_t>(counter >> 32U);
			state_data[14] = static_cast<std::uint32_t>(block_size);
			state_data[15] = static_cast<std::uint32_t>(state_flags);
			*/
			
			std::array<Core::WordType, 16> state_data
			{
				chaining_value[0],
				chaining_value[1],
				chaining_value[2],
				chaining_value[3],
				chaining_value[4],
				chaining_value[5],
				chaining_value[6],
				chaining_value[7],
				Core::Functions::LookupInitialVectorValue(0),
				Core::Functions::LookupInitialVectorValue(1),
				Core::Functions::LookupInitialVectorValue(2),
				Core::Functions::LookupInitialVectorValue(3),
				static_cast<std::uint32_t>(counter),
				static_cast<std::uint32_t>(counter >> 32U),
				static_cast<std::uint32_t>(block_size),
				static_cast<std::uint32_t>(state_flags)
			};

			for(std::size_t rounds_number = 0; rounds_number < Core::SIGMA_VECTOR_NEW.size(); ++rounds_number)
			{
				Core::Functions::HashValueRound(rounds_number, data_block_words, state_data);
			}

			/*
			state_data[0] ^= state_data[8];
			state_data[1] ^= state_data[9];
			state_data[2] ^= state_data[10];
			state_data[3] ^= state_data[11];
			state_data[4] ^= state_data[12];
			state_data[5] ^= state_data[13];
			state_data[6] ^= state_data[14];
			state_data[7] ^= state_data[15];
			state_data[8] ^= chaining_value[0];
			state_data[9] ^= chaining_value[1];
			state_data[10] ^= chaining_value[2];
			state_data[11] ^= chaining_value[3];
			state_data[12] ^= chaining_value[4];
			state_data[13] ^= chaining_value[5];
			state_data[14] ^= chaining_value[6];
			state_data[15] ^= chaining_value[7];
			*/

			for(std::size_t index = 0; index < 8; ++index)
			{
				state_data[index] ^= state_data[index + 8];
				state_data[index + 8] ^= chaining_value[index];
			}

			return state_data;
		}
	};

	HashDataCompresser HashDataCompresserObject;

	class HashDataGenerator
	{
		
	private:

		std::array<Core::WordType, 8> current_chaining_value;
		std::array<Core::WordType, 16> current_data_block_words;
		std::uint64_t counter = 0;
		std::uint32_t block_size = 0;
		std::uint32_t state_flags = 0;

	public:
		
		// ChainingValue returns the first 8 words of the compressed node. 
		// This is used in two places.
		// First, when a block node is constructed, its (ChainingValue) is overwritten by this value after each block of data from the argument has been processed.
		// Second, when two nodes are merged into a parent node, each of their chaining values provides half of the content of the new node's block.
		// ChainingValue返回压缩节点的前8个字。 
		// 这在两个地方使用。
		// 首先，当一个块状节点被构建时，它的（ChainingValue）在每个来自参数的数据块被处理后会被这个值所覆盖。
		// 第二，当两个节点合并到一个父节点时，它们的每一个链值都会为新节点的块提供一半的内容。
		std::array<Core::WordType, 8> ApplyChainingValue()
		{
			auto hash_data_compressed = HashDataCompresserObject
			(
				this->current_chaining_value,
				this->current_data_block_words,
				this->counter,
				this->block_size,
				this->state_flags
			);

			std::array<Core::WordType, 8> half0_hash_data {0, 0, 0, 0, 0, 0, 0, 0};

			//std::ranges::copy_n( hash_data_compressed.data() + 0, 8, half0_hash_data.data() + 0 );
			std::memmove(half0_hash_data.data(), hash_data_compressed.data(), 8 * sizeof(Core::WordType));

			return half0_hash_data;
		}

		void BuildHashTreeRootNode(std::span<std::uint8_t> hash_byte_data_slice)
		{
			std::size_t that_block_counter = 0;

			for (std::size_t round = 0, byte_data_size = hash_byte_data_slice.size(); byte_data_size != 0; ++round)
			{
				std::array<Core::WordType, 16> current_state_words_data = HashDataCompresserObject
				(
					this->current_chaining_value,
					this->current_data_block_words,
					that_block_counter,
					this->block_size,
					this->state_flags | Core::FlagRoot
				);

				if constexpr(std::endian::native != std::endian::little)
				{
					for(std::size_t current_state_word_index = 0; current_state_word_index < current_state_words_data.size(); ++current_state_word_index)
					{
						Core::WordType& current_state_word = current_state_words_data[current_state_word_index];
						current_state_word = CommonToolkit::ByteSwap::byteswap(current_state_word);
					}
				}

				if(round * Core::GeneratedHashBytesSize < hash_byte_data_slice.size())
				{
					std::memmove(hash_byte_data_slice.data() + round * Core::GeneratedHashBytesSize, current_state_words_data.data(), Core::GeneratedHashBytesSize);

					byte_data_size -= Core::GeneratedHashBytesSize;
				}

				++that_block_counter;
			}
			
			that_block_counter = 0;

			return;
		}

		void Clear()
		{
			memory_set_no_optimize_function<0x00>(this->current_chaining_value.data(), this->current_chaining_value.size() * sizeof(Core::WordType));
			memory_set_no_optimize_function<0x00>(this->current_chaining_value.data(), this->current_chaining_value.size() * sizeof(Core::WordType));

			this->counter = 0;
			this->block_size = 0;
			this->state_flags = 0;
		}

		HashDataGenerator
		(
			std::array<Core::WordType, 8>& chaining_value_or_keys,
			std::array<Core::WordType, 16>& data_block_words,
			std::uint32_t that_counter,
			std::uint32_t that_block_size,
			std::uint32_t that_state_flags
		)
			: 
			current_chaining_value(chaining_value_or_keys), current_data_block_words(data_block_words), 
			counter(that_counter), block_size(that_block_size),  state_flags(that_state_flags)
		{
			
		}

		HashDataGenerator
		(
			const std::array<Core::WordType, 8>& chaining_value_or_keys,
			const std::array<Core::WordType, 16>& hash_state_block,
			const std::uint32_t that_counter,
			const std::uint32_t that_block_size,
			const std::uint32_t that_state_flags
		)
			: 
			current_chaining_value(chaining_value_or_keys), current_data_block_words(hash_state_block),
			counter(that_counter), block_size(that_block_size), state_flags(that_state_flags)
		{
			
		}

		HashDataGenerator(const HashDataGenerator& other_object)
			: 
			current_chaining_value(other_object.current_chaining_value), current_data_block_words(other_object.current_data_block_words),
			counter(other_object.counter), block_size(other_object.block_size), state_flags(other_object.state_flags)
		{
		
		}

		~HashDataGenerator()
		{
			this->Clear();
		}
	};	
 
	class HashProvider : public CommonSecurity::HashProviderBaseTools::InterfaceHashProvider
	{

	private:

		struct CoreWorker
		{
			//HashMemoryChunkState manages the state involved in hashing a single chunk of from other data bytes.
			//HashMemoryChunkState管理着从其他数据字节中散列出一个单一块的状态。
			struct HashMemoryChunkState
			{
				std::array<Core::WordType, 8> chaining_value;
				std::uint64_t counter = 0;
				std::array<std::uint8_t, Core::HashBlockBytesSize> byte_block;
				std::uint8_t byte_block_size = 0x00;
				std::uint8_t byte_block_compressed = 0x00;

				std::uint32_t state_flags = 0;

				std::size_t CheckBlockSize() const
				{
					return Core::HashBlockBytesSize * static_cast<std::size_t>(byte_block_compressed) + static_cast<std::size_t>(byte_block_size);
				}

				std::uint32_t RequestChunkFlagStart()
				{
					return byte_block_compressed == 0U ? Core::FlagChunkStart : 0U;
				}

				void UpdateChunk(std::span<std::uint8_t> bytes_data_span)
				{
					std::vector<std::uint8_t> temporary_bytes_data(bytes_data_span.begin(), bytes_data_span.end());

					//Copy the chunk block (bytes) into the node block and chain it.
					//将大块数据（字节）复制到节点块中，并将其连锁。

					volatile void* CheckPointer = nullptr;

					while(!temporary_bytes_data.empty())
					{
						//If the block buffer is full, compress it and clear it. 
						//More data bytes is coming, so this compression is not FlagChunkEnd.
						//如果块缓冲区满了，就压缩它并清除它。
						//更多的字节数据正在到来，所以这个压缩不是FlagChunkEnd。
						if(static_cast<std::size_t>(byte_block_size) == Core::HashBlockBytesSize)
						{
							std::array<Core::WordType, 16> data_block_words
							{
								0, 0, 0, 0, 0, 0, 0, 0, 
								0, 0, 0, 0, 0, 0, 0, 0
							};

							/*
							if constexpr(CURRENT_SYSTEM_BITS == 32)
								CommonToolkit::BitConverters::le32_copy(this->byte_block.data(), 0, data_block_words.data(), 0, this->byte_block_size);
							else
								CommonToolkit::BitConverters::le64_copy(this->byte_block.data(), 0, data_block_words.data(), 0, this->byte_block_size);
							*/

							std::memmove(data_block_words.data(), this->byte_block.data(), this->byte_block_size);
							if constexpr(std::endian::native != std::endian::little)
							{
								for(auto& data_word : data_block_words)
									data_word = CommonToolkit::ByteSwap::byteswap(data_word);
							}

							//ApplyChaingValue Start

							auto hash_data_compressed = HashDataCompresserObject
							(
								this->chaining_value,
								data_block_words,
								this->counter,
								static_cast<std::uint32_t>(Core::HashBlockBytesSize),
								this->state_flags | Core::FlagChunkStart
							);

							std::memmove(this->chaining_value.data(), hash_data_compressed.data(), 8 * sizeof(Core::WordType));

							//ApplyChaingValue End

							++(this->byte_block_compressed);
							CheckPointer = memory_set_no_optimize_function<0x00>(this->byte_block.data(), this->byte_block.size());
							CheckPointer = nullptr;
							this->byte_block_size = 0x00;
							CheckPointer = memory_set_no_optimize_function<0x00>(data_block_words.data(), data_block_words.size() * sizeof(Core::WordType));
							CheckPointer = nullptr;
						}

						//Copy original bytes into the byte block buffer.
						//将原始字节复制到字节块缓冲区。
						std::size_t want = Core::HashBlockBytesSize - static_cast<std::uint32_t>(this->byte_block_size);
						std::size_t take = std::min(want, temporary_bytes_data.size());

						/*
						if constexpr(CURRENT_SYSTEM_BITS == 32)
							CommonToolkit::BitConverters::le32_copy(temporary_data.data(), 0, byte_block.data(), byte_block_size, take);
						else
							CommonToolkit::BitConverters::le64_copy(temporary_data.data(), 0, byte_block.data(), byte_block_size, take);
						byte_block_size += take;
						*/
					
						std::ranges::copy_n( temporary_bytes_data.data() + 0, take, this->byte_block.data() + 0 );
						if(this->byte_block.data() != nullptr)
							this->byte_block_size += static_cast<std::uint8_t>(take);
						else
							my_cpp2020_assert(false, "cannot update block data because the hash byte blocks of state data are unaligned size or null pointers!", std::source_location::current());

						std::vector<std::uint8_t> memory_bytes_data_slice = Core::Functions::MemoryDataSlice(temporary_bytes_data.data(), take, temporary_bytes_data.size() - take);
						CheckPointer = memory_set_no_optimize_function<0x00>(temporary_bytes_data.data(), temporary_bytes_data.size());
						CheckPointer = nullptr;
						temporary_bytes_data = std::move(memory_bytes_data_slice);
					}

					return;
				}

				//Make a hash data generator
				HashDataGenerator FinalChunk()
				{
					std::array<Core::WordType, 16> data_block_words
					{
						0, 0, 0, 0, 0, 0, 0, 0, 
						0, 0, 0, 0, 0, 0, 0, 0
					};

					std::memmove(data_block_words.data(), this->byte_block.data(), this->byte_block.size());
					if constexpr(std::endian::native != std::endian::little)
					{
						for(auto& data_word : data_block_words)
							data_word = CommonToolkit::ByteSwap::byteswap(data_word);
					}

					return HashDataGenerator
					(
						this->chaining_value,
						data_block_words,
						this->counter,
						static_cast<std::uint32_t>(this->byte_block_size),
						static_cast<std::uint32_t>(this->state_flags | this->RequestChunkFlagStart() | Core::FlagChunkEnd)
					);
				}

				void Clear()
				{
					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->chaining_value.data(), this->chaining_value.size() * sizeof(Core::WordType));
					CheckPointer = nullptr;
					CheckPointer = memory_set_no_optimize_function<0x00>(this->byte_block.data(), this->byte_block.size());
					CheckPointer = nullptr;

					this->counter = 0;
					this->state_flags = 0;
					this->byte_block_compressed = 0x00;
					this->byte_block_size = 0x00;
				}

				HashMemoryChunkState()
				{
					
				}

				HashMemoryChunkState
				(
					std::array<Core::WordType, 8> iniital_vector_or_processed_key,
					std::uint64_t chunk_counter,
					std::uint32_t hash_state_flags
				)
					:
					chaining_value(iniital_vector_or_processed_key),
					counter(chunk_counter),
					byte_block(std::array<std::uint8_t, Core::HashBlockBytesSize>()),
					byte_block_size(0x00),
					byte_block_compressed(0x00),
					state_flags(hash_state_flags)
				{
					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->chaining_value.data(), this->chaining_value.size() * sizeof(Core::WordType));
					CheckPointer = nullptr;
					CheckPointer = memory_set_no_optimize_function<0x00>(this->byte_block.data(), this->byte_block.size());
					CheckPointer = nullptr;
				}

				HashMemoryChunkState(const HashMemoryChunkState& other_object)
					:
					chaining_value(other_object.chaining_value),
					counter(other_object.counter),
					byte_block(other_object.byte_block),
					byte_block_size(other_object.byte_block_size),
					byte_block_compressed(other_object.byte_block_compressed),
					state_flags(other_object.state_flags)
				{
				
				}

				~HashMemoryChunkState()
				{
					this->Clear();
				}
			};
		
			HashMemoryChunkState HashMemoryChunkStateObject;
			std::array<Core::WordType, 8> chaining_value_or_keys;

			// log(n) set of Merkle subtree roots, at most one per height.
			// log(n) Merkle子树根的集合，每个高度最多一个。
			// Space for 54 subtree chaining values: 2^54 * Core::HashChunkBytesSize = 2^64
			// 54个子树链值的空间：2^54 * Core::HashChunkBytesSize = 2^64
			std::array<std::array<Core::WordType, 8>, 54> chaining_values_stack;
			std::uint8_t chaining_values_stack_size = 0;

			std::uint32_t hash_state_flags = 0;

			std::size_t hash_size_with_bit = 0;

			HashDataGenerator BuildHashTreeParentNode
			(
				const std::array<Core::WordType, 8>& left_state_block,
				const std::array<Core::WordType, 8>& right_state_block,
				const std::array<Core::WordType, 8>& chaining_value_or_keys,
				const std::uint32_t hash_state_flags
			)
			{
				//串联的哈希状态数据
				std::array<Core::WordType, 16> hash_state_block
				{
					0, 0, 0, 0, 0, 0, 0, 0, 
					0, 0, 0, 0, 0, 0, 0, 0
				};
				
				//Apply concatenate operation
				//应用串联操作
				/*
				for(std::size_t index = 0; index < hash_state_block.size(); ++index)
				{
					if(index < 8)
					{
						hash_state_block[index] = left_state_block[index];
					}
					else
					{
						hash_state_block[index] = right_state_block[index - 8];
					}
				}
				*/

				std::memmove(hash_state_block.data(), left_state_block.data(), left_state_block.size() * sizeof(Core::WordType));
				std::memmove(hash_state_block.data() + 8 * sizeof(Core::WordType), right_state_block.data(), right_state_block.size() * sizeof(Core::WordType));

				return HashDataGenerator
				(
					chaining_value_or_keys,
					hash_state_block,
					static_cast<std::uint32_t>(0),
					static_cast<std::uint32_t>(Core::HashBlockBytesSize),
					static_cast<std::uint32_t>(hash_state_flags | Core::FlagParent)
				);
			}

			std::array<Core::WordType, 8> HashTreeParentNode_ApplyChainingValue
			(
				const std::array<Core::WordType, 8>& left_state_block,
				const std::array<Core::WordType, 8>& right_state_block,
				const std::array<Core::WordType, 8>& chaining_value_or_keys,
				const std::uint32_t hash_state_flags
			)
			{
				return BuildHashTreeParentNode(left_state_block, right_state_block, chaining_value_or_keys, hash_state_flags).ApplyChainingValue();
			}

			void ChainingValueStackPush(const std::array<Core::WordType, 8>& chaining_value)
			{
				if( (static_cast<std::int32_t>(this->chaining_values_stack_size) + 1) < this->chaining_values_stack.size() )
				{
					this->chaining_values_stack[static_cast<std::size_t>(this->chaining_values_stack_size)] = chaining_value;
					++(this->chaining_values_stack_size);
				}
				else
				{
					my_cpp2020_assert(false, "The stack of hash chained values has overflowed!", std::source_location::current());
				}
			}

			std::array<Core::WordType, 8> ChainingValueStackPop()
			{
				if( (static_cast<std::int32_t>(this->chaining_values_stack_size) - 1) >= 0 )
				{
					--(this->chaining_values_stack_size);
					return this->chaining_values_stack[static_cast<std::size_t>(this->chaining_values_stack_size)];
				}
				else
				{
					my_cpp2020_assert(false, "The stack of hash chained values has underflowed!", std::source_location::current());
				}
			}

			//Appends a chunk to the right edge of the Merkle tree (HashTreeNode).
			//在Merkle树（HashTreeNode）的右侧边缘添加一个分块。
			void AppendChunkChainingValue(std::array<Core::WordType, 8>& chaining_state_data, std::size_t& total_chunk_number)
			{
				// This chunk might complete some subtrees
				// For each completed subtree, its left child will be the current top entry in the CV stack, and its right child will be the current value of `chaining_state_data`.
				// Pop each left child off the stack, merge it with `chaining_state_data`, and overwrite `chaining_state_data` with the result.
				// After all these merges, push the final value of `chaining_state_data` onto the stack.
				// The number of completed subtrees is given by the number of trailing 0-bits in the new total number of chunks.
				// 这个块可能会完成一些子树
				// 对于每个完成的子树，其左边的子树将是CV堆栈中当前最上面的条目，而其右边的子树将是`chaining_state_data`的当前值。
				// 从堆栈中弹出每个左子树，与`chaining_state_data`合并，并将结果覆盖`chaining_state_data`。
				// 在所有这些合并之后，把`chaining_state_data`的最终值推到栈上。
				// 完成的子树的数量由新的总块数中尾部0比特的数量给出。
			
				std::array<Core::WordType, 8> update_chaining_state_data(chaining_state_data);

				while ((total_chunk_number & 1) == 0)
				{
					update_chaining_state_data = this->HashTreeParentNode_ApplyChainingValue
					(
						this->ChainingValueStackPop(),
						chaining_state_data,
						this->chaining_value_or_keys,
						this->hash_state_flags
					);

					total_chunk_number >>= 1;
				}

				this->ChainingValueStackPush(update_chaining_state_data);
			}

			void HashUpdate(std::span<std::uint8_t> bytes_data)
			{
				if(bytes_data.empty())
					return;
			
				std::size_t index_of_bytes = 0;

				while (index_of_bytes < bytes_data.size_bytes())
				{
					//If the current chunk is complete, finalize add chunk data it to the tree.
					//Then reset this hash chunk state (but keep incrementing the counter across chunks).
					//More orginal bytes is coming, so this chunk is not FlagRoot. 
					//如果当前块已经完成，最终确定将块数据添加到树中。
					//然后重置这个哈希块的状态（但继续在各块中递增计数器）。
					//更多的原始字节即将到来，所以这个chunk不是FlagRoot。
					if(HashMemoryChunkStateObject.CheckBlockSize() == Core::HashChunkBytesSize)
					{
						auto hash_memory_chunk = HashMemoryChunkStateObject.FinalChunk();
						std::array<Core::WordType, 8> chaining_value_state_data = hash_memory_chunk.ApplyChainingValue();
					
						//Update total memory chunk count
						HashMemoryChunkStateObject.counter += 1;

						AppendChunkChainingValue(chaining_value_state_data, HashMemoryChunkStateObject.counter);
						this->HashMemoryChunkStateObject = HashMemoryChunkState(this->chaining_value_or_keys, HashMemoryChunkStateObject.counter, this->hash_state_flags);
					}

					//Compress original bytes into the current chunk state.
					//将原始字节压缩到当前分块状态
					std::size_t want_byte_count = Core::HashChunkBytesSize - HashMemoryChunkStateObject.CheckBlockSize();
					std::size_t take_byte_count = std::min(want_byte_count, bytes_data.size_bytes() - index_of_bytes);
					std::vector<std::uint8_t> memory_data_slice = Core::Functions::MemoryDataSlice(bytes_data.data(), index_of_bytes, take_byte_count);
					HashMemoryChunkStateObject.UpdateChunk(memory_data_slice);
					index_of_bytes += take_byte_count;
				}

				index_of_bytes = 0;
			}

			void HashFinal(std::span<std::uint8_t> bytes_data)
			{
				if(bytes_data.empty() || (bytes_data.size() * 8) != this->hash_size_with_bit)
					return;

				//Starting with the Generated from the current chunk,
				//compute all the parent chaining values along the right edge of the tree,
				//until we have the root Generated bytes
				//从当前块中生成的开始。
				//沿着树的右边缘计算所有的父链值。
				//直到我们得到根部的生成字节。

				HashDataGenerator FinalChunkNode = HashMemoryChunkStateObject.FinalChunk();
				std::size_t ParentNodesRemaining = static_cast<std::size_t>(this->chaining_values_stack_size);

				while (ParentNodesRemaining > 0)
				{
					--ParentNodesRemaining;
					FinalChunkNode = BuildHashTreeParentNode
					(
						this->chaining_values_stack[ParentNodesRemaining],
						FinalChunkNode.ApplyChainingValue(),
						this->chaining_value_or_keys,
						this->hash_state_flags
					);
				}

				FinalChunkNode.BuildHashTreeRootNode(bytes_data);
			}

			void Clear()
			{
				volatile void* CheckPointer = nullptr;

				for( auto& that_array : this->chaining_values_stack )
				{
					CheckPointer = memory_set_no_optimize_function<0x00>(that_array.data(), that_array.size() * sizeof(Core::WordType));
					CheckPointer = nullptr;
				}
				this->chaining_values_stack_size = 0x00;
				CheckPointer = memory_set_no_optimize_function<0x00>(this->chaining_value_or_keys.data(), this->chaining_value_or_keys.size() * sizeof(Core::WordType));
				CheckPointer = nullptr;

				this->hash_state_flags = 0;
			}

			CoreWorker
			(
				std::array<Core::WordType, 8> chaining_value_or_keys,
				std::uint32_t hash_state_flags
			)
				:
				HashMemoryChunkStateObject(chaining_value_or_keys, 0U, hash_state_flags),
				chaining_value_or_keys(chaining_value_or_keys),
				hash_state_flags(hash_state_flags)
			{
				volatile void* CheckPointer = nullptr;
				
				for(auto& chaining_values_stack_data : this->chaining_values_stack)
				{
					CheckPointer = memory_set_no_optimize_function<0x00>(chaining_values_stack_data.data(), chaining_values_stack_data.size());
					CheckPointer = nullptr;
				}
			}

			CoreWorker()
				: 
				CoreWorker(HashProviderBaseTools::Blake::HashConstants<Core::WordType>::INITIAL_VECTOR, 0U)
			{

			}

			explicit CoreWorker(const std::array<std::uint8_t, Core::KeyBytesSize> chaining_value_or_keys_argument)
			{
				std::array<Core::WordType, 8> that_chaining_value_or_keys;

				std::memmove(that_chaining_value_or_keys.data(), chaining_value_or_keys_argument.data(), chaining_value_or_keys_argument.size());
				if constexpr(std::endian::native != std::endian::little)
				{
					for(auto& data_word : that_chaining_value_or_keys)
						data_word = CommonToolkit::ByteSwap::byteswap(data_word);
				}

				*this = CoreWorker(that_chaining_value_or_keys, Core::FlagKeyedHash);
			}

			CoreWorker(void *context, std::size_t context_size)
			{
				if(context == nullptr)
					my_cpp2020_assert(false, "", std::source_location::current());

				auto context_hasher = CoreWorker(HashProviderBaseTools::Blake::HashConstants<Core::WordType>::INITIAL_VECTOR, Core::FlagDeriveKeyContext);
			
				auto context_byte_span = std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(context), context_size);

				context_hasher.HashUpdate(context_byte_span);
				std::array<std::uint8_t, Core::KeyBytesSize> context_keys;
				context_hasher.HashFinal(context_keys);

				std::array<Core::WordType, 8> context_key_words;
				std::memmove(context_key_words.data(), context_keys.data(), context_keys.size());
				if constexpr(std::endian::native != std::endian::little)
				{
					for(auto& data_word : context_key_words)
						data_word = CommonToolkit::ByteSwap::byteswap(data_word);
				}

				*this = CoreWorker(context_key_words, Core::FlagDeriveKeyMaterial);
			}

			CoreWorker(const CoreWorker& other_object)
				:
				HashMemoryChunkStateObject(other_object.HashMemoryChunkStateObject),
				chaining_value_or_keys(other_object.chaining_value_or_keys),
				chaining_values_stack_size(other_object.chaining_values_stack_size),
				hash_state_flags(other_object.hash_state_flags),
				hash_size_with_bit(other_object.hash_size_with_bit)
			{
				
			}

			~CoreWorker()
			{
				this->Clear();
				this->hash_size_with_bit = 0;
			}
		};

		CoreWorker CoreWorkerObject;

	public:

		inline void UpdateStringKey(const std::string& string_key)
		{
			if( string_key.empty() )
			{
				return;
			}

			if( string_key.size() != Core::KeyBytesSize )
			{
				std::cout << "The string key you given is an invalid size!" << std::endl;
				return;
			}

			std::vector<std::uint8_t> bytes_key(Core::KeyBytesSize, 0x00);

			for(std::size_t bytes_index = 0; bytes_index < bytes_key.size(); ++bytes_index)
			{
				bytes_key[bytes_index] = static_cast<std::uint8_t>(string_key[bytes_index]);
			}

			if constexpr(CURRENT_SYSTEM_BITS == 32)
				CommonToolkit::BitConverters::le32_copy(bytes_key.data(), 0, this->CoreWorkerObject.chaining_value_or_keys.data(), 0, Core::KeyBytesSize);
			else
				CommonToolkit::BitConverters::le64_copy(bytes_key.data(), 0, this->CoreWorkerObject.chaining_value_or_keys.data(), 0, Core::KeyBytesSize);
		}

		inline void UpdateBytesKey(const std::span<std::uint8_t>& bytes_key)
		{
			if( bytes_key.empty() )
			{
				return;
			}

			if( bytes_key.size() != Core::KeyBytesSize )
			{
				std::cout << "The bytes key you given is an invalid size!" << std::endl;
				return;
			}

			if constexpr(CURRENT_SYSTEM_BITS == 32)
				CommonToolkit::BitConverters::le32_copy(bytes_key.data(), 0, this->CoreWorkerObject.chaining_value_or_keys.data(), 0, Core::KeyBytesSize);
			else
				CommonToolkit::BitConverters::le64_copy(bytes_key.data(), 0, this->CoreWorkerObject.chaining_value_or_keys.data(), 0, Core::KeyBytesSize);
		}

		inline void StepInitialize() override
		{
			this->CoreWorkerObject.Clear();
		}

		inline void StepUpdate( const std::span<const std::uint8_t> data_value_vector ) override
		{
			std::vector<std::uint8_t> bytes_buffer(data_value_vector.begin(), data_value_vector.end());
			
			this->CoreWorkerObject.HashUpdate(bytes_buffer);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(bytes_buffer.data(), bytes_buffer.size());

			CheckPointer = nullptr;
		}

		inline void StepFinal( std::span<std::uint8_t> hash_value_vector ) override
		{
			if(hash_value_vector.empty() || (hash_value_vector.size() % 4) != 0 || (hash_value_vector.size() % 8) != 0)
				return;
			
			this->CoreWorkerObject.HashFinal(hash_value_vector);
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
				this->CoreWorkerObject = CoreWorker();
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






#if 0

/* Deprecated */
namespace CommonSecurity::Blake3
{
	namespace Core
	{
		using CommonSecurity::Blake2::Core::WordType;
		using CommonSecurity::Blake2::Core::HashConstants;

		//Generated hash size is a 64 byte or 128 byte
		inline constexpr CommonToolkit::FourByte GeneratedHashBytesSize = CURRENT_SYSTEM_BITS == 32 ? 64 : 128;

		//Hash data block size is a 64 byte or 128 byte
		inline constexpr CommonToolkit::FourByte HashBlockBytesSize = CURRENT_SYSTEM_BITS == 32 ? 64 : 128;
		
		//Key size is a 32 byte or 64 byte
		inline constexpr CommonToolkit::FourByte KeyBytesSize = CURRENT_SYSTEM_BITS == 32 ? 32 : 64;
		
		//Hash memory chunk size is 1 kilo-byte
		inline constexpr CommonToolkit::FourByte HashChunkBytesSize = 1024;

		inline constexpr std::uint32_t FlagChunkStart = 1 << 0;
		inline constexpr std::uint32_t FlagChunkEnd = 1 << 1;
		inline constexpr std::uint32_t FlagParent = 1 << 2;
		inline constexpr std::uint32_t FlagRoot = 1 << 3;
		inline constexpr std::uint32_t FlagKeyedHash = 1 << 4;

		//inline constexpr std::uint32_t FlagDeriveKyContext = 1 << 5;
        //inline constexpr std::uint32_t FlagDeriveKeyMaterial = 1 << 6;

		//For each round of hashing execution, the permute table of the message data index
		//对于每一轮散列的执行，信息数据索引的permute表
		inline constexpr std::array<std::array<CommonToolkit::FourByte, 16>, 7> SIGMA_VECTOR_NEW
		{
			{
				{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
				{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
				{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
				{ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
				{ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
				{ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
				{ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
			},
		};

		namespace Functions
		{
			using CommonSecurity::Blake2::Core::Functions::ThisWordArray16Type;
			using CommonSecurity::Blake2::Core::Functions::LookupInitialVectorValue;

			static inline void HashValueMixer(std::size_t RoundNumber, std::size_t SigmaVectorIndex, WordType& ValueA, WordType& ValueB, WordType& ValueC, WordType& ValueD, const ThisWordArray16Type<WordType>& Message)
			{
				if constexpr(CURRENT_SYSTEM_BITS == 64)
				{
					ValueA = ValueA + ValueB + Message[SIGMA_VECTOR_NEW[RoundNumber][2 * SigmaVectorIndex]];
					ValueD = CommonSecurity::Binary_RightRotateMove<WordType>(ValueD ^ ValueA, 32);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove<WordType>(ValueB ^ ValueC, 24);

					ValueA = ValueA + ValueB + Message[SIGMA_VECTOR_NEW[RoundNumber][2 * SigmaVectorIndex + 1]];
					ValueD = CommonSecurity::Binary_RightRotateMove<WordType>(ValueD ^ ValueA, 16);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove<WordType>(ValueB ^ ValueC, 63);
				}
				else
				{
					ValueA = ValueA + ValueB + Message[SIGMA_VECTOR_NEW[RoundNumber][2 * SigmaVectorIndex]];
					ValueD = CommonSecurity::Binary_RightRotateMove<WordType>(ValueD ^ ValueA, 16);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove<WordType>(ValueB ^ ValueC, 12);

					ValueA = ValueA + ValueB + Message[SIGMA_VECTOR_NEW[RoundNumber][2 * SigmaVectorIndex + 1]];
					ValueD = CommonSecurity::Binary_RightRotateMove<WordType>(ValueD ^ ValueA, 8);
					ValueC += ValueD;
					ValueB = CommonSecurity::Binary_RightRotateMove<WordType>(ValueB ^ ValueC, 7);
				}
			}

			static inline void HashValueRound(std::size_t RoundNumber, const ThisWordArray16Type<WordType>& Message, ThisWordArray16Type<WordType>& CurrentInitialVector)
			{
				auto&
				[
					StateValue, StateValue2, StateValue3, StateValue4,
					StateValue5, StateValue6, StateValue7, StateValue8,
					StateValue9, StateValue10, StateValue11, StateValue12,
					StateValue13, StateValue14, StateValue15, StateValue16
				] = CurrentInitialVector;

				//Mix the columns

				HashValueMixer(RoundNumber, 0, StateValue, StateValue5, StateValue9, StateValue13, Message);
				HashValueMixer(RoundNumber, 1, StateValue2, StateValue6, StateValue10, StateValue14, Message);
				HashValueMixer(RoundNumber, 2, StateValue3, StateValue7, StateValue11, StateValue15, Message);
				HashValueMixer(RoundNumber, 3, StateValue4, StateValue8, StateValue12, StateValue16, Message);

				//Mix the diagonals.

				HashValueMixer(RoundNumber, 4, StateValue, StateValue6, StateValue11, StateValue16, Message);
				HashValueMixer(RoundNumber, 5, StateValue2, StateValue7, StateValue12, StateValue13, Message);
				HashValueMixer(RoundNumber, 6, StateValue3, StateValue8, StateValue9, StateValue14, Message);
				HashValueMixer(RoundNumber, 7, StateValue4, StateValue5, StateValue10, StateValue15, Message);
			}

			template<typename Type>
			static std::vector<Type>
			MemoryDataSlice(Type* data_pointer, std::size_t data_offset_index, std::size_t data_size)
			{
				if(data_pointer == nullptr || data_size == 0)
					return std::vector<Type>();

				std::vector<Type> memory_data_sliced(data_size, 0x00);
				std::ranges::copy_n(data_pointer + data_offset_index, data_size, memory_data_sliced.data() + 0);
				return memory_data_sliced;
			}
		}

		class HashDataGenerator
		{
			
		private:
			struct HashTreeNode
			{
				//The chaining value from the previous hash state
				std::array<Core::WordType, 8> ChainingValue;

				//The current origin word data
				std::array<Core::WordType, 16> DataWordBlock;
				Core::WordType Counter = 0;
				Core::WordType BlockSize = 0;
				Core::WordType HashStateFlags = 0;

				bool SupportOperationEqual(const HashTreeNode& left, const HashTreeNode& right) const
				{
					bool is_same_object = left.ChainingValue == right.ChainingValue;
					bool is_same_object2 = left.DataWordBlock == right.DataWordBlock;
					bool is_same_object3 = left.Counter == right.Counter;
					bool is_same_object4 = left.BlockSize == right.BlockSize;
					bool is_same_object5 = left.HashStateFlags == right.HashStateFlags;

					if
					(
						is_same_object
						&& is_same_object2
						&& is_same_object3
						&& is_same_object4
						&& is_same_object5
					)
					{
						return true;
					}
					else
					{
						return false;
					}
				}

				HashTreeNode()
					: 
					ChainingValue(std::array<Core::WordType, 8>()),
					DataWordBlock(std::array<Core::WordType, 16>()),
					Counter(0), BlockSize(0), HashStateFlags(0)
				{
			
				}

				HashTreeNode(const HashTreeNode& other) noexcept
					:
					ChainingValue(other.ChainingValue),
					DataWordBlock(other.DataWordBlock),
					Counter(other.Counter),
					BlockSize(other.BlockSize),
					HashStateFlags(other.HashStateFlags)
				{
				
				}

				~HashTreeNode() = default;

				HashTreeNode& operator=(const HashTreeNode& other)
				{
					if(this != std::addressof(other))
					{
						this->ChainingValue = other.ChainingValue;
						this->DataWordBlock = other.DataWordBlock;
						this->Counter = other.Counter;
						this->BlockSize = other.BlockSize;
						this->HashStateFlags = other.HashStateFlags;
					}
					return *this;
				}

				friend bool operator==(const HashTreeNode& left, const HashTreeNode& right)
				{
					if(std::addressof(left) != std::addressof(right))
					{
						left.SupportOperationEqual(left, right);
					}
					else
					{
						return true;
					}
				}

				static HashTreeNode MakeHashTreeNode
				(
					const std::array<Core::WordType, 8>& chaining_value_or_keys,
					const std::array<Core::WordType, 16>& hash_state_block,
					const Core::WordType& counter,
					const Core::WordType& block_size,
					const Core::WordType& state_flags
				)
				{
					HashTreeNode tree_node = HashTreeNode();
					tree_node.ChainingValue = chaining_value_or_keys;
					tree_node.DataWordBlock = hash_state_block;
					tree_node.Counter = counter;
					tree_node.BlockSize = block_size;
					tree_node.HashStateFlags = state_flags;
					return tree_node;
				}
			};

			// Compress is the core hash function, generating 16 pseudorandom words from a node.
			// NOTE: we unroll all of the rounds, as well as the permutations that occur between rounds.
			// Compress是核心的哈希函数，从一个节点生成16个伪随机字。
			// 注意：我们解开所有的轮次，以及轮次之间发生的排列组合。
			std::array<Core::WordType, 16> CompressHashStateData(HashTreeNode& hash_tree_node)
			{
				std::mutex _conditional_mutex;

				{

					/*
					std::array<Core::WordType, 16> state_data = std::array<Core::WordType, 16>();

					state_data[0] = hash_tree_node.ChainingValue[0];
					state_data[1] = hash_tree_node.ChainingValue[1];
					state_data[2] = hash_tree_node.ChainingValue[2];
					state_data[3] = hash_tree_node.ChainingValue[3];
					state_data[4] = hash_tree_node.ChainingValue[4];
					state_data[5] = hash_tree_node.ChainingValue[5];
					state_data[6] = hash_tree_node.ChainingValue[6];
					state_data[7] = hash_tree_node.ChainingValue[7];
					state_data[8] = Core::Functions::LookupInitialVectorValue(0);
					state_data[9] = Core::Functions::LookupInitialVectorValue(1);
					state_data[10] = Core::Functions::LookupInitialVectorValue(2);
					state_data[11] = Core::Functions::LookupInitialVectorValue(3);
					state_data[12] = static_cast<std::uint32_t>(hash_tree_node.ChunkCounter);
					state_data[13] = static_cast<std::uint32_t>(hash_tree_node.ChunkCounter >> 32);
					state_data[14] = static_cast<std::uint32_t>(hash_tree_node.BlockSize);
					state_data[15] = static_cast<std::uint32_t>(HashStateFlags);
					*/

					std::array<Core::WordType, 16> state_data
					{
						hash_tree_node.ChainingValue[0],
						hash_tree_node.ChainingValue[1],
						hash_tree_node.ChainingValue[2],
						hash_tree_node.ChainingValue[3],
						hash_tree_node.ChainingValue[4],
						hash_tree_node.ChainingValue[5],
						hash_tree_node.ChainingValue[6],
						hash_tree_node.ChainingValue[7],
						Core::Functions::LookupInitialVectorValue(0),
						Core::Functions::LookupInitialVectorValue(1),
						Core::Functions::LookupInitialVectorValue(2),
						Core::Functions::LookupInitialVectorValue(3),
						static_cast<Core::WordType>(hash_tree_node.Counter),
						static_cast<Core::WordType>(hash_tree_node.Counter >> 32),
						static_cast<Core::WordType>(hash_tree_node.BlockSize),
						static_cast<Core::WordType>(HashStateFlags)
					};

					auto spin_lock_with_scoped { std::scoped_lock(_conditional_mutex) };

					for(std::size_t rounds_number = 0; rounds_number < 7; ++rounds_number)
					{
						Core::Functions::HashValueRound(rounds_number, hash_tree_node.DataWordBlock, state_data);
					}

					/*
					state_data[0] ^= state_data[8];
					state_data[1] ^= state_data[9];
					state_data[2] ^= state_data[10];
					state_data[3] ^= state_data[11];
					state_data[4] ^= state_data[12];
					state_data[5] ^= state_data[13];
					state_data[6] ^= state_data[14];
					state_data[7] ^= state_data[15];
					state_data[8] ^= hash_tree_node.ChainingValue[0];
					state_data[9] ^= hash_tree_node.ChainingValue[1];
					state_data[10] ^= hash_tree_node.ChainingValue[2];
					state_data[11] ^= hash_tree_node.ChainingValue[3];
					state_data[12] ^= hash_tree_node.ChainingValue[4];
					state_data[13] ^= hash_tree_node.ChainingValue[5];
					state_data[14] ^= hash_tree_node.ChainingValue[6];
					state_data[15] ^= hash_tree_node.ChainingValue[7];
					*/

					for(std::size_t index = 0; index < 8; ++index)
					{
						state_data[index] ^= state_data[index + 8];
						state_data[index + 8] ^= hash_tree_node.ChainingValue[index];
					}

					return state_data;
				}
			}

			HashTreeNode CurrentHashTreeParentNode
			(
				const std::array<Core::WordType, 8>& left_state_block,
				const std::array<Core::WordType, 8>& right_state_block,
				const std::array<Core::WordType, 8>& chaining_value_or_keys,
				const Core::WordType& state_flags
			)
			{
				//Hash state data concatenated
				//串联的哈希状态数据
				std::array<Core::WordType, 16> hash_state_block = std::array<Core::WordType, 16>();
				
				//Apply concatenate operation
				//应用串联操作
				/*
				for(std::size_t index = 0; index < hash_state_block.size(); ++index)
				{
					if(index < 8)
					{
						hash_state_block[index] = left_state_block[index];
					}
					else
					{
						hash_state_block[index] = right_state_block[index - 8];
					}
				}
				*/

				std::memmove(hash_state_block.data(), left_state_block.data(), left_state_block.size() * sizeof(Core::WordType));
				std::memmove(hash_state_block.data() + 8, right_state_block.data(), right_state_block.size() * sizeof(Core::WordType));

				return HashTreeNode::MakeHashTreeNode
				(
					chaining_value_or_keys,
					hash_state_block,
					0,
					Core::HashBlockBytesSize,
					state_flags | Core::FlagParent
				);
			}

			HashTreeNode TreeNode;

		public:
			std::size_t HashGeneratedByteSize = 0;
			std::uint32_t HashStateFlags = 0;

			// ChainingValue returns the first 8 words of the compressed node. 
			// This is used in two places.
			// First, when a block node is constructed, its (ChainingValue) is overwritten by this value after each block of data from the argument has been processed.
			// Second, when two nodes are merged into a parent node, each of their chaining values provides half of the content of the new node's block.
			// ChainingValue返回压缩节点的前8个字。 
			// 这在两个地方使用。
			// 首先，当一个块状节点被构建时，它的（ChainingValue）在每个来自参数的数据块被处理后会被这个值所覆盖。
			// 第二，当两个节点合并到一个父节点时，它们的每一个链值都会为新节点的块提供一半的内容。
			std::array<Core::WordType, 8> ApplyChainingValue()
			{
				std::array<Core::WordType, 8> chaining_state_data = std::array<Core::WordType, 8>();
				
				std::array<Core::WordType, 16> current_state_data = CompressHashStateData(TreeNode);

				//std::memmove(chaining_state_data.data() + 0, current_state_data.data() + 0, 8 * sizeof(Core::WordType));
				std::ranges::copy_n( current_state_data.data() + 0, 8, chaining_state_data.data() + 0 );

				return chaining_state_data;
			}

			std::array<Core::WordType, 8> ApplyChainingValue(HashTreeNode& hash_tree_node)
			{
				std::array<Core::WordType, 8> chaining_state_data = std::array<Core::WordType, 8>();
				
				std::array<Core::WordType, 16> current_state_data = CompressHashStateData(hash_tree_node);

				//std::memmove(chaining_state_data.data() + 0, current_state_data.data() + 0, 8 * sizeof(Core::WordType));
				std::ranges::copy_n( current_state_data.data() + 0, 8, chaining_state_data.data() + 0 );

				return chaining_state_data;
			}

			/*
			
			void ApplyChainingValue(std::array<Core::WordType, 16>& chaining_state_data)
			{
				std::array<Core::WordType, 16> current_state_data = std::array<Core::WordType, 16>();
				CompressStateData(current_state_data);
				std::memmove(&chaining_state_data[0], &current_state_data[0], 8 * sizeof(std::uint64_t));
			}

			*/

			std::array<Core::WordType, 8> ChainedValueOfCurrentParentTreeNode
			(
				std::array<Core::WordType, 8> LeftChildNodeChainedValue,
				std::array<Core::WordType, 8> RightChildNodeChainedValue,
				std::array<Core::WordType, 8> initial_vector_or_processed_key,
				std::uint32_t hash_state_flags
			)
			{
				HashTreeNode hash_tree_parent_node = CurrentHashTreeParentNode
				(
					LeftChildNodeChainedValue,
					RightChildNodeChainedValue,
					initial_vector_or_processed_key,
					hash_state_flags
				);

				return ApplyChainingValue(hash_tree_parent_node);
			}

			void ChangeHashTreeNodeData
			(
				const std::array<Core::WordType, 8>& chaining_value_or_keys,
				const std::array<Core::WordType, 16>& hash_state_block,
				const Core::WordType& counter,
				const Core::WordType& block_size,
				const Core::WordType& state_flags
			)
			{
				TreeNode.ChainingValue = chaining_value_or_keys;
				TreeNode.DataWordBlock = hash_state_block;
				TreeNode.Counter = counter;
				TreeNode.BlockSize = block_size;
				TreeNode.HashStateFlags = state_flags;
			}

			void ComputeDataOfHashTreeRootNode
			(
				std::span<std::uint8_t> generated_hash_data
			)
			{
				if(generated_hash_data.empty())
					return;

				if(generated_hash_data.size() % 8 != 0)
					return;

				HashGeneratedByteSize = generated_hash_data.size();

				Core::WordType GenerateBlockCounter = 0;

				for (std::size_t round = 0; HashGeneratedByteSize != 0; ++round)
				{
					TreeNode.Counter = GenerateBlockCounter;
					TreeNode.HashStateFlags |= Core::FlagRoot;

					std::array<Core::WordType, 16> current_state_words_data = CompressHashStateData(TreeNode);

					if constexpr(std::endian::native != std::endian::little)
					{
						for(std::size_t current_state_word_index = 0; current_state_word_index < current_state_words_data.size(); ++current_state_word_index)
						{
							Core::WordType& current_state_word = current_state_words_data[current_state_word_index];
							current_state_word = CommonToolkit::ByteSwap::byteswap(current_state_word);
						}
					}

					if(round * Core::GeneratedHashBytesSize < generated_hash_data.size())
					{
						std::memmove(generated_hash_data.data() + round * Core::GeneratedHashBytesSize, std::addressof(current_state_words_data), Core::GeneratedHashBytesSize);

						HashGeneratedByteSize -= Core::GeneratedHashBytesSize;
					}

					++GenerateBlockCounter;
				}

				return;
			}

			HashDataGenerator
			(
				std::array<Core::WordType, 8>& chaining_value_or_keys,
				std::array<Core::WordType, 16>& hash_state_block,
				Core::WordType counter,
				Core::WordType block_size,
				Core::WordType state_flags,
				std::size_t hash_generated_byte_size
			)
				: 
				TreeNode(HashDataGenerator::HashTreeNode::MakeHashTreeNode(chaining_value_or_keys, hash_state_block, counter, block_size,  state_flags)),
				HashGeneratedByteSize(hash_generated_byte_size)
			{
			
			}

			HashDataGenerator(const HashDataGenerator& other)
				:
				TreeNode(other.TreeNode),
				HashGeneratedByteSize(other.HashGeneratedByteSize),
				HashStateFlags(other.HashStateFlags)
			{
				
			}

			HashDataGenerator() = delete;
			~HashDataGenerator() = default;

		};

		//HashMemoryChunkState manages the state involved in hashing a single chunk of from other data bytes.
		//HashMemoryChunkState管理着从其他数据字节中散列出一个单一块的状态。
		class HashMemoryChunkState
		{

		private:
			std::array<Core::WordType, Core::KeyBytesSize / 8> ChainingValue;
			std::uint32_t HashStateFlags = 0;

			std::array<std::uint8_t, Core::HashBlockBytesSize> _this_byte_block;
			std::uint8_t _this_byte_block_size = 0;
			std::uint8_t _byte_block_compressed = 0;

		public:
			std::size_t ChunkCounter = 0;

			std::size_t CheckBlockSize() const
			{
				return Core::HashBlockBytesSize * static_cast<std::size_t>(_byte_block_compressed) + static_cast<std::size_t>(_this_byte_block_size);
			}

			std::uint32_t RequestBlockFlagStart()
			{
				return _byte_block_compressed == 0 ? Core::FlagChunkStart : 0;
			}

			bool CheckIsByteBlockComplete() const
			{
				return _this_byte_block_size == Core::HashBlockBytesSize;
			}

			void UpdateChunk(const std::span<std::uint8_t> words_data_span, HashDataGenerator& HashDataGeneratorObject)
			{
				std::vector<std::uint8_t> temporary_data(words_data_span.begin(), words_data_span.end());

				//Copy the chunk block (bytes) into the node block and chain it.
				//将大块数据（字节）复制到节点块中，并将其连锁。

				while(temporary_data.size() > 0)
				{
					//If the block buffer is full, compress it and clear it. 
					//More data bytes is coming, so this compression is not FlagChunkEnd.
					//如果块缓冲区满了，就压缩它并清除它。
					//更多的字节数据正在到来，所以这个压缩不是FlagChunkEnd。
					if(CheckIsByteBlockComplete())
					{
						std::array<Core::WordType, 16> data_words_block = std::array<Core::WordType, 16>();

						if constexpr(CURRENT_SYSTEM_BITS == 32)
							CommonToolkit::BitConverters::le32_copy(_this_byte_block.data(), 0, data_words_block.data(), 0, _this_byte_block_size);
						else
							CommonToolkit::BitConverters::le64_copy(_this_byte_block.data(), 0, data_words_block.data(), 0, _this_byte_block_size);

						HashDataGeneratorObject.ChangeHashTreeNodeData
						(
							ChainingValue,
							data_words_block,
							ChunkCounter,
							Core::HashBlockBytesSize,
							HashStateFlags | Core::FlagChunkStart
						);

						ChainingValue = HashDataGeneratorObject.ApplyChainingValue();

						++_byte_block_compressed;
						_this_byte_block.fill(0x00);
						_this_byte_block_size = 0x00;

						data_words_block.fill(0x00);
					}

					//Copy original bytes into the byte block buffer.
					//将原始字节复制到字节块缓冲区。
					std::size_t want = Core::HashBlockBytesSize - _this_byte_block_size;
					std::size_t take = std::min(want, temporary_data.size());

					/*
					if constexpr(CURRENT_SYSTEM_BITS == 32)
						CommonToolkit::BitConverters::le32_copy(temporary_data.data(), 0, _this_byte_block.data(), _this_byte_block_size, take);
					else
						CommonToolkit::BitConverters::le64_copy(temporary_data.data(), 0, _this_byte_block.data(), _this_byte_block_size, take);
					*/

					if constexpr(CURRENT_SYSTEM_BITS == 64)
					{
						std::ranges::copy_n( temporary_data.data() + 0, take, _this_byte_block.data() + 0 );
						if(_this_byte_block.data() != nullptr && _this_byte_block.size() == take)
							_this_byte_block_size += take;
						else
							my_cpp2020_assert(false, "", std::source_location::current());
					}
					else if constexpr(CURRENT_SYSTEM_BITS == 32)
					{
						std::ranges::copy_n( temporary_data.data() + 0, take, _this_byte_block.data() + 0 );
						std::ranges::copy_n( temporary_data.data() + take, take, _this_byte_block.data() + take );

						if(_this_byte_block.data() != nullptr && _this_byte_block.size() == take)
							_this_byte_block_size += take * 2;
						else
							my_cpp2020_assert(false, "", std::source_location::current());
					}
					else
					{
						static_assert(CURRENT_SYSTEM_BITS == 32 || CURRENT_SYSTEM_BITS == 64, "Unknown number of system bits");
					}

					std::vector<std::uint8_t> memory_data_slice = Core::Functions::MemoryDataSlice(temporary_data.data(), take, temporary_data.size() - take);
					temporary_data.clear();
					temporary_data.shrink_to_fit();
					temporary_data = std::move(memory_data_slice);
				}

				return;
			}

			//Node returns a node containing the chunkState's current state, with set the FlagChunkEnd
			//Node返回一个包含chunkState当前状态的节点，并设置FlagChunkEnd。
			HashDataGenerator HashDataGenerator_CurrentTreeNode(std::size_t HashGeneratedByteSize)
			{
				std::array<Core::WordType, 16> data_words_block = std::array<Core::WordType, 16>();

				if constexpr(CURRENT_SYSTEM_BITS == 32)
					CommonToolkit::BitConverters::le32_copy(&_this_byte_block[0], 0, data_words_block.data(), 0, HashBlockBytesSize);
				else
					CommonToolkit::BitConverters::le64_copy(&_this_byte_block[0], 0, data_words_block.data(), 0, HashBlockBytesSize);

				HashDataGenerator hash_data_generator = HashDataGenerator
				(
					ChainingValue,
					data_words_block,
					ChunkCounter,
					_this_byte_block_size,
					HashStateFlags,
					HashGeneratedByteSize
				);

				//Compress the first block with the set FlagChunkStart
				//用设定的FlagChunkStart压缩第一个区块
				hash_data_generator.HashStateFlags = HashStateFlags | RequestBlockFlagStart();
				hash_data_generator.HashStateFlags |= FlagChunkEnd;

				return hash_data_generator;
			}

			HashDataGenerator HashDataGenerator_BuildHashTreeParentNode
			(
				const HashDataGenerator& hash_data_generator,
				const std::array<Core::WordType, 8>& left_state_block,
				const std::array<Core::WordType, 8>& right_state_block,
				const std::array<Core::WordType, 8>& chaining_value_or_keys,
				const Core::WordType& state_flags
			)
			{
				HashDataGenerator hash_data_generator_copy(hash_data_generator);

				//串联的哈希状态数据
				std::array<Core::WordType, 16> hash_state_block = std::array<Core::WordType, 16>();
				
				//Apply concatenate operation
				//应用串联操作
				/*
				for(std::size_t index = 0; index < hash_state_block.size(); ++index)
				{
					if(index < 8)
					{
						hash_state_block[index] = left_state_block[index];
					}
					else
					{
						hash_state_block[index] = right_state_block[index - 8];
					}
				}
				*/

				std::memmove(hash_state_block.data(), left_state_block.data(), left_state_block.size() * sizeof(Core::WordType));
				std::memmove(hash_state_block.data() + 8, right_state_block.data(), right_state_block.size() * sizeof(Core::WordType));

				hash_data_generator_copy.ChangeHashTreeNodeData
				(
					chaining_value_or_keys,
					hash_state_block,
					0, 
					sizeof(Core::HashBlockBytesSize),
					state_flags | Core::FlagParent
				);

				return hash_data_generator_copy;
			}

			HashMemoryChunkState
			(
				std::array<Core::WordType, Core::KeyBytesSize / 8> iniital_vector_or_processed_key,
				std::size_t chunk_counter,
				std::uint32_t hash_state_flags
			)
				:
				ChainingValue(iniital_vector_or_processed_key),
				_this_byte_block(std::array<std::uint8_t, HashBlockBytesSize>()),
				ChunkCounter(chunk_counter),
				HashStateFlags(hash_state_flags)
			{
			
			}

			HashMemoryChunkState(const HashMemoryChunkState& other)
				:
				ChainingValue(other.ChainingValue),
				_this_byte_block(other._this_byte_block),
				HashStateFlags(other.HashStateFlags),
				_this_byte_block_size(other._this_byte_block_size),
				_byte_block_compressed(other._byte_block_compressed),
				ChunkCounter(other.ChunkCounter)
			{
			
			}

			HashMemoryChunkState& operator=(const HashMemoryChunkState& other)
			{
				if(this != std::addressof(other))
				{
					this->ChainingValue  =other.ChainingValue ,
					this->_this_byte_block = other._this_byte_block,
					this->HashStateFlags = other.HashStateFlags,
					this->_this_byte_block_size = other._this_byte_block_size,
					this->_byte_block_compressed = other._byte_block_compressed,
					this->ChunkCounter = other.ChunkCounter;
				}
				return *this;
			}

			HashMemoryChunkState() = default;
			~HashMemoryChunkState() = default;
		};
	}

	// Blake3 refernce source code 
	// https://github.dev/IZIDIA/MinecraftLauncherCsharp/blob/main/BLAKE3.cs
	// https://github.dev/oconnor663/blake3_reference_impl_c/blob/main/reference_impl.c
	// Modified by Twilight-Dream
	class HashProvider : public CommonSecurity::HashProviderBaseTools::InterfaceHashProvider
	{

	private:
		using NumberCounterType = std::conditional_t<CURRENT_SYSTEM_BITS == 32, std::int32_t, std::int64_t>;

		std::array<std::uint8_t, Core::KeyBytesSize> _OriginKey = std::array<std::uint8_t, Core::KeyBytesSize>();
		std::array<Core::WordType, 8> _ProcessedKey = std::array<Core::WordType, 8>();

		std::size_t _hash_size = 0;
		std::size_t _position = 0;
		CommonToolkit::EightByte _total_bit = 0;

		std::vector<std::uint8_t> _HashStateArrayData;
		std::uint32_t _HashStateFlags = 0;

		struct ChainedValueFromHashTreeNodeOfStack
		{
			//Limit on the number of stack elements (hash tree nodes)
			//堆栈元素的数量限制（哈希树节点）
			static constexpr std::size_t LimitOnTheNumberOfStackElements = 54;

			// log(n) set of Merkle subtree roots, at most one per height.
			// log(n) Merkle子树根的集合，每个高度最多一个。
			// std::uint32 stack [54][8]
			// 2^54 * chunkSize = 2^64
			std::deque<std::array<Core::WordType, 8>> MerkleTreeRootNodeOfStack = std::deque<std::array<Core::WordType, 8>>();

			//Bit vector indicating which stack elems are valid;
			//Also number of chunks added
			//表示哪些堆栈元素是有效的比特位向量。
			//也是添加的块的数量
			std::size_t UsedStackElementsNumber = 0;

			std::array<Core::WordType, 8>& CheckTop()
			{
				return MerkleTreeRootNodeOfStack.back();
			}

			void Push(std::array<Core::WordType, 8> chain_value)
			{
				if(UsedStackElementsNumber == LimitOnTheNumberOfStackElements)
					return;

				MerkleTreeRootNodeOfStack.push_back(chain_value);

				UsedStackElementsNumber = MerkleTreeRootNodeOfStack.size();
			}
			
			std::array<Core::WordType, 8> Pop()
			{
				if(UsedStackElementsNumber == 0)
					return std::array<Core::WordType, 8>();

				std::array<Core::WordType, 8>& chain_value = CheckTop();

				MerkleTreeRootNodeOfStack.pop_back();

				UsedStackElementsNumber = MerkleTreeRootNodeOfStack.size();

				return chain_value;
			}

			ChainedValueFromHashTreeNodeOfStack() = default;

			ChainedValueFromHashTreeNodeOfStack(const ChainedValueFromHashTreeNodeOfStack& other)
				:
				MerkleTreeRootNodeOfStack(other.MerkleTreeRootNodeOfStack),
				UsedStackElementsNumber(other.UsedStackElementsNumber)
			{
			
			}

			~ChainedValueFromHashTreeNodeOfStack()
			{
				MerkleTreeRootNodeOfStack.clear();
				UsedStackElementsNumber = 0;
			}
		};

		//Appends a chunk to the right edge of the Merkle tree (HashTreeNode).
		//在Merkle树（HashTreeNode）的右侧边缘添加一个分块。
		void AppendChunkChainingValue(std::array<Core::WordType, 8> chaining_state_data, std::size_t total_chunk_number)
		{
			// This chunk might complete some subtrees
			// For each completed subtree, its left child will be the current top entry in the CV stack, and its right child will be the current value of `new_cv`.
			// Pop each left child off the stack, merge it with `new_cv`, and overwrite `new_cv` with the result.
			// After all these merges, push the final value of `new_cv` onto the stack.
			// The number of completed subtrees is given by the number of trailing 0-bits in the new total number of chunks.
			// 这个块可能会完成一些子树
			// 对于每个完成的子树，其左边的子树将是CV堆栈中当前最上面的条目，而其右边的子树将是`new_cv`的当前值。
			// 从堆栈中弹出每个左子，与`new_cv`合并，并将结果覆盖`new_cv`。
			// 在所有这些合并之后，把`new_cv`的最终值推到栈上。
			// 完成的子树的数量由新的总块数中尾部0比特的数量给出。

			while ((total_chunk_number & 1) == 0)
			{
				chaining_state_data = HashDataGeneratorObject.ChainedValueOfCurrentParentTreeNode
				(
					ChainedValueFromHashTreeNodeOfStackObject.Pop(),
					chaining_state_data,
					_ProcessedKey,
					_HashStateFlags
				);

				total_chunk_number >>= 1;
			}

			ChainedValueFromHashTreeNodeOfStackObject.Push(chaining_state_data);
		}

		inline void hash_transform( const CommonToolkit::OneByte* data, std::size_t data_offset_index, std::size_t data_number_blocks )
		{
			std::uint8_t* work_data_pointer = nullptr; 
			if(data_offset_index != 0)
				work_data_pointer = const_cast<std::uint8_t*>(data + data_offset_index);
			else
				work_data_pointer = const_cast<std::uint8_t*>(data);

			auto span_block_size = (data_number_blocks - data_offset_index) * Core::HashChunkBytesSize;
			auto index = data_offset_index;

			while ( index < span_block_size )
			{
				//If the current chunk is complete, finalize add chunk data it to the tree.
				//Then reset this hash chunk state (but keep incrementing the counter across chunks).
				//More orginal bytes is coming, so this chunk is not FlagRoot. 
				//如果当前块已经完成，最终确定将块数据添加到树中。
				//然后重置这个哈希块的状态（但继续在各块中递增计数器）。
				//更多的原始字节即将到来，所以这个chunk不是FlagRoot。
				if(HashChunkStateObject.CheckBlockSize() == Core::HashChunkBytesSize)
				{
					std::array<Core::WordType, 8> chaining_value_state_data = HashDataGeneratorObject.ApplyChainingValue();
					
					//Update total memory chunk count
					HashChunkStateObject.ChunkCounter += 1;

					AppendChunkChainingValue(chaining_value_state_data, HashChunkStateObject.ChunkCounter);
					HashChunkStateObject = Core::HashMemoryChunkState(_ProcessedKey, HashChunkStateObject.ChunkCounter, _HashStateFlags);
				}

				//Compress original bytes into the current chunk state.
				//将原始字节压缩到当前分块状态
				std::size_t want = Core::HashChunkBytesSize - HashChunkStateObject.CheckBlockSize();
				std::size_t take = std::min(want, span_block_size);
				std::vector<std::uint8_t> memory_data_slice = Core::Functions::MemoryDataSlice(work_data_pointer, index, take);
				HashChunkStateObject.UpdateChunk(memory_data_slice, HashDataGeneratorObject);
				index += take;
				span_block_size -= index;
			}
		}

		//For First Build
		Core::HashMemoryChunkState HashChunkStateObject;

		//For Last Build
		Core::HashDataGenerator HashDataGeneratorObject;
		ChainedValueFromHashTreeNodeOfStack ChainedValueFromHashTreeNodeOfStackObject;

	public:
		inline void UpdateStringKey(std::string& Key)
		{
			if(Key.empty())
			{
				Key = std::move(std::string(Core::KeyBytesSize, 0x00));
			}

			if( Key.size() != Core::KeyBytesSize )
			{
				std::cout << "The string key you given is an invalid size!" << std::endl;
				return;
			}
			
			for( auto& Character : Key )
			{
				for(auto& Byte : _OriginKey)
				{
					Byte = static_cast<std::uint8_t>(Character);
				}
			}

			if(_OriginKey == std::array<std::uint8_t, Core::KeyBytesSize>())
			{
				_ProcessedKey = Core::HashConstants<Core::WordType>::INITIAL_VECTOR;
				return;
			}

			std::size_t KeySize = Key.size();

			if constexpr(CURRENT_SYSTEM_BITS == 32)
				CommonToolkit::BitConverters::le32_copy(Key.data(), 0, &_ProcessedKey[0], 0, KeySize);
			else
				CommonToolkit::BitConverters::le64_copy(Key.data(), 0, &_ProcessedKey[0], 0, KeySize);

			_HashStateFlags |= Core::FlagKeyedHash;

			HashChunkStateObject = Core::HashMemoryChunkState(_ProcessedKey, 0, _HashStateFlags);
			HashDataGeneratorObject = HashChunkStateObject.HashDataGenerator_CurrentTreeNode(_hash_size / 8);
		}

		inline void UpdateBytesKey(const std::span<std::uint8_t>& Key)
		{
			if(Key.empty())
			{
				_ProcessedKey = Core::HashConstants<Core::WordType>::INITIAL_VECTOR;
				return;
			}

			if( Key.size() != Core::KeyBytesSize )
			{
				std::cout << "The bytes key you given is an invalid size!" << std::endl;
				return;
			}

			std::size_t KeySize = Key.size();

			std::memmove(_OriginKey.data(), Key.data(), Key.size());

			if constexpr(CURRENT_SYSTEM_BITS == 32)
				CommonToolkit::BitConverters::le32_copy(Key.data(), 0, &_ProcessedKey[0], 0, KeySize);
			else
				CommonToolkit::BitConverters::le64_copy(Key.data(), 0, &_ProcessedKey[0], 0, KeySize);

			_HashStateFlags |= Core::FlagKeyedHash;
			HashChunkStateObject = Core::HashMemoryChunkState(_ProcessedKey, 0, _HashStateFlags);
			HashDataGeneratorObject = HashChunkStateObject.HashDataGenerator_CurrentTreeNode(_hash_size / 8);
		}

		inline void StepInitialize() override
		{
			if(_ProcessedKey == std::array<Core::WordType, 8>())
				_ProcessedKey = Core::HashConstants<Core::WordType>::INITIAL_VECTOR;

			HashChunkStateObject = Core::HashMemoryChunkState(_ProcessedKey, 0, _HashStateFlags);
			ChainedValueFromHashTreeNodeOfStackObject = ChainedValueFromHashTreeNodeOfStack();
			_HashStateArrayData = std::vector<std::uint8_t>(_hash_size / 8, 0x00);
		}

		inline void StepUpdate( const std::span<const std::uint8_t> data_value_vector ) override
		{
			const auto* data_pointer = data_value_vector.data();
			auto data_size = data_value_vector.size();

			if(data_pointer == nullptr)
				return;

			if(data_size < Core::HashChunkBytesSize)
				return;

			auto lambda_Transform = [ this ]( const std::uint8_t* data, std::size_t data_blocks_size )
			{
				this->hash_transform( data, 0, data_blocks_size );
			};

			HashProviderBaseTools::absorb_bytes( data_pointer, data_size, Core::HashChunkBytesSize, Core::HashChunkBytesSize, _HashStateArrayData.data(), _position, _total_bit, lambda_Transform );
		}

		inline void StepFinal( std::span<std::uint8_t> hash_value_vector ) override
		{
			if(hash_value_vector.data() == nullptr)
				return;

			Core::HashDataGenerator hash_data_generator = HashChunkStateObject.HashDataGenerator_CurrentTreeNode(_hash_size / 8);
			std::size_t ParentNodesRemaining = ChainedValueFromHashTreeNodeOfStackObject.UsedStackElementsNumber;

			while (ParentNodesRemaining > 0)
			{
				--ParentNodesRemaining;
				hash_data_generator = HashChunkStateObject.HashDataGenerator_BuildHashTreeParentNode
				(
					hash_data_generator,
					ChainedValueFromHashTreeNodeOfStackObject.MerkleTreeRootNodeOfStack[ParentNodesRemaining],
					hash_data_generator.ApplyChainingValue(),
					_ProcessedKey,
					_HashStateFlags
				);
			}

			hash_data_generator.ComputeDataOfHashTreeRootNode(hash_value_vector);
			
			StepInitialize();
		}

		inline std::size_t HashSize() const override
		{
			return _hash_size;
		}

		inline void Clear() override
		{
			HashProviderBaseTools::zero_memory(_HashStateArrayData.data(), _HashStateArrayData.size());
			HashProviderBaseTools::zero_memory(_OriginKey);
			HashProviderBaseTools::zero_memory(_ProcessedKey);
		}

		HashProvider( std::size_t hashsize )
			: _hash_size( hashsize ),
			_HashStateArrayData(),
			HashChunkStateObject(_ProcessedKey, 0, _HashStateFlags),
			HashDataGeneratorObject(HashChunkStateObject.HashDataGenerator_CurrentTreeNode(_hash_size / 8)),
			ChainedValueFromHashTreeNodeOfStackObject()
		{
			
		}

		HashProvider( const HashProvider& other )
			: _hash_size( other._hash_size ),
			_HashStateArrayData(other._HashStateArrayData),
			HashChunkStateObject(other.HashChunkStateObject),
			HashDataGeneratorObject(other.HashDataGeneratorObject),
			ChainedValueFromHashTreeNodeOfStackObject(other.ChainedValueFromHashTreeNodeOfStackObject)
		{
			
		}

		~HashProvider()
		{
			this->Clear();
		}

		HashProvider() = delete;
	};
}

#endif