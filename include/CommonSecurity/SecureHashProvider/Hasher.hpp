/*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * 本文件是 TDOM-EncryptOrDecryptFile-Reborn 的一部分。
 *
 * TDOM-EncryptOrDecryptFile-Reborn 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 TDOM-EncryptOrDecryptFile-Reborn 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */

 /*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * This file is part of TDOM-EncryptOrDecryptFile-Reborn.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "SecureHashProviderBase.hpp"
#include "AlgorithmBlake2.hpp"
#include "AlgorithmBlake3.hpp"
#include "AlgorithmChinaShangYongMiMa3.hpp"
#include "AlgorithmVersion2.hpp"
#include "AlgorithmVersion3.hpp"

namespace CommonSecurity::FNV_1a::Hasher
{
	/*
	
	template <std::size_t FnvPrime, std::size_t OffsetBasis>
    struct no_cryptography_hash_algorithm_fnv_1
    {
        std::size_t operator()(std::string const& text) const
        {
            std::size_t hash = OffsetBasis;
            for(std::string::const_iterator it = text.begin(), end = text.end();
                    it != end; ++it)
            {
                hash *= FnvPrime;
                hash ^= *it;
            }

            return hash;
        }
    };

    template <std::size_t FnvPrime, std::size_t OffsetBasis>
    struct no_cryptography_hash_algorithm_fnv_1a
    {
        std::size_t operator()(std::string const& text) const
        {
            std::size_t hash = OffsetBasis;
            for(std::string::const_iterator it = text.begin(), end = text.end();
                    it != end; ++it)
            {
                hash ^= *it;
                hash *= FnvPrime;
            }

            return hash;
        }
    };

    // For 32 bit machines:
    const std::size_t fnv_prime = 16777619u;
    const std::size_t fnv_offset_basis = 2166136261u;
	
    // For 64 bit machines:
    // const std::size_t fnv_prime = 1099511628211u;
    // const std::size_t fnv_offset_basis = 14695981039346656037u;

    // For 128 bit machines:
    // const std::size_t fnv_prime = 309485009821345068724781401u;
    // const std::size_t fnv_offset_basis =
    //     275519064689413815358837431229664493455u;

    // For 256 bit machines:
    // const std::size_t fnv_prime =
    //     374144419156711147060143317175368453031918731002211u;
    // const std::size_t fnv_offset_basis =
    //     100029257958052580907070968620625704837092796014241193945225284501741471925557u;
	
	*/

	class hash_combine
	{

	public:

		hash_combine(std::size_t seed = 0) : hash_seed(seed)
		{}

		template <class Type>
		std::size_t operator()(Type object) noexcept
		{
			return this->hash_value<Type>(object);
		}

	private:

		std::size_t hash_seed = 0;

		template<typename Type>
		std::size_t hash_value(Type& object) noexcept
		{
			//(1UL << 31) / ((1 + std::sqrt(5)) / 4) == 0x9E3779B9
			constexpr std::size_t golden_ration = 0x9e3779b9;
			//Then I see the implementation of this function
			//The principle of std::hash<Type> is based on the FNV-1a is a non-cryptographic hash function
			//https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
			auto hashed_value = std::hash<Type>()(object);
			hash_seed ^= hashed_value + golden_ration + (hash_seed << 6) + (hash_seed >> 2);
			return hash_seed;
		}
	};
} // namespace CommonSecurity::FNV_1a::Hasher

//安全的散列算法
//Secure Hash Algorithm
namespace CommonSecurity::SHA::Hasher
{
	using namespace CommonSecurity;

	enum class WORKER_MODE
	{
		//HF - Hash Functions

		SHA2_512 = 0,
		SHA3_224 = 1,
		SHA3_256 = 2,
		SHA3_384 = 3,
		SHA3_512 = 4,
		CHINA_SHANG_YONG_MI_MA3 = 5,
		BLAKE2 = 6,
		BLAKE3 = 7,

		//KDF - Key Derivative Functions

		ARGON2 = 8
	};

	class HasherTools
	{

	protected:
		template <typename HashProviderType>
		requires std::is_class_v<HashProviderType> && std::derived_from<HashProviderType, CommonSecurity::HashProviderBaseTools::InterfaceHashProvider>
		class HashCore
		{

		private:
			HashProviderType _HashProvider;

		public:
			inline HashCore& GiveData( const std::string& dataString )
			{
				if ( !dataString.empty() )
				{
					const std::span<const std::uint8_t> bytes_data(reinterpret_cast<const std::uint8_t*>(&dataString[0]), reinterpret_cast<const std::uint8_t*>(&dataString[0]) + dataString.size());
					_HashProvider.StepUpdate( bytes_data );
				}
				return *this;
			}

			template <typename ByteType>
			requires HashProviderBaseTools::Traits::is_byte_v<ByteType>
			inline HashCore& GiveData( std::basic_istream<ByteType>& is )
			{
				constexpr std::size_t stream_buffer_size = 10240;
				std::vector<std::uint8_t> buffer(stream_buffer_size, 0x00);
				size_t size = 0;
				while ( is.read( buffer.data(), buffer.size() * stream_buffer_size ) )
				{
					_HashProvider.StepUpdate( buffer );
					size += buffer.size() * sizeof(std::uint8_t);
				}
				size_t gcount = is.gcount();
				if ( gcount )
				{
					_HashProvider.StepUpdate( buffer );
					size += gcount * sizeof(std::uint8_t);
				}
				return *this;
			}

			template <typename IteratorType>
			requires std::input_or_output_iterator<IteratorType>
			inline HashCore& GiveData( IteratorType begin, IteratorType end )
			{
				auto byte = *begin;
				static_assert(std::same_as<decltype(byte), std::uint8_t>, "The value type of this iterator in the container scope is not the same as the classical byte type.");

				std::iter_difference_t<IteratorType> ranges_iterator_differences =  std::ranges::distance(begin, end);
				if(ranges_iterator_differences > 0)
				{
					std::span<const std::uint8_t> bytes_span(begin, end);
					_HashProvider.StepUpdate( bytes_span );
				}
				else if(ranges_iterator_differences < 0)
				{
					std::span<const std::uint8_t> bytes_span(end, begin);
					_HashProvider.StepUpdate( bytes_span );
				}
				else
				{
					my_cpp2020_assert(false, "The data container for this range is empty!", std::source_location::current());
				}

				return *this;
			}

			template <typename ElementIterableType>
			requires EODF_Reborn_CommonToolkit::CPP2020_Concepts::WithRanges::IsElementIterableLevel1Type<ElementIterableType>
			inline void TakeDigest( ElementIterableType& Iterable ) const
			{
				HashProviderType HashProviderObjectCopies( _HashProvider );
				std::vector<std::uint8_t> hash_value( _HashProvider.HashSize() / 8 );
				HashProviderObjectCopies.StepFinal( hash_value );
				std::copy( hash_value.begin(), hash_value.end(), Iterable.begin() );
				HashProviderObjectCopies.Clear();

				//std::vector<std::uint8_t>().swap( hash_value );
				hash_value.clear();
				hash_value.shrink_to_fit();
			}

			inline std::string TakeHexadecimalDigest() const
			{
				std::stringstream ss;
				std::vector<std::uint8_t> hash_value( _HashProvider.HashSize() / 8 );
				this->TakeDigest( hash_value );
				ss << UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString( hash_value );
				
				//std::vector<uint8_t>().swap( hash_value );
				hash_value.clear();
				hash_value.shrink_to_fit();

				return ss.str();
			}

			inline void ResetHashProvider( bool resetParameters = false )
			{
				if ( resetParameters )
				{
					_HashProvider.Clear();
				}
				_HashProvider.StepInitialize();
			}

			HashCore() : _HashProvider()
			{
				_HashProvider.StepInitialize();
			}

			explicit HashCore( std::size_t hashsize ) : _HashProvider( hashsize )
			{
				_HashProvider.StepInitialize();
			}

			HashCore
			(
				std::size_t hashsize,
				std::string& Key,
				std::span<std::uint8_t> salt_bytes,
				std::span<std::uint8_t> personalization_bytes
			)
				: _HashProvider( hashsize )
			{
				_HashProvider.UpdateStringKey(Key);
				_HashProvider.UpdateSaltBytes(salt_bytes);
				_HashProvider.UpdatePersonalizationBytes(personalization_bytes);
				_HashProvider.StepInitialize();
			}

			~HashCore()
			{
				ResetHashProvider( true );
			}

			HashCore( HashCore& object ) = delete;
		};

	public:

		//With Byte Ranges

		void GenerateHashed
		(
			const WORKER_MODE& mode,
			std::span<const std::uint8_t> dataRanges,
			std::span<std::uint8_t> hashedDataRanges
		)
		{
			if(dataRanges.empty())
				return;
			else
			{
				switch (mode)
				{
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512:
					{
						std::unique_ptr<Version2::HashProvider> hash_provider_pointer = std::make_unique<Version2::HashProvider>();
						auto hashedByteArray = hash_provider_pointer.get()->Hash( { std::bit_cast<std::byte*>( dataRanges.data() ), dataRanges.size() } );

						if(hashedByteArray.size() != hashedDataRanges.size())
						{
							hashedByteArray.fill(std::byte {0x00} );
							return;
						}

						for
						(
							std::size_t from_index = 0, to_index = 0;
							from_index < hashedByteArray.size() && to_index < hashedDataRanges.size(); 
							++from_index
						)
						{
							hashedDataRanges[to_index] = static_cast<std::uint8_t>( hashedByteArray[from_index] );
							++from_index;
							++to_index;
						}

						hash_provider_pointer = nullptr;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_224:
					{
						using HashProviderType = HashCore<Version3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( 224 );
						hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
						hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
						hash_provider_pointer = nullptr;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_256:
					{
						using HashProviderType = HashCore<Version3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( 256 );
						hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
						hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
						hash_provider_pointer = nullptr;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_384:
					{
						using HashProviderType = HashCore<Version3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( 384 );
						hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
						hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
						hash_provider_pointer = nullptr;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512:
					{
						using HashProviderType = HashCore<Version3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( 512 );
						hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
						hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
						hash_provider_pointer = nullptr;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3:
					{
						using HashProviderType = HashCore<ChinaShangYongMiMa3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>();
						hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
						hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
						hash_provider_pointer = nullptr;
					}
					default:
						break;
				}
			}
		}

		void GenerateBlake2Hashed
		(
			std::span<const std::uint8_t> dataRanges,
			std::span<std::uint8_t> hashedDataRanges,
			bool whether_extension_mode,
			std::size_t hash_bit_size
		)
		{
			if(dataRanges.empty())
				return;

			if(whether_extension_mode)
			{
				if(hash_bit_size % 8 != 0)
				{
					std::cout << "The Blake2 hash algorithm, if use extension hash mode, you require that the size of the digest it generates must be a multiple of 8!" << std::endl;
					return;
				}
				else
				{
					using HashProviderType = HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>>;
					auto hash_provider_pointer = std::make_unique<HashProviderType>(hash_bit_size);
					hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
					hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
					hash_provider_pointer = nullptr;
				}
			}
			else
			{
				if(hash_bit_size != 224 && hash_bit_size != 256 && hash_bit_size != 384 && hash_bit_size != 512)
				{
					std::cout << "The Blake2 hash algorithm, if use normal hash mode, you require that the digest size it generates must be one of 224, 256, 384, 512!" << std::endl;
					return;
				}
				else
				{
					using HashProviderType = HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>>;
					auto hash_provider_pointer = std::make_unique<HashProviderType>(hash_bit_size);
					hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
					hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
					hash_provider_pointer = nullptr;
				}
			}
		}

		void GenerateBlake2Hashed
		(
			std::span<const std::uint8_t> dataRanges,
			std::span<std::uint8_t> hashedDataRanges,
			bool whether_extension_mode,
			std::size_t hash_bit_size,
			std::string& key,
			std::span<std::uint8_t> salt_bytes,
			std::span<std::uint8_t> personalization_bytes
		)
		{
			if(dataRanges.empty())
				return;

			if(whether_extension_mode)
			{
				if(hash_bit_size % 8 != 0)
				{
					std::cout << "The Blake2 hash algorithm, if use extension hash mode, you require that the size of the digest it generates must be a multiple of 8!" << std::endl;
					return;
				}
				else
				{
					using HashProviderType = HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>>;
					auto hash_provider_pointer = std::make_unique<HashProviderType>(hash_bit_size, key, salt_bytes, personalization_bytes);
					hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
					hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
					hash_provider_pointer = nullptr;
				}
			}
			else
			{
				if(hash_bit_size != 224 && hash_bit_size != 256 && hash_bit_size != 384 && hash_bit_size != 512)
				{
					std::cout << "The Blake2 hash algorithm, if use normal hash mode, you require that the digest size it generates must be one of 224, 256, 384, 512!" << std::endl;
					return;
				}
				else
				{
					using HashProviderType = HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>>;
					auto hash_provider_pointer = std::make_unique<HashProviderType>(hash_bit_size, key, salt_bytes, personalization_bytes);
					hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
					hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
					hash_provider_pointer = nullptr;
				}
			}
		}

		void GenerateBlake3ModificationHashed
		(
			std::span<std::uint8_t> dataRanges,
			std::span<std::uint8_t> hashedDataRanges,
			std::size_t hash_bit_size
		)
		{
			if(dataRanges.empty())
				return;

			if(hash_bit_size % 8 != 0)
			{
				std::cout << "The Blake3 hash algorithm (Modified version), you require that the size of the digest it generates must be a multiple of 8!" << std::endl;
				return;
			}
			else
			{
				using HashProviderType = HashCore<CommonSecurity::Blake3::HashProvider>;
				std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( hash_bit_size );
				hash_provider_pointer.get()->GiveData( dataRanges.begin(), dataRanges.end() );
				hash_provider_pointer.get()->TakeDigest( hashedDataRanges );
			}
		}

		//With String

		std::optional<std::string> GenerateHashed
		(
			const WORKER_MODE& mode,
			const std::string& dataString
		)
		{
			if ( dataString.empty() )
				return std::nullopt;
			else
			{
				switch (mode)
				{
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512:
					{
						std::unique_ptr<Version2::HashProvider> hash_provider_pointer = std::make_unique<Version2::HashProvider>();
						auto hashedByteArray = hash_provider_pointer.get()->Hash( { std::bit_cast<std::byte*>( dataString.c_str()), dataString.size() } );
						std::string hashedString = HashProviderBaseTools::Bytes2HexadecimalString({hashedByteArray.begin(), hashedByteArray.end()});
						hash_provider_pointer = nullptr;
						return hashedString;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_224:
					{
						using HashProviderType = HashCore<Version3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( 224 );
						hash_provider_pointer.get()->GiveData( dataString );
						std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
						hash_provider_pointer = nullptr;
						return hashedString;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_256:
					{
						using HashProviderType = HashCore<Version3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( 256 );
						hash_provider_pointer.get()->GiveData( dataString );
						std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
						hash_provider_pointer = nullptr;
						return hashedString;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_384:
					{
						using HashProviderType = HashCore<Version3::HashProvider>;
						std::unique_ptr<HashCore<Version3::HashProvider>> hash_provider_pointer = std::make_unique<HashProviderType>( 384 );
						hash_provider_pointer.get()->GiveData( dataString );
						std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
						hash_provider_pointer = nullptr;
						return hashedString;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512:
					{
						using HashProviderType = HashCore<Version3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( 512 );
						hash_provider_pointer.get()->GiveData( dataString );
						std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
						hash_provider_pointer = nullptr;
						return hashedString;
					}
					case CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3:
					{
						using HashProviderType = HashCore<ChinaShangYongMiMa3::HashProvider>;
						std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>();
						hash_provider_pointer.get()->GiveData( dataString );
						std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
						hash_provider_pointer = nullptr;
						return hashedString;
					}
					default:
						break;
				}
			}
		}

		std::optional<std::string> GenerateBlake2Hashed
		(
			const std::string& dataString,
			bool whether_extension_mode,
			std::size_t hash_bit_size
		)
		{
			if(dataString.empty())
				return std::nullopt;

			if(whether_extension_mode)
			{
				if(hash_bit_size % 8 != 0)
				{
					std::cout << "The Blake2 hash algorithm, if use extension hash mode, you require that the size of the digest it generates must be a multiple of 8!" << std::endl;
					return std::nullopt;
				}
				else
				{
					using HashProviderType = HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>>;
					auto hash_provider_pointer = std::make_unique<HashProviderType>(hash_bit_size);
					hash_provider_pointer.get()->GiveData( dataString );
					std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
					hash_provider_pointer = nullptr;
					return hashedString;
				}
			}
			else
			{
				if(hash_bit_size != 224 && hash_bit_size != 256 && hash_bit_size != 384 && hash_bit_size != 512)
				{
					std::cout << "The Blake2 hash algorithm, if use normal hash mode, you require that the digest size it generates must be one of 224, 256, 384, 512!" << std::endl;
					return std::nullopt;
				}
				else
				{
					using HashProviderType = HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>>;
					auto hash_provider_pointer = std::make_unique<HashProviderType>(hash_bit_size);
					hash_provider_pointer.get()->GiveData( dataString );
					std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
					hash_provider_pointer = nullptr;
					return hashedString;
				}
			}
		}

		std::optional<std::string> GenerateBlake2Hashed
		(
			const std::string& dataString,
			bool whether_extension_mode,
			std::size_t hash_bit_size,
			std::string& key,
			std::span<std::uint8_t> salt_bytes,
			std::span<std::uint8_t> personalization_bytes
		)
		{
			if(dataString.empty())
				return std::nullopt;

			if(whether_extension_mode)
			{
				if(hash_bit_size % 8 != 0)
				{
					std::cout << "The Blake2 hash algorithm, if use extension hash mode, you require that the size of the digest it generates must be a multiple of 8!" << std::endl;
					return std::nullopt;
				}
				else
				{
					using HashProviderType = HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>>;
					auto hash_provider_pointer = std::make_unique<HashProviderType>(hash_bit_size, key, salt_bytes, personalization_bytes);
					hash_provider_pointer.get()->GiveData( dataString );
					std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
					hash_provider_pointer = nullptr;
					return hashedString;
				}
			}
			else
			{
				if(hash_bit_size != 224 && hash_bit_size != 256 && hash_bit_size != 384 && hash_bit_size != 512)
				{
					std::cout << "The Blake2 hash algorithm, if use normal hash mode, you require that the digest size it generates must be one of 224, 256, 384, 512!" << std::endl;
					return std::nullopt;
				}
				else
				{
					using HashProviderType = HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>>;
					auto hash_provider_pointer = std::make_unique<HashProviderType>(hash_bit_size, key, salt_bytes, personalization_bytes);
					hash_provider_pointer.get()->GiveData( dataString );
					std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
					hash_provider_pointer = nullptr;
					return hashedString;
				}
			}
		}

		std::optional<std::string> GenerateBlake3ModificationHashed
		(
			const std::string& dataString,
			std::size_t hash_bit_size
		)
		{
			if(dataString.empty())
				return std::nullopt;

			if(hash_bit_size % 8 != 0)
			{
				std::cout << "The Blake3 hash algorithm (Modified version), you require that the size of the digest it generates must be a multiple of 8!" << std::endl;
				return std::nullopt;
			}
			else
			{
				using HashProviderType = HashCore<CommonSecurity::Blake3::HashProvider>;
				std::unique_ptr<HashProviderType> hash_provider_pointer = std::make_unique<HashProviderType>( hash_bit_size );
				hash_provider_pointer.get()->GiveData( dataString );
				std::string hashedString = hash_provider_pointer.get()->TakeHexadecimalDigest();
				return hashedString;
			}
		}

		HasherTools() {}

		~HasherTools() {}

		HasherTools( HasherTools& object ) = delete;
	};
}  // namespace CommonSecurity::SHA::Hasher

namespace CommonSecurity::DataHashingWrapper
{
	struct HashersAssistantParameters
	{

	public:
		CommonSecurity::SHA::Hasher::WORKER_MODE hash_mode = static_cast<CommonSecurity::SHA::Hasher::WORKER_MODE>(0);
		bool whether_use_hash_extension_bit_mode = false;
		std::size_t generate_hash_bit_size = 0;
		std::string inputDataString = "";
		std::string outputHashedHexadecimalString = "";
	};

	//哈希器助手
	//Hashers' Assistant
	struct HashersAssistant
	{

	public:
		static void SELECT_HASH_FUNCTION(HashersAssistantParameters& thisInstance)
		{
			std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools> hasherClassPointer = std::unique_ptr<CommonSecurity::SHA::Hasher::HasherTools>();
			std::optional<std::string> optionalHashedHexadecimalString = std::optional<std::string>();

			switch (thisInstance.hash_mode)
			{
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512:
				{
					optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( thisInstance.hash_mode, thisInstance.inputDataString );
					hasherClassPointer = nullptr;
					break;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_224:
				{
					optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( thisInstance.hash_mode, thisInstance.inputDataString );
					hasherClassPointer = nullptr;
					break;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_256:
				{
					optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( thisInstance.hash_mode, thisInstance.inputDataString );
					hasherClassPointer = nullptr;
					break;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_384:
				{
					optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( thisInstance.hash_mode, thisInstance.inputDataString );
					hasherClassPointer = nullptr;
					break;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512:
				{
					optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( thisInstance.hash_mode, thisInstance.inputDataString );
					hasherClassPointer = nullptr;
					break;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3:
				{
					optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateHashed( thisInstance.hash_mode, thisInstance.inputDataString );
					hasherClassPointer = nullptr;
					break;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::BLAKE2:
				{
					optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateBlake2Hashed( thisInstance.inputDataString, thisInstance.whether_use_hash_extension_bit_mode, thisInstance.generate_hash_bit_size );
					hasherClassPointer = nullptr;
					break;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::BLAKE3:
				{
					optionalHashedHexadecimalString = hasherClassPointer.get()->GenerateBlake3ModificationHashed( thisInstance.inputDataString, thisInstance.generate_hash_bit_size );
					hasherClassPointer = nullptr;
					break;
				}
				default:
					break;
			}

			if(optionalHashedHexadecimalString.has_value())
				optionalHashedHexadecimalString.value().swap(thisInstance.outputHashedHexadecimalString);
			else
				throw std::invalid_argument(" If the size of the source string message is zero, then it cannot be transformed into the target hash digest message! ");
		}
		

		HashersAssistant() = default;
		~HashersAssistant() = default;

		HashersAssistant( const HashersAssistant& _object) = delete;
	};

	/**
	*	https://zh.wikipedia.org/wiki/HMAC
	*	密钥散列消息认证码（英语：Keyed-hash message authentication code），又称散列消息认证码（Hash-based message authentication code，缩写为HMAC）
	*	是一种通过特别计算方式之后产生的消息认证码（MAC），使用密码散列函数，同时结合一个加密密钥。
	*	它可以用来保证资料的完整性，同时可以用来作某个消息的身份验证。
	*	https://en.wikipedia.org/wiki/HMAC
	*	In cryptography, an HMAC (sometimes expanded as either keyed-hash message authentication code or hash-based message authentication code)
	*	is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key.
	*	As with any MAC, it may be used to simultaneously verify both the data integrity and authenticity of a message.
	*	HMAC can provide authentication using a shared secret instead of using digital signatures with asymmetric cryptography.
	*	It trades off the need for a complex public key infrastructure by delegating the key exchange to the communicating parties, who are responsible for establishing and using a trusted channel to agree on the key prior to communication.
	*/
	class HMAC_Worker
	{

	private:
		struct AlgorithmImplementation
		{
			std::string ComputeMessageAuthenticationCode
			(
				HashersAssistantParameters& HashersAssistantParameters_Instance,
				const std::string& Message,
				const std::size_t& MessageBlockSize,
				std::string Key
			)
			{
				// Outer padded key
				constexpr char OuterPaddingKey = 0x5c;
				// Inner padded key
				constexpr char InnerPaddingKey = 0x36;

				std::string KeyPaddings( MessageBlockSize, 0x00 );
				std::string OuterPaddedKeys( MessageBlockSize, OuterPaddingKey );
				std::string InnerPaddedKeys( MessageBlockSize, InnerPaddingKey );

				// Compute the block sized key
				auto lambda_ComputeBlockSizedKey = [ &HashersAssistantParameters_Instance, &KeyPaddings, &MessageBlockSize ]( std::string Key, std::size_t KeySize )
				{
					if ( KeySize == MessageBlockSize )
					{
						KeyPaddings = Key;
					}
					else if ( KeySize > MessageBlockSize )
					{
						// Keys longer than blockSize are shortened by hashing them
						// 长于blockSize的密钥通过散列来缩短其长度

						HashersAssistantParameters_Instance.inputDataString = Key;
						HashersAssistant::SELECT_HASH_FUNCTION( HashersAssistantParameters_Instance );
						std::string KeyHashed = HashersAssistantParameters_Instance.outputHashedHexadecimalString;
						if(KeyHashed.size() != MessageBlockSize)
							KeyHashed.resize(MessageBlockSize, 0x00);
						KeyPaddings = std::move(KeyHashed);
					}
					else if ( KeySize < MessageBlockSize )
					{
						// Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
						// 短于blockSize的键被填充到blockSize，在右边用0填充。

						for ( std::size_t index = 0; index < MessageBlockSize; ++index )
						{
							// Pad key with zeros to make it blockSize bytes long
							if ( index < MessageBlockSize - KeySize )
							{
								KeyPaddings[ index ] = 0x00;
							}
							else
							{
								KeyPaddings[ index ] = Key[ index - ( MessageBlockSize - KeySize ) ];
							}
						}
					}
				};

				lambda_ComputeBlockSizedKey( Key, Key.size() );

				for ( std::size_t index = 0; index < MessageBlockSize; ++index )
				{
					OuterPaddedKeys[ index ] ^= KeyPaddings[ index ];
					InnerPaddedKeys[ index ] ^= KeyPaddings[ index ];
				}

				std::string FirstData = InnerPaddedKeys + Message;

				HashersAssistantParameters_Instance.inputDataString = FirstData;
				HashersAssistant::SELECT_HASH_FUNCTION( HashersAssistantParameters_Instance );
				std::string FirstHashedData = HashersAssistantParameters_Instance.outputHashedHexadecimalString;

				std::string LastData = OuterPaddedKeys + FirstHashedData;

				HashersAssistantParameters_Instance.inputDataString = LastData;
				HashersAssistant::SELECT_HASH_FUNCTION( HashersAssistantParameters_Instance );
				std::string LastHashedData = HashersAssistantParameters_Instance.outputHashedHexadecimalString;
				
				FirstData.clear();
				FirstHashedData.clear();
				LastData.clear();
				
				HashersAssistantParameters_Instance.inputDataString.clear();
				HashersAssistantParameters_Instance.outputHashedHexadecimalString.clear();

				return LastHashedData;
			}
		};

		std::unique_ptr<AlgorithmImplementation> HMAC_Pointer = std::unique_ptr<AlgorithmImplementation>();
		std::atomic<bool> whether_occupied = false;

	public:
		std::string operator()( HashersAssistantParameters& HashersAssistantParameters_Instance, const std::string& Message, const std::size_t& MessageBlockSize, std::string Key )
		{
			whether_occupied.wait(true, std::memory_order_seq_cst);

			whether_occupied.store(true, std::memory_order_seq_cst);
			if(std::addressof(HashersAssistantParameters_Instance) == nullptr)
			{
				whether_occupied.store(false, std::memory_order_relaxed);
				whether_occupied.notify_all();
				return std::string();
			}
			std::string HMAC_String = HMAC_Pointer.get()->ComputeMessageAuthenticationCode( HashersAssistantParameters_Instance, Message, MessageBlockSize, Key );
			whether_occupied.store(false, std::memory_order_relaxed);
			whether_occupied.notify_all();
			return HMAC_String;
		}
	};

	inline HMAC_Worker HMAC_FunctionObject;
} // CommonSecurity::DataHashingWrapper
