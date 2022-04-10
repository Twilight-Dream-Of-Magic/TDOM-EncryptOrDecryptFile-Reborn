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
		SHA2_512 = 0,
		SHA3_224 = 1,
		SHA3_256 = 2,
		SHA3_384 = 3,
		SHA3_512 = 4,
		CHINA_SHANG_YONG_MI_MA3 = 5
	};

	class HasherTools
	{

	protected:
		template <typename HashProviderType>
		class HashCore
		{

		private:

			HashProviderType _HashProvider;

		public:

			inline HashCore& GiveData( std::string& dataString )
			{
				if ( !dataString.empty() )
				{
					_HashProvider.StepUpdate( reinterpret_cast<const uint8_t*>( &dataString[ 0 ] ), dataString.size() );
				}
				return *this;
			}

			template <typename ByteType>
			requires HashProviderBaseTools::Traits::is_byte_v<ByteType>
			inline HashCore& GiveData( std::basic_istream<ByteType>& is )
			{
				const size_t stream_buffer_size = 10240;
				uint8_t		 buffer[ stream_buffer_size ];
				size_t		 size = 0;
				while ( is.read( reinterpret_cast<ByteType*>( buffer ), sizeof( buffer ) ) )
				{
					_HashProvider.StepUpdate( buffer, sizeof( buffer ) );
					size += sizeof( buffer );
				}
				size_t gcount = is.gcount();
				if ( gcount )
				{
					_HashProvider.StepUpdate( buffer, gcount );
					size += gcount;
				}
				return *this;
			}

			template <typename IteratorType>
			requires std::input_or_output_iterator<IteratorType>
			inline HashCore& GiveData( IteratorType begin, IteratorType end )
			{
				while ( begin != end )
				{
					uint8_t byte = *begin;
					begin++;
					_HashProvider.StepUpdate( &byte, 1 );
				}
				return *this;
			}

			template <typename ByteType>
			requires HashProviderBaseTools::Traits::is_byte_v<ByteType>
			inline HashCore& TakeDigest( ByteType* buffer, size_t buffer_size ) const
			{
				if ( buffer_size < _HashProvider.HashSize() / 8 )
				{
					throw std::invalid_argument( "Invalid buffer size" );
				}

				HashProviderType HashProviderObjectCopies( _HashProvider );
				HashProviderObjectCopies.StepFinal( buffer );
			}

			template <typename ElementIterableType>
			requires EODF_Reborn_CommonToolkit::CPP2020_Concepts::WithRanges::IsElementIterableLevel1Type<ElementIterableType>
			inline void TakeDigest( ElementIterableType& Iterable ) const
			{
				HashProviderType	 HashProviderObjectCopies( _HashProvider );
				std::vector<std::uint8_t> hash_value( _HashProvider.HashSize() / 8 );
				HashProviderObjectCopies.StepFinal( hash_value );
				std::copy( hash_value.begin(), hash_value.end(), Iterable.begin() );
				HashProviderObjectCopies.Clear();
				hash_value.clear();
				hash_value.shrink_to_fit();
				//std::vector<std::uint8_t>().swap( hash_value );
			}

			inline std::string TakeHexadecimalDigest() const
			{
				std::stringstream	 ss;
				std::vector<std::uint8_t> hash_value( _HashProvider.HashSize() / 8 );
				this->TakeDigest( hash_value );
				ss << UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString( hash_value );
				hash_value.clear();
				hash_value.shrink_to_fit();
				//std::vector<uint8_t>().swap( hash_value );
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

			HashCore( std::size_t hashsize, std::string& Key, std::vector<std::uint8_t>& salt_bytes, std::vector<std::uint8_t>& personalization_bytes ) : _HashProvider( hashsize )
			{
				_HashProvider.UpdateStringKey(Key);
				_HashProvider.UpdateSaltBytes(salt_bytes.data(), salt_bytes.size());
				_HashProvider.UpdatePersonalizationBytes(salt_bytes.data(), salt_bytes.size());
				_HashProvider.StepInitialize();
			}

			~HashCore()
			{
				ResetHashProvider( true );
			}

			HashCore( HashCore& object ) = delete;
		};

	public:

		std::optional<std::string> GenerateHashed( WORKER_MODE mode, std::string& dataString );

		std::optional<std::string> GenerateBlake2Hashed( std::string& dataString, bool whether_extension_mode, std::size_t hash_size );

		std::optional<std::string> GenerateBlake2Hashed( std::string& dataString, bool whether_extension_mode, std::size_t hash_size, std::string& key, std::vector<std::uint8_t>& salt_bytes, std::vector<std::uint8_t>& personalization_bytes );

		HasherTools() {}

		~HasherTools() {}

		HasherTools( HasherTools& object ) = delete;
	};

	std::optional<std::string> HasherTools::GenerateHashed( WORKER_MODE mode, std::string& dataString )
	{
		if ( dataString.empty() )
		{
			return std::nullopt;
		}
		else
		{
			switch (mode)
			{
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512:
				{
					Version2::HashProvider* hash_provider_pointer = new Version2::HashProvider;
					auto					hashedByteArray = hash_provider_pointer->Hash( { ( std::byte* )dataString.c_str(), dataString.size() } );
					std::string				hashedString = HashProviderBaseTools::Bytes2HexadecimalString( { hashedByteArray.begin(), hashedByteArray.end() } );
					delete hash_provider_pointer;
					hash_provider_pointer = nullptr;
					return hashedString;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_224:
				{
					HashCore<Version3::HashProvider>* hash_provider_pointer = new HashCore<Version3::HashProvider>( 224 );
					hash_provider_pointer->GiveData( dataString );
					std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
					delete hash_provider_pointer;
					hash_provider_pointer = nullptr;
					return hashedString;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_256:
				{
					HashCore<Version3::HashProvider>* hash_provider_pointer = new HashCore<Version3::HashProvider>( 256 );
					hash_provider_pointer->GiveData( dataString );
					std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
					delete hash_provider_pointer;
					hash_provider_pointer = nullptr;
					return hashedString;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_384:
				{
					HashCore<Version3::HashProvider>* hash_provider_pointer = new HashCore<Version3::HashProvider>( 384 );
					hash_provider_pointer->GiveData( dataString );
					std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
					delete hash_provider_pointer;
					hash_provider_pointer = nullptr;
					return hashedString;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512:
				{
					HashCore<Version3::HashProvider>* hash_provider_pointer = new HashCore<Version3::HashProvider>( 512 );
					hash_provider_pointer->GiveData( dataString );
					std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
					delete hash_provider_pointer;
					hash_provider_pointer = nullptr;
					return hashedString;
				}
				case CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3:
				{
					HashCore<ChinaShangeYongMiMa3::HashProvider>* hash_provider_pointer = new HashCore<ChinaShangeYongMiMa3::HashProvider>();
					hash_provider_pointer->GiveData( dataString );
					std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
					delete hash_provider_pointer;
					hash_provider_pointer = nullptr;
					return hashedString;
				}
				default:
					break;
			}
		}
	}

	std::optional<std::string> HasherTools::GenerateBlake2Hashed( std::string& dataString, bool whether_extension_mode, std::size_t hash_size )
	{
		if(dataString.empty())
		{
			return std::nullopt;
		}

		if(whether_extension_mode)
		{
			if(hash_size % 8 != 0)
			{
				std::cout << "The Blake2 hash algorithm, if use extension hash mode, you require that the size of the digest it generates must be a multiple of 8!" << std::endl;
				return std::nullopt;
			}
			else
			{
				HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>>* hash_provider_pointer = new HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>>(hash_size);
				hash_provider_pointer->GiveData( dataString );
				std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
				delete hash_provider_pointer;
				hash_provider_pointer = nullptr;
				return hashedString;
			}
		}
		else
		{
			if(hash_size != 224 && hash_size != 256 && hash_size != 384 && hash_size != 512)
			{
				std::cout << "The Blake2 hash algorithm, if use normal hash mode, you require that the digest size it generates must be one of 224, 256, 384, 512!" << std::endl;
				return std::nullopt;
			}
			else
			{
				HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>>* hash_provider_pointer = new HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>>(hash_size);
				hash_provider_pointer->GiveData( dataString );
				std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
				delete hash_provider_pointer;
				hash_provider_pointer = nullptr;
				return hashedString;
			}
		}
	}

	std::optional<std::string> HasherTools::GenerateBlake2Hashed( std::string& dataString, bool whether_extension_mode, std::size_t hash_size, std::string& key, std::vector<std::uint8_t>& salt_bytes, std::vector<std::uint8_t>& personalization_bytes )
	{
		if(dataString.empty())
		{
			return std::nullopt;
		}

		if(whether_extension_mode)
		{
			if(hash_size % 8 != 0)
			{
				std::cout << "The Blake2 hash algorithm, if use extension hash mode, you require that the size of the digest it generates must be a multiple of 8!" << std::endl;
				return std::nullopt;
			}
			else
			{
				HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>>* hash_provider_pointer = new HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>>(hash_size, key, salt_bytes, personalization_bytes);
				hash_provider_pointer->GiveData( dataString );
				std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
				delete hash_provider_pointer;
				hash_provider_pointer = nullptr;
				return hashedString;
			}
		}
		else
		{
			if(hash_size != 224 && hash_size != 256 && hash_size != 384 && hash_size != 512)
			{
				std::cout << "The Blake2 hash algorithm, if use normal hash mode, you require that the digest size it generates must be one of 224, 256, 384, 512!" << std::endl;
				return std::nullopt;
			}
			else
			{
				HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>>* hash_provider_pointer = new HashCore<CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>>(hash_size, key, salt_bytes, personalization_bytes);
				hash_provider_pointer->GiveData( dataString );
				std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
				delete hash_provider_pointer;
				hash_provider_pointer = nullptr;
				return hashedString;
			}
		}
	}
}  // namespace CommonSecurity::SHA::Hasher
