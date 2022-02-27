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

#include "AlgorithmVersion2.hpp"
#include "AlgorithmVersion3.hpp"

namespace CommonSecurity::FNV_1a::Hasher
{

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
	using namespace CommonSecurity::SHA;

	enum class WORKER_MODE
	{
		SHA2_512 = 0,
		SHA3_224 = 1,
		SHA3_256 = 2,
		SHA3_384 = 3,
		SHA3_512 = 4
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
			requires SHA::BaseTools::Traits::is_byte_v<ByteType>
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
			requires SHA::BaseTools::Traits::is_byte_v<ByteType>
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
				std::vector<uint8_t> hash( _HashProvider.HashSize() / 8 );
				HashProviderObjectCopies.StepFinal( &hash[ 0 ] );
				std::copy( hash.begin(), hash.end(), Iterable.begin() );
				HashProviderObjectCopies.Clear();
				hash.clear();
				std::vector<uint8_t>().swap( hash );
			}

			inline std::string TakeHexadecimalDigest() const
			{
				std::stringstream	 ss;
				std::vector<uint8_t> hash( _HashProvider.HashSize() / 8 );
				TakeDigest( hash );
				ss << UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString( hash );
				hash.clear();
				std::vector<uint8_t>().swap( hash );
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

			explicit HashCore( size_t hashsize ) : _HashProvider( hashsize )
			{
				_HashProvider.StepInitialize();
			}

			~HashCore()
			{
				ResetHashProvider( true );
			}

			HashCore( HashCore& object ) = delete;
		};

	public:
		std::string GenerateHashed( WORKER_MODE mode, std::string& dataString );

		HasherTools() {}

		~HasherTools() {}

		HasherTools( HasherTools& object ) = delete;
	};

	std::string HasherTools::GenerateHashed( WORKER_MODE mode, std::string& dataString )
	{
		if ( mode == WORKER_MODE::SHA2_512 )
		{
			if ( !dataString.empty() )
			{
				Version2::HashProvider* hash_provider_pointer = new Version2::HashProvider;
				auto					hashedByteArray = hash_provider_pointer->Hash( { ( std::byte* )dataString.c_str(), dataString.size() } );
				std::string				hashedString = BaseTools::Bytes2HexadecimalString( { hashedByteArray.begin(), hashedByteArray.end() } );
				delete hash_provider_pointer;
				hash_provider_pointer = nullptr;
				return hashedString;
			}
			return std::string();
		}
		if ( mode == WORKER_MODE::SHA3_224 )
		{
			HashCore<Version3::HashProvider>* hash_provider_pointer = new HashCore<Version3::HashProvider>( 224 );
			hash_provider_pointer->GiveData( dataString );
			std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
			delete hash_provider_pointer;
			hash_provider_pointer = nullptr;
			return hashedString;
		}
		if ( mode == WORKER_MODE::SHA3_256 )
		{
			HashCore<Version3::HashProvider>* hash_provider_pointer = new HashCore<Version3::HashProvider>( 256 );
			hash_provider_pointer->GiveData( dataString );
			std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
			delete hash_provider_pointer;
			hash_provider_pointer = nullptr;
			return hashedString;
		}
		if ( mode == WORKER_MODE::SHA3_384 )
		{
			HashCore<Version3::HashProvider>* hash_provider_pointer = new HashCore<Version3::HashProvider>( 384 );
			hash_provider_pointer->GiveData( dataString );
			std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
			delete hash_provider_pointer;
			hash_provider_pointer = nullptr;
			return hashedString;
		}
		if ( mode == WORKER_MODE::SHA3_512 )
		{
			HashCore<Version3::HashProvider>* hash_provider_pointer = new HashCore<Version3::HashProvider>( 512 );
			hash_provider_pointer->GiveData( dataString );
			std::string hashedString = hash_provider_pointer->TakeHexadecimalDigest();
			delete hash_provider_pointer;
			hash_provider_pointer = nullptr;
			return hashedString;
		}
	}
}  // namespace CommonSecurity::SHA::Hasher
