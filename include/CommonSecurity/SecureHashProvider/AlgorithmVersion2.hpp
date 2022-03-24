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

namespace CommonSecurity::SHA
{
	//Chinese: SHA-2 第二代安全散列算法
	//English: Secure Hash Algorithm Version 2
	namespace Version2
	{
		using std::vector;
		using std::byte;
		using std::span;
		using std::numeric_limits;
		using std::array;
		using std::string;

		namespace Core
		{
			//HASH状态常量
			//HASH_STATE_CONSTANTS
			constexpr array HASH_STATE_CONSTANTS
			{
				0x6a09e667f3bcc908ULL,
				0xbb67ae8584caa73bULL,
				0x3c6ef372fe94f82bULL,
				0xa54ff53a5f1d36f1ULL,
				0x510e527fade682d1ULL,
				0x9b05688c2b3e6c1fULL,
				0x1f83d9abfb41bd6bULL,
				0x5be0cd19137e2179ULL
			};

			//哈希回合常量
			//HASH_ROUND_CONSTANTS
			constexpr array HASH_ROUND_CONSTANTS
			{
				0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
				0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
				0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
				0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
				0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
				0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
				0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
				0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
				0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
				0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
				0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
				0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
				0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
				0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
				0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
				0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
				0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
				0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
				0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
				0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
			};

			constexpr int sha512BlockByteCount = 1024 / 8; // sha512BlockByteCount == 128bytes
			constexpr int fillByteCount = 896 / 8; // fillByteCount == 112bytes
			constexpr int finalLengthByteCount = 128 / 8; // finalLengthByteCount == 16bytes

			namespace Functions
			{
				//Function to find the choose of hash code (e, f, g)
				inline CommonSecurity::EightByte chooseHashCode( CommonSecurity::EightByte e, CommonSecurity::EightByte f, CommonSecurity::EightByte g )
				{
					return ( e & f ) ^ ( ~e & g );
				}

				//Function to find the majority of hash code (a, b, c)
				inline CommonSecurity::EightByte majorityHashCode( CommonSecurity::EightByte a, CommonSecurity::EightByte b, CommonSecurity::EightByte c )
				{
					return ( a & b ) ^ ( b & c ) ^ ( c & a );
				}

				//Function to find the Bitwise XOR with the right rotate over 14, 18, and 41 for (hash code e)
				inline CommonSecurity::EightByte Sigma0( CommonSecurity::EightByte e )
				{
					auto ea = CommonSecurity::Binary_RightRotateMove< decltype( e ) >( e, 14ULL );
					auto eb = CommonSecurity::Binary_RightRotateMove< decltype( e ) >( e, 18ULL );
					auto ec = CommonSecurity::Binary_RightRotateMove< decltype( e ) >( e, 41ULL );
					return ea ^ eb ^ ec;
				}

				//Function to find the Bitwise XOR with the right rotate over 28, 34, and 39 for (hash code a)
				inline CommonSecurity::EightByte Sigma1( CommonSecurity::EightByte a )
				{
					auto aa = CommonSecurity::Binary_RightRotateMove< decltype( a ) >( a, 28ULL );
					auto ab = CommonSecurity::Binary_RightRotateMove< decltype( a ) >( a, 34ULL );
					auto ac = CommonSecurity::Binary_RightRotateMove< decltype( a ) >( a, 39ULL );
					return aa ^ ab ^ ac;
				}

				//For hash word a
				inline CommonSecurity::EightByte Gamma0( CommonSecurity::EightByte hashWord )
				{
					auto a = CommonSecurity::Binary_RightRotateMove< decltype( hashWord ) >( hashWord, 19ULL );
					auto b = CommonSecurity::Binary_RightRotateMove< decltype( hashWord ) >( hashWord, 61ULL );
					auto c = CommonSecurity::Binary_RightShift< decltype( hashWord ) >( hashWord, 6ULL );
					return a ^ b ^ c;
				}

				//For hash word c
				inline CommonSecurity::EightByte Gamma1( CommonSecurity::EightByte hashWord )
				{
					auto a = CommonSecurity::Binary_RightRotateMove< decltype( hashWord ) >( hashWord, 1ULL );
					auto b = CommonSecurity::Binary_RightRotateMove< decltype( hashWord ) >( hashWord, 8ULL );
					auto c = CommonSecurity::Binary_RightShift< decltype( hashWord ) >( hashWord, 7ULL );
					return a ^ b ^ c;
				}

				// convert 128 bytes to 16 uint64(8bytes)
				inline auto Byte128ToEightBytes( span< byte, Core::sha512BlockByteCount > chunkSpan )
				{
					array< CommonSecurity::EightByte, Core::sha512BlockByteCount / sizeof( CommonSecurity::EightByte ) > answer;
					auto																								 spanBegin = chunkSpan.begin();
					for ( size_t index = 0; index < answer.size(); ++index )
					{
						answer[ index ] = CommonSecurity::packInteger( CommonSecurity::SpanEightByte{ spanBegin, sizeof( CommonSecurity::EightByte ) } );
						spanBegin += sizeof( CommonSecurity::EightByte );
					}
					return answer;
				}
			}  // namespace Functions
		}

		class HashProvider
		{

		public:
			std::array< std::byte, 64 > Hash( std::span< std::byte > data );

		protected:
			// add 0b1000'0000... to the end of data
			inline void StepFill( std::vector< std::byte >& data );

			inline void StepInitialize();

			inline void StepUpdate( std::array< CommonSecurity::EightByte, 8 >& input, const std::array< CommonSecurity::EightByte, 80 >& keys );

		private:
			std::array< CommonSecurity::EightByte, 8 > hashes;
		};

		inline void HashProvider::StepFill( vector< byte >& data )
		{
			//This type of size must be (uint64_t)!
			EightByte data_size = data.size();
			EightByte modulue = data_size % Core::sha512BlockByteCount;

			auto bytesToFill = Core::fillByteCount - static_cast< int >( modulue );
			if ( bytesToFill <= 0 )
			{
				// at least 1 bit is added
				bytesToFill += Core::sha512BlockByteCount;
			}

			// add 0b1000'0000...
			data.emplace_back( static_cast< byte >( 0x80 ) );
			data.insert( data.end(), static_cast< std::size_t >( bytesToFill - 1 ), static_cast< byte >( 0 ) );

			// add length inform
			// since sizeof(size_t) usually equals to 8
			// add 8 bytes of 0, then 8 bytes of length
			data.insert( data.end(), 8, static_cast< byte >( 0 ) );
			auto lengthBytes = CommonSecurity::unpackInteger< decltype( data_size ) >( data_size * 8 );
			data.insert( data.end(), lengthBytes.begin(), lengthBytes.end() );
			return;
		}

		inline void HashProvider::StepInitialize()
		{
			hashes = Core::HASH_STATE_CONSTANTS;
		}

		inline void HashProvider::StepUpdate( array< CommonSecurity::EightByte, 8 >& data, const array< CommonSecurity::EightByte, 80 >& keys )
		{
			using namespace Core;
			using namespace Core::Functions;

			auto lambda_choose = []( CommonSecurity::EightByte e, CommonSecurity::EightByte f, CommonSecurity::EightByte g ) -> CommonSecurity::EightByte {
				return chooseHashCode( e, f, g );
			};
			auto lambda_sigmaE = []( CommonSecurity::EightByte e ) -> CommonSecurity::EightByte {
				return Sigma0( e );
			};
			auto lambda_sigmaA = []( CommonSecurity::EightByte a ) -> CommonSecurity::EightByte {
				return Sigma1( a );
			};
			auto lambda_majority = []( CommonSecurity::EightByte a, CommonSecurity::EightByte b, CommonSecurity::EightByte c ) -> CommonSecurity::EightByte {
				return majorityHashCode( a, b, c );
			};

			auto lambda_hashingRound = [ & ]( CommonSecurity::EightByte a, CommonSecurity::EightByte b, CommonSecurity::EightByte c, CommonSecurity::EightByte& d, CommonSecurity::EightByte e, CommonSecurity::EightByte f, CommonSecurity::EightByte g, CommonSecurity::EightByte& h, std::size_t count ) {
				CommonSecurity::EightByte hashcode = h + lambda_choose( e, f, g ) + lambda_sigmaE( e ) + keys[ count ] + HASH_ROUND_CONSTANTS[ count ];
				CommonSecurity::EightByte hashcode2 = lambda_sigmaA( a ) + lambda_majority( a, b, c );
				d += hashcode;
				h = hashcode + hashcode2;
			};

			auto& [ a, b, c, d, e, f, g, h ] = data;

			// total 80 rounds of "hashingRound" called
			size_t count = 0;
			for ( size_t TotalRound = 0; TotalRound < 10; ++TotalRound )
			{
				lambda_hashingRound( a, b, c, d, e, f, g, h, count++ );
				lambda_hashingRound( h, a, b, c, d, e, f, g, count++ );
				lambda_hashingRound( g, h, a, b, c, d, e, f, count++ );
				lambda_hashingRound( f, g, h, a, b, c, d, e, count++ );
				lambda_hashingRound( e, f, g, h, a, b, c, d, count++ );
				lambda_hashingRound( d, e, f, g, h, a, b, c, count++ );
				lambda_hashingRound( c, d, e, f, g, h, a, b, count++ );
				lambda_hashingRound( b, c, d, e, f, g, h, a, count++ );
			}
			return;
		}

		array< byte, 64 > HashProvider::Hash( span< byte > data )
		{
			using namespace Core;
			using namespace Core::Functions;

			// put binary 10000...000 at the end of data
			vector< byte > blocks( data.begin(), data.end() );
			StepFill( blocks );
			StepInitialize();

			// sha512 hash each 1024bits(128bytes)
			// loop for all chunks
			for ( std::size_t loopCount = 0; loopCount < blocks.size(); loopCount += sha512BlockByteCount )
			{
				// C++ 20 <bit> header contains these two template functions
				//using std::rotr;
				//using std::rotl;

				// get 1024bits(128bytes) as chunk
				span< byte, sha512BlockByteCount > chunkSpan{ blocks.begin() + loopCount, sha512BlockByteCount };
				auto							   words = Byte128ToEightBytes( chunkSpan );

				// 1st-fill in keys[80]
				// front 16 uint64 are from those 128bytes (16*8==128)
				// back 64 uint64 are calculated
				array< CommonSecurity::EightByte, 80 > keys;
				std::copy( words.begin(), words.end(), keys.begin() );
				for ( std::size_t KeyIndex = 16; KeyIndex < 80; ++KeyIndex )
				{
					CommonSecurity::EightByte wa = Gamma0( keys[ KeyIndex - 2 ] );
					CommonSecurity::EightByte wb = keys[ KeyIndex - 7 ];
					CommonSecurity::EightByte wc = Gamma1( keys[ KeyIndex - 15 ] );
					CommonSecurity::EightByte wd = keys[ KeyIndex - 16 ];
					CommonSecurity::EightByte resultWord = wa + wb + wc + wd;  // notice only unsigned overflow is legal
					keys[ KeyIndex ] = resultWord;
				}

				// 2nd calculate hash of chunk[loopCount]
				auto tempHash = hashes;
				int	 count = 0;
				StepUpdate( tempHash, keys );

				// 3rd add hash of chunk[loopCount] to global hashes
				for ( std::size_t index = 0; index < hashes.size(); ++index )
				{
					hashes[ index ] += tempHash[ index ];
				}
			}

			array< byte, 64 > hashArray;
			auto			  iter = hashArray.begin();
			for ( std::size_t index = 0; index < hashes.size(); ++index, iter += sizeof( hashes[ 0 ] ) )
			{
				auto bytes = CommonSecurity::unpackInteger( hashes[ index ] );
				std::copy( bytes.begin(), bytes.end(), iter );
			}
			return hashArray;
		}
	}
}
