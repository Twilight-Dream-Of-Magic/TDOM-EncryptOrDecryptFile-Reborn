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

//自定义的密钥衍生函数
//Customized key derivation functions
namespace Cryptograph::CustomizedKDF
{
	enum class IGD_RNG_EnumList : std::uint8_t
	{
		LinearCongruential = 0,
		SquareTakeMiddle = 1,
		ExclusiveorShiftRotate = 2,
		ISAAC = 3,
		MersenneTwister19937 = 4
	};

	enum class IGD_Hasher_EnumList : std::uint8_t
	{
		SHA2 = 0, //512 bit
		SHA3 = 1, //512 bit
		CHINA_SHANG_YONG_MI_MA3 = 2, //512 bit
		BLAKE2 = 3, //512 bit
		BLAKE3 = 4 //512 bit
	};
		
	/*
		Infinite garbled data generation
		无限的乱码数据生成
	*/
	class InfiniteGarbledData
	{
			
	private:

		//512 Bit
		static constexpr std::size_t DataBlockByteSize = 64;

		/*
			All available pseudo-random number generators
			所有可用的伪随机数生成器
		*/
		CommonSecurity::RNG_LC::LinearCongruential<std::uint64_t> PRNG_LinearCongruential; // 0
		CommonSecurity::RNG_NumberSquare_TakeMiddle::JohnVonNeumannAlgorithm<std::uint64_t> PRNG_SquareTakeMiddle; // 1
		CommonSecurity::RNG_Xoshiro::xoshiro1024 PRNG_ExclusiveorShiftRotate; // 2
		CommonSecurity::RNG_ISAAC::isaac64<8> CSPRNG_ISAAC; // 3
		std::mt19937_64 PRNG_MersenneTwister19937; // 4

		std::array<IGD_RNG_EnumList, 5> RNG_EnumState
		{ 
			IGD_RNG_EnumList::LinearCongruential,
			IGD_RNG_EnumList::SquareTakeMiddle,
			IGD_RNG_EnumList::ExclusiveorShiftRotate,
			IGD_RNG_EnumList::ISAAC,
			IGD_RNG_EnumList::MersenneTwister19937
		};

		/*
			All available cryptographic hash functions, key derivation functions
			所有可用的加密哈希函数, 密钥衍生函数
		*/

		using HashersAssistant = CommonSecurity::DataHashingWrapper::HashersAssistant;
		using HashersAssistantParameters = CommonSecurity::DataHashingWrapper::HashersAssistantParameters;

		HashersAssistant HA_Object;
		HashersAssistantParameters HAP_Object;
		CommonSecurity::KDF::HMAC::Algorithm KDF_HMAC;

		std::array<IGD_Hasher_EnumList, 5> Hasher_EnumState
		{ 
			IGD_Hasher_EnumList::SHA2,
			IGD_Hasher_EnumList::SHA3,
			IGD_Hasher_EnumList::CHINA_SHANG_YONG_MI_MA3,
			IGD_Hasher_EnumList::BLAKE2,
			IGD_Hasher_EnumList::BLAKE3
		};

		std::vector<std::uint64_t> UseRNG(IGD_RNG_EnumList SelectRNG, std::size_t Count = 1)
		{
			if(Count == 0)
				Count = 1;

			std::vector<std::uint64_t> RandomNumbers(Count, 0);
				
			switch (SelectRNG)
			{
				case IGD_RNG_EnumList::LinearCongruential:
				{
					for(auto& RandomNumber : RandomNumbers)
						RandomNumber = this->PRNG_LinearCongruential();

					break;
				}
				case IGD_RNG_EnumList::SquareTakeMiddle:
				{
					for(auto& RandomNumber : RandomNumbers)
						RandomNumber = this->PRNG_SquareTakeMiddle();

					break;
				}
				case IGD_RNG_EnumList::ExclusiveorShiftRotate:
				{
					for(auto& RandomNumber : RandomNumbers)
						RandomNumber = this->PRNG_ExclusiveorShiftRotate();

					break;
				}
				case IGD_RNG_EnumList::ISAAC:
				{
					for(auto& RandomNumber : RandomNumbers)
						RandomNumber = this->CSPRNG_ISAAC();

					break;
				}
				case IGD_RNG_EnumList::MersenneTwister19937:
				{
					for(auto& RandomNumber : RandomNumbers)
						RandomNumber = this->PRNG_MersenneTwister19937();

					break;
				}
				default:
					break;
			}

			return RandomNumbers;
		}

		void ChangeSelectHasher(IGD_Hasher_EnumList& SelectHasher)
		{
			switch (SelectHasher)
			{
				case IGD_Hasher_EnumList::SHA2:
					this->HAP_Object.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA2_512;
					break;
				case IGD_Hasher_EnumList::SHA3:
					this->HAP_Object.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::SHA3_512;
					break;
				case IGD_Hasher_EnumList::CHINA_SHANG_YONG_MI_MA3:
					this->HAP_Object.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::CHINA_SHANG_YONG_MI_MA3;
					break;
				case IGD_Hasher_EnumList::BLAKE2:
					this->HAP_Object.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::BLAKE2;
					break;
				case IGD_Hasher_EnumList::BLAKE3:
					this->HAP_Object.hash_mode = CommonSecurity::SHA::Hasher::WORKER_MODE::BLAKE3;
					break;
				default:
					break;
			}
		}

		void InitialEnumState(IGD_RNG_EnumList SelectRNG, std::uint64_t Number)
		{
			if(Number == 0)
				Number = 1;

			std::array<std::uint64_t, 5> RandomSeedNumbers {};

			switch (SelectRNG)
			{
				case IGD_RNG_EnumList::LinearCongruential:
				{
					RandomSeedNumbers[0] = this->PRNG_LinearCongruential() + Number;
					RandomSeedNumbers[1] = this->PRNG_SquareTakeMiddle() + RandomSeedNumbers[0];
					RandomSeedNumbers[2] = this->PRNG_ExclusiveorShiftRotate() + RandomSeedNumbers[1];
					RandomSeedNumbers[3] = this->CSPRNG_ISAAC() + RandomSeedNumbers[2];
					RandomSeedNumbers[4] = this->PRNG_MersenneTwister19937() + RandomSeedNumbers[3];
					RandomSeedNumbers[0] = this->PRNG_LinearCongruential() + RandomSeedNumbers[4];

					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->PRNG_LinearCongruential);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->PRNG_LinearCongruential);
					CommonSecurity::ShuffleRangeData(RandomSeedNumbers, this->PRNG_LinearCongruential);

					break;
				}
				case IGD_RNG_EnumList::SquareTakeMiddle:
				{
					RandomSeedNumbers[0] = this->PRNG_SquareTakeMiddle() + Number;
					RandomSeedNumbers[1] = this->PRNG_ExclusiveorShiftRotate() + RandomSeedNumbers[0];
					RandomSeedNumbers[2] = this->CSPRNG_ISAAC() + RandomSeedNumbers[1];
					RandomSeedNumbers[3] = this->PRNG_MersenneTwister19937() + RandomSeedNumbers[2];
					RandomSeedNumbers[4] = this->PRNG_LinearCongruential() + RandomSeedNumbers[3];
					RandomSeedNumbers[0] = this->PRNG_SquareTakeMiddle() + RandomSeedNumbers[4];

					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->PRNG_SquareTakeMiddle);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->PRNG_SquareTakeMiddle);
					CommonSecurity::ShuffleRangeData(RandomSeedNumbers, this->PRNG_SquareTakeMiddle);

					break;
				}
				case IGD_RNG_EnumList::ExclusiveorShiftRotate:
				{
					RandomSeedNumbers[0] = this->PRNG_ExclusiveorShiftRotate() + Number;
					RandomSeedNumbers[1] = this->CSPRNG_ISAAC() + RandomSeedNumbers[0];
					RandomSeedNumbers[2] = this->PRNG_MersenneTwister19937() + RandomSeedNumbers[1];
					RandomSeedNumbers[3] = this->PRNG_LinearCongruential() + RandomSeedNumbers[2];
					RandomSeedNumbers[4] = this->PRNG_SquareTakeMiddle() + RandomSeedNumbers[3];
					RandomSeedNumbers[0] = this->PRNG_ExclusiveorShiftRotate() + RandomSeedNumbers[4];

					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->PRNG_ExclusiveorShiftRotate);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->PRNG_ExclusiveorShiftRotate);
					CommonSecurity::ShuffleRangeData(RandomSeedNumbers, this->PRNG_ExclusiveorShiftRotate);

					break;
				}
				case IGD_RNG_EnumList::ISAAC:
				{
					RandomSeedNumbers[0] = this->CSPRNG_ISAAC() + Number;
					RandomSeedNumbers[1] = this->PRNG_MersenneTwister19937() + RandomSeedNumbers[0];
					RandomSeedNumbers[2] = this->PRNG_LinearCongruential() + RandomSeedNumbers[1];
					RandomSeedNumbers[3] = this->PRNG_SquareTakeMiddle() + RandomSeedNumbers[2];
					RandomSeedNumbers[4] = this->PRNG_ExclusiveorShiftRotate() + RandomSeedNumbers[3];
					RandomSeedNumbers[0] = this->CSPRNG_ISAAC() + RandomSeedNumbers[4];

					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->CSPRNG_ISAAC);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->CSPRNG_ISAAC);
					CommonSecurity::ShuffleRangeData(RandomSeedNumbers, this->CSPRNG_ISAAC);

					break;
				}
				case IGD_RNG_EnumList::MersenneTwister19937:
				{
					RandomSeedNumbers[0] = this->PRNG_MersenneTwister19937() + Number;
					RandomSeedNumbers[1] = this->PRNG_LinearCongruential() + RandomSeedNumbers[0];
					RandomSeedNumbers[2] = this->PRNG_SquareTakeMiddle() + RandomSeedNumbers[1];
					RandomSeedNumbers[3] = this->PRNG_ExclusiveorShiftRotate() + RandomSeedNumbers[2];
					RandomSeedNumbers[4] = this->CSPRNG_ISAAC() + RandomSeedNumbers[3];
					RandomSeedNumbers[0] = this->PRNG_MersenneTwister19937() + RandomSeedNumbers[4];

					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->PRNG_MersenneTwister19937);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->PRNG_MersenneTwister19937);
					CommonSecurity::ShuffleRangeData(RandomSeedNumbers, this->PRNG_MersenneTwister19937);

					break;
				}
				default:
					break;
			}

			this->PRNG_LinearCongruential.seed(RandomSeedNumbers[0]);
			this->PRNG_SquareTakeMiddle.seed(RandomSeedNumbers[1]);
			this->PRNG_ExclusiveorShiftRotate.seed(RandomSeedNumbers[2]);
			this->CSPRNG_ISAAC.seed(RandomSeedNumbers[3]);
			this->PRNG_MersenneTwister19937.seed(RandomSeedNumbers[4]);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(RandomSeedNumbers.data(), RandomSeedNumbers.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;

			//选择初始的哈希算法
			//Select the initial hashing algorithm
			IGD_Hasher_EnumList& Hasher_EnumValue = this->Hasher_EnumState[0];

			this->ChangeSelectHasher(Hasher_EnumValue);
		}

		void UpdateEnumState()
		{
			switch (this->RNG_EnumState[0])
			{
				case IGD_RNG_EnumList::LinearCongruential:
					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->PRNG_LinearCongruential);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->PRNG_LinearCongruential);
					break;
				case IGD_RNG_EnumList::SquareTakeMiddle:
					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->PRNG_SquareTakeMiddle);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->PRNG_SquareTakeMiddle);
					break;
				case IGD_RNG_EnumList::ExclusiveorShiftRotate:
					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->PRNG_ExclusiveorShiftRotate);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->PRNG_ExclusiveorShiftRotate);
					break;
				case IGD_RNG_EnumList::ISAAC:
					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->CSPRNG_ISAAC);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->CSPRNG_ISAAC);
					break;
				case IGD_RNG_EnumList::MersenneTwister19937:
					CommonSecurity::ShuffleRangeData(this->RNG_EnumState, this->PRNG_MersenneTwister19937);
					CommonSecurity::ShuffleRangeData(this->Hasher_EnumState, this->PRNG_MersenneTwister19937);
					break;
				default:
					break;
			}

			this->ChangeSelectHasher(this->Hasher_EnumState[0]);
		}

		// Step 1. RandomNumbers = UseRNG()
		// Step 2. RandomNumbers --Conversion-> RandomBytes --Conversion-> RandomStringA
		// Step 3. RightPartByteData --Conversion-> RandomBytes --Conversion-> RandomStringB
		// Step 4. In = (RandomStringA ||(Concatenation) RandomStringB)
		// Step 5. Out = Hasher(In)
		// Step 6. RightPartByteData <--Conversion-- RandomBytes <--Conversion-- Out
		std::vector<std::uint8_t> HalfRoundRightPart(IGD_RNG_EnumList& RNG_EnumValue, std::span<std::uint8_t> RightPartByteData)
		{
			using UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString;
			using UtilTools::DataFormating::ASCII_Hexadecmial::hexadecimalString2ByteArray;

			std::vector<std::uint64_t> RandomNumbers = this->UseRNG(RNG_EnumValue, DataBlockByteSize * std::numeric_limits<std::uint8_t>::digits / std::numeric_limits<std::uint64_t>::digits);
			std::vector<std::uint8_t> RandomBytes = CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(RandomNumbers.data(), RandomNumbers.size());
				
			HAP_Object.inputDataString = byteArray2HexadecimalString(RandomBytes) + byteArray2HexadecimalString(RightPartByteData);
			HashersAssistant::SELECT_HASH_FUNCTION(HAP_Object);
			RandomBytes = hexadecimalString2ByteArray(HAP_Object.outputHashedHexadecimalString);

			this->UpdateEnumState();

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(RandomNumbers.data(), RandomNumbers.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			RandomNumbers.resize(0);

			return RandomBytes;
		}

		// Step 1. LeftPartByteData --Conversion-> RandomBytes --Conversion-> RandomStringA
		// Step 2. RandomNumbers = UseRNG()
		// Step 3. RandomNumbers --Conversion-> RandomBytes --Conversion-> RandomStringB
		// Step 4. In = HMAC_KDF(RandomStringA, RandomStringB)
		// Step 5. Out = Hasher(In)
		// Step 6. LeftPartByteData <--Conversion-- RandomBytes <--Conversion-- Out
		std::vector<std::uint8_t> HalfRoundLeftPart(IGD_RNG_EnumList& RNG_EnumValue, std::span<std::uint8_t> LeftPartByteData)
		{
			using UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString;
			using UtilTools::DataFormating::ASCII_Hexadecmial::hexadecimalString2ByteArray;
			using CommonSecurity::KDF::HMAC::Algorithm;

			std::vector<std::uint64_t> RandomNumbers = this->UseRNG(RNG_EnumValue, DataBlockByteSize * std::numeric_limits<std::uint8_t>::digits / std::numeric_limits<std::uint64_t>::digits);
			std::vector<std::uint8_t> RandomBytes = CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(RandomNumbers.data(), RandomNumbers.size());
			std::string SaltByteString = byteArray2HexadecimalString(RandomBytes);

			Algorithm HMAC_KDF_Object;
			HAP_Object.inputDataString = HMAC_KDF_Object.MakeHashByteStreamWithKeyDerivation(HAP_Object, byteArray2HexadecimalString(LeftPartByteData), SaltByteString, "", DataBlockByteSize * 4);

			this->UpdateEnumState();

			HashersAssistant::SELECT_HASH_FUNCTION(HAP_Object);
			RandomBytes = hexadecimalString2ByteArray(HAP_Object.outputHashedHexadecimalString);

			volatile void* CheckPointer = nullptr;

			CheckPointer = memory_set_no_optimize_function<0x00>(RandomNumbers.data(), RandomNumbers.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			RandomNumbers.resize(0);

			return RandomBytes;
		}

	public:

		std::vector<std::uint8_t> ComputationGarbledData(std::span<const std::uint8_t> ByteDataSpan)
		{
			volatile void* CheckPointer = nullptr;

			std::vector<std::uint8_t> ResultByteData(ByteDataSpan.begin(), ByteDataSpan.end());
				
			ResultByteData.resize(DataBlockByteSize, 0);

			//ByteData --Split-> L, R
			std::vector<std::uint8_t> LeftBufferData(ResultByteData.begin(), ResultByteData.begin() + (ResultByteData.size() / 2));
			std::vector<std::uint8_t> RightBufferData(ResultByteData.begin() + (ResultByteData.size() / 2), ResultByteData.end());

			CheckPointer = memory_set_no_optimize_function<0x00>(ResultByteData.data(), ResultByteData.size());
			CheckPointer = nullptr;
			ResultByteData.resize(0);

			IGD_RNG_EnumList& RNG_EnumValue = this->RNG_EnumState[0];

			//Threefish 512 Bit
			std::vector<std::uint64_t> ThreefishObjectWithData(DataBlockByteSize / sizeof(std::uint64_t), 0);
			std::vector<std::uint64_t> ThreefishObjectWithKey(DataBlockByteSize / sizeof(std::uint64_t), 0);
			CommonSecurity::Threefish::Algorithm<8> ThreefishObject {ThreefishObjectWithKey};

			//A design structure with reference to the symmetric encryption-decryption algorithm : Feistel
			//参考了对称加密解密算法的一种设计结构 : Feistel
			for(std::size_t ExexuteRound = 0; ExexuteRound < 8; ++ExexuteRound)
			{
				//Unidirectional Transformations (data hash hashers and pseudo-random number generators)
				//单向变换（数据散列器和伪随机数生成器）
				//R' = HalfRound(R);
				RightBufferData = this->HalfRoundRightPart(RNG_EnumValue, RightBufferData);

				//Transform-Function (Encryption): Data, Key
				//变换-函数（加密）：数据、密钥
				//R'' = Transform-Encryption(R', L);
				ThreefishObjectWithData = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(RightBufferData.data(), RightBufferData.size());
				ThreefishObjectWithKey = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(LeftBufferData.data(), LeftBufferData.size());
				ThreefishObject.UpdateKey(ThreefishObjectWithKey);
				ThreefishObject.EncryptionWithECB(ThreefishObjectWithData.size(), ThreefishObjectWithData, ThreefishObjectWithData);
				RightBufferData = CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(ThreefishObjectWithData.data(), ThreefishObjectWithData.size());

				//L = L ⊕ R''
				std::ranges::transform
				(
					LeftBufferData.begin(),
					LeftBufferData.end(),
					RightBufferData.begin(),
					RightBufferData.end(),
					LeftBufferData.begin(),
					[](std::uint8_t left, std::uint8_t right) -> std::uint8_t
					{
						return left ^ right;
					}
				);

				//Unidirectional Transformations (data hash hashers and pseudo-random number generators)
				//单向变换（数据散列器和伪随机数生成器）
				//L' = HalfRound(L);
				LeftBufferData = this->HalfRoundLeftPart(RNG_EnumValue, LeftBufferData);

				//Transform-Function (Decryption): Data, Key
				//变换-函数（解密）：数据、密钥
				//L'' = Transform-Encryption(L', R'');
				ThreefishObjectWithData = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(LeftBufferData.data(), LeftBufferData.size());
				ThreefishObjectWithKey = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(RightBufferData.data(), RightBufferData.size());
				ThreefishObject.UpdateKey(ThreefishObjectWithKey);
				ThreefishObject.DecryptionWithECB(ThreefishObjectWithData.size(), ThreefishObjectWithData, ThreefishObjectWithData);
				LeftBufferData = CommonToolkit::MessageUnpacking<std::uint64_t, std::uint8_t>(ThreefishObjectWithData.data(), ThreefishObjectWithData.size());

				//R''' = R'' ⊕ L''
				std::ranges::transform
				(
					RightBufferData.begin(),
					RightBufferData.end(),
					LeftBufferData.begin(),
					LeftBufferData.end(),
					RightBufferData.begin(),
					[](std::uint8_t right, std::uint8_t left) -> std::uint8_t
					{
						return left ^ right;
					}
				);

				ResultByteData.insert(ResultByteData.end(), LeftBufferData.begin(), LeftBufferData.end());
				ResultByteData.insert(ResultByteData.end(), RightBufferData.begin(), RightBufferData.end());
			}

			return ResultByteData;
		}

		InfiniteGarbledData() = delete;
		InfiniteGarbledData(const InfiniteGarbledData& OtherObject) = delete;
		InfiniteGarbledData(InfiniteGarbledData&& OtherObject) = delete;

		InfiniteGarbledData(IGD_RNG_EnumList SelectRNG, std::uint64_t Number)
		{
			this->HAP_Object.generate_hash_bit_size = DataBlockByteSize * std::numeric_limits<std::uint8_t>::digits;
				
			this->InitialEnumState(SelectRNG, Number);

			this->HAP_Object.whether_use_hash_extension_bit_mode = true;
		}

		~InfiniteGarbledData() = default;
	};
}

//Cryptography for Quantum-Resistant Computers
//抗量子计算机的密码学
namespace Cryptograph::QuantumResistantComputers
{
	//N
	#define OPC_WITH_EIGEN_MATRIX_COLUMNS 128

	//M
	#define OPC_WITH_EIGEN_MATRIX_ROWS 128

	//Reference code: https://github.com/cepdnaclk/e16-4yp-post-quantum-cryptographic-schemes-based-on-plain-lattices/blob/main/code/Hybrid/ssl.cpp
	class LearningWithErrorModule
	{

	private:

		//http://compoasso.free.fr/primelistweb/page/prime/liste_online_en.php
		static constexpr std::int64_t BigPrimeNumber = 4294967311;
		static constexpr double pi = 3.141592653589793;

		//M is matrix columns, N is matrix rows

		Eigen::Matrix<std::int64_t, OPC_WITH_EIGEN_MATRIX_COLUMNS, OPC_WITH_EIGEN_MATRIX_ROWS> RandomMatrixA = Eigen::Matrix<std::int64_t, OPC_WITH_EIGEN_MATRIX_COLUMNS, OPC_WITH_EIGEN_MATRIX_ROWS>::Zero();
		Eigen::Matrix<std::int64_t, 1, OPC_WITH_EIGEN_MATRIX_COLUMNS> SecretKeyMaterials = Eigen::Matrix<std::int64_t, 1, OPC_WITH_EIGEN_MATRIX_COLUMNS>::Zero();

		CommonSecurity::RNG_ISAAC::isaac64<8> CSPRNG;

		#if 0

		// U ~ [0, 1]
		// S = sum U_i for i = 1 to M
		// S ~ N(M / 2, M / 12)
		// Z = (S - M / 2) / sqrt(M / 12)
		// Z ~ N(0, 1)
		// https://en.wikipedia.org/wiki/Central_limit_theorem
		// https://github.com/miloyip/normaldist-benchmark
		template<std::floating_point RealNumberType, typename RNG_Type, std::uint32_t SUM_COUNTER>
		requires std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		RealNumberType CentralLimitTheorem(RNG_Type& function)
		{
			// (SUM_COUNTER > 2), SUM_COUNTER can be 4, 8, 16, 32, 64 ......
			RealNumberType invert_number = 1.0 / std::sqrt(RealNumberType(SUM_COUNTER) / 12U);

			RealNumberType sum = function();
			for(std::uint32_t index = 1; index < SUM_COUNTER; index++)
			{
				sum += function();
			}

			return (sum - SUM_COUNTER / RealNumberType(2U)) * invert_number;
		}

		void UseCentralLimitTheorem()
		{
			auto floating_value = CentralLimitTheorem<double, CommonSecurity::RNG_ISAAC::isaac64<8>, 16>(CSPRNG);
		}
			
		#endif

		double GaussianDistribution(double sigma_value)
		{
			/*
				Warning!
				Although this is C++ 2011 STL code is mostly portable, however the implementation of the library source code for the random number generation distribution is not consistent.
				so the data generated by platform A and the data generated by platform B cannot be used with each other
				so if the data is not saved, then it is not portable!

				So don't use the commented out code below!
			*/
			//std::normal_distribution<double> stl_normal_distribution(0.0, sigma_value);
			//auto value = stl_normal_distribution(CSPRNG);
				
			//Reference code:
			//https://people.sc.fsu.edu/~jburkardt/cpp_src/normal/normal.html

			CommonSecurity::RND::UniformRealNumberDistribution<double> uniform_distribution(0.0, sigma_value);

			auto uniform_distribution_random_number_0 = uniform_distribution(CSPRNG);
			auto uniform_distribution_random_number_1 = uniform_distribution(CSPRNG);

			auto normal_distribution_floating_number_01 = ::sqrt( -2.0 * ::log( uniform_distribution_random_number_0 ) ) * ::cos( 2.0 * pi * uniform_distribution_random_number_1 );

			//normal_distribution_floating_number = min + max * normal_distribution_floating_number_01(uniform_distribution(PRNG), uniform_distribution(PRNG));
			auto normal_distribution_floating_number = 0.0 + sigma_value * normal_distribution_floating_number_01;

			//normal_distribution_random_number = normal_distribution_random_number_min_max(normal_distribution_floating_number);
			if(normal_distribution_floating_number > 0.5)
				normal_distribution_floating_number -= 1.0;
			else if(normal_distribution_floating_number < -0.5)
				normal_distribution_floating_number += 1.0;

			return normal_distribution_floating_number;
		}

	public:

		std::vector<std::uint8_t> KeyGeneration(std::span<const std::uint8_t> classic_byte_personal_key_materials)
		{
			using CommonSecurity::RND::UniformIntegerDistribution;

			std::vector<std::uint64_t> quad_words = CommonToolkit::MessagePacking<std::uint64_t, std::uint8_t>(classic_byte_personal_key_materials.data(), classic_byte_personal_key_materials.size());

			UniformIntegerDistribution<std::int64_t> uniform_integer_distribution(0, BigPrimeNumber - 1);

			for(std::size_t current_column = 0; current_column < OPC_WITH_EIGEN_MATRIX_COLUMNS; current_column++)
			{
				for(std::size_t current_row = 0; current_row < OPC_WITH_EIGEN_MATRIX_ROWS; current_row++)
				{
					this->RandomMatrixA(current_column, current_row) = uniform_integer_distribution(CSPRNG);
				}
			}

			for(std::size_t current_column = 0; current_column < this->SecretKeyMaterials.cols(); current_column++)
			{
				if(current_column < quad_words.size())
				{
					std::int64_t* quad_words_type_alias = std::bit_cast<std::int64_t*>(&quad_words[current_column]);
					this->SecretKeyMaterials(current_column) = uniform_integer_distribution(CSPRNG) ^ *quad_words_type_alias;
				}
				else
				{
					this->SecretKeyMaterials(current_column) = uniform_integer_distribution(CSPRNG);
				}
			}

			memory_set_no_optimize_function<0x00>(quad_words.data(), quad_words.size() * sizeof(std::uint64_t));
			quad_words.clear();
			quad_words.shrink_to_fit();

			double alpha_value = ::sqrt(static_cast<double>(OPC_WITH_EIGEN_MATRIX_COLUMNS)) / static_cast<double>(BigPrimeNumber);
			double sigma_value = alpha_value / ::sqrt(2.0 * pi);

			Eigen::Matrix<std::int64_t, 1, OPC_WITH_EIGEN_MATRIX_ROWS> ErrorNoiseKeysWord = Eigen::Matrix<std::int64_t, 1, OPC_WITH_EIGEN_MATRIX_ROWS>::Zero();

			for(std::size_t current_column = 0; current_column < ErrorNoiseKeysWord.cols(); current_column++)
			{
				ErrorNoiseKeysWord(current_column) = static_cast<std::int64_t>(this->GaussianDistribution(sigma_value) * static_cast<double>(BigPrimeNumber));
			}

			Eigen::Matrix<std::int64_t, 1, OPC_WITH_EIGEN_MATRIX_ROWS> GeneretedKeysWord = Eigen::Matrix<std::int64_t, 1, OPC_WITH_EIGEN_MATRIX_ROWS>::Zero();

			//基于容错学习问题的抗量子密码学
			//Error-tolerant learning problem-based quantum-resistant cryptography
			//https://zh.wikipedia.org/wiki/%E5%AE%B9%E9%94%99%E5%AD%A6%E4%B9%A0%E9%97%AE%E9%A2%98
			//https://en.wikipedia.org/wiki/Learning_with_errors
			GeneretedKeysWord = this->SecretKeyMaterials * this->RandomMatrixA + ErrorNoiseKeysWord;

			std::vector<std::uint8_t> ResultKeysByte(GeneretedKeysWord.size() * sizeof(std::int64_t), std::uint8_t{0});

			std::size_t KeysByteIndex = 0;
			for(const auto& KeysWord : GeneretedKeysWord)
			{
				auto BytesArrayBuffer = CommonToolkit::value_to_bytes<std::int64_t, std::uint8_t>(KeysWord);
				for(const auto& Byte : BytesArrayBuffer)
				{
					if(KeysByteIndex < ResultKeysByte.size())
					{
						ResultKeysByte[KeysByteIndex] = Byte;
						++KeysByteIndex;
					}
				}
			}
			KeysByteIndex = 0;

			return ResultKeysByte;
		}

		LearningWithErrorModule() = delete;

		LearningWithErrorModule(std::uint32_t seed) : CSPRNG(seed) {}

		LearningWithErrorModule(std::span<const std::uint32_t> seed_sequence) : CSPRNG(seed_sequence) {}

		LearningWithErrorModule(std::random_device random_device_object) : CSPRNG(random_device_object) {}
	};

	#undef OPC_WITH_EIGEN_MATRIX_COLUMNS;

	#undef OPC_WITH_EIGEN_MATRIX_ROWS;
}

//#define USE_ALZETTE_KEYSTEAM_MODULE

#ifdef USE_ALZETTE_KEYSTEAM_MODULE

/*
	Alzette: A 64-Bit ARX-box: (feat. CRAX and TRAX)
	https://hal.inria.fr/hal-03135836
*/
namespace Cryptograph::AlzetteModule
{
	struct AlgorithmImplementation
	{
		static constexpr std::array<std::uint32_t, 8> ALZETTE_ROUND_CONSTANT_VALUES
		{ 
			static_cast<std::uint32_t>(0xB7E15162),
			static_cast<std::uint32_t>(0xBF715880),
			static_cast<std::uint32_t>(0x38B4DA56),
			static_cast<std::uint32_t>(0x324E7738),
			static_cast<std::uint32_t>(0xBB1185EB),
			static_cast<std::uint32_t>(0x4F7C7B57),
			static_cast<std::uint32_t>(0xCFBFA1C8),
			static_cast<std::uint32_t>(0xC2B3293D)
		};

		void KeyStream
		(
			std::array<std::uint32_t, 8> Keys,
			std::array<std::uint32_t, 8 * 17 + 8>& SubKeys
		)
		{
			for(std::uint32_t StepCounter = 0, TemporaryKey = 0; StepCounter < 18; ++StepCounter)
			{
				//change 8 subkeys

				for(std::uint32_t BranchCounter; BranchCounter < 8; ++BranchCounter)
					SubKeys[8 * StepCounter + BranchCounter] = Keys[BranchCounter];

				//update rotate keys

				Keys[0] += Keys[1] + ALZETTE_ROUND_CONSTANT_VALUES[(2 * StepCounter) % ALZETTE_ROUND_CONSTANT_VALUES.size()];
				Keys[2] ^= Keys[3] ^ StepCounter;
				Keys[4] += Keys[5] + ALZETTE_ROUND_CONSTANT_VALUES[(2 * StepCounter + 1) % ALZETTE_ROUND_CONSTANT_VALUES.size()];
				Keys[6] ^= Keys[7] ^ static_cast<std::uint32_t>(StepCounter << 16);

				//left rotate keys 

				TemporaryKey = Keys[0];

				for (std::uint32_t BranchCounter = 1; BranchCounter < 8; BranchCounter++)
					Keys[BranchCounter - 1] = Keys[BranchCounter ];

				Keys[7] = TemporaryKey;

			}
		}

		std::array<std::uint32_t, 2>
		Transfrom
		(
			std::span<const std::uint32_t> BitReorganizationWord
		)
		{
			std::array<std::uint32_t, 2> RoundSubKeyWords { BitReorganizationWord[0], BitReorganizationWord[1] };

			auto& [RandomValueA, RandomValueB] = RoundSubKeyWords;

			//#define SELECT_ALZETTE_KEYSTEAM_FUCTION_FORWARD
			//#define SELECT_ALZETTE_KEYSTEAM_FUCTION_BACKWARD

			#if defined(USE_ALZETTE_KEYSTEAM_FUCTION) && defined(SELECT_ALZETTE_KEYSTEAM_FUCTION_FORWARD) && !defined(SELECT_ALZETTE_KEYSTEAM_FUCTION_BACKWARD)

			//
			//	x ← x + (y >>> 31)
			//	y ← y ⊕ (x >>> 24)
			//	x ← x ⊕ constant_values[i]

			//	x ← x + (y >>> 17)
			//	y ← y ⊕ (x >>> 17)
			//	x ← x ⊕ constant_values[i + 1]

			//	x ← x + (y >>> 0)
			//	y ← y ⊕ (x >>> 31)
			//	x ← x ⊕ constant_values[i + 2]

			//	x ← x + (y >>> 24)
			//	y ← y ⊕ (x >>> 16)
			//	x ← x ⊕ constant_values[i + 3]
			//

			for(std::uint32_t LoopStep = 0; LoopStep < 17; LoopStep++)
			{
				RandomValueA += std::rotr(RandomValueB, static_cast<std::uint32_t>(31));
				RandomValueB ^= std::rotr(RandomValueA, static_cast<std::uint32_t>(24));
				RandomValueA ^= ALZETTE_ROUND_CONSTANT_VALUES[LoopStep % ALZETTE_ROUND_CONSTANT_VALUES.size()];

				RandomValueA += std::rotr(RandomValueB, static_cast<std::uint32_t>(17));
				RandomValueB ^= std::rotr(RandomValueA, static_cast<std::uint32_t>(17));
				RandomValueA ^= ALZETTE_ROUND_CONSTANT_VALUES[(LoopStep + 1) % ALZETTE_ROUND_CONSTANT_VALUES.size()];

				RandomValueA += RandomValueB;
				RandomValueB ^= std::rotr(RandomValueA, static_cast<std::uint32_t>(31));
				RandomValueA ^= ALZETTE_ROUND_CONSTANT_VALUES[(LoopStep + 2) % ALZETTE_ROUND_CONSTANT_VALUES.size()];

				RandomValueA += std::rotr(RandomValueB, static_cast<std::uint32_t>(24));
				RandomValueB ^= std::rotr(RandomValueA, static_cast<std::uint32_t>(16));
				RandomValueA ^= ALZETTE_ROUND_CONSTANT_VALUES[(LoopStep + 3) % ALZETTE_ROUND_CONSTANT_VALUES.size()];
			}

			return RoundSubKeyWords;

			#elif defined(USE_ALZETTE_KEYSTEAM_FUCTION) && defined(SELECT_ALZETTE_KEYSTEAM_FUCTION_BACKWARD) && !defined(SELECT_ALZETTE_KEYSTEAM_FUCTION_FORWARD)

			//
			//	x ← x ⊕ constant_values[i + 3]
			//	y ← y ⊕ (x >>> 16)
			//	x ← x - (y >>> 24)
			// 
			//	x ← x ⊕ constant_values[i + 2]
			//	y ← y ⊕ (x >>> 31)
			//	x ← x - (y >>> 0)
			//
			//	x ← x ⊕ constant_values[i + 1]
			//	y ← y ⊕ (x >>> 17)
			//	x ← x - (y >>> 17)
			//
			//	x ← x ⊕ constant_values[i]
			//	y ← y ⊕ (x >>> 24)
			//	x ← x - (y >>> 31)
			//

			for(std::uint32_t LoopStep = 17; LoopStep > 0; LoopStep--)
			{
				RandomValueA ^= ALZETTE_ROUND_CONSTANT_VALUES[(LoopStep + 3) % ALZETTE_ROUND_CONSTANT_VALUES.size()];
				RandomValueB ^= std::rotr(RandomValueA, static_cast<std::uint32_t>(16));
				RandomValueA -= std::rotr(RandomValueB, static_cast<std::uint32_t>(24));
						
				RandomValueA ^= ALZETTE_ROUND_CONSTANT_VALUES[(LoopStep + 2) % ALZETTE_ROUND_CONSTANT_VALUES.size()];
				RandomValueB ^= std::rotr(RandomValueA, static_cast<std::uint32_t>(31));
				RandomValueA -= RandomValueB;

				RandomValueA ^= ALZETTE_ROUND_CONSTANT_VALUES[(LoopStep + 1) % ALZETTE_ROUND_CONSTANT_VALUES.size()];
				RandomValueB ^= std::rotr(RandomValueA, static_cast<std::uint32_t>(17));
				RandomValueB -= std::rotr(RandomValueA, static_cast<std::uint32_t>(17));

				RandomValueA ^= ALZETTE_ROUND_CONSTANT_VALUES[LoopStep % ALZETTE_ROUND_CONSTANT_VALUES.size()];
				RandomValueB ^= std::rotr(RandomValueA, static_cast<std::uint32_t>(24));
				RandomValueA -= std::rotr(RandomValueB, static_cast<std::uint32_t>(31));
			}

			return RoundSubKeyWords;

			#endif

			#undef SELECT_ALZETTE_KEYSTEAM_FUCTION_FORWARD
			#undef SELECT_ALZETTE_KEYSTEAM_FUCTION_BACKWARD
		}

		AlgorithmImplementation() = default;
		~AlgorithmImplementation() = default;
	};
}

#endif

#if defined(USE_ALZETTE_KEYSTEAM_FUCTION)
#undef USE_ALZETTE_KEYSTEAM_FUCTION
#endif