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
 * This document is part of TDOM-EncryptOrDecryptFile-Reborn.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

namespace CommonSecurity::KDF::Argon2
{
	/*
		
		https://en.wikipedia.org/wiki/Argon2
		https://password-hashing.net/argon2-specs.pdf

		Argon2 is a key derivation function that was selected as the winner of the Password Hashing Competition.
		It was designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg.
		The reference implementation of Argon2 is released under a Creative Commons CC0 license (i.e. public domain) or the Apache License 2.0, and provides three related versions:

		Argon2d maximizes resistance to GPU cracking attacks.
		Faster compute.
		It accesses the memory array in a password dependent order, which reduces the possibility of time–memory trade-off (TMTO) attacks;
		Uses data-dependent memory access, but this data dependency is not completely secure and unknown third parties may immediately use side-channel attacks. 
		This only applies to cryptocurrencies and applications where there is no threat from a side-channel attack.
		
		Argon2i is optimized to resist side-channel attacks.
		It accesses the memory array in a password independent order.
		Uses data-independent memory access, which is preferred for cryptographic hashing and password-based key derivation functions.
		
		Argon2id is a hybrid version.
		Is a hybrid of Argon2i and Argon2d, using a combination of data-depending and data-independent memory accesses, which gives some of Argon2i’s resistance to side-channel cache timing attacks and much of Argon2d’s resistance to GPU cracking attacks.
		It follows the Argon2i approach for the first half pass over memory and the Argon2d approach for subsequent passes. 

		The RFC recommends using Argon2id if you don't know the difference between these hash working mode types, or if you think that side-channel attacks are a viable threat.
		
		All three modes allow specification by three parameters that control:

		execution time
		memory required
		degree of parallelism

	*/

	/*
		
		https://en.wikipedia.org/wiki/Argon2
		https://password-hashing.net/argon2-specs.pdf

		Argon2是一个密钥推导函数，被选为密码哈希大赛的冠军。
		它是由卢森堡大学的Alex Biryukov, Daniel Dinu, 和Dmitry Khovratovich设计的。
		Argon2的参考实现以知识共享CC0许可（即公共领域）或Apache许可2.0发布，并提供三个相关版本。

		Argon2d能最大限度地抵抗GPU破解攻击。
		更快的计算。
		它以依赖密码的顺序访问内存阵列，这减少了时间-内存折衷（TMTO）攻击的可能性。
		使用数据依赖性内存访问，但这种数据依赖性并不完全安全，未知的第三方可能立即使用侧通道攻击。 
		这只适用于加密货币和应用程序，因为没有来自侧信道攻击的威胁。
		
		Argon2i进行了优化，以抵御侧信道攻击。
		它以独立于密码的顺序访问内存阵列。
		使用与数据无关的内存访问，这对于密码散列和基于密码的密钥推导函数是首选。
		
		Argon2id是一个混合版本。
		是Argon2i和Argon2d的混合体，使用数据依赖和数据独立的内存访问的组合，这使Argon2i对侧信道缓存定时攻击有一些抵抗力，Argon2d对GPU破解攻击有很多抵抗力。
		它在内存的前半段采用Argon2i方法，在随后的段落中采用Argon2d方法。

		RFC建议，如果你不知道这些哈希工作模式类型之间的区别，或者你认为侧信道攻击是一个可行的威胁，就使用Argon2id。
		
		所有这三种模式都允许通过三个参数进行规范，这些参数控制。

		执行时间
		所需内存
		并行性的程度

	*/

	namespace Exceptions
	{
		enum class StatusCodes
		{
			OK = 0,

			GENERATE_HASHED_POINTER_NULL = 1,

			GENERATE_HASHED_SIZE_TOO_SHORT = 2,
			GENERATE_HASHED_SIZE_TOO_LONG = 2,

			MESSAGE_PASSWORD_SIZE_TOO_SHORT = 4,
			MESSAGE_PASSWORD_SIZE_TOO_LONG = 5,

			SALT_BYTE_SIZE_TOO_SHORT = 6,
			SALT_BYTE_SIZE_TOO_LONG = 7,

			EXTRA_BYTE_SIZE_TOO_SHORT = 8,
			EXTRA_BYTE_SIZE_TOO_LONG = 9,

			SECRET_KEY_SIZE_TOO_SHORT = 10,
			SECRET_KEY_SIZE_TOO_LONG = 11,

			ITERATION_TIME_COST_TOO_SMALL = 12,
			ITERATION_TIME_COST_TOO_BIG = 13,

			MEMORY_COST_TOO_LITTIE = 14,
			MEMORY_COST_TOO_LARGE = 15,

			LANES_ROWS_TOO_FEW = 16,
			LANES_ROWS_TOO_MANY = 17,

			//Null-pointer with non-zero length/size
			MESSAGE_PASSWORD_POINTER_MISMATCH = 18,
			//Null-pointer with non-zero length/size
			SALT_BYTE_POINTER_MISMATCH = 19,
			//Null-pointer with non-zero length/size
			SECRET_KEY_POINTER_MISMATCH = 21,
			//Null-pointer with non-zero length/size
			EXTREA_BYTE_POINTER_MISMATCH = 22,
			//Null-pointer with non-zero length/size
			GENERATE_HASHED_POINTER_MISMATCH = 23,

			INCORRECT_PARAMETER = 24,
			INCORRECT_HASH_MODE_TYPE = 25,

			THREADS_COST_TOO_FEW = 26,
			THRAEDS_COST_TOO_MANY = 27,

			STATUS_CODES_SIZE
		};

		static const std::map<StatusCodes, std::string> StatusMessage
		{
			{StatusCodes::OK, "OK"},

			{StatusCodes::GENERATE_HASHED_POINTER_NULL, "Argon2 Error: Generate hashed pointer is null-pointer!"},

			{StatusCodes::GENERATE_HASHED_SIZE_TOO_SHORT, "Argon2 Error: Generate hashed size is too short!"},
			{StatusCodes::GENERATE_HASHED_SIZE_TOO_LONG, "Argon2 Error: Generate hashed size is too long!"},

			{StatusCodes::MESSAGE_PASSWORD_SIZE_TOO_SHORT, "Argon2 Error: Message or password size is too short!"},
			{StatusCodes::MESSAGE_PASSWORD_SIZE_TOO_LONG, "Argon2 Error: Message or password size is too long!"},

			{StatusCodes::SALT_BYTE_SIZE_TOO_SHORT, "Argon2 Error: Salt byte size is too short!"},
			{StatusCodes::SALT_BYTE_SIZE_TOO_LONG, "Argon2 Error: Salt byte size is too long!"},

			{StatusCodes::EXTRA_BYTE_SIZE_TOO_SHORT, "Argon2 Error: Extra byte size is too short!"},
			{StatusCodes::EXTRA_BYTE_SIZE_TOO_LONG, "Argon2 Error: Extra byte size is too long!"},

			{StatusCodes::SECRET_KEY_SIZE_TOO_SHORT, "Argon2 Error: Secret key size is too short!"},
			{StatusCodes::SECRET_KEY_SIZE_TOO_LONG, "Argon2 Error: Secret key size is too long!"},

			{StatusCodes::ITERATION_TIME_COST_TOO_SMALL, "Argon2 Error: Too small iteration time cost!"},
			{StatusCodes::ITERATION_TIME_COST_TOO_BIG, "Argon2 Error: Too big iteration time cost!"},

			{StatusCodes::MEMORY_COST_TOO_LITTIE, "Argon2 Error: Too little memory block space cost!"},
			{StatusCodes::MEMORY_COST_TOO_LARGE, "Argon2 Error: Too large memory block space cost!"},

			{StatusCodes::MESSAGE_PASSWORD_POINTER_MISMATCH, "Argon2 Error: Message or Password pointer is null-pointer, then the data space cost should be 0 units, but this unit size is not 0!"},
			{StatusCodes::SALT_BYTE_POINTER_MISMATCH, "Argon2 Error: Salt pointer is null-pointer, then the data space cost should be 0 units, but this unit size is not 0!"},
			{StatusCodes::SECRET_KEY_POINTER_MISMATCH, "Argon2 Error: Secret pointer is null-pointer, then the data space cost should be 0 units, but this unit size is not 0!"},
			{StatusCodes::EXTREA_BYTE_POINTER_MISMATCH, "Argon2 Error: Extra byte data or Associated byte data pointer is null-pointer, then the data space cost should be 0 units, but this unit size is not 0!"},
			{StatusCodes::GENERATE_HASHED_POINTER_MISMATCH, "Argon2 Error: generate hashed digest byte data pointer is null-pointer, then the data space cost should be 0 units, but this unit size is not 0!"},

			{StatusCodes::INCORRECT_PARAMETER, "Argon2 Error: Argon2Parameters struct context is null-pointer"},
			{StatusCodes::INCORRECT_HASH_MODE_TYPE, "Argon2 Error: There is no such hash mode type of Argon2"},
    
			{StatusCodes::THREADS_COST_TOO_FEW, "Argon2 Error: Too few threads cost!"},
			{StatusCodes::THRAEDS_COST_TOO_MANY, "Argon2 Error: Too many threads cost!"}

		};

		inline std::string GetStatusCodeMessage(const StatusCodes& status_code)
		{
			if(status_code < StatusCodes::STATUS_CODES_SIZE)
			{
				return StatusMessage.at(status_code);
			}

			return std::string("Argon2 Fatal: Oops, This is unknown status code.");
		}
	}
	enum class AlgorithmVersion : std::uint32_t
	{
		NUMBER_0x10 = static_cast<std::uint32_t>(0x10),
		NUMBER_0x13 = static_cast<std::uint32_t>(0x13),
	};

	/*
		Argon2 primitive hash mode type
	*/
	enum class HashModeType : std::uint32_t
	{
		//Argon2 dependent addressing Mode <-> Argon2d
		//Argon2依赖寻址模式 <-> Argon2d
		DependentAddressing = 0,

		//Argon2 independent addressing Mode <-> Argon2i
		//Argon2独立寻址模式 <-> Argon2i
		IndependentAddressing = 1,

		//Argon2 independent and dependent mixed Addressing Mode <-> Argon2id (Hybrid construction)
		//In the first two slices of the first pass it generates reference addresses data-independently as in Argon2i, whereas in later slices and next passes it generates them data-dependently as in Argon2d.
		//Argon2独立和依赖的混合寻址模式 <-> Argon2id (混合结构)
		//在第一次传递的前两个片断中，它像Argon2i一样独立于数据生成参考地址，而在后面的片断和下一次传递中，它像Argon2d一样独立于数据生成。
		MixedAddressing = 2,

		//Argon2 special work Mode <-> Argon2ds (Substitution box hardened)
		//In this version the compression function G includes the 64-bit transformation function tao , which is a chain of S-boxes, multiplications, and additions.
		//Argon2特殊工作模式<->Argon2ds (置换盒硬化)
		//在这个版本中，压缩函数G包括64位变换函数tao，它是一个置换盒、乘法和加法的链条。
		SubstitutionBox = 4,
	};

	enum class HashModeTypeStringAlphabetFormat
	{
		LOWER_CASE,
		UPPER_CASE,
	};

	inline const std::string GetHashModeTypeString(const HashModeType& hash_mode_type, const HashModeTypeStringAlphabetFormat& alphabet_format)
	{
		switch (hash_mode_type)
		{
			case CommonSecurity::KDF::Argon2::HashModeType::DependentAddressing:
				return alphabet_format == HashModeTypeStringAlphabetFormat::LOWER_CASE ? "argon2d" : "Argon2d" ;
				break;
			case CommonSecurity::KDF::Argon2::HashModeType::IndependentAddressing:
				return alphabet_format == HashModeTypeStringAlphabetFormat::LOWER_CASE ? "argon2i" : "Argon2i" ;
				break;
			case CommonSecurity::KDF::Argon2::HashModeType::MixedAddressing:
				return alphabet_format == HashModeTypeStringAlphabetFormat::LOWER_CASE ? "argon2id" : "Argon2id" ;
				break;
			case CommonSecurity::KDF::Argon2::HashModeType::SubstitutionBox:
				return alphabet_format == HashModeTypeStringAlphabetFormat::LOWER_CASE ? "argon2ds" : "Argon2ds" ;
				break;
			default:
				break;
		}
	}

	namespace Constants
	{
		/*************************Argon2 parameter restrictions**************************************************/

		/* Minimum and maximum number of lanes(rows) (degree of parallelism) */
		//Integer (1 ~ power(2,24)-1) Degree of planned parallelism (i.e. number of planned threads)
		inline constexpr std::uint32_t MINIMUM_PARALLELISM_LANES_ROWS = 1;
		//Integer (1 ~ power(2,24)-1) Degree of planned parallelism (i.e. number of planned threads)
        inline constexpr std::uint32_t MAXIMUM_PARALLELISM_LANES_ROWS = 1 << 24;

		//Integer (1 ~ power(2,24)-1) Degree of actual parallelism (i.e. number of actual threads)
		inline constexpr std::uint32_t MINIMUM_ACTUAL_PARALLELISM_LANES_ROWS = 1;
		//Integer (1 ~ power(2,24)-1) Degree of actual parallelism (i.e. number of actual threads)
        inline constexpr std::uint32_t MAXIMUM_ACTUAL_PARALLELISM_LANES_ROWS = 1 << 24;

		/* Number of synchronization points between lanes(rows) per pass */
		inline constexpr std::uint32_t SYNC_POINTS = 4;

		/* Minimum and maximum digest size in bytes */
		//Integer (4 ~ power(2,32)-1) Desired number of returned bytes)
		inline constexpr std::uint32_t MINIMUM_GENERATE_HASHED_DIGEST_SIZE = 4;
		//Integer (4 ~ power(2,32)-1) Desired number of returned bytes
        inline constexpr std::uint32_t MAXIMUM_GENERATE_HASHED_DIGEST_SIZE = std::numeric_limits<std::uint32_t>::max();

		/* Minimum and maximum number of memory blocks (each of BYTES_MEMORY_BLOCK_SIZE bytes) */
		//Integer (8 * parallelism_block_row_number ~ power(2,32)-1) Amount of memory (in kilobytes) to use
		/* 2 blocks per slice(column) */
		inline constexpr std::size_t MINIMUM_MEMORY_BLOCK_BYTE_COUNT = 2 * SYNC_POINTS;

		inline constexpr std::uint32_t CHOSE1_MINIMUM_MEMORY_BLOCK_BITS = static_cast<std::uint32_t>(32);
		inline constexpr std::uint32_t CHOSE2_MINIMUM_MEMORY_BLOCK_BITS = ( sizeof(void *) * std::numeric_limits<std::uint8_t>::digits - 10 - 1 );
		inline constexpr std::size_t MINIMUM_MEMORY_BLOCK_BITS = ( CHOSE1_MINIMUM_MEMORY_BLOCK_BITS < CHOSE2_MINIMUM_MEMORY_BLOCK_BITS ) ? CHOSE1_MINIMUM_MEMORY_BLOCK_BITS : CHOSE2_MINIMUM_MEMORY_BLOCK_BITS;

		/* Max memory size is half the addressing space, topping at 2^32 blocks (4 TB)*/
		//Integer (8 * parallelism_block_row_number ~ power(2,32)-1) Amount of memory (in kilobytes) to use
		inline constexpr std::uint64_t CHOSE1_MEMORY_BLOCK_BYTE_COUNT = std::numeric_limits<std::uint32_t>::max();
		inline constexpr std::uint64_t CHOSE2_MEMORY_BLOCK_BYTE_COUNT = static_cast<std::uint64_t>(1) << MINIMUM_MEMORY_BLOCK_BITS;
        inline constexpr std::size_t MAXIMUM_MEMORY_BLOCK_BYTE_COUNT = ( CHOSE1_MEMORY_BLOCK_BYTE_COUNT < CHOSE2_MEMORY_BLOCK_BYTE_COUNT ) ? CHOSE1_MEMORY_BLOCK_BYTE_COUNT : CHOSE2_MEMORY_BLOCK_BYTE_COUNT;

		/* Minimum and maximum number of passes */
		//Integer (1 ~ power(2,32)-1) Number of iterations to perform
		inline constexpr std::uint32_t MINIMUM_BLOCK_ITERATIONS_TIME = 1;
		//Integer (1 ~ power(2,32)-1) Number of iterations to perform
        inline constexpr std::uint32_t MAXIMUM_BLOCK_ITERATIONS_TIME = std::numeric_limits<std::uint32_t>::max();

		/* Minimum and maximum password length in bytes */
		//Bytes (0 ~ power(2,32)-1) Password (or message) need be hashed
		inline constexpr std::uint32_t MINIMUM_MESSAGE_PASSWORD_BYTE_SIZE = 0;
		//Bytes (0 ~ power(2,32)-1) Password (or message) need be hashed
        inline constexpr std::uint32_t MAXIMUM_MESSAGE_PASSWORD_BYTE_SIZE = std::numeric_limits<std::uint32_t>::max();

		/* Minimum and maximum salt length in bytes */
		//Bytes (8 ~ power(2,32)-1) Salt (16 bytes recommended for password hashing)
		inline constexpr std::uint32_t MINIMUM_SALT_BYTE_SIZE = 8;
		//Bytes (8 ~ power(2,32)-1) Salt (16 bytes recommended for password hashing)
        inline constexpr std::uint32_t MAXIMUM_SALT_BYTE_SIZE = std::numeric_limits<std::uint32_t>::max();

		/* Minimum and maximum key length in bytes */
		//Bytes (0 ~ power(2,32)-1) Optional key (Errata: PDF says 0..32 bytes, RFC says power(2,32) bytes)
		inline constexpr std::uint32_t MINIMUM_OPTIONAL_KEY_BYTE_SIZE = 0;
		//Bytes (0 ~ power(2,32)-1) Optional key (Errata: PDF says 0..32 bytes, RFC says power(2,32) bytes)
        inline constexpr std::uint32_t MAXIMUM_OPTIONAL_KEY_BYTE_SIZE = std::numeric_limits<std::uint32_t>::max();
			
		/* Minimum and maximum associated data length in bytes */
		//Bytes (0 ~ power(2,32)-1) Optional arbitrary extra data
		inline constexpr std::uint32_t MINIMUM_OPTIONAL_EXTRA_DATA_BYTE_SIZE = 0;
		//Bytes (0 ~ power(2,32)-1) Optional key (Errata: PDF says 0..32 bytes, RFC says power(2,32) bytes)
        inline constexpr std::uint32_t MAXIMUM_OPTIONAL_EXTRA_DATA_BYTE_SIZE = std::numeric_limits<std::int32_t>::max();

		/*************************Argon2 internal module constants**************************************************/

		/* Memory block size in bytes */
		inline constexpr std::uint32_t BYTES_MEMORY_BLOCK_SIZE = 1024;

		/* Memory block size in words */
		inline constexpr std::uint32_t WORDS_MEMORY_BLOCK_SIZE = BYTES_MEMORY_BLOCK_SIZE / sizeof(std::uint64_t);

		/* Memory block size in quad words */
		inline constexpr std::uint32_t QUAD_WORDS_MEMORY_BLOCK_SIZE = WORDS_MEMORY_BLOCK_SIZE / 2;

		/* Number of pseudo-random values generated by one call to Blake2 Hasher in Argon2i hash mode to generate reference block positions */
		inline constexpr std::uint32_t BLOCK_ADDRESS_COUNT = ( BYTES_MEMORY_BLOCK_SIZE * sizeof(std::uint8_t) / sizeof(std::uint64_t));

		/* Pre-hashing digest length and its extension*/
		inline constexpr std::uint32_t PRE_HASHING_DIGEST_SIZE = 64;
		inline constexpr std::uint32_t PRE_HASHING_SEED_SIZE = PRE_HASHING_DIGEST_SIZE + 8;

		/*****SM-related constants******/
		inline constexpr std::uint32_t SBOX_SIZE = 1 << 10;
		inline constexpr std::uint32_t SBOX_MASK = SBOX_SIZE / 2 - 1;

		namespace Default
		{
			inline constexpr std::uint32_t GENERATE_HASHED_DIGEST_BYTE_SIZE = 32;
			inline constexpr std::uint32_t MEMORY_BLOCK_EXECUTE_ITERATIONS_TIME_COUNT = 3;
			inline constexpr std::uint32_t LOG_MEMORY_BLOCK_KILOBYTE_SPACE_COUNT = 12;
			inline constexpr std::uint32_t MEMORY_BLOCK_PARALLELISM_LANES_SIZE = 1;
			inline constexpr std::uint32_t ALGORITHM_VERSION_NUMBER = static_cast<std::uint32_t>(0x13);
			inline constexpr HashModeType HASH_WORK_MODE = HashModeType::IndependentAddressing;
		}
	}

	/*
		****************************************************************************************************
		Context: structure to hold Argon2 inputs: 
		output array and its length, 
		password and its length,
		salt and its length,
		secret and its length,
		associated data and its length,
		number of passes, amount of used memory (in KBytes, can be rounded up a bit)
		number of parallel threads that will be run.
		All the parameters above affect the output hash value.
		Additionally, two function pointers can be provided to allocate and deallocate the memory (if is null-pointer, memory will be allocated internally).
		Also, three flags indicate whether to erase password, secret as soon as they are pre-hashed (and thus not needed anymore), and the entire memory
		****************************************************************************************************
			 
		Simplest situation: you have output array out[8], password is stored in password[32], salt is stored in salt[16], you do not have keys nor associated data.
		You need to spend 1 GB of RAM and you run 5 passes of Argon2d with 4 parallel lanes.
		You want to erase the password, but you're OK with last pass not being erased.
		You want to use the default memory allocator.
		Then you initialize
		Argon2_Context(out,8,pwd,32,salt,16,NULL,0,NULL,0,5,1<<20,4,NULL,NULL,true,false,false).
	*/
	struct Argon2_Parameters
	{
		//Generate hashed byte data array
		//生成哈希的字节数据数组
		std::vector<std::uint8_t> _generate_hashed_digest_bytes_;
		//Generate hashed byte data array size
		//生成哈希的字节数据数组的大小
		std::uint32_t _generate_hashed_digest_bytes_size_;

		//Message byte data array or password byte data array
		//信息字节数据数组或密码字节数据数组
		std::vector<std::uint8_t> _message_or_password_bytes_;
		//Message byte data array size or password byte data array size
		//信息字节数据数组大小或密码字节数据数组的大小
		std::uint32_t _message_or_password_bytes_size_ = _message_or_password_bytes_.size();
		
		//Salt disorderly byte data array
		//盐的无序字节数据数组
		std::vector<std::uint8_t> _salt_disorderly_bytes_;
		//Salt disorderly byte data array size
		//盐的无序字节数据数组的大小
		std::uint32_t _salt_disorderly_bytes_size_ = _salt_disorderly_bytes_.size();

		//Secret key byte data array
		//秘密钥匙的字节数据数组
		std::vector<std::uint8_t> _process_secret_key_bytes_;
		//Secret key byte data array size
		//秘密钥匙的字节数据数组的大小
		std::uint32_t _process_secret_key_bytes_size_ = _process_secret_key_bytes_.size();

		//Associated byte data array or extra byte data array
		//相关的字节数据数组或额外的字节数据数组
		std::vector<std::uint8_t> _process_extra_data_bytes_;
		//Associated byte data array size or extra byte data array size
		//相关的字节数据数组或额外的字节数据数组的大小
		std::uint32_t _process_extra_data_bytes_size_ = _process_extra_data_bytes_.size();

		/*
			Number of execute iteration or passes time cost
			执行迭代次数或通过时间成本
		*/
		std::uint32_t _requested_execute_iteration_time_cost_;
		/*
			Number of requestedmemory (Unit: KiloByte) data space cost
			要求的内存数量（单位：KiloByte）数据空间成本
		*/
		std::uint32_t _requested_memory_block_space_cost_;
		/*
			Number of Lanes and Rows(Maximum Parallelism Block Count)
			车道数和行数（最大平行度块数）
		*/
		std::uint32_t _parallelism_lanes_and_rows_number_;
		/*
			Number of Lane threads and Row threads(Actual Maximum Parallelism Block Count)
			If _actual_parallelism_threads_ > _parallelism_lanes_and_rows_number_, no error is reported, just unnecessary threads are not created.

			车道线程和行线程的数量（实际最大平行度块数）。
			如果_actual_parallelism_threads_>_parallelism_lanes_and_rows_number_，则不会报告错误，只是不创建不必要的线程。
		*/
		std::uint32_t _actual_thread_parallelism_lanes_and_rows_number_;

		//Whether to automatically clear the password array?
		//是否自动清除密码数组?
		const bool _clear_message_password_;

		//Whether to automatically clear the secret key array?
		//是否自动清除秘密钥匙数组?
		const bool _clear_secret_key_;

		//Whether to automatically clear the salt bytes array?
		//是否自动清除盐的字节数组?
		const bool _clear_salt_bytes_;

		//Whether to automatically clear the extra bytes array?
		//是否自动清除额外的字节数组
		const bool _clear_extra_bytes_; 

		//Whether to automatically clear the memory after the run?
		//运行后是否自动清除内存
		//const bool _clear_memory_; 

		const AlgorithmVersion _algorithm_version_;
		const HashModeTypeStringAlphabetFormat _hash_mode_type_string_alphabet_;
		const HashModeType _hash_mode_type_;
		const std::string _hash_mode_type_string_ = GetHashModeTypeString(_hash_mode_type_, _hash_mode_type_string_alphabet_);

		void SetSecretKeyByteData(const std::vector<std::uint8_t>& process_secret_key_bytes)
		{
			this->_process_secret_key_bytes_ = process_secret_key_bytes;
			this->_process_secret_key_bytes_size_ = process_secret_key_bytes.size();
		}

		void SetExtraByteData(const std::vector<std::uint8_t>& process_extra_data_bytes)
		{
			this->_process_extra_data_bytes_ = process_extra_data_bytes;
			this->_process_extra_data_bytes_size_ = process_extra_data_bytes.size();
		}

		explicit Argon2_Parameters( const Argon2_Parameters& other_argon2_parameter ) noexcept
			: _generate_hashed_digest_bytes_(other_argon2_parameter._generate_hashed_digest_bytes_),
			_generate_hashed_digest_bytes_size_(other_argon2_parameter._generate_hashed_digest_bytes_size_),
			_message_or_password_bytes_(other_argon2_parameter._message_or_password_bytes_),
			_salt_disorderly_bytes_(other_argon2_parameter._salt_disorderly_bytes_),
			_process_secret_key_bytes_(other_argon2_parameter._process_secret_key_bytes_),
			_process_extra_data_bytes_(other_argon2_parameter._process_extra_data_bytes_),
			_requested_execute_iteration_time_cost_(other_argon2_parameter._requested_execute_iteration_time_cost_),
			_requested_memory_block_space_cost_(other_argon2_parameter._requested_memory_block_space_cost_),
			_parallelism_lanes_and_rows_number_(other_argon2_parameter._parallelism_lanes_and_rows_number_),
			_actual_thread_parallelism_lanes_and_rows_number_(other_argon2_parameter._actual_thread_parallelism_lanes_and_rows_number_),
			_clear_message_password_(other_argon2_parameter._clear_message_password_),
			_clear_secret_key_(other_argon2_parameter._clear_secret_key_),
			_clear_salt_bytes_(other_argon2_parameter._clear_salt_bytes_),
			_clear_extra_bytes_(other_argon2_parameter._clear_extra_bytes_),
			//_clear_memory_(other_argon2_parameter._clear_memory_),
			_hash_mode_type_string_alphabet_(other_argon2_parameter._hash_mode_type_string_alphabet_),
			_algorithm_version_(other_argon2_parameter._algorithm_version_),
			_hash_mode_type_(other_argon2_parameter._hash_mode_type_)
		{
			
		}

		explicit Argon2_Parameters( Argon2_Parameters&& other_argon2_parameter ) noexcept
			: _generate_hashed_digest_bytes_(std::move(other_argon2_parameter._generate_hashed_digest_bytes_)),
			_generate_hashed_digest_bytes_size_(std::move(other_argon2_parameter._generate_hashed_digest_bytes_size_)),
			_message_or_password_bytes_(std::move(other_argon2_parameter._message_or_password_bytes_)),
			_salt_disorderly_bytes_(std::move(other_argon2_parameter._salt_disorderly_bytes_)),
			_process_secret_key_bytes_(std::move(other_argon2_parameter._process_secret_key_bytes_)),
			_process_extra_data_bytes_(std::move(other_argon2_parameter._process_extra_data_bytes_)),
			_requested_execute_iteration_time_cost_(std::move(other_argon2_parameter._requested_execute_iteration_time_cost_)),
			_requested_memory_block_space_cost_(std::move(other_argon2_parameter._requested_memory_block_space_cost_)),
			_parallelism_lanes_and_rows_number_(std::move(other_argon2_parameter._parallelism_lanes_and_rows_number_)),
			_actual_thread_parallelism_lanes_and_rows_number_(std::move(other_argon2_parameter._actual_thread_parallelism_lanes_and_rows_number_)),
			_clear_message_password_(std::move(other_argon2_parameter._clear_message_password_)),
			_clear_secret_key_(std::move(other_argon2_parameter._clear_secret_key_)),
			_clear_salt_bytes_(std::move(other_argon2_parameter._clear_salt_bytes_)),
			_clear_extra_bytes_(std::move(other_argon2_parameter._clear_extra_bytes_)),
			//_clear_memory_(std::move(other_argon2_parameter._clear_memory_)),
			_hash_mode_type_string_alphabet_(std::move(other_argon2_parameter._hash_mode_type_string_alphabet_)),
			_algorithm_version_(std::move(other_argon2_parameter._algorithm_version_)),
			_hash_mode_type_(std::move(other_argon2_parameter._hash_mode_type_))
		{
			
		}

		Argon2_Parameters& operator=(Argon2_Parameters&& other_argon2_parameter ) noexcept
		{
			/*
				this->_generate_hashed_digest_bytes_ = std::move(other_argon2_parameter._generate_hashed_digest_bytes_);
				this->_generate_hashed_digest_bytes_size_ = std::move(other_argon2_parameter._generate_hashed_digest_bytes_size_);
				this->_message_or_password_bytes_ = std::move(other_argon2_parameter._message_or_password_bytes_);
				this->_salt_disorderly_bytes_ = std::move(other_argon2_parameter._salt_disorderly_bytes_);
				this->_process_secret_key_bytes_ = std::move(other_argon2_parameter._process_secret_key_bytes_);
				this->_process_extra_data_bytes_ = std::move(other_argon2_parameter._process_extra_data_bytes_);
				this->_requested_execute_iteration_time_cost_ = std::move(other_argon2_parameter._requested_execute_iteration_time_cost_);
				this->_requested_memory_block_space_cost_ = std::move(other_argon2_parameter._requested_memory_block_space_cost_);
				this->_parallelism_lanes_and_rows_number_ = std::move(other_argon2_parameter._parallelism_lanes_and_rows_number_);
				this->_actual_thread_parallelism_lanes_and_rows_number_ = std::move(other_argon2_parameter._actual_thread_parallelism_lanes_and_rows_number_);
				this->_clear_message_password_ = std::move(other_argon2_parameter._clear_message_password_);
				this->_clear_secret_key_ = std::move(other_argon2_parameter._clear_secret_key_);
				this->_clear_salt_bytes_ = std::move(other_argon2_parameter._clear_salt_bytes_);
				this->_clear_extra_bytes_ = std::move(other_argon2_parameter._clear_extra_bytes_);
				//_clear_memory_ = std::move(other_argon2_parameter._clear_memory_);
				this->_hash_mode_type_string_alphabet_ = std::move(other_argon2_parameter._hash_mode_type_string_alphabet_); 
				this->_algorithm_version_ = std::move(other_argon2_parameter._algorithm_version_);
				this->_hash_mode_type_ = std::move(other_argon2_parameter._hash_mode_type_);
			*/

			//Do not move from ourselves or all hell will break loose
			//不要离开我们自己，否则大祸临头。
			if(this == &other_argon2_parameter)
				return *this;

			//Call our own destructor to clean up the class object before moving it
			//在移动类对象之前，调用我们自己的析构器来清理它
			std::destroy_at(this);

			//Moving class objects from calling our own copy constructor or move constructor
			//从调用我们自己的复制构造函数或移动构造函数来移动类对象
			std::construct_at(this, other_argon2_parameter);

			return *this;
		}

		Argon2_Parameters
		(
			const std::vector<std::uint8_t>& generate_hashed_digest_bytes,
			const std::uint32_t& generate_hashed_digest_bytes_size,
			const std::vector<std::uint8_t>& message_or_password_bytes,
			const std::vector<std::uint8_t>& salt_disorderly_bytes,
			const std::uint32_t& actual_thread_parallelism_lanes_and_rows_number,
			bool clear_message_password,
			bool clear_secret_key,
			bool clear_salt_bytes,
			bool clear_extra_bytes
		)
			:
			_generate_hashed_digest_bytes_(generate_hashed_digest_bytes),
			_generate_hashed_digest_bytes_size_(Constants::Default::GENERATE_HASHED_DIGEST_BYTE_SIZE),
			_message_or_password_bytes_(message_or_password_bytes),
			_salt_disorderly_bytes_(salt_disorderly_bytes),
			_requested_execute_iteration_time_cost_(Constants::Default::MEMORY_BLOCK_EXECUTE_ITERATIONS_TIME_COUNT),
			_requested_memory_block_space_cost_(1 << Constants::Default::LOG_MEMORY_BLOCK_KILOBYTE_SPACE_COUNT),
			_parallelism_lanes_and_rows_number_(Constants::Default::MEMORY_BLOCK_PARALLELISM_LANES_SIZE),
			_actual_thread_parallelism_lanes_and_rows_number_(actual_thread_parallelism_lanes_and_rows_number == 0 ? _parallelism_lanes_and_rows_number_ : actual_thread_parallelism_lanes_and_rows_number),
			_clear_message_password_(clear_message_password),
			_clear_secret_key_(clear_secret_key),
			_clear_salt_bytes_(clear_salt_bytes),
			_clear_extra_bytes_(clear_extra_bytes),
			_hash_mode_type_string_alphabet_(HashModeTypeStringAlphabetFormat::UPPER_CASE),
			_algorithm_version_(static_cast<AlgorithmVersion>(Constants::Default::ALGORITHM_VERSION_NUMBER)),
			_hash_mode_type_(Constants::Default::HASH_WORK_MODE)
		{
			
		}

		Argon2_Parameters
		(
			const std::vector<std::uint8_t>& generate_hashed_digest_bytes,
			const std::uint32_t& generate_hashed_digest_bytes_size,
			const std::vector<std::uint8_t>& message_or_password_bytes,
			const std::vector<std::uint8_t>& salt_disorderly_bytes,
			const std::uint32_t& requested_execute_iteration_time_cost,
			const std::uint32_t& requested_memory_block_space_cost,
			const std::uint32_t& parallelism_lanes_and_rows_number,
			const std::uint32_t& actual_thread_parallelism_lanes_and_rows_number,
			bool clear_message_password,
			bool clear_secret_key,
			bool clear_salt_bytes,
			bool clear_extra_bytes,
			HashModeTypeStringAlphabetFormat hash_mode_type_string_alphabet,
			AlgorithmVersion algorithm_version_number,
			HashModeType hash_mode_type
		)
			:
			_generate_hashed_digest_bytes_(generate_hashed_digest_bytes),
			_generate_hashed_digest_bytes_size_(generate_hashed_digest_bytes_size),
			_message_or_password_bytes_(message_or_password_bytes),
			_salt_disorderly_bytes_(salt_disorderly_bytes),
			_requested_execute_iteration_time_cost_(requested_execute_iteration_time_cost),
			_requested_memory_block_space_cost_(requested_memory_block_space_cost),
			_parallelism_lanes_and_rows_number_(parallelism_lanes_and_rows_number == 0 ? Constants::Default::MEMORY_BLOCK_PARALLELISM_LANES_SIZE : parallelism_lanes_and_rows_number),
			_actual_thread_parallelism_lanes_and_rows_number_(actual_thread_parallelism_lanes_and_rows_number == 0 ? parallelism_lanes_and_rows_number : parallelism_lanes_and_rows_number),
			_clear_message_password_(clear_message_password),
			_clear_secret_key_(clear_secret_key),
			_clear_salt_bytes_(clear_salt_bytes),
			_clear_extra_bytes_(clear_extra_bytes),
			_hash_mode_type_string_alphabet_(hash_mode_type_string_alphabet),
			_algorithm_version_(algorithm_version_number),
			_hash_mode_type_(hash_mode_type)
		{
			
		}

		~Argon2_Parameters() = default;
	};

	namespace Core
	{
		namespace Modules
		{
			class Argon2_RuntimeInstance;

			namespace Functions
			{
				/*
					H' <-> Variable-length(size) hash function (Blake2 64bit Long)
					Argon2 makes use of a hash function capable of producing digests up to std::power(2,32) bytes long. 
					This hash function is internally built upon Blake2 algorithm.

					H'<->可变长度（大小）哈希函数（Blake2 64位长）。

					Argon2使用了一个哈希函数，能够产生长达std::power(2,32)字节的摘要。
					这个哈希函数在内部建立在Blake2算法之上。

					//CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Extension>( std::numeric_limits<std::uint8_t>::digits * digest_byte_size );
				*/
				inline std::optional<std::vector<std::uint8_t>> SpecializedHash
				(
					const std::vector<std::uint8_t>& message_or_password_bytes,
					std::uint32_t digest_byte_size
				)
				{
					using CommonToolkit::MessagePacking;
					using CommonToolkit::MessageUnpacking;
					
					//message: Bytes (0 ~ power(2,32)-1) Message to be hashed
					if( message_or_password_bytes.size() == 0 || message_or_password_bytes.size() > std::numeric_limits<std::uint32_t>::max() )
					{
						return std::nullopt;
					}

					//digestSize: Integer (0 ~ power(2,32)-1) Desired number of bytes to be returned
					if( digest_byte_size == 0 || digest_byte_size > std::numeric_limits<std::uint32_t>::max() )
					{
						return std::nullopt;
					}

					constexpr std::size_t blake2_64bit_hash_bytesize = 64;
					std::vector<std::uint8_t> digest_byte_size_data = MessageUnpacking<std::uint32_t, std::uint8_t>(&(digest_byte_size), 1);

					auto lambda_Blake64Bit = [](const std::vector<std::uint8_t>& input_bytes, const std::vector<std::uint8_t>& output_size_bytes, const std::size_t& output_size) -> std::vector<std::uint8_t>
					{
						/*
							Note! Maybe this modification, will make the module broken.
							注意！也许这个修改，会让模块坏掉。
							
							//Backup source code segments:
							//备份源代码段
							auto Hasher_Blake2OrdinaryMode = CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>( std::numeric_limits<std::uint8_t>::digits * output_size );
						*/
						
						constexpr std::size_t HASH_BIT_SIZE = CURRENT_SYSTEM_BITS == 64 ? std::numeric_limits<std::uint8_t>::digits * Constants::PRE_HASHING_DIGEST_SIZE : (std::numeric_limits<std::uint8_t>::digits * Constants::PRE_HASHING_DIGEST_SIZE) / 2;
						auto Hasher_Blake2OrdinaryMode = CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary>( HASH_BIT_SIZE );				
						
						Hasher_Blake2OrdinaryMode.StepInitialize();

						if(!output_size_bytes.empty())
							Hasher_Blake2OrdinaryMode.StepUpdate(output_size_bytes);

						Hasher_Blake2OrdinaryMode.StepUpdate(input_bytes);

						std::vector<std::uint8_t> hashed_digest(output_size, 0);
						Hasher_Blake2OrdinaryMode.StepFinal(hashed_digest);

						return hashed_digest;
					};

					//If the requested digestSize is 64-bytes or lower, then we use Blake2b directly
					//如果请求的digestSize是64字节或更低，那么我们直接使用Blake2b
					if(digest_byte_size <= blake2_64bit_hash_bytesize)
					{
						return lambda_Blake64Bit(message_or_password_bytes, digest_byte_size_data, digest_byte_size);
					}
					else
					{
						//Else for desired hashes over 64-bytes (e.g. 1024 bytes for Argon2 blocks),
						//we use Blake2b to generate twice the number of needed 64-byte blocks,
						//and then only use 32-bytes from each block
						//否则，对于所需的超过64字节的哈希值（例如Argon2块的1024字节）。
						//我们使用Blake2b来生成两倍于所需64字节的块。
						//然后只使用每个块中的32字节

						//Calculate the number of whole blocks (knowing we're only going to use 32-bytes from each)
						//计算整个区块的数量（知道我们将只使用每个区块的32字节）。

						std::vector<std::uint8_t> current_work_hashed_vector(digest_byte_size, 0);

						/* Vector round 1 */
						//Initial block is generated from message
						//初始块是由信息生成的
						std::vector<std::uint8_t> temporary_hashed_digest;

						temporary_hashed_digest = lambda_Blake64Bit(message_or_password_bytes, digest_byte_size_data, blake2_64bit_hash_bytesize);
						std::ranges::copy_n(temporary_hashed_digest.begin(), blake2_64bit_hash_bytesize / 2, current_work_hashed_vector.begin());

						digest_byte_size_data.clear();
						digest_byte_size_data.shrink_to_fit();
						
						std::size_t block_rounds_number = ( digest_byte_size / 32 ) + ( (digest_byte_size % 32 == 0) ? 0 : 1 ) - 2;

						/* Vector round 2 ~ Vector N round */
						//Subsequent blocks are generated from previous blocks
						//后面的区块是由前面的区块生成的
						std::size_t block_position = blake2_64bit_hash_bytesize / 2;
						for( std::size_t index = 2; index <= block_rounds_number; ++index, block_position += blake2_64bit_hash_bytesize / 2)
						{
							temporary_hashed_digest = lambda_Blake64Bit(temporary_hashed_digest, digest_byte_size_data, blake2_64bit_hash_bytesize);
							std::ranges::copy_n(temporary_hashed_digest.begin(), blake2_64bit_hash_bytesize / 2, current_work_hashed_vector.begin() + block_position);
						}

						/* Vector N round +1 */
						//Generate the final (possibly partial) block
						//生成最后的（可能是部分）区块
						std::size_t partial_bytes_needed = digest_byte_size - 32 * block_rounds_number;
						temporary_hashed_digest = lambda_Blake64Bit(temporary_hashed_digest, digest_byte_size_data, partial_bytes_needed);
						std::ranges::copy_n(temporary_hashed_digest.begin(), partial_bytes_needed, current_work_hashed_vector.begin() + block_position);

						return current_work_hashed_vector;
					}
				}


				/*
					Generate initial 64-byte block Hash_Block0.
					All the input parameters are concatenated and input as a source of additional entropy.
					Errata: RFC says H0 is 64-bits; PDF says H0 is 64-bytes.
					Errata: RFC says the Hash is H^, the PDF says it's ℋ (but doesn't document what ℋ is). It's actually Blake2b.
					Variable length items are prepended with their length as 32-bit little-endian integers.

					生成初始64字节的块Hash_Block0。
					所有的输入参数被串联起来，作为额外熵的来源输入。
					勘误表。RFC说H0是64位；PDF说H0是64字节。
					勘误表。RFC说Hash是H^，PDF说它是ℋ（但没有记录ℋ是什么）。它实际上是Blake2b。
					可变长度的项目是以32位小-endian整数的形式预置其长度。

					password (P):       Bytes
					salt (S):           Bytes
					parallelism (p):    Number
					tagLength (T):      Number
					memorySizeKB (m):   Number 
					iterations (t):     Number
					version (v):        Number
					key (K):            Bytes
					associatedData (X): Bytes
					hashType (y):       Number (0=Argon2d, 1=Argon2i, 2=Argon2id, 4=Argon2ds)

					H0 = H(p, τ, m, t, v, y, size(P), P, size(S), S, size(K), K, size(X), X).

					const std::vector<std::uint8_t>& lanes_and_rows_number_bytes,
					const std::vector<std::uint8_t>& generate_hashed_digest_size_bytes,
					const std::vector<std::uint8_t>& reserve_memory_block_kilobyte_size_bytes,
					const std::vector<std::uint8_t>& execute_iteration_number_bytes,
					const std::vector<std::uint8_t>& algorithm_version_number_bytes,
					const std::vector<std::uint8_t>& algorithm_mode_type_number_bytes,

					const std::vector<std::uint8_t>& message_or_password_size_bytes,
					const std::vector<std::uint8_t>& message_or_password_bytes,
					const std::vector<std::uint8_t>& salt_disorderly_size_bytes,
					const std::vector<std::uint8_t>& salt_disorderly_bytes,
					const std::vector<std::uint8_t>& optional_process_secret_key_size_bytes,
					const std::vector<std::uint8_t>& optional_process_secret_key_bytes,
					const std::vector<std::uint8_t>& optional_extra_data_size_bytes,
					const std::vector<std::uint8_t>& optional_extra_data_bytes
				*/
				inline std::vector<std::uint8_t> GenerateHashedByte0(Argon2_Parameters& argon2_parameters_context)
				{
					using CommonToolkit::MessagePacking;
					using CommonToolkit::MessageUnpacking;

					auto parallelism_block_lanes_and_rows_number_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(argon2_parameters_context._parallelism_lanes_and_rows_number_), 1);
					auto generate_hashed_digest_size_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(argon2_parameters_context._generate_hashed_digest_bytes_size_), 1);
					
					auto requested_memory_block_space_cost_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(argon2_parameters_context._requested_memory_block_space_cost_), 1);
					auto requested_execute_iteration_time_cost_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(argon2_parameters_context._requested_execute_iteration_time_cost_), 1);
					
					std::uint32_t algorithm_version_number = static_cast<std::uint32_t>(argon2_parameters_context._algorithm_version_);
					auto algorithm_version_number_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(algorithm_version_number), 1);
					
					auto message_or_password_size_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(argon2_parameters_context._message_or_password_bytes_size_), 1);
					auto salt_disorderly_size_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(argon2_parameters_context._salt_disorderly_bytes_size_), 1);
					auto optional_process_secret_key_size_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(argon2_parameters_context._process_secret_key_bytes_size_), 1);
					auto optional_extra_data_size_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(argon2_parameters_context._process_extra_data_bytes_size_), 1);

					auto algorithm_hash_mode_type = static_cast<std::uint32_t>(argon2_parameters_context._hash_mode_type_);
					auto algorithm_mode_type_number_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(algorithm_hash_mode_type), 1);

					/*
						Note! Maybe this modification, will make the module broken.
						注意！也许这个修改，会让模块坏掉。
							
						//Backup source code segments:
						//备份源代码段
						CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary> Hasher_Blake2OrdinaryMode( std::numeric_limits<std::uint8_t>::digits * Constants::PRE_HASHING_DIGEST_SIZE);
					*/
					
					constexpr std::size_t HASH_BIT_SIZE = CURRENT_SYSTEM_BITS == 64 ? std::numeric_limits<std::uint8_t>::digits * Constants::PRE_HASHING_DIGEST_SIZE : (std::numeric_limits<std::uint8_t>::digits * Constants::PRE_HASHING_DIGEST_SIZE) / 2;
					CommonSecurity::Blake2::HashProvider<CommonSecurity::Blake2::Core::HashModeType::Ordinary> Hasher_Blake2OrdinaryMode( HASH_BIT_SIZE );
					
					Hasher_Blake2OrdinaryMode.StepInitialize();

					Hasher_Blake2OrdinaryMode.StepUpdate(parallelism_block_lanes_and_rows_number_bytes);
					Hasher_Blake2OrdinaryMode.StepUpdate(generate_hashed_digest_size_bytes);
					Hasher_Blake2OrdinaryMode.StepUpdate(requested_memory_block_space_cost_bytes);
					Hasher_Blake2OrdinaryMode.StepUpdate(requested_execute_iteration_time_cost_bytes);
					Hasher_Blake2OrdinaryMode.StepUpdate(algorithm_version_number_bytes);
					Hasher_Blake2OrdinaryMode.StepUpdate(algorithm_mode_type_number_bytes);

					Hasher_Blake2OrdinaryMode.StepUpdate(message_or_password_size_bytes);
					if(!argon2_parameters_context._message_or_password_bytes_.empty())
					{
						Hasher_Blake2OrdinaryMode.StepUpdate(argon2_parameters_context._message_or_password_bytes_);
						if(argon2_parameters_context._clear_message_password_)
						{
							argon2_parameters_context._message_or_password_bytes_.clear();
							argon2_parameters_context._message_or_password_bytes_.shrink_to_fit();
						}
					}

					Hasher_Blake2OrdinaryMode.StepUpdate(salt_disorderly_size_bytes);
					if(!argon2_parameters_context._salt_disorderly_bytes_.empty())
					{
						Hasher_Blake2OrdinaryMode.StepUpdate(argon2_parameters_context._salt_disorderly_bytes_);
						if(argon2_parameters_context._clear_salt_bytes_)
						{
							argon2_parameters_context._salt_disorderly_bytes_.clear();
							argon2_parameters_context._salt_disorderly_bytes_.shrink_to_fit();
						}
					}

					Hasher_Blake2OrdinaryMode.StepUpdate(optional_process_secret_key_size_bytes);
					if(!argon2_parameters_context._process_secret_key_bytes_.empty())
					{
						Hasher_Blake2OrdinaryMode.StepUpdate(argon2_parameters_context._process_secret_key_bytes_);
						if(argon2_parameters_context._clear_secret_key_)
						{
							argon2_parameters_context._process_secret_key_bytes_.clear();
							argon2_parameters_context._process_secret_key_bytes_.shrink_to_fit();
						}
					}

					Hasher_Blake2OrdinaryMode.StepUpdate(optional_extra_data_size_bytes);
					if(!argon2_parameters_context._process_extra_data_bytes_.empty())
					{
						Hasher_Blake2OrdinaryMode.StepUpdate(argon2_parameters_context._process_extra_data_bytes_);
						if(argon2_parameters_context._clear_extra_bytes_)
						{
							argon2_parameters_context._process_extra_data_bytes_.clear();
							argon2_parameters_context._process_extra_data_bytes_.shrink_to_fit();
						}
					}

					std::vector<std::uint8_t> GenerateHashedByte0(64, 0);
					Hasher_Blake2OrdinaryMode.StepFinal(GenerateHashedByte0);

					return GenerateHashedByte0;
				}

				/*
					Algorithm function Designed by Argon2 Team
					算法函数由Argon2团队设计
				*/
				inline std::uint64_t BlaMkaFunction(const std::uint64_t& ValueX, const std::uint64_t& ValueY)
				{
					const std::uint64_t ValueM = static_cast<std::uint64_t>( std::numeric_limits<std::uint32_t>::max() );
					const std::uint64_t ValueXY = ( ValueX & ValueM ) * ( ValueY & ValueM );
					return ValueX + ValueY + 2 * ValueXY;
				}

				/*
					
					Details of GB:
					GB(a, b, c, d) is defined as follows:
					GB的细节:
					GB(a, b, c, d)定义如下:

						a = (a + b + 2 * trunc(a) * trunc(b)) mod pow(2,32)
						d = (d XOR a) >>> 32
						c = (c + d + 2 * trunc(c) * trunc(d)) mod pow(2,32)
						b = (b XOR c) >>> 24

						a = (a + b + 2 * trunc(a) * trunc(b)) mod pow(2,32)
						d = (d XOR a) >>> 16
						c = (c + d + 2 * trunc(c) * trunc(d)) mod pow(2,32)
						b = (b XOR c) >>> 63

					The modular additions in GB are combined with 64-bit multiplications.
					Multiplications are the only difference from the original BLAKE2b design.
					This choice is done to increase the circuit depth and thus the running time of ASIC implementations, while having roughly the same running time on CPUs thanks to parallelism and pipelining.
					GB中的模块化加法与64位乘法相结合。
					乘法是与原始BLAKE2b设计的唯一区别。
					这样的选择是为了增加电路深度，从而增加ASIC实现的运行时间，同时由于并行和流水线，在CPU上有大致相同的运行时间。
				*/
				inline void HashValueMixer( std::uint64_t& ValueA, std::uint64_t& ValueB, std::uint64_t& ValueC, std::uint64_t& ValueD)
				{
					ValueA = BlaMkaFunction(ValueA, ValueB);
					ValueD = CommonSecurity::Binary_RightRotateMove<std::uint64_t>(ValueD ^ ValueA, 32);
					ValueC = BlaMkaFunction(ValueC, ValueD);
					ValueB = CommonSecurity::Binary_RightRotateMove<std::uint64_t>(ValueB ^ ValueC, 24);

					ValueA = BlaMkaFunction(ValueA, ValueB);
					ValueD = CommonSecurity::Binary_RightRotateMove<std::uint64_t>(ValueD ^ ValueA, 16);
					ValueC = BlaMkaFunction(ValueC, ValueD);
					ValueB = CommonSecurity::Binary_RightRotateMove<std::uint64_t>(ValueB ^ ValueC, 63);
				}

				/*
					Permutation P is based on the round function of BLAKE2b. (This version of the hash wheel function, designed by the Agron2 team, is based on the BlaMka function.)
					The eight 16-byte inputs S_0, S_1, ... , S_7 are viewed as a 4x4 matrix of 64-bit words, where S_i = (v_{2*i+1} || v_{2*i}):
					Permutation P是基于BLAKE2b的轮函数。(这个版本的哈希轮函数是由Agron2团队设计的，基于BlaMka函数)
					8个16字节的输入S_0, S_1, .... S_7被看作是一个由64位字组成的4x4矩阵，其中S_i=（v_{2*i+1}||v_{2*i}）:

						Matrix Element Labeling:
						矩阵元素标记中:
							v_0  v_1  v_2  v_3
							v_4  v_5  v_6  v_7
							v_8  v_9 v_10 v_11
						   v_12 v_13 v_14 v_15

						Feeding Matrix Elements to GB:
						向GB输送矩阵元素:
						   It works as follows:
						   它的工作原理如下:

						   GB(v_0, v_4,  v_8, v_12)
						   GB(v_1, v_5,  v_9, v_13)
						   GB(v_2, v_6, v_10, v_14)
						   GB(v_3, v_7, v_11, v_15)

						   GB(v_0, v_5, v_10, v_15)
						   GB(v_1, v_6, v_11, v_12)
						   GB(v_2, v_7,  v_8, v_13)
						   GB(v_3, v_4,  v_9, v_14)

				*/
				inline void HashValueRound(std::array<std::uint64_t, 16>& current_state_vector)
				{
					auto&
					[
						StateValue, StateValue2, StateValue3, StateValue4,
						StateValue5, StateValue6, StateValue7, StateValue8,
						StateValue9, StateValue10, StateValue11, StateValue12,
						StateValue13, StateValue14, StateValue15, StateValue16
					] = current_state_vector;

					HashValueMixer(StateValue, StateValue5, StateValue9, StateValue13);
					HashValueMixer(StateValue2, StateValue6, StateValue10, StateValue14);
					HashValueMixer(StateValue3, StateValue7, StateValue11, StateValue15);
					HashValueMixer(StateValue4, StateValue8, StateValue12, StateValue16);
					HashValueMixer(StateValue, StateValue6, StateValue11, StateValue16);
					HashValueMixer(StateValue2, StateValue7, StateValue12, StateValue13);
					HashValueMixer(StateValue3, StateValue8, StateValue9, StateValue14);
					HashValueMixer(StateValue4, StateValue5, StateValue10, StateValue15);
				}
			}

			/*
				Structure for the (1KB) memory block implemented as 128 64-bit words.
				Memory blocks can be copied, ExclusiveOR-ed.
				Internal words can be accessed by [] (no bounds checking).

				(1KB)内存块的结构以128个64位字实现。
				内存块可以被复制，ExclusiveOR-ed。
				内部字可以通过[]访问（没有边界检查）。
			 */
			class HashingDataBlock
			{
				
			private:
				/* 128 * 8 Byte quadword */
				std::array<std::uint64_t, Constants::WORDS_MEMORY_BLOCK_SIZE> work_vector {};

				friend HashingDataBlock operator^(const HashingDataBlock& blockA, const HashingDataBlock& blockB);

			public:

				//Processing each quad-word block (8 bytes = 64 bits) is actually a slice !!!!!!
				void FromBytes(const std::vector<std::uint8_t>& bytes_data)
				{
					using CommonToolkit::MessagePacking;
					using CommonToolkit::MessageUnpacking;

					std::span<const std::uint8_t> bytes_data_span { bytes_data.begin(), bytes_data.end() };
					MessagePacking( bytes_data_span, this->work_vector.data());
				}

				//Processing each quad-word block (8 bytes = 64 bits) is actually a slice !!!!!!
				void ToBytes(std::vector<std::uint8_t>& bytes_data)
				{
					using CommonToolkit::MessagePacking;
					using CommonToolkit::MessageUnpacking;

					std::span<const std::uint64_t> quad_words_data_span{ this->work_vector.begin(), this->work_vector.end() };
					MessageUnpacking( quad_words_data_span, bytes_data.data());
				}

				HashingDataBlock& operator=(const HashingDataBlock& other)
				{
					std::ranges::copy(other.work_vector.begin(), other.work_vector.end(), this->work_vector.begin());
					return *this;
				}

				std::uint64_t& operator[](const std::size_t& index)
				{
					return work_vector.operator[](index);
				}

				//Exclusive_OR Use Multi Block
				void ExclusiveOR_Multi(HashingDataBlock& blockA, const HashingDataBlock& blockB, const HashingDataBlock& blockC)
				{
					for(std::size_t count = 0; count < blockA.work_vector.size(); ++count)
					{
						this->work_vector[count] = blockA.work_vector[count] ^ blockB.work_vector[count] ^ blockC.work_vector[count];
					}
				}

				//Exclusive_OR With Other Work Vector
				HashingDataBlock& operator^=(HashingDataBlock& other)
				{
					for(std::size_t count = 0; count < Constants::WORDS_MEMORY_BLOCK_SIZE; ++count)
					{
						this->work_vector[count] ^= other.work_vector[count];
					}
					return *this;
				}

				std::array<std::uint64_t, Constants::WORDS_MEMORY_BLOCK_SIZE>& GetHashingDataBlock()
				{
					return this->work_vector;
				}

				void Clear()
				{
					memory_set_no_optimize_function_pointer(this->work_vector.data(), 0, Constants::BYTES_MEMORY_BLOCK_SIZE);
				}

				HashingDataBlock() = default;

				explicit HashingDataBlock(const std::uint8_t& fill_byte_data)
				{
					memory_set_no_optimize_function_pointer(this->work_vector.data(), fill_byte_data, Constants::BYTES_MEMORY_BLOCK_SIZE);
				}

				HashingDataBlock(const HashingDataBlock& other)
				{
					std::memmove(this->work_vector.data(), other.work_vector.data(), Constants::BYTES_MEMORY_BLOCK_SIZE);
				}

				~HashingDataBlock()
				{
					constexpr std::array<std::uint64_t, Constants::WORDS_MEMORY_BLOCK_SIZE> zero_work_vector {};
					if(this->work_vector != zero_work_vector)
						this->Clear();
				}
			};

			//Exclusive_OR By The Two Work Vector
			inline HashingDataBlock operator^(const HashingDataBlock& blockA, const HashingDataBlock& blockB)
			{
				HashingDataBlock temporary_hashing_data_block;
				for(std::size_t count = 0; count < blockA.work_vector.size(); ++count)
				{
					temporary_hashing_data_block.work_vector[count] = blockA.work_vector[count] ^ blockB.work_vector[count];
				}

				return temporary_hashing_data_block;
			}

			class Argon2_RuntimeInstance
			{

			private:
				std::unique_ptr<std::vector<HashingDataBlock>> _memory_blocks_instance_pointer_ = std::make_unique<std::vector<HashingDataBlock>>();
				
				std::uint32_t _algorithm_argon2_version_;

				/*
					Execute iteration time number of passes
					执行迭代时间 迭代次数
				*/
				const std::uint32_t _requested_execute_iteration_time_cost_;

				/*
					Number of memory actual requested (Unit: KiloByte) data space
					实际请求的内存数量（单位：KiloByte）数据空间
				*/
				const std::uint32_t _memory_blocks_count_;
				
				/*
					Number of Lanes and Rows(Maximum Parallelism Block Count)
					车道数和行数（最大平行度块数）
				*/
				std::uint32_t _parallelism_lanes_and_rows_number_;

				/*
					Number of Lane threads and Row threads(Actual Maximum Parallelism Block Count)
					If _actual_parallelism_threads_ > _parallelism_lanes_and_rows_number_, no error is reported, just unnecessary threads are not created.

					车道线程和行线程的数量(实际最大平行化块数)
					如果_actual_parallelism_threads_>_parallelism_lanes_and_rows_number_，则不会报告错误，只是不创建不必要的线程。
				*/
				std::uint32_t _actual_thread_parallelism_lanes_and_rows_number_;

				const AlgorithmVersion _algorithm_version_;

				const HashModeType _hash_mode_type_;

				//Value derived from _memory_blocks_count_ and _parallelism_lanes_and_rows_number_ --- just for cache and readability
				//从_memory_blocks_count_和_parallelism_lanes_and_rows_number_衍生出来的值 --- 只是为了缓存和可读性。
				const std::uint32_t _parallelism_lanes_and_rows_each_size_;
				//Value derived from _parallelism_block_lanes_and_rows_each_size_ and SYNC_POINTS --- just for cache and readability
				//从_parallelism_block_lanes_and_rows_each_size_和SYNC_POINTS得出的值 --- 只是为了缓存和可读性。
				const std::uint32_t _block_segment_size_;

				//Argon2 special work Mode <-> Argon2ds (Substitution box hardened) before it will be used
				//Argon2特殊工作模式<->Argon2ds（置换盒硬化）才会使用它
				std::unique_ptr<std::array<std::uint64_t, Constants::SBOX_SIZE>> _substitution_box_array_pointer_;

				void AllocateMemory(std::size_t block_count)
				{
					if(this->_substitution_box_array_pointer_ == nullptr && this->_hash_mode_type_ == HashModeType::SubstitutionBox)
					{
						//Allocate substitution-box memory
						//分配置换盒的内存
						this->_substitution_box_array_pointer_ = std::make_unique<std::array<std::uint64_t, Constants::SBOX_SIZE>>();
					}

					//Create each hash block to the memory matrix and then allocate memory for each of them
					//向内存矩阵中创建每一个哈希块，然后都分配内存
					for(std::size_t count = 0; count < block_count; ++count)
					{
						auto hashing_block_object = HashingDataBlock();
						_memory_blocks_instance_pointer_.get()->push_back(hashing_block_object);
					}
				}

				void DeallocateMemory()
				{
					if(this->_substitution_box_array_pointer_ != nullptr && this->_hash_mode_type_ == HashModeType::SubstitutionBox)
					{
						memory_set_no_optimize_function_pointer(this->_substitution_box_array_pointer_.get()->data(), 0, Constants::SBOX_SIZE);
						
						//Deallocate substitution-box memory
						//取消分配置换盒的内存
						this->_substitution_box_array_pointer_.reset();
					}

					std::vector<HashingDataBlock>& memory_instance_blocks = *(this->_memory_blocks_instance_pointer_.get());
					
					//Remove each hash block from the memory matrix and then all deallocate the memory
					//从内存矩阵中删除每一个哈希块，然后都取消分配内存
					for(HashingDataBlock& hashing_block_object : memory_instance_blocks )
					{
						hashing_block_object.~HashingDataBlock();
						memory_instance_blocks.pop_back();
					}

					memory_instance_blocks.shrink_to_fit();
					this->_memory_blocks_instance_pointer_.reset();
				}

			public:
				void ClearMemory()
				{
					std::vector<HashingDataBlock>& memory_instance_blocks = *(this->_memory_blocks_instance_pointer_.get());
					for(HashingDataBlock& hashing_block_object : memory_instance_blocks )
					{
						hashing_block_object.Clear();
					}
				}

				std::vector<HashingDataBlock>& GetMemoryBlocks()
				{
					std::vector<HashingDataBlock>& memory_instance_blocks = *(this->_memory_blocks_instance_pointer_.get());
					return memory_instance_blocks;
				}

				void SetThreadActualParallelismNumber_LanesAndRows(const std::uint32_t& value)
				{
					this->_actual_thread_parallelism_lanes_and_rows_number_ = value;
				}

				const std::uint32_t GetExecuteIterationTimeNumber() const
				{
					return this->_requested_execute_iteration_time_cost_;
				}

				const std::uint32_t GetBlockSegmentSize() const
				{
					return this->_block_segment_size_;
				}

				const std::uint32_t GetEachSizeOfParallelismNumber_LanesAndRows() const
				{
					return this->_parallelism_lanes_and_rows_each_size_;
				}

				std::uint32_t GetParallelismNumber_LanesAndRows() const
				{
					return this->_parallelism_lanes_and_rows_number_;
				}

				std::uint32_t GetActualThreadParallelismNumber_LanesAndRows() const
				{
					return this->_actual_thread_parallelism_lanes_and_rows_number_;
				}

				const std::uint32_t GetMemoryBlockCount() const
				{
					return this->_memory_blocks_count_;
				}

				const AlgorithmVersion& GetAlgorithmVersion() const
				{
					return this->_algorithm_version_;
				}

				const HashModeType& GetHashModeTypeEnum() const
				{
					return this->_hash_mode_type_;
				}

				auto GetSubstitutionBoxPointer() const
				{
					return this->_substitution_box_array_pointer_.get();
				}

				Argon2_RuntimeInstance() = delete;

				Argon2_RuntimeInstance(const Argon2_RuntimeInstance& _object) = delete;
				Argon2_RuntimeInstance& operator=(Argon2_RuntimeInstance& _object) = delete;

				explicit Argon2_RuntimeInstance
				(
					std::uint32_t execute_iteration_number,
					std::uint32_t memory_blocks_count,
					std::uint32_t block_segment_size,
					std::uint32_t parallelism_lanes_and_rows_number,
					std::uint32_t actual_thread_parallelism_lanes_and_rows_number,
					AlgorithmVersion algorithm_version,
					HashModeType hash_mode_type
				) 
					: _requested_execute_iteration_time_cost_(execute_iteration_number),
					_memory_blocks_count_(memory_blocks_count),
					_block_segment_size_(block_segment_size),
					_parallelism_lanes_and_rows_each_size_(block_segment_size * Constants::SYNC_POINTS),
					_parallelism_lanes_and_rows_number_(parallelism_lanes_and_rows_number),
					_actual_thread_parallelism_lanes_and_rows_number_(actual_thread_parallelism_lanes_and_rows_number),
					_algorithm_version_(algorithm_version),
					_hash_mode_type_(hash_mode_type),
					_substitution_box_array_pointer_(nullptr)
				{
					this->AllocateMemory(this->_memory_blocks_count_);
				}

				~Argon2_RuntimeInstance()
				{
					this->DeallocateMemory();
					this->_memory_blocks_instance_pointer_.reset();
				}
			};

			struct PositionByMemoryBlock
			{
				//Current passed iteration time
				//当前已经通过的迭代时间
				const uint32_t _pass_iteration_time_;

				//What is the current lane (row) of the memory matrix? (can be computed in parallel with multiple threads)
				//当前是内存矩阵的第几个车道(行)? (可以多线程的并行计算)
				const uint32_t _lane_and_row_;

				//What is the current slice (column) of the memory matrix? (Valid range is 0 ~ 3)
				//当前是内存矩阵的第几个切片(列)? (有效范围是 0 ~ 3)
				const uint8_t _slice_and_column_;

				//The index of the current segment is the position of the hash block in the current segment
				//当前段的index是当前段中的哈希块位置
				uint32_t _index_;

				PositionByMemoryBlock
				(
					std::uint32_t pass_time,
					std::uint32_t lane_and_row,
					std::uint8_t slice_and_column,
					std::uint32_t index
				) 
					: _pass_iteration_time_(pass_time),
					_lane_and_row_(lane_and_row),
					_slice_and_column_(slice_and_column),
					_index_(index)
				{
					
				}
			};


			namespace Operations
			{
				/*
					The compression function G is built upon the BLAKE2b-based transformation P.
					P operates on the 128-byte input, which can be viewed as eight 16-byte registers:
					压缩函数G是建立在基于BLAKE2b的变换P之上。
					P对128字节的输入进行操作，它可以被看作是8个16字节的寄存器。

									Blake2 Round Function P:
									Blake2轮函数P:
					P(A_0, A_1, ... ,A_7) = (B_0, B_1, ... ,B_7)
				*/
				inline void ForEachBlockHashRoundFunctions(HashingDataBlock& block)
				{
					/*
						Apply Blake2 on columns of 64-bit words: initially(0,1,...,15) , then (16,17,..31)... finally (112,113,...127)
						在64位字的列上应用Blake2：初始（0,1,...,15），然后（16,17,...31）...最后（112,113,...127）
					*/

					//The purpose of this loop is to generate a new round of "hash" numbers for the data of the 0~15 indexes of the hash_block, where the data of the 0~1 indexes of the current_state_vector are two pseudo-random large numbers that are not 0, and the data of the other indexes N~N+15 may be 0 and will not change
					//这个循环的作用是给hash_block的 0~15 的索引的数据生成新的一轮"哈希"数字，其中current_state_vector的 0~1 索引的数据是两个不为0的伪随机大数，其他索引 N~N+15 的数据可能为0而且不会改变
					for ( std::uint32_t blamka_functon_round = 0; blamka_functon_round < 8; ++blamka_functon_round )
					{
						//Copy current block state value
						//复制当前区块状态值
						std::array<std::uint64_t, 16> current_state_vector
						{
							block[16 * blamka_functon_round], block[16 * blamka_functon_round + 1], block[16 * blamka_functon_round + 2], block[16 * blamka_functon_round + 3],
							block[16 * blamka_functon_round + 4], block[16 * blamka_functon_round + 5], block[16 * blamka_functon_round + 6], block[16 * blamka_functon_round + 7],
							block[16 * blamka_functon_round + 8], block[16 * blamka_functon_round + 9], block[16 * blamka_functon_round + 10], block[16 * blamka_functon_round + 11],
							block[16 * blamka_functon_round + 12], block[16 * blamka_functon_round + 13], block[16 * blamka_functon_round + 14], block[16 * blamka_functon_round + 15]
						};

						//Execute hash round function by copying block state values
						//通过复制区块状态值执行哈希轮函数
						Core::Modules::Functions::HashValueRound(current_state_vector);

						//Change current block state value
						//改变当前区块的状态值
						for ( std::size_t block_source_index = 0, block_target_index = 0; block_source_index < 16; ++block_source_index )
						{
							block[16 * blamka_functon_round + block_target_index] = current_state_vector[block_source_index];
							++block_target_index;
						}
					}

					//Now, temporary block R is changed to temporary block Q
					//现在，临时区块R被改变为临时区块Q

					/*
						Apply Blake2 on rows of 64-bit words: initially(0,1,16,17,...112,113), then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127)
						在64位字的行上应用Blake2：初始（0,1,16,17,...112,113），然后（2,3,18,19,...,114,115）...最后（14,15,30,31,...,126,127）
					*/

					//The role of this loop is to generate a new round of "hashing" the data of indexes 0~15 according to the hash_block, where the data of indexes 0~1 of current_state_vector are from index N and index N+1 (condition N < 14) and update the data of index N+15 and index N+15+1
					//这个循环的作用是根据hash_block生成的新一轮"哈希"在 0~15 的索引的数据，其中current_state_vector的 0~1 索引的数据是来自于索引 N 和索引 N+1 (条件 N < 14)而且更新索引 N+15 和索引 N+15+1 的数据
					for ( std::uint32_t blamka_functon_round = 0; blamka_functon_round < 8; ++blamka_functon_round )
					{
						//Copy current block state value
						//复制当前区块状态值
						std::array<std::uint64_t, 16> current_state_vector
						{
							block[2 * blamka_functon_round], block[2 * blamka_functon_round + 1], block[2 * blamka_functon_round + 16], block[2 * blamka_functon_round + 17],
							block[2 * blamka_functon_round + 32], block[2 * blamka_functon_round + 33], block[2 * blamka_functon_round + 48], block[2 * blamka_functon_round + 49],
							block[2 * blamka_functon_round + 64], block[2 * blamka_functon_round + 65], block[2 * blamka_functon_round + 80], block[2 * blamka_functon_round + 81],
							block[2 * blamka_functon_round + 96], block[2 * blamka_functon_round + 97], block[2 * blamka_functon_round + 112], block[2 * blamka_functon_round + 113]
						};

						//Execute hash round function by copying block state values
						//通过复制区块状态值执行哈希轮函数
						Core::Modules::Functions::HashValueRound(current_state_vector);

						//Change current block state value
						//改变当前区块的状态值
						for ( std::size_t block_source_index = 0, block_target_index = 0; block_source_index < 16; block_source_index += 2 )
						{
							block[2 * blamka_functon_round + block_target_index] = current_state_vector[block_source_index];
							block[2 * blamka_functon_round + (block_target_index + 1)] = current_state_vector[block_source_index + 1];
							block_target_index += 16;
						}
					}

					//Now, temporary block Q is changed to temporary block Z
					//现在，临时区块Q被改变为临时区块Z
				}

				/*
				 * @param current_previous_block_x; Pointer to the previous block
				 * @param reference_block_y; Pointer to the reference block
				 * @param current_next_block; Pointer to the block to be constructed
				 * @param substitution_box_pointer; In this argon2ds hash mode type, working with substitution box by the dependent addressing; the compression function G includes the 64-bit transformation tao function, which is a chain of substitution-boxes, multiplications, and additions.
				 * @param with_exclusive_or; Whether to ExclusiveOR into the new block (1/true) or just overwrite (0/false)
				 */
				inline void FillHashBlockData
				(
					const HashingDataBlock& current_previous_block_x,
					const HashingDataBlock& reference_block_y,
					HashingDataBlock& current_next_block,
					std::array<std::uint64_t, Constants::SBOX_SIZE>* substitution_box_array_pointer,
					bool with_exclusive_or
				)
				{
					/*
						Function fills a new memory block and optionally ExclusiveORs the old block over the new one. 
						Warnning: parameter current_next_block must be initialized.

						该函数填充了一个新的内存块，并且可以选择将旧的内存块进行排他性操作地(ExclusiveORs)放在新的内存块上。 
						警告：参数current_next_block必须被初始化。
					*/

					/*
						The compression function G(X, Y) operates on two 1024-byte blocks X and Y. 
						It first computes R = X XOR Y.
						Then R is viewed as an 8x8 matrix of 16-byte registers R_0, R_1, ... , R_63.
						Then P is first applied to each row, and then to each column to get Z:
						压缩函数G(X, Y)对两个1024字节的块X和Y进行操作.
						它首先计算R = XOR Y。
						然后，R被看作是一个8x8的16字节寄存器的矩阵。R_0, R_1, ... , R_63.
						然后，P首先应用于每一行，然后应用于每一列，得到Z

										Core of Compression Function G:
										压缩函数的核心G:
						( Q_0,  Q_1,  Q_2, ... ,  Q_7) <- P( R_0,  R_1,  R_2, ... ,  R_7)
						( Q_8,  Q_9, Q_10, ... , Q_15) <- P( R_8,  R_9, R_10, ... , R_15)
													 ...
						(Q_56, Q_57, Q_58, ... , Q_63) <- P(R_56, R_57, R_58, ... , R_63)
						( Z_0,  Z_8, Z_16, ... , Z_56) <- P( Q_0,  Q_8, Q_16, ... , Q_56)
						( Z_1,  Z_9, Z_17, ... , Z_57) <- P( Q_1,  Q_9, Q_17, ... , Q_57)
													 ...
						( Z_7, Z_15, Z 23, ... , Z_63) <- P( Q_7, Q_15, Q_23, ... , Q_63)

						Finally, G outputs Z XOR R:
						G: (X, Y) -> R -> Q -> Z -> Z XOR R

										Argon2 Compression Function G:
												+---+       +---+
												| X |       | Y |
												+---+       +---+
												  |           |
												  ---->XOR<----
												--------|
												|      \ /
												|     +---+
												|     | R |
												|     +---+
												|       |
												|      \ /
												|   P rowwise
												|       |
												|      \ /
												|     +---+
												|     | Q |
												|     +---+
												|       |
												|      \ /
												|  P columnwise
												|       |
												|      \ /
												|     +---+
												|     | Z |
												|     +---+
												|       |
												|      \ /
												------>XOR
														|
													   \ /
					
					*/

					HashingDataBlock temporary_block_r = HashingDataBlock(current_previous_block_x ^ reference_block_y);
					HashingDataBlock temporary_block_z = HashingDataBlock(temporary_block_r);

					if ( substitution_box_array_pointer != nullptr )
					{
						std::array<std::uint64_t, Constants::SBOX_SIZE>& substitution_box_array = *(substitution_box_array_pointer);

						std::uint64_t block_value_x = 0;

						//x(WordBit64) := LowestShiftOfBit64(BlockR0 ⊕ BlockR63);
						block_value_x = temporary_block_r[0] ^ temporary_block_r[Constants::WORDS_MEMORY_BLOCK_SIZE - 1];

						//The transformation function Tau, on the 64-bit word (Word64Bit) is defined as follows (Repeat 96 times):
						//变换函数Tau，对64位字（Word64Bit）的定义如下（重复96次）:
						for ( std::size_t substitution_box_round = 0; substitution_box_round < 6 * 16; ++substitution_box_round )
						{
							//NewWordBit64(0) += FunctionTao(WordBit64);
							std::uint32_t temporary_value_x1 = block_value_x >> 32;

							//NewWordBit64(63) += FunctionTao(WordBit64) << 32.
							std::uint32_t temporary_value_x2 = block_value_x & std::numeric_limits<std::uint32_t>::max();

							//y := SubstitutionBox[Word64Bit[8 : 0]];
							std::uint64_t block_value_y = substitution_box_array.operator[]( temporary_value_x1 & Constants::SBOX_MASK );
							
							//z := SubstitutionBox[512 + Word64Bit[40 : 32]];
							std::uint64_t block_value_z = substitution_box_array.operator[]( (temporary_value_x2 & Constants::SBOX_MASK) + Constants::SBOX_SIZE / 2 );
							
							//WordBit64 := ((Word64Bit[31 : 0] · Word64Bit[63 : 32]) + y) ⊕ z.
							block_value_x = static_cast<std::uint64_t>(temporary_value_x1) * static_cast<std::uint64_t>(temporary_value_x2);
							block_value_x += block_value_y;
							block_value_x ^= block_value_z;
						}

						/*
							All the operations are performed modulo 2^64. 
							· is the 64-bit multiplication, S[] is the lookup table that maps 10-bit indices to 64-bit values.
							NewWordBit64[i : j] is the subset of bits of NewWordBit64 from i to j inclusive.
							所有的操作都是以2^64为模数进行的。
							· 是64位的乘法，S[]是查找表，将10位指数映射为64位的值
							NewWordBit64[i : j]是W中从i到j（含）的比特子集。
						*/

						ForEachBlockHashRoundFunctions(temporary_block_r);

						current_next_block = temporary_block_r ^ temporary_block_z;
						current_next_block[0] += block_value_x;
						current_next_block[Constants::WORDS_MEMORY_BLOCK_SIZE - 1] += block_value_x;
					}
					else
					{
						ForEachBlockHashRoundFunctions(temporary_block_r);

						if ( with_exclusive_or )
						{
							current_next_block.ExclusiveOR_Multi(temporary_block_r, temporary_block_z, current_next_block);
						}
						else
						{
							current_next_block = temporary_block_r ^ temporary_block_z;
						}
					}
				}

				inline void GenerateAddresses
				(
					const Core::Modules::Argon2_RuntimeInstance& this_runtime_instance,
					const PositionByMemoryBlock& memory_block_position,
					std::unique_ptr<std::uint64_t[]>& pseudo_random_value_pointer
				)
				{
					if ( std::addressof(this_runtime_instance) != nullptr && std::addressof(memory_block_position) != nullptr)
					{
						HashingDataBlock zero_block(static_cast<std::uint8_t>(0)),
						info_block(static_cast<std::uint8_t>(0)),
						address_block(static_cast<std::uint8_t>(0));

						info_block[0] = memory_block_position._pass_iteration_time_;
						info_block[1] = memory_block_position._lane_and_row_;
						info_block[2] = memory_block_position._slice_and_column_;

						info_block[3] = this_runtime_instance.GetMemoryBlockCount();
						info_block[4] = this_runtime_instance.GetExecuteIterationTimeNumber();
						info_block[5] = static_cast<std::uint64_t>(this_runtime_instance.GetHashModeTypeEnum());

						const std::uint32_t& block_segment_size = this_runtime_instance.GetBlockSegmentSize();

						for(std::uint32_t index = 0; index < block_segment_size; ++index)
						{
							if(index % Constants::BLOCK_ADDRESS_COUNT == 0)
							{
								(info_block[6])++;
								FillHashBlockData(zero_block, info_block, address_block, nullptr, false);
								FillHashBlockData(zero_block, address_block, address_block, nullptr, false);
							}
							pseudo_random_value_pointer[index] = address_block[index % Constants::BLOCK_ADDRESS_COUNT];
						}
					}
				}

				/*
					Explanation: An index needs to be calculated, and this index is the location of the hash block in the current segment of this memory 
					解释：需要计算一个索引，这个索引就是哈希块在当前的这个内存段中的位置

					The value of l = J_2 mod p gives the index of the lane from which the block will be taken. 
					For the first pass (r=0) and the first slice (sl=0), the block is taken from the current lane.

					   The set W contains the indices that are referenced according to the following rules:

					   1.  If l is the current lane, then W includes the indices of all blocks in the last SL - 1 = 3 segments computed and finished, as well as the blocks computed in the current segment in the current pass excluding B[i][j-1].

					   2.  If l is not the current lane, then W includes the indices of all  blocks in the last SL - 1 = 3 segments computed and finished in lane l. 
					If B[i][j] is the first block of a segment, then the  very last index from W is excluded.

					   Then take a block from W with a nonuniform distribution over [0, |W|)
					   using the following mapping:

									Figure 12: Computing J1:
								J_1 -> |W|(1 - J_1^2 / 2^(64))

					   To avoid floating point computation, the following approximation is used:

									Figure 13: Computing J1, Part 2
										x = J_1^2 / 2^(32)
										y = (|W| * x) / 2^(32)
										zz = |W| - 1 - y

					   Then take the zz-th index from W; it will be the z value for the
					   reference block index [l][z].
				*/
				inline std::uint32_t IndexAlpha
				(
					const Core::Modules::Argon2_RuntimeInstance& this_runtime_instance,
					const PositionByMemoryBlock& memory_block_position,
					const std::uint32_t& pseudo_random_value,
					const bool& is_same_lanes_or_rows
				)
				{

					const std::uint32_t& block_segment_size = this_runtime_instance.GetBlockSegmentSize();
					const std::uint32_t& block_lanes_or_rows_each_size = this_runtime_instance.GetEachSizeOfParallelismNumber_LanesAndRows();

					/*
						Pass 0:
							This lane : all already finished segments plus already constructed blocks in this segment
							Other lanes : all already finished segments
						Pass 1+:
							This lane : (SYNC_POINTS - 1) last segments plus already constructed blocks in this segment
							Other lanes : (SYNC_POINTS - 1) last segments
						
						如果通过迭代时间为0。
							本车道（行）：所有已经完成的区段，加上本区段中已经建造的区块
							其他车道（行）：所有已经完成的区段
						否则，如果通过迭代时间为1+。
							本车道（行）：(SYNC_POINTS - 1)最后一个区段加上本区段已经建造的区块
							其他车道（行）: (SYNC_POINTS - 1) 最后的区段
					 
					*/
					auto lambda_ComputeReferenceAreaSize = [&block_segment_size, &block_lanes_or_rows_each_size](const PositionByMemoryBlock& memory_block_position, const bool& is_same_lanes_or_rows) -> std::uint32_t
					{
						if( memory_block_position._pass_iteration_time_ == 0 )
						{
							/*
								Current (Is first) passed execute iteration time.
								当前（是第一次）通过的执行迭代时间。
							*/

							//Is the current slices(columns) equals to zero?
							//当前切片（列）是否等于零？
							if(memory_block_position._slice_and_column_ == 0)
							{
								//All but the previous
								//除了前面的，其他的都是
								return memory_block_position._index_ - 1;
							}
							else
							{
								//Whether: Is the lane(row) the same as the reference block lane(row)?
								//是否: 该车道（行）是否与参考区块车道（行）相同？
								if(is_same_lanes_or_rows)
								{
									//If boolean value is true.
									//Then the position of the hash block is calculated by the previous index of the current memory segment.
									//如果布尔值为真。
									//那么哈希块的位置就由当前内存段的前一个索引来计算。
								
									/*
										Tips: Accessing memory segments by vertical addressing in the memory 
										提示：在内存矩阵中通过垂直寻址访问内存段
									*/
									return memory_block_position._slice_and_column_ * block_segment_size + memory_block_position._index_ - 1;
								}
								else
								{
									//Else, the boolean is false.
									//Then determine the index of the hash block that is currently in the memory segment.
									//If this index is 0, then the position of the hash block is calculated by the previous index of the current memory segment. 
									//If this index is not 0, then the position of the hash block is calculated directly by the index of the current memory segment 
									//否则，布尔值为假。
									//然后判断当前在内存段的哈希块的索引。
									//如果这个索引是0，那么哈希块的位置就按当前内存段的前一个索引来计算。 
									//如果这个索引不是0，那么哈希块的位置直接按当前内存段的索引来计算。 
								
									/*
										Tips: Accessing memory segments by vertical addressing in the memory 
										提示：在内存矩阵中通过垂直寻址访问内存段
									*/

									if(memory_block_position._index_ == 0)
										return memory_block_position._slice_and_column_ * block_segment_size - 1;
									else
										return memory_block_position._slice_and_column_ * block_segment_size;
								}
							}
						}
						else
						{
							/* Current (Is not first)/(Is Second) passed execute iteration time. */

							//Whether: Is the lane(row) the same as the reference block lane(row)?
							//是否: 该车道（行）是否与参考区块车道（行）相同？
							if(is_same_lanes_or_rows)
							{
								//If boolean value is true.
								//Then the position of the hash block is calculated by the previous index of the current memory segment.
								//如果布尔值为真。
								//那么哈希块的位置就由当前内存段的前一个索引来计算。
							
								/*
									Tips: Accessing memory segments by horizontal addressing in the memory 
									提示：在内存矩阵中通过水平寻址访问内存段
								*/
								return block_lanes_or_rows_each_size - block_segment_size + memory_block_position._index_ - 1;
							}
							else
							{
								//Else, the boolean is false.
								//Then determine the index of the hash block that is currently in the memory segment.
								//If this index is 0, then the position of the hash block is calculated by the previous index of the current memory segment. 
								//If this index is not 0, then the position of the hash block is calculated directly by the index of the current memory segment 
								//否则，布尔值为假。
								//然后判断当前在内存段的哈希块的索引。
								//如果这个索引是0，那么哈希块的位置就按当前内存段的前一个索引来计算。 
								//如果这个索引不是0，那么哈希块的位置直接按当前内存段的索引来计算。

								/*
									Tips: Accessing memory segments by horizontal addressing in the memory 
									提示：在内存矩阵中通过水平寻址访问内存段
								*/

								if(memory_block_position._index_ == 0)
									return block_lanes_or_rows_each_size - block_segment_size - 1;
								else
									return block_lanes_or_rows_each_size - block_segment_size;
							}
						}
					};

					std::uint32_t reference_area_size = lambda_ComputeReferenceAreaSize(memory_block_position, is_same_lanes_or_rows);
					
					/*
						1.2.4. Mapping pseudo_random_value to 0..<reference_area_size-1> and produce relative position
						1.2.4. 将pseudo_random_value映射到0...<reference_area_size-1>并产生相对位置
					*/
					std::uint64_t relative_position = pseudo_random_value;
					relative_position = relative_position * relative_position >> 32;
					relative_position = reference_area_size - 1 - (reference_area_size * relative_position >> 32);

					/*
						1.2.5 Computing starting position
						1.2.5 计算起始位置
					*/
					std::uint32_t start_position = 0;
					if (memory_block_position._pass_iteration_time_ != 0)
						start_position = (memory_block_position._slice_and_column_ == Constants::SYNC_POINTS - 1)
							? 0 
							: (memory_block_position._slice_and_column_ + 1) * block_segment_size;

					/*
						1.2.6. Computing absolute position
						1.2.6. 计算绝对位置
					*/

					//Absolute position
					std::uint32_t absolute_position = (start_position + relative_position) % block_lanes_or_rows_each_size;
					return absolute_position;
				}

				/*
					Hint: A segment consists of multiple hash blocks
					提示：一个段由多个哈希块组成
				*/
				inline void FillMemoryDataSegment
				(
					Core::Modules::Argon2_RuntimeInstance& this_runtime_instance,
					PositionByMemoryBlock& memory_block_position
				)
				{
					std::uint64_t pseudo_random_value, reference_block_index, reference_block_lane_or_row;
					std::uint32_t previous_block_offset, current_block_offest;
					
					const HashModeType& hash_mode_type = this_runtime_instance.GetHashModeTypeEnum();

					bool data_independent_addressing = (hash_mode_type == HashModeType::IndependentAddressing)
						|| (hash_mode_type == HashModeType::MixedAddressing && (memory_block_position._pass_iteration_time_ == 0)
						&& (memory_block_position._slice_and_column_ < Constants::SYNC_POINTS / 2));

					const std::uint32_t& block_segment_size = this_runtime_instance.GetBlockSegmentSize();
					
					//Pseudo-random values that determine the reference block position
					std::unique_ptr<std::uint64_t[]> pseudo_random_value_pointer = std::unique_ptr<std::uint64_t[]>( new std::uint64_t[block_segment_size] );
					std::span<std::uint64_t> span_pseudo_random_values(pseudo_random_value_pointer.get(), block_segment_size);

					if ( data_independent_addressing )
						GenerateAddresses(this_runtime_instance, memory_block_position, pseudo_random_value_pointer);

					std::uint32_t starting_index = 0;
					if ( (memory_block_position._pass_iteration_time_ == 0) && (memory_block_position._slice_and_column_ == 0) )
						//We have already generated the first two blocks
						starting_index = 2;

					std::uint32_t block_lanes_or_rows_each_size = this_runtime_instance.GetEachSizeOfParallelismNumber_LanesAndRows();
					
					//Offset of the current block
					current_block_offest = memory_block_position._lane_and_row_
						* block_lanes_or_rows_each_size
						+ memory_block_position._slice_and_column_
						* block_segment_size
						+ starting_index;
					
					if ( current_block_offest % block_lanes_or_rows_each_size == 0 )
					{
						//Last block in this lane(row)
						previous_block_offset = current_block_offest + block_lanes_or_rows_each_size - 1;
					}
					else
					{
						//Previous block
						previous_block_offset = current_block_offest - 1;
					}

					std::vector<Core::Modules::HashingDataBlock>& current_instance_memory_blocks = this_runtime_instance.GetMemoryBlocks();
					std::uint32_t block_lanes_or_rows = this_runtime_instance.GetParallelismNumber_LanesAndRows();
					
					AlgorithmVersion algorithm_version = this_runtime_instance.GetAlgorithmVersion();
					auto* argon2_substitution_box_pointer = this_runtime_instance.GetSubstitutionBoxPointer();

					const std::uint32_t& ending_index = block_segment_size;
					for(std::uint32_t index = starting_index; index < ending_index; ++index, ++current_block_offest, ++previous_block_offset)
					{
						/*
							1.1 Rotating previous_block_offset if needed
							1.1 必要时旋转previous_block_offset
						*/

						if ( current_block_offest % block_segment_size == 1 )
							previous_block_offset = current_block_offest - 1;

						/*
							1.2 Computing the index of the reference block
							1.2.1 Taking pseudo-random value from the previous block
						
							1.2 计算参考区块的索引
							1.2.1 从上一个区块中获取伪随机值
						*/

						if ( data_independent_addressing )
							pseudo_random_value = span_pseudo_random_values[index];
						else
							pseudo_random_value = current_instance_memory_blocks[previous_block_offset].operator[](0);

						/*
							1.2.2 Computing the lane(row) of the reference block
							1.2.2 计算参考区块的车道（行）
						*/

						reference_block_lane_or_row = (pseudo_random_value >> 32) % block_lanes_or_rows;
						if ( (memory_block_position._pass_iteration_time_ == 0) && (memory_block_position._slice_and_column_ == 0) )
							//Can not reference other lanes yet
							reference_block_lane_or_row = memory_block_position._lane_and_row_;

						/*
							1.2.3 Computing the number of possible reference block within the lane(row).
							1.2.3 计算车道（行）内可能的参考块数。
						*/

						memory_block_position._index_ = index;
						reference_block_index = IndexAlpha
						(
							this_runtime_instance,
							memory_block_position,
							pseudo_random_value & std::numeric_limits<std::uint32_t>::max(),
							reference_block_lane_or_row == memory_block_position._lane_and_row_
						);

						/*
							2. Creating a new block
							2. 创建一个新的区块
						*/

						HashingDataBlock& reference_block = current_instance_memory_blocks[block_lanes_or_rows_each_size * reference_block_lane_or_row + reference_block_index];
						HashingDataBlock& current_block = current_instance_memory_blocks[current_block_offest];

						if ( hash_mode_type == HashModeType::SubstitutionBox )
						{
							FillHashBlockData(current_instance_memory_blocks[previous_block_offset], reference_block, current_block, argon2_substitution_box_pointer, false);
						}
						else
						{
							if ( algorithm_version == AlgorithmVersion::NUMBER_0x10 )
							{
								FillHashBlockData(current_instance_memory_blocks[previous_block_offset], reference_block, current_block, nullptr, false);
							}
							else
							{
								if ( memory_block_position._pass_iteration_time_ == 0 )
								{
									FillHashBlockData(current_instance_memory_blocks[previous_block_offset], reference_block, current_block, nullptr, false);
								}
								else
								{
									FillHashBlockData(current_instance_memory_blocks[previous_block_offset], reference_block, current_block, nullptr, true);
								}
							}
						}
					}

					pseudo_random_value_pointer.reset();
				}

				/*
					The Substitution-Box is generated in the start of every pass in the following procedure. In total we specify 2^10· 8 bytes, or 8 KBytes. 
					We take block HashingDataBlock[0][0] and apply function F (the core of function G) to it 16 times. 
					After each two iterations we use the entire 1024-byte value and initialize 128 lookup values.
					The properties of function tao and its initialization procedure is subject to change.

					在下面的程序中，替代框是在每一次传递的开始时产生的。我们总共指定了2^10·8个字节，即8KBytes。 
					我们取块HashingDataBlock[0][0]并对其应用函数F（函数G的核心）16次。
					在每两次迭代之后，我们使用整个1024字节的值并初始化128个查找值。
					函数tao的属性和它的初始化程序是可以改变的。
				*/
				inline void GenerateSubstitutionBox(Argon2_RuntimeInstance& this_runtime_instance)
				{
					if ( std::addressof(this_runtime_instance) == nullptr )
						return;

					std::vector<HashingDataBlock> three_hashing_block
					{
						HashingDataBlock(static_cast<std::uint8_t>(0)),
						(this_runtime_instance.GetMemoryBlocks().operator[](0)),
						HashingDataBlock(static_cast<std::uint8_t>(0))
					};

					auto& zero_block = three_hashing_block[0];
					auto& temporary_block_a = three_hashing_block[1];
					auto& temporary_block_b = three_hashing_block[2];

					auto* argon2_substitution_box_pointer = this_runtime_instance.GetSubstitutionBoxPointer();

					//Generate pseudo-random word substitution boxes passed by transformed memory data
					//产生由转换内存数据传递的伪随机字置换框
					for(std::uint64_t index = 0; index < Constants::SBOX_SIZE / Constants::WORDS_MEMORY_BLOCK_SIZE; ++index)
					{
						FillHashBlockData(zero_block, temporary_block_a, temporary_block_b, nullptr, false);
						FillHashBlockData(zero_block, temporary_block_b, temporary_block_a, nullptr, false);
						std::memcpy(argon2_substitution_box_pointer->data() + index * Constants::WORDS_MEMORY_BLOCK_SIZE, temporary_block_a.GetHashingDataBlock().data(), Constants::BYTES_MEMORY_BLOCK_SIZE);
					}
				}
			}
		}

		class Argon2_Module
		{

		private:
			struct Initializer
			{
				static void FillFirstMemoryBlock(Core::Modules::Argon2_RuntimeInstance& this_runtime_instance, std::vector<std::uint8_t>& hashed_zero_bytes, std::vector<std::uint8_t>& hashed_one_bytes)
				{
					/**
					 * (H0 || 0 || i) 72 byte -> 1024 byte
					 * (H0 || 1 || i) 72 byte -> 1024 byte
					 */

					using CommonToolkit::MessagePacking;
					using CommonToolkit::MessageUnpacking;

					std::uint32_t block_lanes_or_rows = this_runtime_instance.GetParallelismNumber_LanesAndRows();
					std::uint32_t block_lanes_or_rows_each_size = this_runtime_instance.GetEachSizeOfParallelismNumber_LanesAndRows();
					std::vector<Core::Modules::HashingDataBlock>& current_instance_memory_blocks = this_runtime_instance.GetMemoryBlocks();

					//Make the first and second block in each lane(row) as G(H0||0||i) or G(H0||1||i) 
					for(std::uint32_t current_lane_and_row = 0; current_lane_and_row < block_lanes_or_rows; ++current_lane_and_row)
					{
						std::vector<std::uint8_t> current_lane_and_row_bytes = MessageUnpacking<std::uint32_t, std::uint8_t>(&(current_lane_and_row), 1);

						std::ranges::copy_n(current_lane_and_row_bytes.begin(), 4, hashed_zero_bytes.begin() + (Constants::PRE_HASHING_DIGEST_SIZE + 4));
						std::ranges::copy_n(current_lane_and_row_bytes.begin(), 4, hashed_one_bytes.begin() + (Constants::PRE_HASHING_DIGEST_SIZE + 4));

						auto BlockBytesBySpecializedHashed = Core::Modules::Functions::SpecializedHash(hashed_zero_bytes, Constants::BYTES_MEMORY_BLOCK_SIZE);
						if(!BlockBytesBySpecializedHashed.has_value())
							throw std::runtime_error("Argon2 Error: Oh, you can't call the Blake64bitLong function by using invalid parameters, the code location is in (Argon2_ModuleCore class inside Initializer::InitialBlockStep().lambda_FillOneMemoryBlock). [1]");
						else
						{
							//Access first_hash_block
							Core::Modules::HashingDataBlock& hash_block = current_instance_memory_blocks.operator[](current_lane_and_row * block_lanes_or_rows_each_size);
							hash_block.FromBytes(BlockBytesBySpecializedHashed.value());
						}

						BlockBytesBySpecializedHashed = Core::Modules::Functions::SpecializedHash(hashed_one_bytes, Constants::BYTES_MEMORY_BLOCK_SIZE);
						if(!BlockBytesBySpecializedHashed.has_value())
							throw std::runtime_error("Argon2 Error: Oh, you can't call the Blake64bitLong function by using invalid parameters, the code location is in (Argon2_ModuleCore class inside Initializer::InitialBlockStep().lambda_FillOneMemoryBlock). [2]");
						else
						{
							if ( current_instance_memory_blocks.size() > (current_lane_and_row * block_lanes_or_rows_each_size) + 1 )
							{
								//Access first_hash_block
								Core::Modules::HashingDataBlock& hash_block = current_instance_memory_blocks.operator[]((current_lane_and_row * block_lanes_or_rows_each_size) + 1);
								hash_block.FromBytes(BlockBytesBySpecializedHashed.value());
							}
						}
					}
				}

				static void InitialBlockStep(Core::Modules::Argon2_RuntimeInstance& this_runtime_instance, Argon2_Parameters& argon2_parameters_context)
				{
					/*
						Initial hashing H0
					*/
					std::vector<std::uint8_t> H0Data = Core::Modules::Functions::GenerateHashedByte0(argon2_parameters_context);

					auto lambda_ExpandHashedBytes0 = [](const std::vector<std::uint8_t>& HashedBytes0Data, const std::array<std::uint8_t, 4>& NeedAppendBytes) -> std::vector<std::uint8_t>
					{
						std::vector<std::uint8_t> ExpandedHashedBytes0(Constants::PRE_HASHING_SEED_SIZE, 0);

						std::ranges::copy_n(HashedBytes0Data.begin(), Constants::PRE_HASHING_DIGEST_SIZE, ExpandedHashedBytes0.begin());
						std::ranges::copy_n(NeedAppendBytes.begin(), 4, ExpandedHashedBytes0.begin() + Constants::PRE_HASHING_DIGEST_SIZE);

						return ExpandedHashedBytes0;
					};

					constexpr std::array<std::uint8_t, 4> ConstantZeroBytes{ 0, 0, 0, 0 };
					constexpr std::array<std::uint8_t, 4> ConstantOneBytes{ 1, 0, 0, 0 };

					std::vector<std::uint8_t> HashWithZeroBytes = lambda_ExpandHashedBytes0(H0Data, ConstantZeroBytes);
					std::vector<std::uint8_t> HashWithOneBytes = lambda_ExpandHashedBytes0(H0Data, ConstantOneBytes);

					Initializer::FillFirstMemoryBlock( this_runtime_instance, HashWithZeroBytes, HashWithOneBytes );
				}
			};

			struct MemoryFiller
			{
				static void UpdateBlocksStep(Core::Modules::Argon2_RuntimeInstance& this_runtime_instance)
				{
					if ( std::addressof(this_runtime_instance) == nullptr )
						return;

					std::uint32_t IterationTimeCost = this_runtime_instance.GetExecuteIterationTimeNumber();
					std::uint32_t LanesAndRows = this_runtime_instance.GetParallelismNumber_LanesAndRows();
					HashModeType InstanceHashModeType = this_runtime_instance.GetHashModeTypeEnum();
					std::uint32_t LanesAndRowsInActualThreads = this_runtime_instance.GetActualThreadParallelismNumber_LanesAndRows();

					/*
						
						Indexing Function

						To realize that hash blocks can be computed in parallel in the memory matrix, we further divide the memory matrix into SL = 4 vertical slices.
						The intersection of a slice (column) and a lane (row) is called a segment, whose length (size) is q/SL.
						Segments of the same slice (column) can be computed in parallel and do not reference each other's hash blocks.
						All other hash blocks can be referenced.

						为了实现哈希块在内存矩阵可以并行计算，我们进一步将内存矩阵划分为SL=4个垂直切片。
						一个切片(列)和一个车道(行)的交叉点被称为一个段，其长度为q/SL。
						同一切片(列)的段可以并行计算，并且不引用彼此的哈希块。
						所有其他的哈希块都可以被引用。

						Single-Pass Argon2 with p Lanes and 4 Slices:

							slice 0    slice 1    slice 2    slice 3
						   ___/\___   ___/\___   ___/\___   ___/\___
						  /        \ /        \ /        \ /        \
						 +----------+----------+----------+----------+
						 |          |          |          |          | > lane 0
						 +----------+----------+----------+----------+
						 |          |          |          |          | > lane 1
						 +----------+----------+----------+----------+
						 |          |          |          |          | > lane 2
						 +----------+----------+----------+----------+
						 |         ...        ...        ...         | ...
						 +----------+----------+----------+----------+
						 |          |          |          |          | > lane p - 1
						 +----------+----------+----------+----------+

					*/

					if(LanesAndRows == 1)
					{
						//Compute hash blocks via single thread
						//通过单线程来计算哈希块

						for ( std::uint32_t time_counter = 0; time_counter < IterationTimeCost; ++time_counter )
						{
							if(InstanceHashModeType == HashModeType::SubstitutionBox)
							{
								Core::Modules::Operations::GenerateSubstitutionBox(this_runtime_instance);
							}

							for ( std::uint8_t slice_and_column = 0; slice_and_column < Constants::SYNC_POINTS; ++slice_and_column )
							{
								auto memory_block_position = Core::Modules::PositionByMemoryBlock(time_counter, 0, slice_and_column, 0);
								Core::Modules::Operations::FillMemoryDataSegment(this_runtime_instance, memory_block_position);
							}
						}
					}
					else
					{
						//Compute hash blocks via multiple threads
						//通过多线程来计算哈希块

						std::vector<std::thread> thread_objects;

						for ( std::uint32_t time_counter = 0; time_counter < IterationTimeCost; ++time_counter )
						{
							if(InstanceHashModeType == HashModeType::SubstitutionBox)
							{
								Core::Modules::Operations::GenerateSubstitutionBox(this_runtime_instance);
							}

							for ( std::uint8_t slice_and_column = 0; slice_and_column < Constants::SYNC_POINTS; ++slice_and_column )
							{
								for ( std::uint32_t lane_and_row = 0; lane_and_row < LanesAndRows; ++lane_and_row )
								{
									auto memory_block_position = Core::Modules::PositionByMemoryBlock(time_counter, lane_and_row, slice_and_column, 0);
									std::thread work_thread( Core::Modules::Operations::FillMemoryDataSegment, std::ref(this_runtime_instance), std::ref(memory_block_position) );
									thread_objects.push_back( std::move(work_thread) );
								
									//Have to join extra threads
									if(LanesAndRowsInActualThreads <= thread_objects.size())
									{
										for(auto& thread : thread_objects)
										{
											if(thread.joinable())
												thread.join();
										}
										thread_objects.clear();
									}
								}

								if(!thread_objects.empty())
								{
									for(auto& thread : thread_objects)
									{
										if(thread.joinable())
											thread.join();
									}
									thread_objects.clear();
								}
							}
						}

						thread_objects.shrink_to_fit();
					}
				}
			};

			struct Finalizer
			{
				static void FillLastMemoryBlock(Core::Modules::Argon2_RuntimeInstance& this_runtime_instance, std::vector<std::uint8_t>& result_hash_block_bytes)
				{
					std::vector<Core::Modules::HashingDataBlock>& current_instance_memory_blocks = this_runtime_instance.GetMemoryBlocks();

					const std::uint32_t block_lanes_or_rows = this_runtime_instance.GetParallelismNumber_LanesAndRows();
					const std::uint32_t block_lanes_or_rows_each_size = this_runtime_instance.GetEachSizeOfParallelismNumber_LanesAndRows();

					//Access last_hash_block
					Core::Modules::HashingDataBlock hash_block( current_instance_memory_blocks[block_lanes_or_rows_each_size - 1] );

					//ExclusiveOR last hash blocks
					for(std::uint32_t lane_and_row = 1; lane_and_row < block_lanes_or_rows; ++lane_and_row)
					{
						std::uint32_t last_hash_block_in_lanes = block_lanes_or_rows_each_size + ( block_lanes_or_rows_each_size - 1 );
						hash_block ^= current_instance_memory_blocks[last_hash_block_in_lanes];
					}

					result_hash_block_bytes.resize(Constants::WORDS_MEMORY_BLOCK_SIZE * sizeof(std::uint64_t));
					hash_block.ToBytes(result_hash_block_bytes);

					hash_block.Clear();
				}

				static void FinalBlockStep(Core::Modules::Argon2_RuntimeInstance& this_runtime_instance, Argon2_Parameters& argon2_parameters_context, std::vector<std::uint8_t>& result_hash_block_bytes)
				{
					std::vector<Core::Modules::HashingDataBlock>& current_instance_memory_blocks = this_runtime_instance.GetMemoryBlocks();

					const std::uint32_t block_lanes_or_rows = this_runtime_instance.GetParallelismNumber_LanesAndRows();
					const std::uint32_t block_lanes_or_rows_each_size = this_runtime_instance.GetEachSizeOfParallelismNumber_LanesAndRows();

					Finalizer::FillLastMemoryBlock( this_runtime_instance, result_hash_block_bytes );

					//Hash the result
					std::optional<std::vector<std::uint8_t>> optional_result_hash_block_bytes = Core::Modules::Functions::SpecializedHash(result_hash_block_bytes, argon2_parameters_context._generate_hashed_digest_bytes_size_);

					result_hash_block_bytes.clear();
					result_hash_block_bytes.shrink_to_fit();

					if(optional_result_hash_block_bytes.has_value())
						result_hash_block_bytes.swap(optional_result_hash_block_bytes.value());
				}
			};

			Exceptions::StatusCodes ValidateArgon2_Parameters(const Argon2_Parameters& argon2_parameters_context)
			{
				using Exceptions::StatusCodes;

				if ( std::addressof(argon2_parameters_context) == nullptr )
					return StatusCodes::INCORRECT_PARAMETER;

				if ( argon2_parameters_context._generate_hashed_digest_bytes_.data() == nullptr )
				{
					if (argon2_parameters_context._generate_hashed_digest_bytes_size_ != 0)
					{
						return StatusCodes::GENERATE_HASHED_POINTER_MISMATCH;
					}
					return StatusCodes::GENERATE_HASHED_POINTER_NULL;
				}
				else
				{
					//generate_hashed_digest_bytes: Bytes (4 ~ power(2,32)-1) Password (or message) need be hashed
					if ( argon2_parameters_context._generate_hashed_digest_bytes_size_ < Constants::MINIMUM_GENERATE_HASHED_DIGEST_SIZE )
						return StatusCodes::MESSAGE_PASSWORD_SIZE_TOO_SHORT;
					else if ( argon2_parameters_context._generate_hashed_digest_bytes_size_ > Constants::MAXIMUM_GENERATE_HASHED_DIGEST_SIZE )
						return StatusCodes::MESSAGE_PASSWORD_SIZE_TOO_LONG;
				}

				/* Validate message or password size */
				if ( argon2_parameters_context._message_or_password_bytes_.data() == nullptr )
				{
					if ( argon2_parameters_context._message_or_password_bytes_size_ != 0 )
						return StatusCodes::MESSAGE_PASSWORD_POINTER_MISMATCH;
				}
				else
				{
					//message_or_password_bytes: Bytes (0 ~ power(2,32)-1) Password (or message) need be hashed
					if( argon2_parameters_context._message_or_password_bytes_size_ < Constants::MINIMUM_MESSAGE_PASSWORD_BYTE_SIZE )
						return StatusCodes::MESSAGE_PASSWORD_SIZE_TOO_SHORT;
					else if ( argon2_parameters_context._message_or_password_bytes_size_ > Constants::MAXIMUM_MESSAGE_PASSWORD_BYTE_SIZE )
						return StatusCodes::MESSAGE_PASSWORD_SIZE_TOO_LONG;
				}

				/* Validate salt size */
				if ( argon2_parameters_context._salt_disorderly_bytes_.data() == nullptr )
				{
					if ( argon2_parameters_context._salt_disorderly_bytes_size_ != 0 )
						return StatusCodes::SALT_BYTE_POINTER_MISMATCH;
				}
				else
				{
					//salt_bytes: Bytes (8 ~ power(2,32)-1) Salt (16 bytes recommended for password hashing)
					if ( argon2_parameters_context._salt_disorderly_bytes_size_ < Constants::MINIMUM_MESSAGE_PASSWORD_BYTE_SIZE )
						return StatusCodes::SALT_BYTE_SIZE_TOO_SHORT;
					else if ( argon2_parameters_context._salt_disorderly_bytes_size_ > Constants::MAXIMUM_MESSAGE_PASSWORD_BYTE_SIZE )
						return StatusCodes::SALT_BYTE_SIZE_TOO_LONG;
				}

				/* Validate secret key byte size */
				if ( argon2_parameters_context._process_secret_key_bytes_.data() == nullptr )
				{
					if ( argon2_parameters_context._process_secret_key_bytes_size_ != 0 )
						return StatusCodes::SECRET_KEY_POINTER_MISMATCH;
				}
				else
				{
					//optional_process_secret_key_bytes: Bytes (0 ~ power(2,32)-1) Optional key (Errata: PDF says 0..32 bytes, RFC says power(2,32) bytes)
					if( argon2_parameters_context._process_secret_key_bytes_size_ < Constants::MINIMUM_MESSAGE_PASSWORD_BYTE_SIZE )
						return StatusCodes::SECRET_KEY_SIZE_TOO_SHORT;
					else if ( argon2_parameters_context._process_secret_key_bytes_size_ > Constants::MAXIMUM_MESSAGE_PASSWORD_BYTE_SIZE )
						return StatusCodes::SECRET_KEY_SIZE_TOO_LONG;
				}

				/* Validate extra byte data or associated byte data size */
				if ( argon2_parameters_context._process_extra_data_bytes_.data() == nullptr )
				{
					if ( argon2_parameters_context._process_extra_data_bytes_size_ != 0 )
						return StatusCodes::EXTREA_BYTE_POINTER_MISMATCH;
				}
				else
				{
					//optional_process_extra_data_bytes: Bytes (0 ~ power(2,32)-1) Optional arbitrary extra data
					if ( argon2_parameters_context._process_extra_data_bytes_size_ < Constants::MINIMUM_MESSAGE_PASSWORD_BYTE_SIZE )
						return StatusCodes::EXTRA_BYTE_SIZE_TOO_SHORT;
					else if ( argon2_parameters_context._process_extra_data_bytes_size_ > Constants::MAXIMUM_MESSAGE_PASSWORD_BYTE_SIZE )
						return StatusCodes::EXTRA_BYTE_SIZE_TOO_LONG;
				}

				/* Validate memory cost */
				//reserve_memory_kibibyte_size: Integer (8 * parallelism_block_row_number ~ power(2,32)-1) Amount of memory (in kilobytes) to use
				if ( argon2_parameters_context._requested_memory_block_space_cost_ < Constants::MINIMUM_MEMORY_BLOCK_BYTE_COUNT )
					return StatusCodes::MEMORY_COST_TOO_LITTIE;
				else if ( argon2_parameters_context._requested_memory_block_space_cost_ > Constants::MAXIMUM_MEMORY_BLOCK_BYTE_COUNT )
					return StatusCodes::MEMORY_COST_TOO_LARGE;

				/* Validate time cost */
				//iteration_number: Integer (1 ~ power(2,32)-1) Number of iterations to perform
				if ( argon2_parameters_context._requested_execute_iteration_time_cost_ < Constants::MINIMUM_BLOCK_ITERATIONS_TIME )
					return StatusCodes::ITERATION_TIME_COST_TOO_SMALL;
				else if ( argon2_parameters_context._requested_execute_iteration_time_cost_ > Constants::MAXIMUM_BLOCK_ITERATIONS_TIME )
					return StatusCodes::ITERATION_TIME_COST_TOO_BIG;

				//parallelism_block_row_number: Integer (1 ~ power(2,24)-1) Degree of parallelism (i.e. number of threads)
				if ( argon2_parameters_context._parallelism_lanes_and_rows_number_ < Constants::MINIMUM_PARALLELISM_LANES_ROWS )
					return StatusCodes::LANES_ROWS_TOO_FEW;
				else if ( argon2_parameters_context._parallelism_lanes_and_rows_number_ > Constants::MAXIMUM_PARALLELISM_LANES_ROWS )
					return StatusCodes::LANES_ROWS_TOO_MANY;

				/* Validate threads */
				if (argon2_parameters_context._actual_thread_parallelism_lanes_and_rows_number_ < Constants::MINIMUM_ACTUAL_PARALLELISM_LANES_ROWS)
					return StatusCodes::THREADS_COST_TOO_FEW;
				else if (argon2_parameters_context._actual_thread_parallelism_lanes_and_rows_number_ > Constants::MAXIMUM_ACTUAL_PARALLELISM_LANES_ROWS)
					return StatusCodes::THRAEDS_COST_TOO_MANY;

				return StatusCodes::OK;
			}

		protected:
			std::vector<std::uint8_t> _module_generate_hashed_digest_bytes_;

			void HashAlgorithm(Argon2_Parameters& argon2_parameters_context)
			{
				/* 1. Validate all inputs */
				Exceptions::StatusCodes argon2_status_code = this->ValidateArgon2_Parameters(argon2_parameters_context);

				my_cpp2020_assert(argon2_status_code == Exceptions::StatusCodes::OK, Exceptions::GetStatusCodeMessage(argon2_status_code).data(), std::source_location::current());
				if (HashModeType::DependentAddressing != argon2_parameters_context._hash_mode_type_ && HashModeType::IndependentAddressing != argon2_parameters_context._hash_mode_type_ && HashModeType::MixedAddressing != argon2_parameters_context._hash_mode_type_ && HashModeType::SubstitutionBox != argon2_parameters_context._hash_mode_type_)
				{
					my_cpp2020_assert(false, Exceptions::GetStatusCodeMessage(Exceptions::StatusCodes::INCORRECT_HASH_MODE_TYPE).data(), std::source_location::current());
				}

				/* 2. Align memory size */
				// Minimum memory_blocks = 8L blocks, where L is the number of lanes
				std::uint32_t memory_block_count = argon2_parameters_context._requested_memory_block_space_cost_;

				//Reference test website: https://argon2.online/
				//警告! 不要随便尝试改变这个判断，这将导致测试数据和官方测试数据的不匹配！
				//Warning! Don't just change this judgment, it will cause a mismatch between the test data and the official test data!
				if (memory_block_count < 2 * Constants::SYNC_POINTS * argon2_parameters_context._parallelism_lanes_and_rows_number_)
					memory_block_count = 2 * Constants::SYNC_POINTS * argon2_parameters_context._parallelism_lanes_and_rows_number_;
				else if( memory_block_count >= 2 * Constants::SYNC_POINTS * argon2_parameters_context._parallelism_lanes_and_rows_number_ )
					memory_block_count = memory_block_count - memory_block_count % ( argon2_parameters_context._parallelism_lanes_and_rows_number_ * Constants::SYNC_POINTS);

				//确保所有的段都是同等大小的
				//Make sure all segments are of equal size
				std::uint32_t block_segment_size = memory_block_count / (argon2_parameters_context._parallelism_lanes_and_rows_number_ * Constants::SYNC_POINTS);
				memory_block_count = block_segment_size * ( argon2_parameters_context._parallelism_lanes_and_rows_number_ * Constants::SYNC_POINTS);

				//内存块的自动分配和取消分配是通过C++类对象的RAII（Resource Acquisition Is Initialization）机制实现的。
				//Automatic allocation and deallocation of memory blocks is achieved through the RAII (Resource Acquisition Is Initialization) mechanism of C++ class objects.
				Core::Modules::Argon2_RuntimeInstance this_runtime_instance = Core::Modules::Argon2_RuntimeInstance
				(
					argon2_parameters_context._requested_execute_iteration_time_cost_,
					memory_block_count,
					block_segment_size,
					argon2_parameters_context._parallelism_lanes_and_rows_number_,
					argon2_parameters_context._actual_thread_parallelism_lanes_and_rows_number_,
					argon2_parameters_context._algorithm_version_,
					argon2_parameters_context._hash_mode_type_
				);

				if(this_runtime_instance.GetActualThreadParallelismNumber_LanesAndRows() > this_runtime_instance.GetParallelismNumber_LanesAndRows())
					this_runtime_instance.SetThreadActualParallelismNumber_LanesAndRows(argon2_parameters_context._parallelism_lanes_and_rows_number_);
				
				/* 3. Initialization: Hashing inputs, allocating memory, filling first(one) hash blocks */
				Initializer::InitialBlockStep(this_runtime_instance, argon2_parameters_context);

				/* 4. Filling memory block and update */
				MemoryFiller::UpdateBlocksStep(this_runtime_instance);

				/* 5. Finalization: ExclusiveOR the last hash blocks, hash the result */
				Finalizer::FinalBlockStep(this_runtime_instance, argon2_parameters_context, this->_module_generate_hashed_digest_bytes_);
			}

		};
	}

	template<typename Type>
	concept HashedDigestConcept = std::same_as<std::remove_const_t<Type>, std::vector<std::uint8_t>> || std::same_as<std::remove_const_t<Type>, std::string>;

	class Argon2 : public Core::Argon2_Module
	{

	private:
		//Argon2 hash algorithm parameters
		Argon2_Parameters _parameters_context_;

		//Whether the current hash task is completed
		std::atomic_flag hash_worker_is_used {};
		bool hash_worker_is_not_used = true;

		friend std::ostream& operator<<(std::stringstream& output_stream, const Argon2& argon2_object);
		friend std::istream& operator>>(std::stringstream& input_stream, Argon2& argon2_object);

		void ComputeHashValue()
		{
			this->HashAlgorithm(_parameters_context_);
		}

		void SetHashedDigestByte(std::vector<std::uint8_t>& module_generate_hashed_digest_bytes)
		{
			if ( !module_generate_hashed_digest_bytes.empty() )
			{
				if ( this->_parameters_context_._generate_hashed_digest_bytes_.empty() )
					this->_parameters_context_._generate_hashed_digest_bytes_.assign( module_generate_hashed_digest_bytes.begin(), module_generate_hashed_digest_bytes.end() );
				else
					this->_parameters_context_._generate_hashed_digest_bytes_.swap( module_generate_hashed_digest_bytes );
			}
		}

		template<HashedDigestConcept HashedDigestType>
		requires std::is_same_v<HashedDigestType, std::vector<std::uint8_t>>
		std::vector<std::uint8_t> GetHashedDigest()
		{
			return this->_module_generate_hashed_digest_bytes_;
		}

		template<HashedDigestConcept HashedDigestType>
		requires std::is_same_v<HashedDigestType, std::string>
		std::string GetHashedDigest()
		{
			return UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString
			(
				{ this->_module_generate_hashed_digest_bytes_.begin(), this->_module_generate_hashed_digest_bytes_.end() } 
			);
		}

		template<HashedDigestConcept HashedDigestType>
		std::optional<HashedDigestType> DoHash()
		{
			this->ComputeHashValue();

			if ( this->_module_generate_hashed_digest_bytes_.empty() )
				return std::nullopt;
			else
				return this->GetHashedDigest<HashedDigestType>();
		}

		void SetHashWorkerState()
		{
			if(this->hash_worker_is_used.test() == false)
				this->hash_worker_is_not_used = this->hash_worker_is_used.test_and_set();
		}

	public:
		template<HashedDigestConcept HashedDigestType>
		void Hash(const std::vector<std::uint8_t>& message_or_password_bytes, const std::vector<std::uint8_t>& salt_bytes, HashedDigestType& generate_hashed_data)
		{
			if ( this->GetHashWorkerState() == true )
			{
				std::cout << "Argon2 Information: Please reset the hash worker state and retry !" << std::endl;
				return;
			}

			std::optional<bool> compared_result_with_hashed_bytes = (_parameters_context_._message_or_password_bytes_ == message_or_password_bytes);

			if(!compared_result_with_hashed_bytes.value())
				_parameters_context_._message_or_password_bytes_.assign(message_or_password_bytes.begin(), message_or_password_bytes.end());

			compared_result_with_hashed_bytes = (_parameters_context_._salt_disorderly_bytes_ == salt_bytes);

			if(!compared_result_with_hashed_bytes.value())
				_parameters_context_._salt_disorderly_bytes_.assign(salt_bytes.begin(), salt_bytes.end());

			std::optional<HashedDigestType> optional_module_generate_hashed_digest_bytes = this->DoHash<HashedDigestType>();
			if ( optional_module_generate_hashed_digest_bytes.has_value() )
			{
				bool whether_hash_byte_from_message_password = false;

				whether_hash_byte_from_message_password = std::ranges::equal(generate_hashed_data, optional_module_generate_hashed_digest_bytes.value());

				if ( whether_hash_byte_from_message_password == true )
					std::cout << "Argon2 Warning: Duplicate hashed data found! It doesn't make any sense to produce an output that matches the input in a computational hash function." << std::endl;
				
				this->SetHashedDigestByte( optional_module_generate_hashed_digest_bytes.value() );
				this->SetHashWorkerState();

				std::cout << "Argon2 Infomation: Hashed digest data of the original data has been generated." << std::endl;
					
				if constexpr ( std::same_as<HashedDigestType, std::vector<std::uint8_t>> )
					generate_hashed_data = _parameters_context_._generate_hashed_digest_bytes_;
				else if ( std::same_as<HashedDigestType, std::string> )
					generate_hashed_data = UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString(_parameters_context_._generate_hashed_digest_bytes_);
			}
			else
				throw std::runtime_error("Argon2 Fatal: An unknown error has occurred in this hash worker!");
		}

		template<HashedDigestConcept HashedDigestType>
		void Hash(HashedDigestType& generate_hashed_bytes)
		{
			this->Hash<HashedDigestType>(this->_parameters_context_._message_or_password_bytes_, this->_parameters_context_._salt_disorderly_bytes_, generate_hashed_bytes);
		}

		//The argon2 module object is same ?
		bool operator==(const Argon2_Parameters& other_parameters_context)
		{
			if ( this->GetHashWorkerState() == false )
			{
				std::cout << "Argon2 Information: Since the current status of this hash worker is unused, the validation operation will always mismatch!" << std::endl;
				return false;
			}

			bool is_same_argon2_module_object = false;

			is_same_argon2_module_object = std::cmp_equal
			(
				this->_parameters_context_._requested_execute_iteration_time_cost_,
				other_parameters_context._requested_execute_iteration_time_cost_
			);

			is_same_argon2_module_object = std::cmp_equal
			(
				this->_parameters_context_._requested_memory_block_space_cost_,
				other_parameters_context._requested_memory_block_space_cost_
			);

			is_same_argon2_module_object = std::cmp_equal
			(
				this->_parameters_context_._parallelism_lanes_and_rows_number_,
				other_parameters_context._parallelism_lanes_and_rows_number_
			);

			is_same_argon2_module_object = std::ranges::equal
			(
				this->_parameters_context_._message_or_password_bytes_.begin(),
				this->_parameters_context_._message_or_password_bytes_.end(),
				other_parameters_context._message_or_password_bytes_.begin(),
				other_parameters_context._message_or_password_bytes_.end()
			);

			is_same_argon2_module_object = std::ranges::equal
			(
				this->_parameters_context_._salt_disorderly_bytes_.begin(),
				this->_parameters_context_._salt_disorderly_bytes_.end(),
				other_parameters_context._salt_disorderly_bytes_.begin(),
				other_parameters_context._salt_disorderly_bytes_.end()
			);

			return is_same_argon2_module_object;
		}

		//Verify that the hash bytes are transformed one-way by the message password.
		bool VerifyHashedData(const std::vector<std::uint8_t>& other_generate_hashed_digest_bytes)
		{
			std::vector<std::uint8_t> generate_hashed_digest_bytes;
			
			if(!std::ranges::equal(this->_parameters_context_._generate_hashed_digest_bytes_, other_generate_hashed_digest_bytes))
			{
				this->Hash(this->_parameters_context_._message_or_password_bytes_, this->_parameters_context_._salt_disorderly_bytes_, generate_hashed_digest_bytes);
			}
			else
			{
				return true;
			}

			if ( generate_hashed_digest_bytes.empty() && other_generate_hashed_digest_bytes.empty() )
			{
				std::cout << "Argon2 Error: The two hash bytes used for comparison, both of which are empty size!" << std::endl;
				return false;
			}
			else if ( generate_hashed_digest_bytes.size() != other_generate_hashed_digest_bytes.size() )
			{
				std::cout << "Argon2 Warning: The hashed password size does not match the supplied hash size!" << std::endl;
				return false;
			}
			else
			{
				bool whether_same_bytes = std::ranges::equal( generate_hashed_digest_bytes.begin(), generate_hashed_digest_bytes.end(), other_generate_hashed_digest_bytes.begin(), other_generate_hashed_digest_bytes.end() );
				if ( whether_same_bytes )
					std::cout << "Argon2 Information: The hashed password does match the supplied hash!" << std::endl;
				else
					std::cout << "Argon2 Information: The hashed password does not match the supplied hash!" << std::endl;

				return whether_same_bytes;
			}
		}

		//Verify that the hash string are transformed one-way by the message password.
		bool VerifyHashedData(const std::string& other_generate_hashed_digest_string)
		{
			std::vector<std::uint8_t> generate_hashed_digest_bytes;
			this->Hash(this->_parameters_context_._message_or_password_bytes_, this->_parameters_context_._salt_disorderly_bytes_, generate_hashed_digest_bytes);
			
			std::string generate_hashed_digest_string = UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString(this->_parameters_context_._generate_hashed_digest_bytes_);

			if ( generate_hashed_digest_string.empty() && other_generate_hashed_digest_string.empty() )
			{
				std::cout << "Argon2 Error: The two hash string used for comparison, both of which are empty size!" << std::endl;
				return false;
			}
			else if ( generate_hashed_digest_string.size() != other_generate_hashed_digest_string.size() )
			{
				std::cout << "Argon2 Warning: The hashed password size does not match the supplied hash size!" << std::endl;
				return false;
			}
			else
			{
				bool whether_same_string
				(
					generate_hashed_digest_string == other_generate_hashed_digest_string
				);

				if ( whether_same_string )
					std::cout << "Argon2 Information: The hashed password does match the supplied hash!" << std::endl;
				else
					std::cout << "Argon2 Information: The hashed password does not match the supplied hash!" << std::endl;

				return whether_same_string;
			}
		}

		const bool GetHashWorkerState() const
		{
			if ( this->hash_worker_is_used.test() == false && this->hash_worker_is_not_used == true )
				return false;
			else if ( this->hash_worker_is_used.test() == true && this->hash_worker_is_not_used == false )
				return true;
			else
				return false;
		}

		void ResetHashWorkerState()
		{
			if ( this->GetHashWorkerState() == false )
				return;
			
			if(this->hash_worker_is_used.test() == true)
			{
				this->hash_worker_is_used.clear();
				this->hash_worker_is_used.notify_all();
				this->hash_worker_is_not_used = true;
			}
		}

		void SetParametersContext(Argon2_Parameters& argon2_parameters_context)
		{
			//首先销毁自身管理的Argon2参数对象，然后由其他Argon2参数对象重新构造它
			//First destroy the Argon2 parameter object managed by itself, and then reconstruct it from other Argon2 parameter objects
			this->_parameters_context_ = std::move(argon2_parameters_context);
		}

		void Clear()
		{
			_parameters_context_._message_or_password_bytes_.clear();
			_parameters_context_._message_or_password_bytes_.shrink_to_fit();

			_parameters_context_._salt_disorderly_bytes_.clear();
			_parameters_context_._salt_disorderly_bytes_.shrink_to_fit();

			_parameters_context_._process_secret_key_bytes_.clear();
			_parameters_context_._process_secret_key_bytes_.shrink_to_fit();

			_parameters_context_._process_extra_data_bytes_.clear();
			_parameters_context_._process_extra_data_bytes_.shrink_to_fit();
		}

		explicit Argon2(const Argon2_Parameters& argon2_parameters_context) noexcept
			:
			_parameters_context_(argon2_parameters_context)
		{
			
		}

		explicit Argon2(Argon2_Parameters&& argon2_parameters_context) noexcept
			:
			_parameters_context_(std::move(argon2_parameters_context))
		{
			
		}

		~Argon2() = default;
	};

	inline std::ostream& operator<<(std::stringstream& output_stream, const Argon2& argon2_object)
	{
		/*
				Argon2: encode hash bytes and salt bytes into base64 strings and then format the strings
				Argon2：提供哈希字节和盐字节，编码为base64字符串，然后格式化这个字符串
		*/

		const Argon2_Parameters& argon2_parameters_context = argon2_object._parameters_context_;

		if ( argon2_object.GetHashWorkerState() == true )
		{
			const std::vector<std::uint8_t> zero_bytes(argon2_parameters_context._salt_disorderly_bytes_size_,0);
				
			bool is_same_bytes = argon2_parameters_context._salt_disorderly_bytes_ == zero_bytes;
			if ( is_same_bytes )
			{
				std::cout << "Argon2 Warning: The disorder byte size of the salt is the same as the zero byte !" << std::endl;
				return output_stream;
			}

			is_same_bytes = argon2_parameters_context._generate_hashed_digest_bytes_ == zero_bytes;
			if ( is_same_bytes )
			{
				return output_stream;
			}

		}
		else
		{
			throw std::invalid_argument("Argon2 Error: Since the current state of that hash worker is unused, it's impossible to extract the salt bytes and hash data!");
		}

		std::string argon2_parameters_salt_string = UtilTools::DataFormating::Base64Coder::Author5::Base64::encode
		(
			argon2_parameters_context._salt_disorderly_bytes_.data(),
			argon2_parameters_context._salt_disorderly_bytes_.size()
		);

		//Remove characters "=="
		std::size_t found_index = argon2_parameters_salt_string.find("==", argon2_parameters_salt_string.size() - 5);
		if(found_index != std::string::npos)
		{
			argon2_parameters_salt_string.erase(found_index, 2);
		}

		std::string argon2_parameters_hashed_string = UtilTools::DataFormating::Base64Coder::Author5::Base64::encode
		(
			argon2_parameters_context._generate_hashed_digest_bytes_.data(),
			argon2_parameters_context._generate_hashed_digest_bytes_.size()
		);

		found_index = argon2_parameters_hashed_string.find("==", argon2_parameters_hashed_string.size() - 5);
		if(found_index != std::string::npos)
		{
			argon2_parameters_hashed_string.erase(found_index, 2);
		}

		output_stream << "$"
		<< argon2_parameters_context._hash_mode_type_string_
		<< "$v=" << static_cast<std::uint32_t>(argon2_parameters_context._algorithm_version_)
		<< "$m=" << argon2_parameters_context._requested_memory_block_space_cost_ << ","
		<< "t=" <<argon2_parameters_context._requested_execute_iteration_time_cost_ << ","
		<< "p=" << argon2_parameters_context._parallelism_lanes_and_rows_number_
		<< "$" << argon2_parameters_salt_string << "$" << argon2_parameters_hashed_string;

		return output_stream;
	}

	inline std::istream& operator>>(std::stringstream& input_stream, Argon2& argon2_object)
	{
		/*
				Argon2: parse this formatted string, then hash bytes and salt bytes, decode from base64 string
				Argon2：解析这个格式化的字符串，然后哈希字节和盐字节，来自base64字符串解码
		*/

		std::string argon2_base64_string = input_stream.str();

		if ( argon2_base64_string.empty() )
			throw std::invalid_argument("Argon2 Error: This string cannot be empty!");

		/*
		std::uint32_t parsing_part_number = 0;

		for( auto& argon2_base64_character : argon2_base64_string )
		{
			if( argon2_base64_character == '$' || argon2_base64_character == ',' )
			{
				++parsing_part_number;
				continue;
			}

			switch (parsing_part_number)
			{
				case 1:
					hash_mode_type_string.push_back(argon2_base64_character);
					break;
				case 2:
					if ( argon2_base64_character != 'v' && argon2_base64_character != '=' )
						algorithm_version_string.push_back(argon2_base64_character);
					break;
				case 3:
					if ( argon2_base64_character != 'm' && argon2_base64_character != '=' )
						memory_space_cost_string.push_back(argon2_base64_character);
					break;
				case 4:
					if ( argon2_base64_character != 't' && argon2_base64_character != '=' )
						time_iterations_cost.push_back(argon2_base64_character);
					break;
				case 5:
					if ( argon2_base64_character != 'p' && argon2_base64_character != '=' )
						parallelism_factor_string.push_back(argon2_base64_character);
					break;
				case 6:
					salt_disorderly_bytes_data_string.push_back(argon2_base64_character);
					break;
				case 7:
					generate_hashed_bytes_data_string.push_back(argon2_base64_character);
					break;
				default:
					break;
			}
		}
		*/

		HashModeTypeStringAlphabetFormat hash_mode_type_string_alpha_format;
		HashModeType hash_mode_type;
		AlgorithmVersion algorithm_version;
		std::uint32_t memory_space_cost;
		std::uint32_t time_iterations_cost;
		std::uint32_t parallelism_factor;

		std::size_t found_index = argon2_base64_string.find('$');
		if ( found_index == std::string::npos )
			throw std::invalid_argument("Argon2 Error: This is not vaild formatted string! (0)");
		else
		{
			if( argon2_base64_string[1] == 'a' || argon2_base64_string[1] == 'A' )
			{
				if ( argon2_base64_string[1] == 'a' )
				{
					hash_mode_type_string_alpha_format = HashModeTypeStringAlphabetFormat::LOWER_CASE;
					std::string_view view_part("$Argon2");
					found_index += view_part.size();
				}
				else if ( argon2_base64_string[1] == 'A' )
				{
					hash_mode_type_string_alpha_format = HashModeTypeStringAlphabetFormat::UPPER_CASE;
					std::string_view view_part("$argon2");
					found_index += view_part.size();
				}

				if ( argon2_base64_string[found_index] == 'i' && argon2_base64_string[found_index + 1] == 'd' )
				{
					hash_mode_type = HashModeType::MixedAddressing;
					found_index += 2;
				}
				else if ( argon2_base64_string[found_index] == 'd' && argon2_base64_string[found_index + 1] == 's' )
				{
					hash_mode_type = HashModeType::SubstitutionBox;
					found_index += 2;
				}
				else if ( argon2_base64_string[found_index] == 'd' )
				{
					hash_mode_type = HashModeType::DependentAddressing;
					found_index += 1;
				}
				else if ( argon2_base64_string[found_index] == 'i' )
				{
					hash_mode_type = HashModeType::IndependentAddressing;
					found_index += 1;
				}
			}
			else
			{
				throw std::invalid_argument("Argon2 Error: This is not vaild formatted string! (1)");
			}
		}

		found_index = argon2_base64_string.find("$v=", found_index);
		if ( found_index != std::string::npos )
		{
			std::string_view view_part("$v=");
			found_index += view_part.size();

			std::string algorithm_version_string;

			while ( argon2_base64_string[found_index] != '$')
			{
				algorithm_version_string.push_back(argon2_base64_string[found_index]);
				++found_index;
			}

			algorithm_version = static_cast<AlgorithmVersion>(std::stoi(algorithm_version_string));
		}
		else
			throw std::invalid_argument("Argon2 Error: This is not vaild formatted string! (2)");

		if ( argon2_base64_string[found_index] == '$' && argon2_base64_string[found_index + 1] == 'm' && argon2_base64_string[found_index + 2] == '=' )
		{
			std::string_view view_part("$m=");
			found_index += view_part.size();

			std::string memory_space_cost_string;

			while ( argon2_base64_string[found_index] != ',')
			{
				memory_space_cost_string.push_back(argon2_base64_string[found_index]);
				++found_index;
			}

			memory_space_cost = std::stoi(memory_space_cost_string);
		}
		else
			throw std::invalid_argument("Argon2 Error: This is not vaild formatted string! (3)");

		if ( argon2_base64_string[found_index] == ',' && argon2_base64_string[found_index + 1] == 't' && argon2_base64_string[found_index + 2] == '=' )
		{
			std::string_view view_part(",t=");
			found_index += view_part.size();

			std::string time_iterations_cost_string;

			while ( argon2_base64_string[found_index] != ',')
			{
				time_iterations_cost_string.push_back(argon2_base64_string[found_index]);
				++found_index;
			}

			time_iterations_cost = std::stoi(time_iterations_cost_string);
		}
		else
			throw std::invalid_argument("Argon2 Error: This is not vaild formatted string! (4)");

		if ( argon2_base64_string[found_index] == ',' && argon2_base64_string[found_index + 1] == 'p' && argon2_base64_string[found_index + 2] == '=' )
		{
			std::string_view view_part(",p=");
			found_index += view_part.size();

			std::string parallelism_factor_string;

			while ( argon2_base64_string[found_index] != '$')
			{
				parallelism_factor_string.push_back(argon2_base64_string[found_index]);
				++found_index;
			}

			parallelism_factor = std::stoi(parallelism_factor_string);
		}
		else
			throw std::invalid_argument("Argon2 Error: This is not vaild formatted string! (5)");

		std::vector<std::uint8_t> salt_disorderly_bytes_data;

		if ( argon2_base64_string.find('$', found_index) != std::string::npos )
		{
			found_index += 1;

			std::string salt_disorderly_data_string;

			while ( argon2_base64_string[found_index] != '$')
			{
				salt_disorderly_data_string.push_back(argon2_base64_string[found_index]);
				++found_index;
			}

			salt_disorderly_bytes_data = UtilTools::DataFormating::Base64Coder::Author5::Base64::decode(salt_disorderly_data_string);
		}
		else
			throw std::invalid_argument("Argon2 Error: This is not vaild formatted string! (6)");

		std::vector<std::uint8_t> generate_hashed_bytes_data;

		if ( argon2_base64_string.find('$', found_index) != std::string::npos )
		{
			found_index += 1;

			std::string generate_hashed_data_string;

			while ( argon2_base64_string[found_index] != '$' && found_index < argon2_base64_string.size())
			{
				generate_hashed_data_string.push_back(argon2_base64_string[found_index]);
				++found_index;
			}

			generate_hashed_bytes_data = UtilTools::DataFormating::Base64Coder::Author5::Base64::decode(generate_hashed_data_string);
		}
		else
			throw std::invalid_argument("Argon2 Error: This is not vaild formatted string! (7)");

		argon2_object._parameters_context_ = std::move
		(
			Argon2_Parameters
			(
				generate_hashed_bytes_data,
				generate_hashed_bytes_data.size(),
				std::vector<std::uint8_t>(),
				salt_disorderly_bytes_data,
				time_iterations_cost,
				memory_space_cost,
				parallelism_factor,
				0,
				false,
				false,
				false,
				false,
				hash_mode_type_string_alpha_format,
				algorithm_version,
				hash_mode_type
			)
		);

		if ( argon2_object.GetHashWorkerState() == false )
			argon2_object.SetHashWorkerState();

		return input_stream;
	}

	/*
	
	inline std::optional<std::vector<std::uint8_t>> MakeHashByteStreamWithKeyDerivation
	(
		const std::vector<std::uint8_t>& message_or_password_bytes,
		const std::vector<std::uint8_t>& salt_disorderly_bytes,
		std::uint32_t parallelism_block_row_number,
		std::uint32_t generate_hashed_digest_size,
		std::uint32_t reserve_memory_block_kilobyte_size,
		std::uint32_t execute_iteration_number,
		const std::vector<std::uint8_t>& optional_process_secret_key_bytes,
		const std::vector<std::uint8_t>& optional_extra_data_bytes,
		HashModeType algorithm_mode_type_number
	)
	{
		
		
	}

	*/
}