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

namespace CommonSecurity::AES::DefineConstants
{
	//
	//Row is 0x?0
	//Column is 0x0?
	//Example: 0x00 <-> 0x63
	//1. Search Forward_S_Box, the row is 0 and the column is 0, then find the data 0x63
	//2. Search Backward_S_Box, the row is 6 and the column is 3, then find the data 0x00
	//
	//例子：0x00 <-> 0x63
	//1.搜索Forward_S_Box，行是0和列是0，然后找到数据0x63
	//2.搜索Backward_S_Box，行是6和列是3，然后找到数据0x00
	static constexpr std::array<std::array<unsigned char, 16>, 16> Forward_S_Box
	{
		{
			{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
			{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
			{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
			{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
			{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
			{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
			{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
			{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
			{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
			{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
			{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
			{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
			{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
			{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
			{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
			{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
		},
	};

	static constexpr std::array<std::array<unsigned char, 16>, 16> Backward_S_Box
	{
		{
			{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
			{0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
			{0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
			{0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
			{0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
			{0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
			{0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
			{0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
			{0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
			{0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
			{0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
			{0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
			{0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
			{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
			{0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
			{0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
		},
	};

	#if 0

	// Galois field Multiplication lookup tables
	// 伽罗瓦场乘法查询表
	// Size is 15 * 256
	static const std::vector<std::vector<unsigned char>> GF_Multiplication_Lookup_Table
	{
		{},

		{},

		// Multiplication by 2
		{
			0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
			0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
			0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
			0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
			0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
			0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
			0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
			0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
			0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
			0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
			0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
			0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
			0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
			0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
			0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
			0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
		},

		// Multiplication by 3
		{
			0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
			0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
			0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
			0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
			0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
			0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
			0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
			0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
			0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
			0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
			0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
			0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
			0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
			0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
			0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
			0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
		},

		{},

		{},

		{},

		{},

		{},

		// Multiplication by 9
		{
		  0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
		  0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
		  0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
		  0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
		  0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
		  0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
		  0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
		  0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
		  0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
		  0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
		  0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
		  0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
		  0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
		  0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
		  0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
		  0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46
		},

		{},

		// Multiplication by 11
		{
		  0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
		  0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
		  0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
		  0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
		  0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
		  0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
		  0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
		  0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
		  0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
		  0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
		  0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
		  0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
		  0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
		  0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
		  0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
		  0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
		},

		{},

		// Multiplication by 13
		{
		  0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
		  0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
		  0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
		  0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
		  0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
		  0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
		  0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
		  0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
		  0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
		  0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
		  0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
		  0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
		  0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
		  0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
		  0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
		  0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97
		},

		// Multiplication by 14
		{
		  0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
		  0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
		  0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
		  0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
		  0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
		  0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
		  0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
		  0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
		  0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
		  0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
		  0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
		  0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
		  0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
		  0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
		  0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
		  0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
		}
	};

	// Constant matrix for mix columns step
	// 用于混合列步骤的恒定矩阵

	// 环形MDS矩阵
	// Circulant MDS matrix
	static constexpr std::array<std::array<unsigned char, 4>, 4> CMDS
	{
		{
			{0x02, 0x03, 0x01, 0x01},
			{0x01, 0x02, 0x03, 0x01},
			{0x01, 0x01, 0x02, 0x03},
			{0x03, 0x01, 0x01, 0x02}
		},
	};

	// 反环形MDS矩阵
	// Inverse circulant MDS matrix
	static constexpr std::array<std::array<unsigned char, 4>, 4> INVERSE_CMDS
	{
		{
			{0x0E, 0x0B, 0x0D, 0x09},
			{0x09, 0x0E, 0x0B, 0x0D},
			{0x0D, 0x09, 0x0E, 0x0B},
			{0x0B, 0x0D, 0x09, 0x0E}
		},
	};

	static constexpr std::array<std::array<unsigned char, 4>, 11> KeyRoundConstants
	{
		{
			{0x00, 0x00, 0x00, 0x00},
			{0x01, 0x00, 0x00, 0x00},
			{0x02, 0x00, 0x00, 0x00},
			{0x04, 0x00, 0x00, 0x00},
			{0x08, 0x00, 0x00, 0x00},
			{0x10, 0x00, 0x00, 0x00},
			{0x20, 0x00, 0x00, 0x00},
			{0x40, 0x00, 0x00, 0x00},
			{0x80, 0x00, 0x00, 0x00},
			{0x1b, 0x00, 0x00, 0x00},
			{0x36, 0x00, 0x00, 0x00}
		},
	};

	#endif
}

namespace CommonSecurity::AES::ProcedureFunctions
{
	//For Key Schedule

	/**
		In computing, the modulo operation returns the remainder or signed remainder of a division, after one number is divided by another (called the modulus of the operation).
		Given two positive numbers a and n, a modulo n (abbreviated as a mod n) is the remainder of the Euclidean division of a by n, where a is the dividend and n is the divisor.
		The modulo operation is to be distinguished from the symbol mod, which refers to the modulus[1] (or divisor) one is operating from.
		For example, the expression "5 mod 2" would evaluate to 1, because 5 divided by 2 has a quotient of 2 and a remainder of 1, while "9 mod 3" would evaluate to 0
		Because the division of 9 by 3 has a quotient of 3 and a remainder of 0; there is nothing to subtract from 9 after multiplying 3 times 3.
		Although typically performed with a and n both being integers, many computing systems now allow other types of numeric operands.
		The range of values for an integer modulo operation of n is 0 to n − 1 inclusive (a mod 1 is always 0; a mod 0 is undefined, possibly resulting in a division by zero error in some programming languages).
		See Modular arithmetic for an older and related convention applied in number theory.
		When exactly one of a or n is negative, the naive definition breaks down, and programming languages differ in how these values are defined.

		模除（又称模数、取模操作、取模运算等，英语：modulo 有时也称作 modulus
		得到的是一个数除以另一个数的余数。
		给定两个正整数：被除数 a 和除数 n，a modulo n (缩写为 a mod n)
		得到的是使用欧几里德除法时 a/n 的余数。
		举个例子：计算表达式 "5 mod 2" 得到 1，因为 5÷2=2...1（5 除以 2 商 2 余1）；而 "9 mod 3" 得到 0，因为 9÷3=3...0；
		注意：如果使用计算器做除法，不能整除时，你不会得到商，而是会得到一个小数，如：5÷2=2.5。
		虽然通常情况下 a 和 n 都是整数，但许多计算系统允许其他类型的数字操作，如：对浮点数取模。
		一个整数对 n 取模的结果范围为： 0 到 n − 1（a mod 1 恒等于 0；a mod 0 则是未定义的，在编程语言里可能会导致除零错误）。
		有关概念在数论中的应用请参阅模算数。
		当 a 和 n 均为负数时，通常的定义就不适用了，不同的编程语言对结果有不同的处理。

		GF is Galois field
			在数学中，有限域（英语：finite field）或伽罗瓦域（英语：Galois field，为纪念埃瓦里斯特·伽罗瓦命名）是包含有限个元素的域。
			与其他域一样，有限域是进行加减乘除运算都有定义并且满足特定规则的集合。
			有限域最常见的例子是当 p 为素数时，整数对 p 取模。
			有限域的元素个数称为它的阶。
			有限域在许多数学和计算机科学领域的基础，包括数论、代数几何、伽罗瓦理论、有限几何学、密码学和编码理论。
			In mathematics, a finite field or Galois field (so-named in honor of Évariste Galois) is a field that contains a finite number of elements.
			As with any field, a finite field is a set on which the operations of multiplication, addition, subtraction and division are defined and satisfy certain basic rules.
			The most common examples of finite fields are given by the integers mod p when p is a prime number.
			The order of a finite field is its number of elements, which is either a prime number or a prime power.
			For every prime number p and every positive integer k there are fields of order p^k, all of which are isomorphic.
			Finite fields are fundamental in a number of areas of mathematics and computer science, including number theory, algebraic geometry, Galois theory, finite geometry, cryptography and coding theory.

		Paper 3.2 Bytes (Part)

			All byte values in the AES algorithm will be presented as the concatenation of its individual bit
			values (0 or 1) between braces in the order
			Byte {bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0}.
			These bytes are
			interpreted as finite field elements using a polynomial representation:

			Mathematical equations 3.1
			bit7*x^7 + bit6*x^6 + bit5*x^5 + bit4*x^4 + bit3*x^3 + bit2*x^2 + bit1*x + bit0

			For example, {01100011} identifies the specific finite field element x
			x^6 + x^5 + x +1.

		Paper 3.2 字节 (部分)

			在AES算法中，所有的字节值都将以其单独的比特值（0或1）的串联形式出现在大括号中。
			值（0或1）在大括号之间的连接，顺序为
			字节{bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0}。
			这些字节被
			被解释为使用多项式表示的有限场元素。

			数学方程式 3.1
			bit7*x^7 + bit6*x^6 + bit5*x^5 + bit4*x^4 + bit3*x^3 + bit2*x^2 + bit1*x + bit0

			例如，{01100011}确定了具体的有限场元素x
			x^6 + x^5 + x +1

		Paper 4. Mathematical Preliminaries
			All bytes in the AES algorithm are interpreted as finite field elements using the notation introduced in Sec. 3.2.
			Finite field elements can be added and multiplied, but these operations are different from those used for numbers.
			The following subsections introduce the basic mathematical concepts needed for Sec. 5.

		论文 4. 数学预演
			在AES算法中，所有的字节都被解释为有限场元素，使用的符号是 3.2节中介绍的符号。
			有限场元素可以被添加和相乘，但这些操作 与用于数字的操作不同。
			下面几个小节介绍了 第5章所需的基本数学概念。

		Parer 4.1 Addition

			The addition of two elements in a finite field is achieved by "adding" the coefficients for the corresponding powers in the polynomials for the two elements.
			The addition is performed with the XOR operation (denoted by (Exclusive-OR) ) - i.e., modulo 2 - so that 1 Exclusive-OR 1 = 0 , 1 Exclusive-OR  0 = 1, and 0 Exclusive-OR 0 = 0 .
			Consequently, subtraction of polynomials is identical to addition of polynomials.

			Alternatively, addition of finite field elements can be described as the modulo 2 addition of corresponding bits in the byte.
			For two bytes {bit_a7,bit_a6,bit_a5,bit_a4,bit_a3,bit_a2,bit_a1,bit_a0} and {bit_b7,bit_b6,bit_b5,bit_b4,bit_b3,bit_b2,bit_b1,bit_b0}, the sum is {bit_c7,bit_c6,bit_c5,bit_c4,bit_c3,bit_c2,bit_c1,bit_c0}
			Where each bit_ci = bit_ai (+) bit_bi (i.e., bit_c7 = bit_a7 (+) bit_b7, bit_c6 = bit_a6 (+) bit_b6, ...... bit_c0 = bit_a0 (+) bit_b0).

			For example, the following expressions are equivalent to one another:
			(x^6 + x^4 + x^2 + x + 1) + (x^7 + x + 1) = x^7 + x^6 + x^4 + x^2 (polynomial notation)
			{01010111} (+) {10000011} = {11010100} (binary notation);
			{57} (+) {83} = {d4} (hexadecimal notation).

		论文 4.1 加法
			有限域中两个元素的相加是通过 "添加 "这两个元素的多项式中的相应幂的系数来实现的。
			加法是通过XOR操作（用(Exclusive-OR)表示）进行的。- 即模数2--因此，1 Exclusive-OR 1 = 0 ，1 Exclusive-OR 0 = 1，0 Exclusive-OR 0 = 0。
			因此，多项式的减法与多项式的加法是相同的。

			另外，有限场元素的加法可以描述为字节中相应位的模2加法。
			对于两个字节{bit_a7,bit_a6,bit_a5,bit_a4,bit_a3,bit_a2,bit_a1,bit_a0}和{bit_b7,bit_b6,bit_b5, bit_b4,bit_b3,bit_b2,bit_b1,bit_b0}，其总和为{bit_c7,bit_c6,bit_c5,bit_c4,bit_c3,bit_c2,bit_c1,bit_c0}。
			其中每个bit_ci = bit_ai (+) bit_bi（即bit_c7 = bit_a7 (+) bit_b7, bit_c6 = bit_a6 (+) bit_b6, ...... bit_c0 = bit_a0 (+) bit_b0）。

			例如，下面的表达式是相互等价的。
			(x^6 + x^4 + x^2 + x + 1) + (x^7 + x + 1) = x^7 + x^6 + x^4 + x^2 (多项式记号)
			{01010111} (+) {10000011} = {11010100}（二进制记法）
			{57}（+）{83}={d4}（十六进制记法）

		Paper 4.2 Multiplication
			In the polynomial representation, multiplication in GF(2^8) (denoted by •) corresponds with the multiplication of polynomials modulo an irreducible polynomial of degree 8.
			A polynomial is irreducible if its only divisors are one and itself.

			For the AES algorithm, this irreducible polynomial is

			Mathematical equations 4.1
			m(x) = x^8 + x^4 + x^3 + x + 1 (4.1)

			Or {01}{1b} in hexadecimal notation.

			For example, {57} • {83} = {c1}

			(x^6 + x^4 + x^2 + x + 1)*(x^7 + x + 1)
			= x^13 + x^11 + x^9 + x^8 + x^7 + x^7 + x^5 + x^3 + x^2 + x + x^6 + x^4 + x^2 + x + 1
			= x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1

			and x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1 modulo (x^8 + x^4 + x^3 + x + 1)
			= x^7 + x^6 + 1

			The modular reduction by m(x) ensures that the result will be a binary polynomial of degree less than 8, and thus can be represented by a byte.
			Unlike addition, there is no simple operation at the byte level that corresponds to this multiplication.
			The multiplication defined above is associative, and the element {01} is the multiplicative identity.
			For any non-zero binary polynomial b(x) of degree less than 8, the multiplicative inverse of b(x), denoted b^-1(x), can be found as follows: the extended Euclidean algorithm [7]
			is used to compute polynomials a(x) and c(x) such that

			Mathematical equations 4.2
			b(x)*a(x) + m(x)*c(x) = 1

			Hence, a(x) • b(x) mod(m(x)) = 1
			which means

			Mathematical equations 4.3
			b^-1 (x) = a(x) mod m(x)
			Moreover, for any a(x), b(x) and c(x) in the field, it holds that
			a(x) • (b(x) + c(x)) = a(x) • b(x) + a(x) • c(x).
			It follows that the set of 256 possible byte values, with (Exclusive-OR operation) used as addition and the multiplication defined as above, has the structure of the finite field GF(2^8).


		论文 4.2 乘法
			在多项式表示中，GF(2^8)中的乘法（用•表示）对应于多项式与8度的不可还原多项式的乘法。
			如果一个多项式的除数只有一个和它本身，那么它就是不可还原的。

			对于AES算法，这个不可还原的多项式是

			数学方程式 4.1
			m(x) = x^8 + x^4 + x^3 + x + 1 (4.1)

			或者是十六进制的{01}{1b}
			例如，{57}•{83}={c1}
			Because (因为):

			(x^6 + x^4 + x^2 + x + 1)*(x^7 + x + 1)
			= x^13 + x^11 + x^9 + x^8 + x^7 + x^7 + x^5 + x^3 + x^2 + x + x^6 + x^4 + x^2 + x + 1
			= x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1

			and x^13 + x^11 + x^9 + x^8 + x^5 + x^4 + x^3 + 1 modulo (x^8 + x^4 + x^3 + x + 1)
			= x^7 + x^6 + 1

			m(x)的模块化还原保证了结果将是一个小于8度的二进制多项式，因此可以用一个字节来表示。
			与加法不同的是，在字节级没有对应于这种乘法的简单操作。
			上面定义的乘法是关联性的，元素{01}是乘法的身份。
			对于任何小于8度的非零二元多项式b(x)，b(x)的乘法逆数，表示为b^-1(x)，可以按如下方法找到：扩展的欧几里得算法[7] 。
			用来计算多项式a(x)和c(x)，以便于
			数学方程式 4.2
			b(x)*a(x)+m(x)*c(x)=1
			因此，a（x）• b（x）mod（m（x））= 1
			这意味着
			数学方程式 4.3
			b^-1 (x) = a(x) mod m(x)
			此外，对于场中的任何a(x), b(x)和c(x)，可以看出
			a(x) - (b(x) + c(x)) = a(x) - b(x) + a(x) - c(x)。
			由此可见，256个可能的字节值的集合，用（Exclusive-OR操作）作为加法，乘法定义如上，具有有限域GF(2^8)的结构。

		Paper 4.2.1 Multiplication by x

			Multiplying the binary polynomial defined in equation (3.1) with the polynomial x results in

			Mathematical equations 4.4
			bit7*x^8 + bit6*x^7 + bit5*x^6 + bit4*x^5 + bit3*x^4 + bit2*x^3 + bit1*x^2 + bit0*x

			The result x • b(x) is obtained by reducing the above result modulo m(x), as defined in math equation (4.1)
			If bit7 = 0, the result is already in reduced form.
			Else bit7 = 1, the reduction is accomplished by subtracting (i.e., (Exclusive-OR operation)ing) the polynomial m(x).
			It follows that multiplication by x (i.e., {00000010} or {02}) can be implemented at the byte level as a left shift and a subsequent conditional bitwise (+) with {1b}.

			This operation on bytes is denoted by xtime().
			Multiplication by higher powers of x can be implemented by repeated application of xtime().
			By adding intermediate results, multiplication by any constant can be implemented.

		论文 4.2.1 乘以x

			将数学方程式（3.1）中定义的二元多项式与多项式x相乘的结果是

			数学方程式4.4
			bit7*x^8 + bit6*x^7 + bit5*x^6 + bit4*x^5 + bit3*x^4 + bit2*x^3 + bit1*x^2 + bit0*x

			结果x-b(x)是通过减少上述结果的模数m(x)得到的，如数学方程(4.1)所定义的那样
			如果binray bit7 = 0，结果已经是还原形式。
			否则binray bit7 = 1, 减少是通过减去（即（Exclusive-OR操作））多项式m(x)来完成的。
			由此可见，x的乘法（即{00000010}或{02}）可以在字节级实现为左移和随后与{1b}的条件性位操作（+）。

			这种对字节的操作用xtime()来表示。
			x的高次幂乘法可以通过重复应用xtime()来实现。
			通过添加中间结果，可以实现与任何常数的乘法。
	*/
	inline unsigned char XTime(unsigned char Xbyte)
	{
		unsigned char bitMask = 0x80, moduloInnumerableMask = 0x1b;
		unsigned char highBit = Xbyte & bitMask;

		// Rotate ByteA left (multiply by (?) in GF(2^8))
		Xbyte <<= 1;
		//Xbyte = Xbyte << 1;

		// If LSB is active (equivalent to a '1' in the polynomial of ByteB)
		/* If the polynomial for ByteB has a constant term, add the corresponding ByteA to Result */
		if(highBit)
		{
			// result += ByteA in GF(2^8)
			/* Addition in GF(2^m) is an XOR of the polynomial coefficients */
			Xbyte ^= moduloInnumerableMask;
			//Xbyte = Xbyte ^ moduloInnumerableMask
		}
		return Xbyte;
	}

	/***********************************************************************************************
	* This function implements GF(2^8) mulitplication using a variation of peasent multiplication.
	* This algo takes advantage of multiplication's distributive property.
	*
	* e.g. 4 * 9 = 4 * (1* 2^0 + 0 * 2^1 + 0 * 2^2 + 1 * 2^3)
	* by the modulo polynomial relation x^8 + x^4 + x^3 + x + 1 = 0
	* (the other way being to do carryless multiplication followed by a modular reduction)
	*
	* Algorithm described in...
	* https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	***********************************************************************************************/
	inline unsigned char MultiplicationOfByteWithGaloisField(unsigned char ByteA, unsigned char ByteB)
	{
		// Taken and documented from https://en.wikipedia.org/wiki/Rijndael_MixColumns

		/* Accumulator for the product of the multiplication */
		unsigned char result = 0x00;
		const unsigned char BitMask = 0x01;

		for (int counter = 0; counter < 8; ++counter)
		{
			//ByteA is LeftByteData
			//ByteB is RightByteData

			// ByteA >= 128 = 0b0100'0000
			/* GF modulo: if a has a nonzero term x^7, then must be reduced when it becomes x^8 */
			unsigned char Bit = (ByteB & BitMask);

			if (Bit != static_cast<unsigned char>(0x00))
			{
				unsigned XByte = ByteA;

				for (int counter2 = 0; counter2 < counter; ++counter2)
				{
					XByte = XTime(XByte);
				}

				// Must reduce
				// ByteA -= 00011011 == modulo(x^8 + x^4 + x^3 + x + 1) = AES irreducible
				/* Subtract (XOR) the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1'0001'1011) – you can change it but it must be irreducible */
				result ^= XByte;
				//result = result ^ Xbyte
			}
			// Rotate ByteB right (divide by (?) in GF(2^8))
			ByteB >>= 1;
			//ByteB = ByteB >> 1;
		}

		return result;
	}

	//The generate round constant word from array index
	//从数组索引生成每轮常数字
	inline void RCON(std::array<unsigned char, 4>& Word, int roundCount)
	{
		//Byte data

		unsigned char constantByteForThisRound { 1 };

		for(signed int indexCount = 0; indexCount < roundCount - 1; ++indexCount)
		{
			constantByteForThisRound = XTime(constantByteForThisRound);
		}

		Word[0] = constantByteForThisRound;
		Word[1] = Word[2] = Word[3] = 0;
	}

	inline void AES_ExclusiveOR_ByteDataBlock
	(
		const std::vector<unsigned char> ADataBlock,
		const std::vector<unsigned char> BDatalock,
        std::vector<unsigned char> &CDataBlock,
		unsigned int count
	)
    {
        for (unsigned int index = 0; index < count; ++index)
			CDataBlock.operator[](index) = ADataBlock.operator[](index) ^ BDatalock.operator[](index);
    }

	template<std::size_t SIZE_OF_WORD>
	std::array<unsigned char, SIZE_OF_WORD> ExclusiveOR_Words
	(
		const std::array<unsigned char, SIZE_OF_WORD> &lhs,
		const std::array<unsigned char, SIZE_OF_WORD> &rhs
	)
	{
		std::array<unsigned char, SIZE_OF_WORD> result;
		std::ranges::transform
		(
			rhs.begin(),
			rhs.end(),
			lhs.begin(),
			result.begin(),
			[](const unsigned char &rhs_byte, const unsigned char &lhs_byte) -> unsigned char
			{
				return rhs_byte ^ lhs_byte;
			}
		);
		return result;
	}

	//在密钥扩展例程中使用的函数，它接收一个四字节的输入字，并对四个字节中的每个字节应用一个S-box，以产生一个输出字。
	//Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word.
	inline void KeyWordAES_Subtitute(std::array<unsigned char, 4>& Word)
	{
		using namespace AES::DefineConstants;

		std::ranges::transform
		(
			Word.begin(),
			Word.end(),
			Word.begin(),
			[](const unsigned char &byte) -> unsigned char
			{
				return Forward_S_Box[byte / 16][byte % 16];
			}
		);
	}

	inline void KeyWordAES_LeftRotate(unsigned int& Word)
	{
		//Double Word
		auto temporaryWord = CommonSecurity::Binary_LeftRotateMove<unsigned int>(Word, 4);
		Word = temporaryWord;
	}

	inline void KeyWordAES_LeftRotate(std::array<unsigned char, 4>& Word)
	{
		/*
			Example Code:
			for (int k{}; k != 5; ++k) {
				std::iota(s.begin(), s.end(), 'A');
				std::ranges::rotate(s, s.begin() + k);
				std::cout << "Rotate left (" << k << "): " << s << '\n';
			}

			std::cout << '\n';

			for (int k{}; k != 5; ++k) {
				std::iota(s.begin(), s.end(), 'A');
				std::ranges::rotate(s, s.end() - k);
				std::cout << "Rotate right (" << k << "): " << s << '\n';
			}
		*/

		//std::ranges::rotate(Word, Word.begin() + 1);
		std::ranges::rotate(Word.begin(), Word.begin() + 1, Word.end());
	}

	//inline void RCON(std::vector<unsigned char>& Word, int roundCount)
	//{
	//	//Byte data
	//	unsigned char constantByteForThisRound = unsigned char(1);
	//
	//	for(int indexCount = 0; indexCount < roundCount - 1; ++indexCount)
	//	{
	//		constantByteForThisRound = XTime(constantByteForThisRound);
	//	}
	//
	//	Word.operator[](0) = constantByteForThisRound;
	//	Word.operator[](1) = Word.operator[](2) = Word.operator[](3) = unsigned char(0);
	//}

	/*
		The MixColumns() transformation operates on the State column-by-column, treating each column as a four-term polynomial as described in Sec. 4.3.
		The columns are considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a fixed polynomial a(x), given by

		Mathematical equations 5.5
		a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

		Mathematical equations 5.6
		As described in Sec. 4.3, this can be written as a matrix multiplication.
		state' = a(x) (*) state(x):

		As a result of this multiplication, the four bytes in a column are replaced by the following:
		state'[0][column] = ({02} • state[0][column]) (+) ({03} • state[1][column]) (+) state[2][column] (+) state[3][column]
		state'[1][column] = state[0][column] (+) ({02} • state[1][column]) (+) ({03} • state[2][column]) (+) state[3][column]
		state'[2][column] = state[0][column] (+) state[1][column] (+) ({02} • state[2][column]) (+) ({03} • state[3][column])
		state'[3][column] = ({03} • state[0][column]) (+) state[1][column] (+) state[2][column] (+) ({02} • state[3][column])

		MixColumns()转换对状态逐列操作，如第4.3节所述，将每一列作为一个四项多项式处理。
		这些列被视为GF(2^8)上的多项式，并与固定的多项式a(x)相乘以x^4+1，给出如下

		数学公式5.5
		a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

		数学方程5.6
		如第4.3节所述，这可以写成一个矩阵乘法。
		state' = a(x) (*) state(x)

		作为这个乘法的结果，一列中的四个字节被替换成以下内容:
		state'[0][column] = ({02} • state[0][column]) (+) ({03} • state[1][column]) (+) state[2][column] (+) state[3][column]
		state'[1][column] = state[0][column] (+) ({02} • state[1][column]) (+) ({03} • state[2][column]) (+) state[3][column]
		state'[2][column] = state[0][column] (+) state[1][column] (+) ({02} • state[2][column]) (+) ({03} • state[3][column])
		state'[3][column] = ({03} • state[0][column]) (+) state[1][column] (+) state[2][column] (+) ({02} • state[3][column])

		In the MixColumns step, the four bytes of each column of the state are combined using an invertible linear transformation.
		The MixColumns function takes four bytes as input and outputs four bytes, where each input byte affects all four output bytes.
		Together with ShiftRows, MixColumns provides diffusion in the cryptographs.

		在MixColumns步骤中，状态的每一列的四个字节用一个可逆的线性变换进行组合。
		MixColumns函数将四个字节作为输入，并输出四个字节，其中每个输入字节会影响所有四个输出字节。
		与ShiftRows一起，MixColumns在密码器中提供了扩散性。
	*/
	inline void MixColumns(std::array<std::array<unsigned char, 4>, 4>& stateByteDataBlock)
	{
		using namespace AES::DefineConstants;

		// AES_BLOCK_SIDE is 4
		#if 0

		std::deque<std::vector<unsigned char>> _stateByteDataBlock
		{
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0}
		};

		// matrix multiplication in GF(2^8)
		// * => galoisMul, + => ^

		for(unsigned int row = 0; row < 4; ++row)
		{
			for(unsigned int column = 0; column < 4; ++column)
			{
				_stateByteDataBlock.operator[](row).operator[](column) = 0x00;

				// Dot product of row (r) of the MixColumns and the column (c) of the state
				// MixColumns的r行与状态的c列的点积
				_stateByteDataBlock.operator[](row).operator[](column) ^= MultiplicationOfByteWithGaloisField(CMDS.operator[](row).operator[](column), stateByteDataBlock.operator[](row).operator[](column));
			}
		}

		stateByteDataBlock.swap(_stateByteDataBlock);

		_stateByteDataBlock.clear();

		#else

		unsigned char rowDatas[4], columnDatas[4];
		for (int column = 0; column < 4; ++column)
		{
			for (int row = 0; row < 4; ++row)
			{
				rowDatas[row] = stateByteDataBlock[row][column];
			}
			columnDatas[0] = MultiplicationOfByteWithGaloisField(0x02, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[1]) ^ rowDatas[2] ^ rowDatas[3];
			columnDatas[1] = rowDatas[0] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[2]) ^ rowDatas[3];
			columnDatas[2] = rowDatas[0] ^ rowDatas[1] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x03, rowDatas[3]);
			columnDatas[3] = MultiplicationOfByteWithGaloisField(0x03, rowDatas[0]) ^ rowDatas[1] ^ rowDatas[2] ^ MultiplicationOfByteWithGaloisField(0x02, rowDatas[3]);
			for (int row = 0; row < 4; ++row)
			{
				stateByteDataBlock[row][column] = columnDatas[row];
			}
		}

		#endif

	}

	/*

		InvMixColumns() is the inverse of the MixColumns() transformation.
		InvMixColumns() operates on the State column-by-column, treating each column as a fourterm polynomial as described in Sec. 4.3.
		The columns are considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a fixed polynomial a^-1*(x), given by
		Mathematical equations 5.9

		a^-1*x = {0b}*x^3 + {0d}*x^2 + {09}*x + {0e}

		Mathematical equations 5.10
		As described in Sec. 4.3, this can be written as a matrix multiplication.
		state'[x] = a^-1*x (*) state[x]

		As a result of this multiplication, the four bytes in a column are replaced by the following:

		state'[0][column] = ({0e} • state[0][column]) (+) ({0b} • state[1][column]) (+) ({0d} • state[2][column]) (+) ({09} • state[3][column])
		state'[1][column] = ({09} • state[0][column]) (+) ({0e} • state[1][column]) (+) ({0b} • state[2][column]) (+) ({0d} • state[3][column])
		state'[2][column] = ({0d} • state[0][column]) (+) ({09} • state[1][column]) (+) ({0e} • state[2][column]) (+) ({0b} • state[3][column])
		state'[3][column] = ({0b} • state[0][column]) (+) ({0d} • state[1][column]) (+) ({09} • state[2][column]) (+) ({0e} • state[3][column])

		InvMixColumns()是MixColumns()的逆向转换。
		InvMixColumns()对国家逐列操作，如第4.3节所述，将每一列作为一个四项式多项式处理。
		这些列被视为GF(2^8)上的多项式，并与固定的多项式a^-1*(x)相乘以x^4+1，给出如下
		数学方程式 5.9

		a^-1*x = {0b}*x^3 + {0d}*x^2 + {09}*x + {0e}

		数学方程式5.10
		如第4.3节所述，这可以写成一个矩阵乘法。
		state'[x] = a^-1*x (*) state[x]

		作为这个乘法的结果，一列中的四个字节被替换成以下内容:

		state'[0][column] = ({0e} • state[0][column]) (+) ({0b} • state[1][column]) (+) ({0d} • state[2][column]) (+) ({09} • state[3][column])
		state'[1][column] = ({09} • state[0][column]) (+) ({0e} • state[1][column]) (+) ({0b} • state[2][column]) (+) ({0d} • state[3][column])
		state'[2][column] = ({0d} • state[0][column]) (+) ({09} • state[1][column]) (+) ({0e} • state[2][column]) (+) ({0b} • state[3][column])
		state'[3][column] = ({0b} • state[0][column]) (+) ({0d} • state[1][column]) (+) ({09} • state[2][column]) (+) ({0e} • state[3][column])

	*/
	inline void InverseMixColumns(std::array<std::array<unsigned char, 4>, 4>& stateByteDataBlock)
	{
		using namespace AES::DefineConstants;

		// AES_BLOCK_SIDE is 4
		#if 0

		std::deque<std::vector<unsigned char>> _stateByteDataBlock
		{
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0}
		};

		// matrix multiplication in GF(2^8)
		// * => galoisMul, + => ^

		for(unsigned int row = 0; row < 4; ++row)
		{
			for(unsigned int column = 0; column < 4; ++column)
			{
				_stateByteDataBlock.operator[](row).operator[](column) = 0x00;

				// Dot product of row (r) of the InverseMixColumns and the column (c) of the state
				// InverseMixColumns的r行与状态的c列的点积
				_stateByteDataBlock.operator[](row).operator[](column) ^= MultiplicationOfByteWithGaloisField(INVERSE_CMDS.operator[](row).operator[](column), stateByteDataBlock.operator[](row).operator[](column));
			}
		}

		stateByteDataBlock.swap(_stateByteDataBlock);

		_stateByteDataBlock.clear();

		#else

		unsigned char rowDatas[4], columnDatas[4];
		for (int column = 0; column < 4; ++column)
		{
			for (int row = 0; row < 4; ++row)
			{
				rowDatas[row] = stateByteDataBlock[row][column];
			}
			columnDatas[0] = MultiplicationOfByteWithGaloisField(0x0e, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[3]);
			columnDatas[1] = MultiplicationOfByteWithGaloisField(0x09, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[3]);
			columnDatas[2] = MultiplicationOfByteWithGaloisField(0x0d, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0b, rowDatas[3]);
			columnDatas[3] = MultiplicationOfByteWithGaloisField(0x0b, rowDatas[0]) ^ MultiplicationOfByteWithGaloisField(0x0d, rowDatas[1]) ^ MultiplicationOfByteWithGaloisField(0x09, rowDatas[2]) ^ MultiplicationOfByteWithGaloisField(0x0e, rowDatas[3]);
			for (int row = 0; row < 4; ++row)
			{
				stateByteDataBlock[row][column] = columnDatas[row];
			}
		}

		#endif
	}


	//Transformation in the Cipher that processes the State by cyclically shifting the last three rows of the State by different offsets.
	//密码中的转换，通过循环处理状态 将状态的最后三行按不同的偏移量进行移位。

	/*
		In the ShiftRows() transformation, the bytes in the last three rows of the State are cyclically shifted over different numbers of bytes (offsets).
		The first row, r = 0, is not shifted.
		Specifically, the ShiftRows() transformation proceeds as follows:

		Mathematical equations 5.3
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)

		where the shift value shift(row,Nb) depends on the row number, row, as follows (recall that Nb = 4):

		Mathematical equations 5.4
		shift(1,4) = 1;
		shift(2,4) = 2;
		shift(3,4) = 3;

		This has the effect of moving bytes to "lower" positions in the row (i.e., lower values of column in a given row),
		While the "lowest "bytes wrap around into the "top" of the row (i.e., higher values of column in a given row).

		在ShiftRows()转换中，State最后三行的字节在不同的字节数（偏移量）上被循环移位
		第一行，r = 0，不被移位。
		具体来说，ShiftRows()转换的过程如下。

		数学公式5.3
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)

		其中移位值shift(row,Nb)取决于行数row，如下所示（记得Nb=4）

		数学公式5.4
		shift(1,4) = 1;
		shift(2,4) = 2;
		shift(3,4) = 3。

		这样做的效果是将字节移到行中的 "较低 "位置（即在给定行中列的低值）
		而 "最低的 "字节则环绕到行的 "顶部"（即某一行中列的数值较高）

		The ShiftRows step operates on the rows of the state;
		It cyclically shifts the bytes in each row by a certain offset.
		In this way, each column of the output state of the ShiftRows step is composed of bytes from each column of the input state.
		The importance of this step is to avoid the columns being encrypted independently, in which case AES would degenerate into four independent block ciphers.

		ShiftRows步骤对状态的行进行操作。
		它循环地将每一行的字节按一定的偏移量移动。
		这样，ShiftRows步骤的输出状态的每一列都是由输入状态的每一列的字节组成。
		这一步的重要性在于避免各列被独立加密，在这种情况下，AES将退化为四个独立的块密码。
	*/
	inline void ShiftRows(std::array<std::array<unsigned char, 4>, 4>& stateByteDataBlock)
	{
		std::size_t counter = 0;
		for (auto &row : stateByteDataBlock)
		{
			std::ranges::rotate(row.begin(), row.begin() + counter, row.end());
			++counter;
		}
	}

	/*
		This is the inverse of the ShiftRows() transformation.
		The bytes in the last three rows of the State are cyclically shifted over different numbers of bytes (offsets).
		The first row, r = 0, is not shifted.
		The bottom three rows are cyclically shifted by Nb - shift(r, Nb) bytes, where the shift value shift(r,Nb) depends on the row number, and is given in equation (5.4)
		(see Sec. 5.1.2).

		Specifically, the InvShiftRows() transformation proceeds as follows:
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)
		Conditions for variables: 0 < row < 4 and 0 <= column < Nb

		这是ShiftRows()转换的逆运算。
		最后三行的字节在不同的字节数（偏移量）上被循环移位。
		第一行，row = 0，不被移位。
		最下面的三行被循环移位Nb-shift(r,Nb)字节，其中shift(r,Nb)的值取决于行数，在公式(5.4)中给出
		(见第5.1.2节)。

		具体来说，InvShiftRows()转换的过程如下。
		function(State[row], (column + shift(row, Nb))) mod Nb = function(State[row], column)
		变量的条件：0 < row < 4 和 0 <= column < Nb
	*/
	inline void InverseShiftRows(std::array<std::array<unsigned char, 4>, 4>& stateByteDataBlock)
	{
		std::size_t counter = 0;
		for (auto &row : stateByteDataBlock)
		{
			std::ranges::rotate(row.rbegin(), row.rbegin() + counter, row.rend());
			++counter;
		}
	}

	/*
		The SubBytes() transformation is a non-linear byte substitution that operates independently on each byte of the State using a substitution table (S-box).
		This S-box which is invertible, is constructed by composing two transformations:
		1. Take the multiplicative inverse in the finite field GF(2^8), described in Sec. 4.2;
		the element {00} is mapped to itself.
		2. Apply the following affine transformation (over GF(2) ):
		Mathematical equations 5.1
		bit[index] = bit[index] (+) bit[index + 4 mod 8] (+) bit[index + 5 mod 8] (+) bit[index + 6 mod 8] (+) bit[index + 7 mod 8] (+) c[index]

		for 0 <= index < 8 , where bit[index] is the index ^ the bit of the byte, and c[index] is the index ^ the bit of a byte c with the value {63} or {01100011}.
		Here and elsewhere, a prime on a variable (e.g., bit' ) indicates that the variable is to be updated with the value on the right.

		SubBytes()转换是一种非线性的字节替换，它使用一个替换表（S-box）对State的每个字节独立操作。
		这个S-box是可反转的，它是由两个转换组成的。
		1. 在有限域GF(2^8)中进行乘法逆运算，在第4.2节中描述。
		元素{00}被映射到它自己。
		2. 应用下面的仿射变换（在GF(2)上）。
		数学公式5.1
		bit[index] = bit[index] (+) bit[index + 4 mod 8] (+) bit[index + 5 mod 8] (+) bit[index + 6 mod 8] (+) bit[index + 7 mod 8] (+) c[index]
		for 0 <= index < 8 , 其中bit[index]是字节的index ^ the位，c[index]是字节c的index ^ the位，值为{63}或{01100011}。
		在这里和其他地方，变量上的素数（例如，bit'）表示该变量要用右边的值来更新。

		In the SubBytes step, each byte arrays[i][j] in the state array is replaced with a SubByte S-box[arrays[i][j]] using an 8-bit substitution box.
		Note that before round 0, the state array is simply the plaintext/input.
		This operation provides the non-linearity in the cipher.
		The S-box used is derived from the multiplicative inverse over GF(2^8), known to have good non-linearity properties.
		To avoid attacks based on simple algebraic properties, the S-box is constructed by combining the inverse function with an invertible affine transformation.
		The S-box is also chosen to avoid any fixed points (and so is a derangement), i.e., S-box[arrays[i][j]] != arrays[i][j] , and also any opposite fixed points, i.e., S-box[arrays[i][j]] (+) arrays[i][j] != FF16.
		While performing the decryption, the InvSubBytes step (the inverse of SubBytes) is used, which requires first taking the inverse of the affine transformation and then finding the multiplicative inverse.

		在SubBytes步骤中，状态数组中的每个字节arrays[i][j]被替换为SubByte S-box[arrays[i][j]]，使用一个8位替换框。
		注意，在第0轮之前，状态数组只是明文/输入。
		这个操作提供了密码中的非线性。
		所用的S-box是由GF(2^8)上的乘法逆推而来，已知其具有良好的非线性特性。
		为了避免基于简单代数特性的攻击，S-box是通过将反函数与可反转的仿射变换相结合而构建的。
		S-box的选择也是为了避免任何固定点（因此是一个脱轨），即S-box[arrays[i][j]] != arrays[i][j] ，以及任何相反的固定点，即S-box[ arrays[i][j] ] (+) arrays[i][j] != FF16。
		在进行解密时，使用了InvSubBytes步骤（SubBytes的逆），这需要先取仿射变换的逆，然后找到乘法的逆。
	*/

	//在密钥扩展例程中使用的函数，它接收一个四字节的输入字，并对四个字节中的每个字节应用一个S-box，以产生一个输出字。
	//Function used in the Key Expansion routine that takes a four-byte input word and applies an S-box to each of the four bytes to produce an output word.
	inline void SubtituteBytes(std::array<std::array<unsigned char, 4>, 4>& stateByteDataBlock)
	{
		using namespace AES::DefineConstants;

		#if 0

		// AES_BLOCK_SIDE is 4
		constexpr unsigned int AES_BLOCK_SIDE = 4;

		std::vector<unsigned char> Subtitute_ByteBox
		{
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
		};

		for(unsigned int row = 0; row < AES_BLOCK_SIDE; ++row)
		{
			for(unsigned int column = 0; column < AES_BLOCK_SIDE; ++column)
			{
				stateByteDataBlock.operator[](row).operator[](column) = Subtitute_ByteBox.operator[](stateByteDataBlock.operator[](row).operator[](column));
			}
		}

		Subtitute_ByteBox.clear();

		#else

		for(auto& row : stateByteDataBlock)
		{
			std::ranges::transform
			(
				row.begin(),
				row.end(),
				row.begin(),
				[](const unsigned char &byte) -> unsigned char
				{
					return Forward_S_Box[byte / 16][byte % 16];
				}
			);
		}

		#endif
	}

	/*
		InvSubBytes() is the inverse of the byte substitution transformation, in which the inverse S-box is applied to each byte of the State.
		This is obtained by applying the inverse of the affine transformation (5.1) followed by taking the multiplicative inverse in GF(2^8).

		InvSubBytes()是字节替换变换的逆运算，其中逆S-box被应用于状态的每个字节。
		这是由应用仿射变换的逆（5.1），然后在GF(2^8)中取乘法逆得到的。
	*/
	inline void InverseSubtituteBytes(std::array<std::array<unsigned char, 4>, 4>& stateByteDataBlock)
	{
		using namespace AES::DefineConstants;

		#if 0

		// AES_BLOCK_SIDE is 4
		constexpr unsigned int AES_BLOCK_SIDE = 4;

		std::vector<unsigned char> InverseSubtitute_ByteBox
		{
			0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
			0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
			0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
			0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
			0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
			0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
			0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
			0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
			0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
			0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
			0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
			0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
			0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
			0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
			0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
		};

		for(unsigned int row = 0; row < AES_BLOCK_SIDE; ++row)
		{
			for(unsigned int column = 0; column < AES_BLOCK_SIDE; ++column)
			{
				stateByteDataBlock.operator[](row).operator[](column) = InverseSubtitute_ByteBox.operator[](stateByteDataBlock.operator[](row).operator[](column));
			}
		}

		InverseSubtitute_ByteBox.clear();

		#else

		for(auto& row : stateByteDataBlock)
		{
			std::ranges::transform
			(
				row.begin(),
				row.end(),
				row.begin(),
				[](const unsigned char &byte) -> unsigned char
				{
					return Backward_S_Box[byte / 16][byte % 16];
				}
			);
		}

		#endif
	}

	/*
		In the AddRoundKey step, the subkey is combined with the state.
		For each round, a subkey is derived from the main key using Rijndael's key schedule; each subkey is the same size as the state.
		The subkey is added by combining each byte of the state with the corresponding byte of the subkey using bitwise (+).

		在AddRoundKey步骤中，子密钥与状态相结合。
		对于每一轮，使用Rijndael的密钥计划从主密钥中导出一个子密钥；每个子密钥的大小与状态相同。
		子密钥的添加是通过将状态的每个字节与子密钥的相应字节用位法（+）结合起来。

		Transformation in the Cipher and Inverse Cipher in which a Round Key is added to the State using an XOR operation.
		The length of a Round Key equals the size of the State data block (i.e., for Nb = 4, the Round Key length equals 128 bits/16 bytes).

		在密码器和反密码器中的转换，其中一个轮密钥是使用XOR操作添加到状态数据中
		轮密钥的长度等于状态数据块的大小（例如，对于Nb=4，轮密钥的长度等于128比特/16字节）
	*/
	inline void AddRoundKey(std::array<std::array<unsigned char, 4>, 4>& blockByteState, const std::vector<unsigned char>::const_iterator blockKeyIterator)
	{
		// AES_BLOCK_SIDE is 4
		// Add in GF(2^8) corresponding bytes of the subkey and state
		for(std::size_t row = 0; row < 4; ++row)
		{
			for(std::size_t column = 0; column < 4; ++column)
			{
				blockByteState.operator[](row).operator[](column) = blockByteState.operator[](row).operator[](column) ^ blockKeyIterator.operator[](row + 4 * column);
			}
		}
	}
}

namespace CommonSecurity::TripleDES::DefineConstants
{
	template<bool Experimental>
	struct SubstitutionBox;

	template<>
	struct SubstitutionBox<true>
	{
		//Byte Data Substitution Box
		//字节数据代换盒
		//Here it means that each S-box is a 4x16 permutation table, 6 bits -> 4 bits, 8 S-boxes
		//在这里表示每个S盒是4x16的置换表，6位 -> 4位，8个S盒
		static inline const std::vector<std::vector<std::vector<char>>> CubeData
		{{
			{{
				/* Box 0 */
				{{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 }},
				{{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 }},
				{{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 }},
				{{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }},

				/* Box 1 */
				{{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 }},
				{{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 }},
				{{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 }},
				{{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }},

				/* Box 2 */
				{{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 }},
				{{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 }},
				{{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 }},
				{{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }},

				/* Box 3 */
				{{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 }},
				{{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 }},
				{{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 }},
				{{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }},

				/* Box 4 */
				{{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 }},
				{{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 }},
				{{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 }},
				{{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }},

				/* Box 5 */
				{{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 }},
				{{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 }},
				{{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 }},
				{{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }},

				/* Box 6 */
				{{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 }},
				{{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 }},
				{{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 }},
				{{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }},

				/* Box 7 */
				{{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 }},
				{{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 }},
				{{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 }},
				{{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }},
			}},
		}};
	};

	template<>
	struct SubstitutionBox<false>
	{
		static constexpr std::array<std::array<char, 64>, 8> PlaneData
		{{
			{{
				14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
				0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
				4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
				15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
			}},
			{{
				15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
				3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
				0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
				13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
			}},
			{{
				10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
				13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
				13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
				1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
			}},
			{{
				7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
				13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
				10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
				3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
			}},
			{{
				2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
				14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
				4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
				11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
			}},
			{{
				12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
				10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
				9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
				4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
			}},
			{{
				4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
				13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
				1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
				6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
			}},
			{{
				13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
				1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
				7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
				2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
			}}
		}};
	};

	//First Step
	//第一个步骤
	//Forward Permutation Table - Initial
	static constexpr std::array<char, 64> InitialPermutationTable
	{
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17,  9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};

	//Last Step
	//最后一步
	//Backward Permutation Table - Final
	static constexpr std::array<char, 64> FinalPermutationTable
	{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25
	};

	//The 64 bit key Transform(Results like data compression) to 56 bit key
	//64位的密钥转换（结果像数据压缩）为56位的密钥
	static constexpr std::array<char, 56> KeyParityChoiceTable
	{
        57, 49, 41, 33, 25, 17, 9,  1,
		58, 50, 42, 34, 26, 18, 10, 2,
		59, 51, 43, 35, 27, 19, 11, 3,
		60, 52, 44, 36, 63, 55, 47, 39, 
		31, 23, 15, 7, 62, 54, 46, 38,
		30, 22, 14, 6, 61, 53, 45, 37,
		29, 21, 13, 5, 28, 20, 12, 4
	};

	//The 56 bit key Transform(Results like data compression) to 48 bit key
	//56位的密钥转换（结果像数据压缩）为48位的密钥
	static constexpr std::array<char, 48> KeyPermutationCompressionChoiceTable
	{
        14, 17, 11, 24, 1,  5,  3,  28,
		15, 6,  21, 10, 23, 19, 12, 4, 
		26, 8,  16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
		51, 45, 33, 48, 44, 49, 39, 56,
		34, 53, 46, 42, 50, 36, 29, 32
	};

	//Generate the number of bits to be circular shifted left or right for each (16) key rounds
	//生成每个(16)个密钥轮的循环左移或右移的比特数
	static constexpr std::array<char, 16> BitShiftWithRound
	{
		1, 1, 2, 2, 2, 2, 2, 2,
		1, 2, 2, 2, 2, 2, 2, 1
	};

	//The 32 bit data extension to 48 bit data
	//32位数据扩展为48位数据
    static constexpr std::array<char, 48> DataExtensionPermutationTable
	{
		32, 1,  2,  3,  4,  5,  4,  5, 
		6,  7,  8,  9,  8,  9,  10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1
	};

	//Byte Data Permutation Box
	//字节数据置换盒
	static constexpr std::array<char, 32> P_Box
	{
		16, 7,  20, 21,
		29, 12, 28, 17,
		1,  15, 23, 26,
		5,  18, 31, 10,
        2,  8,  24, 14,
		32, 27, 3,  9,
		19, 13, 30, 6,
		22, 11, 4,  25
	};
}

namespace CommonSecurity::TripleDES::ProcedureFunctions
{
	template<bool Experimental>
	class Worker;

	template<>
	class Worker<true>
	{

	private:
		
		//缓存的主密钥 (64位)
		//Cached original master key (64-bit)
		std::bitset<64> OriginalKey;
		std::bitset<64> RecordOriginalKey;

		//缓存的16轮子密钥（48位）
		//Cached 16 rounds of subkeys (48 bit)
		std::array<std::bitset<48>, 16> SubKeyArray;

		/*
				Binary 6 bit:
						
						column
							|
						*--+--*
					[0 (0 0 0 0) 0]
						^           ^
						|           |
						+-----+-----+
							|
							row
		*/

		std::pair<signed int, signed int> SubstitutionIndex(const std::bitset<6>& DataBits)
		{
			std::bitset<4> SubstitutionBox_RowBinary;
			std::bitset<4> SubstitutionBox_ColumnBinary;

			bool bitDigit5 = DataBits.operator[](5);
			bool bitDigit4 = DataBits.operator[](4);
			bool bitDigit3 = DataBits.operator[](3);
			bool bitDigit2 = DataBits.operator[](2);
			bool bitDigit1 = DataBits.operator[](1);
			bool bitDigit0 = DataBits.operator[](0);

			//The first and sixth binary digits are converted to decimal and set to row
			//第一和第六位二进制数字被转换为十进制并设置为行
			SubstitutionBox_RowBinary.set(1, bitDigit5);
			SubstitutionBox_RowBinary.set(0, bitDigit0);

			//The four adjacent binary bits in the middle are converted to decimal and set as columns
			//中间相邻的四个二进制位被转换为十进制并设置为列
			SubstitutionBox_ColumnBinary.set(3, bitDigit4);
			SubstitutionBox_ColumnBinary.set(2, bitDigit3);
			SubstitutionBox_ColumnBinary.set(1, bitDigit2);
			SubstitutionBox_ColumnBinary.set(0, bitDigit1);

			//The current bitset data, need to access the current bitset according to the index inside the loop, construct the decimal number representing the row as well as the column
			//当前bitset数据，需要根据循环内部的index访问当前比特位，构造出代表行以及列的十进制数
			return std::pair<signed int, signed int>(SubstitutionBox_RowBinary.to_ulong(), SubstitutionBox_ColumnBinary.to_ulong());
		}

		//The new decimal number as index passed to S_box for access operation, according to the value obtained update to the new S_box data to the new variable
		//So far the transformation of S_box is implemented
		//新的十进制数作为index传递给S_Box进行访问操作，根据得到的数值更新到新的S_Box数据到新的变量
		//至此就实现了S_box的变换。
		std::bitset<4> SubstitutionDataBits(signed int WhereBoxNumber, signed int BoxRowNumber, signed int BoxColumnNumber)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			unsigned int TransformedBoxNumber = SubstitutionBox<true>::CubeData.operator[](WhereBoxNumber).operator[](BoxRowNumber).operator[](BoxColumnNumber);
			std::bitset<4> TransformedBinaryData(TransformedBoxNumber);
			return TransformedBinaryData;
		}

		template<typename InputType, typename OutputType>
		void PermuteData(InputType&& Data, OutputType&& PermutedData, const char* PermutationTable, auto PermutationTableSize)
		{
			for (decltype(PermutationTableSize) index = 0; index < PermutationTableSize; index++)
			{
				PermutedData[PermutationTableSize - 1 - index] = Data[PermutationTableSize - PermutationTable[index]];
			}
		}

		std::bitset<32> RoundFeistelFunction(const std::bitset<32>& CurrentRoundDataBlock, std::bitset<48>& CurrentRoundKey)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			//std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );
			//std::cout << "RoundFeistelFunction Before:" << std::hex << CurrentRoundDataBlock.to_ulong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			std::bitset<48> CurrentExtendData;
		
			//Extend the data block and then re-permute the operation
			//对数据块进行扩展，然后重新置换操作
			for(unsigned int index = 0; index < 48; ++index)
				CurrentExtendData[47 - index] = CurrentRoundDataBlock[32 - DataExtensionPermutationTable[index]];

			//Use the key's data for exclusive-or operation with the original data
			//使用密钥的数据与原始数据进行异或操作
			CurrentExtendData ^= CurrentRoundKey;

			std::array<std::bitset<6>, 8> GroupedCurrentExtendDataBits;

			auto GroupingCurrentExtendDataBits = [&GroupedCurrentExtendDataBits](const std::bitset<48>& CurrentExtendData) -> void
			{
				for(unsigned int index = 0, index2 = 0; index < CurrentExtendData.size() && index2 < GroupedCurrentExtendDataBits.size(); ++index, ++index2)
				{
					std::bitset<6> TemporaryDataBits;
					TemporaryDataBits.operator[](5) = CurrentExtendData.operator[](47 - index);
					TemporaryDataBits.operator[](4) = CurrentExtendData.operator[](47 - index - 1);
					TemporaryDataBits.operator[](3) = CurrentExtendData.operator[](47 - index - 2);
					TemporaryDataBits.operator[](2) = CurrentExtendData.operator[](47 - index - 3);
					TemporaryDataBits.operator[](1) = CurrentExtendData.operator[](47 - index - 4);
					TemporaryDataBits.operator[](0) = CurrentExtendData.operator[](47 - index - 5);
					GroupedCurrentExtendDataBits.operator[](7 - index2) = TemporaryDataBits;
				}
			};

			//The 48-bit extended replacement key, divided into eight groups of six bits each
			//48位扩展置换后的密钥，分成8组，每组6位
			GroupingCurrentExtendDataBits(CurrentExtendData);
			
			std::bitset<32> Transformed_S_Box;

			for (std::size_t index = 0, index2 = 0; index < GroupedCurrentExtendDataBits.size(); ++index, index2 += 4)
			{
				auto [S_BoxRowNumber, BoxColumnNumber] = SubstitutionIndex(GroupedCurrentExtendDataBits.operator[](index));

				std::bitset<4> TransformedBinaryData = SubstitutionDataBits(index, S_BoxRowNumber, BoxColumnNumber);

				Transformed_S_Box.operator[](31 - index2) = TransformedBinaryData.operator[](3);
				Transformed_S_Box.operator[](31 - index2 - 1) = TransformedBinaryData.operator[](2);
				Transformed_S_Box.operator[](31 - index2 - 2) = TransformedBinaryData.operator[](1);
				Transformed_S_Box.operator[](31 - index2 - 3) = TransformedBinaryData.operator[](0);
			}

			//The value of P_Box is accessed through the index inside the loop, and then given to Transformed_S_Box
			//The index is 32 subtracted from the value of P_Box already accessed, and the data can be transformed
			//通过循环内部的索引访问P_Box的值，然后给Transformed_S_Box
			//索引是32减去已经访问P_Box的值，就可以对数据进行变换

			std::bitset<32> ProcessedCurrentRoundDataBlock;
			this->PermuteData(Transformed_S_Box, ProcessedCurrentRoundDataBlock, P_Box.data(), P_Box.size());

			//std::cout << "RoundFeistelFunction After:" << std::hex << ProcessedCurrentRoundDataBlock.to_ulong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			return ProcessedCurrentRoundDataBlock;
		}

		void GenerateSubKeys()
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );

			//二进制位数，最左边是最高位，最右边是最低位。
			//Binary bits, the leftmost is the highest bit and the rightmost is the lowest bit.

			/*
				In this std::bitset<BitsetSize> template class, All binary data is stored with the same number of bits as index.
				A larger index accessed means the higher part of the real binary data, and a smaller index accessed means the lower part of the real binary data.
				在这个std::bitset<BitsetSize>模板类中
				所有二进制数据的储存位数与index相同，访问的index越大表示的是真实二进制数据的高位部分，访问的index越小表示的是真实二进制数据的低位部分。

				Example:
				例子：
			
				std::bitset<64> bitset_binary_data_object;
			
				// This is accessing the 0th bit of the original binary data
				//此处是访问原有二进制数据第0位
				bitset_binary_data_object.operator[](0);
			
				//this is accessing the 63rd bit of the original binary data
				//此处是访问原有二进制数据第63位
				bitset_binary_data_object.operator[](63);

				The website link for the reference problem:
				https://stackoverflow.com/questions/29483123/why-does-stdbitset-expose-bits-in-little-endian-fashion
				https://stackoverflow.com/questions/37200967/is-bitset-data-stored-in-reverse-order
			*/

			std::bitset<56> BinaryKeyNotParityMarker;
			std::bitset<48> GenerateCompressedBinaryKey;

			//通过访问置换选择表1，去掉奇偶标记位，将64位密钥变成56位
			//Select Table 1 by accessing the permutation, removing the parity marker bits and turning the 64-bit key into a 56-bit
			for (unsigned int index = 0; index < 56; ++index)
				BinaryKeyNotParityMarker[55 - index] = this->OriginalKey[64 - KeyParityChoiceTable[index]];

			//Split the 56-bit key into the first 28 bits and the last 28 bits
			//将56位密钥分解成为前28位和后28位
			auto SplitedBitsetPair = Cryptograph::Bitset::SplitBitset<BinaryKeyNotParityMarker.size(), BinaryKeyNotParityMarker.size() / 2>(BinaryKeyNotParityMarker);

			std::bitset<28> BinaryKeyHighDigitPart { SplitedBitsetPair.first };
			std::bitset<28> BinaryKeyLowDigitPart { SplitedBitsetPair.second };

			for (unsigned int RoundNumber = 0; RoundNumber < 16; RoundNumber++)
			{
				//Perform circular left-shift and circular right-shift for the front and back parts of the 56-bit key (The original version for the key operation are circular left shift, maybe for the key operation are circular right shift?)
				//对56位密钥的前后部分，进行循环左移和循环右移（原版对于密钥的操作都是循环左移，也许可以对于密钥的操作都是循环右移？）

				Cryptograph::Bitset::BitLeftCircularShift<28>(BinaryKeyHighDigitPart, BitShiftWithRound.operator[](RoundNumber), BinaryKeyHighDigitPart);
				Cryptograph::Bitset::BitRightCircularShift<28>(BinaryKeyLowDigitPart, BitShiftWithRound.operator[](RoundNumber), BinaryKeyLowDigitPart);
				
				/*
				
					std::size_t shift_count = BitShiftWithRound.operator[](RoundNumber);
					shift_count %= BinaryKeyHighDigitPart.size();
					BinaryKeyHighDigitPart = (BinaryKeyHighDigitPart << shift_count) | (BinaryKeyHighDigitPart >> (BinaryKeyHighDigitPart.size() - shift_count));
					std::size_t shift_count2 = BitShiftWithRound.operator[](RoundNumber);
					shift_count2 %= BinaryKeyHighDigitPart.size();
					BinaryKeyLowDigitPart = (BinaryKeyLowDigitPart >> shift_count2) | (BinaryKeyLowDigitPart << (BinaryKeyHighDigitPart.size() - shift_count2));
				
				*/

				//Concatenation into a 56-bit key
				//组合成56比特位密钥
				BinaryKeyNotParityMarker = Cryptograph::Bitset::ConcatenateBitset<BinaryKeyLowDigitPart.size(), BinaryKeyHighDigitPart.size()>(BinaryKeyHighDigitPart, BinaryKeyLowDigitPart, false);

				//Turn a 56-bit key into a 48-bit key by accessing permutation selection table 2
				//通过访问置换选择表2，将56位密钥变成48位
				for (unsigned int index = 0; index < 48; ++index)
					GenerateCompressedBinaryKey[47 - index] = BinaryKeyNotParityMarker[56 - KeyPermutationCompressionChoiceTable[index]];

				//std::cout << "DES Round " << RoundNumber;
				//std::cout << " Sub-key is generated: " << std::hex << GenerateCompressedBinaryKey.to_ullong() << std::endl;
				//std::cout.flags(cpp_output_formatflag);

				this->SubKeyArray.operator[](RoundNumber) = GenerateCompressedBinaryKey;
			}
		}

		std::bitset<64> Encryption(const std::bitset<64>& PlainBits)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::bitset<64> CurrentBits;

			//std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );
			//std::cout << "InitialPermutation Before:" << std::hex << PlainBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			this->PermuteData(PlainBits, CurrentBits, InitialPermutationTable.data(), InitialPermutationTable.size());

			//std::cout << "InitialPermutation After:" << std::hex << CurrentBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			//Step 2: PlainBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			auto SplitedBitsetPair = Cryptograph::Bitset::SplitBitset<CurrentBits.size(), CurrentBits.size() / 2>(CurrentBits);

			/*
				Left<--------------------------------------------->Right
					[      High Bits     ] | [      Low Bits      ]
				
					std::bitset<64> Index:
					63                   32  31                   0

					BinaryDataHighDigitPart( std::bitset<64>.operator[](): 63 ~ 32 )
					BinaryDataLowDigitPart( std::bitset<64>.operator[](): 31 ~ 0 )
			*/

			std::bitset<32> BinaryData_LeftBits { SplitedBitsetPair.first};
			std::bitset<32> BinaryData_RightBits { SplitedBitsetPair.second };

			//Step 3: Total 16 rounds of iterations (Sub-key forward sequential application)
			//共16轮迭代（子密钥正向顺序应用）
			
			for (auto& SubKey : this->SubKeyArray)
			{
				/*std::cout << "Round: " << RoundNumber << " Encryption Data (Left):" << std::endl;
				std::cout << std::dec << std::hex << BinaryData_LeftBits.to_ulong() << std::endl;
				std::cout << "Round: " << RoundNumber << " Encryption Data (Right):" << std::endl;
				std::cout << std::dec << std::hex << BinaryData_RightBits.to_ulong() << std::endl;*/
				
				std::bitset<32> TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = Cryptograph::Bitset::ConcatenateBitset<BinaryData_LeftBits.size(), BinaryData_RightBits.size()>(BinaryData_LeftBits, BinaryData_RightBits, true);

			//std::cout << "FinalPermutationTable Before:" << std::hex << CurrentBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			std::bitset<64> CipherBits;
			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			this->PermuteData(CurrentBits, CipherBits, FinalPermutationTable.data(), FinalPermutationTable.size());

			//std::cout << "FinalPermutationTable After:" << std::hex << CipherBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			return CipherBits;
		}

		std::bitset<64> Decryption(const std::bitset<64>& CipherBits)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::bitset<64> CurrentBits;

			//std::ios_base::fmtflags cpp_output_formatflag( std::cout.flags() );
			//std::cout << "InitialPermutation Before:" << std::hex << CipherBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			this->PermuteData(CipherBits, CurrentBits, InitialPermutationTable.data(), InitialPermutationTable.size());

			//std::cout << "InitialPermutation After:" << std::hex << CurrentBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			//Step 2: CipherBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			auto SplitedBitsetPair = Cryptograph::Bitset::SplitBitset<CurrentBits.size(), CurrentBits.size() / 2>(CurrentBits);

			/*
				Left<--------------------------------------------->Right
					[      High Bits     ] | [      Low Bits      ]
				
					std::bitset<64> Index:
					63                   32  31                   0

					BinaryDataHighDigitPart( std::bitset<64>.operator[](): 63 ~ 32 )
					BinaryDataLowDigitPart( std::bitset<64>.operator[](): 31 ~ 0 )
			*/
			std::bitset<32> BinaryData_LeftBits { SplitedBitsetPair.first};
			std::bitset<32> BinaryData_RightBits { SplitedBitsetPair.second };

			//Step 3: Total 16 rounds of iterations (Sub-key backward sequential application)
			//共16轮迭代（子密钥反向顺序应用）
			for (auto& SubKey : std::ranges::subrange(this->SubKeyArray.rbegin(), this->SubKeyArray.rend()))
			{
				/*std::cout << "Round: " << RoundNumber << " Decryption Data (Left):" << std::endl;
				std::cout << std::dec << std::hex << BinaryData_LeftBits.to_ulong() << std::endl;
				std::cout << "Round: " << RoundNumber << " Decryption Data (Right):" << std::endl;
				std::cout << std::dec << std::hex << BinaryData_RightBits.to_ulong() << std::endl;*/

				std::bitset<32> TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = Cryptograph::Bitset::ConcatenateBitset<BinaryData_LeftBits.size(), BinaryData_RightBits.size()>(BinaryData_LeftBits, BinaryData_RightBits, true);

			//std::cout << "FinalPermutationTable Before:" << std::hex << CurrentBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			std::bitset<64> PlainBits;

			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			this->PermuteData(CurrentBits, PlainBits, FinalPermutationTable.data(), FinalPermutationTable.size());

			//std::cout << "FinalPermutationTable Atfer:" << std::hex << PlainBits.to_ullong() << std::endl;
			//std::cout.flags(cpp_output_formatflag);

			return PlainBits;
		}

	public:
		
		void UpadateMainKeyOnly(std::bitset<64>& Key)
		{
			if(Key != this->RecordOriginalKey)
			{
				this->OriginalKey = Key;
				this->RecordOriginalKey = Key;
			}
		}

		void UpadateSubKeyOnly()
		{
			this->GenerateSubKeys();
		}

		//The update sub-round key by the main-round key
		//通过主轮密钥更新子轮密钥 
		void UpadateMainKeyAndSubKey(std::bitset<64>& Key)
		{
			this->UpadateMainKeyOnly(Key);
			this->UpadateSubKeyOnly();
		}

		std::vector<unsigned char> DES_Executor
		(
			Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
			const std::vector<unsigned char>& dataBlock,
			bool updateSubKey
		)
		{
			std::size_t dataBlockByteSize = dataBlock.size();

			/*
				Data buffer
			*/

			std::bitset<64> Bitset64Object_Plain;
			std::bitset<64> Bitset64Object_Cipher;

			if(updateSubKey)
			{
				this->UpadateSubKeyOnly();
			}

			my_cpp2020_assert(dataBlockByteSize != 0 && dataBlockByteSize % 8 == 0, "The size of the input data must be a multiple of eight to ensure that the output data is properly sized! ", std::source_location::current());

			if(dataBlockByteSize == std::numeric_limits<unsigned char>::digits)
			{
				//Byte array data container size is 64 bits
				if(executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					Bitset64Object_Plain = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(dataBlock);
					Bitset64Object_Cipher = this->Encryption(Bitset64Object_Plain);
					return Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(Bitset64Object_Cipher);
				}
				else if (executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					Bitset64Object_Cipher = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(dataBlock);
					Bitset64Object_Plain = this->Decryption(Bitset64Object_Cipher);
					return Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(Bitset64Object_Plain);
				}
				else
				{
					std::cout << "Wrong DES Algorithm worker is selected" << std::endl;
					abort();
				}
			}
			else
			{
				//Byte array data container size is not 64 bits

				std::vector<unsigned char> processedDataBlock;

				switch (executeMode)
				{
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
					{
						std::deque<std::vector<unsigned char>> dataBlockChain;
						std::deque<std::vector<unsigned char>> processedDataBlockChain;

						CommonToolkit::ProcessingDataBlock::splitter(dataBlock, std::back_inserter(dataBlockChain), std::numeric_limits<unsigned char>::digits);

						//For each 8-byte size of data to be processed
						for(auto& EightClassicByteBlock : dataBlockChain)
						{
							Bitset64Object_Plain = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(EightClassicByteBlock);
							Bitset64Object_Cipher = this->Encryption(Bitset64Object_Plain);
							processedDataBlock = Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(Bitset64Object_Cipher);
							processedDataBlockChain.push_back(std::move(processedDataBlock));
						}

						processedDataBlock.clear();
						processedDataBlock.shrink_to_fit();

						dataBlockChain.clear();
						dataBlockChain.shrink_to_fit();

						CommonToolkit::ProcessingDataBlock::merger(processedDataBlockChain, std::back_inserter(processedDataBlock));

						break;
					}
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
					{
						std::deque<std::vector<unsigned char>> dataBlockChain;
						std::deque<std::vector<unsigned char>> processedDataBlockChain;

						CommonToolkit::ProcessingDataBlock::splitter(dataBlock, std::back_inserter(dataBlockChain), std::numeric_limits<unsigned char>::digits);

						//For each 8-byte size of data to be processed
						for(auto& EightClassicByteBlock : dataBlockChain)
						{
							Bitset64Object_Cipher = Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(EightClassicByteBlock);
							Bitset64Object_Plain = this->Decryption(Bitset64Object_Cipher);
							processedDataBlock = Cryptograph::Bitset::ClassicByteArrayFromBitset64Bit(Bitset64Object_Plain);
							processedDataBlockChain.push_back(processedDataBlock);
						}

						processedDataBlock.clear();
						processedDataBlock.shrink_to_fit();

						dataBlockChain.clear();
						dataBlockChain.shrink_to_fit();

						CommonToolkit::ProcessingDataBlock::merger(processedDataBlockChain, std::back_inserter(processedDataBlock));

						break;
					}
					default:
					{
						std::cout << "Wrong DES Algorithm worker is selected" << std::endl;
						abort();
					}
				}

				return processedDataBlock;
			}
		}

		explicit Worker(std::bitset<64>& key) : OriginalKey(key), RecordOriginalKey(key)
		{
		}

		Worker() :OriginalKey(std::bitset<64>()), RecordOriginalKey(std::bitset<64>())
		{
		}

		~Worker() = default;

		Worker(Worker& _object) = delete;
		Worker& operator=(Worker& _object) = delete;
	};

	inline void TripleDES_Executor
	(
		Worker<true>& DES_Worker,
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
		const std::vector<unsigned char>& inputDataBlock,
		std::deque<std::vector<unsigned char>>& keyBlockChain,
		std::vector<unsigned char>& outputDataBlock,
		bool forceAssert = true
	)
	{
		std::vector<std::bitset<64>> Bitset64_Keys;

		std::mt19937 pseudoRandomGenerator { static_cast<unsigned int>( keyBlockChain.front().operator[](0) ) };
		CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution number_distribution(0, 255);

		if(inputDataBlock.empty())
		{
			throw std::length_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the input data cannot be zero!");
		}

		if(forceAssert)
		{
			my_cpp2020_assert(keyBlockChain.size() % 3 == 0, "CommonSecurity::TripleDES::TripleDES_Executor() The Triple DES algorithm requires the number of keys to be modulo 3 to work!", std::source_location::current());

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : keyBlockChain)
			{
				while(keyBlock.size() % std::numeric_limits<unsigned char>::digits != 0)
				{
					unsigned char randomByte = static_cast<unsigned char>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bitset64_Keys.push_back( Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(keyBlock) );
			}
		}
		else
		{
			std::deque<std::vector<unsigned char>> copiedKeyBlockChain = keyBlockChain;

			std::size_t KeyBlockTruncationCount = copiedKeyBlockChain.size() % 3;
			while (KeyBlockTruncationCount > 0)
			{
				copiedKeyBlockChain.back().clear();
				copiedKeyBlockChain.back().shrink_to_fit();
				copiedKeyBlockChain.pop_back();
				--KeyBlockTruncationCount;
			}

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : copiedKeyBlockChain)
			{
				while(keyBlock.size() % std::numeric_limits<unsigned char>::digits != 0)
				{
					unsigned char randomByte = static_cast<unsigned char>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bitset64_Keys.push_back( Cryptograph::Bitset::ClassicByteArrayToBitset64Bit(keyBlock) );
			}
		}

		std::size_t dataBlockByteSize = inputDataBlock.size();

		switch (executeMode)
		{
			//CipherText = Encryption(Decryption(Encryption(PlainText, Key), Key2), Key3);
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				//PKCS is Public Key Cryptography Standards
				/*
					https://en.wikipedia.org/wiki/Padding_(cryptography)
					https://datatracker.ietf.org/doc/html/rfc5652
					PKCS#7 is described in RFC 5652. (section-6.3)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Padding Data
				std::size_t padedDataByteSize = dataBlockByteSize + 8 - (dataBlockByteSize % 8);
				std::size_t paddingDataByteSize = padedDataByteSize - dataBlockByteSize;
				const std::vector<unsigned char> paddingData(paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));

				std::vector<unsigned char> temporaryDataBlock { std::move(inputDataBlock) };
				temporaryDataBlock.insert(temporaryDataBlock.end(), paddingData.begin(), paddingData.end());

				std::cout << "TripleDES Encryption Start !" << std::endl;

				for(std::size_t index = 0; index < Bitset64_Keys.size(); index += 3)
				{
					//Use Encryption Main Round Key 1
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				
					//Use Encryption Main Round Key 2
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index + 1));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);

					//Use Encryption Main Round Key 3
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index + 2));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				}

				std::cout << "TripleDES Encryption End !" << std::endl;

				outputDataBlock.resize(padedDataByteSize);

				std::ranges::copy(temporaryDataBlock.begin(), temporaryDataBlock.end(), outputDataBlock.begin());
				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				break;
			}
			//PlainText = Decryption(Encryption(Decryption(CipherText, Key3), Key2), Key);
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				std::vector<unsigned char> temporaryDataBlock { std::move(inputDataBlock) };

				std::cout << "TripleDES Decryption Start !" << std::endl;

				for(std::size_t index = Bitset64_Keys.size() - 1; index > 0; index -= 3)
				{
					if(index >= Bitset64_Keys.size())
					{
						break;
					}

					//Use Decryption Main Round Key 1
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);
				
					//Use Decryption Main Round Key 2
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index - 1));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);

					//Use Decryption Main Round Key 3
					DES_Worker.UpadateMainKeyAndSubKey(Bitset64_Keys.operator[](index - 2));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);
				}

				std::cout << "TripleDES Decryption End !" << std::endl;

				outputDataBlock.resize(temporaryDataBlock.size());

				std::ranges::copy(temporaryDataBlock.begin(), temporaryDataBlock.end(), outputDataBlock.begin());
				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				//PKCS is Public Key Cryptography Standards
				/*
					https://en.wikipedia.org/wiki/Padding_(cryptography)
					https://datatracker.ietf.org/doc/html/rfc5652
					PKCS#7 is described in RFC 5652. (section-6.3)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Unpadding Data
				std::size_t paddingDataByteSize = outputDataBlock.back();
				const std::vector<unsigned char> paddingData(paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));
				auto searchHasBeenFoundSubrange = std::ranges::search(outputDataBlock.end() - paddingDataByteSize * 2, outputDataBlock.end(), paddingData.begin(), paddingData.end());
				if(searchHasBeenFoundSubrange.begin() != searchHasBeenFoundSubrange.end())
				{
					outputDataBlock.erase(searchHasBeenFoundSubrange.begin(), searchHasBeenFoundSubrange.end());
					outputDataBlock.shrink_to_fit();
				}
				else
				{
					throw std::logic_error("Operation failed, maybe the padding data, before encryption, was corrupted?");
				}

				break;
			}
			default:
			{
				std::cout << "Wrong TripleDES Algorithm worker is selected" << std::endl;
				abort();
			}
		}
	}

	template<>
	class Worker<false>
	{

	private:
		
		static constexpr std::uint32_t LOW_BIT32_ONE_MASK = 0x00000001;
		static constexpr std::uint64_t LOW_BIT64_ONE_MASK = 0x0000000000000001;
		static constexpr std::uint64_t LOW_BIT64_MASK  = 0x00000000FFFFFFFF;

		//缓存的主密钥 (64位)
		//Cached original master key (64-bit)
		std::uint64_t OriginalKey;
		std::uint64_t RecordOriginalKey;

		//缓存的16轮子密钥（48位）
		//Cached 16 rounds of subkeys (48 bit)
		std::array<std::uint64_t, 16> SubKeyArray;

		template<typename InputType, typename OutputType>
		void PermuteData(InputType&& Data, OutputType&& PermutedData, std::size_t DataTableSize, const char* PermutationTable, auto PermutationTableSize, auto BitMask)
		{
			for (decltype(PermutationTableSize) index = 0; index < PermutationTableSize; index++)
			{
				PermutedData <<= 1;
				PermutedData |= (Data >> ( DataTableSize - PermutationTable[index]) ) & BitMask;
			}
		}

		std::uint32_t RoundFeistelFunction(const std::uint32_t& CurrentRoundDataBlock, std::uint64_t& CurrentRoundKey)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;
			
			/* 48 Bits */
			std::uint64_t SubstitutionBoxInput = 0;
			
			/* 32 Bits */
			std::uint32_t SubstitutionBoxOutput = 0;

			//Extend the data block and then re-permute the operation
			//对数据块进行扩展，然后重新置换操作
			this->PermuteData(CurrentRoundDataBlock, SubstitutionBoxInput, 32, DataExtensionPermutationTable.data(), DataExtensionPermutationTable.size(), LOW_BIT32_ONE_MASK);

			//Use the key's data (48 Bits) for exclusive-or operation with the original data (48 Bits)
			//使用密钥的数据与原始数据进行异或操作
			SubstitutionBoxInput ^= CurrentRoundKey;

			//The 48-bit extended replacement key, divided into eight groups of six bits each
			//48位扩展置换后的密钥，分成8组，每组6位
			for(std::size_t Counter = 0; Counter < 8; ++Counter)
			{
				// 00 00 RCCC CR00 00 00 00 00 00 s_input
				// 00 00 1000 0100 00 00 00 00 00 row mask
				// 00 00 0111 1000 00 00 00 00 00 column mask

				char row = 0, column = 0;

				row = static_cast<char>( (SubstitutionBoxInput & (0x0000840000000000 >> (6 * Counter))) >> (42 - 6 * Counter) );
				row = (row >> 4) | row & 0x01;

				column = static_cast<char>( (SubstitutionBoxInput & (0x0000780000000000 >> (6 * Counter))) >> (43 - 6 * Counter) );

				SubstitutionBoxOutput <<= 4;
				SubstitutionBoxOutput |= static_cast<std::uint32_t>( SubstitutionBox<false>::PlaneData[Counter][16 * row + column] & 0x0f );
			}

			//The value of P_Box is accessed through the index inside the loop, and then given to Transformed_S_Box
			//The index is 32 subtracted from the value of P_Box already accessed, and the data can be transformed
			//通过循环内部的索引访问P_Box的值，然后给Transformed_S_Box
			//索引是32减去已经访问P_Box的值，就可以对数据进行变换

			std::uint32_t ProcessedCurrentRoundData = 0;
			this->PermuteData(SubstitutionBoxOutput, ProcessedCurrentRoundData, 32, P_Box.data(), P_Box.size(), LOW_BIT32_ONE_MASK);

			return ProcessedCurrentRoundData;
		}

		void GenerateSubKeys()
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;
			
			/* 56 Bits */
			std::uint64_t BinaryKeyNotParityMarker;
			
			/* 48 Bits */
			std::uint64_t GenerateCompressedBinaryKey;

			//通过访问置换选择表1，去掉奇偶标记位，将64位密钥变成56位
			//Select Table 1 by accessing the permutation, removing the parity marker bits and turning the 64-bit key into a 56-bit
			this->PermuteData(OriginalKey, BinaryKeyNotParityMarker, 64, KeyParityChoiceTable.data(), KeyParityChoiceTable.size(), LOW_BIT64_ONE_MASK);

			//Split the 56-bit key into the first 28 bits and the last 28 bits
			//将56位密钥分解成为前28位和后28位
			std::uint32_t BinaryKeyHighDigitPart = static_cast<std::uint32_t>( (BinaryKeyNotParityMarker >> 28) & 0x000000000FFFFFFF );
			std::uint32_t BinaryKeyLowDigitPart = static_cast<std::uint32_t>(BinaryKeyNotParityMarker & 0x000000000FFFFFFF);

			/* Calculate the key schedule for 16 rounds */
			/* 计算16个轮回的密钥日程表 */
			for (unsigned int RoundNumber = 0; RoundNumber < 16; RoundNumber++)
			{
				/*
					//Circular left shifting
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart << 1) | 0x00000001 & (BinaryKeyHighDigitPart >> 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart << 1) | 0x00000001 & (BinaryKeyLowDigitPart >> 27);

					//Circular right shifting
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart >> 1) | 0x00000001 & (BinaryKeyHighDigitPart << 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart >> 1) | 0x00000001 & (BinaryKeyLowDigitPart << 27);
				*/

				//Perform circular left-shift and circular right-shift for the front and back parts of the 56-bit key (The original version for the key operation are circular left shift, maybe for the key operation are circular right shift?)
				//对56位密钥的前后部分，进行循环左移和循环右移（原版对于密钥的操作都是循环左移，也许可以对于密钥的操作都是循环右移？）
				for(unsigned int RoundNumber2 = 0; RoundNumber2 < BitShiftWithRound[RoundNumber]; RoundNumber2++)
				{
					BinaryKeyHighDigitPart = 0x0fffffff & (BinaryKeyHighDigitPart << 1) | 0x00000001 & (BinaryKeyHighDigitPart >> 27);
					BinaryKeyLowDigitPart = 0x0fffffff & (BinaryKeyLowDigitPart >> 1) | 0x00000001 & (BinaryKeyLowDigitPart << 27);
				}

				//Concatenation into a 56-bit key
				//组合成56比特位密钥
				BinaryKeyNotParityMarker = ( static_cast<std::uint64_t>(BinaryKeyHighDigitPart) << 28 ) | static_cast<std::uint64_t>(BinaryKeyLowDigitPart);

				this->SubKeyArray.operator[](RoundNumber) = 0;

				//Turn a 56-bit key into a 48-bit key by accessing permutation selection table 2
				//通过访问置换选择表2，将56位密钥变成48位
				this->PermuteData(BinaryKeyNotParityMarker, GenerateCompressedBinaryKey, 56, KeyPermutationCompressionChoiceTable.data(), KeyPermutationCompressionChoiceTable.size(), LOW_BIT64_ONE_MASK);

				this->SubKeyArray.operator[](RoundNumber) = GenerateCompressedBinaryKey;
			}
		}

		std::uint64_t Encryption(const std::uint64_t& PlainBits)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::uint64_t CurrentBits;

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			this->PermuteData(PlainBits, CurrentBits, 64, InitialPermutationTable.data(), InitialPermutationTable.size(), LOW_BIT64_ONE_MASK);

			//Step 2: PlainBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			std::uint32_t BinaryData_LeftBits = static_cast<std::uint32_t>( CurrentBits >> 32 ) & LOW_BIT64_MASK;
			std::uint32_t BinaryData_RightBits = CurrentBits & LOW_BIT64_MASK;

			//Step 3: Total 16 rounds of iterations (Sub-key forward sequential application)
			//共16轮迭代（子密钥正向顺序应用）
			
			for (auto& SubKey : this->SubKeyArray)
			{
				std::uint32_t TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = static_cast<std::uint64_t>(BinaryData_RightBits) << 32 | static_cast<std::uint64_t>(BinaryData_LeftBits);

			std::uint64_t CipherBits;

			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			this->PermuteData(CurrentBits, CipherBits, 64, FinalPermutationTable.data(), FinalPermutationTable.size(), LOW_BIT64_ONE_MASK);

			return CipherBits;
		}

		std::uint64_t Decryption(const std::uint64_t& CipherBits)
		{
			using namespace CommonSecurity::TripleDES::DefineConstants;

			std::uint64_t CurrentBits;

			//Step 1: Initial data for forward-table substitution
			//初始的数据进行正向表置换
			this->PermuteData(CipherBits, CurrentBits, 64, InitialPermutationTable.data(), InitialPermutationTable.size(), LOW_BIT64_ONE_MASK);

			//Step 2: CipherBit split to LeftBits an RightBits
			//Split 64 bits of data into the first 32 bits and the last 32 bits of data
			//将64位比特数据分解，成为前32位比特数据和后32位比特数据
			std::uint32_t BinaryData_LeftBits = static_cast<std::uint32_t>( CurrentBits >> 32 ) & LOW_BIT64_MASK;
			std::uint32_t BinaryData_RightBits = CurrentBits & LOW_BIT64_MASK;

			//Step 3: Total 16 rounds of iterations (Sub-key backward sequential application)
			//共16轮迭代（子密钥反向顺序应用）
			for (auto& SubKey : std::ranges::subrange(this->SubKeyArray.rbegin(), this->SubKeyArray.rend()))
			{
				std::uint32_t TemporaryBinaryPart = BinaryData_RightBits;
				BinaryData_RightBits = BinaryData_LeftBits ^ this->RoundFeistelFunction(BinaryData_RightBits, SubKey);
				BinaryData_LeftBits = TemporaryBinaryPart;
			}

			/*
				Step 4: 
				将比特数据进行串联
				输入两个比特数据部分（第一个32位比特和第二个32位比特），然后输出64位的比特数据，但是顺序需要交换为（第二个32位比特和第一个32位比特）的形式。
				Concatenate the bit data
				Input two bit data parts (first 32 bits and second 32 bits), then output 64 bits of bit data, but the order needs to be swapped to the form (second 32 bits and first 32 bits).
			*/
			CurrentBits = static_cast<std::uint64_t>(BinaryData_RightBits) << 32 | static_cast<std::uint64_t>(BinaryData_LeftBits);

			std::uint64_t PlainBits;

			//Step 5: Final data for backward-table substitution
			//最后的数据进行反向表置换
			this->PermuteData(CurrentBits, PlainBits, 64, FinalPermutationTable.data(), FinalPermutationTable.size(), LOW_BIT64_ONE_MASK);

			return PlainBits;
		}

	public:

		void UpadateMainKeyOnly(std::uint64_t& Key)
		{
			if(Key != this->RecordOriginalKey)
			{
				this->OriginalKey = Key;
				this->RecordOriginalKey = Key;
			}
		}

		void UpadateSubKeyOnly()
		{
			this->GenerateSubKeys();
		}

		//The update sub-round key by the main-round key
		//通过主轮密钥更新子轮密钥 
		void UpadateMainKeyAndSubKey(std::uint64_t& Key)
		{
			this->UpadateMainKeyOnly(Key);
			this->UpadateSubKeyOnly();
		}

		std::vector<unsigned char> DES_Executor
		(
			Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
			const std::vector<unsigned char>& dataBlock,
			bool updateSubKey
		)
		{
			std::size_t dataBlockByteSize = dataBlock.size();

			/*
				Data buffer
			*/

			std::uint64_t Bitset64Object_Plain;
			std::uint64_t Bitset64Object_Cipher;

			if(updateSubKey)
			{
				this->UpadateSubKeyOnly();
			}

			my_cpp2020_assert(dataBlockByteSize != 0 && dataBlockByteSize % 8 == 0, "The size of the input data must be a multiple of eight to ensure that the output data is properly sized! ", std::source_location::current());

			CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange memoryDataFormatExchanger;

			if(dataBlockByteSize == std::numeric_limits<unsigned char>::digits)
			{
				//Byte array data container size is 64 bits
				if(executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER)
				{
					Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte(dataBlock);
					Bitset64Object_Cipher = this->Encryption(Bitset64Object_Plain);
					auto spanData = memoryDataFormatExchanger.Unpacker_8Byte(Bitset64Object_Cipher);
					return std::vector<unsigned char>(spanData.begin(), spanData.end());
				}
				else if (executeMode == Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER)
				{
					Bitset64Object_Cipher = memoryDataFormatExchanger.Packer_8Byte(dataBlock);
					Bitset64Object_Plain = this->Decryption(Bitset64Object_Cipher);
					auto spanData = memoryDataFormatExchanger.Unpacker_8Byte(Bitset64Object_Plain);
					return std::vector<unsigned char>(spanData.begin(), spanData.end());
				}
				else
				{
					std::cout << "Wrong DES Algorithm worker is selected" << std::endl;
					abort();
				}
			}
			else
			{
				//Byte array data container size is not 64 bits

				std::vector<unsigned char> processedDataBlock(dataBlock.size(), 0x00);

				switch (executeMode)
				{
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
					{
						//For each 8-byte size of data to be processed
						for(std::size_t DataIndex = 0; DataIndex != dataBlock.size(); DataIndex += sizeof(std::uint64_t))
						{
							std::span<const unsigned char> byteSpanData0 ( dataBlock.begin() + DataIndex, dataBlock.begin() + DataIndex + sizeof(std::uint64_t) );
							Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte( byteSpanData0 );
							Bitset64Object_Cipher = this->Encryption( Bitset64Object_Plain );
							auto byteSpanData = memoryDataFormatExchanger.Unpacker_8Byte( Bitset64Object_Cipher );
							
							std::ranges::move(byteSpanData.begin(), byteSpanData.end(), processedDataBlock.begin() + DataIndex);
						}

						break;
					}
					case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
					{
						//For each 8-byte size of data to be processed
						for(std::size_t DataIndex = 0; DataIndex != dataBlock.size(); DataIndex += sizeof(std::uint64_t))
						{
							std::span<const unsigned char> byteSpanData0( dataBlock.begin() + DataIndex, dataBlock.begin() + DataIndex + sizeof(std::uint64_t) );
							Bitset64Object_Plain = memoryDataFormatExchanger.Packer_8Byte( byteSpanData0 );
							Bitset64Object_Cipher = this->Decryption( Bitset64Object_Plain );
							auto byteSpanData = memoryDataFormatExchanger.Unpacker_8Byte( Bitset64Object_Cipher );
							
							std::ranges::move(byteSpanData.begin(), byteSpanData.end(), processedDataBlock.begin() + DataIndex);
						}

						break;
					}
					default:
					{
						std::cout << "Wrong DES Algorithm worker is selected" << std::endl;
						abort();
					}
				}

				return processedDataBlock;
			}
		}
	};

	inline void TripleDES_Executor
	(
		Worker<false>& DES_Worker,
		Cryptograph::CommonModule::CryptionMode2MCAC4_FDW executeMode,
		const std::vector<unsigned char>& inputDataBlock,
		std::deque<std::vector<unsigned char>>& keyBlockChain,
		std::vector<unsigned char>& outputDataBlock,
		bool forceAssert = true
	)
	{
		CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange MemoryDataFormatExchanger;
		std::vector<std::uint64_t> Bit64_Keys;

		std::mt19937 pseudoRandomGenerator { static_cast<unsigned int>( keyBlockChain.front().operator[](0) ) };
		CommonSecurity::ShufflingRangeDataDetails::UniformIntegerDistribution number_distribution(0, 255);

		if(inputDataBlock.empty())
		{
			throw std::length_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the input data cannot be zero!");
		}

		if(forceAssert)
		{
			my_cpp2020_assert(keyBlockChain.size() % 3 == 0, "CommonSecurity::TripleDES::TripleDES_Executor() The Triple DES algorithm requires the number of keys to be modulo 3 to work!", std::source_location::current());

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : keyBlockChain)
			{
				while(keyBlock.size() % sizeof(std::uint64_t) != 0)
				{
					unsigned char randomByte = static_cast<unsigned char>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bit64_Keys.push_back( MemoryDataFormatExchanger.Packer_8Byte(keyBlock) );
			}
		}
		else
		{
			std::deque<std::vector<unsigned char>> copiedKeyBlockChain = keyBlockChain;

			std::size_t KeyBlockTruncationCount = copiedKeyBlockChain.size() % 3;
			while (KeyBlockTruncationCount > 0)
			{
				copiedKeyBlockChain.back().clear();
				copiedKeyBlockChain.back().shrink_to_fit();
				copiedKeyBlockChain.pop_back();
				--KeyBlockTruncationCount;
			}

			//Preprocessing of multiple main keys
			//将多个主要密钥进行预处理
			for(auto& keyBlock : copiedKeyBlockChain)
			{
				while(keyBlock.size() % sizeof(std::uint64_t) != 0)
				{
					unsigned char randomByte = static_cast<unsigned char>( number_distribution(pseudoRandomGenerator) );
					keyBlock.push_back(randomByte);
				}

				Bit64_Keys.push_back( MemoryDataFormatExchanger.Packer_8Byte(keyBlock) );
			}
		}

		std::size_t dataBlockByteSize = inputDataBlock.size();

		switch (executeMode)
		{
			//CipherText = Encryption(Decryption(Encryption(PlainText, Key), Key2), Key3);
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
			{
				//PKCS is Public Key Cryptography Standards
				/*
					https://en.wikipedia.org/wiki/Padding_(cryptography)
					https://datatracker.ietf.org/doc/html/rfc5652
					PKCS#7 is described in RFC 5652. (section-6.3)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Padding Data
				std::size_t padedDataByteSize = dataBlockByteSize + 8 - (dataBlockByteSize % 8);
				std::size_t paddingDataByteSize = padedDataByteSize - dataBlockByteSize;
				const std::vector<unsigned char> paddingData(paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));

				std::vector<unsigned char> temporaryDataBlock { std::move(inputDataBlock) };
				temporaryDataBlock.insert(temporaryDataBlock.end(), paddingData.begin(), paddingData.end());

				std::cout << "TripleDES Encryption Start !" << std::endl;

				for(std::size_t index = 0; index < Bit64_Keys.size(); index += 3)
				{
					//Use Encryption Main Round Key 1
					DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				
					//Use Encryption Main Round Key 2
					DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index + 1));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);

					//Use Encryption Main Round Key 3
					DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index + 2));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);
				}

				std::cout << "TripleDES Encryption End !" << std::endl;

				outputDataBlock.resize(padedDataByteSize);

				std::ranges::copy(temporaryDataBlock.begin(), temporaryDataBlock.end(), outputDataBlock.begin());
				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				break;
			}
			//PlainText = Decryption(Encryption(Decryption(CipherText, Key3), Key2), Key);
			case Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
			{
				std::vector<unsigned char> temporaryDataBlock { std::move(inputDataBlock) };

				std::cout << "TripleDES Decryption Start !" << std::endl;

				for(std::size_t index = Bit64_Keys.size() - 1; index > 0; index -= 3)
				{
					if(index >= Bit64_Keys.size())
					{
						break;
					}

					//Use Decryption Main Round Key 1
					DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);
				
					//Use Decryption Main Round Key 2
					DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index - 1));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_ENCRYPTER, temporaryDataBlock, false);

					//Use Decryption Main Round Key 3
					DES_Worker.UpadateMainKeyAndSubKey(Bit64_Keys.operator[](index - 2));
					temporaryDataBlock = DES_Worker.DES_Executor(Cryptograph::CommonModule::CryptionMode2MCAC4_FDW::MCA_DECRYPTER, temporaryDataBlock, false);
				}

				std::cout << "TripleDES Decryption End !" << std::endl;

				outputDataBlock.resize(temporaryDataBlock.size());

				std::ranges::copy(temporaryDataBlock.begin(), temporaryDataBlock.end(), outputDataBlock.begin());
				temporaryDataBlock.clear();
				temporaryDataBlock.shrink_to_fit();

				if(outputDataBlock.empty())
				{
					throw std::runtime_error("CommonSecurity::TripleDES::TripleDES_Executor() The size of the output data cannot be zero!");
				}

				//PKCS is Public Key Cryptography Standards
				/*
					https://en.wikipedia.org/wiki/Padding_(cryptography)
					https://datatracker.ietf.org/doc/html/rfc5652
					PKCS#7 is described in RFC 5652. (section-6.3)

					Padding is in whole bytes.
					The value of each added byte is the number of bytes that are added, i.e. bytes, each of value are added.
					The number of bytes added will depend on the block boundary to which the message needs to be extended. 
				*/
				//Unpadding Data
				std::size_t paddingDataByteSize = outputDataBlock.back();
				const std::vector<unsigned char> paddingData(paddingDataByteSize, static_cast<unsigned char>(paddingDataByteSize));
				auto searchHasBeenFoundSubrange = std::ranges::search(outputDataBlock.end() - paddingDataByteSize * 2, outputDataBlock.end(), paddingData.begin(), paddingData.end());
				if(searchHasBeenFoundSubrange.begin() != searchHasBeenFoundSubrange.end())
				{
					outputDataBlock.erase(searchHasBeenFoundSubrange.begin(), searchHasBeenFoundSubrange.end());
					outputDataBlock.shrink_to_fit();
				}
				else
				{
					throw std::logic_error("Operation failed, maybe the padding data, before encryption, was corrupted?");
				}

				break;
			}
			default:
			{
				std::cout << "Wrong TripleDES Algorithm worker is selected" << std::endl;
				abort();
			}
		}
	}
}

namespace CommonSecurity::RC6::DefineConstants
{
	constexpr unsigned int KEY_BIT_SIZE_MAX_LIMIT = 8 * 255;

	/*
	
	double GOLDEN_RATIO 0.618033988749895 = 1 / ((1 + std::sqrt(5)) / 2) is 1 / 1.618033988749895;
	(std::numbers::phi == 1 / 0.618033988749895) is true
	(0.618033988749895 == 1 / std::numbers::phi) is true
	where Φ is the golden ratio constant
	
	*/
	constexpr double GOLDEN_RATIO = std::numbers::phi - 1;

	/*
	
	double BASE_OF_THE_NATURAL_LOGARITHM = sum( 1/(factorial(items_number)) + 1/(factorial(items_number - 1 )) + 1/(factorial(items_number - 2)) ..... + 1/(factorial(1)) + 1/(factorial(0)) ) is 2.718281828459045
	If items_number approaches infinity, hen it is the limit of (1 + 1/items_number)^items_number
	where e is the base of natural logarithm function
	
	*/
	constexpr double BASE_OF_THE_NATURAL_LOGARITHM = std::numbers::e;

	//least significant bit by 32
	static const unsigned int LSB_32_Value = std::log2(static_cast<unsigned int>(32));
}

namespace CommonSecurity::RC6::ProcedureFunctions
{
	#if 0

	//Rotate the w-bit word a(source_value) to the left by the amount given by the least significant log w bits of b(offset_value)
	//将w位的字a(source_value)向左旋转，旋转量由b(offset_value)的最小有效对数w位给出。
	inline unsigned int LeftRotateBit(unsigned int source_value, unsigned int offset_value, const unsigned int word_bit_size = 32, const unsigned int log2_word_bit_size = RC6::DefineConstants::LSB_32_Value)
	{
		unsigned int mask = 0xFFFFFFFF >> (word_bit_size - log2_word_bit_size);
		offset_value &= mask;
		unsigned int value = (source_value << offset_value) | (source_value >> (word_bit_size - offset_value));
		return value;
	}

	//Rotate the w-bit word a(source_value) to the right by the amount given by the least significant log w bits of b(offset(source_value)
	//将w位的字a(source_value)向右旋转，旋转量由b(offset_value)的最小有效对数w位给出。
	inline unsigned int RightRotateBit(unsigned int source_value, unsigned int offset_value, const unsigned int word_bit_size = 32, const unsigned int log2_word_bit_size = RC6::DefineConstants::LSB_32_Value)
	{
		unsigned int mask = 0xFFFFFFFF >> (word_bit_size - log2_word_bit_size);
		offset_value &= mask;
		unsigned int value = (source_value >> offset_value) | (source_value << (word_bit_size - offset_value));
		return value;
	}

	#endif

	/**
	 * Rotate a N-bit value left
	 * @param word: value to rotate
	 * @param shift: bits to roll
	 */
	template<class Type>
	inline Type LeftRotateBit(Type word, int shift)
	{
		return (word << shift) | (word >> (std::numeric_limits<Type>::digits - shift));
	}

	/**
	 * Rotate a N-bit value right
	 * @param word: value to rotate
	 * @param shift: bits to roll
	 */
	template<class Type>
	inline Type RightRotateBit(Type word, int shift)
	{
		return (word >> shift) | (word << (std::numeric_limits<Type>::digits - shift));
	}

	/**
	 * Check if architecture is big or little endian
	 */
	inline bool is_big_endian()
	{
		#if __cplusplus >= 202002L

		return std::endian::native == std::endian::big;

		#else

		union
		{
			unsigned int i;
			char c[4];
		} bint = {0x01020304};

		return bint.c[0] == 1;

		#endif
	}

	/**
	 * Reverse endianness of a type
	 * @param u: value to flip endianness of
	 */
	template<typename Type>
	Type SwapEndian(Type u)
	{
		static_assert(std::numeric_limits<unsigned char>::digits == 8, "CHAR_BIT != 8");

		union
		{
			Type u;
			unsigned char u8[sizeof(Type)];
		} source, dest;

		source.u = u;

		for (size_t index = 0; index < sizeof(Type); index++)
			dest.u8[index] = source.u8[sizeof(Type) - index - 1];

		return dest.u;
	}

	template<typename Type>
	concept BlockWordType = std::same_as<Type, unsigned int> || std::same_as<Type, unsigned long long>;

	template<typename Type> requires BlockWordType<Type>
	class BaseInterface
	{

	public:
		virtual void Encryption(std::vector<unsigned char>& dataBlock, const std::vector<unsigned char>& keyBlock) = 0;
		virtual void Decryption(std::vector<unsigned char>& dataBlock, const std::vector<unsigned char>& keyBlock) = 0;

		virtual size_t BlockSize() { return sizeof(Type); }
		virtual size_t BlockByteSize() { return sizeof(Type) * 4; }

		virtual ~BaseInterface() = default;
	};
}
