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

#include "Support+Library/Support-MyType.hpp"

#ifndef HUFFMAN_TREE_TEST
//#define HUFFMAN_TREE_TEST
#endif // !HUFFMAN_TREE_TEST

//vector<char>只许装16进制，字母需要大写
//vector<std::bitset<8>>48个字节文件头，1个字节文件尾

namespace CompressDataProcessing
{
	//Huffman文件压缩
	namespace Huffman
	{
		//Huffman压缩部分
		class Compression
		{

		public:
			struct HuffmanNode
			{
				char _characterData;
				int _weight;
				struct HuffmanNode* _left;
				struct HuffmanNode* _right;
				HuffmanNode(HuffmanNode* left, HuffmanNode* right);
				HuffmanNode(char teamporary, int node_weight);
			}*root;

		private:

			//编码map
			std::map<const char, std::string>_CodingMap;
			//压缩过的vector<8-bit>
			std::vector<std::bitset<8>> _CompressedBits;

		public:

			//采用引用传递，考虑数据作用域，返回数据也是引用传递
			//主压缩程序，接受文件数据，然后处理，返回vector<8-bit>
			std::vector<std::bitset<8>>& Main_Compression(std::vector<char>& _DecompressedDatas);
			
			Compression();
			~Compression();

			Compression(Compression& object) = delete;

		private:

			//接受文件数据传入, 统计权重，构建Huffman Tree
			void Make_Code_map(std::vector<char>& _DecompressedDatas);
			//遍历Huffman树
			void Traversing_Tree(const HuffmanNode* head, std::string code);
			//写Huffman编码进bits
			void Write_Code(std::vector<char>& _DecompressedDatas);
			//用于释放树内存的空间
			void Delete_tree(HuffmanNode* head);
		};

		Compression::HuffmanNode::HuffmanNode(HuffmanNode* left, HuffmanNode* right)
			:_characterData('!'), _weight(0), _left(nullptr), _right(nullptr)
		{
			this->_characterData = '!';
			this->_weight = left->_weight + right->_weight;
			this->_left = left;
			this->_right = right;
		}

		Compression::HuffmanNode::HuffmanNode(char teamporary, int node_weight)
			:_characterData('!'), _weight(0), _left(nullptr), _right(nullptr)
		{
			this->_characterData = teamporary;
			this->_weight = node_weight;
			this->_left = nullptr;
			this->_right = nullptr;
		}
		Compression::Compression()
			:root(nullptr)
		{
		}

		Compression::~Compression()
		{
		}
		struct Build_Tree
		{
			bool operator()(const Compression::HuffmanNode* nodeA, const Compression::HuffmanNode* nodeB)const
			{

				if (nodeA->_weight != nodeB->_weight)
				{

					return nodeA->_weight < nodeB->_weight;
				}
				else
				{
					if (nodeA->_characterData != '!' && nodeB->_characterData != '!')
					{
						return nodeA->_characterData < nodeB->_characterData;
					}
					else
					{
						return nodeA->_characterData != '!' && nodeB->_characterData == '!';
					}
				}
			}
		};

		//主程序可以选择返回值，用空对象调用
		std::vector<std::bitset<8>>& Compression::Main_Compression(std::vector<char>& _DecompressedDatas)
		{
			//接受文件数据传入, 统计权重，构建Huffman Tree,生成map
			Make_Code_map(_DecompressedDatas);
			//接受文件并压缩完成
			Write_Code(_DecompressedDatas);
			_CompressedBits.resize(_CompressedBits.size());
			return _CompressedBits;
		}

		void Compression::Make_Code_map(std::vector<char>& _DecompressedDatas)
		{
			//构建叶子节点
			std::multiset<HuffmanNode*, Build_Tree> tree
			{
				new HuffmanNode{ '0', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '0')) },
				new HuffmanNode{ '1', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '1')) },
				new HuffmanNode{ '2', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '2')) },
				new HuffmanNode{ '3', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '3')) },
				new HuffmanNode{ '4', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '4')) },
				new HuffmanNode{ '5', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '5')) },
				new HuffmanNode{ '6', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '6')) },
				new HuffmanNode{ '7', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '7')) },
				new HuffmanNode{ '8', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '8')) },
				new HuffmanNode{ '9', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), '9')) },
				new HuffmanNode{ 'A', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), 'A')) },
				new HuffmanNode{ 'B', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), 'B')) },
				new HuffmanNode{ 'C', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), 'C')) },
				new HuffmanNode{ 'D', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), 'D')) },
				new HuffmanNode{ 'E', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), 'E')) },
				new HuffmanNode{ 'F', static_cast<int>(std::count(_DecompressedDatas.begin(), _DecompressedDatas.end(), 'F')) },
			};

			//Huffman树构建
			while (tree.size() >= 2)
			{
				HuffmanNode* leftNode = *tree.begin();
				HuffmanNode* rightNode = *tree.erase(tree.begin());
				tree.insert(new HuffmanNode(leftNode, rightNode));
				tree.erase(tree.begin());;
				//遍历树生成Huffman编码
				if (tree.size() == 1)
				{
					std::string teamporary;
					root = *tree.begin();
					Traversing_Tree(root, teamporary);
				}
			}

			//释放树的空间
			{
				Delete_tree(root);
				delete root;
				root = nullptr;
			}
		}


		void Compression::Traversing_Tree(const HuffmanNode* head, std::string code)
		{

			if (head->_left != nullptr && head->_right != nullptr)
			{
				Traversing_Tree(head->_left, code += "0");
				code.erase(code.end() - 1);
				Traversing_Tree(head->_right, code += "1");
				code.erase(code.end() - 1);
				return;
			}
			else
			{
				if (head->_characterData != '!')
					_CodingMap.insert(std::make_pair(head->_characterData, code));
				return;
			}

		}

		void Compression::Write_Code(std::vector<char>& _DecompressedDatas)
		{
			std::string teamporary0 = "";
			/*
				写入哈夫曼编码头
				可以注释掉 选择打开测试0 可以查看每个字母的编码
				文件头占48个字节，可以继续压缩不过空间不固定（大概16到40字节之间），写入和读取不方便
			*/
			for (auto iter = _CodingMap.begin(); iter != _CodingMap.end(); iter++)
			{
				std::bitset<8> teamporary_bit{ iter->second.size() };//写入编码长度方便读取
				_CompressedBits.push_back(teamporary_bit);
				teamporary0 = iter->second + "00000000000000000";
				std::bitset<8> teamporary_bit0{ teamporary0,0,8 };
				std::bitset<8> teamporary_bit1{ teamporary0,8,8 };
				_CompressedBits.push_back(teamporary_bit0);
				_CompressedBits.push_back(teamporary_bit1);
				std::string().swap(teamporary0);
			}

			//压缩中
			for (auto iter = _DecompressedDatas.begin(); iter != _DecompressedDatas.end(); iter++)
			{
				teamporary0 += _CodingMap[*iter];
				//测试0
				//{
				//std::cout << teamporary0 << "\n";
				//teamporary0.clear();
				//}
				while (teamporary0.size() >= 8)
				{
					std::bitset<8> teamporary_bit0{ teamporary0,0,8 };
					_CompressedBits.push_back(teamporary_bit0);
					teamporary0.erase(0, 8);
				}

				//清理内存，可以注释掉提高效率
				{
					std::string  teamporary1 = teamporary0.substr(0);
					teamporary0.swap(teamporary1);
					std::string().swap(teamporary1);
				}
			}
			std::map<const char, std::string >().swap(_CodingMap);//code map销毁
			if (!teamporary0.empty())
			{

				std::bitset<8> teamporary_bit1{ teamporary0.size() };//记录是否补0
				teamporary0 += "0000000000";
				std::bitset<8> teamporary_bit0{ teamporary0,0,8 };
				_CompressedBits.push_back(teamporary_bit0);
				_CompressedBits.push_back(teamporary_bit1);
				std::string().swap(teamporary0);
			}
			//压缩完成
		}

		void Compression::Delete_tree(HuffmanNode* head)
		{
			if (head->_left != nullptr)
			{
				Delete_tree(head->_left);
				delete head->_left;
				head->_left = nullptr;
			}
			if (head->_right != nullptr)
			{
				Delete_tree(head->_right);
				delete head->_right;
				head->_right = nullptr;
			}

			return;
		}

	}
}

namespace CompressDataProcessing
{
	//Huffman文件解压
	namespace Huffman
	{
		//Huffman解压缩
		class Decompression
		{
		public:
			//主解压缩程序
			std::vector<char>& Main_Decompress(std::vector<std::bitset<8>>& _CompressedBits);

			Decompression();
			~Decompression();

			Decompression(Decompression& object) = delete;

		private:
			//返回的数据
			std::vector<char> _DecompressedDatas;
			//编码图
			std::map<std::string, const char>_CodingMap;

		private:
			//读取Huffman编码
			void Read_HuffmanCode_Map(std::vector<std::bitset<8>>& _CompressedBits);
			//写入数据流
			void Write_Data(std::vector<std::bitset<8>>& _CompressedBits);
		};

		Decompression::Decompression()
		{
		}

		Decompression::~Decompression()
		{
		}

		std::vector<char>& Decompression::Main_Decompress(std::vector<std::bitset<8>>& _CompressedBits)
		{
			Read_HuffmanCode_Map(_CompressedBits);
			Write_Data(_CompressedBits);
			std::map<std::string, const char>().swap(_CodingMap);
			return _DecompressedDatas;
		}

		void Decompression::Read_HuffmanCode_Map(std::vector<std::bitset<8>>& _CompressedBits)
		{
			constexpr char transArray[]
			{
				'0', '1', '2', '3', '4', '5', '6', '7',
				'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
			};

			//读取编码map
			auto iter = _CompressedBits.begin();
			for (int index = 0; index < 16; index++, iter++)
			{
				std::string code;
				//获得编码map长度
				int code_size = iter->to_ulong();
				iter++;
				code += iter->to_string();
				iter++;
				code += iter->to_string();
				_CodingMap.insert(std::make_pair(code.substr(0, code_size), transArray[index]));
				
				std::string().swap(code);
			}
			_CompressedBits.erase(_CompressedBits.begin(), iter);

		}

		void Decompression::Write_Data(std::vector<std::bitset<8>>& _CompressedBits)
		{
			//数据是否填充0
			bool is8bit = false;
			auto iter = _CompressedBits.begin();
			std::string teamporary;
			std::string teamporary0;
			int code_size = _CompressedBits.back().to_ulong();
			if (code_size)
			{
				//对填充0的数据做拆分
				is8bit = true;
				_CompressedBits.pop_back();
				teamporary = _CompressedBits.back().to_string();
				teamporary0 = teamporary.substr(0, code_size);
				std::string().swap(teamporary);
			}
			_CompressedBits.pop_back();

			//写入数据
			while (iter != _CompressedBits.end())
			{
				teamporary += iter->to_string();
				iter++;
				if (is8bit && iter == _CompressedBits.end())
				{
					teamporary += teamporary0;
				}
				size_t index = 1;
				while (index++)
				{
					auto iter2 = _CodingMap.find(teamporary.substr(0, index));
					if (iter2 != _CodingMap.end())
					{
						_DecompressedDatas.push_back(iter2->second);
						teamporary.erase(0, index);
						index = 1;
					}
					if (teamporary.size() <= index)
					{
						break;
					}
				}
			}
		}
	}  // namespace Huffman
}  // namespace CompressDataProcessing


////////////////////////////////TEST/////////////////////////////////////

#if defined(HUFFMAN_TREE_TEST)

struct Printer
{
	//std::bitset<8>&
	//const char
	void operator()(const char& temporary)const
	{
		std::cout << "\n";
		std::cout << temporary << "\n";
	}
};

int main()
{
	using namespace  CompressDataProcessing::Huffman;
	std::vector<char> d{ '0','A','C','2','D' };
	Compression Compressor;
	std::vector<std::bitset<8>> Bits = Compressor.Main_Compression(d);
	Decompression Decompressor;
	std::vector<char> d1;
	d1 = Decompressor.Main_Decompress(Bits);
	std::for_each(d1.begin(), d1.end(), Printer());
	return 0;
}

#endif
