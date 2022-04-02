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

#include "Support-MyType.hpp"

//多线程无锁支持
//Multi-threaded lock-free support
namespace MySupport_Library::ExperimentalExtensions::MultiThreaded_LockFreeSupport
{

	template<typename Type> requires std::is_copy_assignable_v<Type> || std::is_copy_constructible_v<Type> || std::is_move_assignable_v<Type> || std::is_move_constructible_v<Type>
	class DataAtomizedWrapper
	{

	private:

		//Wrapped data
		Type Data;

		std::atomic_flag DataIsProtected {};
		std::atomic_flag DataIsOccupied {};
		std::atomic_flag DataIsChanging {};
		std::atomic_flag DataIsChanged {};

	protected:

		//Memory operations using C plus plus standard template library
		bool MemoryFunctionLibraryWithCPPSTL = true;

		enum class DataWorkMode
		{
			Copy = 0,
			Move = 1
		};

		DataWorkMode _DataWorkMode;

		bool _DataIsChanging()
		{
			return DataIsChanging.test(std::memory_order::memory_order_seq_cst);
		}

		bool _DataIsChanged(const Type& OldData, const Type& NewData)
		{
			using namespace MemoryOperation;

			if (MemoryFunctionLibraryWithCPPSTL)
			{
				return std::memcmp(std::addressof(OldData), std::addressof(NewData), sizeof(OldData)) != 0;
			}
			else
			{
				return MemoryOperation::MemoryDataComparison_Fixed<sizeof(OldData)>(MemoryOperation::addressof(OldData), MemoryOperation::addressof(NewData)) != 0;
			}
		}

	public:

		void setWorkMode(int dataWorkMode)
		{
			DataWorkMode _dataWorkMode = DataWorkMode(dataWorkMode);

			switch (_dataWorkMode)
			{

			case DataWorkMode::Copy:
				_DataWorkMode = _dataWorkMode;
				break;
			case DataWorkMode::Move:
				_DataWorkMode = _dataWorkMode;
				break;
			default:
				break;
			}
		}

		int getWorkMode()
		{
			return int(_DataWorkMode);
		}

		void switchingMemoryOperationModes()
		{
			MemoryFunctionLibraryWithCPPSTL = !MemoryFunctionLibraryWithCPPSTL;
		}

		std::optional<Type> loadData()
		{
			DataIsChanging.wait(true);

			DataIsChanged.test_and_set(false, std::memory_order::memory_order_seq_cst);

			if (DataIsOccupied.test(std::memory_order::memory_order_seq_cst) == false && DataIsChanged.test(std::memory_order::memory_order_seq_cst) == false)
			{
				DataIsOccupied.test_and_set(true, std::memory_order::memory_order_seq_cst);
				DataIsOccupied.notify_all();
				return Data;
				DataIsOccupied.clear(std::memory_order::memory_order_seq_cst);
				DataIsOccupied.notify_all();
			}
			else
			{
				return std::nullopt;
			}
		}

		bool storeData(const Type& NewData, bool WaitToDataIsChanged = false)
		{
			using namespace MemoryOperation;

			DataIsProtected.wait(true);

			if (_DataIsChanging() != true)
			{
				if (DataIsOccupied.test(std::memory_order::memory_order_seq_cst) == true)
				{
					DataIsOccupied.wait(true, std::memory_order::memory_order_seq_cst);
				}
				else
				{
					DataIsOccupied.test_and_set(true, std::memory_order::memory_order_seq_cst);
				}

				DataIsChanging.test_and_set(true, std::memory_order::memory_order_seq_cst);
				DataIsChanging.notify_all();

				Type OldData(std::move(Data));

				if (_DataWorkMode == DataWorkMode::Copy)
				{
					if (MemoryFunctionLibraryWithCPPSTL)
					{
						std::memcpy(std::addressof(Data), std::addressof(NewData), sizeof(NewData));
					}
					else
					{
						MemoryOperation::MemoryDataCopy<sizeof(NewData)>(MemoryOperation::addressof(Data), MemoryOperation::addressof(NewData));
					}
				}
				if (_DataWorkMode == DataWorkMode::Move)
				{
					if (MemoryFunctionLibraryWithCPPSTL)
					{
						std::memmove(std::addressof(Data), std::addressof(NewData), sizeof(NewData));
					}
					else
					{
						MemoryOperation::MemoryDataCopy<sizeof(NewData)>(MemoryOperation::addressof(Data), MemoryOperation::addressof(NewData));
					}
					std::swap(std::move(Type()), std::move(NewData));
				}

				DataIsChanging.clear(std::memory_order::memory_order_seq_cst);
				DataIsChanging.notify_one();

				if (_DataIsChanged(OldData, Data) == false)
				{
					DataIsOccupied.test_and_set(false, std::memory_order::memory_order_seq_cst);
					return false;
				}
				else
				{
					DataIsChanged.test_and_set(true, std::memory_order::memory_order_seq_cst);
				}

				DataIsOccupied.test_and_set(false, std::memory_order::memory_order_seq_cst);
				return true;
			}
			else
			{
				if (WaitToDataIsChanged == false)
				{
					this->storeData(NewData, true);
				}
			}
		}

		void exchangeData(Type& OtherData)
		{
			DataIsProtected.test_and_set(std::memory_order::memory_order_seq_cst);
			DataIsProtected.notify_all();
			OtherData = std::exchange(std::move(Data), std::move(OtherData));
			DataIsProtected.clear(std::memory_order::memory_order_seq_cst);
			DataIsProtected.notify_all();
		}

		bool data_is_protected()
		{
			return DataIsProtected.test(std::memory_order::memory_order_seq_cst);
		}

		bool data_is_changed()
		{
			return DataIsChanged.test(std::memory_order::memory_order_seq_cst);
		}

		void freeze()
		{
			DataIsProtected.test_and_set(std::memory_order::memory_order_seq_cst);
			DataIsProtected.notify_all();
		}

		void unfreeze()
		{
			DataIsProtected.clear();
			DataIsProtected.notify_all();
		}

		DataAtomizedWrapper()
		{
			this->setWorkMode(0);
		}

		explicit DataAtomizedWrapper(const Type& _object)
		{
			this->setWorkMode(0);
			this->storeData(_object);
		}

		~DataAtomizedWrapper() = default;

		DataAtomizedWrapper(const DataAtomizedWrapper& _object) = delete;
		DataAtomizedWrapper& operator=(const DataAtomizedWrapper& _object) = delete;
	};

	template<typename Type> requires std::is_copy_assignable_v<Type> || std::is_copy_constructible_v<Type> || std::is_move_assignable_v<Type> || std::is_move_constructible_v<Type>
	bool ExchangeDataAtomized(DataAtomizedWrapper<Type>&LeftObject, DataAtomizedWrapper<Type>&RightObject)
	{
		LeftObject.freeze();
		RightObject.freeze();

		while (LeftObject.DataIsOccupied.test(std::memory_order::memory_order_seq_cst) = true || RightObject.DataIsOccupied.test(std::memory_order::memory_order_seq_cst) = true)
		{
			continue;
		}

		RightObject.DataIsChanged.test_and_set(LeftObject.DataIsChanged.test_and_set(RightObject.DataIsChanged.test(), std::memory_order::memory_order_seq_cst), std::memory_order::memory_order_seq_cst);
		RightObject.DataIsChanging.test_and_set(LeftObject.DataIsChanging.test_and_set(RightObject.DataIsChanging.test(), std::memory_order::memory_order_seq_cst), std::memory_order::memory_order_seq_cst);
		LeftObject.exchangeData(RightObject.loadData());

		RightObject.unfreeze();
		LeftObject.unfreeze();
	}
}
