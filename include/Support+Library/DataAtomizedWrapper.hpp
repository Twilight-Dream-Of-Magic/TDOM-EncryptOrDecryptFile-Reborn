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

	protected:

		//Memory operations using C plus plus standard template library
		bool MemoryFunctionLibraryWithCPPSTL = true;

		enum class DataWorkMode
		{
			Copy = 0,
			Move = 1
		};

		DataWorkMode _DataWorkMode;

		std::atomic<bool> DataIsProtected = false;
		std::atomic<bool> DataIsOccupied = false;
		std::atomic<bool> DataIsChanging = false;
		std::atomic<bool> DataIsChanged = false;

		bool _DataIsChanging()
		{
			if (DataIsChanging != false)
			{
				return false;
			}
			else
			{
				return true;
			}
		}

		bool _DataIsChanged(const Type& OldData, const Type& NewData)
		{
			using namespace MemoryOperation;

			if (MemoryFunctionLibraryWithCPPSTL)
			{
				return std::memcmp(std::addressof(OldData), std::addressof(NewData), sizeof(OldData)) != 0;
			}
			return MemoryOperation::MemoryDataComparison_Fixed<sizeof(OldData)>(MemoryOperation::addressof(OldData), MemoryOperation::addressof(NewData)) != 0;
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

		Type loadData()
		{
			if (_DataIsChanging() == true)
			{
				DataIsChanging.wait(true);
			}

			DataIsChanged.store(false);

			if (DataIsOccupied.load() == false && DataIsChanged.load() == false)
			{
				DataIsOccupied.store(true);
				return Data;
				DataIsOccupied.store(false);
			}
			else
			{
				return Type();
			}
		}

		bool storeData(const Type& NewData, bool WaitToDataIsChanged = false)
		{
			using namespace MemoryOperation;

			if (DataIsProtected.load() == false)
			{
				if (_DataIsChanging() != true)
				{
					if (DataIsOccupied.load() == true)
					{
						DataIsOccupied.wait(true);
					}
					else
					{
						DataIsOccupied.store(true);
					}

					DataIsChanging.store(true);

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

					DataIsChanging.store(false);
					DataIsChanging.notify_one();

					if (_DataIsChanged(OldData, Data) == false)
					{
						DataIsOccupied.store(false);
						return false;
					}
					else
					{
						DataIsChanged.store(true);
					}

					DataIsOccupied.store(false);
					return true;
				}
				else
				{
					if (WaitToDataIsChanged == true)
					{
						this->store(NewData, true);
					}
				}
			}
		}

		void exchangeData(Type& OtherData)
		{
			DataIsProtected.store(true);
			std::swap(std::move(Data), std::move(OtherData));
			DataIsProtected.store(false);
		}

		bool data_is_protected()
		{
			return DataIsProtected.load() == true;
		}

		bool data_is_changed()
		{
			return DataIsChanged.load();
		}

		void freeze()
		{
			DataIsProtected.store(true);
		}

		void unfreeze()
		{
			DataIsProtected.store(false);
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

		while (LeftObject.DataIsOccupied.load() = true || RightObject.DataIsOccupied.load() = true)
		{
			continue;
		}

		RightObject.DataIsChanged.store(LeftObject.DataIsChanged.exchange(RightObject.DataIsChanged.load()));
		RightObject.DataIsChanging.store(LeftObject.DataIsChanging.exchange(RightObject.DataIsChanging.load()));
		LeftObject.exchangeData(RightObject.loadData());

		RightObject.unfreeze();
		LeftObject.unfreeze();

	}
}
