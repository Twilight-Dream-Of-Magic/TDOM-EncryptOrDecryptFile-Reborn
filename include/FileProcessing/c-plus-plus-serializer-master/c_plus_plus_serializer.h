#ifndef C_PLUS_PLUS_SERIALIZER
#define C_PLUS_PLUS_SERIALIZER

namespace CPlusPlus_Serializer
{

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

	inline std::uint8_t is_little_endian()
	{
		static std::int32_t test = 1;
		return *reinterpret_cast<std::int8_t*>( &test ) == 1;
	}

	inline void portable_swap_bytes( std::uint8_t * data, std::size_t DataSize )
	{
		for( std::size_t begin = 0, end = DataSize / 2; begin < end; ++begin )
		{
			std::swap( data[begin], data[DataSize - begin - 1] );
		}
	}

	//
	// 64 bits for serializing is a bit overkill for serializing, so use int
	//
	#ifdef USE_SIZE_T
	using my_size_t = size_t;
	#else
	using my_size_t = unsigned int;
	#endif

	template < typename TYPE > struct Bits {
		TYPE object_type;
	};

	template < typename TYPE > static inline Bits< TYPE & > bits(TYPE &t) { return Bits< TYPE & > {t}; }

	template < typename TYPE > static inline Bits< const TYPE & > bits(const TYPE &t) { return Bits< const TYPE & > {t}; }

	////////////////////////////////////////////////////////////////////////////
	// Read/write POD types
	////////////////////////////////////////////////////////////////////////////
	template < typename TYPE > static inline std::istream &operator>>(std::istream &in, Bits< TYPE & > b)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read " << sizeof(TYPE) << " bytes" << std::endl;
	#endif

	#if __cplusplus >= 202002L

		if constexpr (std::endian::native == std::endian::big)
		{
			const std::streamsize objectSize = sizeof(b.object_type);
			const std::streamsize dataTypeSize = sizeof(TYPE);
			std::streamsize readedSize = 0;
			const void * dataPointer = std::addressof(b.object_type);

			// Big endian system

			// load data
			readedSize = in.rdbuf()->xsgetn( std::bit_cast<char*>( dataPointer ), objectSize );

			std::uint8_t * bytePointer = std::bit_cast<std::uint8_t*>( dataPointer );
			for( std::streamsize i = 0; i < objectSize; i += dataTypeSize )
			{
				portable_swap_bytes( bytePointer + i, static_cast<std::size_t>(dataTypeSize) );
			}

			if(readedSize != objectSize)
			{
				throw std::runtime_error("Failed to read " + std::to_string(objectSize) + " bytes from input stream! Read " + std::to_string(readedSize));
			}
		} 
		else if constexpr (std::endian::native == std::endian::little)
		{
			// Little endian system

			// load data

			return in.read(std::bit_cast<char*>(std::addressof(b.object_type)), sizeof(TYPE));
		} 

	#else

		if (!static_cast<bool>(is_little_endian()))
		{
			// Big endian system

			const std::streamsize objectSize = sizeof(b.object_type);
			const std::streamsize dataTypeSize = sizeof(TYPE);
			std::streamsize readedSize = 0;
			const void * dataPointer = std::addressof(b.object_type);

			readedSize = in.rdbuf()->sgetn( reinterpret_cast<char*>( dataPointer ), objectSize );

			std::uint8_t * bytePointer = reinterpret_cast<std::uint8_t*>( dataPointer );
			for( std::streamsize i = 0; i < objectSize; i += dataTypeSize )
			{
				portable_swap_bytes( bytePointer + i, static_cast<std::size_t>(dataTypeSize) );
			}

			if(readedSize != objectSize)
			{
				throw std::runtime_error("Failed to read " + std::to_string(objectSize) + " bytes from input stream! Read " + std::to_string(readSize));
			}
		} 
		else
		{
			// Little endian system

			// reinterpret_cast is for pointer conversion
			// static_cast is for compatible pointer conversion

			// load data
			return in.read(reinterpret_cast< char *>(std::addressof(b.object_type)), sizeof(TYPE));
		}

	#endif

	}

	template < typename TYPE > static inline std::ostream &operator<<(std::ostream &out, Bits< TYPE & > const b)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write " << sizeof(TYPE) << " bytes" << std::endl;
	#endif



	#if __cplusplus >= 202002L

		if constexpr (std::endian::native == std::endian::big)
		{
			const std::streamsize objectSize = sizeof(b.object_type);
			const std::streamsize dataTypeSize = sizeof(TYPE);
			std::streamsize writedSize = 0;
			const void * dataPointer = std::addressof(b.object_type);

			// Big endian system

			for (std::streamsize i = 0; i < objectSize; i += dataTypeSize)
			{
				for (std::streamsize j = 0; j < dataTypeSize; ++j)
				{
					// save data
					writedSize += out.rdbuf()->xsputn(std::bit_cast<const char *>(dataPointer) + dataTypeSize - j - 1 + i, 1);
				}
			}

			if(writedSize != objectSize)
			{
				throw std::runtime_error("Failed to write " + std::to_string(objectSize) + " bytes to output stream! Wrote " + std::to_string(writedSize));
			}
		} 
		else if constexpr (std::endian::native == std::endian::little)
		{
			// Little endian system

			// save data
			return out.write(std::bit_cast<char *>(std::addressof(b.object_type)), sizeof(TYPE));
		}

	#else

		if (!static_cast<bool>(is_little_endian()))
		{
			const std::streamsize objectSize = sizeof(b.object_type);
			const std::streamsize dataTypeSize = sizeof(TYPE);
			std::streamsize writedSize = 0;
			const void * dataPointer = std::addressof(b.object_type);

			// Big endian system

			for (std::streamsize begin = 0; begin < objectSize; begin += dataTypeSize)
			{
				for (std::streamsize j = 0; j < dataTypeSize; ++j)
				{
					writedSize += out.rdbuf()->sputn(reinterpret_cast<const char *>(dataPointer) + dataTypeSize - j - 1 + begin, 1);
				}	
			}

			if(writedSize != objectSize)
			{
				throw std::runtime_error("Failed to write " + std::to_string(objectSize) + " bytes to output stream! Writed " + std::to_string(writedSize));
			}
		} 
		else
		{
			// Little endian system

			// reinterpret_cast is for pointer conversion
			// static_cast is for compatible pointer conversion


			//save data
			return out.write(reinterpret_cast<const char *>(std::addressof(b.object_type)), sizeof(TYPE));
		}

	#endif
	}

	////////////////////////////////////////////////////////////////////////////
	// Read/write std::string
	////////////////////////////////////////////////////////////////////////////
	static inline std::istream &operator>>(std::istream &in, Bits< std::string & > v)
	{
		my_size_t sz = 0;
		in >> bits(sz);
		if (in && sz) {
		std::vector< char > tmp(sz);
		in.read(tmp.data(), sz);
		v.object_type.assign(tmp.data(), sz);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read '" << v.object_type << "'" << std::endl;
	#endif
		}

		return in;
	}

	static inline std::ostream &operator<<(std::ostream &out, Bits< const std::string & > const v)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write const '" << v.object_type << "'" << std::endl;
	#endif
		my_size_t sz = v.object_type.size();
		return out << bits(sz) << v.object_type;
	}

	static inline std::ostream &operator<<(std::ostream &out, Bits< std::string & > const v)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write '" << v.object_type << "'" << std::endl;
	#endif
		my_size_t sz = v.object_type.size();
		return out << bits(sz) << v.object_type;
	}

	////////////////////////////////////////////////////////////////////////////
	// Read/write std::wstring
	////////////////////////////////////////////////////////////////////////////
	static inline std::istream &operator>>(std::istream &in, Bits< std::wstring & > v)
	{
		my_size_t sz = 0;
		in >> bits(sz);
		if (in && sz) {
		while (sz--) {
			wchar_t tmp;
			in >> bits(tmp);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
			std::cout << "read '" << tmp << "'" << std::endl;
	#endif
			v.object_type += tmp;
		}
		}

		return in;
	}

	static inline std::ostream &operator<<(std::ostream &out, Bits< const std::wstring & > const v)
	{
		my_size_t sz = v.object_type.size();
		out << bits(sz);
		for (auto tmp : v.object_type) {
		out << bits(tmp);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write const '" << tmp << "'" << std::endl;
	#endif
		}
		return out;
	}

	static inline std::ostream &operator<<(std::ostream &out, Bits< std::wstring & > const v)
	{
		my_size_t sz = v.object_type.size();
		out << bits(sz);
		for (auto tmp : v.object_type) {
		out << bits(tmp);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write '" << tmp << "'" << std::endl;
	#endif
		}
		return out;
	}

	////////////////////////////////////////////////////////////////////////////
	// Read/write wchar_t
	////////////////////////////////////////////////////////////////////////////
	static inline std::istream &operator>>(std::istream &in, Bits< wchar_t & > v)
	{
		if (sizeof(wchar_t) == 4) {
		unsigned char _a, _b, _c, _d;
		in >> bits(_a);
		in >> bits(_b);
		in >> bits(_c);
		in >> bits(_d);
		v.object_type = (_a << 24) | (_b << 16) | (_c << 8) | _d;
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read '" << _a << "'" << std::endl;
		std::cout << "read '" << _b << "'" << std::endl;
		std::cout << "read '" << _c << "'" << std::endl;
		std::cout << "read '" << _d << "'" << std::endl;
	#endif
		} else if (sizeof(wchar_t) == 2) {
		unsigned char _a, _b;
		in >> bits(_a);
		in >> bits(_b);
		v.object_type = (_a << 8) | _b;
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read '" << _a << "'" << std::endl;
		std::cout << "read '" << _b << "'" << std::endl;
	#endif
		} else {
		static_assert(sizeof(wchar_t) <= 4, "wchar_t is greater that 32 bit");
		}

		return in;
	}

	static inline std::ostream &operator<<(std::ostream &out, Bits< const wchar_t & > const v)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write const '" << v.object_type << "'" << std::endl;
	#endif
		if (sizeof(wchar_t) == 4) {
		unsigned char _a, _b, _c, _d;
		_a = (v.object_type & (0xff000000)) >> 24;
		out << bits(_a);
		_b = (v.object_type & (0x00ff0000)) >> 16;
		out << bits(_b);
		_c = (v.object_type & (0x0000ff00)) >> 8;
		out << bits(_c);
		_d = (v.object_type & (0x000000ff)) >> 0;
		out << bits(_d);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write '" << _a << "'" << std::endl;
		std::cout << "write '" << _b << "'" << std::endl;
		std::cout << "write '" << _c << "'" << std::endl;
		std::cout << "write '" << _d << "'" << std::endl;
	#endif
		} else if (sizeof(wchar_t) == 2) {
		unsigned char _a, _b;
		_a = (v.object_type & (0xff00)) >> 8;
		out << bits(_a);
		_b = (v.object_type & (0x00ff)) >> 0;
		out << bits(_b);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write '" << _a << "'" << std::endl;
		std::cout << "write '" << _b << "'" << std::endl;
	#endif
		} else {
		static_assert(sizeof(wchar_t) <= 4, "wchar_t is greater that 32 bit");
		}
		return (out);
	}

	static inline std::ostream &operator<<(std::ostream &out, Bits< wchar_t & > const v)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write const '" << v.object_type << "'" << std::endl;
	#endif
		if (sizeof(wchar_t) == 4) {
		unsigned char _a, _b, _c, _d;
		_a = (v.object_type & (0xff000000)) >> 24;
		out << bits(_a);
		_b = (v.object_type & (0x00ff0000)) >> 16;
		out << bits(_b);
		_c = (v.object_type & (0x0000ff00)) >> 8;
		out << bits(_c);
		_d = (v.object_type & (0x000000ff)) >> 0;
		out << bits(_d);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write '" << _a << "'" << std::endl;
		std::cout << "write '" << _b << "'" << std::endl;
		std::cout << "write '" << _c << "'" << std::endl;
		std::cout << "write '" << _d << "'" << std::endl;
	#endif
		} else if (sizeof(wchar_t) == 2) {
		unsigned char _a, _b;
		_a = (v.object_type & (0xff00)) >> 8;
		out << bits(_a);
		_b = (v.object_type & (0x00ff)) >> 0;
		out << bits(_b);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write '" << _a << "'" << std::endl;
		std::cout << "write '" << _b << "'" << std::endl;
	#endif
		} else {
		static_assert(sizeof(wchar_t) <= 4, "wchar_t is greater that 32 bit");
		}
		return (out);
	}

	////////////////////////////////////////////////////////////////////////////
	// Read/write simple container
	////////////////////////////////////////////////////////////////////////////
	template < class T, template < typename ELEM, typename ALLOC = std::allocator< ELEM > > class C >
	static inline std::ostream &operator<<(std::ostream &out, Bits< C< T > & > const v)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write container<T> " << v.object_type.objectSize() << " elems" << std::endl;
	#endif
		my_size_t sz = v.object_type.size();
		out << bits(sz);
		for (auto i : v.object_type) {
		out << bits(i);
		}
		return (out);
	}

	template < class T, template < typename ELEM, typename ALLOC = std::allocator< ELEM > > class C >
	static inline std::ostream &operator<<(std::ostream &out, Bits< const C< T > & > const v)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write container<const T> " << v.object_type.objectSize() << " elems" << std::endl;
	#endif
		my_size_t sz = v.object_type.size();
		out << bits(sz);
		for (auto i : v.object_type) {
		out << bits(i);
		}
		return (out);
	}

	template < class T, template < typename ELEM, typename ALLOC = std::allocator< ELEM > > class C >
	static inline std::istream &operator>>(std::istream &in, Bits< C< T > & > v)
	{
		my_size_t sz = 0;
		in >> bits(sz);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read container<T> " << sz << " elems" << std::endl;
	#endif
		if (in && sz) {
		while (sz--) {
			T s;
			in >> bits(s);
			v.object_type.push_back(s);
		}
		}

		return in;
	}

	////////////////////////////////////////////////////////////////////////////
	// Read/write std::array
	////////////////////////////////////////////////////////////////////////////
	template < class T, std::size_t N, template < typename ELEM, std::size_t > class C >
	static inline std::ostream &operator<<(std::ostream &out, Bits< C< T, N > & > const v)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write array container<T> " << v.object_type.objectSize() << " elems" << std::endl;
	#endif
		my_size_t sz = v.object_type.size();
		out << bits(sz);
		for (auto i : v.object_type) {
		out << bits(i);
		}
		return (out);
	}

	template < class T, std::size_t N, template < typename ELEM, std::size_t > class C >
	static inline std::ostream &operator<<(std::ostream &out, Bits< const C< T, N > & > const v)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write array container<const T> " << v.object_type.objectSize() << " elems" << std::endl;
	#endif
		my_size_t sz = v.object_type.size();
		out << bits(sz);
		for (auto i : v.object_type) {
		out << bits(i);
		}
		return (out);
	}

	template < class T, std::size_t N, template < typename ELEM, std::size_t > class C >
	static inline std::istream &operator>>(std::istream &in, Bits< C< T, N > & > v)
	{
		my_size_t sz = 0;
		in >> bits(sz);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read array container<T> " << sz << " elems" << std::endl;
	#endif
		if (in && sz) {
		for (auto n = 0; n < sz; n++) {
			T s;
			in >> bits(s);
			v.object_type[ n ] = s;
		}
		}

		return in;
	}

	////////////////////////////////////////////////////////////////////////////
	// Read/write map
	////////////////////////////////////////////////////////////////////////////

	template < template < class K, class V, class Compare = std::less< K >,
							class Alloc = std::allocator< std::pair< const K, V > > >
				 class M,
				 class K, class V >

	static inline std::ostream &operator<<(std::ostream &out, Bits< M< K, V > & > const m)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write map<K,V> " << m.object_type.objectSize() << " elems" << std::endl;
	#endif
		my_size_t sz = m.object_type.size();
		out << bits(sz);
		for (auto i : m.object_type) {
		out << bits(i.first) << bits(i.second);
		}
		return (out);
	}

	template < template < class K, class V, class Compare = std::less< K >,
							class Alloc = std::allocator< std::pair< const K, V > > >
				 class M,
				 class K, class V >

	static inline std::ostream &operator<<(std::ostream &out, Bits< M< K, const V > & > const m)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write map<K,const V> " << m.object_type.objectSize() << " elems" << std::endl;
	#endif
		my_size_t sz = m.object_type.size();
		out << bits(sz);
		for (auto i : m.object_type) {
		out << bits(i.first) << bits(i.second);
		}
		return (out);
	}

	template < template < class K, class V, class Compare = std::less< K >,
							class Alloc = std::allocator< std::pair< const K, V > > >
				 class M,
				 class K, class V >

	static inline std::istream &operator>>(std::istream &in, Bits< M< K, V > & > m)
	{
		my_size_t sz = 0;
		in >> bits(sz);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read map<K,V> " << sz << " elems" << std::endl;
	#endif
		if (in && sz) {
		while (sz--) {
			K k;
			V v;
			in >> bits(k) >> bits(v);
			m.object_type.insert(std::make_pair(k, v));
		}
		}

		return in;
	}

	////////////////////////////////////////////////////////////////////////////
	// Read/write unordered_map
	////////////////////////////////////////////////////////////////////////////

	template < template < class K, class T, class Hash = std::hash< K >, class Pred = std::equal_to< K >,
							class Alloc = std::allocator< std::pair< const K, T > > >
				 class M,
				 class K, class V >

	static inline std::ostream &operator<<(std::ostream &out, Bits< M< K, V > & > const m)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write unordered_map<K,V> " << m.object_type.objectSize() << " elems" << std::endl;
	#endif
		my_size_t sz = m.object_type.size();
		out << bits(sz);
		for (auto i : m.object_type) {
		out << bits(i.first) << bits(i.second);
		}
		return (out);
	}

	template < template < class K, class T, class Hash = std::hash< K >, class Pred = std::equal_to< K >,
							class Alloc = std::allocator< std::pair< const K, T > > >
				 class M,
				 class K, class V >

	static inline std::ostream &operator<<(std::ostream &out, Bits< M< K, const V > & > const m)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write unordered_map<K,const V> " << m.object_type.objectSize() << " elems" << std::endl;
	#endif
		my_size_t sz = m.object_type.size();
		out << bits(sz);
		for (auto i : m.object_type) {
		out << bits(i.first) << bits(i.second);
		}
		return (out);
	}

	template < template < class K, class T, class Hash = std::hash< K >, class Pred = std::equal_to< K >,
							class Alloc = std::allocator< std::pair< const K, T > > >
				 class M,
				 class K, class V >

	static inline std::istream &operator>>(std::istream &in, Bits< M< K, V > & > m)
	{
		my_size_t sz = 0;
		in >> bits(sz);
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read unordered_map<K,V> " << sz << " elems" << std::endl;
	#endif
		if (in && sz) {
		while (sz--) {
			K k;
			V v;
			in >> bits(k) >> bits(v);
			m.object_type.insert(std::make_pair(k, v));
		}
		}

		return in;
	}

	////////////////////////////////////////////////////////////////////////////
	// Read/write pair
	////////////////////////////////////////////////////////////////////////////

	template < typename K, typename V >
	static inline std::ostream &operator<<(std::ostream &out, Bits< std::pair< K, V > & > const wrapped)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "read pair<K,V>" std::endl;
	#endif
		out << bits(wrapped.object_type.first);
		out << bits(wrapped.object_type.second);
		return (out);
	}

	template < typename K, typename V >
	static inline std::istream &operator>>(std::istream &in, Bits< std::pair< K, V > & > wrapped)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "write pair<K,V>" std::endl;
	#endif
		in >> bits(wrapped.object_type.first);
		in >> bits(wrapped.object_type.second);
		return in;
	}

	template < typename K, typename V >
	static inline std::istream &operator>>(std::istream &in, Bits< const std::pair< K, V > & > wrapped)
	{
	#ifdef DEBUG_C_PLUS_PLUS_SERIALIZER
		std::cout << "const write pair<K,V>" std::endl;
	#endif
		in >> bits(wrapped.object_type.first);
		in >> bits(wrapped.object_type.second);
		return in;
	}
	
}

#endif /* C_PLUS_PLUS_SERIALIZER */