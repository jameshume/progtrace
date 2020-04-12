/*
 * Derived from addr2line.c.
 *
 * Just refactored various bits and bobs in an attempt to try an understand it and use it for
 * this little program trace exercise. Nothing new here, all addr2line code, just refactored and
 * modified. All credits to addr2line - see Copyright below:
 *
 * To compile you will first need to `sudo apt install install binutils-dev and libiberty-dev`.
 *
 * -------------------------------------------------------------------------------------------------
 *
 * addr2line.c -- convert addresses to line number and function name
 * Copyright 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009
 * Free Software Foundation, Inc.
 * Contributed by Ulrich Lauther <Ulrich.Lauther@mchp.siemens.de>
 * This file is part of GNU Binutils.
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 3, or 
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details. You should have received a copy of the GNU General
 * Public License along with this program; if not, write to the Free Software Foundation, 51
 * Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <exception>
#include <string>
#include <sstream>

extern "C" {
	#include "bfd.h"
	namespace libiberty {
		// Using a namespace because otherwise basename() from libiberty collides with the
		// one defined in string.h
		#include "libiberty/libiberty.h"
		#include "libiberty/demangle.h"
	}
}



/*
 ***************************************************************************************************
 * Trace File Classes
 ***************************************************************************************************
 */

/*
 * An exception class for the trace file parser. Just contains a simple string message.
 */
class TraceFileException : public std::exception
{
public:
	TraceFileException(const std::string message)
	: m_message(message)
	{ }

	const char * what () const throw () { return m_message.c_str(); }

private:
	std::string m_message;
};



/*
 * Class that reads the trace.out that ftrace_funcs.c will produce if copied into a program.
 *
 * The trace file will looks like this:
 *    HEADER: {uint32_t, uint32_t, uint32_t, uint32_t}
 *    MAIN_ADD: void *
 *    (
 *       MARKER: uint8_t
 *       TID: void *
 *       CALLEE: void *
 *       CALLSITE: void *
 *    )+
 *
 * The MARKER just lets us know whether this is an entry to, or exit from, a function.
 */
class TraceFile
{
public:
	static const uint8_t entry_marker = 0xaa;
	static const uint8_t exit_marker = 0x55;

	TraceFile(const char *const filename)
	: m_fh(fopen(filename, "rb"))
	{
		if (m_fh == nullptr)
		{
			throw TraceFileException("Failed to open trace file");
		}
		else
		{
			const uint32_t header[4] = { 0x4a656854, 0x6563682d, 0x42696e54, 0x72616365 }; // "JehTech-BinTrace"
			uint32_t read_header[4];
			fread(&read_header, sizeof(read_header), 1, m_fh);
			if (memcmp(header, read_header, sizeof(header)) != 0)
			{
				throw TraceFileException("Trace file format invalid. No header.");
			}
			const size_t nread = fread(&m_main_addr, sizeof(m_main_addr), 1, m_fh);
			if (nread != 1) { throw TraceFileException("Trace file format invalid. No main address."); }
		}
	}

	~TraceFile()
	{
		if (m_fh != nullptr) { fclose(m_fh); }
	}

	void* GetMainAddr()
	{
		return m_main_addr;
	}

	bool GetNext(uint8_t *marker, void **tid, void **func, void **caller)
	{
		bool is_eof = false;

		if (marker == nullptr || tid == nullptr || func == nullptr || caller == nullptr)
		{
			throw TraceFileException("Invalid parameter for GetNext()");
		}
		else
		{
			size_t nread = fread(marker, sizeof(*marker), 1, m_fh);
			if (nread == 1)
			{
				void *data[3];
				nread = fread(&data, sizeof(void *), 3, m_fh);
				if (nread == 3)
				{
					*tid = data[0];
					*func = data[1];
					*caller = data[2];
				}
				else
				{
					if (feof(m_fh)) { is_eof = true; }
					else            { throw TraceFileException("Bad trace file format - data"); }
				}
			}
			else
			{
				if (feof(m_fh)) { is_eof = true; } 
				else            { throw TraceFileException("Bad trace file format - type marker"); }
			}
		}

		return !is_eof;
	}

private:
	FILE * m_fh;
	void * m_main_addr;
};




/*
 ***************************************************************************************************
 * BFD Wrapper Classes
 ***************************************************************************************************
 */

/*
 * An exception class for BFD errors. Automatically encorporates the BDF error code and error
 * description into the exception message.
 */
class BfdException : public std::exception
{
public:
	BfdException(const std::string &message)
	{
		try
		{
			std::stringstream ss("BFD: ");
			ss << message << ": ";

			const bfd_error_type e = bfd_get_error();
			ss << bfd_errmsg(e) << "(" << e << ")";

			m_message = ss.str();
		}
		catch (...)
		{
			m_message = "ERROR in BfdException constructor!";
		}
	}

	virtual const char* what() const throw()
	{
		return m_message.c_str();
	}

private:
	std::string m_message;
};



/*
 * Representation of a symbol, including the file name it is in, function name and line number
 * Caters for BDF demangled function names which will require free()'ing.'
 */
class SymbolInfo
{
public:
	const char *file_name;
	const char *function_name;
	unsigned int line;
	unsigned int discriminator;

	SymbolInfo() : m_needs_free(false) { }
	~SymbolInfo()
	{
		if (m_needs_free) { free((char *)function_name); }
	}
	void RequiresFree() { m_needs_free = true; }

private:
	bool m_needs_free;
};



/*
 * RAII for a BFD file descriptor.
 */
class BfdFile
{
public:
	BfdFile(const char *const filename, const char *const target)
	: m_abfd(nullptr)
	{
		m_abfd = bfd_openr(filename, target);
		if (m_abfd == nullptr)
		{
			throw BfdException("Could not open BfdFile");
		}
	}

	~BfdFile()
	{
		bfd_close(m_abfd);
	}

	operator bfd*() const { return m_abfd; }
	bfd* operator->() { return m_abfd; }

private:
	bfd *m_abfd;
};



/*
 * Opens a BDF file and allows symbol-to-address and address-to-symbol lookup
 */
class SymbolFinder
{
public:
	SymbolFinder(const char *const filename, const char *const target)
		: m_abfd(BfdFile(filename, target)),
		  m_symbol_table(nullptr),
		  m_sym_table_bytes(0)
	{
		const char *err_msg = "File is bfd_archive. Cannot read symbols";
		bool success = true;

		/* Check that the BFD file is NOT of type bdf_archive, which means it contains other
		 * BFDs and an optional index. Addresses cannot be read from this - I guess would have
		 * to iterate over artifacts in the archive?? */
		m_abfd->flags |= BFD_DECOMPRESS; /* Decompress sections. */
		success = !bfd_check_format(m_abfd, bfd_archive);

		/* Check that the BFD file is also of a format can contain data, symbols, relocations and
		 * debug info */
		if (success) 
		{
			err_msg = "Format format isn't supported";
			success = bfd_check_format_matches(m_abfd, bfd_object, NULL);
		}

		if (success)
		{
			/* The file has an object format that is recognised */
			err_msg = "Could not read symbol table";
			alloc_and_read_symtab(m_abfd);
			success = (m_symbol_table != nullptr);
		}

		if (!success)
		{
			throw BfdException(err_msg);
		}
	}

	~SymbolFinder()
	{
		free(m_symbol_table);
	}

	bool symbol_to_address(const char *const symbol_name, bfd_vma *const address)
	{
		if ((symbol_name == nullptr) || (address == nullptr) || (m_symbol_table == nullptr))
		{
			throw "Invalid param - symbol_to_address()";
		}

		bool found = false;
		for (size_t idx = 0; m_symbol_table[idx] != nullptr; ++idx)
		{
			const asymbol *const this_symbol = m_symbol_table[idx];
			if (strcmp(symbol_name, bfd_asymbol_name(this_symbol)) == 0)
			{
				*address = bfd_asymbol_value(this_symbol);
				found = true;
				break;
			}
		}

		return found;
	}

	bool address_to_symbol(const bfd_vma address, SymbolInfo *const inf)
	{
		if ((inf == nullptr) || (m_symbol_table == nullptr))
		{
			throw "Invalid param address_to_symbol()";
		}

		// Not the prefered way, according to the docs, to iterate over sections but this saves
		// having to bother with a callback..
		bool found = false;
		for (bfd_section *p = m_abfd->sections; p != NULL; p = p->next)
		{
			if ((bfd_get_section_flags(m_abfd, p) & SEC_ALLOC) != 0)
			{
				// The section has been allocated space on load, i.e. it is not a debug-info-only
				// section, so consider it!
				const bfd_vma vma = bfd_get_section_vma(m_abfd, p);
				const bfd_size_type size = bfd_get_section_size(p);
				if ((address >= vma) && (address < vma + size))
				{
					/* The address is within the current section */
					found = bfd_find_nearest_line_discriminator(
						m_abfd, p, m_symbol_table, address - vma,
						&inf->file_name, &inf->function_name, &inf->line, &inf->discriminator);
					if (found)
					{
						const char *const res = libiberty::cplus_demangle(
							inf->function_name, DMGL_ANSI);
						if (res != nullptr) { inf->function_name = res; inf->RequiresFree(); }
						break;
					}
				}
			}
		}
		return found;
	}

private:
	/*
	 * Allocate the memory to hold the symbol table and read it in.
	 * Returns and array of pointers to asymbols that has been malloced.
	 */
	void alloc_and_read_symtab (bfd *const abfd)
	{
		const char *error_msg = "Getting file flags";
		bool success = false;
		bfd_boolean dynamic = FALSE;

		/* There are two stages to reading a symbol table from a BFD: allocating storage, and the
		 * actual reading process. */
		success = ((bfd_get_file_flags(abfd) & HAS_SYMS) != 0);
		if (success)
		{
			/* Figure out how much storage is required for the symbol table */
			/* Number of bytes required to store a vector of pointers to asymbols for all the
			 * symbols in the BFD abfd, including a terminal NULL pointer. */
			error_msg = "Getting upper bound";
			m_sym_table_bytes = bfd_get_symtab_upper_bound(abfd);
			if (m_sym_table_bytes == 0)
			{
				/* Maybe it is the dynamic link table, not the static one? */
				error_msg = "Getting dynamic upper bound";
				m_sym_table_bytes = bfd_get_dynamic_symtab_upper_bound(abfd);
				dynamic = TRUE;
			}
			success = (m_sym_table_bytes >= 0);
		}

		if (success)
		{
			error_msg = "allocing sym table";
			m_symbol_table = (asymbol**) malloc(m_sym_table_bytes);
			success = (m_symbol_table != NULL);
		}

		if (success)
		{
			error_msg = "canonicalization of symtab";
			m_num_sym_table_entries = dynamic 
				? bfd_canonicalize_dynamic_symtab(abfd, m_symbol_table)
				: bfd_canonicalize_symtab(abfd, m_symbol_table);
			success = (m_num_sym_table_entries >= 0);
		}

		if (success)
		{
			/* If there are no symbols left after canonicalization and we have not tried the dynamic
			 * symbols then give them a go. */
			error_msg = "Dyn upper bound";
			m_sym_table_bytes = bfd_get_dynamic_symtab_upper_bound(abfd);
			if ((m_num_sym_table_entries == 0) && !dynamic && (m_sym_table_bytes > 0))
			{
				free(m_symbol_table);
				m_symbol_table = (asymbol**) malloc(m_sym_table_bytes);
				m_num_sym_table_entries = bfd_canonicalize_dynamic_symtab(abfd, m_symbol_table);
			}
		}

		if (!success)
		{
			throw BfdException(error_msg);
		}
	}

	BfdFile m_abfd;
	asymbol** m_symbol_table;
	long m_sym_table_bytes;
	long m_num_sym_table_entries;
};




/*
 ***************************************************************************************************
 * Main() and helper functions
 ***************************************************************************************************
 */

static void print_trace_binary_to_symbols(const char *const obj_file_name, const char *const trace_file_name)
{
	SymbolFinder sym_finder(obj_file_name, NULL);
	TraceFile trace_file(trace_file_name);

	// The trace file reports the address of the main() function as seen by the running program,
	// i.e., the address when the program is loaded at some arbitrary memory location.
	const bfd_vma relocated_main_address = (bfd_vma) trace_file.GetMainAddr();

	// Get the address of main() as an offset from the base of the program, or imagining that it
	// was loaded at address zero.
	bfd_vma main_address;
	const bool main_found = sym_finder.symbol_to_address("main", &main_address);

	if (main_found)
	{
		// The difference between the two is the offset to which the program was loaded.
		const bfd_vma load_offset = relocated_main_address - main_address;

		uint8_t marker;
		void *tid, *callee, *caller;
		while (trace_file.GetNext(&marker, &tid, &callee, &caller))
		{
			SymbolInfo caller_inf;
			SymbolInfo callee_inf;
			const bool callee_found = sym_finder.address_to_symbol(
				(bfd_vma)callee - load_offset, &callee_inf);
			const bool caller_found = sym_finder.address_to_symbol(
				(bfd_vma)caller - load_offset, &caller_inf);

			if (callee_found && caller_found)
			{
				printf("%p: %s:%s:%u  called from %s : %s:%u\n",
					tid,
					callee_inf.file_name, callee_inf.function_name, callee_inf.line,
					caller_inf.file_name, caller_inf.function_name, caller_inf.line);
			}
			else if(callee_found)
			{
				printf("%p: %s:%s:%u  called from ?:?:?\n",
					tid,
					callee_inf.file_name, callee_inf.function_name, callee_inf.line);
			}
			else if (caller_found)
			{
				printf("%p: ?:?:?  called from %s:%s:%u\n",
					tid,
					caller_inf.file_name, caller_inf.function_name, caller_inf.line);
			}
			else
			{
				printf("%p: ?:?:?  called from ?:?:?\n", tid);
			}
		}
	}
	else
	{
		throw BfdException("Could not find address of main()");
	}
}



int main(int argc, char *argv[])
{
	try
	{
		bfd_init();
		print_trace_binary_to_symbols(argv[1], argv[2]);
	}
	catch (const std::exception &e)
	{
		fprintf(stderr, "##\n");
		fprintf(stderr, "## ERROR \n");
		fprintf(stderr, "## An error occurred while trying to process the trace!\n");
		fprintf(stderr, "##    > %s\n", e.what());
	}
	return 0;
}
