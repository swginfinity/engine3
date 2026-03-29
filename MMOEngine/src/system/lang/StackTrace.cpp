/*
** Copyright (C) 2007-2019 SWGEmu
** See file COPYING for copying conditions.
*/

#include "system/lang/System.h"

#include "system/thread/Thread.h"

#include "engine/log/Logger.h"
#include "engine/core/Core.h"

String StackTrace::binaryName = "core3";

namespace StackTraceNs {
	static Logger logger("StackTrace");
}

using namespace StackTraceNs;

StackTrace::StackTrace() {
	#ifdef PLATFORM_UNIX
		count = backtrace(symbols, maxSize);
	#endif
}

StackTrace::StackTrace(const StackTrace& c) {
	count = c.count;
	memcpy(symbols, c.symbols, sizeof(void*) * c.count);
}

Logger* StackTrace::getLogger() {
	return &StackTraceNs::logger;
}

StackTrace& StackTrace::operator=(const StackTrace& c) {
	if (this == &c)
		return *this;

	count = c.count;
	memcpy(symbols, c.symbols, sizeof(void*) * c.count);

	return *this;
}

StackTrace::~StackTrace() {
}

bool StackTrace::containsAddress(const void* address) const {
	for (int i = 0; i < count; ++i) {
		if (symbols[i] == address) {
			return true;
		}
	}

	return false;
}

void StackTrace::print() const {
	static const int initializeProperties = Core::initializeProperties("StackTrace");

#ifdef PLATFORM_UNIX
	static const bool enableAddr2Line = Core::getIntProperty("StackTrace.enableAddr2Line", 1);
	static const String addr2linePath = Core::getProperty("StackTrace.addr2linePath", "/usr/bin/addr2line");
	static const String configBinaryName = Core::getProperty("StackTrace.binaryName", binaryName);

	char** tracedSymbols = backtrace_symbols(symbols, count);

	if (tracedSymbols == nullptr) {
		logger.error() << "error while trying to print stack trace: tracedSymbols == nullptr";
		return;
	}

	StringBuffer command;

#ifdef PLATFORM_MAC
	command << "atos -p " << Thread::getProcessID();
#else
	command << addr2linePath << " -f -C -e " << configBinaryName;
#endif

	StringBuffer lines;
	for (int i = 0; i < count; ++i) {
		if (enableAddr2Line) {
			// For PIE binaries, backtrace_symbols returns "binary(+0xOFFSET) [0xADDR]"
			// Parse the file offset (+0x...) since raw addresses are ASLR'd
			const char* sym = tracedSymbols[i];
			const char* offsetStart = strstr(sym, "(+0x");
			if (offsetStart != nullptr) {
				// Extract the hex offset after "(+"
				unsigned long offset = strtoul(offsetStart + 2, nullptr, 16);
				command << " 0x" << hex << offset;
			} else {
				// Fallback to raw address (non-PIE or shared library)
				command << " " << hex << symbols[i];
			}
		}

		lines << tracedSymbols[i] << endl;
	}

	free(tracedSymbols);

	if (enableAddr2Line) {
		FILE* pipe = popen(command.toString().toCharArray(), "r");
		if (pipe != nullptr) {
			// addr2line outputs pairs of lines: function name, then file:line
			// Interleave with our backtrace_symbols output
			char buffer[512];
			StringBuffer resolved;
			resolved << "----- Resolved Stack Trace -----" << endl;

			int lineNum = 0;
			while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
				// Strip trailing newline
				size_t len = strlen(buffer);
				if (len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';

				if (lineNum % 2 == 0) {
					// Function name
					resolved << "  " << buffer;
				} else {
					// File:line
					resolved << " at " << buffer << endl;
				}
				lineNum++;
			}
			pclose(pipe);

			logger.warning(resolved.toString());
		}
	}

	logger.warning(lines.toString());
#elif defined PLATFORM_CYGWIN
	cygwin_stackdump();
#endif
}

String StackTrace::toStringData() {
#ifdef PLATFORM_UNIX
	char** tracedSymbols = backtrace_symbols(symbols, count);

	if (tracedSymbols == nullptr) {
		logger.error() << "error while trying to print stack trace: tracedSymbols == nullptr";
		return String();
	}

	StringBuffer lines;
	for (int i = 0; i < count; ++i) {
		lines << tracedSymbols[i] << endl;
	}

	free(tracedSymbols);

	return lines.toString();
#else
	return String();
#endif
}

void StackTrace::printStackTrace() {
	StackTrace trace;
	trace.print();
}

bool StackTrace::equals(const StackTrace& trace) const {
	if (count != trace.count)
		return false;

	for (int i = 0; i < count; ++i) {
		void* symbol1 = symbols[i];
		void* symbol2 = trace.symbols[i];

		if (symbol1 != symbol2)
			return false;
	}

	return true;
}
