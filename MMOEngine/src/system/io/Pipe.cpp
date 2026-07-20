/*
** Copyright (C) 2007-2019 SWGEmu
** See file COPYING for copying conditions.
*/
#include "IOException.h"

#include "Pipe.h"

namespace PipeNs {
#ifdef PLATFORM_WIN
	const static Pipe::PipeType NullPipe = reinterpret_cast<Pipe::PipeType>(0);
#else
	const static Pipe::PipeType NullPipe = -1;
#endif
}

using namespace PipeNs;

Pipe::Pipe() {
	for (auto i = 0; i < 2 ; ++i) {
		pipefd[i] = NullPipe;
	}
}

Pipe::~Pipe() {
	close();
}

void Pipe::create(bool autoClose) {
	doAutoClose = autoClose;

#ifndef PLATFORM_WIN
	if (pipe(pipefd) < 0)
		throw IOException("unable to create pipe");

	fileDescriptor = pipefd[0];
#else
	auto res = CreatePipe(&pipefd[0], &pipefd[1], nullptr, 0);

	if (!res) {
		throw IOException("unable to create pipe");
	}
#endif
}

void Pipe::close() {
	for (auto i = 0; i < 2; ++i) {
		closePipe(pipefd[i]);
	}
}

void Pipe::closePipe(PipeType& pipe) {
	if (pipe != NullPipe) {
#ifndef PLATFORM_WIN
		::close(pipe);
#else
		CloseHandle(pipe);
#endif
		pipe = NullPipe;
	}
}

int Pipe::readInt() {
	int value;
	read((char*) &value, sizeof(int));
	return value;
}

int Pipe::readLine(char* buf, int len) {
	int count = 0;

	if (len <= 0) {
		return 0;
	}

	// (1) MEMORY SAFETY. The loop must never advance buf past buf[len - 1]: the
	// terminator below is written unconditionally, so a full-length line (or a
	// newline landing in the final slot, which also advances buf) previously left
	// buf pointing one PAST the caller's buffer and wrote a zero there.
	//
	// Every caller passes a fixed stack array and its exact size -- GdbStub
	// writeOutput/parseOutput (char[4096], 4096) and ServerCore::handleCommands
	// (char[256], 256) -- so that was a one-byte out-of-bounds stack write,
	// silently corrupting an adjacent local or tripping the stack protector
	// depending on frame layout.
	//
	// (2) RETURN VALUE = BYTES CONSUMED, not non-newline characters.
	// Every caller loops on `readLine(...) > 0`, so the return has to mean "did
	// this call make progress", and the old count could not express that: it
	// excluded the newline, making a bare newline indistinguishable from EOF.
	// Two data-loss bugs followed, both fixed by counting consumed bytes.
	//
	//   a) PRE-EXISTING: any blank line returned 0, so GdbStub's drain loop
	//      treated it as EOF and discarded ALL remaining output. Every captured
	//      backtrace was silently truncated at its first empty line.
	//   b) INTRODUCED BY (1) IF COUNT EXCLUDED THE NEWLINE: reserving the
	//      terminator slot defers a newline that previously fit, so a line of
	//      exactly len-1 characters made the NEXT call return 0 and stop the
	//      loop at that exact boundary.
	//
	// Only genuine EOF now returns 0. Callers reading content take it from the
	// NUL-terminated buffer, not the count, so none of the three is affected by
	// the changed number: GdbStub uses String(line), ServerCore tests `if (!len)`
	// and then trims the buffer.
	//
	// The unread remainder of an overlong line is still left in the pipe. That is
	// fine for GdbStub (a split long line reassembles on write), but a caller that
	// must not act on a fragment -- ServerCore, which executes these as commands --
	// has to detect the filled-buffer-without-newline case and reject the whole
	// line rather than run its prefix.
	for (; count < len - 1; ++count, ++buf) {
		if (read(buf, 1) == 0)
			break;

		if (*buf == '\n') {
			++buf;
			++count;   // count the newline: it was consumed
			break;
		}
	}

	*buf = 0;

	return count;
}

void Pipe::writeInt(int val) {
	write((char *) &val, sizeof(int));
}

int Pipe::read(char* buf, int len) {
	if (doAutoClose) {
		closePipe(pipefd[1]);
	}

	if (pipefd[0] == NullPipe)
		throw IOException("pipe does not exists on read");

#ifndef PLATFORM_WIN
	int result = ::read(pipefd[0], buf, len);

	if (result < 0)
		throw IOException("unable to read from pipe");

	return result;
#else
	DWORD numberOfBytesRead;

	auto res = ReadFile(pipefd[0], buf, len, &numberOfBytesRead, nullptr);

	if (!res)
		throw IOException("unable to read from pipe");
	
	return numberOfBytesRead;
#endif
}

int Pipe::writeLine(const char* str) {
	int len = strlen(str);

	return write(str, len);
}

int Pipe::write(const String& string) {
	return write(string.toCharArray(), string.length());
}

int Pipe::write(const char* buf, int len) {
	if (doAutoClose) {
		closePipe(pipefd[0]);	
	}

	if (pipefd[1] == NullPipe)
		throw IOException("pipe does not exists on write");

#ifndef PLATFORM_WIN
	int result = ::write(pipefd[1], buf, len);
	if (result < 0)
		throw IOException("unable to write to pipe");

	return result;
#else
	DWORD numberOfBytesWritten;

	auto res = WriteFile(pipefd[1], buf, len, &numberOfBytesWritten, nullptr);

	if (!res)
		throw IOException("unable to write to pipe");

	return numberOfBytesWritten;
#endif
}

void Pipe::redirectFile(PipeType fd) {
#ifndef PLATFORM_WIN
	dup2(pipefd[1], fd);
#else
	E3_ABORT("Pipe::redirectFile file not implemented in windows");
#endif
}
