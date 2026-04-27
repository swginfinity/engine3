/*
** Copyright (C) 2007-2019 SWGEmu
** See file COPYING for copying conditions.
*/

#ifndef BASEFRAGMENTEDPACKET_H_
#define BASEFRAGMENTEDPACKET_H_

#include "BasePacket.h"

namespace engine {
  namespace service {
    namespace proto {

	class FragmentedPacketParseException : public Exception {
	public:
		FragmentedPacketParseException(const String& msg) : Exception(msg) {

		}
	};

	class BaseFragmentedPacket : public BasePacket {
		BasePacket* singlePacket;

		int totalSize;

		// Set when addFragment rejects a fragment. While set, further
		// addFragment calls drop silently — the caller is expected to
		// detect the message boundary and discard the accumulator. This
		// preserves the in-flight metadata (totalSize, accumulated bytes)
		// so the next fragment after a parse failure can be evaluated
		// against the existing message context instead of being misread
		// as a fresh first-fragment.
		bool poisoned;

		StringBuffer error;

		StringBuffer& addError() {
			if (error.length()) {
				error << endl;
			}
			return error;
		}

	public:
		BaseFragmentedPacket();
		BaseFragmentedPacket(BasePacket* pack);

		~BaseFragmentedPacket();

		bool addFragment(Packet* pack);

		// True once a parse failure has invalidated this accumulator. Owner
		// should not feed further fragments and should discard at the
		// next logical-message boundary.
		bool isPoisoned() const { return poisoned; }

		// True if the failure happened BEFORE any valid fragment was
		// accepted — i.e., the very first parse hit an unreasonable
		// totalSize. Distinguishes hostile-first-fragment (correct
		// response: disconnect the client) from mid-message corruption
		// (correct response: drop the message, keep the connection).
		bool isPoisonedOnFirstParse() const { return poisoned && totalSize <= 0; }

		BasePacket* getFragment();

		bool isComplete();

		bool hasFragments() const;

		bool hasError() const {
			return !error.length();
		}

		String getError() const {
			return error.toString();
		}
	};

    } // namespace proto
  } // namespace service
} // namespace engine

using namespace engine::service::proto;

#endif /*BASEFRAGMENTEDPACKET_H_*/
