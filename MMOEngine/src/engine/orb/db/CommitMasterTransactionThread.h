/*
** Copyright (C) 2007-2019 SWGEmu
** See file COPYING for copying conditions.
*/
/*
 * CommitMasterTransactionThread.h
 *
 *  Created on: 18/02/2012
 *      Author: victor
 */

#ifndef COMMITMASTERTRANSACTIONTHREAD_H_
#define COMMITMASTERTRANSACTIONTHREAD_H_

#include "engine/engine.h"
#include "system/thread/atomic/AtomicBoolean.h"

#include "UpdateModifiedObjectsThread.h"

namespace engine {
	namespace ORB {

	class CommitMasterTransactionThread : public Thread, public Singleton<CommitMasterTransactionThread>,
					      public Object, public Logger {
		Mutex blockMutex;
		Condition waitCondition;

		// 🔴 THE PREDICATE -- AND READ WHAT IT DOES AND DOES NOT DO, because the obvious reading
		// is wrong here. This is NOT closing a lost-wakeup hole. engine3's Condition is not a raw
		// pthread condition variable: doSignal() latches into signalCount when waiterCount == 0
		// (Condition.h:146-155) and doWait() consumes it without parking (Condition.h:104-118).
		// Both sides of this class run under blockMutex, so those counters cannot be raced here and
		// a signal delivered while the master is in its tail is REMEMBERED. Measured against the
		// real header with a positive control (a plain condvar loses it; this one does not) --
		// hk-artifacts/2026-09-06-gh2193/RESULT.md.
		// What the predicate IS worth: pthread_cond_wait is permitted to return spuriously, and the
		// old bare wait would then have run commitData() on nulled members. It also states the
		// handoff invariant in the code instead of leaving it implicit in Condition's counters.
		// ⚠️ It does NOT fix GH #2193. That incident's root cause is OPEN; the candidates are
		// commitData() making untimed external calls (SQL, a director socket send, BDB
		// commitSync/checkpoint) while holding blockMutex, and the objectUpdateInProgress latch,
		// which is cleared only inside commitData() and so turns any stall into a permanent one.
		bool workPending;

		engine::db::berkeley::Transaction* transaction;
		Vector<UpdateModifiedObjectsThread*>* threads;
		Vector<DistributedObject* >* objectsToDeleteFromRam;
		int numberOfThreads;

		AtomicBoolean doRun;

	public:
		CommitMasterTransactionThread();
		~CommitMasterTransactionThread();

		void run();

		void shutdown();

		void startWatch(engine::db::berkeley::Transaction* trans, Vector<UpdateModifiedObjectsThread*>* workers, int number, Vector<DistributedObject* >* objectsToCollect);

		void commitData() NO_THREAD_SAFETY_ANALYSIS;

		int garbageCollect(DOBObjectManager* objectManager);

		// Writes bin/log/last-successful-save after a master transaction that ACTUALLY committed.
		// Never throws into the commit thread (Thread::run has no catch); every failure leaves the
		// PREVIOUS marker in place, so the guard degrades to "stale" (reads as a stall) rather than
		// to a fresh-mtime lie.
		// Runs on a TASK, not on the commit thread, so filesystem I/O never holds blockMutex.
		// commitTime is sampled at the COMMIT and passed in: a delayed task must not stamp the
		// marker with its own later clock, which would overstate freshness and mask a stall.
		void writeSuccessfulSaveMarker(DOBObjectManager* objectManager, const Time& commitTime);
	};

  } // namespace ORB
} // namespace engine

#endif /* COMMITMASTERTRANSACTIONTHREAD_H_ */
