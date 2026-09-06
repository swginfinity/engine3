/*
** Copyright (C) 2007-2019 SWGEmu
** See file COPYING for copying conditions.
*/
/*
 * CommitMasterTransactionThread.cpp
 *
 *  Created on: 18/02/2012
 *      Author: victor
 */

#include "engine/orb/DistributedObjectBroker.h"

#include "DOBObjectManager.h"

#include "UpdateModifiedObjectsThread.h"

#include "CommitMasterTransactionThread.h"

#include "engine/core/Core.h"
#include "engine/core/TaskManager.h"

#include "system/io/File.h"
#include "system/io/FileWriter.h"

#include <cstdio>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

CommitMasterTransactionThread::CommitMasterTransactionThread() : Logger("CommitMasterTransactionThread") {
	transaction = nullptr;
	threads = nullptr;

	objectsToDeleteFromRam = nullptr;

	numberOfThreads = 0;

	workPending = false;

	doRun = true;
}

CommitMasterTransactionThread::~CommitMasterTransactionThread() {
	if (doRun) {
		shutdown();
	}
}

void CommitMasterTransactionThread::startWatch(engine::db::berkeley::Transaction* trans, Vector<UpdateModifiedObjectsThread*>* workers, int number, Vector<DistributedObject* >* objectsToCollect) {
	fatal(workers != nullptr) << "workers is null";
	fatal(objectsToCollect != nullptr) << "objectsToCollect is null";

	// 🔴 THE HANDOFF IS NOW ENTIRELY UNDER blockMutex. (a) IS THE SUBSTANTIVE FIX; (b) is hygiene.
	//
	// (a) The four members used to be assigned OUTSIDE the lock while run() nulls them INSIDE it,
	//     which is a plain data race on the same window that loses the signal: run() can null what
	//     startWatch() has just written, and commitData() then dereferences objectsToDeleteFromRam
	//     as a null pointer. Assigning under the lock also makes startWatch() WAIT for the previous
	//     iteration's tail instead of racing it, which is the serialisation the caller-side
	//     objectUpdateInProgress latch was wrongly assumed to provide -- finishObjectUpdate() runs
	//     INSIDE commitData(), so the latch is already clear while run() is still in its tail.
	//
	// (b) workPending is set before the signal. ⚠️ NOT because a signal would otherwise be lost --
	//     Condition already latches one (Condition.h:146-155), see the header comment -- but so the
	//     master cannot act on a SPURIOUS pthread_cond_wait return, which is permitted and which the
	//     old bare wait would have taken as work.
	//
	// ⚠️ This does not add blocking that was not already there: commitData() runs with blockMutex
	// held for its whole duration, so startWatch()'s existing lock() already waited on it.
	blockMutex.lock();

	transaction = trans;
	threads = workers;
	numberOfThreads = number;
	objectsToDeleteFromRam = objectsToCollect;

	workPending = true;

	waitCondition.signal(&blockMutex);

	blockMutex.unlock();
}

void CommitMasterTransactionThread::run() {
	while (doRun) {
		blockMutex.lock();

		// 🔴 while, NOT if -- the loop is what makes the predicate worth having. It absorbs a
		// spurious wakeup, and it re-parks when shutdown()'s broadcast is not for us. doRun is
		// tested here too so a shutdown that arrives with no work queued still leaves the wait.
		// ⚠️ KNOWN AND UNCHANGED: a shutdown arriving with workPending set drops that save, exactly
		// as the old code did (it tested `if (doRun)` before commitData). Draining it is a shutdown
		// -protocol change and is deliberately not attempted here.
		while (!workPending && doRun) {
			waitCondition.wait(&blockMutex);
		}

		if (doRun && workPending) {
			commitData();
		}

		// Cleared under the same lock that set it, AFTER commitData() has consumed the members.
		// The next startWatch() is blocked on blockMutex until this point, so it cannot overwrite
		// a cycle still in flight nor lose its own signal.
		workPending = false;

		transaction = nullptr;
		threads = nullptr;
		objectsToDeleteFromRam = nullptr;

		blockMutex.unlock();
	}
}

void CommitMasterTransactionThread::shutdown() {
	doRun = false;

	blockMutex.lock();

	waitCondition.broadcast(&blockMutex);

	blockMutex.unlock();

	join();
}

int CommitMasterTransactionThread::garbageCollect(DOBObjectManager* objectManager) {
	int i = 0;

	if (objectsToDeleteFromRam == nullptr) {
		return i;
	}

	static const int objectsToDeletePerSleep = Core::getIntProperty("ObjectManager.objectsToDeletePerSleepThrottle", 10000);
	static const int actualObjectsToDeleteSleep = Core::getIntProperty("ObjectManager.actualObjectsToDeleteSleepThrottle", 100);
	static const int objectsToDeleteSleep = Core::getIntProperty("ObjectManager.objectsToDeleteSleepThrottle", 25);

	//      while (objectsToDeleteFromRam->size() != 0) {
	for (int j = 0; j < objectsToDeleteFromRam->size(); ++j) {
		DistributedObject* object = objectsToDeleteFromRam->getUnsafe(j);

		Locker locker(objectManager);

		//printf("object ref count:%d and updated flag:%d\n", object->getReferenceCount(), object->_isUpdated());

		if (object->getReferenceCount() == 2 && (!object->_isUpdated() || object->_isDeletedFromDatabase() || !object->isPersistent())) {
			if (objectManager->localObjectDirectory.tryRemoveHelper(object->_getObjectID())) {
				//localObjectDirectory.removeHelper(object->_getObjectID());

				++i;

				object = nullptr;
			}
		} /*else if (object->_isUpdated() && !object->_isDeletedFromDatabase()) {
			String text = TypeInfo<DistributedObject>::getClassName(object) + " 0x" + String::hexvalueOf((int64)object->_getObjectID());

			printf("%s refs:%d\n", text.toCharArray(), object->getReferenceCount());
		}*/

		if ((((j + 1) % objectsToDeletePerSleep) == 0) || ((i + 1) % actualObjectsToDeleteSleep ) == 0) {
			locker.release();

			Thread::sleep(objectsToDeleteSleep);
		}
	}

	delete objectsToDeleteFromRam;
	objectsToDeleteFromRam = nullptr;

	return i;
}

void CommitMasterTransactionThread::commitData() NO_THREAD_SAFETY_ANALYSIS {
	for (int i = 0; i < numberOfThreads; ++i) {
		UpdateModifiedObjectsThread* worker = threads->get(i);

		while (!worker->hasFinishedCommiting()) {
			worker->signalMasterTransactionFinish();

			static const int databaseWatchThreadThrottle = Core::getIntProperty("ObjectManager.databaseWatchThreadThrottle", 500);

			Thread::sleep(databaseWatchThreadThrottle);
		}
	}

	DOBObjectManager* objectManager = DistributedObjectBroker::instance()->getObjectManager();

	// 🔴 The return is CAPTURED so the save-complete line below can only print when the
	// master transaction actually committed. Control flow is deliberately unchanged --
	// checkpoint() and onCommitData() still run exactly as before. Acting on a failed
	// commit is GH-2198 and is NOT in scope here; this change only stops us REPORTING a
	// success we did not have.
	const bool rootBroker = DistributedObjectBroker::instance()->isRootBroker();
	int commitRet = 0;
	// 🔴 SAMPLED THE INSTANT THE COMMIT RETURNS, not at the end of commitData(). The marker
	// answers "when did we last successfully SAVE", so it must carry the COMMIT's clock.
	// Sampling it further down -- after checkCommittedObjects(), garbageCollect() and
	// finishObjectUpdate() -- overstates freshness by the length of that tail, which on a
	// large GC pass is not small (a 743,794-candidate pass was observed taking minutes).
	// That lag was a review finding, and the first version of this change did NOT fix it:
	// it moved the write to a task but still sampled the time at the bottom of the function.
	Time commitTime;

	if (rootBroker) {
		commitRet = ObjectDatabaseManager::instance()->commitTransaction(transaction);

		commitTime.updateToCurrentTime();

		ObjectDatabaseManager::instance()->checkpoint();

		objectManager->onCommitData();
	}

	// 🔴 GATED 2026-08-31 (review finding, free lanes + Opus, both independently). This line
	// used to print UNCONDITIONALLY -- outside the rootBroker block and regardless of
	// commitRet -- which is the exact defect bdb5d1a4's own message claimed to have fixed
	// and did not. The return was captured for the marker only, so on a failed commit the
	// console still said "master transaction committed" and the scrollback detector that
	// this whole change exists to replace still read a SUCCESS on a failed save.
	if (!rootBroker) {
		objectManager->info(true) << "master transaction complete (non-root broker, no local commit)";
	} else if (commitRet == 0) {
		objectManager->info(true) << "master transaction committed";
	} else {
		// Console-only, deliberately matching the level of the success line it replaces; the
		// authoritative failure record is commitTransaction's own error() with db_strerror
		// (DatabaseManager.cpp:517-519). Control flow is still UNCHANGED -- acting on a
		// failed commit is GH-2198 and remains out of scope.
		objectManager->error() << "master transaction FAILED to commit, ret " << commitRet
			<< " -- this cycle's changes are NOT on disk (see the db_strerror line above)";
	}

	objectManager->checkCommittedObjects();

	objectManager->info(true) << "starting garbage collection for " << objectsToDeleteFromRam->size() << " candidates";

	int objs = garbageCollect(objectManager);

	objectManager->info(true) << "deleted from ram " << objs << " objects";

	objectManager->finishObjectUpdate();

	// 🔴 A MARKER FILE, NOT A LOG LINE -- and the reason is that core3.log cannot carry a
	// heartbeat. Its flush is gated on `syncGlobalLog || forceSync` (Logger.cpp:270), and
	// `syncGlobalLog` is initialised false (Logger.cpp:22) and CONFIG-CONTROLLED, not
	// hardcoded: Logger::setGlobalFileLoggerSync() (Logger.cpp:129) is called from
	// ServerCore.cpp:3295 with `Core3.LogSync`, which defaults false (ConfigManager.h:596)
	// and is `LogSync = 0` in live's conf/config.lua:115. (An earlier version of this
	// comment claimed nothing in the tree sets it -- that grep was scoped to the engine3
	// subtree and missed the Core3-side caller.) So on every box we run, the file reaches
	// disk only when its buffer fills. One ~70-byte line every five minutes cannot fill it;
	// ambient traffic on live is a MEASURED ~4.1 KB/h (77,884 B / 395 lines / 19 h), which
	// against a buffer of a few KB puts the flush period on the order of an hour -- the
	// traffic is measured, the buffer SIZE is not, so treat the period as an estimate.
	// 🔑 Being a CONFIG knob strengthens the case for a marker: a heartbeat whose visibility
	// depends on a logging setting nobody remembers is worse than one that does not depend
	// on logging at all. And the delay is a function of UNRELATED log volume,
	// so a quiet healthy server flushes SLOWEST. There is no stable latency there to
	// calibrate a stall threshold against. (MrO 2026-08-31: "I wouldn't change how core3.log
	// works just for this.")
	//
	// So the success signal is a fixed-size file whose CONTENT AND MTIME ARE THE ANSWER to
	// the only question a monitor asks: when did we last successfully save? No parsing, no
	// grep, no rotation, no buffering, no scrollback eviction, and no log growth at all.
	// A monitor reads mtime; the timestamp inside is for humans. Same idiom as
	// core3-backup-health-check.py, which reads the artifact rather than the log a failing
	// run never manages to write.
	//
	// FAILURE is deliberately NOT written here: commitTransaction already logs error() with
	// db_strerror (DatabaseManager.cpp:517-519), and this function now logs its own error()
	// on a non-zero commitRet.
	// ⚠️ CORRECTED 2026-08-31 -- an earlier version of this comment said "a failure is LOUD in
	// core3.log", and that is FALSE in the way that matters. Logger::error() calls
	// log(msg, LogLevel::ERROR) with forceSync defaulting FALSE (Logger.cpp:283-291); only
	// fatal() passes true. So an ERROR line goes into the SAME buffered globalLogFile,
	// behind the SAME `syncGlobalLog || forceSync` flush gate (Logger.cpp:270) that this
	// comment cites two paragraphs up as the reason a heartbeat cannot live in core3.log.
	// It therefore carries the same unbounded, inversely-load-dependent latency, and it is
	// lost outright if the process aborts before the buffer fills. error() DOES write to the
	// console immediately (System::err ... << flush), so the failure is loud on the SCREEN --
	// which is precisely the scrollback channel that got blinded mid-incident on 2026-08-30.
	// 🔴 CONSEQUENCE, STATED PLAINLY RATHER THAN PAPERED OVER: the marker gives us a reliable
	// SUCCESS signal and a reliable STALL signal (its absence). It does NOT give us a
	// reliable FAILURE signal. A monitor must treat marker staleness as the trigger and must
	// not wait for an error line that may never reach disk. Making the failure durable is
	// GH-2198 and is not attempted here.
	//
	// 🔴 THIS MUST NEVER THROW INTO THE COMMIT THREAD. Thread::run is invoked with no catch
	// (Thread.cpp:46-56), so an escaping exception here would take the process down -- i.e. a
	// monitoring convenience could kill the server it exists to watch. Any failure to write
	// the marker is swallowed after one error line; a stale marker then reads as a stall,
	// which fails in the safe direction.
	if (rootBroker && commitRet == 0) {
		// 🔴 commitTime was sampled AT THE COMMIT above, and is passed by value into the task
		// (MrObvious 2026-09-01: "pass it the time in case the task is delayed"). If the
		// queued writer runs late under load, stamping the marker with the WRITER's clock
		// would silently overstate freshness and mask the very stall this exists to detect.
		//
		// 🔴 OFF THE COMMIT THREAD ON PURPOSE (MrObvious 2026-09-01: "why not move it to a
		// separate task?"). commitData() runs with blockMutex held for its whole duration,
		// and the next save cycle blocks on that mutex in startWatch(). Doing filesystem I/O
		// inline meant a hung or stalled log filesystem would stall SAVES -- exactly the
		// failure class the marker is meant to report on, caused by the reporter. All three
		// review lanes flagged it. An immediate task takes the I/O off the lock entirely.
		//
		// It also retires the hand-rolled "must never throw into the commit thread" guard as
		// the load-bearing protection: Thread::run has no catch, but this no longer runs on
		// that thread. The try/catch inside stays anyway -- belt and braces, and the task
		// worker deserves the same courtesy.
		DOBObjectManager* markerObjectManager = objectManager;

		// Core::getTaskManager() returns nullptr once taskManagerShutDown is set (Core.cpp:206),
		// and calling through it would be UB plus a leaked LambdaTask. The rest of the engine
		// goes through Task::execute() precisely because that null-checks; this call site has to
		// do it itself.
		// 🔴 SKIP THE MARKER ENTIRELY IF WE ARE SHUTTING DOWN -- MrObvious 2026-09-01: "there is
		// no need to write the marker during the server shutdown" / "I would just skip the task
		// if taskmanager is down/during shutdown process". This is INTENDED behaviour, not a gap
		// to close: the server is going down deliberately, nothing monitors for a save it was
		// told to stop doing, and the checker's own BOOT_GRACE_S covers the window after it comes
		// back. 🔴 DO NOT add a synchronous shutdown-path write to "fix" this -- a review filed
		// the dropped final-save marker as a defect and it is not one.
		//
		// Both shutdown states are already covered, and between them the skip is total:
		//   * task manager DOWN  -> Core::getTaskManager() returns nullptr once
		//     taskManagerShutDown is set (Core.cpp:206), and the null check below skips. Without
		//     it this would be a call through a null pointer plus a leaked LambdaTask, since the
		//     rest of the engine reaches the manager via Task::execute(), which null-checks.
		//   * still alive but SHUTTING DOWN -> TaskManagerImpl::executeTask drops the task itself
		//     when shuttingDown is set (TaskManagerImpl.cpp:465).
		TaskManager* taskManager = Core::getTaskManager();

		if (taskManager != nullptr) {
			taskManager->executeTask([markerObjectManager, commitTime]() {
				CommitMasterTransactionThread::instance()->writeSuccessfulSaveMarker(markerObjectManager, commitTime);
			}, "WriteSuccessfulSaveMarker");
		}
	}
}

// 🔴 REWRITTEN 2026-08-31 FROM FileWriter TO RAW POSIX, AND THE REASON IS THAT THE FIRST
// VERSION FAILED IN THE UNSAFE DIRECTION. Found by the review that should have run before
// bdb5d1a4 shipped (free lanes + Opus, independently).
//
// The FileWriter version checked NOTHING. `FileWriter::operator<<` discards fwrite's return
// (FileWriter.h:205-209) and `FileWriter::close()` discards File::close()'s bool (File.cpp:61-71),
// which is the only place fclose -- and therefore the actual write -- reports failure. Neither
// throws on ENOSPC/EIO/EDQUOT. So on a full disk the tmp file ended up ZERO BYTES, no error was
// logged, the rename succeeded, and the published marker was EMPTY WITH A CURRENT MTIME.
// An mtime-based monitor reads that as HEALTHY.
// 🔑 That is the worst possible direction for this particular guard: a full log filesystem is
// strongly correlated with the database trouble the marker exists to detect, so the guard was
// most likely to lie exactly when it mattered. "Rename is atomic" was true and irrelevant -- it
// atomically publishes a complete-looking truncated file.
//
// It also was not durable: fclose only reaches the page cache. Now the file is fsync'ed AND the
// containing directory is fsync'ed after the rename, which is what makes the rename itself
// survive a power loss rather than leaving a zero-length or absent target.
//
// Raw POSIX rather than File/FileWriter because neither exposes fsync, every return here must be
// checked, and dropping FileWriter also removes its exception surface from a thread that cannot
// afford one (Thread::run is invoked with no catch, Thread.cpp:46-56 -- an escaping exception
// would take down the server this exists to watch). The try/catch stays as a belt-and-braces
// outer guard; nothing inside is expected to throw any more.
void CommitMasterTransactionThread::writeSuccessfulSaveMarker(DOBObjectManager* objectManager, const Time& commitTime) {
	static const char* const MARKER = "log/last-successful-save";
	static const char* const MARKER_DIR = "log";

	try {
		// commitTime is the COMMIT's clock, passed in from commitData -- never sampled here.
		const Time& now = commitTime;
		StringBuffer markerText;

		// getTime() is the exact tv_sec (Time.h:388-390). The old getMiliTime() / 1000 routed
		// through a float division (tv_nsec / 1000000.f), which rounds 999999999ns up to 1000ms
		// and can report an epoch second one GREATER than the real one.
		// getFormattedTimeFull() is ISO-8601 with a %z offset; the old getFormattedTime() is
		// ctime_r -- LOCAL time with no offset in the string, printed next to an absolute epoch,
		// so a reader in another timezone saw two fields disagreeing with nothing marking which
		// was which.
		markerText << now.getTime() << " " << now.getFormattedTimeFull() << "\n";

		String text = markerText.toString();

		// 🔴 UNIQUE PER TASK, NOT PER PROCESS -- and the difference is the whole point.
		// This used to be `.tmp.<pid>`, which was sufficient while the write ran INLINE on the
		// single commit thread under blockMutex: only one writer could ever exist. Moving it to
		// a task removed that serialisation -- tasks are dispatched round-robin across worker
		// queues (TaskManagerImpl.cpp:473), so cycle N's task can still be running when N+1's is
		// dispatched. Two tasks then open the SAME path with O_TRUNC: A writes 40 bytes and
		// blocks in fsync, B truncates to 0 and writes its own, and A renames a NUL-padded file
		// into place with a fresh mtime. That is precisely the healthy-looking lie the POSIX
		// rewrite exists to prevent, reintroduced by the concurrency the task change created.
		// The stall that makes it likely -- a hung log filesystem -- is the exact condition the
		// task change was made to tolerate. Found by review before this shipped.
		StringBuffer tmpPath;
		tmpPath << MARKER << ".tmp." << (int) getpid() << "." << (uint64) now.getMiliTime();
		String tmp = tmpPath.toString();

		int fd = ::open(tmp.toCharArray(), O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (fd < 0) {
			objectManager->error() << "last-successful-save marker: open(" << tmp << ") failed: "
				<< strerror(errno);
			return;
		}

		const char* buf = text.toCharArray();
		size_t remaining = text.length();
		bool ok = true;

		// write(2) is permitted to write fewer bytes than asked even for a regular file; a short
		// write is exactly how the empty/truncated marker above got published.
		while (remaining > 0) {
			ssize_t written = ::write(fd, buf, remaining);

			if (written < 0) {
				if (errno == EINTR) {
					continue;
				}

				objectManager->error() << "last-successful-save marker: write failed: " << strerror(errno);
				ok = false;
				break;
			}

			buf += written;
			remaining -= (size_t) written;
		}

		// fsync BEFORE the rename, or the rename can be journalled ahead of the data and a crash
		// leaves a zero-length marker with a fresh mtime -- the same lie, arrived at differently.
		if (ok && ::fsync(fd) != 0) {
			objectManager->error() << "last-successful-save marker: fsync failed: " << strerror(errno);
			ok = false;
		}

		if (::close(fd) != 0 && ok) {
			objectManager->error() << "last-successful-save marker: close failed: " << strerror(errno);
			ok = false;
		}

		if (!ok) {
			// Leave the PREVIOUS marker in place. A stale marker reads as a stall, which is the
			// safe direction; publishing this one would read as healthy, which is not.
			::unlink(tmp.toCharArray());
			return;
		}

		// 🔴 MONOTONICITY GUARD (B2). Nothing orders tasks across worker queues, so a delayed
		// task can carry an OLDER commitTime than the marker already on disk. Publishing it
		// would walk the marker BACKWARDS and manufacture a stall alert on a healthy server.
		// Read what is there and refuse to go back in time. Failing to read (missing/corrupt)
		// is treated as "publish", which is the safe direction -- it restores a valid marker.
		{
			FILE* existing = ::fopen(MARKER, "r");

			if (existing != nullptr) {
				unsigned long long onDisk = 0;

				if (::fscanf(existing, "%llu", &onDisk) == 1 && onDisk > (unsigned long long) now.getTime()) {
					::fclose(existing);
					::unlink(tmp.toCharArray());
					return;
				}

				::fclose(existing);
			}
		}

		if (::rename(tmp.toCharArray(), MARKER) != 0) {
			objectManager->error() << "last-successful-save marker: rename into place failed: "
				<< strerror(errno);
			::unlink(tmp.toCharArray());  // do not accumulate orphaned temp files
			return;
		}

		// fsync the DIRECTORY so the rename itself is durable. Without this the file contents
		// survive a power loss but the directory entry pointing at them may not.
		int dirFd = ::open(MARKER_DIR, O_RDONLY | O_DIRECTORY);

		if (dirFd >= 0) {
			::fsync(dirFd);
			::close(dirFd);
		}
		// A failure to fsync the directory is NOT reported: the marker is already correct and
		// visible, and this only affects survival of an unclean power loss.
	} catch (const Exception& e) {
		objectManager->error() << "last-successful-save marker: unexpected exception: " << e.getMessage();
	} catch (...) {
		objectManager->error() << "last-successful-save marker: unknown exception";
	}
}
