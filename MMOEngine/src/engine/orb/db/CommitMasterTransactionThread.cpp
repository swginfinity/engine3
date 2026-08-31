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

#include "system/io/File.h"
#include "system/io/FileWriter.h"

#include <cstdio>

CommitMasterTransactionThread::CommitMasterTransactionThread() : Logger("CommitMasterTransactionThread") {
	transaction = nullptr;
	threads = nullptr;

	objectsToDeleteFromRam = nullptr;

	numberOfThreads = 0;

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

	transaction = trans;
	threads = workers;
	numberOfThreads = number;
	objectsToDeleteFromRam = objectsToCollect;

	blockMutex.lock();

	waitCondition.signal(&blockMutex);

	blockMutex.unlock();
}

void CommitMasterTransactionThread::run() {
	while (doRun) {
		blockMutex.lock();

		waitCondition.wait(&blockMutex);

		if (doRun) {
			commitData();
		}

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

	if (rootBroker) {
		commitRet = ObjectDatabaseManager::instance()->commitTransaction(transaction);
		ObjectDatabaseManager::instance()->checkpoint();

		objectManager->onCommitData();
	}

	objectManager->info(true) << "master transaction committed";

	objectManager->checkCommittedObjects();

	objectManager->info(true) << "starting garbage collection for " << objectsToDeleteFromRam->size() << " candidates";

	int objs = garbageCollect(objectManager);

	objectManager->info(true) << "deleted from ram " << objs << " objects";

	objectManager->finishObjectUpdate();

	// 🔴 THE ONE SAVE-PATH LINE THAT REACHES core3.log, AND THE LEVEL IS THE WHOLE POINT.
	// Every other line in this cycle is info(true): `forcedLog` forces only the CONSOLE
	// print, while the file still goes through the level filter, and INFO(4) is above our
	// LogFileLevel(3) on both TC and live. So the entire save cycle has only ever existed
	// in screen scrollback, which is why detecting the 2026-08-30 six-hour stall required
	// scraping a screen buffer -- and why a gdb session that flooded that buffer later
	// blinded the detector mid-incident. log() is LogLevel::LOG(3), which passes the file
	// filter. Do NOT "tidy" this to info(true); that silently returns it to console-only.
	//
	// warning() would also reach the file, but this is a routine success and the sampler
	// counts WARNING/ERROR lines -- a heartbeat at WARNING would manufacture alert noise
	// 288 times a day. LOG lands in the file and stays out of those counters.
	//
	// Deliberately terse (MrO 2026-08-31: "I would like to see every 5 minutes that the
	// backup succeeded, don't need all the details"). The counts stay on the console line
	// in finishObjectUpdate(). A FAILED commit already reports itself: commitTransaction
	// logs error() with db_strerror (DatabaseManager.cpp:517-519), and ERROR(1) passes the
	// file filter too -- so the file gets a success heartbeat or a loud failure, and a
	// STALL is the absence of both.
	//
	// Only on the root broker: a non-root broker performs no local commit, so printing a
	// durability line there would assert something this process did not do.
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
	// db_strerror (DatabaseManager.cpp:517-519) and ERROR(1) passes the file-level filter.
	// So a failure is loud in core3.log, a success refreshes this file, and a STALL is the
	// absence of both -- which is exactly the signal that did not exist on 2026-08-30.
	//
	// 🔴 THIS MUST NEVER THROW INTO THE COMMIT THREAD. Thread::run is invoked with no catch
	// (Thread.cpp:46-56), so an escaping exception here would take the process down -- i.e. a
	// monitoring convenience could kill the server it exists to watch. Any failure to write
	// the marker is swallowed after one error line; a stale marker then reads as a stall,
	// which fails in the safe direction.
	if (rootBroker && commitRet == 0) {
		try {
			Time now;
			StringBuffer marker;
			marker << now.getMiliTime() / 1000 << " " << now.getFormattedTime() << "\n";

			// Write-and-rename so a monitor can never read a half-written marker.
			File tmpFile("log/last-successful-save.tmp");
			FileWriter tmpWriter(&tmpFile, false);
			tmpWriter << marker;
			tmpWriter.close();

			// std::rename is the atomic step; engine3's File has no rename. Same directory, so
			// it is a rename within one filesystem and a reader sees either the old marker or
			// the new one, never a half-written one.
			if (std::rename("log/last-successful-save.tmp", "log/last-successful-save") != 0) {
				objectManager->error("could not rename last-successful-save marker into place");
			}
		} catch (const Exception& e) {
			objectManager->error() << "failed writing last-successful-save marker: " << e.getMessage();
		} catch (...) {
			objectManager->error() << "failed writing last-successful-save marker: unknown exception";
		}
	}
}
