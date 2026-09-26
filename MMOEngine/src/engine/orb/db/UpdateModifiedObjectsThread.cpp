/*
** Copyright (C) 2007-2019 SWGEmu
** See file COPYING for copying conditions.
*/

#include "UpdateModifiedObjectsThread.h"

UpdateModifiedObjectsThread::UpdateModifiedObjectsThread(int id, DOBObjectManager* manager, int cpu) {
	objectManager = manager;
	objectsToUpdate = nullptr;
	objectsToDelete = nullptr;
	startOffset = 0;
	endOffset = 0;
	doRun = true;
	waitingToStart = true;
	threadId = id;
	working = false;
	finishedCommiting = false;
	waitingToCommit = false;
	loadedDBHandles = false;

	transaction = nullptr;

	this->cpu = cpu;
}

void UpdateModifiedObjectsThread::run() NO_THREAD_SAFETY_ANALYSIS {
	assignToCPU(cpu);

	while (doRun) {
		blockMutex.lock();

		while (!copyRAMFinished) {
			waitingToStart = true;

			waitCondition.wait(&blockMutex);

			waitingToStart = false;

			working = true;
			finishedCommiting = false;

			commitObjectsToDatabase();

			if (!loadedDBHandles) {
				auto dbManager = ObjectDatabaseManager::instance();
				auto dbCount = dbManager->getTotalDatabaseCount();

				for (int i = 0; i < dbCount; i++) {
					dbManager->getDatabase(i)->getDatabaseHandle();
				}

				loadedDBHandles = true;
			}

			working = false;

			objectsToUpdate = nullptr;
			objectsToDelete = nullptr;

			finishedWorkCondition.broadcast(&blockMutex);
		}

		commitTransaction();
	}
}

void UpdateModifiedObjectsThread::commitTransaction() NO_THREAD_SAFETY_ANALYSIS {
	bool rootBroker = DistributedObjectBroker::instance()->isRootBroker();

	if (transaction != nullptr) {
		waitingToCommit = true;

		waitMasterTransaction.wait(&blockMutex);

		Timer clockTimer(Time::MONOTONIC_TIME);
		clockTimer.start();

		ObjectDatabaseManager::instance()->commitLocalTransaction(transaction);

		uint64 delta = clockTimer.stop();

		objectManager->info(true) << "thread " << threadId << " committed objects into database in " << delta / 1000000 << " ms";

		transaction = nullptr;

		copyRAMFinished = false;

		finishedCommiting = true;

		blockMutex.unlock();
	} else {
		finishedCommiting = true;

		copyRAMFinished = false;

		blockMutex.unlock();

		if (rootBroker) {
			ObjectDatabaseManager::instance()->commitLocalTransaction();
		}
	}
}

void UpdateModifiedObjectsThread::commitObjectsToDatabase() {
	try {
		Time start(Time::MONOTONIC_TIME);

		if (objectsToUpdate != nullptr) {
			int j = 0;

			// Infinity (GH-2201): snapshot-container filter. This is the single choke
			// point every save (full, delta, and the final shutdown save all funnel
			// here -- see DOBObjectManager::executeUpdateThreads/executeDeltaUpdateThreads,
			// both of which dispatch to this same commitObjectsToDatabase()) uses to
			// actually write a persistent object's row, so it is the one place that
			// covers every write regardless of which path selected the object.
			//
			// An exempt object is simply NOT WRITTEN, and nothing else: no row delete, no
			// bookkeeping flags, and its dirty flag is deliberately LEFT SET. So it is
			// re-evaluated on every save, and the save after it (or its parent) leaves the
			// snapshot container writes it -- and its children, which were skipped the same
			// way -- with no re-dirtying needed. A dirty object is also never picked by the
			// post-commit RAM eviction (CommitMasterTransactionThread). The first version
			// deleted rows and cleared the flag; three review rounds found three lifecycle
			// defects in that (stale lastCRCSave, eviction with no row, children of a looted
			// item never rewritten). A row that already exists for something now in a crate
			// is left for the orphan purge, like the ones that predate this change.
			int skippedCount = 0;

			for (int i = startOffset; i < endOffset; ++i) {
				DistributedObject* object = objectsToUpdate->get(i);

				if (object->isPersistent() && static_cast<ManagedObject*>(object)->isSaveExemptFromDatabase()) {
					++skippedCount;

					continue;
				}

				if (object->isPersistent() && objectManager->commitUpdatePersistentObjectToDB(object) == 0)
					++j;
			}

			objectManager->info(true) << "thread " << threadId << " copied "
				<< commas << j << " modified objects into ram in " << start.miliDifference(Time::MONOTONIC_TIME) << " ms";

			// log(), not info(true): info(true) only forces the CONSOLE print, and INFO is above
			// the core3.log file level on dev, TC and live. One line per worker per save cycle.
			if (skippedCount > 0) {
				objectManager->log() << "thread " << threadId << " save-exempt: skipped " << commas << skippedCount
					<< " snapshot-container objects (not written, left dirty)";
			}
		}

		start.updateToCurrentTime(Time::MONOTONIC_TIME);

		if (objectsToDelete != nullptr) {
			for (int i = 0; i < objectsToDelete->size(); ++i) {
				DistributedObject* object = objectsToDelete->getUnsafe(i);

				if (!object->_isDeletedFromDatabase()) {
					objectManager->commitDestroyObjectToDB(object->_getObjectID());
					object->_setDeletedFromDatabase(true);
				}
			}

			objectManager->info(true) << "thread " << threadId << " committed "
				<< commas << objectsToDelete->size() <<  " objects for deletion into ram in " << start.miliDifference(Time::MONOTONIC_TIME) << " ms";
		}
	} catch (const Exception& e) {
		objectManager->error(e.getMessage());
	} catch (...) {
		objectManager->error("unreported exception caught");

		throw;
	}
}
