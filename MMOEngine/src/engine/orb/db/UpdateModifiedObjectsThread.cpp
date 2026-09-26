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
			int skippedCount = 0;
			int skippedRowsDeleted = 0;

			for (int i = startOffset; i < endOffset; ++i) {
				DistributedObject* object = objectsToUpdate->get(i);
				ManagedObject* managedObject = static_cast<ManagedObject*>(object);

				if (object->isPersistent() && managedObject->isSaveExemptFromDatabase()) {
					++skippedCount;

					// A previous save may already have deleted this row; only issue
					// the delete once per transition into exemption (mirrors the
					// _isDeletedFromDatabase bookkeeping already used for the
					// _isMarkedForDeletion path below).
					if (!object->_isDeletedFromDatabase()) {
						objectManager->commitDestroyObjectToDB(object->_getObjectID());
						object->_setDeletedFromDatabase(true);

						// The row is gone, so the last-saved CRC no longer describes anything
						// on disk. Without this, an object that leaves exemption in exactly the
						// state it was last written in (moved into a crate and straight back)
						// hits commitUpdatePersistentObjectToDB's unchanged-CRC early return,
						// is never rewritten, and is lost at the next boot.
						managedObject->setLastCRCSave(0);

						++skippedRowsDeleted;
					}

					// Consume the dirty flag: this object is not being written, so
					// there is nothing left for the next save to do until it is
					// legitimately re-dirtied (e.g. moved out of the snapshot
					// container), which sets _updated true again on its own.
					object->_setUpdated(false);

					continue;
				}

				if (object->isPersistent() && objectManager->commitUpdatePersistentObjectToDB(object) == 0) {
					++j;

					// Reset now-stale "deleted" bookkeeping: this object has a real row
					// again, so if it cycles back into exemption later its row must be
					// deleted again rather than being (wrongly) assumed already gone.
					object->_setDeletedFromDatabase(false);
				}
			}

			objectManager->info(true) << "thread " << threadId << " copied "
				<< commas << j << " modified objects into ram in " << start.miliDifference(Time::MONOTONIC_TIME) << " ms";

			// log(), not info(true): info(true) only forces the CONSOLE print, and INFO is above
			// the core3.log file level on dev, TC and live. One line per worker per save cycle.
			if (skippedCount > 0) {
				objectManager->log() << "thread " << threadId << " save-exempt: skipped " << commas << skippedCount
					<< " snapshot-container objects, deleted " << commas << skippedRowsDeleted << " stale rows";
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
