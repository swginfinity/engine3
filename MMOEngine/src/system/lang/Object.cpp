/*
Copyright (C) 2007 <SWGEmu>. All rights reserved.
Distribution of this file for usage outside of Core3 is prohibited.
*/

#include "ref/Reference.h"
#include "ref/WeakReference.h"

#include "system/thread/Locker.h"

#include "MemoryManager.h"

#include "Object.h"

void Object::release() {
	if (_references.get() == 0)
		assert(0 && "Object already delted");

	if (decreaseCount()) {
		if (notifyDestroy()) {
			MemoryManager::getInstance()->reclaim(this);
		}
	}
}

void Object::acquireWeak(WeakReferenceBase* ref) {
#ifndef WITH_STM
	Locker locker(&referenceMutex);

	weakReferences.add(ref);
#endif


}

void Object::releaseWeak(WeakReferenceBase* ref) {
#ifndef WITH_STM
	Locker locker(&referenceMutex);

	for (int i = 0; i < weakReferences.size(); ++i) {
		WeakReferenceBase* reference = weakReferences.get(i);

		if (reference == ref) {
			weakReferences.remove(i);

			break;
		}
	}
#endif


}

void Object::destroy() {
	_destroying = true;

#ifndef WITH_STM
	Locker locker(&referenceMutex);

	while (!weakReferences.isEmpty()) {
			WeakReferenceBase* ref = weakReferences.remove(0);
			ref->clearObject();
		}
#endif


#ifndef WITH_STM
	locker.release();
#endif

	delete this;
}

#ifdef TRACE_REFERENCES
void Object::addHolder(void* obj) {
#ifndef WITH_STM
	Locker locker(&referenceMutex);
#endif

	StackTrace* trace = new StackTrace();
	referenceHolders.put(obj, trace);
}

void Object::removeHolder(void* obj) {
#ifndef WITH_STM
	Locker locker(&referenceMutex);
#endif

	StackTrace* trace = referenceHolders.get(obj);

	if (trace != NULL) {
		delete trace;
		referenceHolders.drop(obj);
	}
}

void Object::printReferenceHolders() {
	for (int i = 0; i < referenceHolders.size(); ++i) {
		StackTrace* trace = referenceHolders.get(i);

		trace->print();
	}
}
#endif

String Object::toString() {
	char buf[20];

	sprintf(buf, "%p", this);

	return String(buf);
}
