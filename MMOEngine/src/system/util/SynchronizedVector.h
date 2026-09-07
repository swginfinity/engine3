/*
** Copyright (C) 2007-2019 SWGEmu
** See file COPYING for copying conditions.
*/
/*
 * SynchronizedVector.h
 *
 *  Created on: 20/12/2013
 *      Author: victor
 */

#ifndef SYNCHRONIZEDVECTOR_H_
#define SYNCHRONIZEDVECTOR_H_

#include "Vector.h"

#include "system/thread/ReadWriteLock.h"
#include "system/thread/Locker.h"

namespace sys {
 namespace util {

   template<class E> class SynchronizedVector : public Object {
   protected:
	   mutable ReadWriteLock guard;
	   Vector<E> vector;

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   AtomicInteger count;
#endif
   public:
	   SynchronizedVector();

	   SynchronizedVector(const SynchronizedVector<E>& array);

	   SynchronizedVector(const Vector<E>& array);

	   SynchronizedVector<E>& operator=(const SynchronizedVector<E>& array);

	   bool add(const E& element);
	   bool add(int index, const E& element);

	   void addAll(const ArrayList<E>& array);

	   bool contains(const E& element);

	   void insertElementAt(const E& element, int index);

	   E get(int index) const;

	   E elementAt(int index) const;

	   E remove(int index);

	   bool removeElement(const E& element);

	   void removeElementAt(int index);

	   void removeRange(int fromIndex, int toIndex);

	   void removeAll(int newSize = 10, int newIncrement = 5);

	   E set(int index, const E& element);
	   void setElementAt(int index, const E& element);

	   bool toBinaryStream(ObjectOutputStream* stream) {
		   return vector.toBinaryStream(stream);
	   }

	   bool parseFromBinaryStream(ObjectInputStream* stream) {
		   return vector.parseFromBinaryStream(stream);
	   }

	   const Vector<E>& getVectorUnsafe() const {
	   	   return vector;
	   }

	   /**
	    * A SNAPSHOT of the contents, taken under the read lock.
	    *
	    * Every operation on this class is individually locked and NONE of them compose. The
	    * idiom `for (int i = 0; i < v.size(); ++i) v.get(i)` therefore has no lock spanning the
	    * two calls: a writer that shrinks the vector between them makes get(i) throw
	    * ArrayIndexOutOfBoundsException, which is a caught-and-logged exception that abandons
	    * whatever the loop was doing partway through. size() is worse than get() here -- with
	    * ATOMIC_SYNC_VECTOR_COUNT off it reads vector.size() with NO lock at all.
	    *
	    * Callers that iterate must iterate a snapshot. The elements are references, so a snapshot
	    * can contain something that has since been removed -- an iteration over a snapshot must
	    * still tolerate a stale element, exactly as it must tolerate one removed a line later.
	    * What the snapshot removes is the crash, not the staleness.
	    */
	   Vector<E> toVector() const {
		   ReadLocker locker(&guard);

		   return vector;
	   }

	   int size() const {
#ifdef ATOMIC_SYNC_VECTOR_COUNT
		   return count;
#else
		   return vector.size();
#endif
	   }

	   inline bool isEmpty() const {
#ifdef ATOMIC_SYNC_VECTOR_COUNT
		   return count == 0;
#else
		   return vector.isEmpty();
#endif
	   }
   };
   template<class E>
   SynchronizedVector<E>::SynchronizedVector() : vector() {

   }

   template<class E>
   SynchronizedVector<E>::SynchronizedVector(const SynchronizedVector<E>& array) : Object(), vector(array.toVector()) {
	   // toVector() rather than array.vector: the copy constructor read the source's storage with
	   // NO lock held, so copying a vector another thread was mutating raced on the buffer itself.
	   // DisseminateExperienceTask does exactly that -- it copies a lair's live spawnedCreatures on
	   // the death path (DisseminateExperienceTask.h:27) while the lair keeps despawning into it.
	   // Only the SOURCE is locked here; a newly constructed object has no other referent.
#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count = vector.size();
#endif
   }

   template<class E>
   SynchronizedVector<E>::SynchronizedVector(const Vector<E>& array) : vector(array) {
#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count = array.vector.size();
#endif
   }

   template<class E>
   SynchronizedVector<E>& SynchronizedVector<E>::operator=(const SynchronizedVector<E>& array) {
	   // Snapshot the SOURCE before taking our own lock. This used to read array.getVectorUnsafe()
	   // with only the destination locked, so assigning from a vector another thread was mutating
	   // raced on the source's buffer -- the same hole the copy constructor had.
	   //
	   // 🔴 CONSTRAINT THIS INTRODUCES, AND IT IS NOT SATISFIED BY SynchronizedSortedVector:
	   // the source read lock must not be taken while the CALLER already holds another
	   // SynchronizedVector's guard, or two threads assigning in opposite directions deadlock
	   // ABBA on non-recursive pthread rwlocks. This function itself holds nothing while
	   // snapshotting, so a direct `a = b` is safe. SynchronizedSortedVector::operator= takes its
	   // own write lock and THEN calls this, which nests source-read inside destination-write --
	   // that path is already a hard self-deadlock for an unrelated reason (it re-acquires its own
	   // non-recursive guard through the Locker below), so it is dead rather than newly broken.
	   // Do not revive it without restructuring both.
	   Vector<E> snapshot = array.toVector();

	   Locker locker(&guard);

	   vector.operator=(std::move(snapshot));

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   // From what we actually hold, not from the source's live counter: `vector` is the snapshot,
	   // and array.count is both a different moment and an unlocked read.
	   count = vector.size();
#endif

	   return *this;
   }

   template<class E>
   bool SynchronizedVector<E>::add(const E& element) {
	   Locker locker(&guard);

	   bool ret = vector.add(element);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count.increment();
#endif

	   return ret;
   }

   template<class E>
   bool SynchronizedVector<E>::add(int index, const E& element) {
	   Locker locker(&guard);

	   bool ret = vector.add(index, element);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count = vector.size();
#endif

	   return ret;
   }

   template<class E>
   void SynchronizedVector<E>::addAll(const ArrayList<E>& array) {
	   Locker locker(&guard);

	   vector.addAll(array);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count = vector.size();
#endif
   }

   template<class E>
   bool SynchronizedVector<E>::contains(const E& element) {
	   ReadLocker locker(&guard);

	   bool ret = vector.contains(element);

	   return ret;
   }

   template<class E>
   void SynchronizedVector<E>::insertElementAt(const E& element, int index) {
	   Locker locker(&guard);

	   vector.insertElementAt(element, index);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count = vector.size();
#endif
   }

   template<class E>
   E SynchronizedVector<E>::get(int index) const {
	   ReadLocker locker(&guard);

	   E ret = vector.get(index);

	   return ret;
   }

   template<class E>
   E SynchronizedVector<E>::elementAt(int index) const {
	   ReadLocker locker(&guard);

	   E ret = vector.elementAt(index);

	   return ret;
   }

   template<class E>
   E SynchronizedVector<E>::remove(int index) {
	   Locker locker(&guard);

	   E obj = vector.remove(index);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count.decrement();
#endif

	   return obj;
   }

   template<class E>
   bool SynchronizedVector<E>::removeElement(const E& element) {
	   Locker locker(&guard);

	   bool obj = vector.removeElement(element);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count = vector.size();
#endif

	   return obj;
   }

   template<class E>
   void SynchronizedVector<E>::removeElementAt(int index) {
	   Locker locker(&guard);

	   vector.removeElementAt(index);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count.decrement();
#endif
   }

   template<class E>
   void SynchronizedVector<E>::removeRange(int fromIndex, int toIndex) {
	   Locker locker(&guard);

	   vector.removeRange(fromIndex, toIndex);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count = vector.size();
#endif
   }

   template<class E>
   void SynchronizedVector<E>::removeAll(int newSize, int newIncrement) {
	   Locker locker(&guard);

	   vector.removeAll(newSize, newIncrement);

#ifdef ATOMIC_SYNC_VECTOR_COUNT
	   count = 0;
#endif
   }

   template<class E>
   E SynchronizedVector<E>::set(int index, const E& element) {
	   Locker locker(&guard);

	   E obj = vector.set(index, element);

	   return obj;
   }

   template<class E>
   void SynchronizedVector<E>::setElementAt(int index, const E& element) {
	   Locker locker(&guard);

	   vector.setElementAt(index, element);
   }

 }
}

using namespace sys::util;

#endif /* SYNCHRONIZEDVECTOR_H_ */
