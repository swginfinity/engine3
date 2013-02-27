/*
 *	engine/core/ManagedService.h generated by engine3 IDL compiler 0.60
 */

#ifndef MANAGEDSERVICE_H_
#define MANAGEDSERVICE_H_

#include "engine/core/Core.h"

#include "engine/core/ManagedReference.h"

#include "engine/core/ManagedWeakReference.h"

#include "engine/core/ManagedObject.h"

namespace engine {
namespace core {

class ManagedService : public ManagedObject {
public:
	DistributedObjectServant* _getImplementation();
	DistributedObjectServant* _getImplementationForRead();

	void _setImplementation(DistributedObjectServant* servant);

protected:
	ManagedService(DummyConstructorParameter* param);

	virtual ~ManagedService();

	friend class ManagedServiceHelper;
};

} // namespace core
} // namespace engine

using namespace engine::core;

namespace engine {
namespace core {

class ManagedServiceImplementation : public ManagedObjectImplementation {

public:
	ManagedServiceImplementation();
	ManagedServiceImplementation(DummyConstructorParameter* param);

	WeakReference<ManagedService*> _this;

	operator const ManagedService*();

	DistributedObjectStub* _getStub();
	virtual void readObject(ObjectInputStream* stream);
	virtual void writeObject(ObjectOutputStream* stream);
protected:
	virtual ~ManagedServiceImplementation();

	void finalize();

	void _initializeImplementation();

	void _setStub(DistributedObjectStub* stub);

	void lock(bool doLock = true);

	void lock(ManagedObject* obj);

	void rlock(bool doLock = true);

	void wlock(bool doLock = true);

	void wlock(ManagedObject* obj);

	void unlock(bool doLock = true);

	void runlock(bool doLock = true);

	void _serializationHelperMethod();
	bool readObjectMember(ObjectInputStream* stream, const uint32& nameHashCode);
	int writeObjectMembers(ObjectOutputStream* stream);

	friend class ManagedService;
};

class ManagedServiceAdapter : public ManagedObjectAdapter {
public:
	ManagedServiceAdapter(ManagedService* impl);

	void invokeMethod(sys::uint32 methid, DistributedMethod* method);

};

class ManagedServiceHelper : public DistributedObjectClassHelper, public Singleton<ManagedServiceHelper> {
	static ManagedServiceHelper* staticInitializer;

public:
	ManagedServiceHelper();

	void finalizeHelper();

	DistributedObject* instantiateObject();

	DistributedObjectServant* instantiateServant();

	DistributedObjectAdapter* createAdapter(DistributedObjectStub* obj);

	friend class Singleton<ManagedServiceHelper>;
};

} // namespace core
} // namespace engine

using namespace engine::core;

#endif /*MANAGEDSERVICE_H_*/
