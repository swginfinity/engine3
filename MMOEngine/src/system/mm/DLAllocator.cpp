/*
Copyright (C) 2007 <SWGEmu>. All rights reserved.
Distribution of this file for usage outside of Core3 is prohibited.
*/

#include "DLAllocator.h"

#define USE_DL_PREFIX 1
#define USE_LOCKS 1
#define MSPACES 1
#include "dlmalloc.h"

DLAllocator::DLAllocator(void* base, size_t size) {
	dlMspace = NULL;

	dlBase = base;
	dlSize = size;

	initialize();
}

DLAllocator::~DLAllocator() {
	destroy();
}

void DLAllocator::initialize() {
	dlMspace = create_mspace_with_base(dlBase, dlSize, 1);
}

void DLAllocator::destroy() {
	destroy_mspace((mspace) dlMspace);
}

void* DLAllocator::allocate(size_t size) {
	return mspace_malloc((mspace) dlMspace, size);
}

void DLAllocator::free(void* mem) {
	mspace_free((mspace) dlMspace, mem);
}