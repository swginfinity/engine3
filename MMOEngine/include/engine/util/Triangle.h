/*
 * Triangle.h
 *
 *  Created on: 05/12/2010
 *      Author: victor
 */

#ifndef TRIANGLE_H_
#define TRIANGLE_H_

#include "Vector3.h"

namespace engine {
 namespace util {

	class AABB;

	class Triangle : public Variable {
		Vector3 vertices[3];

	public:
		Triangle() {

		}

		Triangle(const Triangle& tri) : Variable() {
			vertices[0] = tri.vertices[0];
			vertices[1] = tri.vertices[1];
			vertices[2] = tri.vertices[2];
		}

		Triangle(const Vector3 vert[]) {
			this->vertices[0] = vert[0];
			this->vertices[1] = vert[1];
			this->vertices[2] = vert[2];
		}

		Triangle& operator=(const Triangle& tri) {
			vertices[0] = tri.vertices[0];
			vertices[1] = tri.vertices[1];
			vertices[2] = tri.vertices[2];

			return *this;
		}

		bool toBinaryStream(ObjectOutputStream* stream) {
			for (int i = 0; i < 3; ++i) {
				vertices[i].toBinaryStream(stream);
			}

			return true;
		}

		bool parseFromBinaryStream(ObjectInputStream* stream) {
			for (int i = 0; i < 3; ++i) {
				vertices[i].parseFromBinaryStream(stream);
			}

			return true;
		}

		// distance squared to a point from the tri
		//float distSqrd(const Vector3& point) const;

		// calculate the midpoint
		Vector3 midPoint() const {
			return (vertices[0] + vertices[1] + vertices[2]) * (1.0f / 3.0f);
		}

		AABB triAABB() const;

		Vector3 getNormal() const {
			Vector3 normal;

			Vector3 v1 = vertices[1] - vertices[0];
			Vector3 v2 = vertices[2] - vertices[0];

			normal = v1.crossProduct(v2);

			normal.normalize();

			return normal;
		}

		inline Vector3 getVertex(int i) const {
			if (i > 2)
				ArrayIndexOutOfBoundsException(i);

			return vertices[i];
		}
	};
 }
}

using namespace engine::util;


#endif /* TRIANGLE_H_ */
