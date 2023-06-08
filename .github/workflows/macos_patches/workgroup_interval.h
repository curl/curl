/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
 *
 * @APPLE_APACHE_LICENSE_HEADER_START@
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @APPLE_APACHE_LICENSE_HEADER_END@
 */

#ifndef __OS_WORKGROUP_INTERVAL__
#define __OS_WORKGROUP_INTERVAL__

#ifndef __OS_WORKGROUP_INDIRECT__
#error "Please #include <os/workgroup.h> instead of this file directly."
#include <os/workgroup_base.h> // For header doc
#endif

__BEGIN_DECLS

OS_WORKGROUP_ASSUME_NONNULL_BEGIN
OS_WORKGROUP_ASSUME_ABI_SINGLE_BEGIN

/*!
 * @typedef os_workgroup_interval_t
 *
 * @abstract
 * A subclass of an os_workgroup_t for tracking work performed as part of
 * a repeating interval-driven workload.
 */
OS_WORKGROUP_SUBCLASS_DECL_PROTO(os_workgroup_interval, Repeatable);
OS_WORKGROUP_SUBCLASS_DECL(os_workgroup_interval, os_workgroup, WorkGroupInterval);

/* During the first instance of this API, the only supported interval
 * workgroups are for audio workloads. Please refer to the AudioToolbox
 * framework for more information.
 */

/*
 * @typedef os_workgroup_interval_data, os_workgroup_interval_data_t
 *
 * @abstract
 * An opaque structure containing additional configuration for the workgroup
 * interval.
 */
typedef struct os_workgroup_interval_data_opaque_s os_workgroup_interval_data_s;
typedef struct os_workgroup_interval_data_opaque_s *os_workgroup_interval_data_t;
#define OS_WORKGROUP_INTERVAL_DATA_INITIALIZER \
	{ .sig = _OS_WORKGROUP_INTERVAL_DATA_SIG_INIT }

/*!
 * @function os_workgroup_interval_start
 *
 * @abstract
 * Indicates to the system that the member threads of this
 * os_workgroup_interval_t have begun working on an instance of the repeatable
 * interval workload with the specified timestamps. This function is real time
 * safe.
 *
 * This function will set and return an errno in the following cases:
 *
 * - The current thread is not a member of the os_workgroup_interval_t
 * - The os_workgroup_interval_t has been cancelled
 * - The timestamps passed in are malformed
 * - os_workgroup_interval_start() was previously called on the
 * os_workgroup_interval_t without an intervening os_workgroup_interval_finish()
 * - A concurrent workgroup interval configuration operation is taking place.
 *
 * @param start
 * Start timestamp specified in the os_clockid_t with which the
 * os_workgroup_interval_t was created. This is generally a time in the past and
 * indicates when the workgroup started working on an interval period
 *
 * @param deadline
 * Deadline timestamp specified in the os_clockid_t with which the
 * os_workgroup_interval_t was created. This specifies the deadline which the
 * interval period would like to meet.
 *
 * @param data
 * This field is currently unused and should be NULL
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT OS_WORKGROUP_WARN_RESULT
int
os_workgroup_interval_start(os_workgroup_interval_t wg, uint64_t start, uint64_t
		deadline, os_workgroup_interval_data_t _Nullable data);

/*!
 * @function os_workgroup_interval_update
 *
 * @abstract
 * Updates an already started interval workgroup to have the new
 * deadline specified. This function is real time safe.
 *
 * This function will return an error in the following cases:
 * - The current thread is not a member of the os_workgroup_interval_t
 * - The os_workgroup_interval_t has been cancelled
 * - The timestamp passed in is malformed
 * - os_workgroup_interval_start() was not previously called on the
 * os_workgroup_interval_t or was already matched with an
 * os_workgroup_interval_finish()
 * - A concurrent workgroup interval configuration operation is taking place
 *
 * @param deadline
 * Timestamp specified in the os_clockid_t with
 * which the os_workgroup_interval_t was created.
 *
 * @param data
 * This field is currently unused and should be NULL
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT OS_WORKGROUP_WARN_RESULT
int
os_workgroup_interval_update(os_workgroup_interval_t wg, uint64_t deadline,
		os_workgroup_interval_data_t _Nullable data);

/*!
 * @function os_workgroup_interval_finish
 *
 * @abstract
 * Indicates to the system that the member threads of
 * this os_workgroup_interval_t have finished working on the current instance
 * of the interval workload. This function is real time safe.
 *
 * This function will return an error in the following cases:
 *  - The current thread is not a member of the os_workgroup_interval_t
 *  - os_workgroup_interval_start() was not previously called on the
 * os_workgroup_interval_t or was already matched with an
 * os_workgroup_interval_finish()
 * - A concurrent workgroup interval configuration operation is taking place.
 *
 * @param data
 * This field is currently unused and should be NULL
 *
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT OS_WORKGROUP_WARN_RESULT
int
os_workgroup_interval_finish(os_workgroup_interval_t wg,
		os_workgroup_interval_data_t _Nullable data);

OS_WORKGROUP_ASSUME_NONNULL_END

__END_DECLS

#endif /* __OS_WORKGROUP_INTERVAL__ */
