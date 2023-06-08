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

#ifndef __OS_WORKGROUP_OBJECT__
#define __OS_WORKGROUP_OBJECT__

#ifndef __OS_WORKGROUP_INDIRECT__
#error "Please #include <os/workgroup.h> instead of this file directly."
#include <os/workgroup_base.h> // For header doc
#endif

__BEGIN_DECLS

OS_WORKGROUP_ASSUME_NONNULL_BEGIN
OS_WORKGROUP_ASSUME_ABI_SINGLE_BEGIN

/*!
 * @typedef os_workgroup_t
 *
 * @abstract
 * A reference counted os object representing a workload that needs to
 * be distinctly recognized and tracked by the system.  The workgroup
 * tracks a collection of threads all working cooperatively. An os_workgroup
 * object - when not an instance of a specific os_workgroup_t subclass -
 * represents a generic workload and makes no assumptions about the kind of
 * work done.
 *
 * @discussion
 * Threads can explicitly join an os_workgroup_t to mark themselves as
 * participants in the workload.
 */
;OS_WORKGROUP_DECL(os_workgroup, WorkGroup);


/* Attribute creation and specification */

/*!
 * @typedef os_workgroup_attr_t
 *
 * @abstract
 * Pointer to an opaque structure for describing attributes that can be
 * configured on a workgroup at creation.
 */
typedef struct os_workgroup_attr_opaque_s os_workgroup_attr_s;
typedef struct os_workgroup_attr_opaque_s *os_workgroup_attr_t;

/* os_workgroup_t attributes need to be initialized before use. This initializer
 * allows you to create a workgroup with the system default attributes. */
#define OS_WORKGROUP_ATTR_INITIALIZER_DEFAULT \
	{ .sig = _OS_WORKGROUP_ATTR_SIG_DEFAULT_INIT }



/* The main use of the workgroup API is through instantiations of the concrete
 * subclasses - please refer to os/workgroup_interval.h and
 * os/workgroup_parallel.h for more information on creating workgroups.
 *
 * The functions below operate on all subclasses of os_workgroup_t.
 */

/*!
 * @function os_workgroup_copy_port
 *
 * @abstract
 * Returns a reference to a send right representing this workgroup that is to be
 * sent to other processes. This port is to be passed to
 * os_workgroup_create_with_port() to create a workgroup object.
 *
 * It is the client's responsibility to release the send right reference.
 *
 * If an error is encountered, errno is set and returned.
 */
API_AVAILABLE(macos(11.0))
API_UNAVAILABLE(ios, tvos, watchos)
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT OS_WORKGROUP_WARN_RESULT
int
os_workgroup_copy_port(os_workgroup_t wg, mach_port_t *mach_port_out);

/*!
 * @function os_workgroup_create_with_port
 *
 * @abstract
 * Create an os_workgroup_t object from a send right returned by a previous
 * call to os_workgroup_copy_port, potentially in a different process.
 *
 * A newly created os_workgroup_t has no initial member threads - in particular
 * the creating thread does not join the os_workgroup_t implicitly.
 *
 * @param name
 * A client specified string for labelling the workgroup. This parameter is
 * optional and can be NULL.
 *
 * @param mach_port
 * The send right to create the workgroup from. No reference is consumed
 * on the specified send right.
 */
API_AVAILABLE(macos(11.0))
API_UNAVAILABLE(ios, tvos, watchos)
OS_SWIFT_NAME(WorkGroup.init(__name:port:)) OS_WORKGROUP_EXPORT OS_WORKGROUP_RETURNS_RETAINED
os_workgroup_t _Nullable
os_workgroup_create_with_port(const char *OS_WORKGROUP_UNSAFE_INDEXABLE _Nullable, mach_port_t mach_port);

/*!
 * @function os_workgroup_create_with_workgroup
 *
 * @abstract
 * Create a new os_workgroup object from an existing os_workgroup.
 *
 * The newly created os_workgroup has no initial member threads - in particular
 * the creating threaad does not join the os_workgroup_t implicitly.
 *
 * @param name
 * A client specified string for labelling the workgroup. This parameter is
 * optional and can be NULL.
 *
 * @param wg
 * The existing workgroup to create a new workgroup object from.
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT OS_WORKGROUP_RETURNS_RETAINED
os_workgroup_t _Nullable
os_workgroup_create_with_workgroup(const char * OS_WORKGROUP_UNSAFE_INDEXABLE _Nullable, os_workgroup_t wg);

/*!
 * @typedef os_workgroup_join_token, os_workgroup_join_token_t
 *
 * @abstract
 * An opaque join token which the client needs to pass to os_workgroup_join
 * and os_workgroup_leave
 */
OS_REFINED_FOR_SWIFT
typedef struct os_workgroup_join_token_opaque_s os_workgroup_join_token_s;
OS_REFINED_FOR_SWIFT
typedef struct os_workgroup_join_token_opaque_s *os_workgroup_join_token_t;


/*!
 * @function os_workgroup_join
 *
 * @abstract
 * Joins the current thread to the specified workgroup and populates the join
 * token that has been passed in. This API is real-time safe.
 *
 * @param wg
 * The workgroup that the current thread would like to join
 *
 * @param token_out
 * Pointer to a client allocated struct which the function will populate
 * with the join token. This token must be passed in by the thread when it calls
 * os_workgroup_leave().
 *
 * Errors will be returned in the following cases:
 *
 * EALREADY		The thread is already part of a workgroup that the specified
 *				workgroup does not nest with
 * EINVAL		The workgroup has been cancelled
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT OS_WORKGROUP_WARN_RESULT
int
os_workgroup_join(os_workgroup_t wg, os_workgroup_join_token_t token_out);

/*!
 * @function os_workgroup_leave
 *
 * @abstract
 * This removes the current thread from a workgroup it has previously
 * joined. Threads must leave all workgroups in the reverse order that they
 * have joined them. Failing to do so before exiting will result in undefined
 * behavior.
 *
 * If the join token is malformed, the process will be aborted.
 *
 * This API is real time safe.
 *
 * @param wg
 * The workgroup that the current thread would like to leave.
 *
 * @param token
 * This is the join token populated by the most recent call to
 * os_workgroup_join().
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT
void
os_workgroup_leave(os_workgroup_t wg, os_workgroup_join_token_t token);

/* Working Arena index of a thread in a workgroup */
typedef uint32_t os_workgroup_index;
/* Destructor for Working Arena */
typedef void (*os_workgroup_working_arena_destructor_t)(void * _Nullable);

/*!
 * @function os_workgroup_set_working_arena
 *
 * @abstract
 * Associates a client defined working arena with the workgroup. The arena
 * is local to the workgroup object in the process. This is intended for
 * distributing a manually managed memory allocation between member threads
 * of the workgroup.
 *
 * This function can be called multiple times and the client specified
 * destructor will be called on the previously assigned arena, if any. This
 * function can only be called when no threads have currently joined the
 * workgroup and all workloops associated with the workgroup are idle.
 *
 * @param wg
 * The workgroup to associate the working arena with
 *
 * @param arena
 * The client managed arena to associate with the workgroup. This value can
 * be NULL.
 *
 * @param max_workers
 * The maximum number of threads that will ever query the workgroup for the
 * arena and request an index into it.  If the arena is not used to partition
 * work amongst member threads, then this field can be 0.
 *
 * @param destructor
 * A destructor to call on the previously assigned working arena, if any
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT OS_WORKGROUP_WARN_RESULT
int
os_workgroup_set_working_arena(os_workgroup_t wg, void * _Nullable arena,
	uint32_t max_workers, os_workgroup_working_arena_destructor_t destructor);

/*!
 * @function os_workgroup_get_working_arena
 *
 * @abstract
 * Returns the working arena associated with the workgroup and the current
 * thread's index in the workgroup. This function can only be called by a member
 * of the workgroup. Multiple calls to this API by a member thread will return
 * the same arena and index until the thread leaves the workgroup.
 *
 * For workloops with an associated workgroup, every work item on the workloop
 * will receive the same index in the arena.
 *
 * This method returns NULL if no arena is set on the workgroup. The index
 * returned by this function is zero-based and is namespaced per workgroup
 * object in the process. The indices provided are strictly monotonic and never
 * reused until a future call to os_workgroup_set_working_arena.
 *
 * @param wg
 * The workgroup to get the working arena from.
 *
 * @param index_out
 * A pointer to a os_workgroup_index which will be populated by the caller's
 * index in the workgroup.
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT
void * _Nullable
os_workgroup_get_working_arena(os_workgroup_t wg,
		os_workgroup_index * _Nullable index_out);

/*!
 * @function os_workgroup_cancel
 *
 * @abstract
 * This API invalidates a workgroup and indicates to the system that the
 * workload is no longer relevant to the caller.
 *
 * No new work should be initiated for a cancelled workgroup and
 * work that is already underway should periodically check for
 * cancellation with os_workgroup_testcancel and initiate cleanup if needed.
 *
 * Threads currently in the workgroup continue to be tracked together but no
 * new threads may join this workgroup - the only possible operation allowed is
 * to leave the workgroup. Other actions may have undefined behavior or
 * otherwise fail.
 *
 * This API is idempotent. Cancellation is local to the workgroup object
 * it is called on and does not affect other workgroups.
 *
 * @param wg
 * The workgroup that that the thread would like to cancel
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT
void
os_workgroup_cancel(os_workgroup_t wg);

/*!
 * @function os_workgroup_testcancel
 *
 * @abstract
 * Returns true if the workgroup object has been cancelled. See also
 * os_workgroup_cancel
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT
bool
os_workgroup_testcancel(os_workgroup_t wg);

/*!
 * @typedef os_workgroup_max_parallel_threads_attr_t
 *
 * @abstract
 * A pointer to a structure describing the set of properties of a workgroup to
 * override with the explicitly specified values in the structure.
 *
 * See also os_workgroup_max_parallel_threads.
 */
OS_REFINED_FOR_SWIFT
typedef struct os_workgroup_max_parallel_threads_attr_s os_workgroup_mpt_attr_s;
OS_REFINED_FOR_SWIFT
typedef struct os_workgroup_max_parallel_threads_attr_s *os_workgroup_mpt_attr_t;

/*!
 * @function os_workgroup_max_parallel_threads
 *
 * @abstract
 * Returns the system's recommendation for maximum number of threads the client
 * should make for a multi-threaded workload in a given workgroup.
 *
 * This API takes into consideration the current hardware the code is running on
 * and the attributes of the workgroup. It does not take into consideration the
 * current load of the system and therefore always provides the most optimal
 * recommendation for the workload.
 *
 * @param wg
 * The workgroup in which the multi-threaded workload will be performed in. The
 * threads performing the multi-threaded workload are expected to join this
 * workgroup.
 *
 * @param attr
 * This value is currently unused and should be NULL.
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_REFINED_FOR_SWIFT OS_WORKGROUP_EXPORT
int
os_workgroup_max_parallel_threads(os_workgroup_t wg, os_workgroup_mpt_attr_t
		_Nullable attr);

OS_WORKGROUP_ASSUME_NONNULL_END

__END_DECLS

#endif /* __OS_WORKGROUP_OBJECT__ */
