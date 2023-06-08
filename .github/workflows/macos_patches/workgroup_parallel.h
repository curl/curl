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

#ifndef __OS_WORKGROUP_PARALLEL__
#define __OS_WORKGROUP_PARALLEL__

#ifndef __OS_WORKGROUP_INDIRECT__
#error "Please #include <os/workgroup.h> instead of this file directly."
#include <os/workgroup_base.h> // For header doc
#endif

#include <os/workgroup_object.h>

__BEGIN_DECLS

OS_WORKGROUP_ASSUME_NONNULL_BEGIN
OS_WORKGROUP_ASSUME_ABI_SINGLE_BEGIN

/*!
 * @typedef os_workgroup_parallel_t
 *
 * @abstract
 * A subclass of an os_workgroup_t for tracking parallel work.
 */
OS_WORKGROUP_SUBCLASS_DECL_PROTO(os_workgroup_parallel, Parallelizable);
OS_WORKGROUP_SUBCLASS_DECL(os_workgroup_parallel, os_workgroup, WorkGroupParallel);

/*!
 * @function os_workgroup_parallel_create
 *
 * @abstract
 * Creates an os_workgroup_t which tracks a parallel workload.
 * A newly created os_workgroup_interval_t has no initial member threads -
 * in particular the creating thread does not join the os_workgroup_parallel_t
 * implicitly.
 *
 * See also os_workgroup_max_parallel_threads().
 *
 * @param name
 * A client specified string for labelling the workgroup. This parameter is
 * optional and can be NULL.
 *
 * @param attr
 * The requested set of workgroup attributes. NULL is to be specified for the
 * default set of attributes.
 */
API_AVAILABLE(macos(11.0), ios(14.0), tvos(14.0), watchos(7.0))
OS_WORKGROUP_EXPORT OS_WORKGROUP_RETURNS_RETAINED
OS_SWIFT_NAME(WorkGroupParallel.init(__name:attr:))
os_workgroup_parallel_t _Nullable
os_workgroup_parallel_create(const char *OS_WORKGROUP_UNSAFE_INDEXABLE _Nullable,
	os_workgroup_attr_t _Nullable attr);

OS_WORKGROUP_ASSUME_ABI_SINGLE_END
OS_WORKGROUP_ASSUME_NONNULL_END

__END_DECLS

#endif /* __OS_WORKGROUP_PARALLEL__ */
