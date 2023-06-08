/*
 * Copyright (c) 2011-2014 Apple Inc. All rights reserved.
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

#ifndef __OS_OBJECT__
#define __OS_OBJECT__

#ifdef __APPLE__
#include <Availability.h>
#include <os/availability.h>
#include <TargetConditionals.h>
#include <os/base.h>
#elif defined(_WIN32)
#include <os/generic_win_base.h>
#elif defined(__unix__)
#include <os/generic_unix_base.h>
#endif

/*!
 * @header
 *
 * @preprocinfo
 * By default, libSystem objects such as GCD and XPC objects are declared as
 * Objective-C types when building with an Objective-C compiler. This allows
 * them to participate in ARC, in RR management by the Blocks runtime and in
 * leaks checking by the static analyzer, and enables them to be added to Cocoa
 * collections.
 *
 * NOTE: this requires explicit cancellation of dispatch sources and xpc
 *       connections whose handler blocks capture the source/connection object,
 *       resp. ensuring that such captures do not form retain cycles (e.g. by
 *       declaring the source as __weak).
 *
 * To opt-out of this default behavior, add -DOS_OBJECT_USE_OBJC=0 to your
 * compiler flags.
 *
 * This mode requires a platform with the modern Objective-C runtime, the
 * Objective-C GC compiler option to be disabled, and at least a Mac OS X 10.8
 * or iOS 6.0 deployment target.
 */

#define OS_OBJECT_ASSUME_ABI_SINGLE_BEGIN	OS_ASSUME_PTR_ABI_SINGLE_BEGIN
#define OS_OBJECT_ASSUME_ABI_SINGLE_END		OS_ASSUME_PTR_ABI_SINGLE_END

#ifndef OS_OBJECT_HAVE_OBJC_SUPPORT
#if !defined(__OBJC__) || defined(__OBJC_GC__)
#  define OS_OBJECT_HAVE_OBJC_SUPPORT 0
#elif !defined(TARGET_OS_MAC) || !TARGET_OS_MAC
#  define OS_OBJECT_HAVE_OBJC_SUPPORT 0
#elif TARGET_OS_IOS && __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_6_0
#  define OS_OBJECT_HAVE_OBJC_SUPPORT 0
#elif TARGET_OS_MAC && !TARGET_OS_IPHONE
#  if __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_8
#  define OS_OBJECT_HAVE_OBJC_SUPPORT 0
#  elif defined(__i386__) && __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_12
#  define OS_OBJECT_HAVE_OBJC_SUPPORT 0
#  else
#  define OS_OBJECT_HAVE_OBJC_SUPPORT 1
#  endif
#else
#  define OS_OBJECT_HAVE_OBJC_SUPPORT 1
#endif
#endif // OS_OBJECT_HAVE_OBJC_SUPPORT

#if OS_OBJECT_HAVE_OBJC_SUPPORT
#if defined(__swift__) && __swift__ && !OS_OBJECT_USE_OBJC
#define OS_OBJECT_USE_OBJC 1
#endif
#ifndef OS_OBJECT_USE_OBJC
#define OS_OBJECT_USE_OBJC 1
#endif
#elif defined(OS_OBJECT_USE_OBJC) && OS_OBJECT_USE_OBJC
/* Unsupported platform for OS_OBJECT_USE_OBJC=1 */
#undef OS_OBJECT_USE_OBJC
#define OS_OBJECT_USE_OBJC 0
#else
#define OS_OBJECT_USE_OBJC 0
#endif

#ifndef OS_OBJECT_SWIFT3
#ifdef __swift__
#define OS_OBJECT_SWIFT3 1
#else // __swift__
#define OS_OBJECT_SWIFT3 0
#endif // __swift__
#endif // OS_OBJECT_SWIFT3

#if __has_feature(assume_nonnull)
#define OS_OBJECT_ASSUME_NONNULL_BEGIN _Pragma("clang assume_nonnull begin")
#define OS_OBJECT_ASSUME_NONNULL_END   _Pragma("clang assume_nonnull end")
#else
#define OS_OBJECT_ASSUME_NONNULL_BEGIN
#define OS_OBJECT_ASSUME_NONNULL_END
#endif
#define OS_OBJECT_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))

#if OS_OBJECT_USE_OBJC
#import <objc/NSObject.h>
#if __has_attribute(objc_independent_class)
#define OS_OBJC_INDEPENDENT_CLASS __attribute__((objc_independent_class))
#endif // __has_attribute(objc_independent_class)
#ifndef OS_OBJC_INDEPENDENT_CLASS
#define OS_OBJC_INDEPENDENT_CLASS
#endif
#define OS_OBJECT_CLASS(name) OS_##name
#define OS_OBJECT_DECL_PROTOCOL(name, ...) \
		@protocol OS_OBJECT_CLASS(name) __VA_ARGS__ \
		@end
#define OS_OBJECT_CLASS_IMPLEMENTS_PROTOCOL_IMPL(name, proto) \
		@interface name () <proto> \
		@end
#define OS_OBJECT_CLASS_IMPLEMENTS_PROTOCOL(name, proto) \
		OS_OBJECT_CLASS_IMPLEMENTS_PROTOCOL_IMPL( \
				OS_OBJECT_CLASS(name), OS_OBJECT_CLASS(proto))
#define OS_OBJECT_DECL_IMPL(name, adhere, ...) \
		OS_OBJECT_DECL_PROTOCOL(name, __VA_ARGS__) \
		typedef adhere<OS_OBJECT_CLASS(name)> \
				* OS_OBJC_INDEPENDENT_CLASS name##_t
#define OS_OBJECT_DECL_BASE(name, ...) \
		@interface OS_OBJECT_CLASS(name) : __VA_ARGS__ \
		- (instancetype)init OS_SWIFT_UNAVAILABLE("Unavailable in Swift"); \
		@end
#define OS_OBJECT_DECL_IMPL_CLASS(name, ...) \
		OS_OBJECT_DECL_BASE(name, ## __VA_ARGS__) \
		typedef OS_OBJECT_CLASS(name) \
				* OS_OBJC_INDEPENDENT_CLASS name##_t
#define OS_OBJECT_DECL(name, ...) \
		OS_OBJECT_DECL_IMPL(name, NSObject, <NSObject>)
#define OS_OBJECT_DECL_SUBCLASS(name, super) \
		OS_OBJECT_DECL_IMPL(name, NSObject, <OS_OBJECT_CLASS(super)>)
#if __has_attribute(ns_returns_retained)
#define OS_OBJECT_RETURNS_RETAINED __attribute__((__ns_returns_retained__))
#else
#define OS_OBJECT_RETURNS_RETAINED
#endif
#if __has_attribute(ns_consumed)
#define OS_OBJECT_CONSUMED __attribute__((__ns_consumed__))
#else
#define OS_OBJECT_CONSUMED
#endif
#if __has_feature(objc_arc)
#define OS_OBJECT_BRIDGE __bridge
#define OS_WARN_RESULT_NEEDS_RELEASE
#else
#define OS_OBJECT_BRIDGE
#define OS_WARN_RESULT_NEEDS_RELEASE OS_WARN_RESULT
#endif


#if __has_attribute(objc_runtime_visible) && \
		((defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
		__MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_12) || \
		(defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && \
		!defined(__TV_OS_VERSION_MIN_REQUIRED) && \
		!defined(__WATCH_OS_VERSION_MIN_REQUIRED) && \
		__IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_10_0) || \
		(defined(__TV_OS_VERSION_MIN_REQUIRED) && \
		__TV_OS_VERSION_MIN_REQUIRED < __TVOS_10_0) || \
		(defined(__WATCH_OS_VERSION_MIN_REQUIRED) && \
		__WATCH_OS_VERSION_MIN_REQUIRED < __WATCHOS_3_0))
/*
 * To provide backward deployment of ObjC objects in Swift on pre-10.12
 * SDKs, OS_object classes can be marked as OS_OBJECT_OBJC_RUNTIME_VISIBLE.
 * When compiling with a deployment target earlier than OS X 10.12 (iOS 10.0,
 * tvOS 10.0, watchOS 3.0) the Swift compiler will only refer to this type at
 * runtime (using the ObjC runtime).
 */
#define OS_OBJECT_OBJC_RUNTIME_VISIBLE __attribute__((objc_runtime_visible))
#else
#define OS_OBJECT_OBJC_RUNTIME_VISIBLE
#endif
#ifndef OS_OBJECT_USE_OBJC_RETAIN_RELEASE
#if defined(__clang_analyzer__)
#define OS_OBJECT_USE_OBJC_RETAIN_RELEASE 1
#elif __has_feature(objc_arc) && !OS_OBJECT_SWIFT3
#define OS_OBJECT_USE_OBJC_RETAIN_RELEASE 1
#else
#define OS_OBJECT_USE_OBJC_RETAIN_RELEASE 0
#endif
#endif
#if OS_OBJECT_SWIFT3
#define OS_OBJECT_DECL_SWIFT(name) \
		OS_EXPORT OS_OBJECT_OBJC_RUNTIME_VISIBLE \
		OS_OBJECT_DECL_IMPL_CLASS(name, NSObject)
#define OS_OBJECT_DECL_SUBCLASS_SWIFT(name, super) \
		OS_EXPORT OS_OBJECT_OBJC_RUNTIME_VISIBLE \
		OS_OBJECT_DECL_IMPL_CLASS(name, OS_OBJECT_CLASS(super))
#endif // OS_OBJECT_SWIFT3
OS_EXPORT OS_OBJECT_OBJC_RUNTIME_VISIBLE
OS_OBJECT_DECL_BASE(object, NSObject);
#else
/*! @parseOnly */
#define OS_OBJECT_RETURNS_RETAINED
/*! @parseOnly */
#define OS_OBJECT_CONSUMED
/*! @parseOnly */
#define OS_OBJECT_BRIDGE
/*! @parseOnly */
#define OS_WARN_RESULT_NEEDS_RELEASE OS_WARN_RESULT
/*! @parseOnly */
#define OS_OBJECT_OBJC_RUNTIME_VISIBLE
#define OS_OBJECT_USE_OBJC_RETAIN_RELEASE 0
#endif

#if OS_OBJECT_SWIFT3
#define OS_OBJECT_DECL_CLASS(name) \
		OS_OBJECT_DECL_SUBCLASS_SWIFT(name, object)
#elif OS_OBJECT_USE_OBJC
#define OS_OBJECT_DECL_CLASS(name) \
		OS_OBJECT_DECL(name)
#else
#define OS_OBJECT_DECL_CLASS(name) \
		typedef struct name##_s *name##_t
#endif

#if OS_OBJECT_USE_OBJC
/* Declares a class of the specific name and exposes the interface and typedefs
 * name##_t to the pointer to the class */
#define OS_OBJECT_SHOW_CLASS(name, ...) \
		OS_EXPORT OS_OBJECT_OBJC_RUNTIME_VISIBLE \
		OS_OBJECT_DECL_IMPL_CLASS(name, ## __VA_ARGS__ )
/* Declares a subclass of the same name, and
 * subclass adheres to protocol specified. Typedefs baseclass<proto> * to subclass##_t */
#define OS_OBJECT_SHOW_SUBCLASS(subclass_name, super, proto_name) \
		OS_EXPORT OS_OBJECT_OBJC_RUNTIME_VISIBLE \
		OS_OBJECT_DECL_BASE(subclass_name, OS_OBJECT_CLASS(super)<OS_OBJECT_CLASS(proto_name)>); \
		typedef OS_OBJECT_CLASS(super)<OS_OBJECT_CLASS(proto_name)> \
				* OS_OBJC_INDEPENDENT_CLASS subclass_name##_t
#else /* Plain C */
#define OS_OBJECT_DECL_PROTOCOL(name, ...)
#define OS_OBJECT_SHOW_CLASS(name, ...) \
		typedef struct name##_s *name##_t
#define OS_OBJECT_SHOW_SUBCLASS(name, super, ...) \
		typedef super##_t name##_t
#endif

#define OS_OBJECT_GLOBAL_OBJECT(type, object) ((OS_OBJECT_BRIDGE type)&(object))

__BEGIN_DECLS
OS_OBJECT_ASSUME_ABI_SINGLE_BEGIN

/*!
 * @function os_retain
 *
 * @abstract
 * Increment the reference count of an os_object.
 *
 * @discussion
 * On a platform with the modern Objective-C runtime this is exactly equivalent
 * to sending the object the -[retain] message.
 *
 * @param object
 * The object to retain.
 *
 * @result
 * The retained object.
 */
API_AVAILABLE(macos(10.10), ios(8.0))
;OS_EXPORT OS_SWIFT_UNAVAILABLE("Can't be used with ARC")
void*
os_retain(void *object);
#if OS_OBJECT_USE_OBJC
#undef os_retain
#define os_retain(object) [object retain]
#endif

/*!
 * @function os_release
 *
 * @abstract
 * Decrement the reference count of a os_object.
 *
 * @discussion
 * On a platform with the modern Objective-C runtime this is exactly equivalent
 * to sending the object the -[release] message.
 *
 * @param object
 * The object to release.
 */
API_AVAILABLE(macos(10.10), ios(8.0))
OS_EXPORT
void OS_SWIFT_UNAVAILABLE("Can't be used with ARC")
os_release(void *object);
#if OS_OBJECT_USE_OBJC
#undef os_release
#define os_release(object) [object release]
#endif

OS_OBJECT_ASSUME_ABI_SINGLE_END
__END_DECLS

#endif
