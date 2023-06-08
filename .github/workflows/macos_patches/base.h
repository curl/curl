/*
 * Copyright (c) 2008-2012 Apple Inc. All rights reserved.
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

#ifndef __DISPATCH_BASE__
#define __DISPATCH_BASE__

#ifndef __DISPATCH_INDIRECT__
#error "Please #include <dispatch/dispatch.h> instead of this file directly."
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif
#ifndef __has_include
#define __has_include(x) 0
#endif
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif
#ifndef __has_extension
#define __has_extension(x) 0
#endif

#if __GNUC__
#define DISPATCH_NORETURN __attribute__((__noreturn__))
#define DISPATCH_NOTHROW __attribute__((__nothrow__))
#define DISPATCH_NONNULL1 __attribute__((__nonnull__(1)))
#define DISPATCH_NONNULL2 __attribute__((__nonnull__(2)))
#define DISPATCH_NONNULL3 __attribute__((__nonnull__(3)))
#define DISPATCH_NONNULL4 __attribute__((__nonnull__(4)))
#define DISPATCH_NONNULL5 __attribute__((__nonnull__(5)))
#define DISPATCH_NONNULL6 __attribute__((__nonnull__(6)))
#define DISPATCH_NONNULL7 __attribute__((__nonnull__(7)))
#if __clang__ && __clang_major__ < 3
// rdar://problem/6857843
#define DISPATCH_NONNULL_ALL
#else
#define DISPATCH_NONNULL_ALL __attribute__((__nonnull__))
#endif
#define DISPATCH_SENTINEL __attribute__((__sentinel__))
#define DISPATCH_PURE __attribute__((__pure__))
#define DISPATCH_CONST __attribute__((__const__))
#define DISPATCH_WARN_RESULT __attribute__((__warn_unused_result__))
#define DISPATCH_MALLOC __attribute__((__malloc__))
#define DISPATCH_ALWAYS_INLINE __attribute__((__always_inline__))
#define DISPATCH_UNAVAILABLE __attribute__((__unavailable__))
#define DISPATCH_UNAVAILABLE_MSG(msg) __attribute__((__unavailable__(msg)))
#elif defined(_MSC_VER)
#define DISPATCH_NORETURN __declspec(noreturn)
#define DISPATCH_NOTHROW __declspec(nothrow)
#define DISPATCH_NONNULL1
#define DISPATCH_NONNULL2
#define DISPATCH_NONNULL3
#define DISPATCH_NONNULL4
#define DISPATCH_NONNULL5
#define DISPATCH_NONNULL6
#define DISPATCH_NONNULL7
#define DISPATCH_NONNULL_ALL
#define DISPATCH_SENTINEL
#define DISPATCH_PURE
#define DISPATCH_CONST
#if (_MSC_VER >= 1700)
#define DISPATCH_WARN_RESULT _Check_return_
#else
#define DISPATCH_WARN_RESULT
#endif
#define DISPATCH_MALLOC
#define DISPATCH_ALWAYS_INLINE __forceinline
#define DISPATCH_UNAVAILABLE
#define DISPATCH_UNAVAILABLE_MSG(msg)
#else
/*! @parseOnly */
#define DISPATCH_NORETURN
/*! @parseOnly */
#define DISPATCH_NOTHROW
/*! @parseOnly */
#define DISPATCH_NONNULL1
/*! @parseOnly */
#define DISPATCH_NONNULL2
/*! @parseOnly */
#define DISPATCH_NONNULL3
/*! @parseOnly */
#define DISPATCH_NONNULL4
/*! @parseOnly */
#define DISPATCH_NONNULL5
/*! @parseOnly */
#define DISPATCH_NONNULL6
/*! @parseOnly */
#define DISPATCH_NONNULL7
/*! @parseOnly */
#define DISPATCH_NONNULL_ALL
/*! @parseOnly */
#define DISPATCH_SENTINEL
/*! @parseOnly */
#define DISPATCH_PURE
/*! @parseOnly */
#define DISPATCH_CONST
/*! @parseOnly */
#define DISPATCH_WARN_RESULT
/*! @parseOnly */
#define DISPATCH_MALLOC
/*! @parseOnly */
#define DISPATCH_ALWAYS_INLINE
/*! @parseOnly */
#define DISPATCH_UNAVAILABLE
/*! @parseOnly */
#define DISPATCH_UNAVAILABLE_MSG(msg)
#endif

#if defined(__cplusplus)
# if __cplusplus >= 201703L
#  define DISPATCH_FALLTHROUGH [[fallthrough]]
# elif __cplusplus >= 201103L
#  if defined(__clang__)
#   define DISPATCH_FALLTHROUGH [[clang::fallthrough]]
#  elif defined(__GNUC__) && __GNUC__ >= 7
#   define DISPATCH_FALLTHROUGH [[gnu::fallthrough]]
#  else
#   define DISPATCH_FALLTHROUGH
#  endif
# else
#  define DISPATCH_FALLTHROUGH
# endif
#elif defined(__GNUC__) && __GNUC__ >= 7
# define DISPATCH_FALLTHROUGH __attribute__((__fallthrough__))
#elif defined(__clang__)
# if __has_attribute(fallthrough) && __clang_major__ >= 5
#  define DISPATCH_FALLTHROUGH __attribute__((__fallthrough__))
# else
#  define DISPATCH_FALLTHROUGH
# endif
#else
# define DISPATCH_FALLTHROUGH
#endif


#define DISPATCH_LINUX_UNAVAILABLE()

#ifdef __FreeBSD__
#define DISPATCH_FREEBSD_UNAVAILABLE() \
		DISPATCH_UNAVAILABLE_MSG( \
		"This interface is unavailable on FreeBSD systems")
#else
#define DISPATCH_FREEBSD_UNAVAILABLE()
#endif

#ifndef DISPATCH_ALIAS_V2
#if TARGET_OS_MAC
#define DISPATCH_ALIAS_V2(sym)	 __asm__("_" #sym "$V2")
#else
#define DISPATCH_ALIAS_V2(sym)
#endif
#endif

#if defined(_WIN32)
#if defined(__cplusplus)
#define DISPATCH_EXPORT extern "C" __declspec(dllimport)
#else
#define DISPATCH_EXPORT extern __declspec(dllimport)
#endif
#elif __GNUC__
#define DISPATCH_EXPORT extern __attribute__((visibility("default")))
#else
#define DISPATCH_EXPORT extern
#endif

#if __GNUC__
#define DISPATCH_INLINE static __inline__
#else
#define DISPATCH_INLINE static inline
#endif

#if __GNUC__
#define DISPATCH_EXPECT(x, v) __builtin_expect((x), (v))
#define dispatch_compiler_barrier()  __asm__ __volatile__("" ::: "memory")
#else
#define DISPATCH_EXPECT(x, v) (x)
#define dispatch_compiler_barrier()  do { } while (0)
#endif

#if __has_attribute(not_tail_called)
#define DISPATCH_NOT_TAIL_CALLED __attribute__((__not_tail_called__))
#else
#define DISPATCH_NOT_TAIL_CALLED
#endif

#if __has_builtin(__builtin_assume)
#define DISPATCH_COMPILER_CAN_ASSUME(expr) __builtin_assume(expr)
#else
#define DISPATCH_COMPILER_CAN_ASSUME(expr) ((void)(expr))
#endif

#if __has_attribute(noescape)
#define DISPATCH_NOESCAPE __attribute__((__noescape__))
#else
#define DISPATCH_NOESCAPE
#endif

#if __has_attribute(cold)
#define DISPATCH_COLD __attribute__((__cold__))
#else
#define DISPATCH_COLD
#endif

#if __has_feature(assume_nonnull)
#define DISPATCH_ASSUME_NONNULL_BEGIN _Pragma("clang assume_nonnull begin")
#define DISPATCH_ASSUME_NONNULL_END   _Pragma("clang assume_nonnull end")
#else
#define DISPATCH_ASSUME_NONNULL_BEGIN
#define DISPATCH_ASSUME_NONNULL_END
#endif

#if __has_feature(bounds_attributes)
#define DISPATCH_ASSUME_ABI_SINGLE_BEGIN	_Pragma("clang abi_ptr_attr set(single)")
#define DISPATCH_ASSUME_ABI_SINGLE_END		_Pragma("clang abi_ptr_attr set(unsafe_indexable)")
#define DISPATCH_UNSAFE_INDEXABLE __attribute__((__unsafe_indexable__))
#define DISPATCH_COUNTED_BY(X) __attribute__((__counted_by__(X)))
#define DISPATCH_SIZED_BY(X) __attribute__((__sized_by__(X)))
#else
#define DISPATCH_ASSUME_ABI_SINGLE_BEGIN
#define DISPATCH_ASSUME_ABI_SINGLE_END
#define DISPATCH_UNSAFE_INDEXABLE
#define DISPATCH_COUNTED_BY(X)
#define DISPATCH_SIZED_BY(X)
#endif

#if !__has_feature(nullability)
#ifndef _Nullable
#define _Nullable
#endif
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Null_unspecified
#define _Null_unspecified
#endif
#endif

#ifndef DISPATCH_RETURNS_RETAINED_BLOCK
#if __has_attribute(ns_returns_retained)
#define DISPATCH_RETURNS_RETAINED_BLOCK __attribute__((__ns_returns_retained__))
#else
#define DISPATCH_RETURNS_RETAINED_BLOCK
#endif
#endif

#if __has_attribute(enum_extensibility)
#define __DISPATCH_ENUM_ATTR __attribute__((__enum_extensibility__(open)))
#define __DISPATCH_ENUM_ATTR_CLOSED __attribute__((__enum_extensibility__(closed)))
#else
#define __DISPATCH_ENUM_ATTR
#define __DISPATCH_ENUM_ATTR_CLOSED
#endif // __has_attribute(enum_extensibility)

#if __has_attribute(flag_enum)
#define __DISPATCH_OPTIONS_ATTR __attribute__((__flag_enum__))
#else
#define __DISPATCH_OPTIONS_ATTR
#endif // __has_attribute(flag_enum)


#if __has_feature(objc_fixed_enum) || __has_extension(cxx_strong_enums) || \
		__has_extension(cxx_fixed_enum) || defined(_WIN32)
#define DISPATCH_ENUM(name, type, ...) \
		typedef enum : type { __VA_ARGS__ } __DISPATCH_ENUM_ATTR name##_t
#define DISPATCH_OPTIONS(name, type, ...) \
		typedef enum : type { __VA_ARGS__ } __DISPATCH_OPTIONS_ATTR __DISPATCH_ENUM_ATTR name##_t
#else
#define DISPATCH_ENUM(name, type, ...) \
		enum { __VA_ARGS__ } __DISPATCH_ENUM_ATTR; typedef type name##_t
#define DISPATCH_OPTIONS(name, type, ...) \
		enum { __VA_ARGS__ } __DISPATCH_OPTIONS_ATTR __DISPATCH_ENUM_ATTR; typedef type name##_t
#endif // __has_feature(objc_fixed_enum) ...



#if __has_feature(enumerator_attributes)
#define DISPATCH_ENUM_API_AVAILABLE(...) API_AVAILABLE(__VA_ARGS__)
#define DISPATCH_ENUM_API_DEPRECATED(...) API_DEPRECATED(__VA_ARGS__)
#define DISPATCH_ENUM_API_DEPRECATED_WITH_REPLACEMENT(...) \
		API_DEPRECATED_WITH_REPLACEMENT(__VA_ARGS__)
#else
#define DISPATCH_ENUM_API_AVAILABLE(...)
#define DISPATCH_ENUM_API_DEPRECATED(...)
#define DISPATCH_ENUM_API_DEPRECATED_WITH_REPLACEMENT(...)
#endif

#ifdef __swift__
#define DISPATCH_SWIFT3_OVERLAY 1
#else // __swift__
#define DISPATCH_SWIFT3_OVERLAY 0
#endif // __swift__

#if __has_feature(attribute_availability_swift)
#define DISPATCH_SWIFT_UNAVAILABLE(_msg) \
		__attribute__((__availability__(swift, unavailable, message=_msg)))
#else
#define DISPATCH_SWIFT_UNAVAILABLE(_msg)
#endif

#if DISPATCH_SWIFT3_OVERLAY
#define DISPATCH_SWIFT3_UNAVAILABLE(_msg) DISPATCH_SWIFT_UNAVAILABLE(_msg)
#else
#define DISPATCH_SWIFT3_UNAVAILABLE(_msg)
#endif

#if __has_attribute(swift_private)
#define DISPATCH_REFINED_FOR_SWIFT __attribute__((__swift_private__))
#else
#define DISPATCH_REFINED_FOR_SWIFT
#endif

#if __has_attribute(swift_name)
#define DISPATCH_SWIFT_NAME(_name) __attribute__((__swift_name__(#_name)))
#else
#define DISPATCH_SWIFT_NAME(_name)
#endif

#ifndef __cplusplus
#define DISPATCH_TRANSPARENT_UNION __attribute__((__transparent_union__))
#else
#define DISPATCH_TRANSPARENT_UNION
#endif

DISPATCH_ASSUME_ABI_SINGLE_BEGIN

;typedef void (*dispatch_function_t)(void *_Nullable);

DISPATCH_ASSUME_ABI_SINGLE_END

#endif
