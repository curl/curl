#ifndef __OS_WORKGROUP_BASE__
#define __OS_WORKGROUP_BASE__

#ifndef __OS_WORKGROUP_INDIRECT__
#error "Please #include <os/workgroup.h> instead of this file directly."
#endif

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <mach/port.h>

#include <Availability.h>
#include <os/base.h>
#include <os/object.h>
#include <os/clock.h>

#if __has_feature(assume_nonnull)
#define OS_WORKGROUP_ASSUME_NONNULL_BEGIN _Pragma("clang assume_nonnull begin")
#define OS_WORKGROUP_ASSUME_NONNULL_END   _Pragma("clang assume_nonnull end")
#else
#define OS_WORKGROUP_ASSUME_NONNULL_BEGIN
#define OS_WORKGROUP_ASSUME_NONNULL_END
#endif
#define OS_WORKGROUP_WARN_RESULT __attribute__((__warn_unused_result__))
#define OS_WORKGROUP_EXPORT OS_EXPORT
#define OS_WORKGROUP_RETURNS_RETAINED OS_OBJECT_RETURNS_RETAINED
#define OS_WORKGROUP_ASSUME_ABI_SINGLE_BEGIN OS_ASSUME_PTR_ABI_SINGLE_BEGIN
#define OS_WORKGROUP_ASSUME_ABI_SINGLE_END OS_ASSUME_PTR_ABI_SINGLE_END
#define OS_WORKGROUP_UNSAFE_INDEXABLE OS_UNSAFE_INDEXABLE

#define OS_WORKGROUP_DECL(name, swift_name) \
	OS_SWIFT_NAME(swift_name) \
	OS_OBJECT_SHOW_CLASS(name, OS_OBJECT_CLASS(object))

#if OS_OBJECT_USE_OBJC
#define OS_WORKGROUP_SUBCLASS_DECL_PROTO(name, swift_name, ...) \
	OS_SWIFT_NAME(swift_name) \
	OS_OBJECT_DECL_PROTOCOL(name ## __VA_ARGS__ )
#else
#define OS_WORKGROUP_SUBCLASS_DECL_PROTO(name, swift_name, ...)
#endif

#define OS_WORKGROUP_SUBCLASS_DECL(name, super, swift_name, ...) \
	OS_SWIFT_NAME(swift_name) \
	OS_OBJECT_SHOW_SUBCLASS(name, super, name, ## __VA_ARGS__)

#if defined(__LP64__)
#define __OS_WORKGROUP_ATTR_SIZE__ 60
#define __OS_WORKGROUP_INTERVAL_DATA_SIZE__ 56
#define __OS_WORKGROUP_JOIN_TOKEN_SIZE__ 36
#else
#define __OS_WORKGROUP_ATTR_SIZE__ 60
#define __OS_WORKGROUP_INTERVAL_DATA_SIZE__ 56
#define __OS_WORKGROUP_JOIN_TOKEN_SIZE__ 28
#endif

#define _OS_WORKGROUP_ATTR_SIG_DEFAULT_INIT 0x2FA863B4
#define _OS_WORKGROUP_ATTR_SIG_EMPTY_INIT 0x2FA863C4

OS_WORKGROUP_ASSUME_ABI_SINGLE_BEGIN

;struct OS_REFINED_FOR_SWIFT os_workgroup_attr_opaque_s {
	uint32_t sig;
	char opaque[__OS_WORKGROUP_ATTR_SIZE__];
};

#define _OS_WORKGROUP_INTERVAL_DATA_SIG_INIT 0x52A74C4D
struct OS_REFINED_FOR_SWIFT os_workgroup_interval_data_opaque_s {
	uint32_t sig;
	char opaque[__OS_WORKGROUP_INTERVAL_DATA_SIZE__];
};

struct OS_REFINED_FOR_SWIFT os_workgroup_join_token_opaque_s {
	uint32_t sig;
	char opaque[__OS_WORKGROUP_JOIN_TOKEN_SIZE__];
};

#endif /* __OS_WORKGROUP_BASE__ */
