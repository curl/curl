#ifndef __OS_CLOCK__
#define __OS_CLOCK__

#include <os/base.h>
#include <stdint.h>

/*
 * @typedef os_clockid_t
 *
 * @abstract
 * Describes the kind of clock that the workgroup timestamp parameters are
 * specified in
 */
;OS_ENUM(os_clockid, uint32_t,
		OS_CLOCK_MACH_ABSOLUTE_TIME = 32,
);

#endif /* __OS_CLOCK__ */
