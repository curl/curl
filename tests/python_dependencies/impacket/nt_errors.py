# Copyright (c) 2003-2016 CORE Security Technologies)
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   NT STATUS Errors from [MS-ERREF]. Ideally all the files
#   should grab the error codes from here (big ToDo) 
#

ERROR_MESSAGES = {
        0x00000000: ("STATUS_SUCCESS","The operation completed successfully."),
        0x00000001: ("STATUS_WAIT_1","The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state."),
        0x00000002: ("STATUS_WAIT_2","The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state."),
        0x00000003: ("STATUS_WAIT_3","The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state."),
        0x0000003F: ("STATUS_WAIT_63","The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state."),
        0x00000080: ("STATUS_ABANDONED","The caller attempted to wait for a mutex that has been abandoned."),
        0x00000080: ("STATUS_ABANDONED_WAIT_0","The caller attempted to wait for a mutex that has been abandoned."),
        0x000000BF: ("STATUS_ABANDONED_WAIT_63","The caller attempted to wait for a mutex that has been abandoned."),
        0x000000C0: ("STATUS_USER_APC","A user-mode APC was delivered before the given Interval expired."),
        0x00000101: ("STATUS_ALERTED","The delay completed because the thread was alerted."),
        0x00000102: ("STATUS_TIMEOUT","The given Timeout interval expired."),
        0x00000103: ("STATUS_PENDING","The operation that was requested is pending completion."),
        0x00000104: ("STATUS_REPARSE","A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link."),
        0x00000105: ("STATUS_MORE_ENTRIES","Returned by enumeration APIs to indicate more information is available to successive calls."),
        0x00000106: ("STATUS_NOT_ALL_ASSIGNED","Indicates not all privileges or groups that are referenced are assigned to the caller. This allows, for example, all privileges to be disabled without having to know exactly which privileges are assigned."),
        0x00000107: ("STATUS_SOME_NOT_MAPPED","Some of the information to be translated has not been translated."),
        0x00000108: ("STATUS_OPLOCK_BREAK_IN_PROGRESS","An open/create operation completed while an opportunistic lock (oplock) break is underway."),
        0x00000109: ("STATUS_VOLUME_MOUNTED","A new volume has been mounted by a file system."),
        0x0000010A: ("STATUS_RXACT_COMMITTED","This success level status indicates that the transaction state already exists for the registry subtree but that a transaction commit was previously aborted. The commit has now been completed."),
        0x0000010B: ("STATUS_NOTIFY_CLEANUP","Indicates that a notify change request has been completed due to closing the handle that made the notify change request."),
        0x0000010C: ("STATUS_NOTIFY_ENUM_DIR","Indicates that a notify change request is being completed and that the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes."),
        0x0000010D: ("STATUS_NO_QUOTAS_FOR_ACCOUNT","{No Quotas} No system quota limits are specifically set for this account."),
        0x0000010E: ("STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED","{Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed. The computer WAS able to connect on a secondary transport."),
        0x00000110: ("STATUS_PAGE_FAULT_TRANSITION","The page fault was a transition fault."),
        0x00000111: ("STATUS_PAGE_FAULT_DEMAND_ZERO","The page fault was a demand zero fault."),
        0x00000112: ("STATUS_PAGE_FAULT_COPY_ON_WRITE","The page fault was a demand zero fault."),
        0x00000113: ("STATUS_PAGE_FAULT_GUARD_PAGE","The page fault was a demand zero fault."),
        0x00000114: ("STATUS_PAGE_FAULT_PAGING_FILE","The page fault was satisfied by reading from a secondary storage device."),
        0x00000115: ("STATUS_CACHE_PAGE_LOCKED","The cached page was locked during operation."),
        0x00000116: ("STATUS_CRASH_DUMP","The crash dump exists in a paging file."),
        0x00000117: ("STATUS_BUFFER_ALL_ZEROS","The specified buffer contains all zeros."),
        0x00000118: ("STATUS_REPARSE_OBJECT","A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link."),
        0x00000119: ("STATUS_RESOURCE_REQUIREMENTS_CHANGED","The device has succeeded a query-stop and its resource requirements have changed."),
        0x00000120: ("STATUS_TRANSLATION_COMPLETE","The translator has translated these resources into the global space and no additional translations should be performed."),
        0x00000121: ("STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY","The directory service evaluated group memberships locally, because it was unable to contact a global catalog server."),
        0x00000122: ("STATUS_NOTHING_TO_TERMINATE","A process being terminated has no threads to terminate."),
        0x00000123: ("STATUS_PROCESS_NOT_IN_JOB","The specified process is not part of a job."),
        0x00000124: ("STATUS_PROCESS_IN_JOB","The specified process is part of a job."),
        0x00000125: ("STATUS_VOLSNAP_HIBERNATE_READY","{Volume Shadow Copy Service} The system is now ready for hibernation."),
        0x00000126: ("STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY","A file system or file system filter driver has successfully completed an FsFilter operation."),
        0x00000127: ("STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED","The specified interrupt vector was already connected."),
        0x00000128: ("STATUS_INTERRUPT_STILL_CONNECTED","The specified interrupt vector is still connected."),
        0x00000129: ("STATUS_PROCESS_CLONED","The current process is a cloned process."),
        0x0000012A: ("STATUS_FILE_LOCKED_WITH_ONLY_READERS","The file was locked and all users of the file can only read."),
        0x0000012B: ("STATUS_FILE_LOCKED_WITH_WRITERS","The file was locked and at least one user of the file can write."),
        0x00000202: ("STATUS_RESOURCEMANAGER_READ_ONLY","The specified ResourceManager made no changes or updates to the resource under this transaction."),
        0x00000367: ("STATUS_WAIT_FOR_OPLOCK","An operation is blocked and waiting for an oplock."),
        0x00010001: ("DBG_EXCEPTION_HANDLED","Debugger handled the exception."),
        0x00010002: ("DBG_CONTINUE","The debugger continued."),
        0x001C0001: ("STATUS_FLT_IO_COMPLETE","The IO was completed by a filter."),
        0xC0000467: ("STATUS_FILE_NOT_AVAILABLE","The file is temporarily unavailable."),
        0xC0000721: ("STATUS_CALLBACK_RETURNED_THREAD_AFFINITY","A threadpool worker thread entered a callback at thread affinity %p and exited at affinity %p.  This is unexpected, indicating that the callback missed restoring the priority."),
        0x40000000: ("STATUS_OBJECT_NAME_EXISTS","{Object Exists} An attempt was made to create an object but the object name already exists."),
        0x40000001: ("STATUS_THREAD_WAS_SUSPENDED","{Thread Suspended} A thread termination occurred while the thread was suspended. The thread resumed, and termination proceeded."),
        0x40000002: ("STATUS_WORKING_SET_LIMIT_RANGE","{Working Set Range Error} An attempt was made to set the working set minimum or maximum to values that are outside the allowable range."),
        0x40000003: ("STATUS_IMAGE_NOT_AT_BASE","{Image Relocated} An image file could not be mapped at the address that is specified in the image file. Local fixes must be performed on this image."),
        0x40000004: ("STATUS_RXACT_STATE_CREATED","This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created."),
        0x40000005: ("STATUS_SEGMENT_NOTIFICATION","{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. An exception is raised so that a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments."),
        0x40000006: ("STATUS_LOCAL_USER_SESSION_KEY","{Local Session Key} A user session key was requested for a local remote procedure call (RPC) connection. The session key that is returned is a constant value and not unique to this connection."),
        0x40000007: ("STATUS_BAD_CURRENT_DIRECTORY","{Invalid Current Directory} The process cannot switch to the startup current directory %hs. Select OK to set the current directory to %hs, or select CANCEL to exit."),
        0x40000008: ("STATUS_SERIAL_MORE_WRITES","{Serial IOCTL Complete} A serial I/O operation was completed by another write to a serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)"),
        0x40000009: ("STATUS_REGISTRY_RECOVERED","{Registry Recovery} One of the files that contains the system registry data had to be recovered by using a log or alternate copy. The recovery was successful."),
        0x4000000A: ("STATUS_FT_READ_RECOVERY_FROM_BACKUP","{Redundant Read} To satisfy a read request, the Windows NT fault-tolerant file system successfully read the requested data from a redundant copy. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device."),
        0x4000000B: ("STATUS_FT_WRITE_RECOVERY","{Redundant Write} To satisfy a write request, the Windows NT fault-tolerant file system successfully wrote a redundant copy of the information. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device."),
        0x4000000C: ("STATUS_SERIAL_COUNTER_TIMEOUT","{Serial IOCTL Timeout} A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER had not reached zero.)"),
        0x4000000D: ("STATUS_NULL_LM_PASSWORD","{Password Too Complex} The Windows password is too complex to be converted to a LAN Manager password. The LAN Manager password that returned is a NULL string."),
        0x4000000E: ("STATUS_IMAGE_MACHINE_TYPE_MISMATCH","{Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load."),
        0x4000000F: ("STATUS_RECEIVE_PARTIAL","{Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later."),
        0x40000010: ("STATUS_RECEIVE_EXPEDITED","{Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system."),
        0x40000011: ("STATUS_RECEIVE_PARTIAL_EXPEDITED","{Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later."),
        0x40000012: ("STATUS_EVENT_DONE","{TDI Event Done} The TDI indication has completed successfully."),
        0x40000013: ("STATUS_EVENT_PENDING","{TDI Event Pending} The TDI indication has entered the pending state."),
        0x40000014: ("STATUS_CHECKING_FILE_SYSTEM","Checking file system on %wZ."),
        0x40000015: ("STATUS_FATAL_APP_EXIT","{Fatal Application Exit} %hs"),
        0x40000016: ("STATUS_PREDEFINED_HANDLE","The specified registry key is referenced by a predefined handle."),
        0x40000017: ("STATUS_WAS_UNLOCKED","{Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process."),
        0x40000018: ("STATUS_SERVICE_NOTIFICATION","%hs"),
        0x40000019: ("STATUS_WAS_LOCKED","{Page Locked} One of the pages to lock was already locked."),
        0x4000001A: ("STATUS_LOG_HARD_ERROR","Application popup: %1 : %2"),
        0x4000001B: ("STATUS_ALREADY_WIN32","A Win32 process already exists."),
        0x4000001C: ("STATUS_WX86_UNSIMULATE","An exception status code that is used by the Win32 x86 emulation subsystem."),
        0x4000001D: ("STATUS_WX86_CONTINUE","An exception status code that is used by the Win32 x86 emulation subsystem."),
        0x4000001E: ("STATUS_WX86_SINGLE_STEP","An exception status code that is used by the Win32 x86 emulation subsystem."),
        0x4000001F: ("STATUS_WX86_BREAKPOINT","An exception status code that is used by the Win32 x86 emulation subsystem."),
        0x40000020: ("STATUS_WX86_EXCEPTION_CONTINUE","An exception status code that is used by the Win32 x86 emulation subsystem."),
        0x40000021: ("STATUS_WX86_EXCEPTION_LASTCHANCE","An exception status code that is used by the Win32 x86 emulation subsystem."),
        0x40000022: ("STATUS_WX86_EXCEPTION_CHAIN","An exception status code that is used by the Win32 x86 emulation subsystem."),
        0x40000023: ("STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE","{Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine."),
        0x40000024: ("STATUS_NO_YIELD_PERFORMED","A yield execution was performed and no thread was available to run."),
        0x40000025: ("STATUS_TIMER_RESUME_IGNORED","The resume flag to a timer API was ignored."),
        0x40000026: ("STATUS_ARBITRATION_UNHANDLED","The arbiter has deferred arbitration of these resources to its parent."),
        0x40000027: ("STATUS_CARDBUS_NOT_SUPPORTED","The device has detected a CardBus card in its slot."),
        0x40000028: ("STATUS_WX86_CREATEWX86TIB","An exception status code that is used by the Win32 x86 emulation subsystem."),
        0x40000029: ("STATUS_MP_PROCESSOR_MISMATCH","The CPUs in this multiprocessor system are not all the same revision level. To use all processors, the operating system restricts itself to the features of the least capable processor in the system. If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported."),
        0x4000002A: ("STATUS_HIBERNATED","The system was put into hibernation."),
        0x4000002B: ("STATUS_RESUME_HIBERNATION","The system was resumed from hibernation."),
        0x4000002C: ("STATUS_FIRMWARE_UPDATED","Windows has detected that the system firmware (BIOS) was updated [previous firmware date = %2, current firmware date %3]."),
        0x4000002D: ("STATUS_DRIVERS_LEAKING_LOCKED_PAGES","A device driver is leaking locked I/O pages and is causing system degradation. The system has automatically enabled the tracking code to try and catch the culprit."),
        0x4000002E: ("STATUS_MESSAGE_RETRIEVED","The ALPC message being canceled has already been retrieved from the queue on the other side."),
        0x4000002F: ("STATUS_SYSTEM_POWERSTATE_TRANSITION","The system power state is transitioning from %2 to %3."),
        0x40000030: ("STATUS_ALPC_CHECK_COMPLETION_LIST","The receive operation was successful. Check the ALPC completion list for the received message."),
        0x40000031: ("STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION","The system power state is transitioning from %2 to %3 but could enter %4."),
        0x40000032: ("STATUS_ACCESS_AUDIT_BY_POLICY","Access to %1 is monitored by policy rule %2."),
        0x40000033: ("STATUS_ABANDON_HIBERFILE","A valid hibernation file has been invalidated and should be abandoned."),
        0x40000034: ("STATUS_BIZRULES_NOT_ENABLED","Business rule scripts are disabled for the calling application."),
        0x40000294: ("STATUS_WAKE_SYSTEM","The system has awoken."),
        0x40000370: ("STATUS_DS_SHUTTING_DOWN","The directory service is shutting down."),
        0x40010001: ("DBG_REPLY_LATER","Debugger will reply later."),
        0x40010002: ("DBG_UNABLE_TO_PROVIDE_HANDLE","Debugger cannot provide a handle."),
        0x40010003: ("DBG_TERMINATE_THREAD","Debugger terminated the thread."),
        0x40010004: ("DBG_TERMINATE_PROCESS","Debugger terminated the process."),
        0x40010005: ("DBG_CONTROL_C","Debugger obtained control of C."),
        0x40010006: ("DBG_PRINTEXCEPTION_C","Debugger printed an exception on control C."),
        0x40010007: ("DBG_RIPEXCEPTION","Debugger received a RIP exception."),
        0x40010008: ("DBG_CONTROL_BREAK","Debugger received a control break."),
        0x40010009: ("DBG_COMMAND_EXCEPTION","Debugger command communication exception."),
        0x40020056: ("RPC_NT_UUID_LOCAL_ONLY","A UUID that is valid only on this computer has been allocated."),
        0x400200AF: ("RPC_NT_SEND_INCOMPLETE","Some data remains to be sent in the request buffer."),
        0x400A0004: ("STATUS_CTX_CDM_CONNECT","The Client Drive Mapping Service has connected on Terminal Connection."),
        0x400A0005: ("STATUS_CTX_CDM_DISCONNECT","The Client Drive Mapping Service has disconnected on Terminal Connection."),
        0x4015000D: ("STATUS_SXS_RELEASE_ACTIVATION_CONTEXT","A kernel mode component is releasing a reference on an activation context."),
        0x40190034: ("STATUS_RECOVERY_NOT_NEEDED","The transactional resource manager is already consistent. Recovery is not needed."),
        0x40190035: ("STATUS_RM_ALREADY_STARTED","The transactional resource manager has already been started."),
        0x401A000C: ("STATUS_LOG_NO_RESTART","The log service encountered a log stream with no restart area."),
        0x401B00EC: ("STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST","{Display Driver Recovered From Failure} The %hs display driver has detected a failure and recovered from it. Some graphical operations may have failed. The next time you restart the machine, a dialog box appears, giving you an opportunity to upload data about this failure to Microsoft."),
        0x401E000A: ("STATUS_GRAPHICS_PARTIAL_DATA_POPULATED","The specified buffer is not big enough to contain the entire requested dataset. Partial data is populated up to the size of the buffer. The caller needs to provide a buffer of the size as specified in the partially populated buffer's content (interface specific)."),
        0x401E0117: ("STATUS_GRAPHICS_DRIVER_MISMATCH","The kernel driver detected a version mismatch between it and the user mode driver."),
        0x401E0307: ("STATUS_GRAPHICS_MODE_NOT_PINNED","No mode is pinned on the specified VidPN source/target."),
        0x401E031E: ("STATUS_GRAPHICS_NO_PREFERRED_MODE","The specified mode set does not specify a preference for one of its modes."),
        0x401E034B: ("STATUS_GRAPHICS_DATASET_IS_EMPTY","The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) is empty."),
        0x401E034C: ("STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET","The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) does not contain any more elements."),
        0x401E0351: ("STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED","The specified content transformation is not pinned on the specified VidPN present path."),
        0x401E042F: ("STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS","The child device presence was not reliably detected."),
        0x401E0437: ("STATUS_GRAPHICS_LEADLINK_START_DEFERRED","Starting the lead adapter in a linked configuration has been temporarily deferred."),
        0x401E0439: ("STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY","The display adapter is being polled for children too frequently at the same polling level."),
        0x401E043A: ("STATUS_GRAPHICS_START_DEFERRED","Starting the adapter has been temporarily deferred."),
        0x40230001: ("STATUS_NDIS_INDICATION_REQUIRED","The request will be completed later by an NDIS status indication."),
        0x80000001: ("STATUS_GUARD_PAGE_VIOLATION","{EXCEPTION} Guard Page Exception A page of memory that marks the end of a data structure, such as a stack or an array, has been accessed."),
        0x80000002: ("STATUS_DATATYPE_MISALIGNMENT","{EXCEPTION} Alignment Fault A data type misalignment was detected in a load or store instruction."),
        0x80000003: ("STATUS_BREAKPOINT","{EXCEPTION} Breakpoint A breakpoint has been reached."),
        0x80000004: ("STATUS_SINGLE_STEP","{EXCEPTION} Single Step A single step or trace operation has just been completed."),
        0x80000005: ("STATUS_BUFFER_OVERFLOW","{Buffer Overflow} The data was too large to fit into the specified buffer."),
        0x80000006: ("STATUS_NO_MORE_FILES","{No More Files} No more files were found which match the file specification."),
        0x80000007: ("STATUS_WAKE_SYSTEM_DEBUGGER","{Kernel Debugger Awakened} The system debugger was awakened by an interrupt."),
        0x8000000A: ("STATUS_HANDLES_CLOSED","{Handles Closed} Handles to objects have been automatically closed because of the requested operation."),
        0x8000000B: ("STATUS_NO_INHERITANCE","{Non-Inheritable ACL} An access control list (ACL) contains no components that can be inherited."),
        0x8000000C: ("STATUS_GUID_SUBSTITUTION_MADE","{GUID Substitution} During the translation of a globally unique identifier (GUID) to a Windows security ID (SID), no administratively defined GUID prefix was found. A substitute prefix was used, which will not compromise system security. However, this may provide a more restrictive access than intended."),
        0x8000000D: ("STATUS_PARTIAL_COPY","Because of protection conflicts, not all the requested bytes could be copied."),
        0x8000000E: ("STATUS_DEVICE_PAPER_EMPTY","{Out of Paper} The printer is out of paper."),
        0x8000000F: ("STATUS_DEVICE_POWERED_OFF","{Device Power Is Off} The printer power has been turned off."),
        0x80000010: ("STATUS_DEVICE_OFF_LINE","{Device Offline} The printer has been taken offline."),
        0x80000011: ("STATUS_DEVICE_BUSY","{Device Busy} The device is currently busy."),
        0x80000012: ("STATUS_NO_MORE_EAS","{No More EAs} No more extended attributes (EAs) were found for the file."),
        0x80000013: ("STATUS_INVALID_EA_NAME","{Illegal EA} The specified extended attribute (EA) name contains at least one illegal character."),
        0x80000014: ("STATUS_EA_LIST_INCONSISTENT","{Inconsistent EA List} The extended attribute (EA) list is inconsistent."),
        0x80000015: ("STATUS_INVALID_EA_FLAG","{Invalid EA Flag} An invalid extended attribute (EA) flag was set."),
        0x80000016: ("STATUS_VERIFY_REQUIRED","{Verifying Disk} The media has changed and a verify operation is in progress; therefore, no reads or writes may be performed to the device, except those that are used in the verify operation."),
        0x80000017: ("STATUS_EXTRANEOUS_INFORMATION","{Too Much Information} The specified access control list (ACL) contained more information than was expected."),
        0x80000018: ("STATUS_RXACT_COMMIT_NECESSARY","This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has NOT been completed but has not been rolled back either; therefore, it may still be committed, if needed."),
        0x8000001A: ("STATUS_NO_MORE_ENTRIES","{No More Entries} No more entries are available from an enumeration operation."),
        0x8000001B: ("STATUS_FILEMARK_DETECTED","{Filemark Found} A filemark was detected."),
        0x8000001C: ("STATUS_MEDIA_CHANGED","{Media Changed} The media may have changed."),
        0x8000001D: ("STATUS_BUS_RESET","{I/O Bus Reset} An I/O bus reset was detected."),
        0x8000001E: ("STATUS_END_OF_MEDIA","{End of Media} The end of the media was encountered."),
        0x8000001F: ("STATUS_BEGINNING_OF_MEDIA","The beginning of a tape or partition has been detected."),
        0x80000020: ("STATUS_MEDIA_CHECK","{Media Changed} The media may have changed."),
        0x80000021: ("STATUS_SETMARK_DETECTED","A tape access reached a set mark."),
        0x80000022: ("STATUS_NO_DATA_DETECTED","During a tape access, the end of the data written is reached."),
        0x80000023: ("STATUS_REDIRECTOR_HAS_OPEN_HANDLES","The redirector is in use and cannot be unloaded."),
        0x80000024: ("STATUS_SERVER_HAS_OPEN_HANDLES","The server is in use and cannot be unloaded."),
        0x80000025: ("STATUS_ALREADY_DISCONNECTED","The specified connection has already been disconnected."),
        0x80000026: ("STATUS_LONGJUMP","A long jump has been executed."),
        0x80000027: ("STATUS_CLEANER_CARTRIDGE_INSTALLED","A cleaner cartridge is present in the tape library."),
        0x80000028: ("STATUS_PLUGPLAY_QUERY_VETOED","The Plug and Play query operation was not successful."),
        0x80000029: ("STATUS_UNWIND_CONSOLIDATE","A frame consolidation has been executed."),
        0x8000002A: ("STATUS_REGISTRY_HIVE_RECOVERED","{Registry Hive Recovered} The registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost."),
        0x8000002B: ("STATUS_DLL_MIGHT_BE_INSECURE","The application is attempting to run executable code from the module %hs. This may be insecure. An alternative, %hs, is available. Should the application use the secure module %hs?"),
        0x8000002C: ("STATUS_DLL_MIGHT_BE_INCOMPATIBLE","The application is loading executable code from the module %hs. This is secure but may be incompatible with previous releases of the operating system. An alternative, %hs, is available. Should the application use the secure module %hs?"),
        0x8000002D: ("STATUS_STOPPED_ON_SYMLINK","The create operation stopped after reaching a symbolic link."),
        0x80000288: ("STATUS_DEVICE_REQUIRES_CLEANING","The device has indicated that cleaning is necessary."),
        0x80000289: ("STATUS_DEVICE_DOOR_OPEN","The device has indicated that its door is open. Further operations require it closed and secured."),
        0x80000803: ("STATUS_DATA_LOST_REPAIR","Windows discovered a corruption in the file %hs. This file has now been repaired. Check if any data in the file was lost because of the corruption."),
        0x80010001: ("DBG_EXCEPTION_NOT_HANDLED","Debugger did not handle the exception."),
        0x80130001: ("STATUS_CLUSTER_NODE_ALREADY_UP","The cluster node is already up."),
        0x80130002: ("STATUS_CLUSTER_NODE_ALREADY_DOWN","The cluster node is already down."),
        0x80130003: ("STATUS_CLUSTER_NETWORK_ALREADY_ONLINE","The cluster network is already online."),
        0x80130004: ("STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE","The cluster network is already offline."),
        0x80130005: ("STATUS_CLUSTER_NODE_ALREADY_MEMBER","The cluster node is already a member of the cluster."),
        0x80190009: ("STATUS_COULD_NOT_RESIZE_LOG","The log could not be set to the requested size."),
        0x80190029: ("STATUS_NO_TXF_METADATA","There is no transaction metadata on the file."),
        0x80190031: ("STATUS_CANT_RECOVER_WITH_HANDLE_OPEN","The file cannot be recovered because there is a handle still open on it."),
        0x80190041: ("STATUS_TXF_METADATA_ALREADY_PRESENT","Transaction metadata is already present on this file and cannot be superseded."),
        0x80190042: ("STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET","A transaction scope could not be entered because the scope handler has not been initialized."),
        0x801B00EB: ("STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED","{Display Driver Stopped Responding and recovered} The %hs display driver has stopped working normally. The recovery had been performed."),
        0x801C0001: ("STATUS_FLT_BUFFER_TOO_SMALL","{Buffer too small} The buffer is too small to contain the entry. No information has been written to the buffer."),
        0x80210001: ("STATUS_FVE_PARTIAL_METADATA","Volume metadata read or write is incomplete."),
        0x80210002: ("STATUS_FVE_TRANSIENT_STATE","BitLocker encryption keys were ignored because the volume was in a transient state."),
        0xC0000001: ("STATUS_UNSUCCESSFUL","{Operation Failed} The requested operation was unsuccessful."),
        0xC0000002: ("STATUS_NOT_IMPLEMENTED","{Not Implemented} The requested operation is not implemented."),
        0xC0000003: ("STATUS_INVALID_INFO_CLASS","{Invalid Parameter} The specified information class is not a valid information class for the specified object."),
        0xC0000004: ("STATUS_INFO_LENGTH_MISMATCH","The specified information record length does not match the length that is required for the specified information class."),
        0xC0000005: ("STATUS_ACCESS_VIOLATION","The instruction at 0x%08lx referenced memory at 0x%08lx. The memory could not be %s."),
        0xC0000006: ("STATUS_IN_PAGE_ERROR","The instruction at 0x%08lx referenced memory at 0x%08lx. The required data was not placed into memory because of an I/O error status of 0x%08lx."),
        0xC0000007: ("STATUS_PAGEFILE_QUOTA","The page file quota for the process has been exhausted."),
        0xC0000008: ("STATUS_INVALID_HANDLE","An invalid HANDLE was specified."),
        0xC0000009: ("STATUS_BAD_INITIAL_STACK","An invalid initial stack was specified in a call to NtCreateThread."),
        0xC000000A: ("STATUS_BAD_INITIAL_PC","An invalid initial start address was specified in a call to NtCreateThread."),
        0xC000000B: ("STATUS_INVALID_CID","An invalid client ID was specified."),
        0xC000000C: ("STATUS_TIMER_NOT_CANCELED","An attempt was made to cancel or set a timer that has an associated APC and the specified thread is not the thread that originally set the timer with an associated APC routine."),
        0xC000000D: ("STATUS_INVALID_PARAMETER","An invalid parameter was passed to a service or function."),
        0xC000000E: ("STATUS_NO_SUCH_DEVICE","A device that does not exist was specified."),
        0xC000000F: ("STATUS_NO_SUCH_FILE","{File Not Found} The file %hs does not exist."),
        0xC0000010: ("STATUS_INVALID_DEVICE_REQUEST","The specified request is not a valid operation for the target device."),
        0xC0000011: ("STATUS_END_OF_FILE","The end-of-file marker has been reached. There is no valid data in the file beyond this marker."),
        0xC0000012: ("STATUS_WRONG_VOLUME","{Wrong Volume} The wrong volume is in the drive. Insert volume %hs into drive %hs."),
        0xC0000013: ("STATUS_NO_MEDIA_IN_DEVICE","{No Disk} There is no disk in the drive. Insert a disk into drive %hs."),
        0xC0000014: ("STATUS_UNRECOGNIZED_MEDIA","{Unknown Disk Format} The disk in drive %hs is not formatted properly. Check the disk, and reformat it, if needed."),
        0xC0000015: ("STATUS_NONEXISTENT_SECTOR","{Sector Not Found} The specified sector does not exist."),
        0xC0000016: ("STATUS_MORE_PROCESSING_REQUIRED","{Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete."),
        0xC0000017: ("STATUS_NO_MEMORY","{Not Enough Quota} Not enough virtual memory or paging file quota is available to complete the specified operation."),
        0xC0000018: ("STATUS_CONFLICTING_ADDRESSES","{Conflicting Address Range} The specified address range conflicts with the address space."),
        0xC0000019: ("STATUS_NOT_MAPPED_VIEW","The address range to unmap is not a mapped view."),
        0xC000001A: ("STATUS_UNABLE_TO_FREE_VM","The virtual memory cannot be freed."),
        0xC000001B: ("STATUS_UNABLE_TO_DELETE_SECTION","The specified section cannot be deleted."),
        0xC000001C: ("STATUS_INVALID_SYSTEM_SERVICE","An invalid system service was specified in a system service call."),
        0xC000001D: ("STATUS_ILLEGAL_INSTRUCTION","{EXCEPTION} Illegal Instruction An attempt was made to execute an illegal instruction."),
        0xC000001E: ("STATUS_INVALID_LOCK_SEQUENCE","{Invalid Lock Sequence} An attempt was made to execute an invalid lock sequence."),
        0xC000001F: ("STATUS_INVALID_VIEW_SIZE","{Invalid Mapping} An attempt was made to create a view for a section that is bigger than the section."),
        0xC0000020: ("STATUS_INVALID_FILE_FOR_SECTION","{Bad File} The attributes of the specified mapping file for a section of memory cannot be read."),
        0xC0000021: ("STATUS_ALREADY_COMMITTED","{Already Committed} The specified address range is already committed."),
        0xC0000022: ("STATUS_ACCESS_DENIED","{Access Denied} A process has requested access to an object but has not been granted those access rights."),
        0xC0000023: ("STATUS_BUFFER_TOO_SMALL","{Buffer Too Small} The buffer is too small to contain the entry. No information has been written to the buffer."),
        0xC0000024: ("STATUS_OBJECT_TYPE_MISMATCH","{Wrong Type} There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request."),
        0xC0000025: ("STATUS_NONCONTINUABLE_EXCEPTION","{EXCEPTION} Cannot Continue Windows cannot continue from this exception."),
        0xC0000026: ("STATUS_INVALID_DISPOSITION","An invalid exception disposition was returned by an exception handler."),
        0xC0000027: ("STATUS_UNWIND","Unwind exception code."),
        0xC0000028: ("STATUS_BAD_STACK","An invalid or unaligned stack was encountered during an unwind operation."),
        0xC0000029: ("STATUS_INVALID_UNWIND_TARGET","An invalid unwind target was encountered during an unwind operation."),
        0xC000002A: ("STATUS_NOT_LOCKED","An attempt was made to unlock a page of memory that was not locked."),
        0xC000002B: ("STATUS_PARITY_ERROR","A device parity error on an I/O operation."),
        0xC000002C: ("STATUS_UNABLE_TO_DECOMMIT_VM","An attempt was made to decommit uncommitted virtual memory."),
        0xC000002D: ("STATUS_NOT_COMMITTED","An attempt was made to change the attributes on memory that has not been committed."),
        0xC000002E: ("STATUS_INVALID_PORT_ATTRIBUTES","Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort."),
        0xC000002F: ("STATUS_PORT_MESSAGE_TOO_LONG","The length of the message that was passed to NtRequestPort or NtRequestWaitReplyPort is longer than the maximum message that is allowed by the port."),
        0xC0000030: ("STATUS_INVALID_PARAMETER_MIX","An invalid combination of parameters was specified."),
        0xC0000031: ("STATUS_INVALID_QUOTA_LOWER","An attempt was made to lower a quota limit below the current usage."),
        0xC0000032: ("STATUS_DISK_CORRUPT_ERROR","{Corrupt Disk} The file system structure on the disk is corrupt and unusable. Run the Chkdsk utility on the volume %hs."),
        0xC0000033: ("STATUS_OBJECT_NAME_INVALID","The object name is invalid."),
        0xC0000034: ("STATUS_OBJECT_NAME_NOT_FOUND","The object name is not found."),
        0xC0000035: ("STATUS_OBJECT_NAME_COLLISION","The object name already exists."),
        0xC0000037: ("STATUS_PORT_DISCONNECTED","An attempt was made to send a message to a disconnected communication port."),
        0xC0000038: ("STATUS_DEVICE_ALREADY_ATTACHED","An attempt was made to attach to a device that was already attached to another device."),
        0xC0000039: ("STATUS_OBJECT_PATH_INVALID","The object path component was not a directory object."),
        0xC000003A: ("STATUS_OBJECT_PATH_NOT_FOUND","{Path Not Found} The path %hs does not exist."),
        0xC000003B: ("STATUS_OBJECT_PATH_SYNTAX_BAD","The object path component was not a directory object."),
        0xC000003C: ("STATUS_DATA_OVERRUN","{Data Overrun} A data overrun error occurred."),
        0xC000003D: ("STATUS_DATA_LATE_ERROR","{Data Late} A data late error occurred."),
        0xC000003E: ("STATUS_DATA_ERROR","{Data Error} An error occurred in reading or writing data."),
        0xC000003F: ("STATUS_CRC_ERROR","{Bad CRC} A cyclic redundancy check (CRC) checksum error occurred."),
        0xC0000040: ("STATUS_SECTION_TOO_BIG","{Section Too Large} The specified section is too big to map the file."),
        0xC0000041: ("STATUS_PORT_CONNECTION_REFUSED","The NtConnectPort request is refused."),
        0xC0000042: ("STATUS_INVALID_PORT_HANDLE","The type of port handle is invalid for the operation that is requested."),
        0xC0000043: ("STATUS_SHARING_VIOLATION","A file cannot be opened because the share access flags are incompatible."),
        0xC0000044: ("STATUS_QUOTA_EXCEEDED","Insufficient quota exists to complete the operation."),
        0xC0000045: ("STATUS_INVALID_PAGE_PROTECTION","The specified page protection was not valid."),
        0xC0000046: ("STATUS_MUTANT_NOT_OWNED","An attempt to release a mutant object was made by a thread that was not the owner of the mutant object."),
        0xC0000047: ("STATUS_SEMAPHORE_LIMIT_EXCEEDED","An attempt was made to release a semaphore such that its maximum count would have been exceeded."),
        0xC0000048: ("STATUS_PORT_ALREADY_SET","An attempt was made to set the DebugPort or ExceptionPort of a process, but a port already exists in the process, or an attempt was made to set the CompletionPort of a file but a port was already set in the file, or an attempt was made to set the associated completion port of an ALPC port but it is already set."),
        0xC0000049: ("STATUS_SECTION_NOT_IMAGE","An attempt was made to query image information on a section that does not map an image."),
        0xC000004A: ("STATUS_SUSPEND_COUNT_EXCEEDED","An attempt was made to suspend a thread whose suspend count was at its maximum."),
        0xC000004B: ("STATUS_THREAD_IS_TERMINATING","An attempt was made to suspend a thread that has begun termination."),
        0xC000004C: ("STATUS_BAD_WORKING_SET_LIMIT","An attempt was made to set the working set limit to an invalid value (for example, the minimum greater than maximum)."),
        0xC000004D: ("STATUS_INCOMPATIBLE_FILE_MAP","A section was created to map a file that is not compatible with an already existing section that maps the same file."),
        0xC000004E: ("STATUS_SECTION_PROTECTION","A view to a section specifies a protection that is incompatible with the protection of the initial view."),
        0xC000004F: ("STATUS_EAS_NOT_SUPPORTED","An operation involving EAs failed because the file system does not support EAs."),
        0xC0000050: ("STATUS_EA_TOO_LARGE","An EA operation failed because the EA set is too large."),
        0xC0000051: ("STATUS_NONEXISTENT_EA_ENTRY","An EA operation failed because the name or EA index is invalid."),
        0xC0000052: ("STATUS_NO_EAS_ON_FILE","The file for which EAs were requested has no EAs."),
        0xC0000053: ("STATUS_EA_CORRUPT_ERROR","The EA is corrupt and cannot be read."),
        0xC0000054: ("STATUS_FILE_LOCK_CONFLICT","A requested read/write cannot be granted due to a conflicting file lock."),
        0xC0000055: ("STATUS_LOCK_NOT_GRANTED","A requested file lock cannot be granted due to other existing locks."),
        0xC0000056: ("STATUS_DELETE_PENDING","A non-close operation has been requested of a file object that has a delete pending."),
        0xC0000057: ("STATUS_CTL_FILE_NOT_SUPPORTED","An attempt was made to set the control attribute on a file. This attribute is not supported in the destination file system."),
        0xC0000058: ("STATUS_UNKNOWN_REVISION","Indicates a revision number that was encountered or specified is not one that is known by the service. It may be a more recent revision than the service is aware of."),
        0xC0000059: ("STATUS_REVISION_MISMATCH","Indicates that two revision levels are incompatible."),
        0xC000005A: ("STATUS_INVALID_OWNER","Indicates a particular security ID may not be assigned as the owner of an object."),
        0xC000005B: ("STATUS_INVALID_PRIMARY_GROUP","Indicates a particular security ID may not be assigned as the primary group of an object."),
        0xC000005C: ("STATUS_NO_IMPERSONATION_TOKEN","An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client."),
        0xC000005D: ("STATUS_CANT_DISABLE_MANDATORY","A mandatory group may not be disabled."),
        0xC000005E: ("STATUS_NO_LOGON_SERVERS","No logon servers are currently available to service the logon request."),
        0xC000005F: ("STATUS_NO_SUCH_LOGON_SESSION","A specified logon session does not exist. It may already have been terminated."),
        0xC0000060: ("STATUS_NO_SUCH_PRIVILEGE","A specified privilege does not exist."),
        0xC0000061: ("STATUS_PRIVILEGE_NOT_HELD","A required privilege is not held by the client."),
        0xC0000062: ("STATUS_INVALID_ACCOUNT_NAME","The name provided is not a properly formed account name."),
        0xC0000063: ("STATUS_USER_EXISTS","The specified account already exists."),
        0xC0000064: ("STATUS_NO_SUCH_USER","The specified account does not exist."),
        0xC0000065: ("STATUS_GROUP_EXISTS","The specified group already exists."),
        0xC0000066: ("STATUS_NO_SUCH_GROUP","The specified group does not exist."),
        0xC0000067: ("STATUS_MEMBER_IN_GROUP","The specified user account is already in the specified group account. Also used to indicate a group cannot be deleted because it contains a member."),
        0xC0000068: ("STATUS_MEMBER_NOT_IN_GROUP","The specified user account is not a member of the specified group account."),
        0xC0000069: ("STATUS_LAST_ADMIN","Indicates the requested operation would disable or delete the last remaining administration account. This is not allowed to prevent creating a situation in which the system cannot be administrated."),
        0xC000006A: ("STATUS_WRONG_PASSWORD","When trying to update a password, this return status indicates that the value provided as the current password is not correct."),
        0xC000006B: ("STATUS_ILL_FORMED_PASSWORD","When trying to update a password, this return status indicates that the value provided for the new password contains values that are not allowed in passwords."),
        0xC000006C: ("STATUS_PASSWORD_RESTRICTION","When trying to update a password, this status indicates that some password update rule has been violated. For example, the password may not meet length criteria."),
        0xC000006D: ("STATUS_LOGON_FAILURE","The attempted logon is invalid. This is either due to a bad username or authentication information."),
        0xC000006E: ("STATUS_ACCOUNT_RESTRICTION","Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions)."),
        0xC000006F: ("STATUS_INVALID_LOGON_HOURS","The user account has time restrictions and may not be logged onto at this time."),
        0xC0000070: ("STATUS_INVALID_WORKSTATION","The user account is restricted so that it may not be used to log on from the source workstation."),
        0xC0000071: ("STATUS_PASSWORD_EXPIRED","The user account password has expired."),
        0xC0000072: ("STATUS_ACCOUNT_DISABLED","The referenced account is currently disabled and may not be logged on to."),
        0xC0000073: ("STATUS_NONE_MAPPED","None of the information to be translated has been translated."),
        0xC0000074: ("STATUS_TOO_MANY_LUIDS_REQUESTED","The number of LUIDs requested may not be allocated with a single allocation."),
        0xC0000075: ("STATUS_LUIDS_EXHAUSTED","Indicates there are no more LUIDs to allocate."),
        0xC0000076: ("STATUS_INVALID_SUB_AUTHORITY","Indicates the sub-authority value is invalid for the particular use."),
        0xC0000077: ("STATUS_INVALID_ACL","Indicates the ACL structure is not valid."),
        0xC0000078: ("STATUS_INVALID_SID","Indicates the SID structure is not valid."),
        0xC0000079: ("STATUS_INVALID_SECURITY_DESCR","Indicates the SECURITY_DESCRIPTOR structure is not valid."),
        0xC000007A: ("STATUS_PROCEDURE_NOT_FOUND","Indicates the specified procedure address cannot be found in the DLL."),
        0xC000007B: ("STATUS_INVALID_IMAGE_FORMAT","{Bad Image} %hs is either not designed to run on Windows or it contains an error. Try installing the program again using the original installation media or contact your system administrator or the software vendor for support."),
        0xC000007C: ("STATUS_NO_TOKEN","An attempt was made to reference a token that does not exist. This is typically done by referencing the token that is associated with a thread when the thread is not impersonating a client."),
        0xC000007D: ("STATUS_BAD_INHERITANCE_ACL","Indicates that an attempt to build either an inherited ACL or ACE was not successful. This can be caused by a number of things. One of the more probable causes is the replacement of a CreatorId with a SID that did not fit into the ACE or ACL."),
        0xC000007E: ("STATUS_RANGE_NOT_LOCKED","The range specified in NtUnlockFile was not locked."),
        0xC000007F: ("STATUS_DISK_FULL","An operation failed because the disk was full."),
        0xC0000080: ("STATUS_SERVER_DISABLED","The GUID allocation server is disabled at the moment."),
        0xC0000081: ("STATUS_SERVER_NOT_DISABLED","The GUID allocation server is enabled at the moment."),
        0xC0000082: ("STATUS_TOO_MANY_GUIDS_REQUESTED","Too many GUIDs were requested from the allocation server at once."),
        0xC0000083: ("STATUS_GUIDS_EXHAUSTED","The GUIDs could not be allocated because the Authority Agent was exhausted."),
        0xC0000084: ("STATUS_INVALID_ID_AUTHORITY","The value provided was an invalid value for an identifier authority."),
        0xC0000085: ("STATUS_AGENTS_EXHAUSTED","No more authority agent values are available for the particular identifier authority value."),
        0xC0000086: ("STATUS_INVALID_VOLUME_LABEL","An invalid volume label has been specified."),
        0xC0000087: ("STATUS_SECTION_NOT_EXTENDED","A mapped section could not be extended."),
        0xC0000088: ("STATUS_NOT_MAPPED_DATA","Specified section to flush does not map a data file."),
        0xC0000089: ("STATUS_RESOURCE_DATA_NOT_FOUND","Indicates the specified image file did not contain a resource section."),
        0xC000008A: ("STATUS_RESOURCE_TYPE_NOT_FOUND","Indicates the specified resource type cannot be found in the image file."),
        0xC000008B: ("STATUS_RESOURCE_NAME_NOT_FOUND","Indicates the specified resource name cannot be found in the image file."),
        0xC000008C: ("STATUS_ARRAY_BOUNDS_EXCEEDED","{EXCEPTION} Array bounds exceeded."),
        0xC000008D: ("STATUS_FLOAT_DENORMAL_OPERAND","{EXCEPTION} Floating-point denormal operand."),
        0xC000008E: ("STATUS_FLOAT_DIVIDE_BY_ZERO","{EXCEPTION} Floating-point division by zero."),
        0xC000008F: ("STATUS_FLOAT_INEXACT_RESULT","{EXCEPTION} Floating-point inexact result."),
        0xC0000090: ("STATUS_FLOAT_INVALID_OPERATION","{EXCEPTION} Floating-point invalid operation."),
        0xC0000091: ("STATUS_FLOAT_OVERFLOW","{EXCEPTION} Floating-point overflow."),
        0xC0000092: ("STATUS_FLOAT_STACK_CHECK","{EXCEPTION} Floating-point stack check."),
        0xC0000093: ("STATUS_FLOAT_UNDERFLOW","{EXCEPTION} Floating-point underflow."),
        0xC0000094: ("STATUS_INTEGER_DIVIDE_BY_ZERO","{EXCEPTION} Integer division by zero."),
        0xC0000095: ("STATUS_INTEGER_OVERFLOW","{EXCEPTION} Integer overflow."),
        0xC0000096: ("STATUS_PRIVILEGED_INSTRUCTION","{EXCEPTION} Privileged instruction."),
        0xC0000097: ("STATUS_TOO_MANY_PAGING_FILES","An attempt was made to install more paging files than the system supports."),
        0xC0000098: ("STATUS_FILE_INVALID","The volume for a file has been externally altered such that the opened file is no longer valid."),
        0xC0000099: ("STATUS_ALLOTTED_SPACE_EXCEEDED","When a block of memory is allotted for future updates, such as the memory allocated to hold discretionary access control and primary group information, successive updates may exceed the amount of memory originally allotted. Because a quota may already have been charged to several processes that have handles to the object, it is not reasonable to alter the size of the allocated memory. Instead, a request that requires more memory than has been allotted must fail and the STATUS_ALLOTTED_SPACE_EXCEEDED error returned."),
        0xC000009A: ("STATUS_INSUFFICIENT_RESOURCES","Insufficient system resources exist to complete the API."),
        0xC000009B: ("STATUS_DFS_EXIT_PATH_FOUND","An attempt has been made to open a DFS exit path control file."),
        0xC000009C: ("STATUS_DEVICE_DATA_ERROR","There are bad blocks (sectors) on the hard disk."),
        0xC000009D: ("STATUS_DEVICE_NOT_CONNECTED","There is bad cabling, non-termination, or the controller is not able to obtain access to the hard disk."),
        0xC000009F: ("STATUS_FREE_VM_NOT_AT_BASE","Virtual memory cannot be freed because the base address is not the base of the region and a region size of zero was specified."),
        0xC00000A0: ("STATUS_MEMORY_NOT_ALLOCATED","An attempt was made to free virtual memory that is not allocated."),
        0xC00000A1: ("STATUS_WORKING_SET_QUOTA","The working set is not big enough to allow the requested pages to be locked."),
        0xC00000A2: ("STATUS_MEDIA_WRITE_PROTECTED","{Write Protect Error} The disk cannot be written to because it is write-protected. Remove the write protection from the volume %hs in drive %hs."),
        0xC00000A3: ("STATUS_DEVICE_NOT_READY","{Drive Not Ready} The drive is not ready for use; its door may be open. Check drive %hs and make sure that a disk is inserted and that the drive door is closed."),
        0xC00000A4: ("STATUS_INVALID_GROUP_ATTRIBUTES","The specified attributes are invalid or are incompatible with the attributes for the group as a whole."),
        0xC00000A5: ("STATUS_BAD_IMPERSONATION_LEVEL","A specified impersonation level is invalid. Also used to indicate that a required impersonation level was not provided."),
        0xC00000A6: ("STATUS_CANT_OPEN_ANONYMOUS","An attempt was made to open an anonymous-level token. Anonymous tokens may not be opened."),
        0xC00000A7: ("STATUS_BAD_VALIDATION_CLASS","The validation information class requested was invalid."),
        0xC00000A8: ("STATUS_BAD_TOKEN_TYPE","The type of a token object is inappropriate for its attempted use."),
        0xC00000A9: ("STATUS_BAD_MASTER_BOOT_RECORD","The type of a token object is inappropriate for its attempted use."),
        0xC00000AA: ("STATUS_INSTRUCTION_MISALIGNMENT","An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references."),
        0xC00000AB: ("STATUS_INSTANCE_NOT_AVAILABLE","The maximum named pipe instance count has been reached."),
        0xC00000AC: ("STATUS_PIPE_NOT_AVAILABLE","An instance of a named pipe cannot be found in the listening state."),
        0xC00000AD: ("STATUS_INVALID_PIPE_STATE","The named pipe is not in the connected or closing state."),
        0xC00000AE: ("STATUS_PIPE_BUSY","The specified pipe is set to complete operations and there are current I/O operations queued so that it cannot be changed to queue operations."),
        0xC00000AF: ("STATUS_ILLEGAL_FUNCTION","The specified handle is not open to the server end of the named pipe."),
        0xC00000B0: ("STATUS_PIPE_DISCONNECTED","The specified named pipe is in the disconnected state."),
        0xC00000B1: ("STATUS_PIPE_CLOSING","The specified named pipe is in the closing state."),
        0xC00000B2: ("STATUS_PIPE_CONNECTED","The specified named pipe is in the connected state."),
        0xC00000B3: ("STATUS_PIPE_LISTENING","The specified named pipe is in the listening state."),
        0xC00000B4: ("STATUS_INVALID_READ_MODE","The specified named pipe is not in message mode."),
        0xC00000B5: ("STATUS_IO_TIMEOUT","{Device Timeout} The specified I/O operation on %hs was not completed before the time-out period expired."),
        0xC00000B6: ("STATUS_FILE_FORCED_CLOSED","The specified file has been closed by another process."),
        0xC00000B7: ("STATUS_PROFILING_NOT_STARTED","Profiling is not started."),
        0xC00000B8: ("STATUS_PROFILING_NOT_STOPPED","Profiling is not stopped."),
        0xC00000B9: ("STATUS_COULD_NOT_INTERPRET","The passed ACL did not contain the minimum required information."),
        0xC00000BA: ("STATUS_FILE_IS_A_DIRECTORY","The file that was specified as a target is a directory, and the caller specified that it could be anything but a directory."),
        0xC00000BB: ("STATUS_NOT_SUPPORTED","The request is not supported."),
        0xC00000BC: ("STATUS_REMOTE_NOT_LISTENING","This remote computer is not listening."),
        0xC00000BD: ("STATUS_DUPLICATE_NAME","A duplicate name exists on the network."),
        0xC00000BE: ("STATUS_BAD_NETWORK_PATH","The network path cannot be located."),
        0xC00000BF: ("STATUS_NETWORK_BUSY","The network is busy."),
        0xC00000C0: ("STATUS_DEVICE_DOES_NOT_EXIST","This device does not exist."),
        0xC00000C1: ("STATUS_TOO_MANY_COMMANDS","The network BIOS command limit has been reached."),
        0xC00000C2: ("STATUS_ADAPTER_HARDWARE_ERROR","An I/O adapter hardware error has occurred."),
        0xC00000C3: ("STATUS_INVALID_NETWORK_RESPONSE","The network responded incorrectly."),
        0xC00000C4: ("STATUS_UNEXPECTED_NETWORK_ERROR","An unexpected network error occurred."),
        0xC00000C5: ("STATUS_BAD_REMOTE_ADAPTER","The remote adapter is not compatible."),
        0xC00000C6: ("STATUS_PRINT_QUEUE_FULL","The print queue is full."),
        0xC00000C7: ("STATUS_NO_SPOOL_SPACE","Space to store the file that is waiting to be printed is not available on the server."),
        0xC00000C8: ("STATUS_PRINT_CANCELLED","The requested print file has been canceled."),
        0xC00000C9: ("STATUS_NETWORK_NAME_DELETED","The network name was deleted."),
        0xC00000CA: ("STATUS_NETWORK_ACCESS_DENIED","Network access is denied."),
        0xC00000CB: ("STATUS_BAD_DEVICE_TYPE","{Incorrect Network Resource Type} The specified device type (LPT, for example) conflicts with the actual device type on the remote resource."),
        0xC00000CC: ("STATUS_BAD_NETWORK_NAME","{Network Name Not Found} The specified share name cannot be found on the remote server."),
        0xC00000CD: ("STATUS_TOO_MANY_NAMES","The name limit for the network adapter card of the local computer was exceeded."),
        0xC00000CE: ("STATUS_TOO_MANY_SESSIONS","The network BIOS session limit was exceeded."),
        0xC00000CF: ("STATUS_SHARING_PAUSED","File sharing has been temporarily paused."),
        0xC00000D0: ("STATUS_REQUEST_NOT_ACCEPTED","No more connections can be made to this remote computer at this time because the computer has already accepted the maximum number of connections."),
        0xC00000D1: ("STATUS_REDIRECTOR_PAUSED","Print or disk redirection is temporarily paused."),
        0xC00000D2: ("STATUS_NET_WRITE_FAULT","A network data fault occurred."),
        0xC00000D3: ("STATUS_PROFILING_AT_LIMIT","The number of active profiling objects is at the maximum and no more may be started."),
        0xC00000D4: ("STATUS_NOT_SAME_DEVICE","{Incorrect Volume} The destination file of a rename request is located on a different device than the source of the rename request."),
        0xC00000D5: ("STATUS_FILE_RENAMED","The specified file has been renamed and thus cannot be modified."),
        0xC00000D6: ("STATUS_VIRTUAL_CIRCUIT_CLOSED","{Network Request Timeout} The session with a remote server has been disconnected because the time-out interval for a request has expired."),
        0xC00000D7: ("STATUS_NO_SECURITY_ON_OBJECT","Indicates an attempt was made to operate on the security of an object that does not have security associated with it."),
        0xC00000D8: ("STATUS_CANT_WAIT","Used to indicate that an operation cannot continue without blocking for I/O."),
        0xC00000D9: ("STATUS_PIPE_EMPTY","Used to indicate that a read operation was done on an empty pipe."),
        0xC00000DA: ("STATUS_CANT_ACCESS_DOMAIN_INFO","Configuration information could not be read from the domain controller, either because the machine is unavailable or access has been denied."),
        0xC00000DB: ("STATUS_CANT_TERMINATE_SELF","Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process."),
        0xC00000DC: ("STATUS_INVALID_SERVER_STATE","Indicates the Sam Server was in the wrong state to perform the desired operation."),
        0xC00000DD: ("STATUS_INVALID_DOMAIN_STATE","Indicates the domain was in the wrong state to perform the desired operation."),
        0xC00000DE: ("STATUS_INVALID_DOMAIN_ROLE","This operation is only allowed for the primary domain controller of the domain."),
        0xC00000DF: ("STATUS_NO_SUCH_DOMAIN","The specified domain did not exist."),
        0xC00000E0: ("STATUS_DOMAIN_EXISTS","The specified domain already exists."),
        0xC00000E1: ("STATUS_DOMAIN_LIMIT_EXCEEDED","An attempt was made to exceed the limit on the number of domains per server for this release."),
        0xC00000E2: ("STATUS_OPLOCK_NOT_GRANTED","An error status returned when the opportunistic lock (oplock) request is denied."),
        0xC00000E3: ("STATUS_INVALID_OPLOCK_PROTOCOL","An error status returned when an invalid opportunistic lock (oplock) acknowledgment is received by a file system."),
        0xC00000E4: ("STATUS_INTERNAL_DB_CORRUPTION","This error indicates that the requested operation cannot be completed due to a catastrophic media failure or an on-disk data structure corruption."),
        0xC00000E5: ("STATUS_INTERNAL_ERROR","An internal error occurred."),
        0xC00000E6: ("STATUS_GENERIC_NOT_MAPPED","Indicates generic access types were contained in an access mask which should already be mapped to non-generic access types."),
        0xC00000E7: ("STATUS_BAD_DESCRIPTOR_FORMAT","Indicates a security descriptor is not in the necessary format (absolute or self-relative)."),
        0xC00000E8: ("STATUS_INVALID_USER_BUFFER","An access to a user buffer failed at an expected point in time. This code is defined because the caller does not want to accept STATUS_ACCESS_VIOLATION in its filter."),
        0xC00000E9: ("STATUS_UNEXPECTED_IO_ERROR","If an I/O error that is not defined in the standard FsRtl filter is returned, it is converted to the following error, which is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception."),
        0xC00000EA: ("STATUS_UNEXPECTED_MM_CREATE_ERR","If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception."),
        0xC00000EB: ("STATUS_UNEXPECTED_MM_MAP_ERROR","If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception."),
        0xC00000EC: ("STATUS_UNEXPECTED_MM_EXTEND_ERR","If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception."),
        0xC00000ED: ("STATUS_NOT_LOGON_PROCESS","The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process."),
        0xC00000EE: ("STATUS_LOGON_SESSION_EXISTS","An attempt has been made to start a new session manager or LSA logon session by using an ID that is already in use."),
        0xC00000EF: ("STATUS_INVALID_PARAMETER_1","An invalid parameter was passed to a service or function as the first argument."),
        0xC00000F0: ("STATUS_INVALID_PARAMETER_2","An invalid parameter was passed to a service or function as the second argument."),
        0xC00000F1: ("STATUS_INVALID_PARAMETER_3","An invalid parameter was passed to a service or function as the third argument."),
        0xC00000F2: ("STATUS_INVALID_PARAMETER_4","An invalid parameter was passed to a service or function as the fourth argument."),
        0xC00000F3: ("STATUS_INVALID_PARAMETER_5","An invalid parameter was passed to a service or function as the fifth argument."),
        0xC00000F4: ("STATUS_INVALID_PARAMETER_6","An invalid parameter was passed to a service or function as the sixth argument."),
        0xC00000F5: ("STATUS_INVALID_PARAMETER_7","An invalid parameter was passed to a service or function as the seventh argument."),
        0xC00000F6: ("STATUS_INVALID_PARAMETER_8","An invalid parameter was passed to a service or function as the eighth argument."),
        0xC00000F7: ("STATUS_INVALID_PARAMETER_9","An invalid parameter was passed to a service or function as the ninth argument."),
        0xC00000F8: ("STATUS_INVALID_PARAMETER_10","An invalid parameter was passed to a service or function as the tenth argument."),
        0xC00000F9: ("STATUS_INVALID_PARAMETER_11","An invalid parameter was passed to a service or function as the eleventh argument."),
        0xC00000FA: ("STATUS_INVALID_PARAMETER_12","An invalid parameter was passed to a service or function as the twelfth argument."),
        0xC00000FB: ("STATUS_REDIRECTOR_NOT_STARTED","An attempt was made to access a network file, but the network software was not yet started."),
        0xC00000FC: ("STATUS_REDIRECTOR_STARTED","An attempt was made to start the redirector, but the redirector has already been started."),
        0xC00000FD: ("STATUS_STACK_OVERFLOW","A new guard page for the stack cannot be created."),
        0xC00000FE: ("STATUS_NO_SUCH_PACKAGE","A specified authentication package is unknown."),
        0xC00000FF: ("STATUS_BAD_FUNCTION_TABLE","A malformed function table was encountered during an unwind operation."),
        0xC0000100: ("STATUS_VARIABLE_NOT_FOUND","Indicates the specified environment variable name was not found in the specified environment block."),
        0xC0000101: ("STATUS_DIRECTORY_NOT_EMPTY","Indicates that the directory trying to be deleted is not empty."),
        0xC0000102: ("STATUS_FILE_CORRUPT_ERROR","{Corrupt File} The file or directory %hs is corrupt and unreadable. Run the Chkdsk utility."),
        0xC0000103: ("STATUS_NOT_A_DIRECTORY","A requested opened file is not a directory."),
        0xC0000104: ("STATUS_BAD_LOGON_SESSION_STATE","The logon session is not in a state that is consistent with the requested operation."),
        0xC0000105: ("STATUS_LOGON_SESSION_COLLISION","An internal LSA error has occurred. An authentication package has requested the creation of a logon session but the ID of an already existing logon session has been specified."),
        0xC0000106: ("STATUS_NAME_TOO_LONG","A specified name string is too long for its intended use."),
        0xC0000107: ("STATUS_FILES_OPEN","The user attempted to force close the files on a redirected drive, but there were opened files on the drive, and the user did not specify a sufficient level of force."),
        0xC0000108: ("STATUS_CONNECTION_IN_USE","The user attempted to force close the files on a redirected drive, but there were opened directories on the drive, and the user did not specify a sufficient level of force."),
        0xC0000109: ("STATUS_MESSAGE_NOT_FOUND","RtlFindMessage could not locate the requested message ID in the message table resource."),
        0xC000010A: ("STATUS_PROCESS_IS_TERMINATING","An attempt was made to duplicate an object handle into or out of an exiting process."),
        0xC000010B: ("STATUS_INVALID_LOGON_TYPE","Indicates an invalid value has been provided for the LogonType requested."),
        0xC000010C: ("STATUS_NO_GUID_TRANSLATION","Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system. This causes the protection attempt to fail, which may cause a file creation attempt to fail."),
        0xC000010D: ("STATUS_CANNOT_IMPERSONATE","Indicates that an attempt has been made to impersonate via a named pipe that has not yet been read from."),
        0xC000010E: ("STATUS_IMAGE_ALREADY_LOADED","Indicates that the specified image is already loaded."),
        0xC0000117: ("STATUS_NO_LDT","Indicates that an attempt was made to change the size of the LDT for a process that has no LDT."),
        0xC0000118: ("STATUS_INVALID_LDT_SIZE","Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors."),
        0xC0000119: ("STATUS_INVALID_LDT_OFFSET","Indicates that the starting value for the LDT information was not an integral multiple of the selector size."),
        0xC000011A: ("STATUS_INVALID_LDT_DESCRIPTOR","Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors."),
        0xC000011B: ("STATUS_INVALID_IMAGE_NE_FORMAT","The specified image file did not have the correct format. It appears to be NE format."),
        0xC000011C: ("STATUS_RXACT_INVALID_STATE","Indicates that the transaction state of a registry subtree is incompatible with the requested operation. For example, a request has been made to start a new transaction with one already in progress, or a request has been made to apply a transaction when one is not currently in progress."),
        0xC000011D: ("STATUS_RXACT_COMMIT_FAILURE","Indicates an error has occurred during a registry transaction commit. The database has been left in an unknown, but probably inconsistent, state. The state of the registry transaction is left as COMMITTING."),
        0xC000011E: ("STATUS_MAPPED_FILE_SIZE_ZERO","An attempt was made to map a file of size zero with the maximum size specified as zero."),
        0xC000011F: ("STATUS_TOO_MANY_OPENED_FILES","Too many files are opened on a remote server. This error should only be returned by the Windows redirector on a remote drive."),
        0xC0000120: ("STATUS_CANCELLED","The I/O request was canceled."),
        0xC0000121: ("STATUS_CANNOT_DELETE","An attempt has been made to remove a file or directory that cannot be deleted."),
        0xC0000122: ("STATUS_INVALID_COMPUTER_NAME","Indicates a name that was specified as a remote computer name is syntactically invalid."),
        0xC0000123: ("STATUS_FILE_DELETED","An I/O request other than close was performed on a file after it was deleted, which can only happen to a request that did not complete before the last handle was closed via NtClose."),
        0xC0000124: ("STATUS_SPECIAL_ACCOUNT","Indicates an operation that is incompatible with built-in accounts has been attempted on a built-in (special) SAM account. For example, built-in accounts cannot be deleted."),
        0xC0000125: ("STATUS_SPECIAL_GROUP","The operation requested may not be performed on the specified group because it is a built-in special group."),
        0xC0000126: ("STATUS_SPECIAL_USER","The operation requested may not be performed on the specified user because it is a built-in special user."),
        0xC0000127: ("STATUS_MEMBERS_PRIMARY_GROUP","Indicates a member cannot be removed from a group because the group is currently the member's primary group."),
        0xC0000128: ("STATUS_FILE_CLOSED","An I/O request other than close and several other special case operations was attempted using a file object that had already been closed."),
        0xC0000129: ("STATUS_TOO_MANY_THREADS","Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads."),
        0xC000012A: ("STATUS_THREAD_NOT_IN_PROCESS","An attempt was made to operate on a thread within a specific process, but the specified thread is not in the specified process."),
        0xC000012B: ("STATUS_TOKEN_ALREADY_IN_USE","An attempt was made to establish a token for use as a primary token but the token is already in use. A token can only be the primary token of one process at a time."),
        0xC000012C: ("STATUS_PAGEFILE_QUOTA_EXCEEDED","The page file quota was exceeded."),
        0xC000012D: ("STATUS_COMMITMENT_LIMIT","{Out of Virtual Memory} Your system is low on virtual memory. To ensure that Windows runs correctly, increase the size of your virtual memory paging file. For more information, see Help."),
        0xC000012E: ("STATUS_INVALID_IMAGE_LE_FORMAT","The specified image file did not have the correct format: it appears to be LE format."),
        0xC000012F: ("STATUS_INVALID_IMAGE_NOT_MZ","The specified image file did not have the correct format: it did not have an initial MZ."),
        0xC0000130: ("STATUS_INVALID_IMAGE_PROTECT","The specified image file did not have the correct format: it did not have a proper e_lfarlc in the MZ header."),
        0xC0000131: ("STATUS_INVALID_IMAGE_WIN_16","The specified image file did not have the correct format: it appears to be a 16-bit Windows image."),
        0xC0000132: ("STATUS_LOGON_SERVER_CONFLICT","The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role."),
        0xC0000133: ("STATUS_TIME_DIFFERENCE_AT_DC","The time at the primary domain controller is different from the time at the backup domain controller or member server by too large an amount."),
        0xC0000134: ("STATUS_SYNCHRONIZATION_REQUIRED","The SAM database on a Windows Server is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required."),
        0xC0000135: ("STATUS_DLL_NOT_FOUND","{Unable To Locate Component} This application has failed to start because %hs was not found. Reinstalling the application may fix this problem."),
        0xC0000136: ("STATUS_OPEN_FAILED","The NtCreateFile API failed. This error should never be returned to an application; it is a place holder for the Windows LAN Manager Redirector to use in its internal error-mapping routines."),
        0xC0000137: ("STATUS_IO_PRIVILEGE_FAILED","{Privilege Failed} The I/O permissions for the process could not be changed."),
        0xC0000138: ("STATUS_ORDINAL_NOT_FOUND","{Ordinal Not Found} The ordinal %ld could not be located in the dynamic link library %hs."),
        0xC0000139: ("STATUS_ENTRYPOINT_NOT_FOUND","{Entry Point Not Found} The procedure entry point %hs could not be located in the dynamic link library %hs."),
        0xC000013A: ("STATUS_CONTROL_C_EXIT","{Application Exit by CTRL+C} The application terminated as a result of a CTRL+C."),
        0xC000013B: ("STATUS_LOCAL_DISCONNECT","{Virtual Circuit Closed} The network transport on your computer has closed a network connection. There may or may not be I/O requests outstanding."),
        0xC000013C: ("STATUS_REMOTE_DISCONNECT","{Virtual Circuit Closed} The network transport on a remote computer has closed a network connection. There may or may not be I/O requests outstanding."),
        0xC000013D: ("STATUS_REMOTE_RESOURCES","{Insufficient Resources on Remote Computer} The remote computer has insufficient resources to complete the network request. For example, the remote computer may not have enough available memory to carry out the request at this time."),
        0xC000013E: ("STATUS_LINK_FAILED","{Virtual Circuit Closed} An existing connection (virtual circuit) has been broken at the remote computer. There is probably something wrong with the network software protocol or the network hardware on the remote computer."),
        0xC000013F: ("STATUS_LINK_TIMEOUT","{Virtual Circuit Closed} The network transport on your computer has closed a network connection because it had to wait too long for a response from the remote computer."),
        0xC0000140: ("STATUS_INVALID_CONNECTION","The connection handle that was given to the transport was invalid."),
        0xC0000141: ("STATUS_INVALID_ADDRESS","The address handle that was given to the transport was invalid."),
        0xC0000142: ("STATUS_DLL_INIT_FAILED","{DLL Initialization Failed} Initialization of the dynamic link library %hs failed. The process is terminating abnormally."),
        0xC0000143: ("STATUS_MISSING_SYSTEMFILE","{Missing System File} The required system file %hs is bad or missing."),
        0xC0000144: ("STATUS_UNHANDLED_EXCEPTION","{Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx."),
        0xC0000145: ("STATUS_APP_INIT_FAILURE","{Application Error} The application failed to initialize properly (0x%lx). Click OK to terminate the application."),
        0xC0000146: ("STATUS_PAGEFILE_CREATE_FAILED","{Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld."),
        0xC0000147: ("STATUS_NO_PAGEFILE","{No Paging File Specified} No paging file was specified in the system configuration."),
        0xC0000148: ("STATUS_INVALID_LEVEL","{Incorrect System Call Level} An invalid level was passed into the specified system call."),
        0xC0000149: ("STATUS_WRONG_PASSWORD_CORE","{Incorrect Password to LAN Manager Server} You specified an incorrect password to a LAN Manager 2.x or MS-NET server."),
        0xC000014A: ("STATUS_ILLEGAL_FLOAT_CONTEXT","{EXCEPTION} A real-mode application issued a floating-point instruction and floating-point hardware is not present."),
        0xC000014B: ("STATUS_PIPE_BROKEN","The pipe operation has failed because the other end of the pipe has been closed."),
        0xC000014C: ("STATUS_REGISTRY_CORRUPT","{The Registry Is Corrupt} The structure of one of the files that contains registry data is corrupt; the image of the file in memory is corrupt; or the file could not be recovered because the alternate copy or log was absent or corrupt."),
        0xC000014D: ("STATUS_REGISTRY_IO_FAILED","An I/O operation initiated by the Registry failed and cannot be recovered. The registry could not read in, write out, or flush one of the files that contain the system's image of the registry."),
        0xC000014E: ("STATUS_NO_EVENT_PAIR","An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread."),
        0xC000014F: ("STATUS_UNRECOGNIZED_VOLUME","The volume does not contain a recognized file system. Be sure that all required file system drivers are loaded and that the volume is not corrupt."),
        0xC0000150: ("STATUS_SERIAL_NO_DEVICE_INITED","No serial device was successfully initialized. The serial driver will unload."),
        0xC0000151: ("STATUS_NO_SUCH_ALIAS","The specified local group does not exist."),
        0xC0000152: ("STATUS_MEMBER_NOT_IN_ALIAS","The specified account name is not a member of the group."),
        0xC0000153: ("STATUS_MEMBER_IN_ALIAS","The specified account name is already a member of the group."),
        0xC0000154: ("STATUS_ALIAS_EXISTS","The specified local group already exists."),
        0xC0000155: ("STATUS_LOGON_NOT_GRANTED","A requested type of logon (for example, interactive, network, and service) is not granted by the local security policy of the target system. Ask the system administrator to grant the necessary form of logon."),
        0xC0000156: ("STATUS_TOO_MANY_SECRETS","The maximum number of secrets that may be stored in a single system was exceeded. The length and number of secrets is limited to satisfy U.S. State Department export restrictions."),
        0xC0000157: ("STATUS_SECRET_TOO_LONG","The length of a secret exceeds the maximum allowable length. The length and number of secrets is limited to satisfy U.S. State Department export restrictions."),
        0xC0000158: ("STATUS_INTERNAL_DB_ERROR","The local security authority (LSA) database contains an internal inconsistency."),
        0xC0000159: ("STATUS_FULLSCREEN_MODE","The requested operation cannot be performed in full-screen mode."),
        0xC000015A: ("STATUS_TOO_MANY_CONTEXT_IDS","During a logon attempt, the user's security context accumulated too many security IDs. This is a very unusual situation. Remove the user from some global or local groups to reduce the number of security IDs to incorporate into the security context."),
        0xC000015B: ("STATUS_LOGON_TYPE_NOT_GRANTED","A user has requested a type of logon (for example, interactive or network) that has not been granted. An administrator has control over who may logon interactively and through the network."),
        0xC000015C: ("STATUS_NOT_REGISTRY_FILE","The system has attempted to load or restore a file into the registry, and the specified file is not in the format of a registry file."),
        0xC000015D: ("STATUS_NT_CROSS_ENCRYPTION_REQUIRED","An attempt was made to change a user password in the security account manager without providing the necessary Windows cross-encrypted password."),
        0xC000015E: ("STATUS_DOMAIN_CTRLR_CONFIG_ERROR","A Windows Server has an incorrect configuration."),
        0xC000015F: ("STATUS_FT_MISSING_MEMBER","An attempt was made to explicitly access the secondary copy of information via a device control to the fault tolerance driver and the secondary copy is not present in the system."),
        0xC0000160: ("STATUS_ILL_FORMED_SERVICE_ENTRY","A configuration registry node that represents a driver service entry was ill-formed and did not contain the required value entries."),
        0xC0000161: ("STATUS_ILLEGAL_CHARACTER","An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte. For the Unicode character set this includes the characters 0xFFFF and 0xFFFE."),
        0xC0000162: ("STATUS_UNMAPPABLE_CHARACTER","No mapping for the Unicode character exists in the target multibyte code page."),
        0xC0000163: ("STATUS_UNDEFINED_CHARACTER","The Unicode character is not defined in the Unicode character set that is installed on the system."),
        0xC0000164: ("STATUS_FLOPPY_VOLUME","The paging file cannot be created on a floppy disk."),
        0xC0000165: ("STATUS_FLOPPY_ID_MARK_NOT_FOUND","{Floppy Disk Error} While accessing a floppy disk, an ID address mark was not found."),
        0xC0000166: ("STATUS_FLOPPY_WRONG_CYLINDER","{Floppy Disk Error} While accessing a floppy disk, the track address from the sector ID field was found to be different from the track address that is maintained by the controller."),
        0xC0000167: ("STATUS_FLOPPY_UNKNOWN_ERROR","{Floppy Disk Error} The floppy disk controller reported an error that is not recognized by the floppy disk driver."),
        0xC0000168: ("STATUS_FLOPPY_BAD_REGISTERS","{Floppy Disk Error} While accessing a floppy-disk, the controller returned inconsistent results via its registers."),
        0xC0000169: ("STATUS_DISK_RECALIBRATE_FAILED","{Hard Disk Error} While accessing the hard disk, a recalibrate operation failed, even after retries."),
        0xC000016A: ("STATUS_DISK_OPERATION_FAILED","{Hard Disk Error} While accessing the hard disk, a disk operation failed even after retries."),
        0xC000016B: ("STATUS_DISK_RESET_FAILED","{Hard Disk Error} While accessing the hard disk, a disk controller reset was needed, but even that failed."),
        0xC000016C: ("STATUS_SHARED_IRQ_BUSY","An attempt was made to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened. Two concurrent opens of devices that share an IRQ and only work via interrupts is not supported for the particular bus type that the devices use."),
        0xC000016D: ("STATUS_FT_ORPHANING","{FT Orphaning} A disk that is part of a fault-tolerant volume can no longer be accessed."),
        0xC000016E: ("STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT","The basic input/output system (BIOS) failed to connect a system interrupt to the device or bus for which the device is connected."),
        0xC0000172: ("STATUS_PARTITION_FAILURE","The tape could not be partitioned."),
        0xC0000173: ("STATUS_INVALID_BLOCK_LENGTH","When accessing a new tape of a multi-volume partition, the current blocksize is incorrect."),
        0xC0000174: ("STATUS_DEVICE_NOT_PARTITIONED","The tape partition information could not be found when loading a tape."),
        0xC0000175: ("STATUS_UNABLE_TO_LOCK_MEDIA","An attempt to lock the eject media mechanism failed."),
        0xC0000176: ("STATUS_UNABLE_TO_UNLOAD_MEDIA","An attempt to unload media failed."),
        0xC0000177: ("STATUS_EOM_OVERFLOW","The physical end of tape was detected."),
        0xC0000178: ("STATUS_NO_MEDIA","{No Media} There is no media in the drive. Insert media into drive %hs."),
        0xC000017A: ("STATUS_NO_SUCH_MEMBER","A member could not be added to or removed from the local group because the member does not exist."),
        0xC000017B: ("STATUS_INVALID_MEMBER","A new member could not be added to a local group because the member has the wrong account type."),
        0xC000017C: ("STATUS_KEY_DELETED","An illegal operation was attempted on a registry key that has been marked for deletion."),
        0xC000017D: ("STATUS_NO_LOG_SPACE","The system could not allocate the required space in a registry log."),
        0xC000017E: ("STATUS_TOO_MANY_SIDS","Too many SIDs have been specified."),
        0xC000017F: ("STATUS_LM_CROSS_ENCRYPTION_REQUIRED","An attempt was made to change a user password in the security account manager without providing the necessary LM cross-encrypted password."),
        0xC0000180: ("STATUS_KEY_HAS_CHILDREN","An attempt was made to create a symbolic link in a registry key that already has subkeys or values."),
        0xC0000181: ("STATUS_CHILD_MUST_BE_VOLATILE","An attempt was made to create a stable subkey under a volatile parent key."),
        0xC0000182: ("STATUS_DEVICE_CONFIGURATION_ERROR","The I/O device is configured incorrectly or the configuration parameters to the driver are incorrect."),
        0xC0000183: ("STATUS_DRIVER_INTERNAL_ERROR","An error was detected between two drivers or within an I/O driver."),
        0xC0000184: ("STATUS_INVALID_DEVICE_STATE","The device is not in a valid state to perform this request."),
        0xC0000185: ("STATUS_IO_DEVICE_ERROR","The I/O device reported an I/O error."),
        0xC0000186: ("STATUS_DEVICE_PROTOCOL_ERROR","A protocol error was detected between the driver and the device."),
        0xC0000187: ("STATUS_BACKUP_CONTROLLER","This operation is only allowed for the primary domain controller of the domain."),
        0xC0000188: ("STATUS_LOG_FILE_FULL","The log file space is insufficient to support this operation."),
        0xC0000189: ("STATUS_TOO_LATE","A write operation was attempted to a volume after it was dismounted."),
        0xC000018A: ("STATUS_NO_TRUST_LSA_SECRET","The workstation does not have a trust secret for the primary domain in the local LSA database."),
        0xC000018B: ("STATUS_NO_TRUST_SAM_ACCOUNT","The SAM database on the Windows Server does not have a computer account for this workstation trust relationship."),
        0xC000018C: ("STATUS_TRUSTED_DOMAIN_FAILURE","The logon request failed because the trust relationship between the primary domain and the trusted domain failed."),
        0xC000018D: ("STATUS_TRUSTED_RELATIONSHIP_FAILURE","The logon request failed because the trust relationship between this workstation and the primary domain failed."),
        0xC000018E: ("STATUS_EVENTLOG_FILE_CORRUPT","The Eventlog log file is corrupt."),
        0xC000018F: ("STATUS_EVENTLOG_CANT_START","No Eventlog log file could be opened. The Eventlog service did not start."),
        0xC0000190: ("STATUS_TRUST_FAILURE","The network logon failed. This may be because the validation authority cannot be reached."),
        0xC0000191: ("STATUS_MUTANT_LIMIT_EXCEEDED","An attempt was made to acquire a mutant such that its maximum count would have been exceeded."),
        0xC0000192: ("STATUS_NETLOGON_NOT_STARTED","An attempt was made to logon, but the NetLogon service was not started."),
        0xC0000193: ("STATUS_ACCOUNT_EXPIRED","The user account has expired."),
        0xC0000194: ("STATUS_POSSIBLE_DEADLOCK","{EXCEPTION} Possible deadlock condition."),
        0xC0000195: ("STATUS_NETWORK_CREDENTIAL_CONFLICT","Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again."),
        0xC0000196: ("STATUS_REMOTE_SESSION_LIMIT","An attempt was made to establish a session to a network server, but there are already too many sessions established to that server."),
        0xC0000197: ("STATUS_EVENTLOG_FILE_CHANGED","The log file has changed between reads."),
        0xC0000198: ("STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT","The account used is an interdomain trust account. Use your global user account or local user account to access this server."),
        0xC0000199: ("STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT","The account used is a computer account. Use your global user account or local user account to access this server."),
        0xC000019A: ("STATUS_NOLOGON_SERVER_TRUST_ACCOUNT","The account used is a server trust account. Use your global user account or local user account to access this server."),
        0xC000019B: ("STATUS_DOMAIN_TRUST_INCONSISTENT","The name or SID of the specified domain is inconsistent with the trust information for that domain."),
        0xC000019C: ("STATUS_FS_DRIVER_REQUIRED","A volume has been accessed for which a file system driver is required that has not yet been loaded."),
        0xC000019D: ("STATUS_IMAGE_ALREADY_LOADED_AS_DLL","Indicates that the specified image is already loaded as a DLL."),
        0xC000019E: ("STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING","Short name settings may not be changed on this volume due to the global registry setting."),
        0xC000019F: ("STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME","Short names are not enabled on this volume."),
        0xC00001A0: ("STATUS_SECURITY_STREAM_IS_INCONSISTENT","The security stream for the given volume is in an inconsistent state. Please run CHKDSK on the volume."),
        0xC00001A1: ("STATUS_INVALID_LOCK_RANGE","A requested file lock operation cannot be processed due to an invalid byte range."),
        0xC00001A2: ("STATUS_INVALID_ACE_CONDITION","The specified access control entry (ACE) contains an invalid condition."),
        0xC00001A3: ("STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT","The subsystem needed to support the image type is not present."),
        0xC00001A4: ("STATUS_NOTIFICATION_GUID_ALREADY_DEFINED","The specified file already has a notification GUID associated with it."),
        0xC0000201: ("STATUS_NETWORK_OPEN_RESTRICTION","A remote open failed because the network open restrictions were not satisfied."),
        0xC0000202: ("STATUS_NO_USER_SESSION_KEY","There is no user session key for the specified logon session."),
        0xC0000203: ("STATUS_USER_SESSION_DELETED","The remote user session has been deleted."),
        0xC0000204: ("STATUS_RESOURCE_LANG_NOT_FOUND","Indicates the specified resource language ID cannot be found in the image file."),
        0xC0000205: ("STATUS_INSUFF_SERVER_RESOURCES","Insufficient server resources exist to complete the request."),
        0xC0000206: ("STATUS_INVALID_BUFFER_SIZE","The size of the buffer is invalid for the specified operation."),
        0xC0000207: ("STATUS_INVALID_ADDRESS_COMPONENT","The transport rejected the specified network address as invalid."),
        0xC0000208: ("STATUS_INVALID_ADDRESS_WILDCARD","The transport rejected the specified network address due to invalid use of a wildcard."),
        0xC0000209: ("STATUS_TOO_MANY_ADDRESSES","The transport address could not be opened because all the available addresses are in use."),
        0xC000020A: ("STATUS_ADDRESS_ALREADY_EXISTS","The transport address could not be opened because it already exists."),
        0xC000020B: ("STATUS_ADDRESS_CLOSED","The transport address is now closed."),
        0xC000020C: ("STATUS_CONNECTION_DISCONNECTED","The transport connection is now disconnected."),
        0xC000020D: ("STATUS_CONNECTION_RESET","The transport connection has been reset."),
        0xC000020E: ("STATUS_TOO_MANY_NODES","The transport cannot dynamically acquire any more nodes."),
        0xC000020F: ("STATUS_TRANSACTION_ABORTED","The transport aborted a pending transaction."),
        0xC0000210: ("STATUS_TRANSACTION_TIMED_OUT","The transport timed out a request that is waiting for a response."),
        0xC0000211: ("STATUS_TRANSACTION_NO_RELEASE","The transport did not receive a release for a pending response."),
        0xC0000212: ("STATUS_TRANSACTION_NO_MATCH","The transport did not find a transaction that matches the specific token."),
        0xC0000213: ("STATUS_TRANSACTION_RESPONDED","The transport had previously responded to a transaction request."),
        0xC0000214: ("STATUS_TRANSACTION_INVALID_ID","The transport does not recognize the specified transaction request ID."),
        0xC0000215: ("STATUS_TRANSACTION_INVALID_TYPE","The transport does not recognize the specified transaction request type."),
        0xC0000216: ("STATUS_NOT_SERVER_SESSION","The transport can only process the specified request on the server side of a session."),
        0xC0000217: ("STATUS_NOT_CLIENT_SESSION","The transport can only process the specified request on the client side of a session."),
        0xC0000218: ("STATUS_CANNOT_LOAD_REGISTRY_FILE","{Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable."),
        0xC0000219: ("STATUS_DEBUG_ATTACH_FAILED","{Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request. You may choose OK to terminate the process, or Cancel to ignore the error."),
        0xC000021A: ("STATUS_SYSTEM_PROCESS_TERMINATED","{Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down."),
        0xC000021B: ("STATUS_DATA_NOT_ACCEPTED","{Data Not Accepted} The TDI client could not handle the data received during an indication."),
        0xC000021C: ("STATUS_NO_BROWSER_SERVERS_FOUND","{Unable to Retrieve Browser Server List} The list of servers for this workgroup is not currently available."),
        0xC000021D: ("STATUS_VDM_HARD_ERROR","NTVDM encountered a hard error."),
        0xC000021E: ("STATUS_DRIVER_CANCEL_TIMEOUT","{Cancel Timeout} The driver %hs failed to complete a canceled I/O request in the allotted time."),
        0xC000021F: ("STATUS_REPLY_MESSAGE_MISMATCH","{Reply Message Mismatch} An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message."),
        0xC0000220: ("STATUS_MAPPED_ALIGNMENT","{Mapped View Alignment Incorrect} An attempt was made to map a view of a file, but either the specified base address or the offset into the file were not aligned on the proper allocation granularity."),
        0xC0000221: ("STATUS_IMAGE_CHECKSUM_MISMATCH","{Bad Image Checksum} The image %hs is possibly corrupt. The header checksum does not match the computed checksum."),
        0xC0000222: ("STATUS_LOST_WRITEBEHIND_DATA","{Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost. This error may be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere."),
        0xC0000223: ("STATUS_CLIENT_SERVER_PARAMETERS_INVALID","The parameters passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window."),
        0xC0000224: ("STATUS_PASSWORD_MUST_CHANGE","The user password must be changed before logging on the first time."),
        0xC0000225: ("STATUS_NOT_FOUND","The object was not found."),
        0xC0000226: ("STATUS_NOT_TINY_STREAM","The stream is not a tiny stream."),
        0xC0000227: ("STATUS_RECOVERY_FAILURE","A transaction recovery failed."),
        0xC0000228: ("STATUS_STACK_OVERFLOW_READ","The request must be handled by the stack overflow code."),
        0xC0000229: ("STATUS_FAIL_CHECK","A consistency check failed."),
        0xC000022A: ("STATUS_DUPLICATE_OBJECTID","The attempt to insert the ID in the index failed because the ID is already in the index."),
        0xC000022B: ("STATUS_OBJECTID_EXISTS","The attempt to set the object ID failed because the object already has an ID."),
        0xC000022C: ("STATUS_CONVERT_TO_LARGE","Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing oNode is moved or the extent stream is converted to a large stream."),
        0xC000022D: ("STATUS_RETRY","The request needs to be retried."),
        0xC000022E: ("STATUS_FOUND_OUT_OF_SCOPE","The attempt to find the object found an object on the volume that matches by ID; however, it is out of the scope of the handle that is used for the operation."),
        0xC000022F: ("STATUS_ALLOCATE_BUCKET","The bucket array must be grown. Retry the transaction after doing so."),
        0xC0000230: ("STATUS_PROPSET_NOT_FOUND","The specified property set does not exist on the object."),
        0xC0000231: ("STATUS_MARSHALL_OVERFLOW","The user/kernel marshaling buffer has overflowed."),
        0xC0000232: ("STATUS_INVALID_VARIANT","The supplied variant structure contains invalid data."),
        0xC0000233: ("STATUS_DOMAIN_CONTROLLER_NOT_FOUND","A domain controller for this domain was not found."),
        0xC0000234: ("STATUS_ACCOUNT_LOCKED_OUT","The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested."),
        0xC0000235: ("STATUS_HANDLE_NOT_CLOSABLE","NtClose was called on a handle that was protected from close via NtSetInformationObject."),
        0xC0000236: ("STATUS_CONNECTION_REFUSED","The transport-connection attempt was refused by the remote system."),
        0xC0000237: ("STATUS_GRACEFUL_DISCONNECT","The transport connection was gracefully closed."),
        0xC0000238: ("STATUS_ADDRESS_ALREADY_ASSOCIATED","The transport endpoint already has an address associated with it."),
        0xC0000239: ("STATUS_ADDRESS_NOT_ASSOCIATED","An address has not yet been associated with the transport endpoint."),
        0xC000023A: ("STATUS_CONNECTION_INVALID","An operation was attempted on a nonexistent transport connection."),
        0xC000023B: ("STATUS_CONNECTION_ACTIVE","An invalid operation was attempted on an active transport connection."),
        0xC000023C: ("STATUS_NETWORK_UNREACHABLE","The remote network is not reachable by the transport."),
        0xC000023D: ("STATUS_HOST_UNREACHABLE","The remote system is not reachable by the transport."),
        0xC000023E: ("STATUS_PROTOCOL_UNREACHABLE","The remote system does not support the transport protocol."),
        0xC000023F: ("STATUS_PORT_UNREACHABLE","No service is operating at the destination port of the transport on the remote system."),
        0xC0000240: ("STATUS_REQUEST_ABORTED","The request was aborted."),
        0xC0000241: ("STATUS_CONNECTION_ABORTED","The transport connection was aborted by the local system."),
        0xC0000242: ("STATUS_BAD_COMPRESSION_BUFFER","The specified buffer contains ill-formed data."),
        0xC0000243: ("STATUS_USER_MAPPED_FILE","The requested operation cannot be performed on a file with a user mapped section open."),
        0xC0000244: ("STATUS_AUDIT_FAILED","{Audit Failed} An attempt to generate a security audit failed."),
        0xC0000245: ("STATUS_TIMER_RESOLUTION_NOT_SET","The timer resolution was not previously set by the current process."),
        0xC0000246: ("STATUS_CONNECTION_COUNT_LIMIT","A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached."),
        0xC0000247: ("STATUS_LOGIN_TIME_RESTRICTION","Attempting to log on during an unauthorized time of day for this account."),
        0xC0000248: ("STATUS_LOGIN_WKSTA_RESTRICTION","The account is not authorized to log on from this station."),
        0xC0000249: ("STATUS_IMAGE_MP_UP_MISMATCH","{UP/MP Image Mismatch} The image %hs has been modified for use on a uniprocessor system, but you are running it on a multiprocessor machine. Reinstall the image file."),
        0xC0000250: ("STATUS_INSUFFICIENT_LOGON_INFO","There is insufficient account information to log you on."),
        0xC0000251: ("STATUS_BAD_DLL_ENTRYPOINT","{Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly. The stack pointer has been left in an inconsistent state. The entry point should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO may cause the application to operate incorrectly."),
        0xC0000252: ("STATUS_BAD_SERVICE_ENTRYPOINT","{Invalid Service Callback Entrypoint} The %hs service is not written correctly. The stack pointer has been left in an inconsistent state. The callback entry point should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process may operate incorrectly."),
        0xC0000253: ("STATUS_LPC_REPLY_LOST","The server received the messages but did not send a reply."),
        0xC0000254: ("STATUS_IP_ADDRESS_CONFLICT1","There is an IP address conflict with another system on the network."),
        0xC0000255: ("STATUS_IP_ADDRESS_CONFLICT2","There is an IP address conflict with another system on the network."),
        0xC0000256: ("STATUS_REGISTRY_QUOTA_LIMIT","{Low On Registry Space} The system has reached the maximum size that is allowed for the system part of the registry. Additional storage requests will be ignored."),
        0xC0000257: ("STATUS_PATH_NOT_COVERED","The contacted server does not support the indicated part of the DFS namespace."),
        0xC0000258: ("STATUS_NO_CALLBACK_ACTIVE","A callback return system service cannot be executed when no callback is active."),
        0xC0000259: ("STATUS_LICENSE_QUOTA_EXCEEDED","The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because the service has already accepted the maximum number of connections."),
        0xC000025A: ("STATUS_PWD_TOO_SHORT","The password provided is too short to meet the policy of your user account. Choose a longer password."),
        0xC000025B: ("STATUS_PWD_TOO_RECENT","The policy of your user account does not allow you to change passwords too frequently. This is done to prevent users from changing back to a familiar, but potentially discovered, password. If you feel your password has been compromised, contact your administrator immediately to have a new one assigned."),
        0xC000025C: ("STATUS_PWD_HISTORY_CONFLICT","You have attempted to change your password to one that you have used in the past. The policy of your user account does not allow this. Select a password that you have not previously used."),
        0xC000025E: ("STATUS_PLUGPLAY_NO_DEVICE","You have attempted to load a legacy device driver while its device instance had been disabled."),
        0xC000025F: ("STATUS_UNSUPPORTED_COMPRESSION","The specified compression format is unsupported."),
        0xC0000260: ("STATUS_INVALID_HW_PROFILE","The specified hardware profile configuration is invalid."),
        0xC0000261: ("STATUS_INVALID_PLUGPLAY_DEVICE_PATH","The specified Plug and Play registry device path is invalid."),
        0xC0000262: ("STATUS_DRIVER_ORDINAL_NOT_FOUND","{Driver Entry Point Not Found} The %hs device driver could not locate the ordinal %ld in driver %hs."),
        0xC0000263: ("STATUS_DRIVER_ENTRYPOINT_NOT_FOUND","{Driver Entry Point Not Found} The %hs device driver could not locate the entry point %hs in driver %hs."),
        0xC0000264: ("STATUS_RESOURCE_NOT_OWNED","{Application Error} The application attempted to release a resource it did not own. Click OK to terminate the application."),
        0xC0000265: ("STATUS_TOO_MANY_LINKS","An attempt was made to create more links on a file than the file system supports."),
        0xC0000266: ("STATUS_QUOTA_LIST_INCONSISTENT","The specified quota list is internally inconsistent with its descriptor."),
        0xC0000267: ("STATUS_FILE_IS_OFFLINE","The specified file has been relocated to offline storage."),
        0xC0000268: ("STATUS_EVALUATION_EXPIRATION","{Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shutdown in 1 hour. To restore access to this installation of Windows, upgrade this installation by using a licensed distribution of this product."),
        0xC0000269: ("STATUS_ILLEGAL_DLL_RELOCATION","{Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly. The relocation occurred because the DLL %hs occupied an address range that is reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL."),
        0xC000026A: ("STATUS_LICENSE_VIOLATION","{License Violation} The system has detected tampering with your registered product type. This is a violation of your software license. Tampering with the product type is not permitted."),
        0xC000026B: ("STATUS_DLL_INIT_FAILED_LOGOFF","{DLL Initialization Failed} The application failed to initialize because the window station is shutting down."),
        0xC000026C: ("STATUS_DRIVER_UNABLE_TO_LOAD","{Unable to Load Device Driver} %hs device driver could not be loaded. Error Status was 0x%x."),
        0xC000026D: ("STATUS_DFS_UNAVAILABLE","DFS is unavailable on the contacted server."),
        0xC000026E: ("STATUS_VOLUME_DISMOUNTED","An operation was attempted to a volume after it was dismounted."),
        0xC000026F: ("STATUS_WX86_INTERNAL_ERROR","An internal error occurred in the Win32 x86 emulation subsystem."),
        0xC0000270: ("STATUS_WX86_FLOAT_STACK_CHECK","Win32 x86 emulation subsystem floating-point stack check."),
        0xC0000271: ("STATUS_VALIDATE_CONTINUE","The validation process needs to continue on to the next step."),
        0xC0000272: ("STATUS_NO_MATCH","There was no match for the specified key in the index."),
        0xC0000273: ("STATUS_NO_MORE_MATCHES","There are no more matches for the current index enumeration."),
        0xC0000275: ("STATUS_NOT_A_REPARSE_POINT","The NTFS file or directory is not a reparse point."),
        0xC0000276: ("STATUS_IO_REPARSE_TAG_INVALID","The Windows I/O reparse tag passed for the NTFS reparse point is invalid."),
        0xC0000277: ("STATUS_IO_REPARSE_TAG_MISMATCH","The Windows I/O reparse tag does not match the one that is in the NTFS reparse point."),
        0xC0000278: ("STATUS_IO_REPARSE_DATA_INVALID","The user data passed for the NTFS reparse point is invalid."),
        0xC0000279: ("STATUS_IO_REPARSE_TAG_NOT_HANDLED","The layered file system driver for this I/O tag did not handle it when needed."),
        0xC0000280: ("STATUS_REPARSE_POINT_NOT_RESOLVED","The NTFS symbolic link could not be resolved even though the initial file name is valid."),
        0xC0000281: ("STATUS_DIRECTORY_IS_A_REPARSE_POINT","The NTFS directory is a reparse point."),
        0xC0000282: ("STATUS_RANGE_LIST_CONFLICT","The range could not be added to the range list because of a conflict."),
        0xC0000283: ("STATUS_SOURCE_ELEMENT_EMPTY","The specified medium changer source element contains no media."),
        0xC0000284: ("STATUS_DESTINATION_ELEMENT_FULL","The specified medium changer destination element already contains media."),
        0xC0000285: ("STATUS_ILLEGAL_ELEMENT_ADDRESS","The specified medium changer element does not exist."),
        0xC0000286: ("STATUS_MAGAZINE_NOT_PRESENT","The specified element is contained in a magazine that is no longer present."),
        0xC0000287: ("STATUS_REINITIALIZATION_NEEDED","The device requires re-initialization due to hardware errors."),
        0xC000028A: ("STATUS_ENCRYPTION_FAILED","The file encryption attempt failed."),
        0xC000028B: ("STATUS_DECRYPTION_FAILED","The file decryption attempt failed."),
        0xC000028C: ("STATUS_RANGE_NOT_FOUND","The specified range could not be found in the range list."),
        0xC000028D: ("STATUS_NO_RECOVERY_POLICY","There is no encryption recovery policy configured for this system."),
        0xC000028E: ("STATUS_NO_EFS","The required encryption driver is not loaded for this system."),
        0xC000028F: ("STATUS_WRONG_EFS","The file was encrypted with a different encryption driver than is currently loaded."),
        0xC0000290: ("STATUS_NO_USER_KEYS","There are no EFS keys defined for the user."),
        0xC0000291: ("STATUS_FILE_NOT_ENCRYPTED","The specified file is not encrypted."),
        0xC0000292: ("STATUS_NOT_EXPORT_FORMAT","The specified file is not in the defined EFS export format."),
        0xC0000293: ("STATUS_FILE_ENCRYPTED","The specified file is encrypted and the user does not have the ability to decrypt it."),
        0xC0000295: ("STATUS_WMI_GUID_NOT_FOUND","The GUID passed was not recognized as valid by a WMI data provider."),
        0xC0000296: ("STATUS_WMI_INSTANCE_NOT_FOUND","The instance name passed was not recognized as valid by a WMI data provider."),
        0xC0000297: ("STATUS_WMI_ITEMID_NOT_FOUND","The data item ID passed was not recognized as valid by a WMI data provider."),
        0xC0000298: ("STATUS_WMI_TRY_AGAIN","The WMI request could not be completed and should be retried."),
        0xC0000299: ("STATUS_SHARED_POLICY","The policy object is shared and can only be modified at the root."),
        0xC000029A: ("STATUS_POLICY_OBJECT_NOT_FOUND","The policy object does not exist when it should."),
        0xC000029B: ("STATUS_POLICY_ONLY_IN_DS","The requested policy information only lives in the Ds."),
        0xC000029C: ("STATUS_VOLUME_NOT_UPGRADED","The volume must be upgraded to enable this feature."),
        0xC000029D: ("STATUS_REMOTE_STORAGE_NOT_ACTIVE","The remote storage service is not operational at this time."),
        0xC000029E: ("STATUS_REMOTE_STORAGE_MEDIA_ERROR","The remote storage service encountered a media error."),
        0xC000029F: ("STATUS_NO_TRACKING_SERVICE","The tracking (workstation) service is not running."),
        0xC00002A0: ("STATUS_SERVER_SID_MISMATCH","The server process is running under a SID that is different from the SID that is required by client."),
        0xC00002A1: ("STATUS_DS_NO_ATTRIBUTE_OR_VALUE","The specified directory service attribute or value does not exist."),
        0xC00002A2: ("STATUS_DS_INVALID_ATTRIBUTE_SYNTAX","The attribute syntax specified to the directory service is invalid."),
        0xC00002A3: ("STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED","The attribute type specified to the directory service is not defined."),
        0xC00002A4: ("STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS","The specified directory service attribute or value already exists."),
        0xC00002A5: ("STATUS_DS_BUSY","The directory service is busy."),
        0xC00002A6: ("STATUS_DS_UNAVAILABLE","The directory service is unavailable."),
        0xC00002A7: ("STATUS_DS_NO_RIDS_ALLOCATED","The directory service was unable to allocate a relative identifier."),
        0xC00002A8: ("STATUS_DS_NO_MORE_RIDS","The directory service has exhausted the pool of relative identifiers."),
        0xC00002A9: ("STATUS_DS_INCORRECT_ROLE_OWNER","The requested operation could not be performed because the directory service is not the master for that type of operation."),
        0xC00002AA: ("STATUS_DS_RIDMGR_INIT_ERROR","The directory service was unable to initialize the subsystem that allocates relative identifiers."),
        0xC00002AB: ("STATUS_DS_OBJ_CLASS_VIOLATION","The requested operation did not satisfy one or more constraints that are associated with the class of the object."),
        0xC00002AC: ("STATUS_DS_CANT_ON_NON_LEAF","The directory service can perform the requested operation only on a leaf object."),
        0xC00002AD: ("STATUS_DS_CANT_ON_RDN","The directory service cannot perform the requested operation on the Relatively Defined Name (RDN) attribute of an object."),
        0xC00002AE: ("STATUS_DS_CANT_MOD_OBJ_CLASS","The directory service detected an attempt to modify the object class of an object."),
        0xC00002AF: ("STATUS_DS_CROSS_DOM_MOVE_FAILED","An error occurred while performing a cross domain move operation."),
        0xC00002B0: ("STATUS_DS_GC_NOT_AVAILABLE","Unable to contact the global catalog server."),
        0xC00002B1: ("STATUS_DIRECTORY_SERVICE_REQUIRED","The requested operation requires a directory service, and none was available."),
        0xC00002B2: ("STATUS_REPARSE_ATTRIBUTE_CONFLICT","The reparse attribute cannot be set because it is incompatible with an existing attribute."),
        0xC00002B3: ("STATUS_CANT_ENABLE_DENY_ONLY","A group marked \"use for deny only\" cannot be enabled."),
        0xC00002B4: ("STATUS_FLOAT_MULTIPLE_FAULTS","{EXCEPTION} Multiple floating-point faults."),
        0xC00002B5: ("STATUS_FLOAT_MULTIPLE_TRAPS","{EXCEPTION} Multiple floating-point traps."),
        0xC00002B6: ("STATUS_DEVICE_REMOVED","The device has been removed."),
        0xC00002B7: ("STATUS_JOURNAL_DELETE_IN_PROGRESS","The volume change journal is being deleted."),
        0xC00002B8: ("STATUS_JOURNAL_NOT_ACTIVE","The volume change journal is not active."),
        0xC00002B9: ("STATUS_NOINTERFACE","The requested interface is not supported."),
        0xC00002C1: ("STATUS_DS_ADMIN_LIMIT_EXCEEDED","A directory service resource limit has been exceeded."),
        0xC00002C2: ("STATUS_DRIVER_FAILED_SLEEP","{System Standby Failed} The driver %hs does not support standby mode. Updating this driver may allow the system to go to standby mode."),
        0xC00002C3: ("STATUS_MUTUAL_AUTHENTICATION_FAILED","Mutual Authentication failed. The server password is out of date at the domain controller."),
        0xC00002C4: ("STATUS_CORRUPT_SYSTEM_FILE","The system file %1 has become corrupt and has been replaced."),
        0xC00002C5: ("STATUS_DATATYPE_MISALIGNMENT_ERROR","{EXCEPTION} Alignment Error A data type misalignment error was detected in a load or store instruction."),
        0xC00002C6: ("STATUS_WMI_READ_ONLY","The WMI data item or data block is read-only."),
        0xC00002C7: ("STATUS_WMI_SET_FAILURE","The WMI data item or data block could not be changed."),
        0xC00002C8: ("STATUS_COMMITMENT_MINIMUM","{Virtual Memory Minimum Too Low} Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file. During this process, memory requests for some applications may be denied. For more information, see Help."),
        0xC00002C9: ("STATUS_REG_NAT_CONSUMPTION","{EXCEPTION} Register NaT consumption faults. A NaT value is consumed on a non-speculative instruction."),
        0xC00002CA: ("STATUS_TRANSPORT_FULL","The transport element of the medium changer contains media, which is causing the operation to fail."),
        0xC00002CB: ("STATUS_DS_SAM_INIT_FAILURE","Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information."),
        0xC00002CC: ("STATUS_ONLY_IF_CONNECTED","This operation is supported only when you are connected to the server."),
        0xC00002CD: ("STATUS_DS_SENSITIVE_GROUP_VIOLATION","Only an administrator can modify the membership list of an administrative group."),
        0xC00002CE: ("STATUS_PNP_RESTART_ENUMERATION","A device was removed so enumeration must be restarted."),
        0xC00002CF: ("STATUS_JOURNAL_ENTRY_DELETED","The journal entry has been deleted from the journal."),
        0xC00002D0: ("STATUS_DS_CANT_MOD_PRIMARYGROUPID","Cannot change the primary group ID of a domain controller account."),
        0xC00002D1: ("STATUS_SYSTEM_IMAGE_BAD_SIGNATURE","{Fatal System Error} The system image %s is not properly signed. The file has been replaced with the signed file. The system has been shut down."),
        0xC00002D2: ("STATUS_PNP_REBOOT_REQUIRED","The device will not start without a reboot."),
        0xC00002D3: ("STATUS_POWER_STATE_INVALID","The power state of the current device cannot support this request."),
        0xC00002D4: ("STATUS_DS_INVALID_GROUP_TYPE","The specified group type is invalid."),
        0xC00002D5: ("STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN","In a mixed domain, no nesting of a global group if the group is security enabled."),
        0xC00002D6: ("STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN","In a mixed domain, cannot nest local groups with other local groups, if the group is security enabled."),
        0xC00002D7: ("STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER","A global group cannot have a local group as a member."),
        0xC00002D8: ("STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER","A global group cannot have a universal group as a member."),
        0xC00002D9: ("STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER","A universal group cannot have a local group as a member."),
        0xC00002DA: ("STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER","A global group cannot have a cross-domain member."),
        0xC00002DB: ("STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER","A local group cannot have another cross-domain local group as a member."),
        0xC00002DC: ("STATUS_DS_HAVE_PRIMARY_MEMBERS","Cannot change to a security-disabled group because primary members are in this group."),
        0xC00002DD: ("STATUS_WMI_NOT_SUPPORTED","The WMI operation is not supported by the data block or method."),
        0xC00002DE: ("STATUS_INSUFFICIENT_POWER","There is not enough power to complete the requested operation."),
        0xC00002DF: ("STATUS_SAM_NEED_BOOTKEY_PASSWORD","The Security Accounts Manager needs to get the boot password."),
        0xC00002E0: ("STATUS_SAM_NEED_BOOTKEY_FLOPPY","The Security Accounts Manager needs to get the boot key from the floppy disk."),
        0xC00002E1: ("STATUS_DS_CANT_START","The directory service cannot start."),
        0xC00002E2: ("STATUS_DS_INIT_FAILURE","The directory service could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information."),
        0xC00002E3: ("STATUS_SAM_INIT_FAILURE","The Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Safe Mode. Check the event log for more detailed information."),
        0xC00002E4: ("STATUS_DS_GC_REQUIRED","The requested operation can be performed only on a global catalog server."),
        0xC00002E5: ("STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY","A local group can only be a member of other local groups in the same domain."),
        0xC00002E6: ("STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS","Foreign security principals cannot be members of universal groups."),
        0xC00002E7: ("STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED","Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased."),
        0xC00002E9: ("STATUS_CURRENT_DOMAIN_NOT_ALLOWED","This operation cannot be performed on the current domain."),
        0xC00002EA: ("STATUS_CANNOT_MAKE","The directory or file cannot be created."),
        0xC00002EB: ("STATUS_SYSTEM_SHUTDOWN","The system is in the process of shutting down."),
        0xC00002EC: ("STATUS_DS_INIT_FAILURE_CONSOLE","Directory Services could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system. You can use the recovery console to diagnose the system further."),
        0xC00002ED: ("STATUS_DS_SAM_INIT_FAILURE_CONSOLE","Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system. You can use the recovery console to diagnose the system further."),
        0xC00002EE: ("STATUS_UNFINISHED_CONTEXT_DELETED","A security context was deleted before the context was completed. This is considered a logon failure."),
        0xC00002EF: ("STATUS_NO_TGT_REPLY","The client is trying to negotiate a context and the server requires user-to-user but did not send a TGT reply."),
        0xC00002F0: ("STATUS_OBJECTID_NOT_FOUND","An object ID was not found in the file."),
        0xC00002F1: ("STATUS_NO_IP_ADDRESSES","Unable to accomplish the requested task because the local machine does not have any IP addresses."),
        0xC00002F2: ("STATUS_WRONG_CREDENTIAL_HANDLE","The supplied credential handle does not match the credential that is associated with the security context."),
        0xC00002F3: ("STATUS_CRYPTO_SYSTEM_INVALID","The crypto system or checksum function is invalid because a required function is unavailable."),
        0xC00002F4: ("STATUS_MAX_REFERRALS_EXCEEDED","The number of maximum ticket referrals has been exceeded."),
        0xC00002F5: ("STATUS_MUST_BE_KDC","The local machine must be a Kerberos KDC (domain controller) and it is not."),
        0xC00002F6: ("STATUS_STRONG_CRYPTO_NOT_SUPPORTED","The other end of the security negotiation requires strong crypto but it is not supported on the local machine."),
        0xC00002F7: ("STATUS_TOO_MANY_PRINCIPALS","The KDC reply contained more than one principal name."),
        0xC00002F8: ("STATUS_NO_PA_DATA","Expected to find PA data for a hint of what etype to use, but it was not found."),
        0xC00002F9: ("STATUS_PKINIT_NAME_MISMATCH","The client certificate does not contain a valid UPN, or does not match the client name in the logon request. Contact your administrator."),
        0xC00002FA: ("STATUS_SMARTCARD_LOGON_REQUIRED","Smart card logon is required and was not used."),
        0xC00002FB: ("STATUS_KDC_INVALID_REQUEST","An invalid request was sent to the KDC."),
        0xC00002FC: ("STATUS_KDC_UNABLE_TO_REFER","The KDC was unable to generate a referral for the service requested."),
        0xC00002FD: ("STATUS_KDC_UNKNOWN_ETYPE","The encryption type requested is not supported by the KDC."),
        0xC00002FE: ("STATUS_SHUTDOWN_IN_PROGRESS","A system shutdown is in progress."),
        0xC00002FF: ("STATUS_SERVER_SHUTDOWN_IN_PROGRESS","The server machine is shutting down."),
        0xC0000300: ("STATUS_NOT_SUPPORTED_ON_SBS","This operation is not supported on a computer running Windows Server 2003 for Small Business Server."),
        0xC0000301: ("STATUS_WMI_GUID_DISCONNECTED","The WMI GUID is no longer available."),
        0xC0000302: ("STATUS_WMI_ALREADY_DISABLED","Collection or events for the WMI GUID is already disabled."),
        0xC0000303: ("STATUS_WMI_ALREADY_ENABLED","Collection or events for the WMI GUID is already enabled."),
        0xC0000304: ("STATUS_MFT_TOO_FRAGMENTED","The master file table on the volume is too fragmented to complete this operation."),
        0xC0000305: ("STATUS_COPY_PROTECTION_FAILURE","Copy protection failure."),
        0xC0000306: ("STATUS_CSS_AUTHENTICATION_FAILURE","Copy protection error-DVD CSS Authentication failed."),
        0xC0000307: ("STATUS_CSS_KEY_NOT_PRESENT","Copy protection error-The specified sector does not contain a valid key."),
        0xC0000308: ("STATUS_CSS_KEY_NOT_ESTABLISHED","Copy protection error-DVD session key not established."),
        0xC0000309: ("STATUS_CSS_SCRAMBLED_SECTOR","Copy protection error-The read failed because the sector is encrypted."),
        0xC000030A: ("STATUS_CSS_REGION_MISMATCH","Copy protection error-The region of the specified DVD does not correspond to the region setting of the drive."),
        0xC000030B: ("STATUS_CSS_RESETS_EXHAUSTED","Copy protection error-The region setting of the drive may be permanent."),
        0xC0000320: ("STATUS_PKINIT_FAILURE","The Kerberos protocol encountered an error while validating the KDC certificate during smart card logon. There is more information in the system event log."),
        0xC0000321: ("STATUS_SMARTCARD_SUBSYSTEM_FAILURE","The Kerberos protocol encountered an error while attempting to use the smart card subsystem."),
        0xC0000322: ("STATUS_NO_KERB_KEY","The target server does not have acceptable Kerberos credentials."),
        0xC0000350: ("STATUS_HOST_DOWN","The transport determined that the remote system is down."),
        0xC0000351: ("STATUS_UNSUPPORTED_PREAUTH","An unsupported pre-authentication mechanism was presented to the Kerberos package."),
        0xC0000352: ("STATUS_EFS_ALG_BLOB_TOO_BIG","The encryption algorithm that is used on the source file needs a bigger key buffer than the one that is used on the destination file."),
        0xC0000353: ("STATUS_PORT_NOT_SET","An attempt to remove a processes DebugPort was made, but a port was not already associated with the process."),
        0xC0000354: ("STATUS_DEBUGGER_INACTIVE","An attempt to do an operation on a debug port failed because the port is in the process of being deleted."),
        0xC0000355: ("STATUS_DS_VERSION_CHECK_FAILURE","This version of Windows is not compatible with the behavior version of the directory forest, domain, or domain controller."),
        0xC0000356: ("STATUS_AUDITING_DISABLED","The specified event is currently not being audited."),
        0xC0000357: ("STATUS_PRENT4_MACHINE_ACCOUNT","The machine account was created prior to Windows NT 4.0. The account needs to be recreated."),
        0xC0000358: ("STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER","An account group cannot have a universal group as a member."),
        0xC0000359: ("STATUS_INVALID_IMAGE_WIN_32","The specified image file did not have the correct format; it appears to be a 32-bit Windows image."),
        0xC000035A: ("STATUS_INVALID_IMAGE_WIN_64","The specified image file did not have the correct format; it appears to be a 64-bit Windows image."),
        0xC000035B: ("STATUS_BAD_BINDINGS","The client's supplied SSPI channel bindings were incorrect."),
        0xC000035C: ("STATUS_NETWORK_SESSION_EXPIRED","The client session has expired; so the client must re-authenticate to continue accessing the remote resources."),
        0xC000035D: ("STATUS_APPHELP_BLOCK","The AppHelp dialog box canceled; thus preventing the application from starting."),
        0xC000035E: ("STATUS_ALL_SIDS_FILTERED","The SID filtering operation removed all SIDs."),
        0xC000035F: ("STATUS_NOT_SAFE_MODE_DRIVER","The driver was not loaded because the system is starting in safe mode."),
        0xC0000361: ("STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT","Access to %1 has been restricted by your Administrator by the default software restriction policy level."),
        0xC0000362: ("STATUS_ACCESS_DISABLED_BY_POLICY_PATH","Access to %1 has been restricted by your Administrator by location with policy rule %2 placed on path %3."),
        0xC0000363: ("STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER","Access to %1 has been restricted by your Administrator by software publisher policy."),
        0xC0000364: ("STATUS_ACCESS_DISABLED_BY_POLICY_OTHER","Access to %1 has been restricted by your Administrator by policy rule %2."),
        0xC0000365: ("STATUS_FAILED_DRIVER_ENTRY","The driver was not loaded because it failed its initialization call."),
        0xC0000366: ("STATUS_DEVICE_ENUMERATION_ERROR","The device encountered an error while applying power or reading the device configuration. This may be caused by a failure of your hardware or by a poor connection."),
        0xC0000368: ("STATUS_MOUNT_POINT_NOT_RESOLVED","The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached."),
        0xC0000369: ("STATUS_INVALID_DEVICE_OBJECT_PARAMETER","The device object parameter is either not a valid device object or is not attached to the volume that is specified by the file name."),
        0xC000036A: ("STATUS_MCA_OCCURED","A machine check error has occurred. Check the system event log for additional information."),
        0xC000036B: ("STATUS_DRIVER_BLOCKED_CRITICAL","Driver %2 has been blocked from loading."),
        0xC000036C: ("STATUS_DRIVER_BLOCKED","Driver %2 has been blocked from loading."),
        0xC000036D: ("STATUS_DRIVER_DATABASE_ERROR","There was error [%2] processing the driver database."),
        0xC000036E: ("STATUS_SYSTEM_HIVE_TOO_LARGE","System hive size has exceeded its limit."),
        0xC000036F: ("STATUS_INVALID_IMPORT_OF_NON_DLL","A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image."),
        0xC0000371: ("STATUS_NO_SECRETS","The local account store does not contain secret material for the specified account."),
        0xC0000372: ("STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY","Access to %1 has been restricted by your Administrator by policy rule %2."),
        0xC0000373: ("STATUS_FAILED_STACK_SWITCH","The system was not able to allocate enough memory to perform a stack switch."),
        0xC0000374: ("STATUS_HEAP_CORRUPTION","A heap has been corrupted."),
        0xC0000380: ("STATUS_SMARTCARD_WRONG_PIN","An incorrect PIN was presented to the smart card."),
        0xC0000381: ("STATUS_SMARTCARD_CARD_BLOCKED","The smart card is blocked."),
        0xC0000382: ("STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED","No PIN was presented to the smart card."),
        0xC0000383: ("STATUS_SMARTCARD_NO_CARD","No smart card is available."),
        0xC0000384: ("STATUS_SMARTCARD_NO_KEY_CONTAINER","The requested key container does not exist on the smart card."),
        0xC0000385: ("STATUS_SMARTCARD_NO_CERTIFICATE","The requested certificate does not exist on the smart card."),
        0xC0000386: ("STATUS_SMARTCARD_NO_KEYSET","The requested keyset does not exist."),
        0xC0000387: ("STATUS_SMARTCARD_IO_ERROR","A communication error with the smart card has been detected."),
        0xC0000388: ("STATUS_DOWNGRADE_DETECTED","The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you."),
        0xC0000389: ("STATUS_SMARTCARD_CERT_REVOKED","The smart card certificate used for authentication has been revoked. Contact your system administrator. There may be additional information in the event log."),
        0xC000038A: ("STATUS_ISSUING_CA_UNTRUSTED","An untrusted certificate authority was detected while processing the smart card certificate that is used for authentication. Contact your system administrator."),
        0xC000038B: ("STATUS_REVOCATION_OFFLINE_C","The revocation status of the smart card certificate that is used for authentication could not be determined. Contact your system administrator."),
        0xC000038C: ("STATUS_PKINIT_CLIENT_FAILURE","The smart card certificate used for authentication was not trusted. Contact your system administrator."),
        0xC000038D: ("STATUS_SMARTCARD_CERT_EXPIRED","The smart card certificate used for authentication has expired. Contact your system administrator."),
        0xC000038E: ("STATUS_DRIVER_FAILED_PRIOR_UNLOAD","The driver could not be loaded because a previous version of the driver is still in memory."),
        0xC000038F: ("STATUS_SMARTCARD_SILENT_CONTEXT","The smart card provider could not perform the action because the context was acquired as silent."),
        0xC0000401: ("STATUS_PER_USER_TRUST_QUOTA_EXCEEDED","The delegated trust creation quota of the current user has been exceeded."),
        0xC0000402: ("STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED","The total delegated trust creation quota has been exceeded."),
        0xC0000403: ("STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED","The delegated trust deletion quota of the current user has been exceeded."),
        0xC0000404: ("STATUS_DS_NAME_NOT_UNIQUE","The requested name already exists as a unique identifier."),
        0xC0000405: ("STATUS_DS_DUPLICATE_ID_FOUND","The requested object has a non-unique identifier and cannot be retrieved."),
        0xC0000406: ("STATUS_DS_GROUP_CONVERSION_ERROR","The group cannot be converted due to attribute restrictions on the requested group type."),
        0xC0000407: ("STATUS_VOLSNAP_PREPARE_HIBERNATE","{Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service prepares volume %hs for hibernation."),
        0xC0000408: ("STATUS_USER2USER_REQUIRED","Kerberos sub-protocol User2User is required."),
        0xC0000409: ("STATUS_STACK_BUFFER_OVERRUN","The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application."),
        0xC000040A: ("STATUS_NO_S4U_PROT_SUPPORT","The Kerberos subsystem encountered an error. A service for user protocol request was made against a domain controller which does not support service for user."),
        0xC000040B: ("STATUS_CROSSREALM_DELEGATION_FAILURE","An attempt was made by this server to make a Kerberos constrained delegation request for a target that is outside the server realm. This action is not supported and the resulting error indicates a misconfiguration on the allowed-to-delegate-to list for this server. Contact your administrator."),
        0xC000040C: ("STATUS_REVOCATION_OFFLINE_KDC","The revocation status of the domain controller certificate used for smart card authentication could not be determined. There is additional information in the system event log. Contact your system administrator."),
        0xC000040D: ("STATUS_ISSUING_CA_UNTRUSTED_KDC","An untrusted certificate authority was detected while processing the domain controller certificate used for authentication. There is additional information in the system event log. Contact your system administrator."),
        0xC000040E: ("STATUS_KDC_CERT_EXPIRED","The domain controller certificate used for smart card logon has expired. Contact your system administrator with the contents of your system event log."),
        0xC000040F: ("STATUS_KDC_CERT_REVOKED","The domain controller certificate used for smart card logon has been revoked. Contact your system administrator with the contents of your system event log."),
        0xC0000410: ("STATUS_PARAMETER_QUOTA_EXCEEDED","Data present in one of the parameters is more than the function can operate on."),
        0xC0000411: ("STATUS_HIBERNATION_FAILURE","The system has failed to hibernate (The error code is %hs). Hibernation will be disabled until the system is restarted."),
        0xC0000412: ("STATUS_DELAY_LOAD_FAILED","An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed."),
        0xC0000413: ("STATUS_AUTHENTICATION_FIREWALL_FAILED","Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine."),
        0xC0000414: ("STATUS_VDM_DISALLOWED","%hs is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator."),
        0xC0000415: ("STATUS_HUNG_DISPLAY_DRIVER_THREAD","{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the machine a dialog will be displayed giving you a chance to report this failure to Microsoft."),
        0xC0000416: ("STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE","The Desktop heap encountered an error while allocating session memory. There is more information in the system event log."),
        0xC0000417: ("STATUS_INVALID_CRUNTIME_PARAMETER","An invalid parameter was passed to a C runtime function."),
        0xC0000418: ("STATUS_NTLM_BLOCKED","The authentication failed because NTLM was blocked."),
        0xC0000419: ("STATUS_DS_SRC_SID_EXISTS_IN_FOREST","The source object's SID already exists in destination forest."),
        0xC000041A: ("STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST","The domain name of the trusted domain already exists in the forest."),
        0xC000041B: ("STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST","The flat name of the trusted domain already exists in the forest."),
        0xC000041C: ("STATUS_INVALID_USER_PRINCIPAL_NAME","The User Principal Name (UPN) is invalid."),
        0xC0000420: ("STATUS_ASSERTION_FAILURE","There has been an assertion failure."),
        0xC0000421: ("STATUS_VERIFIER_STOP","Application verifier has found an error in the current process."),
        0xC0000423: ("STATUS_CALLBACK_POP_STACK","A user mode unwind is in progress."),
        0xC0000424: ("STATUS_INCOMPATIBLE_DRIVER_BLOCKED","%2 has been blocked from loading due to incompatibility with this system. Contact your software vendor for a compatible version of the driver."),
        0xC0000425: ("STATUS_HIVE_UNLOADED","Illegal operation attempted on a registry key which has already been unloaded."),
        0xC0000426: ("STATUS_COMPRESSION_DISABLED","Compression is disabled for this volume."),
        0xC0000427: ("STATUS_FILE_SYSTEM_LIMITATION","The requested operation could not be completed due to a file system limitation."),
        0xC0000428: ("STATUS_INVALID_IMAGE_HASH","The hash for image %hs cannot be found in the system catalogs. The image is likely corrupt or the victim of tampering."),
        0xC0000429: ("STATUS_NOT_CAPABLE","The implementation is not capable of performing the request."),
        0xC000042A: ("STATUS_REQUEST_OUT_OF_SEQUENCE","The requested operation is out of order with respect to other operations."),
        0xC000042B: ("STATUS_IMPLEMENTATION_LIMIT","An operation attempted to exceed an implementation-defined limit."),
        0xC000042C: ("STATUS_ELEVATION_REQUIRED","The requested operation requires elevation."),
        0xC000042D: ("STATUS_NO_SECURITY_CONTEXT","The required security context does not exist."),
        0xC000042E: ("STATUS_PKU2U_CERT_FAILURE","The PKU2U protocol encountered an error while attempting to utilize the associated certificates."),
        0xC0000432: ("STATUS_BEYOND_VDL","The operation was attempted beyond the valid data length of the file."),
        0xC0000433: ("STATUS_ENCOUNTERED_WRITE_IN_PROGRESS","The attempted write operation encountered a write already in progress for some portion of the range."),
        0xC0000434: ("STATUS_PTE_CHANGED","The page fault mappings changed in the middle of processing a fault so the operation must be retried."),
        0xC0000435: ("STATUS_PURGE_FAILED","The attempt to purge this file from memory failed to purge some or all the data from memory."),
        0xC0000440: ("STATUS_CRED_REQUIRES_CONFIRMATION","The requested credential requires confirmation."),
        0xC0000441: ("STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE","The remote server sent an invalid response for a file being opened with Client Side Encryption."),
        0xC0000442: ("STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER","Client Side Encryption is not supported by the remote server even though it claims to support it."),
        0xC0000443: ("STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE","File is encrypted and should be opened in Client Side Encryption mode."),
        0xC0000444: ("STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE","A new encrypted file is being created and a $EFS needs to be provided."),
        0xC0000445: ("STATUS_CS_ENCRYPTION_FILE_NOT_CSE","The SMB client requested a CSE FSCTL on a non-CSE file."),
        0xC0000446: ("STATUS_INVALID_LABEL","Indicates a particular Security ID may not be assigned as the label of an object."),
        0xC0000450: ("STATUS_DRIVER_PROCESS_TERMINATED","The process hosting the driver for this device has terminated."),
        0xC0000451: ("STATUS_AMBIGUOUS_SYSTEM_DEVICE","The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria."),
        0xC0000452: ("STATUS_SYSTEM_DEVICE_NOT_FOUND","The requested system device cannot be found."),
        0xC0000453: ("STATUS_RESTART_BOOT_APPLICATION","This boot application must be restarted."),
        0xC0000454: ("STATUS_INSUFFICIENT_NVRAM_RESOURCES","Insufficient NVRAM resources exist to complete the API. A reboot might be required."),
        0xC0000500: ("STATUS_INVALID_TASK_NAME","The specified task name is invalid."),
        0xC0000501: ("STATUS_INVALID_TASK_INDEX","The specified task index is invalid."),
        0xC0000502: ("STATUS_THREAD_ALREADY_IN_TASK","The specified thread is already joining a task."),
        0xC0000503: ("STATUS_CALLBACK_BYPASS","A callback has requested to bypass native code."),
        0xC0000602: ("STATUS_FAIL_FAST_EXCEPTION","A fail fast exception occurred. Exception handlers will not be invoked and the process will be terminated immediately."),
        0xC0000603: ("STATUS_IMAGE_CERT_REVOKED","Windows cannot verify the digital signature for this file. The signing certificate for this file has been revoked."),
        0xC0000700: ("STATUS_PORT_CLOSED","The ALPC port is closed."),
        0xC0000701: ("STATUS_MESSAGE_LOST","The ALPC message requested is no longer available."),
        0xC0000702: ("STATUS_INVALID_MESSAGE","The ALPC message supplied is invalid."),
        0xC0000703: ("STATUS_REQUEST_CANCELED","The ALPC message has been canceled."),
        0xC0000704: ("STATUS_RECURSIVE_DISPATCH","Invalid recursive dispatch attempt."),
        0xC0000705: ("STATUS_LPC_RECEIVE_BUFFER_EXPECTED","No receive buffer has been supplied in a synchronous request."),
        0xC0000706: ("STATUS_LPC_INVALID_CONNECTION_USAGE","The connection port is used in an invalid context."),
        0xC0000707: ("STATUS_LPC_REQUESTS_NOT_ALLOWED","The ALPC port does not accept new request messages."),
        0xC0000708: ("STATUS_RESOURCE_IN_USE","The resource requested is already in use."),
        0xC0000709: ("STATUS_HARDWARE_MEMORY_ERROR","The hardware has reported an uncorrectable memory error."),
        0xC000070A: ("STATUS_THREADPOOL_HANDLE_EXCEPTION","Status 0x%08x was returned, waiting on handle 0x%x for wait 0x%p, in waiter 0x%p."),
        0xC000070B: ("STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED","After a callback to 0x%p(0x%p), a completion call to Set event(0x%p) failed with status 0x%08x."),
        0xC000070C: ("STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED","After a callback to 0x%p(0x%p), a completion call to ReleaseSemaphore(0x%p, %d) failed with status 0x%08x."),
        0xC000070D: ("STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED","After a callback to 0x%p(0x%p), a completion call to ReleaseMutex(%p) failed with status 0x%08x."),
        0xC000070E: ("STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED","After a callback to 0x%p(0x%p), a completion call to FreeLibrary(%p) failed with status 0x%08x."),
        0xC000070F: ("STATUS_THREADPOOL_RELEASED_DURING_OPERATION","The thread pool 0x%p was released while a thread was posting a callback to 0x%p(0x%p) to it."),
        0xC0000710: ("STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING","A thread pool worker thread is impersonating a client, after a callback to 0x%p(0x%p). This is unexpected, indicating that the callback is missing a call to revert the impersonation."),
        0xC0000711: ("STATUS_APC_RETURNED_WHILE_IMPERSONATING","A thread pool worker thread is impersonating a client, after executing an APC. This is unexpected, indicating that the APC is missing a call to revert the impersonation."),
        0xC0000712: ("STATUS_PROCESS_IS_PROTECTED","Either the target process, or the target thread's containing process, is a protected process."),
        0xC0000713: ("STATUS_MCA_EXCEPTION","A thread is getting dispatched with MCA EXCEPTION because of MCA."),
        0xC0000714: ("STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE","The client certificate account mapping is not unique."),
        0xC0000715: ("STATUS_SYMLINK_CLASS_DISABLED","The symbolic link cannot be followed because its type is disabled."),
        0xC0000716: ("STATUS_INVALID_IDN_NORMALIZATION","Indicates that the specified string is not valid for IDN normalization."),
        0xC0000717: ("STATUS_NO_UNICODE_TRANSLATION","No mapping for the Unicode character exists in the target multi-byte code page."),
        0xC0000718: ("STATUS_ALREADY_REGISTERED","The provided callback is already registered."),
        0xC0000719: ("STATUS_CONTEXT_MISMATCH","The provided context did not match the target."),
        0xC000071A: ("STATUS_PORT_ALREADY_HAS_COMPLETION_LIST","The specified port already has a completion list."),
        0xC000071B: ("STATUS_CALLBACK_RETURNED_THREAD_PRIORITY","A threadpool worker thread entered a callback at thread base priority 0x%x and exited at priority 0x%x.  This is unexpected, indicating that the callback missed restoring the priority."),
        0xC000071C: ("STATUS_INVALID_THREAD","An invalid thread, handle %p, is specified for this operation. Possibly, a threadpool worker thread was specified."),
        0xC000071D: ("STATUS_CALLBACK_RETURNED_TRANSACTION","A threadpool worker thread entered a callback, which left transaction state.  This is unexpected, indicating that the callback missed clearing the transaction."),
        0xC000071E: ("STATUS_CALLBACK_RETURNED_LDR_LOCK","A threadpool worker thread entered a callback, which left the loader lock held.  This is unexpected, indicating that the callback missed releasing the lock."),
        0xC000071F: ("STATUS_CALLBACK_RETURNED_LANG","A threadpool worker thread entered a callback, which left with preferred languages set.  This is unexpected, indicating that the callback missed clearing them."),
        0xC0000720: ("STATUS_CALLBACK_RETURNED_PRI_BACK","A threadpool worker thread entered a callback, which left with background priorities set.  This is unexpected, indicating that the callback missed restoring the original priorities."),
        0xC0000800: ("STATUS_DISK_REPAIR_DISABLED","The attempted operation required self healing to be enabled."),
        0xC0000801: ("STATUS_DS_DOMAIN_RENAME_IN_PROGRESS","The directory service cannot perform the requested operation because a domain rename operation is in progress."),
        0xC0000802: ("STATUS_DISK_QUOTA_EXCEEDED","An operation failed because the storage quota was exceeded."),
        0xC0000804: ("STATUS_CONTENT_BLOCKED","An operation failed because the content was blocked."),
        0xC0000805: ("STATUS_BAD_CLUSTERS","The operation could not be completed due to bad clusters on disk."),
        0xC0000806: ("STATUS_VOLUME_DIRTY","The operation could not be completed because the volume is dirty. Please run the Chkdsk utility and try again."),
        0xC0000901: ("STATUS_FILE_CHECKED_OUT","This file is checked out or locked for editing by another user."),
        0xC0000902: ("STATUS_CHECKOUT_REQUIRED","The file must be checked out before saving changes."),
        0xC0000903: ("STATUS_BAD_FILE_TYPE","The file type being saved or retrieved has been blocked."),
        0xC0000904: ("STATUS_FILE_TOO_LARGE","The file size exceeds the limit allowed and cannot be saved."),
        0xC0000905: ("STATUS_FORMS_AUTH_REQUIRED","Access Denied. Before opening files in this location, you must first browse to the e.g. site and select the option to log on automatically."),
        0xC0000906: ("STATUS_VIRUS_INFECTED","The operation did not complete successfully because the file contains a virus."),
        0xC0000907: ("STATUS_VIRUS_DELETED","This file contains a virus and cannot be opened. Due to the nature of this virus, the file has been removed from this location."),
        0xC0000908: ("STATUS_BAD_MCFG_TABLE","The resources required for this device conflict with the MCFG table."),
        0xC0000909: ("STATUS_CANNOT_BREAK_OPLOCK","The operation did not complete successfully because it would cause an oplock to be broken. The caller has requested that existing oplocks not be broken."),
        0xC0009898: ("STATUS_WOW_ASSERTION","WOW Assertion Error."),
        0xC000A000: ("STATUS_INVALID_SIGNATURE","The cryptographic signature is invalid."),
        0xC000A001: ("STATUS_HMAC_NOT_SUPPORTED","The cryptographic provider does not support HMAC."),
        0xC000A010: ("STATUS_IPSEC_QUEUE_OVERFLOW","The IPsec queue overflowed."),
        0xC000A011: ("STATUS_ND_QUEUE_OVERFLOW","The neighbor discovery queue overflowed."),
        0xC000A012: ("STATUS_HOPLIMIT_EXCEEDED","An Internet Control Message Protocol (ICMP) hop limit exceeded error was received."),
        0xC000A013: ("STATUS_PROTOCOL_NOT_SUPPORTED","The protocol is not installed on the local machine."),
        0xC000A080: ("STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED","{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused by network connectivity issues. Try to save this file elsewhere."),
        0xC000A081: ("STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR","{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error was returned by the server on which the file exists. Try to save this file elsewhere."),
        0xC000A082: ("STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR","{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused if the device has been removed or the media is write-protected."),
        0xC000A083: ("STATUS_XML_PARSE_ERROR","Windows was unable to parse the requested XML data."),
        0xC000A084: ("STATUS_XMLDSIG_ERROR","An error was encountered while processing an XML digital signature."),
        0xC000A085: ("STATUS_WRONG_COMPARTMENT","This indicates that the caller made the connection request in the wrong routing compartment."),
        0xC000A086: ("STATUS_AUTHIP_FAILURE","This indicates that there was an AuthIP failure when attempting to connect to the remote host."),
        0xC000A087: ("STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS","OID mapped groups cannot have members."),
        0xC000A088: ("STATUS_DS_OID_NOT_FOUND","The specified OID cannot be found."),
        0xC000A100: ("STATUS_HASH_NOT_SUPPORTED","Hash generation for the specified version and hash type is not enabled on server."),
        0xC000A101: ("STATUS_HASH_NOT_PRESENT","The hash requests is not present or not up to date with the current file contents."),
        0xC0010001: ("DBG_NO_STATE_CHANGE","The debugger did not perform a state change."),
        0xC0010002: ("DBG_APP_NOT_IDLE","The debugger found that the application is not idle."),
        0xC0020001: ("RPC_NT_INVALID_STRING_BINDING","The string binding is invalid."),
        0xC0020002: ("RPC_NT_WRONG_KIND_OF_BINDING","The binding handle is not the correct type."),
        0xC0020003: ("RPC_NT_INVALID_BINDING","The binding handle is invalid."),
        0xC0020004: ("RPC_NT_PROTSEQ_NOT_SUPPORTED","The RPC protocol sequence is not supported."),
        0xC0020005: ("RPC_NT_INVALID_RPC_PROTSEQ","The RPC protocol sequence is invalid."),
        0xC0020006: ("RPC_NT_INVALID_STRING_UUID","The string UUID is invalid."),
        0xC0020007: ("RPC_NT_INVALID_ENDPOINT_FORMAT","The endpoint format is invalid."),
        0xC0020008: ("RPC_NT_INVALID_NET_ADDR","The network address is invalid."),
        0xC0020009: ("RPC_NT_NO_ENDPOINT_FOUND","No endpoint was found."),
        0xC002000A: ("RPC_NT_INVALID_TIMEOUT","The time-out value is invalid."),
        0xC002000B: ("RPC_NT_OBJECT_NOT_FOUND","The object UUID was not found."),
        0xC002000C: ("RPC_NT_ALREADY_REGISTERED","The object UUID has already been registered."),
        0xC002000D: ("RPC_NT_TYPE_ALREADY_REGISTERED","The type UUID has already been registered."),
        0xC002000E: ("RPC_NT_ALREADY_LISTENING","The RPC server is already listening."),
        0xC002000F: ("RPC_NT_NO_PROTSEQS_REGISTERED","No protocol sequences have been registered."),
        0xC0020010: ("RPC_NT_NOT_LISTENING","The RPC server is not listening."),
        0xC0020011: ("RPC_NT_UNKNOWN_MGR_TYPE","The manager type is unknown."),
        0xC0020012: ("RPC_NT_UNKNOWN_IF","The interface is unknown."),
        0xC0020013: ("RPC_NT_NO_BINDINGS","There are no bindings."),
        0xC0020014: ("RPC_NT_NO_PROTSEQS","There are no protocol sequences."),
        0xC0020015: ("RPC_NT_CANT_CREATE_ENDPOINT","The endpoint cannot be created."),
        0xC0020016: ("RPC_NT_OUT_OF_RESOURCES","Insufficient resources are available to complete this operation."),
        0xC0020017: ("RPC_NT_SERVER_UNAVAILABLE","The RPC server is unavailable."),
        0xC0020018: ("RPC_NT_SERVER_TOO_BUSY","The RPC server is too busy to complete this operation."),
        0xC0020019: ("RPC_NT_INVALID_NETWORK_OPTIONS","The network options are invalid."),
        0xC002001A: ("RPC_NT_NO_CALL_ACTIVE","No RPCs are active on this thread."),
        0xC002001B: ("RPC_NT_CALL_FAILED","The RPC failed."),
        0xC002001C: ("RPC_NT_CALL_FAILED_DNE","The RPC failed and did not execute."),
        0xC002001D: ("RPC_NT_PROTOCOL_ERROR","An RPC protocol error occurred."),
        0xC002001F: ("RPC_NT_UNSUPPORTED_TRANS_SYN","The RPC server does not support the transfer syntax."),
        0xC0020021: ("RPC_NT_UNSUPPORTED_TYPE","The type UUID is not supported."),
        0xC0020022: ("RPC_NT_INVALID_TAG","The tag is invalid."),
        0xC0020023: ("RPC_NT_INVALID_BOUND","The array bounds are invalid."),
        0xC0020024: ("RPC_NT_NO_ENTRY_NAME","The binding does not contain an entry name."),
        0xC0020025: ("RPC_NT_INVALID_NAME_SYNTAX","The name syntax is invalid."),
        0xC0020026: ("RPC_NT_UNSUPPORTED_NAME_SYNTAX","The name syntax is not supported."),
        0xC0020028: ("RPC_NT_UUID_NO_ADDRESS","No network address is available to construct a UUID."),
        0xC0020029: ("RPC_NT_DUPLICATE_ENDPOINT","The endpoint is a duplicate."),
        0xC002002A: ("RPC_NT_UNKNOWN_AUTHN_TYPE","The authentication type is unknown."),
        0xC002002B: ("RPC_NT_MAX_CALLS_TOO_SMALL","The maximum number of calls is too small."),
        0xC002002C: ("RPC_NT_STRING_TOO_LONG","The string is too long."),
        0xC002002D: ("RPC_NT_PROTSEQ_NOT_FOUND","The RPC protocol sequence was not found."),
        0xC002002E: ("RPC_NT_PROCNUM_OUT_OF_RANGE","The procedure number is out of range."),
        0xC002002F: ("RPC_NT_BINDING_HAS_NO_AUTH","The binding does not contain any authentication information."),
        0xC0020030: ("RPC_NT_UNKNOWN_AUTHN_SERVICE","The authentication service is unknown."),
        0xC0020031: ("RPC_NT_UNKNOWN_AUTHN_LEVEL","The authentication level is unknown."),
        0xC0020032: ("RPC_NT_INVALID_AUTH_IDENTITY","The security context is invalid."),
        0xC0020033: ("RPC_NT_UNKNOWN_AUTHZ_SERVICE","The authorization service is unknown."),
        0xC0020034: ("EPT_NT_INVALID_ENTRY","The entry is invalid."),
        0xC0020035: ("EPT_NT_CANT_PERFORM_OP","The operation cannot be performed."),
        0xC0020036: ("EPT_NT_NOT_REGISTERED","No more endpoints are available from the endpoint mapper."),
        0xC0020037: ("RPC_NT_NOTHING_TO_EXPORT","No interfaces have been exported."),
        0xC0020038: ("RPC_NT_INCOMPLETE_NAME","The entry name is incomplete."),
        0xC0020039: ("RPC_NT_INVALID_VERS_OPTION","The version option is invalid."),
        0xC002003A: ("RPC_NT_NO_MORE_MEMBERS","There are no more members."),
        0xC002003B: ("RPC_NT_NOT_ALL_OBJS_UNEXPORTED","There is nothing to unexport."),
        0xC002003C: ("RPC_NT_INTERFACE_NOT_FOUND","The interface was not found."),
        0xC002003D: ("RPC_NT_ENTRY_ALREADY_EXISTS","The entry already exists."),
        0xC002003E: ("RPC_NT_ENTRY_NOT_FOUND","The entry was not found."),
        0xC002003F: ("RPC_NT_NAME_SERVICE_UNAVAILABLE","The name service is unavailable."),
        0xC0020040: ("RPC_NT_INVALID_NAF_ID","The network address family is invalid."),
        0xC0020041: ("RPC_NT_CANNOT_SUPPORT","The requested operation is not supported."),
        0xC0020042: ("RPC_NT_NO_CONTEXT_AVAILABLE","No security context is available to allow impersonation."),
        0xC0020043: ("RPC_NT_INTERNAL_ERROR","An internal error occurred in the RPC."),
        0xC0020044: ("RPC_NT_ZERO_DIVIDE","The RPC server attempted to divide an integer by zero."),
        0xC0020045: ("RPC_NT_ADDRESS_ERROR","An addressing error occurred in the RPC server."),
        0xC0020046: ("RPC_NT_FP_DIV_ZERO","A floating point operation at the RPC server caused a divide by zero."),
        0xC0020047: ("RPC_NT_FP_UNDERFLOW","A floating point underflow occurred at the RPC server."),
        0xC0020048: ("RPC_NT_FP_OVERFLOW","A floating point overflow occurred at the RPC server."),
        0xC0020049: ("RPC_NT_CALL_IN_PROGRESS","An RPC is already in progress for this thread."),
        0xC002004A: ("RPC_NT_NO_MORE_BINDINGS","There are no more bindings."),
        0xC002004B: ("RPC_NT_GROUP_MEMBER_NOT_FOUND","The group member was not found."),
        0xC002004C: ("EPT_NT_CANT_CREATE","The endpoint mapper database entry could not be created."),
        0xC002004D: ("RPC_NT_INVALID_OBJECT","The object UUID is the nil UUID."),
        0xC002004F: ("RPC_NT_NO_INTERFACES","No interfaces have been registered."),
        0xC0020050: ("RPC_NT_CALL_CANCELLED","The RPC was canceled."),
        0xC0020051: ("RPC_NT_BINDING_INCOMPLETE","The binding handle does not contain all the required information."),
        0xC0020052: ("RPC_NT_COMM_FAILURE","A communications failure occurred during an RPC."),
        0xC0020053: ("RPC_NT_UNSUPPORTED_AUTHN_LEVEL","The requested authentication level is not supported."),
        0xC0020054: ("RPC_NT_NO_PRINC_NAME","No principal name was registered."),
        0xC0020055: ("RPC_NT_NOT_RPC_ERROR","The error specified is not a valid Windows RPC error code."),
        0xC0020057: ("RPC_NT_SEC_PKG_ERROR","A security package-specific error occurred."),
        0xC0020058: ("RPC_NT_NOT_CANCELLED","The thread was not canceled."),
        0xC0020062: ("RPC_NT_INVALID_ASYNC_HANDLE","Invalid asynchronous RPC handle."),
        0xC0020063: ("RPC_NT_INVALID_ASYNC_CALL","Invalid asynchronous RPC call handle for this operation."),
        0xC0020064: ("RPC_NT_PROXY_ACCESS_DENIED","Access to the HTTP proxy is denied."),
        0xC0030001: ("RPC_NT_NO_MORE_ENTRIES","The list of RPC servers available for auto-handle binding has been exhausted."),
        0xC0030002: ("RPC_NT_SS_CHAR_TRANS_OPEN_FAIL","The file designated by DCERPCCHARTRANS cannot be opened."),
        0xC0030003: ("RPC_NT_SS_CHAR_TRANS_SHORT_FILE","The file containing the character translation table has fewer than 512 bytes."),
        0xC0030004: ("RPC_NT_SS_IN_NULL_CONTEXT","A null context handle is passed as an [in] parameter."),
        0xC0030005: ("RPC_NT_SS_CONTEXT_MISMATCH","The context handle does not match any known context handles."),
        0xC0030006: ("RPC_NT_SS_CONTEXT_DAMAGED","The context handle changed during a call."),
        0xC0030007: ("RPC_NT_SS_HANDLES_MISMATCH","The binding handles passed to an RPC do not match."),
        0xC0030008: ("RPC_NT_SS_CANNOT_GET_CALL_HANDLE","The stub is unable to get the call handle."),
        0xC0030009: ("RPC_NT_NULL_REF_POINTER","A null reference pointer was passed to the stub."),
        0xC003000A: ("RPC_NT_ENUM_VALUE_OUT_OF_RANGE","The enumeration value is out of range."),
        0xC003000B: ("RPC_NT_BYTE_COUNT_TOO_SMALL","The byte count is too small."),
        0xC003000C: ("RPC_NT_BAD_STUB_DATA","The stub received bad data."),
        0xC0030059: ("RPC_NT_INVALID_ES_ACTION","Invalid operation on the encoding/decoding handle."),
        0xC003005A: ("RPC_NT_WRONG_ES_VERSION","Incompatible version of the serializing package."),
        0xC003005B: ("RPC_NT_WRONG_STUB_VERSION","Incompatible version of the RPC stub."),
        0xC003005C: ("RPC_NT_INVALID_PIPE_OBJECT","The RPC pipe object is invalid or corrupt."),
        0xC003005D: ("RPC_NT_INVALID_PIPE_OPERATION","An invalid operation was attempted on an RPC pipe object."),
        0xC003005E: ("RPC_NT_WRONG_PIPE_VERSION","Unsupported RPC pipe version."),
        0xC003005F: ("RPC_NT_PIPE_CLOSED","The RPC pipe object has already been closed."),
        0xC0030060: ("RPC_NT_PIPE_DISCIPLINE_ERROR","The RPC call completed before all pipes were processed."),
        0xC0030061: ("RPC_NT_PIPE_EMPTY","No more data is available from the RPC pipe."),
        0xC0040035: ("STATUS_PNP_BAD_MPS_TABLE","A device is missing in the system BIOS MPS table. This device will not be used. Contact your system vendor for a system BIOS update."),
        0xC0040036: ("STATUS_PNP_TRANSLATION_FAILED","A translator failed to translate resources."),
        0xC0040037: ("STATUS_PNP_IRQ_TRANSLATION_FAILED","An IRQ translator failed to translate resources."),
        0xC0040038: ("STATUS_PNP_INVALID_ID","Driver %2 returned an invalid ID for a child device (%3)."),
        0xC0040039: ("STATUS_IO_REISSUE_AS_CACHED","Reissue the given operation as a cached I/O operation"),
        0xC00A0001: ("STATUS_CTX_WINSTATION_NAME_INVALID","Session name %1 is invalid."),
        0xC00A0002: ("STATUS_CTX_INVALID_PD","The protocol driver %1 is invalid."),
        0xC00A0003: ("STATUS_CTX_PD_NOT_FOUND","The protocol driver %1 was not found in the system path."),
        0xC00A0006: ("STATUS_CTX_CLOSE_PENDING","A close operation is pending on the terminal connection."),
        0xC00A0007: ("STATUS_CTX_NO_OUTBUF","No free output buffers are available."),
        0xC00A0008: ("STATUS_CTX_MODEM_INF_NOT_FOUND","The MODEM.INF file was not found."),
        0xC00A0009: ("STATUS_CTX_INVALID_MODEMNAME","The modem (%1) was not found in the MODEM.INF file."),
        0xC00A000A: ("STATUS_CTX_RESPONSE_ERROR","The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem."),
        0xC00A000B: ("STATUS_CTX_MODEM_RESPONSE_TIMEOUT","The modem did not respond to the command sent to it. Verify that the modem cable is properly attached and the modem is turned on."),
        0xC00A000C: ("STATUS_CTX_MODEM_RESPONSE_NO_CARRIER","Carrier detection has failed or the carrier has been dropped due to disconnection."),
        0xC00A000D: ("STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE","A dial tone was not detected within the required time. Verify that the phone cable is properly attached and functional."),
        0xC00A000E: ("STATUS_CTX_MODEM_RESPONSE_BUSY","A busy signal was detected at a remote site on callback."),
        0xC00A000F: ("STATUS_CTX_MODEM_RESPONSE_VOICE","A voice was detected at a remote site on callback."),
        0xC00A0010: ("STATUS_CTX_TD_ERROR","Transport driver error."),
        0xC00A0012: ("STATUS_CTX_LICENSE_CLIENT_INVALID","The client you are using is not licensed to use this system. Your logon request is denied."),
        0xC00A0013: ("STATUS_CTX_LICENSE_NOT_AVAILABLE","The system has reached its licensed logon limit. Try again later."),
        0xC00A0014: ("STATUS_CTX_LICENSE_EXPIRED","The system license has expired. Your logon request is denied."),
        0xC00A0015: ("STATUS_CTX_WINSTATION_NOT_FOUND","The specified session cannot be found."),
        0xC00A0016: ("STATUS_CTX_WINSTATION_NAME_COLLISION","The specified session name is already in use."),
        0xC00A0017: ("STATUS_CTX_WINSTATION_BUSY","The requested operation cannot be completed because the terminal connection is currently processing a connect, disconnect, reset, or delete operation."),
        0xC00A0018: ("STATUS_CTX_BAD_VIDEO_MODE","An attempt has been made to connect to a session whose video mode is not supported by the current client."),
        0xC00A0022: ("STATUS_CTX_GRAPHICS_INVALID","The application attempted to enable DOS graphics mode. DOS graphics mode is not supported."),
        0xC00A0024: ("STATUS_CTX_NOT_CONSOLE","The requested operation can be performed only on the system console. This is most often the result of a driver or system DLL requiring direct console access."),
        0xC00A0026: ("STATUS_CTX_CLIENT_QUERY_TIMEOUT","The client failed to respond to the server connect message."),
        0xC00A0027: ("STATUS_CTX_CONSOLE_DISCONNECT","Disconnecting the console session is not supported."),
        0xC00A0028: ("STATUS_CTX_CONSOLE_CONNECT","Reconnecting a disconnected session to the console is not supported."),
        0xC00A002A: ("STATUS_CTX_SHADOW_DENIED","The request to control another session remotely was denied."),
        0xC00A002B: ("STATUS_CTX_WINSTATION_ACCESS_DENIED","A process has requested access to a session, but has not been granted those access rights."),
        0xC00A002E: ("STATUS_CTX_INVALID_WD","The terminal connection driver %1 is invalid."),
        0xC00A002F: ("STATUS_CTX_WD_NOT_FOUND","The terminal connection driver %1 was not found in the system path."),
        0xC00A0030: ("STATUS_CTX_SHADOW_INVALID","The requested session cannot be controlled remotely. You cannot control your own session, a session that is trying to control your session, a session that has no user logged on, or other sessions from the console."),
        0xC00A0031: ("STATUS_CTX_SHADOW_DISABLED","The requested session is not configured to allow remote control."),
        0xC00A0032: ("STATUS_RDP_PROTOCOL_ERROR","The RDP protocol component %2 detected an error in the protocol stream and has disconnected the client."),
        0xC00A0033: ("STATUS_CTX_CLIENT_LICENSE_NOT_SET","Your request to connect to this terminal server has been rejected. Your terminal server client license number has not been entered for this copy of the terminal client. Contact your system administrator for help in entering a valid, unique license number for this terminal server client. Click OK to continue."),
        0xC00A0034: ("STATUS_CTX_CLIENT_LICENSE_IN_USE","Your request to connect to this terminal server has been rejected. Your terminal server client license number is currently being used by another user. Contact your system administrator to obtain a new copy of the terminal server client with a valid, unique license number. Click OK to continue."),
        0xC00A0035: ("STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE","The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported."),
        0xC00A0036: ("STATUS_CTX_SHADOW_NOT_RUNNING","Remote control could not be terminated because the specified session is not currently being remotely controlled."),
        0xC00A0037: ("STATUS_CTX_LOGON_DISABLED","Your interactive logon privilege has been disabled. Contact your system administrator."),
        0xC00A0038: ("STATUS_CTX_SECURITY_LAYER_ERROR","The terminal server security layer detected an error in the protocol stream and has disconnected the client."),
        0xC00A0039: ("STATUS_TS_INCOMPATIBLE_SESSIONS","The target session is incompatible with the current session."),
        0xC00B0001: ("STATUS_MUI_FILE_NOT_FOUND","The resource loader failed to find an MUI file."),
        0xC00B0002: ("STATUS_MUI_INVALID_FILE","The resource loader failed to load an MUI file because the file failed to pass validation."),
        0xC00B0003: ("STATUS_MUI_INVALID_RC_CONFIG","The RC manifest is corrupted with garbage data, is an unsupported version, or is missing a required item."),
        0xC00B0004: ("STATUS_MUI_INVALID_LOCALE_NAME","The RC manifest has an invalid culture name."),
        0xC00B0005: ("STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME","The RC manifest has and invalid ultimate fallback name."),
        0xC00B0006: ("STATUS_MUI_FILE_NOT_LOADED","The resource loader cache does not have a loaded MUI entry."),
        0xC00B0007: ("STATUS_RESOURCE_ENUM_USER_STOP","The user stopped resource enumeration."),
        0xC0130001: ("STATUS_CLUSTER_INVALID_NODE","The cluster node is not valid."),
        0xC0130002: ("STATUS_CLUSTER_NODE_EXISTS","The cluster node already exists."),
        0xC0130003: ("STATUS_CLUSTER_JOIN_IN_PROGRESS","A node is in the process of joining the cluster."),
        0xC0130004: ("STATUS_CLUSTER_NODE_NOT_FOUND","The cluster node was not found."),
        0xC0130005: ("STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND","The cluster local node information was not found."),
        0xC0130006: ("STATUS_CLUSTER_NETWORK_EXISTS","The cluster network already exists."),
        0xC0130007: ("STATUS_CLUSTER_NETWORK_NOT_FOUND","The cluster network was not found."),
        0xC0130008: ("STATUS_CLUSTER_NETINTERFACE_EXISTS","The cluster network interface already exists."),
        0xC0130009: ("STATUS_CLUSTER_NETINTERFACE_NOT_FOUND","The cluster network interface was not found."),
        0xC013000A: ("STATUS_CLUSTER_INVALID_REQUEST","The cluster request is not valid for this object."),
        0xC013000B: ("STATUS_CLUSTER_INVALID_NETWORK_PROVIDER","The cluster network provider is not valid."),
        0xC013000C: ("STATUS_CLUSTER_NODE_DOWN","The cluster node is down."),
        0xC013000D: ("STATUS_CLUSTER_NODE_UNREACHABLE","The cluster node is not reachable."),
        0xC013000E: ("STATUS_CLUSTER_NODE_NOT_MEMBER","The cluster node is not a member of the cluster."),
        0xC013000F: ("STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS","A cluster join operation is not in progress."),
        0xC0130010: ("STATUS_CLUSTER_INVALID_NETWORK","The cluster network is not valid."),
        0xC0130011: ("STATUS_CLUSTER_NO_NET_ADAPTERS","No network adapters are available."),
        0xC0130012: ("STATUS_CLUSTER_NODE_UP","The cluster node is up."),
        0xC0130013: ("STATUS_CLUSTER_NODE_PAUSED","The cluster node is paused."),
        0xC0130014: ("STATUS_CLUSTER_NODE_NOT_PAUSED","The cluster node is not paused."),
        0xC0130015: ("STATUS_CLUSTER_NO_SECURITY_CONTEXT","No cluster security context is available."),
        0xC0130016: ("STATUS_CLUSTER_NETWORK_NOT_INTERNAL","The cluster network is not configured for internal cluster communication."),
        0xC0130017: ("STATUS_CLUSTER_POISONED","The cluster node has been poisoned."),
        0xC0140001: ("STATUS_ACPI_INVALID_OPCODE","An attempt was made to run an invalid AML opcode."),
        0xC0140002: ("STATUS_ACPI_STACK_OVERFLOW","The AML interpreter stack has overflowed."),
        0xC0140003: ("STATUS_ACPI_ASSERT_FAILED","An inconsistent state has occurred."),
        0xC0140004: ("STATUS_ACPI_INVALID_INDEX","An attempt was made to access an array outside its bounds."),
        0xC0140005: ("STATUS_ACPI_INVALID_ARGUMENT","A required argument was not specified."),
        0xC0140006: ("STATUS_ACPI_FATAL","A fatal error has occurred."),
        0xC0140007: ("STATUS_ACPI_INVALID_SUPERNAME","An invalid SuperName was specified."),
        0xC0140008: ("STATUS_ACPI_INVALID_ARGTYPE","An argument with an incorrect type was specified."),
        0xC0140009: ("STATUS_ACPI_INVALID_OBJTYPE","An object with an incorrect type was specified."),
        0xC014000A: ("STATUS_ACPI_INVALID_TARGETTYPE","A target with an incorrect type was specified."),
        0xC014000B: ("STATUS_ACPI_INCORRECT_ARGUMENT_COUNT","An incorrect number of arguments was specified."),
        0xC014000C: ("STATUS_ACPI_ADDRESS_NOT_MAPPED","An address failed to translate."),
        0xC014000D: ("STATUS_ACPI_INVALID_EVENTTYPE","An incorrect event type was specified."),
        0xC014000E: ("STATUS_ACPI_HANDLER_COLLISION","A handler for the target already exists."),
        0xC014000F: ("STATUS_ACPI_INVALID_DATA","Invalid data for the target was specified."),
        0xC0140010: ("STATUS_ACPI_INVALID_REGION","An invalid region for the target was specified."),
        0xC0140011: ("STATUS_ACPI_INVALID_ACCESS_SIZE","An attempt was made to access a field outside the defined range."),
        0xC0140012: ("STATUS_ACPI_ACQUIRE_GLOBAL_LOCK","The global system lock could not be acquired."),
        0xC0140013: ("STATUS_ACPI_ALREADY_INITIALIZED","An attempt was made to reinitialize the ACPI subsystem."),
        0xC0140014: ("STATUS_ACPI_NOT_INITIALIZED","The ACPI subsystem has not been initialized."),
        0xC0140015: ("STATUS_ACPI_INVALID_MUTEX_LEVEL","An incorrect mutex was specified."),
        0xC0140016: ("STATUS_ACPI_MUTEX_NOT_OWNED","The mutex is not currently owned."),
        0xC0140017: ("STATUS_ACPI_MUTEX_NOT_OWNER","An attempt was made to access the mutex by a process that was not the owner."),
        0xC0140018: ("STATUS_ACPI_RS_ACCESS","An error occurred during an access to region space."),
        0xC0140019: ("STATUS_ACPI_INVALID_TABLE","An attempt was made to use an incorrect table."),
        0xC0140020: ("STATUS_ACPI_REG_HANDLER_FAILED","The registration of an ACPI event failed."),
        0xC0140021: ("STATUS_ACPI_POWER_REQUEST_FAILED","An ACPI power object failed to transition state."),
        0xC0150001: ("STATUS_SXS_SECTION_NOT_FOUND","The requested section is not present in the activation context."),
        0xC0150002: ("STATUS_SXS_CANT_GEN_ACTCTX","Windows was unble to process the application binding information. Refer to the system event log for further information."),
        0xC0150003: ("STATUS_SXS_INVALID_ACTCTXDATA_FORMAT","The application binding data format is invalid."),
        0xC0150004: ("STATUS_SXS_ASSEMBLY_NOT_FOUND","The referenced assembly is not installed on the system."),
        0xC0150005: ("STATUS_SXS_MANIFEST_FORMAT_ERROR","The manifest file does not begin with the required tag and format information."),
        0xC0150006: ("STATUS_SXS_MANIFEST_PARSE_ERROR","The manifest file contains one or more syntax errors."),
        0xC0150007: ("STATUS_SXS_ACTIVATION_CONTEXT_DISABLED","The application attempted to activate a disabled activation context."),
        0xC0150008: ("STATUS_SXS_KEY_NOT_FOUND","The requested lookup key was not found in any active activation context."),
        0xC0150009: ("STATUS_SXS_VERSION_CONFLICT","A component version required by the application conflicts with another component version that is already active."),
        0xC015000A: ("STATUS_SXS_WRONG_SECTION_TYPE","The type requested activation context section does not match the query API used."),
        0xC015000B: ("STATUS_SXS_THREAD_QUERIES_DISABLED","Lack of system resources has required isolated activation to be disabled for the current thread of execution."),
        0xC015000C: ("STATUS_SXS_ASSEMBLY_MISSING","The referenced assembly could not be found."),
        0xC015000E: ("STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET","An attempt to set the process default activation context failed because the process default activation context was already set."),
        0xC015000F: ("STATUS_SXS_EARLY_DEACTIVATION","The activation context being deactivated is not the most recently activated one."),
        0xC0150010: ("STATUS_SXS_INVALID_DEACTIVATION","The activation context being deactivated is not active for the current thread of execution."),
        0xC0150011: ("STATUS_SXS_MULTIPLE_DEACTIVATION","The activation context being deactivated has already been deactivated."),
        0xC0150012: ("STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY","The activation context of the system default assembly could not be generated."),
        0xC0150013: ("STATUS_SXS_PROCESS_TERMINATION_REQUESTED","A component used by the isolation facility has requested that the process be terminated."),
        0xC0150014: ("STATUS_SXS_CORRUPT_ACTIVATION_STACK","The activation context activation stack for the running thread of execution is corrupt."),
        0xC0150015: ("STATUS_SXS_CORRUPTION","The application isolation metadata for this process or thread has become corrupt."),
        0xC0150016: ("STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE","The value of an attribute in an identity is not within the legal range."),
        0xC0150017: ("STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME","The name of an attribute in an identity is not within the legal range."),
        0xC0150018: ("STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE","An identity contains two definitions for the same attribute."),
        0xC0150019: ("STATUS_SXS_IDENTITY_PARSE_ERROR","The identity string is malformed. This may be due to a trailing comma, more than two unnamed attributes, a missing attribute name, or a missing attribute value."),
        0xC015001A: ("STATUS_SXS_COMPONENT_STORE_CORRUPT","The component store has become corrupted."),
        0xC015001B: ("STATUS_SXS_FILE_HASH_MISMATCH","A component's file does not match the verification information present in the component manifest."),
        0xC015001C: ("STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT","The identities of the manifests are identical, but their contents are different."),
        0xC015001D: ("STATUS_SXS_IDENTITIES_DIFFERENT","The component identities are different."),
        0xC015001E: ("STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT","The assembly is not a deployment."),
        0xC015001F: ("STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY","The file is not a part of the assembly."),
        0xC0150020: ("STATUS_ADVANCED_INSTALLER_FAILED","An advanced installer failed during setup or servicing."),
        0xC0150021: ("STATUS_XML_ENCODING_MISMATCH","The character encoding in the XML declaration did not match the encoding used in the document."),
        0xC0150022: ("STATUS_SXS_MANIFEST_TOO_BIG","The size of the manifest exceeds the maximum allowed."),
        0xC0150023: ("STATUS_SXS_SETTING_NOT_REGISTERED","The setting is not registered."),
        0xC0150024: ("STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE","One or more required transaction members are not present."),
        0xC0150025: ("STATUS_SMI_PRIMITIVE_INSTALLER_FAILED","The SMI primitive installer failed during setup or servicing."),
        0xC0150026: ("STATUS_GENERIC_COMMAND_FAILED","A generic command executable returned a result that indicates failure."),
        0xC0150027: ("STATUS_SXS_FILE_HASH_MISSING","A component is missing file verification information in its manifest."),
        0xC0190001: ("STATUS_TRANSACTIONAL_CONFLICT","The function attempted to use a name that is reserved for use by another transaction."),
        0xC0190002: ("STATUS_INVALID_TRANSACTION","The transaction handle associated with this operation is invalid."),
        0xC0190003: ("STATUS_TRANSACTION_NOT_ACTIVE","The requested operation was made in the context of a transaction that is no longer active."),
        0xC0190004: ("STATUS_TM_INITIALIZATION_FAILED","The transaction manager was unable to be successfully initialized. Transacted operations are not supported."),
        0xC0190005: ("STATUS_RM_NOT_ACTIVE","Transaction support within the specified file system resource manager was not started or was shut down due to an error."),
        0xC0190006: ("STATUS_RM_METADATA_CORRUPT","The metadata of the resource manager has been corrupted. The resource manager will not function."),
        0xC0190007: ("STATUS_TRANSACTION_NOT_JOINED","The resource manager attempted to prepare a transaction that it has not successfully joined."),
        0xC0190008: ("STATUS_DIRECTORY_NOT_RM","The specified directory does not contain a file system resource manager."),
        0xC019000A: ("STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE","The remote server or share does not support transacted file operations."),
        0xC019000B: ("STATUS_LOG_RESIZE_INVALID_SIZE","The requested log size for the file system resource manager is invalid."),
        0xC019000C: ("STATUS_REMOTE_FILE_VERSION_MISMATCH","The remote server sent mismatching version number or Fid for a file opened with transactions."),
        0xC019000F: ("STATUS_CRM_PROTOCOL_ALREADY_EXISTS","The resource manager tried to register a protocol that already exists."),
        0xC0190010: ("STATUS_TRANSACTION_PROPAGATION_FAILED","The attempt to propagate the transaction failed."),
        0xC0190011: ("STATUS_CRM_PROTOCOL_NOT_FOUND","The requested propagation protocol was not registered as a CRM."),
        0xC0190012: ("STATUS_TRANSACTION_SUPERIOR_EXISTS","The transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allowed."),
        0xC0190013: ("STATUS_TRANSACTION_REQUEST_NOT_VALID","The requested operation is not valid on the transaction object in its current state."),
        0xC0190014: ("STATUS_TRANSACTION_NOT_REQUESTED","The caller has called a response API, but the response is not expected because the transaction manager did not issue the corresponding request to the caller."),
        0xC0190015: ("STATUS_TRANSACTION_ALREADY_ABORTED","It is too late to perform the requested operation, because the transaction has already been aborted."),
        0xC0190016: ("STATUS_TRANSACTION_ALREADY_COMMITTED","It is too late to perform the requested operation, because the transaction has already been committed."),
        0xC0190017: ("STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER","The buffer passed in to NtPushTransaction or NtPullTransaction is not in a valid format."),
        0xC0190018: ("STATUS_CURRENT_TRANSACTION_NOT_VALID","The current transaction context associated with the thread is not a valid handle to a transaction object."),
        0xC0190019: ("STATUS_LOG_GROWTH_FAILED","An attempt to create space in the transactional resource manager's log failed. The failure status has been recorded in the event log."),
        0xC0190021: ("STATUS_OBJECT_NO_LONGER_EXISTS","The object (file, stream, or link) that corresponds to the handle has been deleted by a transaction savepoint rollback."),
        0xC0190022: ("STATUS_STREAM_MINIVERSION_NOT_FOUND","The specified file miniversion was not found for this transacted file open."),
        0xC0190023: ("STATUS_STREAM_MINIVERSION_NOT_VALID","The specified file miniversion was found but has been invalidated. The most likely cause is a transaction savepoint rollback."),
        0xC0190024: ("STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION","A miniversion may be opened only in the context of the transaction that created it."),
        0xC0190025: ("STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT","It is not possible to open a miniversion with modify access."),
        0xC0190026: ("STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS","It is not possible to create any more miniversions for this stream."),
        0xC0190028: ("STATUS_HANDLE_NO_LONGER_VALID","The handle has been invalidated by a transaction. The most likely cause is the presence of memory mapping on a file or an open handle when the transaction ended or rolled back to savepoint."),
        0xC0190030: ("STATUS_LOG_CORRUPTION_DETECTED","The log data is corrupt."),
        0xC0190032: ("STATUS_RM_DISCONNECTED","The transaction outcome is unavailable because the resource manager responsible for it is disconnected."),
        0xC0190033: ("STATUS_ENLISTMENT_NOT_SUPERIOR","The request was rejected because the enlistment in question is not a superior enlistment."),
        0xC0190036: ("STATUS_FILE_IDENTITY_NOT_PERSISTENT","The file cannot be opened in a transaction because its identity depends on the outcome of an unresolved transaction."),
        0xC0190037: ("STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY","The operation cannot be performed because another transaction is depending on this property not changing."),
        0xC0190038: ("STATUS_CANT_CROSS_RM_BOUNDARY","The operation would involve a single file with two transactional resource managers and is, therefore, not allowed."),
        0xC0190039: ("STATUS_TXF_DIR_NOT_EMPTY","The $Txf directory must be empty for this operation to succeed."),
        0xC019003A: ("STATUS_INDOUBT_TRANSACTIONS_EXIST","The operation would leave a transactional resource manager in an inconsistent state and is therefore not allowed."),
        0xC019003B: ("STATUS_TM_VOLATILE","The operation could not be completed because the transaction manager does not have a log."),
        0xC019003C: ("STATUS_ROLLBACK_TIMER_EXPIRED","A rollback could not be scheduled because a previously scheduled rollback has already executed or been queued for execution."),
        0xC019003D: ("STATUS_TXF_ATTRIBUTE_CORRUPT","The transactional metadata attribute on the file or directory %hs is corrupt and unreadable."),
        0xC019003E: ("STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION","The encryption operation could not be completed because a transaction is active."),
        0xC019003F: ("STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED","This object is not allowed to be opened in a transaction."),
        0xC0190040: ("STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE","Memory mapping (creating a mapped section) a remote file under a transaction is not supported."),
        0xC0190043: ("STATUS_TRANSACTION_REQUIRED_PROMOTION","Promotion was required to allow the resource manager to enlist, but the transaction was set to disallow it."),
        0xC0190044: ("STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION","This file is open for modification in an unresolved transaction and may be opened for execute only by a transacted reader."),
        0xC0190045: ("STATUS_TRANSACTIONS_NOT_FROZEN","The request to thaw frozen transactions was ignored because transactions were not previously frozen."),
        0xC0190046: ("STATUS_TRANSACTION_FREEZE_IN_PROGRESS","Transactions cannot be frozen because a freeze is already in progress."),
        0xC0190047: ("STATUS_NOT_SNAPSHOT_VOLUME","The target volume is not a snapshot volume. This operation is valid only on a volume mounted as a snapshot."),
        0xC0190048: ("STATUS_NO_SAVEPOINT_WITH_OPEN_FILES","The savepoint operation failed because files are open on the transaction, which is not permitted."),
        0xC0190049: ("STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION","The sparse operation could not be completed because a transaction is active on the file."),
        0xC019004A: ("STATUS_TM_IDENTITY_MISMATCH","The call to create a transaction manager object failed because the Tm Identity that is stored in the log file does not match the Tm Identity that was passed in as an argument."),
        0xC019004B: ("STATUS_FLOATED_SECTION","I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data."),
        0xC019004C: ("STATUS_CANNOT_ACCEPT_TRANSACTED_WORK","The transactional resource manager cannot currently accept transacted work due to a transient condition, such as low resources."),
        0xC019004D: ("STATUS_CANNOT_ABORT_TRANSACTIONS","The transactional resource manager had too many transactions outstanding that could not be aborted. The transactional resource manager has been shut down."),
        0xC019004E: ("STATUS_TRANSACTION_NOT_FOUND","The specified transaction was unable to be opened because it was not found."),
        0xC019004F: ("STATUS_RESOURCEMANAGER_NOT_FOUND","The specified resource manager was unable to be opened because it was not found."),
        0xC0190050: ("STATUS_ENLISTMENT_NOT_FOUND","The specified enlistment was unable to be opened because it was not found."),
        0xC0190051: ("STATUS_TRANSACTIONMANAGER_NOT_FOUND","The specified transaction manager was unable to be opened because it was not found."),
        0xC0190052: ("STATUS_TRANSACTIONMANAGER_NOT_ONLINE","The specified resource manager was unable to create an enlistment because its associated transaction manager is not online."),
        0xC0190053: ("STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION","The specified transaction manager was unable to create the objects contained in its log file in the Ob namespace. Therefore, the transaction manager was unable to recover."),
        0xC0190054: ("STATUS_TRANSACTION_NOT_ROOT","The call to create a superior enlistment on this transaction object could not be completed because the transaction object specified for the enlistment is a subordinate branch of the transaction. Only the root of the transaction can be enlisted as a superior."),
        0xC0190055: ("STATUS_TRANSACTION_OBJECT_EXPIRED","Because the associated transaction manager or resource manager has been closed, the handle is no longer valid."),
        0xC0190056: ("STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION","The compression operation could not be completed because a transaction is active on the file."),
        0xC0190057: ("STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED","The specified operation could not be performed on this superior enlistment because the enlistment was not created with the corresponding completion response in the NotificationMask."),
        0xC0190058: ("STATUS_TRANSACTION_RECORD_TOO_LONG","The specified operation could not be performed because the record to be logged was too long. This can occur because either there are too many enlistments on this transaction or the combined RecoveryInformation being logged on behalf of those enlistments is too long."),
        0xC0190059: ("STATUS_NO_LINK_TRACKING_IN_TRANSACTION","The link-tracking operation could not be completed because a transaction is active."),
        0xC019005A: ("STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION","This operation cannot be performed in a transaction."),
        0xC019005B: ("STATUS_TRANSACTION_INTEGRITY_VIOLATED","The kernel transaction manager had to abort or forget the transaction because it blocked forward progress."),
        0xC0190060: ("STATUS_EXPIRED_HANDLE","The handle is no longer properly associated with its transaction. It may have been opened in a transactional resource manager that was subsequently forced to restart. Please close the handle and open a new one."),
        0xC0190061: ("STATUS_TRANSACTION_NOT_ENLISTED","The specified operation could not be performed because the resource manager is not enlisted in the transaction."),
        0xC01A0001: ("STATUS_LOG_SECTOR_INVALID","The log service found an invalid log sector."),
        0xC01A0002: ("STATUS_LOG_SECTOR_PARITY_INVALID","The log service encountered a log sector with invalid block parity."),
        0xC01A0003: ("STATUS_LOG_SECTOR_REMAPPED","The log service encountered a remapped log sector."),
        0xC01A0004: ("STATUS_LOG_BLOCK_INCOMPLETE","The log service encountered a partial or incomplete log block."),
        0xC01A0005: ("STATUS_LOG_INVALID_RANGE","The log service encountered an attempt to access data outside the active log range."),
        0xC01A0006: ("STATUS_LOG_BLOCKS_EXHAUSTED","The log service user-log marshaling buffers are exhausted."),
        0xC01A0007: ("STATUS_LOG_READ_CONTEXT_INVALID","The log service encountered an attempt to read from a marshaling area with an invalid read context."),
        0xC01A0008: ("STATUS_LOG_RESTART_INVALID","The log service encountered an invalid log restart area."),
        0xC01A0009: ("STATUS_LOG_BLOCK_VERSION","The log service encountered an invalid log block version."),
        0xC01A000A: ("STATUS_LOG_BLOCK_INVALID","The log service encountered an invalid log block."),
        0xC01A000B: ("STATUS_LOG_READ_MODE_INVALID","The log service encountered an attempt to read the log with an invalid read mode."),
        0xC01A000D: ("STATUS_LOG_METADATA_CORRUPT","The log service encountered a corrupted metadata file."),
        0xC01A000E: ("STATUS_LOG_METADATA_INVALID","The log service encountered a metadata file that could not be created by the log file system."),
        0xC01A000F: ("STATUS_LOG_METADATA_INCONSISTENT","The log service encountered a metadata file with inconsistent data."),
        0xC01A0010: ("STATUS_LOG_RESERVATION_INVALID","The log service encountered an attempt to erroneously allocate or dispose reservation space."),
        0xC01A0011: ("STATUS_LOG_CANT_DELETE","The log service cannot delete the log file or the file system container."),
        0xC01A0012: ("STATUS_LOG_CONTAINER_LIMIT_EXCEEDED","The log service has reached the maximum allowable containers allocated to a log file."),
        0xC01A0013: ("STATUS_LOG_START_OF_LOG","The log service has attempted to read or write backward past the start of the log."),
        0xC01A0014: ("STATUS_LOG_POLICY_ALREADY_INSTALLED","The log policy could not be installed because a policy of the same type is already present."),
        0xC01A0015: ("STATUS_LOG_POLICY_NOT_INSTALLED","The log policy in question was not installed at the time of the request."),
        0xC01A0016: ("STATUS_LOG_POLICY_INVALID","The installed set of policies on the log is invalid."),
        0xC01A0017: ("STATUS_LOG_POLICY_CONFLICT","A policy on the log in question prevented the operation from completing."),
        0xC01A0018: ("STATUS_LOG_PINNED_ARCHIVE_TAIL","The log space cannot be reclaimed because the log is pinned by the archive tail."),
        0xC01A0019: ("STATUS_LOG_RECORD_NONEXISTENT","The log record is not a record in the log file."),
        0xC01A001A: ("STATUS_LOG_RECORDS_RESERVED_INVALID","The number of reserved log records or the adjustment of the number of reserved log records is invalid."),
        0xC01A001B: ("STATUS_LOG_SPACE_RESERVED_INVALID","The reserved log space or the adjustment of the log space is invalid."),
        0xC01A001C: ("STATUS_LOG_TAIL_INVALID","A new or existing archive tail or the base of the active log is invalid."),
        0xC01A001D: ("STATUS_LOG_FULL","The log space is exhausted."),
        0xC01A001E: ("STATUS_LOG_MULTIPLEXED","The log is multiplexed; no direct writes to the physical log are allowed."),
        0xC01A001F: ("STATUS_LOG_DEDICATED","The operation failed because the log is dedicated."),
        0xC01A0020: ("STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS","The operation requires an archive context."),
        0xC01A0021: ("STATUS_LOG_ARCHIVE_IN_PROGRESS","Log archival is in progress."),
        0xC01A0022: ("STATUS_LOG_EPHEMERAL","The operation requires a nonephemeral log, but the log is ephemeral."),
        0xC01A0023: ("STATUS_LOG_NOT_ENOUGH_CONTAINERS","The log must have at least two containers before it can be read from or written to."),
        0xC01A0024: ("STATUS_LOG_CLIENT_ALREADY_REGISTERED","A log client has already registered on the stream."),
        0xC01A0025: ("STATUS_LOG_CLIENT_NOT_REGISTERED","A log client has not been registered on the stream."),
        0xC01A0026: ("STATUS_LOG_FULL_HANDLER_IN_PROGRESS","A request has already been made to handle the log full condition."),
        0xC01A0027: ("STATUS_LOG_CONTAINER_READ_FAILED","The log service encountered an error when attempting to read from a log container."),
        0xC01A0028: ("STATUS_LOG_CONTAINER_WRITE_FAILED","The log service encountered an error when attempting to write to a log container."),
        0xC01A0029: ("STATUS_LOG_CONTAINER_OPEN_FAILED","The log service encountered an error when attempting to open a log container."),
        0xC01A002A: ("STATUS_LOG_CONTAINER_STATE_INVALID","The log service encountered an invalid container state when attempting a requested action."),
        0xC01A002B: ("STATUS_LOG_STATE_INVALID","The log service is not in the correct state to perform a requested action."),
        0xC01A002C: ("STATUS_LOG_PINNED","The log space cannot be reclaimed because the log is pinned."),
        0xC01A002D: ("STATUS_LOG_METADATA_FLUSH_FAILED","The log metadata flush failed."),
        0xC01A002E: ("STATUS_LOG_INCONSISTENT_SECURITY","Security on the log and its containers is inconsistent."),
        0xC01A002F: ("STATUS_LOG_APPENDED_FLUSH_FAILED","Records were appended to the log or reservation changes were made, but the log could not be flushed."),
        0xC01A0030: ("STATUS_LOG_PINNED_RESERVATION","The log is pinned due to reservation consuming most of the log space. Free some reserved records to make space available."),
        0xC01B00EA: ("STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD","{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the computer, a dialog box will allow you to upload data about this failure to Microsoft."),
        0xC01C0001: ("STATUS_FLT_NO_HANDLER_DEFINED","A handler was not defined by the filter for this operation."),
        0xC01C0002: ("STATUS_FLT_CONTEXT_ALREADY_DEFINED","A context is already defined for this object."),
        0xC01C0003: ("STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST","Asynchronous requests are not valid for this operation."),
        0xC01C0004: ("STATUS_FLT_DISALLOW_FAST_IO","This is an internal error code used by the filter manager to determine if a fast I/O operation should be forced down the input/output request packet (IRP) path. Minifilters should never return this value."),
        0xC01C0005: ("STATUS_FLT_INVALID_NAME_REQUEST","An invalid name request was made. The name requested cannot be retrieved at this time."),
        0xC01C0006: ("STATUS_FLT_NOT_SAFE_TO_POST_OPERATION","Posting this operation to a worker thread for further processing is not safe at this time because it could lead to a system deadlock."),
        0xC01C0007: ("STATUS_FLT_NOT_INITIALIZED","The Filter Manager was not initialized when a filter tried to register. Make sure that the Filter Manager is loaded as a driver."),
        0xC01C0008: ("STATUS_FLT_FILTER_NOT_READY","The filter is not ready for attachment to volumes because it has not finished initializing (FltStartFiltering has not been called)."),
        0xC01C0009: ("STATUS_FLT_POST_OPERATION_CLEANUP","The filter must clean up any operation-specific context at this time because it is being removed from the system before the operation is completed by the lower drivers."),
        0xC01C000A: ("STATUS_FLT_INTERNAL_ERROR","The Filter Manager had an internal error from which it cannot recover; therefore, the operation has failed. This is usually the result of a filter returning an invalid value from a pre-operation callback."),
        0xC01C000B: ("STATUS_FLT_DELETING_OBJECT","The object specified for this action is in the process of being deleted; therefore, the action requested cannot be completed at this time."),
        0xC01C000C: ("STATUS_FLT_MUST_BE_NONPAGED_POOL","A nonpaged pool must be used for this type of context."),
        0xC01C000D: ("STATUS_FLT_DUPLICATE_ENTRY","A duplicate handler definition has been provided for an operation."),
        0xC01C000E: ("STATUS_FLT_CBDQ_DISABLED","The callback data queue has been disabled."),
        0xC01C000F: ("STATUS_FLT_DO_NOT_ATTACH","Do not attach the filter to the volume at this time."),
        0xC01C0010: ("STATUS_FLT_DO_NOT_DETACH","Do not detach the filter from the volume at this time."),
        0xC01C0011: ("STATUS_FLT_INSTANCE_ALTITUDE_COLLISION","An instance already exists at this altitude on the volume specified."),
        0xC01C0012: ("STATUS_FLT_INSTANCE_NAME_COLLISION","An instance already exists with this name on the volume specified."),
        0xC01C0013: ("STATUS_FLT_FILTER_NOT_FOUND","The system could not find the filter specified."),
        0xC01C0014: ("STATUS_FLT_VOLUME_NOT_FOUND","The system could not find the volume specified."),
        0xC01C0015: ("STATUS_FLT_INSTANCE_NOT_FOUND","The system could not find the instance specified."),
        0xC01C0016: ("STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND","No registered context allocation definition was found for the given request."),
        0xC01C0017: ("STATUS_FLT_INVALID_CONTEXT_REGISTRATION","An invalid parameter was specified during context registration."),
        0xC01C0018: ("STATUS_FLT_NAME_CACHE_MISS","The name requested was not found in the Filter Manager name cache and could not be retrieved from the file system."),
        0xC01C0019: ("STATUS_FLT_NO_DEVICE_OBJECT","The requested device object does not exist for the given volume."),
        0xC01C001A: ("STATUS_FLT_VOLUME_ALREADY_MOUNTED","The specified volume is already mounted."),
        0xC01C001B: ("STATUS_FLT_ALREADY_ENLISTED","The specified transaction context is already enlisted in a transaction."),
        0xC01C001C: ("STATUS_FLT_CONTEXT_ALREADY_LINKED","The specified context is already attached to another object."),
        0xC01C0020: ("STATUS_FLT_NO_WAITER_FOR_REPLY","No waiter is present for the filter's reply to this message."),
        0xC01D0001: ("STATUS_MONITOR_NO_DESCRIPTOR","A monitor descriptor could not be obtained."),
        0xC01D0002: ("STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT","This release does not support the format of the obtained monitor descriptor."),
        0xC01D0003: ("STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM","The checksum of the obtained monitor descriptor is invalid."),
        0xC01D0004: ("STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK","The monitor descriptor contains an invalid standard timing block."),
        0xC01D0005: ("STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED","WMI data-block registration failed for one of the MSMonitorClass WMI subclasses."),
        0xC01D0006: ("STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK","The provided monitor descriptor block is either corrupted or does not contain the monitor's detailed serial number."),
        0xC01D0007: ("STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK","The provided monitor descriptor block is either corrupted or does not contain the monitor's user-friendly name."),
        0xC01D0008: ("STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA","There is no monitor descriptor data at the specified (offset or size) region."),
        0xC01D0009: ("STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK","The monitor descriptor contains an invalid detailed timing block."),
        0xC01D000A: ("STATUS_MONITOR_INVALID_MANUFACTURE_DATE","Monitor descriptor contains invalid manufacture date."),
        0xC01E0000: ("STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER","Exclusive mode ownership is needed to create an unmanaged primary allocation."),
        0xC01E0001: ("STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER","The driver needs more DMA buffer space to complete the requested operation."),
        0xC01E0002: ("STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER","The specified display adapter handle is invalid."),
        0xC01E0003: ("STATUS_GRAPHICS_ADAPTER_WAS_RESET","The specified display adapter and all of its state have been reset."),
        0xC01E0004: ("STATUS_GRAPHICS_INVALID_DRIVER_MODEL","The driver stack does not match the expected driver model."),
        0xC01E0005: ("STATUS_GRAPHICS_PRESENT_MODE_CHANGED","Present happened but ended up into the changed desktop mode."),
        0xC01E0006: ("STATUS_GRAPHICS_PRESENT_OCCLUDED","Nothing to present due to desktop occlusion."),
        0xC01E0007: ("STATUS_GRAPHICS_PRESENT_DENIED","Not able to present due to denial of desktop access."),
        0xC01E0008: ("STATUS_GRAPHICS_CANNOTCOLORCONVERT","Not able to present with color conversion."),
        0xC01E000B: ("STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED","Present redirection is disabled (desktop windowing management subsystem is off)."),
        0xC01E000C: ("STATUS_GRAPHICS_PRESENT_UNOCCLUDED","Previous exclusive VidPn source owner has released its ownership"),
        0xC01E0100: ("STATUS_GRAPHICS_NO_VIDEO_MEMORY","Not enough video memory is available to complete the operation."),
        0xC01E0101: ("STATUS_GRAPHICS_CANT_LOCK_MEMORY","Could not probe and lock the underlying memory of an allocation."),
        0xC01E0102: ("STATUS_GRAPHICS_ALLOCATION_BUSY","The allocation is currently busy."),
        0xC01E0103: ("STATUS_GRAPHICS_TOO_MANY_REFERENCES","An object being referenced has already reached the maximum reference count and cannot be referenced further."),
        0xC01E0104: ("STATUS_GRAPHICS_TRY_AGAIN_LATER","A problem could not be solved due to an existing condition. Try again later."),
        0xC01E0105: ("STATUS_GRAPHICS_TRY_AGAIN_NOW","A problem could not be solved due to an existing condition. Try again now."),
        0xC01E0106: ("STATUS_GRAPHICS_ALLOCATION_INVALID","The allocation is invalid."),
        0xC01E0107: ("STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE","No more unswizzling apertures are currently available."),
        0xC01E0108: ("STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED","The current allocation cannot be unswizzled by an aperture."),
        0xC01E0109: ("STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION","The request failed because a pinned allocation cannot be evicted."),
        0xC01E0110: ("STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE","The allocation cannot be used from its current segment location for the specified operation."),
        0xC01E0111: ("STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION","A locked allocation cannot be used in the current command buffer."),
        0xC01E0112: ("STATUS_GRAPHICS_ALLOCATION_CLOSED","The allocation being referenced has been closed permanently."),
        0xC01E0113: ("STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE","An invalid allocation instance is being referenced."),
        0xC01E0114: ("STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE","An invalid allocation handle is being referenced."),
        0xC01E0115: ("STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE","The allocation being referenced does not belong to the current device."),
        0xC01E0116: ("STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST","The specified allocation lost its content."),
        0xC01E0200: ("STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE","A GPU exception was detected on the given device. The device cannot be scheduled."),
        0xC01E0300: ("STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY","The specified VidPN topology is invalid."),
        0xC01E0301: ("STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED","The specified VidPN topology is valid but is not supported by this model of the display adapter."),
        0xC01E0302: ("STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED","The specified VidPN topology is valid but is not currently supported by the display adapter due to allocation of its resources."),
        0xC01E0303: ("STATUS_GRAPHICS_INVALID_VIDPN","The specified VidPN handle is invalid."),
        0xC01E0304: ("STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE","The specified video present source is invalid."),
        0xC01E0305: ("STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET","The specified video present target is invalid."),
        0xC01E0306: ("STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED","The specified VidPN modality is not supported (for example, at least two of the pinned modes are not co-functional)."),
        0xC01E0308: ("STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET","The specified VidPN source mode set is invalid."),
        0xC01E0309: ("STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET","The specified VidPN target mode set is invalid."),
        0xC01E030A: ("STATUS_GRAPHICS_INVALID_FREQUENCY","The specified video signal frequency is invalid."),
        0xC01E030B: ("STATUS_GRAPHICS_INVALID_ACTIVE_REGION","The specified video signal active region is invalid."),
        0xC01E030C: ("STATUS_GRAPHICS_INVALID_TOTAL_REGION","The specified video signal total region is invalid."),
        0xC01E0310: ("STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE","The specified video present source mode is invalid."),
        0xC01E0311: ("STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE","The specified video present target mode is invalid."),
        0xC01E0312: ("STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET","The pinned mode must remain in the set on the VidPN's co-functional modality enumeration."),
        0xC01E0313: ("STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY","The specified video present path is already in the VidPN's topology."),
        0xC01E0314: ("STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET","The specified mode is already in the mode set."),
        0xC01E0315: ("STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET","The specified video present source set is invalid."),
        0xC01E0316: ("STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET","The specified video present target set is invalid."),
        0xC01E0317: ("STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET","The specified video present source is already in the video present source set."),
        0xC01E0318: ("STATUS_GRAPHICS_TARGET_ALREADY_IN_SET","The specified video present target is already in the video present target set."),
        0xC01E0319: ("STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH","The specified VidPN present path is invalid."),
        0xC01E031A: ("STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY","The miniport has no recommendation for augmenting the specified VidPN's topology."),
        0xC01E031B: ("STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET","The specified monitor frequency range set is invalid."),
        0xC01E031C: ("STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE","The specified monitor frequency range is invalid."),
        0xC01E031D: ("STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET","The specified frequency range is not in the specified monitor frequency range set."),
        0xC01E031F: ("STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET","The specified frequency range is already in the specified monitor frequency range set."),
        0xC01E0320: ("STATUS_GRAPHICS_STALE_MODESET","The specified mode set is stale. Reacquire the new mode set."),
        0xC01E0321: ("STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET","The specified monitor source mode set is invalid."),
        0xC01E0322: ("STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE","The specified monitor source mode is invalid."),
        0xC01E0323: ("STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN","The miniport does not have a recommendation regarding the request to provide a functional VidPN given the current display adapter configuration."),
        0xC01E0324: ("STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE","The ID of the specified mode is being used by another mode in the set."),
        0xC01E0325: ("STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION","The system failed to determine a mode that is supported by both the display adapter and the monitor connected to it."),
        0xC01E0326: ("STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES","The number of video present targets must be greater than or equal to the number of video present sources."),
        0xC01E0327: ("STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY","The specified present path is not in the VidPN's topology."),
        0xC01E0328: ("STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE","The display adapter must have at least one video present source."),
        0xC01E0329: ("STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET","The display adapter must have at least one video present target."),
        0xC01E032A: ("STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET","The specified monitor descriptor set is invalid."),
        0xC01E032B: ("STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR","The specified monitor descriptor is invalid."),
        0xC01E032C: ("STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET","The specified descriptor is not in the specified monitor descriptor set."),
        0xC01E032D: ("STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET","The specified descriptor is already in the specified monitor descriptor set."),
        0xC01E032E: ("STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE","The ID of the specified monitor descriptor is being used by another descriptor in the set."),
        0xC01E032F: ("STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE","The specified video present target subset type is invalid."),
        0xC01E0330: ("STATUS_GRAPHICS_RESOURCES_NOT_RELATED","Two or more of the specified resources are not related to each other, as defined by the interface semantics."),
        0xC01E0331: ("STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE","The ID of the specified video present source is being used by another source in the set."),
        0xC01E0332: ("STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE","The ID of the specified video present target is being used by another target in the set."),
        0xC01E0333: ("STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET","The specified VidPN source cannot be used because there is no available VidPN target to connect it to."),
        0xC01E0334: ("STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER","The newly arrived monitor could not be associated with a display adapter."),
        0xC01E0335: ("STATUS_GRAPHICS_NO_VIDPNMGR","The particular display adapter does not have an associated VidPN manager."),
        0xC01E0336: ("STATUS_GRAPHICS_NO_ACTIVE_VIDPN","The VidPN manager of the particular display adapter does not have an active VidPN."),
        0xC01E0337: ("STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY","The specified VidPN topology is stale; obtain the new topology."),
        0xC01E0338: ("STATUS_GRAPHICS_MONITOR_NOT_CONNECTED","No monitor is connected on the specified video present target."),
        0xC01E0339: ("STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY","The specified source is not part of the specified VidPN's topology."),
        0xC01E033A: ("STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE","The specified primary surface size is invalid."),
        0xC01E033B: ("STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE","The specified visible region size is invalid."),
        0xC01E033C: ("STATUS_GRAPHICS_INVALID_STRIDE","The specified stride is invalid."),
        0xC01E033D: ("STATUS_GRAPHICS_INVALID_PIXELFORMAT","The specified pixel format is invalid."),
        0xC01E033E: ("STATUS_GRAPHICS_INVALID_COLORBASIS","The specified color basis is invalid."),
        0xC01E033F: ("STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE","The specified pixel value access mode is invalid."),
        0xC01E0340: ("STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY","The specified target is not part of the specified VidPN's topology."),
        0xC01E0341: ("STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT","Failed to acquire the display mode management interface."),
        0xC01E0342: ("STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE","The specified VidPN source is already owned by a DMM client and cannot be used until that client releases it."),
        0xC01E0343: ("STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN","The specified VidPN is active and cannot be accessed."),
        0xC01E0344: ("STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL","The specified VidPN's present path importance ordinal is invalid."),
        0xC01E0345: ("STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION","The specified VidPN's present path content geometry transformation is invalid."),
        0xC01E0346: ("STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED","The specified content geometry transformation is not supported on the respective VidPN present path."),
        0xC01E0347: ("STATUS_GRAPHICS_INVALID_GAMMA_RAMP","The specified gamma ramp is invalid."),
        0xC01E0348: ("STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED","The specified gamma ramp is not supported on the respective VidPN present path."),
        0xC01E0349: ("STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED","Multisampling is not supported on the respective VidPN present path."),
        0xC01E034A: ("STATUS_GRAPHICS_MODE_NOT_IN_MODESET","The specified mode is not in the specified mode set."),
        0xC01E034D: ("STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON","The specified VidPN topology recommendation reason is invalid."),
        0xC01E034E: ("STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE","The specified VidPN present path content type is invalid."),
        0xC01E034F: ("STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE","The specified VidPN present path copy protection type is invalid."),
        0xC01E0350: ("STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS","Only one unassigned mode set can exist at any one time for a particular VidPN source or target."),
        0xC01E0352: ("STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING","The specified scan line ordering type is invalid."),
        0xC01E0353: ("STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED","The topology changes are not allowed for the specified VidPN."),
        0xC01E0354: ("STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS","All available importance ordinals are being used in the specified topology."),
        0xC01E0355: ("STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT","The specified primary surface has a different private-format attribute than the current primary surface."),
        0xC01E0356: ("STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM","The specified mode-pruning algorithm is invalid."),
        0xC01E0357: ("STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN","The specified monitor-capability origin is invalid."),
        0xC01E0358: ("STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT","The specified monitor-frequency range constraint is invalid."),
        0xC01E0359: ("STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED","The maximum supported number of present paths has been reached."),
        0xC01E035A: ("STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION","The miniport requested that augmentation be canceled for the specified source of the specified VidPN's topology."),
        0xC01E035B: ("STATUS_GRAPHICS_INVALID_CLIENT_TYPE","The specified client type was not recognized."),
        0xC01E035C: ("STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET","The client VidPN is not set on this adapter (for example, no user mode-initiated mode changes have taken place on this adapter)."),
        0xC01E0400: ("STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED","The specified display adapter child device already has an external device connected to it."),
        0xC01E0401: ("STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED","The display adapter child device does not support reporting a descriptor."),
        0xC01E0430: ("STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER","The display adapter is not linked to any other adapters."),
        0xC01E0431: ("STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED","The lead adapter in a linked configuration was not enumerated yet."),
        0xC01E0432: ("STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED","Some chain adapters in a linked configuration have not yet been enumerated."),
        0xC01E0433: ("STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY","The chain of linked adapters is not ready to start because of an unknown failure."),
        0xC01E0434: ("STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED","An attempt was made to start a lead link display adapter when the chain links had not yet started."),
        0xC01E0435: ("STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON","An attempt was made to turn on a lead link display adapter when the chain links were turned off."),
        0xC01E0436: ("STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE","The adapter link was found in an inconsistent state. Not all adapters are in an expected PNP/power state."),
        0xC01E0438: ("STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER","The driver trying to start is not the same as the driver for the posted display adapter."),
        0xC01E043B: ("STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED","An operation is being attempted that requires the display adapter to be in a quiescent state."),
        0xC01E0500: ("STATUS_GRAPHICS_OPM_NOT_SUPPORTED","The driver does not support OPM."),
        0xC01E0501: ("STATUS_GRAPHICS_COPP_NOT_SUPPORTED","The driver does not support COPP."),
        0xC01E0502: ("STATUS_GRAPHICS_UAB_NOT_SUPPORTED","The driver does not support UAB."),
        0xC01E0503: ("STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS","The specified encrypted parameters are invalid."),
        0xC01E0504: ("STATUS_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL","An array passed to a function cannot hold all of the data that the function wants to put in it."),
        0xC01E0505: ("STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST","The GDI display device passed to this function does not have any active protected outputs."),
        0xC01E0506: ("STATUS_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME","The PVP cannot find an actual GDI display device that corresponds to the passed-in GDI display device name."),
        0xC01E0507: ("STATUS_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP","This function failed because the GDI display device passed to it was not attached to the Windows desktop."),
        0xC01E0508: ("STATUS_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED","The PVP does not support mirroring display devices because they do not have any protected outputs."),
        0xC01E050A: ("STATUS_GRAPHICS_OPM_INVALID_POINTER","The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, is not correctly aligned, or it points to an invalid address or a kernel mode address."),
        0xC01E050B: ("STATUS_GRAPHICS_OPM_INTERNAL_ERROR","An internal error caused an operation to fail."),
        0xC01E050C: ("STATUS_GRAPHICS_OPM_INVALID_HANDLE","The function failed because the caller passed in an invalid OPM user-mode handle."),
        0xC01E050D: ("STATUS_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE","This function failed because the GDI device passed to it did not have any monitors associated with it."),
        0xC01E050E: ("STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH","A certificate could not be returned because the certificate buffer passed to the function was too small."),
        0xC01E050F: ("STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED","DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present yarget is in spanning mode."),
        0xC01E0510: ("STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED","DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present target is in theater mode."),
        0xC01E0511: ("STATUS_GRAPHICS_PVP_HFS_FAILED","The function call failed because the display adapter's hardware functionality scan (HFS) failed to validate the graphics hardware."),
        0xC01E0512: ("STATUS_GRAPHICS_OPM_INVALID_SRM","The HDCP SRM passed to this function did not comply with section 5 of the HDCP 1.1 specification."),
        0xC01E0513: ("STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP","The protected output cannot enable the HDCP system because it does not support it."),
        0xC01E0514: ("STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP","The protected output cannot enable analog copy protection because it does not support it."),
        0xC01E0515: ("STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA","The protected output cannot enable the CGMS-A protection technology because it does not support it."),
        0xC01E0516: ("STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET","DxgkDdiOPMGetInformation() cannot return the version of the SRM being used because the application never successfully passed an SRM to the protected output."),
        0xC01E0517: ("STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH","DxgkDdiOPMConfigureProtectedOutput() cannot enable the specified output protection technology because the output's screen resolution is too high."),
        0xC01E0518: ("STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE","DxgkDdiOPMConfigureProtectedOutput() cannot enable HDCP because other physical outputs are using the display adapter's HDCP hardware."),
        0xC01E051A: ("STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS","The operating system asynchronously destroyed this OPM-protected output because the operating system state changed. This error typically occurs because the monitor PDO associated with this protected output was removed or stopped, the protected output's session became a nonconsole session, or the protected output's desktop became inactive."),
        0xC01E051B: ("STATUS_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS","OPM functions cannot be called when a session is changing its type. Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA)."),
        0xC01E051C: ("STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS","The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed. This error is returned only if a protected output has OPM semantics.  DxgkDdiOPMGetCOPPCompatibleInformation always returns this error if a protected output has OPM semantics.  DxgkDdiOPMGetInformation returns this error code if the caller requested COPP-specific information.  DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use a COPP-specific command."),
        0xC01E051D: ("STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST","The DxgkDdiOPMGetInformation and DxgkDdiOPMGetCOPPCompatibleInformation functions return this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid."),
        0xC01E051E: ("STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR","The function failed because an unexpected error occurred inside a display driver."),
        0xC01E051F: ("STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS","The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed. This error is returned only if a protected output has COPP semantics.  DxgkDdiOPMGetCOPPCompatibleInformation returns this error code if the caller requested OPM-specific information.  DxgkDdiOPMGetInformation always returns this error if a protected output has COPP semantics.  DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use an OPM-specific command."),
        0xC01E0520: ("STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED","The DxgkDdiOPMGetCOPPCompatibleInformation and DxgkDdiOPMConfigureProtectedOutput functions return this error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXGKMDT_OPM_SET_ACP_AND_CGMSA_SIGNALING GUIDs."),
        0xC01E0521: ("STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST","The DxgkDdiOPMConfigureProtectedOutput function returns this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid."),
        0xC01E0580: ("STATUS_GRAPHICS_I2C_NOT_SUPPORTED","The monitor connected to the specified video output does not have an I2C bus."),
        0xC01E0581: ("STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST","No device on the I2C bus has the specified address."),
        0xC01E0582: ("STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA","An error occurred while transmitting data to the device on the I2C bus."),
        0xC01E0583: ("STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA","An error occurred while receiving data from the device on the I2C bus."),
        0xC01E0584: ("STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED","The monitor does not support the specified VCP code."),
        0xC01E0585: ("STATUS_GRAPHICS_DDCCI_INVALID_DATA","The data received from the monitor is invalid."),
        0xC01E0586: ("STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE","A function call failed because a monitor returned an invalid timing status byte when the operating system used the DDC/CI get timing report and timing message command to get a timing report from a monitor."),
        0xC01E0587: ("STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING","A monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification."),
        0xC01E0588: ("STATUS_GRAPHICS_MCA_INTERNAL_ERROR","An internal error caused an operation to fail."),
        0xC01E0589: ("STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND","An operation failed because a DDC/CI message had an invalid value in its command field."),
        0xC01E058A: ("STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH","This error occurred because a DDC/CI message had an invalid value in its length field."),
        0xC01E058B: ("STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM","This error occurred because the value in a DDC/CI message's checksum field did not match the message's computed checksum value. This error implies that the data was corrupted while it was being transmitted from a monitor to a computer."),
        0xC01E058C: ("STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE","This function failed because an invalid monitor handle was passed to it."),
        0xC01E058D: ("STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS","The operating system asynchronously destroyed the monitor that corresponds to this handle because the operating system's state changed. This error typically occurs because the monitor PDO associated with this handle was removed or stopped, or a display mode change occurred. A display mode change occurs when Windows sends a WM_DISPLAYCHANGE message to applications."),
        0xC01E05E0: ("STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED","This function can be used only if a program is running in the local console session. It cannot be used if a program is running on a remote desktop session or on a terminal server session."),
        0xC01E05E1: ("STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME","This function cannot find an actual GDI display device that corresponds to the specified GDI display device name."),
        0xC01E05E2: ("STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP","The function failed because the specified GDI display device was not attached to the Windows desktop."),
        0xC01E05E3: ("STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED","This function does not support GDI mirroring display devices because GDI mirroring display devices do not have any physical monitors associated with them."),
        0xC01E05E4: ("STATUS_GRAPHICS_INVALID_POINTER","The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, is not correctly aligned, or points to an invalid address or to a kernel mode address."),
        0xC01E05E5: ("STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE","This function failed because the GDI device passed to it did not have a monitor associated with it."),
        0xC01E05E6: ("STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL","An array passed to the function cannot hold all of the data that the function must copy into the array."),
        0xC01E05E7: ("STATUS_GRAPHICS_INTERNAL_ERROR","An internal error caused an operation to fail."),
        0xC01E05E8: ("STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS","The function failed because the current session is changing its type. This function cannot be called when the current session is changing its type. Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA)."),
        0xC0210000: ("STATUS_FVE_LOCKED_VOLUME","The volume must be unlocked before it can be used."),
        0xC0210001: ("STATUS_FVE_NOT_ENCRYPTED","The volume is fully decrypted and no key is available."),
        0xC0210002: ("STATUS_FVE_BAD_INFORMATION","The control block for the encrypted volume is not valid."),
        0xC0210003: ("STATUS_FVE_TOO_SMALL","Not enough free space remains on the volume to allow encryption."),
        0xC0210004: ("STATUS_FVE_FAILED_WRONG_FS","The partition cannot be encrypted because the file system is not supported."),
        0xC0210005: ("STATUS_FVE_FAILED_BAD_FS","The file system is inconsistent. Run the Check Disk utility."),
        0xC0210006: ("STATUS_FVE_FS_NOT_EXTENDED","The file system does not extend to the end of the volume."),
        0xC0210007: ("STATUS_FVE_FS_MOUNTED","This operation cannot be performed while a file system is mounted on the volume."),
        0xC0210008: ("STATUS_FVE_NO_LICENSE","BitLocker Drive Encryption is not included with this version of Windows."),
        0xC0210009: ("STATUS_FVE_ACTION_NOT_ALLOWED","The requested action was denied by the FVE control engine."),
        0xC021000A: ("STATUS_FVE_BAD_DATA","The data supplied is malformed."),
        0xC021000B: ("STATUS_FVE_VOLUME_NOT_BOUND","The volume is not bound to the system."),
        0xC021000C: ("STATUS_FVE_NOT_DATA_VOLUME","The volume specified is not a data volume."),
        0xC021000D: ("STATUS_FVE_CONV_READ_ERROR","A read operation failed while converting the volume."),
        0xC021000E: ("STATUS_FVE_CONV_WRITE_ERROR","A write operation failed while converting the volume."),
        0xC021000F: ("STATUS_FVE_OVERLAPPED_UPDATE","The control block for the encrypted volume was updated by another thread. Try again."),
        0xC0210010: ("STATUS_FVE_FAILED_SECTOR_SIZE","The volume encryption algorithm cannot be used on this sector size."),
        0xC0210011: ("STATUS_FVE_FAILED_AUTHENTICATION","BitLocker recovery authentication failed."),
        0xC0210012: ("STATUS_FVE_NOT_OS_VOLUME","The volume specified is not the boot operating system volume."),
        0xC0210013: ("STATUS_FVE_KEYFILE_NOT_FOUND","The BitLocker startup key or recovery password could not be read from external media."),
        0xC0210014: ("STATUS_FVE_KEYFILE_INVALID","The BitLocker startup key or recovery password file is corrupt or invalid."),
        0xC0210015: ("STATUS_FVE_KEYFILE_NO_VMK","The BitLocker encryption key could not be obtained from the startup key or the recovery password."),
        0xC0210016: ("STATUS_FVE_TPM_DISABLED","The TPM is disabled."),
        0xC0210017: ("STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO","The authorization data for the SRK of the TPM is not zero."),
        0xC0210018: ("STATUS_FVE_TPM_INVALID_PCR","The system boot information changed or the TPM locked out access to BitLocker encryption keys until the computer is restarted."),
        0xC0210019: ("STATUS_FVE_TPM_NO_VMK","The BitLocker encryption key could not be obtained from the TPM."),
        0xC021001A: ("STATUS_FVE_PIN_INVALID","The BitLocker encryption key could not be obtained from the TPM and PIN."),
        0xC021001B: ("STATUS_FVE_AUTH_INVALID_APPLICATION","A boot application hash does not match the hash computed when BitLocker was turned on."),
        0xC021001C: ("STATUS_FVE_AUTH_INVALID_CONFIG","The Boot Configuration Data (BCD) settings are not supported or have changed because BitLocker was enabled."),
        0xC021001D: ("STATUS_FVE_DEBUGGER_ENABLED","Boot debugging is enabled. Run Windows Boot Configuration Data Store Editor (bcdedit.exe) to turn it off."),
        0xC021001E: ("STATUS_FVE_DRY_RUN_FAILED","The BitLocker encryption key could not be obtained."),
        0xC021001F: ("STATUS_FVE_BAD_METADATA_POINTER","The metadata disk region pointer is incorrect."),
        0xC0210020: ("STATUS_FVE_OLD_METADATA_COPY","The backup copy of the metadata is out of date."),
        0xC0210021: ("STATUS_FVE_REBOOT_REQUIRED","No action was taken because a system restart is required."),
        0xC0210022: ("STATUS_FVE_RAW_ACCESS","No action was taken because BitLocker Drive Encryption is in RAW access mode."),
        0xC0210023: ("STATUS_FVE_RAW_BLOCKED","BitLocker Drive Encryption cannot enter RAW access mode for this volume."),
        0xC0210026: ("STATUS_FVE_NO_FEATURE_LICENSE","This feature of BitLocker Drive Encryption is not included with this version of Windows."),
        0xC0210027: ("STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED","Group policy does not permit turning off BitLocker Drive Encryption on roaming data volumes."),
        0xC0210028: ("STATUS_FVE_CONV_RECOVERY_FAILED","Bitlocker Drive Encryption failed to recover from aborted conversion. This could be due to either all conversion logs being corrupted or the media being write-protected."),
        0xC0210029: ("STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG","The requested virtualization size is too big."),
        0xC0210030: ("STATUS_FVE_VOLUME_TOO_SMALL","The drive is too small to be protected using BitLocker Drive Encryption."),
        0xC0220001: ("STATUS_FWP_CALLOUT_NOT_FOUND","The callout does not exist."),
        0xC0220002: ("STATUS_FWP_CONDITION_NOT_FOUND","The filter condition does not exist."),
        0xC0220003: ("STATUS_FWP_FILTER_NOT_FOUND","The filter does not exist."),
        0xC0220004: ("STATUS_FWP_LAYER_NOT_FOUND","The layer does not exist."),
        0xC0220005: ("STATUS_FWP_PROVIDER_NOT_FOUND","The provider does not exist."),
        0xC0220006: ("STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND","The provider context does not exist."),
        0xC0220007: ("STATUS_FWP_SUBLAYER_NOT_FOUND","The sublayer does not exist."),
        0xC0220008: ("STATUS_FWP_NOT_FOUND","The object does not exist."),
        0xC0220009: ("STATUS_FWP_ALREADY_EXISTS","An object with that GUID or LUID already exists."),
        0xC022000A: ("STATUS_FWP_IN_USE","The object is referenced by other objects and cannot be deleted."),
        0xC022000B: ("STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS","The call is not allowed from within a dynamic session."),
        0xC022000C: ("STATUS_FWP_WRONG_SESSION","The call was made from the wrong session and cannot be completed."),
        0xC022000D: ("STATUS_FWP_NO_TXN_IN_PROGRESS","The call must be made from within an explicit transaction."),
        0xC022000E: ("STATUS_FWP_TXN_IN_PROGRESS","The call is not allowed from within an explicit transaction."),
        0xC022000F: ("STATUS_FWP_TXN_ABORTED","The explicit transaction has been forcibly canceled."),
        0xC0220010: ("STATUS_FWP_SESSION_ABORTED","The session has been canceled."),
        0xC0220011: ("STATUS_FWP_INCOMPATIBLE_TXN","The call is not allowed from within a read-only transaction."),
        0xC0220012: ("STATUS_FWP_TIMEOUT","The call timed out while waiting to acquire the transaction lock."),
        0xC0220013: ("STATUS_FWP_NET_EVENTS_DISABLED","The collection of network diagnostic events is disabled."),
        0xC0220014: ("STATUS_FWP_INCOMPATIBLE_LAYER","The operation is not supported by the specified layer."),
        0xC0220015: ("STATUS_FWP_KM_CLIENTS_ONLY","The call is allowed for kernel-mode callers only."),
        0xC0220016: ("STATUS_FWP_LIFETIME_MISMATCH","The call tried to associate two objects with incompatible lifetimes."),
        0xC0220017: ("STATUS_FWP_BUILTIN_OBJECT","The object is built-in and cannot be deleted."),
        0xC0220018: ("STATUS_FWP_TOO_MANY_BOOTTIME_FILTERS","The maximum number of boot-time filters has been reached."),
        0xC0220018: ("STATUS_FWP_TOO_MANY_CALLOUTS","The maximum number of callouts has been reached."),
        0xC0220019: ("STATUS_FWP_NOTIFICATION_DROPPED","A notification could not be delivered because a message queue has reached maximum capacity."),
        0xC022001A: ("STATUS_FWP_TRAFFIC_MISMATCH","The traffic parameters do not match those for the security association context."),
        0xC022001B: ("STATUS_FWP_INCOMPATIBLE_SA_STATE","The call is not allowed for the current security association state."),
        0xC022001C: ("STATUS_FWP_NULL_POINTER","A required pointer is null."),
        0xC022001D: ("STATUS_FWP_INVALID_ENUMERATOR","An enumerator is not valid."),
        0xC022001E: ("STATUS_FWP_INVALID_FLAGS","The flags field contains an invalid value."),
        0xC022001F: ("STATUS_FWP_INVALID_NET_MASK","A network mask is not valid."),
        0xC0220020: ("STATUS_FWP_INVALID_RANGE","An FWP_RANGE is not valid."),
        0xC0220021: ("STATUS_FWP_INVALID_INTERVAL","The time interval is not valid."),
        0xC0220022: ("STATUS_FWP_ZERO_LENGTH_ARRAY","An array that must contain at least one element has a zero length."),
        0xC0220023: ("STATUS_FWP_NULL_DISPLAY_NAME","The displayData.name field cannot be null."),
        0xC0220024: ("STATUS_FWP_INVALID_ACTION_TYPE","The action type is not one of the allowed action types for a filter."),
        0xC0220025: ("STATUS_FWP_INVALID_WEIGHT","The filter weight is not valid."),
        0xC0220026: ("STATUS_FWP_MATCH_TYPE_MISMATCH","A filter condition contains a match type that is not compatible with the operands."),
        0xC0220027: ("STATUS_FWP_TYPE_MISMATCH","An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type."),
        0xC0220028: ("STATUS_FWP_OUT_OF_BOUNDS","An integer value is outside the allowed range."),
        0xC0220029: ("STATUS_FWP_RESERVED","A reserved field is nonzero."),
        0xC022002A: ("STATUS_FWP_DUPLICATE_CONDITION","A filter cannot contain multiple conditions operating on a single field."),
        0xC022002B: ("STATUS_FWP_DUPLICATE_KEYMOD","A policy cannot contain the same keying module more than once."),
        0xC022002C: ("STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER","The action type is not compatible with the layer."),
        0xC022002D: ("STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER","The action type is not compatible with the sublayer."),
        0xC022002E: ("STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER","The raw context or the provider context is not compatible with the layer."),
        0xC022002F: ("STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT","The raw context or the provider context is not compatible with the callout."),
        0xC0220030: ("STATUS_FWP_INCOMPATIBLE_AUTH_METHOD","The authentication method is not compatible with the policy type."),
        0xC0220031: ("STATUS_FWP_INCOMPATIBLE_DH_GROUP","The Diffie-Hellman group is not compatible with the policy type."),
        0xC0220032: ("STATUS_FWP_EM_NOT_SUPPORTED","An IKE policy cannot contain an Extended Mode policy."),
        0xC0220033: ("STATUS_FWP_NEVER_MATCH","The enumeration template or subscription will never match any objects."),
        0xC0220034: ("STATUS_FWP_PROVIDER_CONTEXT_MISMATCH","The provider context is of the wrong type."),
        0xC0220035: ("STATUS_FWP_INVALID_PARAMETER","The parameter is incorrect."),
        0xC0220036: ("STATUS_FWP_TOO_MANY_SUBLAYERS","The maximum number of sublayers has been reached."),
        0xC0220037: ("STATUS_FWP_CALLOUT_NOTIFICATION_FAILED","The notification function for a callout returned an error."),
        0xC0220038: ("STATUS_FWP_INCOMPATIBLE_AUTH_CONFIG","The IPsec authentication configuration is not compatible with the authentication type."),
        0xC0220039: ("STATUS_FWP_INCOMPATIBLE_CIPHER_CONFIG","The IPsec cipher configuration is not compatible with the cipher type."),
        0xC022003C: ("STATUS_FWP_DUPLICATE_AUTH_METHOD","A policy cannot contain the same auth method more than once."),
        0xC0220100: ("STATUS_FWP_TCPIP_NOT_READY","The TCP/IP stack is not ready."),
        0xC0220101: ("STATUS_FWP_INJECT_HANDLE_CLOSING","The injection handle is being closed by another thread."),
        0xC0220102: ("STATUS_FWP_INJECT_HANDLE_STALE","The injection handle is stale."),
        0xC0220103: ("STATUS_FWP_CANNOT_PEND","The classify cannot be pended."),
        0xC0230002: ("STATUS_NDIS_CLOSING","The binding to the network interface is being closed."),
        0xC0230004: ("STATUS_NDIS_BAD_VERSION","An invalid version was specified."),
        0xC0230005: ("STATUS_NDIS_BAD_CHARACTERISTICS","An invalid characteristics table was used."),
        0xC0230006: ("STATUS_NDIS_ADAPTER_NOT_FOUND","Failed to find the network interface or the network interface is not ready."),
        0xC0230007: ("STATUS_NDIS_OPEN_FAILED","Failed to open the network interface."),
        0xC0230008: ("STATUS_NDIS_DEVICE_FAILED","The network interface has encountered an internal unrecoverable failure."),
        0xC0230009: ("STATUS_NDIS_MULTICAST_FULL","The multicast list on the network interface is full."),
        0xC023000A: ("STATUS_NDIS_MULTICAST_EXISTS","An attempt was made to add a duplicate multicast address to the list."),
        0xC023000B: ("STATUS_NDIS_MULTICAST_NOT_FOUND","At attempt was made to remove a multicast address that was never added."),
        0xC023000C: ("STATUS_NDIS_REQUEST_ABORTED","The network interface aborted the request."),
        0xC023000D: ("STATUS_NDIS_RESET_IN_PROGRESS","The network interface cannot process the request because it is being reset."),
        0xC023000F: ("STATUS_NDIS_INVALID_PACKET","An attempt was made to send an invalid packet on a network interface."),
        0xC0230010: ("STATUS_NDIS_INVALID_DEVICE_REQUEST","The specified request is not a valid operation for the target device."),
        0xC0230011: ("STATUS_NDIS_ADAPTER_NOT_READY","The network interface is not ready to complete this operation."),
        0xC0230014: ("STATUS_NDIS_INVALID_LENGTH","The length of the buffer submitted for this operation is not valid."),
        0xC0230015: ("STATUS_NDIS_INVALID_DATA","The data used for this operation is not valid."),
        0xC0230016: ("STATUS_NDIS_BUFFER_TOO_SHORT","The length of the submitted buffer for this operation is too small."),
        0xC0230017: ("STATUS_NDIS_INVALID_OID","The network interface does not support this object identifier."),
        0xC0230018: ("STATUS_NDIS_ADAPTER_REMOVED","The network interface has been removed."),
        0xC0230019: ("STATUS_NDIS_UNSUPPORTED_MEDIA","The network interface does not support this media type."),
        0xC023001A: ("STATUS_NDIS_GROUP_ADDRESS_IN_USE","An attempt was made to remove a token ring group address that is in use by other components."),
        0xC023001B: ("STATUS_NDIS_FILE_NOT_FOUND","An attempt was made to map a file that cannot be found."),
        0xC023001C: ("STATUS_NDIS_ERROR_READING_FILE","An error occurred while NDIS tried to map the file."),
        0xC023001D: ("STATUS_NDIS_ALREADY_MAPPED","An attempt was made to map a file that is already mapped."),
        0xC023001E: ("STATUS_NDIS_RESOURCE_CONFLICT","An attempt to allocate a hardware resource failed because the resource is used by another component."),
        0xC023001F: ("STATUS_NDIS_MEDIA_DISCONNECTED","The I/O operation failed because the network media is disconnected or the wireless access point is out of range."),
        0xC0230022: ("STATUS_NDIS_INVALID_ADDRESS","The network address used in the request is invalid."),
        0xC023002A: ("STATUS_NDIS_PAUSED","The offload operation on the network interface has been paused."),
        0xC023002B: ("STATUS_NDIS_INTERFACE_NOT_FOUND","The network interface was not found."),
        0xC023002C: ("STATUS_NDIS_UNSUPPORTED_REVISION","The revision number specified in the structure is not supported."),
        0xC023002D: ("STATUS_NDIS_INVALID_PORT","The specified port does not exist on this network interface."),
        0xC023002E: ("STATUS_NDIS_INVALID_PORT_STATE","The current state of the specified port on this network interface does not support the requested operation."),
        0xC023002F: ("STATUS_NDIS_LOW_POWER_STATE","The miniport adapter is in a lower power state."),
        0xC02300BB: ("STATUS_NDIS_NOT_SUPPORTED","The network interface does not support this request."),
        0xC023100F: ("STATUS_NDIS_OFFLOAD_POLICY","The TCP connection is not offloadable because of a local policy setting."),
        0xC0231012: ("STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED","The TCP connection is not offloadable by the Chimney offload target."),
        0xC0231013: ("STATUS_NDIS_OFFLOAD_PATH_REJECTED","The IP Path object is not in an offloadable state."),
        0xC0232000: ("STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED","The wireless LAN interface is in auto-configuration mode and does not support the requested parameter change operation."),
        0xC0232001: ("STATUS_NDIS_DOT11_MEDIA_IN_USE","The wireless LAN interface is busy and cannot perform the requested operation."),
        0xC0232002: ("STATUS_NDIS_DOT11_POWER_STATE_INVALID","The wireless LAN interface is power down and does not support the requested operation."),
        0xC0232003: ("STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL","The list of wake on LAN patterns is full."),
        0xC0232004: ("STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL","The list of low power protocol offloads is full."),
        0xC0360001: ("STATUS_IPSEC_BAD_SPI","The SPI in the packet does not match a valid IPsec SA."),
        0xC0360002: ("STATUS_IPSEC_SA_LIFETIME_EXPIRED","The packet was received on an IPsec SA whose lifetime has expired."),
        0xC0360003: ("STATUS_IPSEC_WRONG_SA","The packet was received on an IPsec SA that does not match the packet characteristics."),
        0xC0360004: ("STATUS_IPSEC_REPLAY_CHECK_FAILED","The packet sequence number replay check failed."),
        0xC0360005: ("STATUS_IPSEC_INVALID_PACKET","The IPsec header and/or trailer in the packet is invalid."),
        0xC0360006: ("STATUS_IPSEC_INTEGRITY_CHECK_FAILED","The IPsec integrity check failed."),
        0xC0360007: ("STATUS_IPSEC_CLEAR_TEXT_DROP","IPsec dropped a clear text packet."),
        0xC0360008: ("STATUS_IPSEC_AUTH_FIREWALL_DROP","IPsec dropped an incoming ESP packet in authenticated firewall mode. This drop is benign."),
        0xC0360009: ("STATUS_IPSEC_THROTTLE_DROP","IPsec dropped a packet due to DOS throttle."),
        0xC0368000: ("STATUS_IPSEC_DOSP_BLOCK","IPsec Dos Protection matched an explicit block rule."),
        0xC0368001: ("STATUS_IPSEC_DOSP_RECEIVED_MULTICAST","IPsec Dos Protection received an IPsec specific multicast packet which is not allowed."),
        0xC0368002: ("STATUS_IPSEC_DOSP_INVALID_PACKET","IPsec Dos Protection received an incorrectly formatted packet."),
        0xC0368003: ("STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED","IPsec Dos Protection failed to lookup state."),
        0xC0368004: ("STATUS_IPSEC_DOSP_MAX_ENTRIES","IPsec Dos Protection failed to create state because there are already maximum number of entries allowed by policy."),
        0xC0368005: ("STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED","IPsec Dos Protection received an IPsec negotiation packet for a keying module which is not allowed by policy."),
        0xC0368006: ("STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES","IPsec Dos Protection failed to create per internal IP ratelimit queue because there is already maximum number of queues allowed by policy."),
        0xC038005B: ("STATUS_VOLMGR_MIRROR_NOT_SUPPORTED","The system does not support mirrored volumes."),
        0xC038005C: ("STATUS_VOLMGR_RAID5_NOT_SUPPORTED","The system does not support RAID-5 volumes."),
        0xC03A0014: ("STATUS_VIRTDISK_PROVIDER_NOT_FOUND","A virtual disk support provider for the specified file was not found."),
        0xC03A0015: ("STATUS_VIRTDISK_NOT_VIRTUAL_DISK","The specified disk is not a virtual disk."),
        0xC03A0016: ("STATUS_VHD_PARENT_VHD_ACCESS_DENIED","The chain of virtual hard disks is inaccessible. The process has not been granted access rights to the parent virtual hard disk for the differencing disk."),
        0xC03A0017: ("STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH","The chain of virtual hard disks is corrupted. There is a mismatch in the virtual sizes of the parent virtual hard disk and differencing disk."),
        0xC03A0018: ("STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED","The chain of virtual hard disks is corrupted. A differencing disk is indicated in its own parent chain."),
        0xC03A0019: ("STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT","The chain of virtual hard disks is inaccessible. There was an error opening a virtual hard disk further up the chain."),
}

# Error Codes

STATUS_SUCCESS                                                    = 0x00000000
STATUS_WAIT_1                                                     = 0x00000001
STATUS_WAIT_2                                                     = 0x00000002
STATUS_WAIT_3                                                     = 0x00000003
STATUS_WAIT_63                                                    = 0x0000003F
STATUS_ABANDONED                                                  = 0x00000080
STATUS_ABANDONED_WAIT_0                                           = 0x00000080
STATUS_ABANDONED_WAIT_63                                          = 0x000000BF
STATUS_USER_APC                                                   = 0x000000C0
STATUS_ALERTED                                                    = 0x00000101
STATUS_TIMEOUT                                                    = 0x00000102
STATUS_PENDING                                                    = 0x00000103
STATUS_REPARSE                                                    = 0x00000104
STATUS_MORE_ENTRIES                                               = 0x00000105
STATUS_NOT_ALL_ASSIGNED                                           = 0x00000106
STATUS_SOME_NOT_MAPPED                                            = 0x00000107
STATUS_OPLOCK_BREAK_IN_PROGRESS                                   = 0x00000108
STATUS_VOLUME_MOUNTED                                             = 0x00000109
STATUS_RXACT_COMMITTED                                            = 0x0000010A
STATUS_NOTIFY_CLEANUP                                             = 0x0000010B
STATUS_NOTIFY_ENUM_DIR                                            = 0x0000010C
STATUS_NO_QUOTAS_FOR_ACCOUNT                                      = 0x0000010D
STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED                           = 0x0000010E
STATUS_PAGE_FAULT_TRANSITION                                      = 0x00000110
STATUS_PAGE_FAULT_DEMAND_ZERO                                     = 0x00000111
STATUS_PAGE_FAULT_COPY_ON_WRITE                                   = 0x00000112
STATUS_PAGE_FAULT_GUARD_PAGE                                      = 0x00000113
STATUS_PAGE_FAULT_PAGING_FILE                                     = 0x00000114
STATUS_CACHE_PAGE_LOCKED                                          = 0x00000115
STATUS_CRASH_DUMP                                                 = 0x00000116
STATUS_BUFFER_ALL_ZEROS                                           = 0x00000117
STATUS_REPARSE_OBJECT                                             = 0x00000118
STATUS_RESOURCE_REQUIREMENTS_CHANGED                              = 0x00000119
STATUS_TRANSLATION_COMPLETE                                       = 0x00000120
STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY                            = 0x00000121
STATUS_NOTHING_TO_TERMINATE                                       = 0x00000122
STATUS_PROCESS_NOT_IN_JOB                                         = 0x00000123
STATUS_PROCESS_IN_JOB                                             = 0x00000124
STATUS_VOLSNAP_HIBERNATE_READY                                    = 0x00000125
STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY                         = 0x00000126
STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED                         = 0x00000127
STATUS_INTERRUPT_STILL_CONNECTED                                  = 0x00000128
STATUS_PROCESS_CLONED                                             = 0x00000129
STATUS_FILE_LOCKED_WITH_ONLY_READERS                              = 0x0000012A
STATUS_FILE_LOCKED_WITH_WRITERS                                   = 0x0000012B
STATUS_RESOURCEMANAGER_READ_ONLY                                  = 0x00000202
STATUS_WAIT_FOR_OPLOCK                                            = 0x00000367
DBG_EXCEPTION_HANDLED                                             = 0x00010001
DBG_CONTINUE                                                      = 0x00010002
STATUS_FLT_IO_COMPLETE                                            = 0x001C0001
STATUS_FILE_NOT_AVAILABLE                                         = 0xC0000467
STATUS_CALLBACK_RETURNED_THREAD_AFFINITY                          = 0xC0000721
STATUS_OBJECT_NAME_EXISTS                                         = 0x40000000
STATUS_THREAD_WAS_SUSPENDED                                       = 0x40000001
STATUS_WORKING_SET_LIMIT_RANGE                                    = 0x40000002
STATUS_IMAGE_NOT_AT_BASE                                          = 0x40000003
STATUS_RXACT_STATE_CREATED                                        = 0x40000004
STATUS_SEGMENT_NOTIFICATION                                       = 0x40000005
STATUS_LOCAL_USER_SESSION_KEY                                     = 0x40000006
STATUS_BAD_CURRENT_DIRECTORY                                      = 0x40000007
STATUS_SERIAL_MORE_WRITES                                         = 0x40000008
STATUS_REGISTRY_RECOVERED                                         = 0x40000009
STATUS_FT_READ_RECOVERY_FROM_BACKUP                               = 0x4000000A
STATUS_FT_WRITE_RECOVERY                                          = 0x4000000B
STATUS_SERIAL_COUNTER_TIMEOUT                                     = 0x4000000C
STATUS_NULL_LM_PASSWORD                                           = 0x4000000D
STATUS_IMAGE_MACHINE_TYPE_MISMATCH                                = 0x4000000E
STATUS_RECEIVE_PARTIAL                                            = 0x4000000F
STATUS_RECEIVE_EXPEDITED                                          = 0x40000010
STATUS_RECEIVE_PARTIAL_EXPEDITED                                  = 0x40000011
STATUS_EVENT_DONE                                                 = 0x40000012
STATUS_EVENT_PENDING                                              = 0x40000013
STATUS_CHECKING_FILE_SYSTEM                                       = 0x40000014
STATUS_FATAL_APP_EXIT                                             = 0x40000015
STATUS_PREDEFINED_HANDLE                                          = 0x40000016
STATUS_WAS_UNLOCKED                                               = 0x40000017
STATUS_SERVICE_NOTIFICATION                                       = 0x40000018
STATUS_WAS_LOCKED                                                 = 0x40000019
STATUS_LOG_HARD_ERROR                                             = 0x4000001A
STATUS_ALREADY_WIN32                                              = 0x4000001B
STATUS_WX86_UNSIMULATE                                            = 0x4000001C
STATUS_WX86_CONTINUE                                              = 0x4000001D
STATUS_WX86_SINGLE_STEP                                           = 0x4000001E
STATUS_WX86_BREAKPOINT                                            = 0x4000001F
STATUS_WX86_EXCEPTION_CONTINUE                                    = 0x40000020
STATUS_WX86_EXCEPTION_LASTCHANCE                                  = 0x40000021
STATUS_WX86_EXCEPTION_CHAIN                                       = 0x40000022
STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE                            = 0x40000023
STATUS_NO_YIELD_PERFORMED                                         = 0x40000024
STATUS_TIMER_RESUME_IGNORED                                       = 0x40000025
STATUS_ARBITRATION_UNHANDLED                                      = 0x40000026
STATUS_CARDBUS_NOT_SUPPORTED                                      = 0x40000027
STATUS_WX86_CREATEWX86TIB                                         = 0x40000028
STATUS_MP_PROCESSOR_MISMATCH                                      = 0x40000029
STATUS_HIBERNATED                                                 = 0x4000002A
STATUS_RESUME_HIBERNATION                                         = 0x4000002B
STATUS_FIRMWARE_UPDATED                                           = 0x4000002C
STATUS_DRIVERS_LEAKING_LOCKED_PAGES                               = 0x4000002D
STATUS_MESSAGE_RETRIEVED                                          = 0x4000002E
STATUS_SYSTEM_POWERSTATE_TRANSITION                               = 0x4000002F
STATUS_ALPC_CHECK_COMPLETION_LIST                                 = 0x40000030
STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION                       = 0x40000031
STATUS_ACCESS_AUDIT_BY_POLICY                                     = 0x40000032
STATUS_ABANDON_HIBERFILE                                          = 0x40000033
STATUS_BIZRULES_NOT_ENABLED                                       = 0x40000034
STATUS_WAKE_SYSTEM                                                = 0x40000294
STATUS_DS_SHUTTING_DOWN                                           = 0x40000370
DBG_REPLY_LATER                                                   = 0x40010001
DBG_UNABLE_TO_PROVIDE_HANDLE                                      = 0x40010002
DBG_TERMINATE_THREAD                                              = 0x40010003
DBG_TERMINATE_PROCESS                                             = 0x40010004
DBG_CONTROL_C                                                     = 0x40010005
DBG_PRINTEXCEPTION_C                                              = 0x40010006
DBG_RIPEXCEPTION                                                  = 0x40010007
DBG_CONTROL_BREAK                                                 = 0x40010008
DBG_COMMAND_EXCEPTION                                             = 0x40010009
RPC_NT_UUID_LOCAL_ONLY                                            = 0x40020056
RPC_NT_SEND_INCOMPLETE                                            = 0x400200AF
STATUS_CTX_CDM_CONNECT                                            = 0x400A0004
STATUS_CTX_CDM_DISCONNECT                                         = 0x400A0005
STATUS_SXS_RELEASE_ACTIVATION_CONTEXT                             = 0x4015000D
STATUS_RECOVERY_NOT_NEEDED                                        = 0x40190034
STATUS_RM_ALREADY_STARTED                                         = 0x40190035
STATUS_LOG_NO_RESTART                                             = 0x401A000C
STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST                          = 0x401B00EC
STATUS_GRAPHICS_PARTIAL_DATA_POPULATED                            = 0x401E000A
STATUS_GRAPHICS_DRIVER_MISMATCH                                   = 0x401E0117
STATUS_GRAPHICS_MODE_NOT_PINNED                                   = 0x401E0307
STATUS_GRAPHICS_NO_PREFERRED_MODE                                 = 0x401E031E
STATUS_GRAPHICS_DATASET_IS_EMPTY                                  = 0x401E034B
STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET                       = 0x401E034C
STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED   = 0x401E0351
STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS                              = 0x401E042F
STATUS_GRAPHICS_LEADLINK_START_DEFERRED                           = 0x401E0437
STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY                            = 0x401E0439
STATUS_GRAPHICS_START_DEFERRED                                    = 0x401E043A
STATUS_NDIS_INDICATION_REQUIRED                                   = 0x40230001
STATUS_GUARD_PAGE_VIOLATION                                       = 0x80000001
STATUS_DATATYPE_MISALIGNMENT                                      = 0x80000002
STATUS_BREAKPOINT                                                 = 0x80000003
STATUS_SINGLE_STEP                                                = 0x80000004
STATUS_BUFFER_OVERFLOW                                            = 0x80000005
STATUS_NO_MORE_FILES                                              = 0x80000006
STATUS_WAKE_SYSTEM_DEBUGGER                                       = 0x80000007
STATUS_HANDLES_CLOSED                                             = 0x8000000A
STATUS_NO_INHERITANCE                                             = 0x8000000B
STATUS_GUID_SUBSTITUTION_MADE                                     = 0x8000000C
STATUS_PARTIAL_COPY                                               = 0x8000000D
STATUS_DEVICE_PAPER_EMPTY                                         = 0x8000000E
STATUS_DEVICE_POWERED_OFF                                         = 0x8000000F
STATUS_DEVICE_OFF_LINE                                            = 0x80000010
STATUS_DEVICE_BUSY                                                = 0x80000011
STATUS_NO_MORE_EAS                                                = 0x80000012
STATUS_INVALID_EA_NAME                                            = 0x80000013
STATUS_EA_LIST_INCONSISTENT                                       = 0x80000014
STATUS_INVALID_EA_FLAG                                            = 0x80000015
STATUS_VERIFY_REQUIRED                                            = 0x80000016
STATUS_EXTRANEOUS_INFORMATION                                     = 0x80000017
STATUS_RXACT_COMMIT_NECESSARY                                     = 0x80000018
STATUS_NO_MORE_ENTRIES                                            = 0x8000001A
STATUS_FILEMARK_DETECTED                                          = 0x8000001B
STATUS_MEDIA_CHANGED                                              = 0x8000001C
STATUS_BUS_RESET                                                  = 0x8000001D
STATUS_END_OF_MEDIA                                               = 0x8000001E
STATUS_BEGINNING_OF_MEDIA                                         = 0x8000001F
STATUS_MEDIA_CHECK                                                = 0x80000020
STATUS_SETMARK_DETECTED                                           = 0x80000021
STATUS_NO_DATA_DETECTED                                           = 0x80000022
STATUS_REDIRECTOR_HAS_OPEN_HANDLES                                = 0x80000023
STATUS_SERVER_HAS_OPEN_HANDLES                                    = 0x80000024
STATUS_ALREADY_DISCONNECTED                                       = 0x80000025
STATUS_LONGJUMP                                                   = 0x80000026
STATUS_CLEANER_CARTRIDGE_INSTALLED                                = 0x80000027
STATUS_PLUGPLAY_QUERY_VETOED                                      = 0x80000028
STATUS_UNWIND_CONSOLIDATE                                         = 0x80000029
STATUS_REGISTRY_HIVE_RECOVERED                                    = 0x8000002A
STATUS_DLL_MIGHT_BE_INSECURE                                      = 0x8000002B
STATUS_DLL_MIGHT_BE_INCOMPATIBLE                                  = 0x8000002C
STATUS_STOPPED_ON_SYMLINK                                         = 0x8000002D
STATUS_DEVICE_REQUIRES_CLEANING                                   = 0x80000288
STATUS_DEVICE_DOOR_OPEN                                           = 0x80000289
STATUS_DATA_LOST_REPAIR                                           = 0x80000803
DBG_EXCEPTION_NOT_HANDLED                                         = 0x80010001
STATUS_CLUSTER_NODE_ALREADY_UP                                    = 0x80130001
STATUS_CLUSTER_NODE_ALREADY_DOWN                                  = 0x80130002
STATUS_CLUSTER_NETWORK_ALREADY_ONLINE                             = 0x80130003
STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE                            = 0x80130004
STATUS_CLUSTER_NODE_ALREADY_MEMBER                                = 0x80130005
STATUS_COULD_NOT_RESIZE_LOG                                       = 0x80190009
STATUS_NO_TXF_METADATA                                            = 0x80190029
STATUS_CANT_RECOVER_WITH_HANDLE_OPEN                              = 0x80190031
STATUS_TXF_METADATA_ALREADY_PRESENT                               = 0x80190041
STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET                        = 0x80190042
STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED                 = 0x801B00EB
STATUS_FLT_BUFFER_TOO_SMALL                                       = 0x801C0001
STATUS_FVE_PARTIAL_METADATA                                       = 0x80210001
STATUS_FVE_TRANSIENT_STATE                                        = 0x80210002
STATUS_UNSUCCESSFUL                                               = 0xC0000001
STATUS_NOT_IMPLEMENTED                                            = 0xC0000002
STATUS_INVALID_INFO_CLASS                                         = 0xC0000003
STATUS_INFO_LENGTH_MISMATCH                                       = 0xC0000004
STATUS_ACCESS_VIOLATION                                           = 0xC0000005
STATUS_IN_PAGE_ERROR                                              = 0xC0000006
STATUS_PAGEFILE_QUOTA                                             = 0xC0000007
STATUS_INVALID_HANDLE                                             = 0xC0000008
STATUS_BAD_INITIAL_STACK                                          = 0xC0000009
STATUS_BAD_INITIAL_PC                                             = 0xC000000A
STATUS_INVALID_CID                                                = 0xC000000B
STATUS_TIMER_NOT_CANCELED                                         = 0xC000000C
STATUS_INVALID_PARAMETER                                          = 0xC000000D
STATUS_NO_SUCH_DEVICE                                             = 0xC000000E
STATUS_NO_SUCH_FILE                                               = 0xC000000F
STATUS_INVALID_DEVICE_REQUEST                                     = 0xC0000010
STATUS_END_OF_FILE                                                = 0xC0000011
STATUS_WRONG_VOLUME                                               = 0xC0000012
STATUS_NO_MEDIA_IN_DEVICE                                         = 0xC0000013
STATUS_UNRECOGNIZED_MEDIA                                         = 0xC0000014
STATUS_NONEXISTENT_SECTOR                                         = 0xC0000015
STATUS_MORE_PROCESSING_REQUIRED                                   = 0xC0000016
STATUS_NO_MEMORY                                                  = 0xC0000017
STATUS_CONFLICTING_ADDRESSES                                      = 0xC0000018
STATUS_NOT_MAPPED_VIEW                                            = 0xC0000019
STATUS_UNABLE_TO_FREE_VM                                          = 0xC000001A
STATUS_UNABLE_TO_DELETE_SECTION                                   = 0xC000001B
STATUS_INVALID_SYSTEM_SERVICE                                     = 0xC000001C
STATUS_ILLEGAL_INSTRUCTION                                        = 0xC000001D
STATUS_INVALID_LOCK_SEQUENCE                                      = 0xC000001E
STATUS_INVALID_VIEW_SIZE                                          = 0xC000001F
STATUS_INVALID_FILE_FOR_SECTION                                   = 0xC0000020
STATUS_ALREADY_COMMITTED                                          = 0xC0000021
STATUS_ACCESS_DENIED                                              = 0xC0000022
STATUS_BUFFER_TOO_SMALL                                           = 0xC0000023
STATUS_OBJECT_TYPE_MISMATCH                                       = 0xC0000024
STATUS_NONCONTINUABLE_EXCEPTION                                   = 0xC0000025
STATUS_INVALID_DISPOSITION                                        = 0xC0000026
STATUS_UNWIND                                                     = 0xC0000027
STATUS_BAD_STACK                                                  = 0xC0000028
STATUS_INVALID_UNWIND_TARGET                                      = 0xC0000029
STATUS_NOT_LOCKED                                                 = 0xC000002A
STATUS_PARITY_ERROR                                               = 0xC000002B
STATUS_UNABLE_TO_DECOMMIT_VM                                      = 0xC000002C
STATUS_NOT_COMMITTED                                              = 0xC000002D
STATUS_INVALID_PORT_ATTRIBUTES                                    = 0xC000002E
STATUS_PORT_MESSAGE_TOO_LONG                                      = 0xC000002F
STATUS_INVALID_PARAMETER_MIX                                      = 0xC0000030
STATUS_INVALID_QUOTA_LOWER                                        = 0xC0000031
STATUS_DISK_CORRUPT_ERROR                                         = 0xC0000032
STATUS_OBJECT_NAME_INVALID                                        = 0xC0000033
STATUS_OBJECT_NAME_NOT_FOUND                                      = 0xC0000034
STATUS_OBJECT_NAME_COLLISION                                      = 0xC0000035
STATUS_PORT_DISCONNECTED                                          = 0xC0000037
STATUS_DEVICE_ALREADY_ATTACHED                                    = 0xC0000038
STATUS_OBJECT_PATH_INVALID                                        = 0xC0000039
STATUS_OBJECT_PATH_NOT_FOUND                                      = 0xC000003A
STATUS_OBJECT_PATH_SYNTAX_BAD                                     = 0xC000003B
STATUS_DATA_OVERRUN                                               = 0xC000003C
STATUS_DATA_LATE_ERROR                                            = 0xC000003D
STATUS_DATA_ERROR                                                 = 0xC000003E
STATUS_CRC_ERROR                                                  = 0xC000003F
STATUS_SECTION_TOO_BIG                                            = 0xC0000040
STATUS_PORT_CONNECTION_REFUSED                                    = 0xC0000041
STATUS_INVALID_PORT_HANDLE                                        = 0xC0000042
STATUS_SHARING_VIOLATION                                          = 0xC0000043
STATUS_QUOTA_EXCEEDED                                             = 0xC0000044
STATUS_INVALID_PAGE_PROTECTION                                    = 0xC0000045
STATUS_MUTANT_NOT_OWNED                                           = 0xC0000046
STATUS_SEMAPHORE_LIMIT_EXCEEDED                                   = 0xC0000047
STATUS_PORT_ALREADY_SET                                           = 0xC0000048
STATUS_SECTION_NOT_IMAGE                                          = 0xC0000049
STATUS_SUSPEND_COUNT_EXCEEDED                                     = 0xC000004A
STATUS_THREAD_IS_TERMINATING                                      = 0xC000004B
STATUS_BAD_WORKING_SET_LIMIT                                      = 0xC000004C
STATUS_INCOMPATIBLE_FILE_MAP                                      = 0xC000004D
STATUS_SECTION_PROTECTION                                         = 0xC000004E
STATUS_EAS_NOT_SUPPORTED                                          = 0xC000004F
STATUS_EA_TOO_LARGE                                               = 0xC0000050
STATUS_NONEXISTENT_EA_ENTRY                                       = 0xC0000051
STATUS_NO_EAS_ON_FILE                                             = 0xC0000052
STATUS_EA_CORRUPT_ERROR                                           = 0xC0000053
STATUS_FILE_LOCK_CONFLICT                                         = 0xC0000054
STATUS_LOCK_NOT_GRANTED                                           = 0xC0000055
STATUS_DELETE_PENDING                                             = 0xC0000056
STATUS_CTL_FILE_NOT_SUPPORTED                                     = 0xC0000057
STATUS_UNKNOWN_REVISION                                           = 0xC0000058
STATUS_REVISION_MISMATCH                                          = 0xC0000059
STATUS_INVALID_OWNER                                              = 0xC000005A
STATUS_INVALID_PRIMARY_GROUP                                      = 0xC000005B
STATUS_NO_IMPERSONATION_TOKEN                                     = 0xC000005C
STATUS_CANT_DISABLE_MANDATORY                                     = 0xC000005D
STATUS_NO_LOGON_SERVERS                                           = 0xC000005E
STATUS_NO_SUCH_LOGON_SESSION                                      = 0xC000005F
STATUS_NO_SUCH_PRIVILEGE                                          = 0xC0000060
STATUS_PRIVILEGE_NOT_HELD                                         = 0xC0000061
STATUS_INVALID_ACCOUNT_NAME                                       = 0xC0000062
STATUS_USER_EXISTS                                                = 0xC0000063
STATUS_NO_SUCH_USER                                               = 0xC0000064
STATUS_GROUP_EXISTS                                               = 0xC0000065
STATUS_NO_SUCH_GROUP                                              = 0xC0000066
STATUS_MEMBER_IN_GROUP                                            = 0xC0000067
STATUS_MEMBER_NOT_IN_GROUP                                        = 0xC0000068
STATUS_LAST_ADMIN                                                 = 0xC0000069
STATUS_WRONG_PASSWORD                                             = 0xC000006A
STATUS_ILL_FORMED_PASSWORD                                        = 0xC000006B
STATUS_PASSWORD_RESTRICTION                                       = 0xC000006C
STATUS_LOGON_FAILURE                                              = 0xC000006D
STATUS_ACCOUNT_RESTRICTION                                        = 0xC000006E
STATUS_INVALID_LOGON_HOURS                                        = 0xC000006F
STATUS_INVALID_WORKSTATION                                        = 0xC0000070
STATUS_PASSWORD_EXPIRED                                           = 0xC0000071
STATUS_ACCOUNT_DISABLED                                           = 0xC0000072
STATUS_NONE_MAPPED                                                = 0xC0000073
STATUS_TOO_MANY_LUIDS_REQUESTED                                   = 0xC0000074
STATUS_LUIDS_EXHAUSTED                                            = 0xC0000075
STATUS_INVALID_SUB_AUTHORITY                                      = 0xC0000076
STATUS_INVALID_ACL                                                = 0xC0000077
STATUS_INVALID_SID                                                = 0xC0000078
STATUS_INVALID_SECURITY_DESCR                                     = 0xC0000079
STATUS_PROCEDURE_NOT_FOUND                                        = 0xC000007A
STATUS_INVALID_IMAGE_FORMAT                                       = 0xC000007B
STATUS_NO_TOKEN                                                   = 0xC000007C
STATUS_BAD_INHERITANCE_ACL                                        = 0xC000007D
STATUS_RANGE_NOT_LOCKED                                           = 0xC000007E
STATUS_DISK_FULL                                                  = 0xC000007F
STATUS_SERVER_DISABLED                                            = 0xC0000080
STATUS_SERVER_NOT_DISABLED                                        = 0xC0000081
STATUS_TOO_MANY_GUIDS_REQUESTED                                   = 0xC0000082
STATUS_GUIDS_EXHAUSTED                                            = 0xC0000083
STATUS_INVALID_ID_AUTHORITY                                       = 0xC0000084
STATUS_AGENTS_EXHAUSTED                                           = 0xC0000085
STATUS_INVALID_VOLUME_LABEL                                       = 0xC0000086
STATUS_SECTION_NOT_EXTENDED                                       = 0xC0000087
STATUS_NOT_MAPPED_DATA                                            = 0xC0000088
STATUS_RESOURCE_DATA_NOT_FOUND                                    = 0xC0000089
STATUS_RESOURCE_TYPE_NOT_FOUND                                    = 0xC000008A
STATUS_RESOURCE_NAME_NOT_FOUND                                    = 0xC000008B
STATUS_ARRAY_BOUNDS_EXCEEDED                                      = 0xC000008C
STATUS_FLOAT_DENORMAL_OPERAND                                     = 0xC000008D
STATUS_FLOAT_DIVIDE_BY_ZERO                                       = 0xC000008E
STATUS_FLOAT_INEXACT_RESULT                                       = 0xC000008F
STATUS_FLOAT_INVALID_OPERATION                                    = 0xC0000090
STATUS_FLOAT_OVERFLOW                                             = 0xC0000091
STATUS_FLOAT_STACK_CHECK                                          = 0xC0000092
STATUS_FLOAT_UNDERFLOW                                            = 0xC0000093
STATUS_INTEGER_DIVIDE_BY_ZERO                                     = 0xC0000094
STATUS_INTEGER_OVERFLOW                                           = 0xC0000095
STATUS_PRIVILEGED_INSTRUCTION                                     = 0xC0000096
STATUS_TOO_MANY_PAGING_FILES                                      = 0xC0000097
STATUS_FILE_INVALID                                               = 0xC0000098
STATUS_ALLOTTED_SPACE_EXCEEDED                                    = 0xC0000099
STATUS_INSUFFICIENT_RESOURCES                                     = 0xC000009A
STATUS_DFS_EXIT_PATH_FOUND                                        = 0xC000009B
STATUS_DEVICE_DATA_ERROR                                          = 0xC000009C
STATUS_DEVICE_NOT_CONNECTED                                       = 0xC000009D
STATUS_FREE_VM_NOT_AT_BASE                                        = 0xC000009F
STATUS_MEMORY_NOT_ALLOCATED                                       = 0xC00000A0
STATUS_WORKING_SET_QUOTA                                          = 0xC00000A1
STATUS_MEDIA_WRITE_PROTECTED                                      = 0xC00000A2
STATUS_DEVICE_NOT_READY                                           = 0xC00000A3
STATUS_INVALID_GROUP_ATTRIBUTES                                   = 0xC00000A4
STATUS_BAD_IMPERSONATION_LEVEL                                    = 0xC00000A5
STATUS_CANT_OPEN_ANONYMOUS                                        = 0xC00000A6
STATUS_BAD_VALIDATION_CLASS                                       = 0xC00000A7
STATUS_BAD_TOKEN_TYPE                                             = 0xC00000A8
STATUS_BAD_MASTER_BOOT_RECORD                                     = 0xC00000A9
STATUS_INSTRUCTION_MISALIGNMENT                                   = 0xC00000AA
STATUS_INSTANCE_NOT_AVAILABLE                                     = 0xC00000AB
STATUS_PIPE_NOT_AVAILABLE                                         = 0xC00000AC
STATUS_INVALID_PIPE_STATE                                         = 0xC00000AD
STATUS_PIPE_BUSY                                                  = 0xC00000AE
STATUS_ILLEGAL_FUNCTION                                           = 0xC00000AF
STATUS_PIPE_DISCONNECTED                                          = 0xC00000B0
STATUS_PIPE_CLOSING                                               = 0xC00000B1
STATUS_PIPE_CONNECTED                                             = 0xC00000B2
STATUS_PIPE_LISTENING                                             = 0xC00000B3
STATUS_INVALID_READ_MODE                                          = 0xC00000B4
STATUS_IO_TIMEOUT                                                 = 0xC00000B5
STATUS_FILE_FORCED_CLOSED                                         = 0xC00000B6
STATUS_PROFILING_NOT_STARTED                                      = 0xC00000B7
STATUS_PROFILING_NOT_STOPPED                                      = 0xC00000B8
STATUS_COULD_NOT_INTERPRET                                        = 0xC00000B9
STATUS_FILE_IS_A_DIRECTORY                                        = 0xC00000BA
STATUS_NOT_SUPPORTED                                              = 0xC00000BB
STATUS_REMOTE_NOT_LISTENING                                       = 0xC00000BC
STATUS_DUPLICATE_NAME                                             = 0xC00000BD
STATUS_BAD_NETWORK_PATH                                           = 0xC00000BE
STATUS_NETWORK_BUSY                                               = 0xC00000BF
STATUS_DEVICE_DOES_NOT_EXIST                                      = 0xC00000C0
STATUS_TOO_MANY_COMMANDS                                          = 0xC00000C1
STATUS_ADAPTER_HARDWARE_ERROR                                     = 0xC00000C2
STATUS_INVALID_NETWORK_RESPONSE                                   = 0xC00000C3
STATUS_UNEXPECTED_NETWORK_ERROR                                   = 0xC00000C4
STATUS_BAD_REMOTE_ADAPTER                                         = 0xC00000C5
STATUS_PRINT_QUEUE_FULL                                           = 0xC00000C6
STATUS_NO_SPOOL_SPACE                                             = 0xC00000C7
STATUS_PRINT_CANCELLED                                            = 0xC00000C8
STATUS_NETWORK_NAME_DELETED                                       = 0xC00000C9
STATUS_NETWORK_ACCESS_DENIED                                      = 0xC00000CA
STATUS_BAD_DEVICE_TYPE                                            = 0xC00000CB
STATUS_BAD_NETWORK_NAME                                           = 0xC00000CC
STATUS_TOO_MANY_NAMES                                             = 0xC00000CD
STATUS_TOO_MANY_SESSIONS                                          = 0xC00000CE
STATUS_SHARING_PAUSED                                             = 0xC00000CF
STATUS_REQUEST_NOT_ACCEPTED                                       = 0xC00000D0
STATUS_REDIRECTOR_PAUSED                                          = 0xC00000D1
STATUS_NET_WRITE_FAULT                                            = 0xC00000D2
STATUS_PROFILING_AT_LIMIT                                         = 0xC00000D3
STATUS_NOT_SAME_DEVICE                                            = 0xC00000D4
STATUS_FILE_RENAMED                                               = 0xC00000D5
STATUS_VIRTUAL_CIRCUIT_CLOSED                                     = 0xC00000D6
STATUS_NO_SECURITY_ON_OBJECT                                      = 0xC00000D7
STATUS_CANT_WAIT                                                  = 0xC00000D8
STATUS_PIPE_EMPTY                                                 = 0xC00000D9
STATUS_CANT_ACCESS_DOMAIN_INFO                                    = 0xC00000DA
STATUS_CANT_TERMINATE_SELF                                        = 0xC00000DB
STATUS_INVALID_SERVER_STATE                                       = 0xC00000DC
STATUS_INVALID_DOMAIN_STATE                                       = 0xC00000DD
STATUS_INVALID_DOMAIN_ROLE                                        = 0xC00000DE
STATUS_NO_SUCH_DOMAIN                                             = 0xC00000DF
STATUS_DOMAIN_EXISTS                                              = 0xC00000E0
STATUS_DOMAIN_LIMIT_EXCEEDED                                      = 0xC00000E1
STATUS_OPLOCK_NOT_GRANTED                                         = 0xC00000E2
STATUS_INVALID_OPLOCK_PROTOCOL                                    = 0xC00000E3
STATUS_INTERNAL_DB_CORRUPTION                                     = 0xC00000E4
STATUS_INTERNAL_ERROR                                             = 0xC00000E5
STATUS_GENERIC_NOT_MAPPED                                         = 0xC00000E6
STATUS_BAD_DESCRIPTOR_FORMAT                                      = 0xC00000E7
STATUS_INVALID_USER_BUFFER                                        = 0xC00000E8
STATUS_UNEXPECTED_IO_ERROR                                        = 0xC00000E9
STATUS_UNEXPECTED_MM_CREATE_ERR                                   = 0xC00000EA
STATUS_UNEXPECTED_MM_MAP_ERROR                                    = 0xC00000EB
STATUS_UNEXPECTED_MM_EXTEND_ERR                                   = 0xC00000EC
STATUS_NOT_LOGON_PROCESS                                          = 0xC00000ED
STATUS_LOGON_SESSION_EXISTS                                       = 0xC00000EE
STATUS_INVALID_PARAMETER_1                                        = 0xC00000EF
STATUS_INVALID_PARAMETER_2                                        = 0xC00000F0
STATUS_INVALID_PARAMETER_3                                        = 0xC00000F1
STATUS_INVALID_PARAMETER_4                                        = 0xC00000F2
STATUS_INVALID_PARAMETER_5                                        = 0xC00000F3
STATUS_INVALID_PARAMETER_6                                        = 0xC00000F4
STATUS_INVALID_PARAMETER_7                                        = 0xC00000F5
STATUS_INVALID_PARAMETER_8                                        = 0xC00000F6
STATUS_INVALID_PARAMETER_9                                        = 0xC00000F7
STATUS_INVALID_PARAMETER_10                                       = 0xC00000F8
STATUS_INVALID_PARAMETER_11                                       = 0xC00000F9
STATUS_INVALID_PARAMETER_12                                       = 0xC00000FA
STATUS_REDIRECTOR_NOT_STARTED                                     = 0xC00000FB
STATUS_REDIRECTOR_STARTED                                         = 0xC00000FC
STATUS_STACK_OVERFLOW                                             = 0xC00000FD
STATUS_NO_SUCH_PACKAGE                                            = 0xC00000FE
STATUS_BAD_FUNCTION_TABLE                                         = 0xC00000FF
STATUS_VARIABLE_NOT_FOUND                                         = 0xC0000100
STATUS_DIRECTORY_NOT_EMPTY                                        = 0xC0000101
STATUS_FILE_CORRUPT_ERROR                                         = 0xC0000102
STATUS_NOT_A_DIRECTORY                                            = 0xC0000103
STATUS_BAD_LOGON_SESSION_STATE                                    = 0xC0000104
STATUS_LOGON_SESSION_COLLISION                                    = 0xC0000105
STATUS_NAME_TOO_LONG                                              = 0xC0000106
STATUS_FILES_OPEN                                                 = 0xC0000107
STATUS_CONNECTION_IN_USE                                          = 0xC0000108
STATUS_MESSAGE_NOT_FOUND                                          = 0xC0000109
STATUS_PROCESS_IS_TERMINATING                                     = 0xC000010A
STATUS_INVALID_LOGON_TYPE                                         = 0xC000010B
STATUS_NO_GUID_TRANSLATION                                        = 0xC000010C
STATUS_CANNOT_IMPERSONATE                                         = 0xC000010D
STATUS_IMAGE_ALREADY_LOADED                                       = 0xC000010E
STATUS_NO_LDT                                                     = 0xC0000117
STATUS_INVALID_LDT_SIZE                                           = 0xC0000118
STATUS_INVALID_LDT_OFFSET                                         = 0xC0000119
STATUS_INVALID_LDT_DESCRIPTOR                                     = 0xC000011A
STATUS_INVALID_IMAGE_NE_FORMAT                                    = 0xC000011B
STATUS_RXACT_INVALID_STATE                                        = 0xC000011C
STATUS_RXACT_COMMIT_FAILURE                                       = 0xC000011D
STATUS_MAPPED_FILE_SIZE_ZERO                                      = 0xC000011E
STATUS_TOO_MANY_OPENED_FILES                                      = 0xC000011F
STATUS_CANCELLED                                                  = 0xC0000120
STATUS_CANNOT_DELETE                                              = 0xC0000121
STATUS_INVALID_COMPUTER_NAME                                      = 0xC0000122
STATUS_FILE_DELETED                                               = 0xC0000123
STATUS_SPECIAL_ACCOUNT                                            = 0xC0000124
STATUS_SPECIAL_GROUP                                              = 0xC0000125
STATUS_SPECIAL_USER                                               = 0xC0000126
STATUS_MEMBERS_PRIMARY_GROUP                                      = 0xC0000127
STATUS_FILE_CLOSED                                                = 0xC0000128
STATUS_TOO_MANY_THREADS                                           = 0xC0000129
STATUS_THREAD_NOT_IN_PROCESS                                      = 0xC000012A
STATUS_TOKEN_ALREADY_IN_USE                                       = 0xC000012B
STATUS_PAGEFILE_QUOTA_EXCEEDED                                    = 0xC000012C
STATUS_COMMITMENT_LIMIT                                           = 0xC000012D
STATUS_INVALID_IMAGE_LE_FORMAT                                    = 0xC000012E
STATUS_INVALID_IMAGE_NOT_MZ                                       = 0xC000012F
STATUS_INVALID_IMAGE_PROTECT                                      = 0xC0000130
STATUS_INVALID_IMAGE_WIN_16                                       = 0xC0000131
STATUS_LOGON_SERVER_CONFLICT                                      = 0xC0000132
STATUS_TIME_DIFFERENCE_AT_DC                                      = 0xC0000133
STATUS_SYNCHRONIZATION_REQUIRED                                   = 0xC0000134
STATUS_DLL_NOT_FOUND                                              = 0xC0000135
STATUS_OPEN_FAILED                                                = 0xC0000136
STATUS_IO_PRIVILEGE_FAILED                                        = 0xC0000137
STATUS_ORDINAL_NOT_FOUND                                          = 0xC0000138
STATUS_ENTRYPOINT_NOT_FOUND                                       = 0xC0000139
STATUS_CONTROL_C_EXIT                                             = 0xC000013A
STATUS_LOCAL_DISCONNECT                                           = 0xC000013B
STATUS_REMOTE_DISCONNECT                                          = 0xC000013C
STATUS_REMOTE_RESOURCES                                           = 0xC000013D
STATUS_LINK_FAILED                                                = 0xC000013E
STATUS_LINK_TIMEOUT                                               = 0xC000013F
STATUS_INVALID_CONNECTION                                         = 0xC0000140
STATUS_INVALID_ADDRESS                                            = 0xC0000141
STATUS_DLL_INIT_FAILED                                            = 0xC0000142
STATUS_MISSING_SYSTEMFILE                                         = 0xC0000143
STATUS_UNHANDLED_EXCEPTION                                        = 0xC0000144
STATUS_APP_INIT_FAILURE                                           = 0xC0000145
STATUS_PAGEFILE_CREATE_FAILED                                     = 0xC0000146
STATUS_NO_PAGEFILE                                                = 0xC0000147
STATUS_INVALID_LEVEL                                              = 0xC0000148
STATUS_WRONG_PASSWORD_CORE                                        = 0xC0000149
STATUS_ILLEGAL_FLOAT_CONTEXT                                      = 0xC000014A
STATUS_PIPE_BROKEN                                                = 0xC000014B
STATUS_REGISTRY_CORRUPT                                           = 0xC000014C
STATUS_REGISTRY_IO_FAILED                                         = 0xC000014D
STATUS_NO_EVENT_PAIR                                              = 0xC000014E
STATUS_UNRECOGNIZED_VOLUME                                        = 0xC000014F
STATUS_SERIAL_NO_DEVICE_INITED                                    = 0xC0000150
STATUS_NO_SUCH_ALIAS                                              = 0xC0000151
STATUS_MEMBER_NOT_IN_ALIAS                                        = 0xC0000152
STATUS_MEMBER_IN_ALIAS                                            = 0xC0000153
STATUS_ALIAS_EXISTS                                               = 0xC0000154
STATUS_LOGON_NOT_GRANTED                                          = 0xC0000155
STATUS_TOO_MANY_SECRETS                                           = 0xC0000156
STATUS_SECRET_TOO_LONG                                            = 0xC0000157
STATUS_INTERNAL_DB_ERROR                                          = 0xC0000158
STATUS_FULLSCREEN_MODE                                            = 0xC0000159
STATUS_TOO_MANY_CONTEXT_IDS                                       = 0xC000015A
STATUS_LOGON_TYPE_NOT_GRANTED                                     = 0xC000015B
STATUS_NOT_REGISTRY_FILE                                          = 0xC000015C
STATUS_NT_CROSS_ENCRYPTION_REQUIRED                               = 0xC000015D
STATUS_DOMAIN_CTRLR_CONFIG_ERROR                                  = 0xC000015E
STATUS_FT_MISSING_MEMBER                                          = 0xC000015F
STATUS_ILL_FORMED_SERVICE_ENTRY                                   = 0xC0000160
STATUS_ILLEGAL_CHARACTER                                          = 0xC0000161
STATUS_UNMAPPABLE_CHARACTER                                       = 0xC0000162
STATUS_UNDEFINED_CHARACTER                                        = 0xC0000163
STATUS_FLOPPY_VOLUME                                              = 0xC0000164
STATUS_FLOPPY_ID_MARK_NOT_FOUND                                   = 0xC0000165
STATUS_FLOPPY_WRONG_CYLINDER                                      = 0xC0000166
STATUS_FLOPPY_UNKNOWN_ERROR                                       = 0xC0000167
STATUS_FLOPPY_BAD_REGISTERS                                       = 0xC0000168
STATUS_DISK_RECALIBRATE_FAILED                                    = 0xC0000169
STATUS_DISK_OPERATION_FAILED                                      = 0xC000016A
STATUS_DISK_RESET_FAILED                                          = 0xC000016B
STATUS_SHARED_IRQ_BUSY                                            = 0xC000016C
STATUS_FT_ORPHANING                                               = 0xC000016D
STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT                           = 0xC000016E
STATUS_PARTITION_FAILURE                                          = 0xC0000172
STATUS_INVALID_BLOCK_LENGTH                                       = 0xC0000173
STATUS_DEVICE_NOT_PARTITIONED                                     = 0xC0000174
STATUS_UNABLE_TO_LOCK_MEDIA                                       = 0xC0000175
STATUS_UNABLE_TO_UNLOAD_MEDIA                                     = 0xC0000176
STATUS_EOM_OVERFLOW                                               = 0xC0000177
STATUS_NO_MEDIA                                                   = 0xC0000178
STATUS_NO_SUCH_MEMBER                                             = 0xC000017A
STATUS_INVALID_MEMBER                                             = 0xC000017B
STATUS_KEY_DELETED                                                = 0xC000017C
STATUS_NO_LOG_SPACE                                               = 0xC000017D
STATUS_TOO_MANY_SIDS                                              = 0xC000017E
STATUS_LM_CROSS_ENCRYPTION_REQUIRED                               = 0xC000017F
STATUS_KEY_HAS_CHILDREN                                           = 0xC0000180
STATUS_CHILD_MUST_BE_VOLATILE                                     = 0xC0000181
STATUS_DEVICE_CONFIGURATION_ERROR                                 = 0xC0000182
STATUS_DRIVER_INTERNAL_ERROR                                      = 0xC0000183
STATUS_INVALID_DEVICE_STATE                                       = 0xC0000184
STATUS_IO_DEVICE_ERROR                                            = 0xC0000185
STATUS_DEVICE_PROTOCOL_ERROR                                      = 0xC0000186
STATUS_BACKUP_CONTROLLER                                          = 0xC0000187
STATUS_LOG_FILE_FULL                                              = 0xC0000188
STATUS_TOO_LATE                                                   = 0xC0000189
STATUS_NO_TRUST_LSA_SECRET                                        = 0xC000018A
STATUS_NO_TRUST_SAM_ACCOUNT                                       = 0xC000018B
STATUS_TRUSTED_DOMAIN_FAILURE                                     = 0xC000018C
STATUS_TRUSTED_RELATIONSHIP_FAILURE                               = 0xC000018D
STATUS_EVENTLOG_FILE_CORRUPT                                      = 0xC000018E
STATUS_EVENTLOG_CANT_START                                        = 0xC000018F
STATUS_TRUST_FAILURE                                              = 0xC0000190
STATUS_MUTANT_LIMIT_EXCEEDED                                      = 0xC0000191
STATUS_NETLOGON_NOT_STARTED                                       = 0xC0000192
STATUS_ACCOUNT_EXPIRED                                            = 0xC0000193
STATUS_POSSIBLE_DEADLOCK                                          = 0xC0000194
STATUS_NETWORK_CREDENTIAL_CONFLICT                                = 0xC0000195
STATUS_REMOTE_SESSION_LIMIT                                       = 0xC0000196
STATUS_EVENTLOG_FILE_CHANGED                                      = 0xC0000197
STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT                          = 0xC0000198
STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT                          = 0xC0000199
STATUS_NOLOGON_SERVER_TRUST_ACCOUNT                               = 0xC000019A
STATUS_DOMAIN_TRUST_INCONSISTENT                                  = 0xC000019B
STATUS_FS_DRIVER_REQUIRED                                         = 0xC000019C
STATUS_IMAGE_ALREADY_LOADED_AS_DLL                                = 0xC000019D
STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING       = 0xC000019E
STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME                          = 0xC000019F
STATUS_SECURITY_STREAM_IS_INCONSISTENT                            = 0xC00001A0
STATUS_INVALID_LOCK_RANGE                                         = 0xC00001A1
STATUS_INVALID_ACE_CONDITION                                      = 0xC00001A2
STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT                                = 0xC00001A3
STATUS_NOTIFICATION_GUID_ALREADY_DEFINED                          = 0xC00001A4
STATUS_NETWORK_OPEN_RESTRICTION                                   = 0xC0000201
STATUS_NO_USER_SESSION_KEY                                        = 0xC0000202
STATUS_USER_SESSION_DELETED                                       = 0xC0000203
STATUS_RESOURCE_LANG_NOT_FOUND                                    = 0xC0000204
STATUS_INSUFF_SERVER_RESOURCES                                    = 0xC0000205
STATUS_INVALID_BUFFER_SIZE                                        = 0xC0000206
STATUS_INVALID_ADDRESS_COMPONENT                                  = 0xC0000207
STATUS_INVALID_ADDRESS_WILDCARD                                   = 0xC0000208
STATUS_TOO_MANY_ADDRESSES                                         = 0xC0000209
STATUS_ADDRESS_ALREADY_EXISTS                                     = 0xC000020A
STATUS_ADDRESS_CLOSED                                             = 0xC000020B
STATUS_CONNECTION_DISCONNECTED                                    = 0xC000020C
STATUS_CONNECTION_RESET                                           = 0xC000020D
STATUS_TOO_MANY_NODES                                             = 0xC000020E
STATUS_TRANSACTION_ABORTED                                        = 0xC000020F
STATUS_TRANSACTION_TIMED_OUT                                      = 0xC0000210
STATUS_TRANSACTION_NO_RELEASE                                     = 0xC0000211
STATUS_TRANSACTION_NO_MATCH                                       = 0xC0000212
STATUS_TRANSACTION_RESPONDED                                      = 0xC0000213
STATUS_TRANSACTION_INVALID_ID                                     = 0xC0000214
STATUS_TRANSACTION_INVALID_TYPE                                   = 0xC0000215
STATUS_NOT_SERVER_SESSION                                         = 0xC0000216
STATUS_NOT_CLIENT_SESSION                                         = 0xC0000217
STATUS_CANNOT_LOAD_REGISTRY_FILE                                  = 0xC0000218
STATUS_DEBUG_ATTACH_FAILED                                        = 0xC0000219
STATUS_SYSTEM_PROCESS_TERMINATED                                  = 0xC000021A
STATUS_DATA_NOT_ACCEPTED                                          = 0xC000021B
STATUS_NO_BROWSER_SERVERS_FOUND                                   = 0xC000021C
STATUS_VDM_HARD_ERROR                                             = 0xC000021D
STATUS_DRIVER_CANCEL_TIMEOUT                                      = 0xC000021E
STATUS_REPLY_MESSAGE_MISMATCH                                     = 0xC000021F
STATUS_MAPPED_ALIGNMENT                                           = 0xC0000220
STATUS_IMAGE_CHECKSUM_MISMATCH                                    = 0xC0000221
STATUS_LOST_WRITEBEHIND_DATA                                      = 0xC0000222
STATUS_CLIENT_SERVER_PARAMETERS_INVALID                           = 0xC0000223
STATUS_PASSWORD_MUST_CHANGE                                       = 0xC0000224
STATUS_NOT_FOUND                                                  = 0xC0000225
STATUS_NOT_TINY_STREAM                                            = 0xC0000226
STATUS_RECOVERY_FAILURE                                           = 0xC0000227
STATUS_STACK_OVERFLOW_READ                                        = 0xC0000228
STATUS_FAIL_CHECK                                                 = 0xC0000229
STATUS_DUPLICATE_OBJECTID                                         = 0xC000022A
STATUS_OBJECTID_EXISTS                                            = 0xC000022B
STATUS_CONVERT_TO_LARGE                                           = 0xC000022C
STATUS_RETRY                                                      = 0xC000022D
STATUS_FOUND_OUT_OF_SCOPE                                         = 0xC000022E
STATUS_ALLOCATE_BUCKET                                            = 0xC000022F
STATUS_PROPSET_NOT_FOUND                                          = 0xC0000230
STATUS_MARSHALL_OVERFLOW                                          = 0xC0000231
STATUS_INVALID_VARIANT                                            = 0xC0000232
STATUS_DOMAIN_CONTROLLER_NOT_FOUND                                = 0xC0000233
STATUS_ACCOUNT_LOCKED_OUT                                         = 0xC0000234
STATUS_HANDLE_NOT_CLOSABLE                                        = 0xC0000235
STATUS_CONNECTION_REFUSED                                         = 0xC0000236
STATUS_GRACEFUL_DISCONNECT                                        = 0xC0000237
STATUS_ADDRESS_ALREADY_ASSOCIATED                                 = 0xC0000238
STATUS_ADDRESS_NOT_ASSOCIATED                                     = 0xC0000239
STATUS_CONNECTION_INVALID                                         = 0xC000023A
STATUS_CONNECTION_ACTIVE                                          = 0xC000023B
STATUS_NETWORK_UNREACHABLE                                        = 0xC000023C
STATUS_HOST_UNREACHABLE                                           = 0xC000023D
STATUS_PROTOCOL_UNREACHABLE                                       = 0xC000023E
STATUS_PORT_UNREACHABLE                                           = 0xC000023F
STATUS_REQUEST_ABORTED                                            = 0xC0000240
STATUS_CONNECTION_ABORTED                                         = 0xC0000241
STATUS_BAD_COMPRESSION_BUFFER                                     = 0xC0000242
STATUS_USER_MAPPED_FILE                                           = 0xC0000243
STATUS_AUDIT_FAILED                                               = 0xC0000244
STATUS_TIMER_RESOLUTION_NOT_SET                                   = 0xC0000245
STATUS_CONNECTION_COUNT_LIMIT                                     = 0xC0000246
STATUS_LOGIN_TIME_RESTRICTION                                     = 0xC0000247
STATUS_LOGIN_WKSTA_RESTRICTION                                    = 0xC0000248
STATUS_IMAGE_MP_UP_MISMATCH                                       = 0xC0000249
STATUS_INSUFFICIENT_LOGON_INFO                                    = 0xC0000250
STATUS_BAD_DLL_ENTRYPOINT                                         = 0xC0000251
STATUS_BAD_SERVICE_ENTRYPOINT                                     = 0xC0000252
STATUS_LPC_REPLY_LOST                                             = 0xC0000253
STATUS_IP_ADDRESS_CONFLICT1                                       = 0xC0000254
STATUS_IP_ADDRESS_CONFLICT2                                       = 0xC0000255
STATUS_REGISTRY_QUOTA_LIMIT                                       = 0xC0000256
STATUS_PATH_NOT_COVERED                                           = 0xC0000257
STATUS_NO_CALLBACK_ACTIVE                                         = 0xC0000258
STATUS_LICENSE_QUOTA_EXCEEDED                                     = 0xC0000259
STATUS_PWD_TOO_SHORT                                              = 0xC000025A
STATUS_PWD_TOO_RECENT                                             = 0xC000025B
STATUS_PWD_HISTORY_CONFLICT                                       = 0xC000025C
STATUS_PLUGPLAY_NO_DEVICE                                         = 0xC000025E
STATUS_UNSUPPORTED_COMPRESSION                                    = 0xC000025F
STATUS_INVALID_HW_PROFILE                                         = 0xC0000260
STATUS_INVALID_PLUGPLAY_DEVICE_PATH                               = 0xC0000261
STATUS_DRIVER_ORDINAL_NOT_FOUND                                   = 0xC0000262
STATUS_DRIVER_ENTRYPOINT_NOT_FOUND                                = 0xC0000263
STATUS_RESOURCE_NOT_OWNED                                         = 0xC0000264
STATUS_TOO_MANY_LINKS                                             = 0xC0000265
STATUS_QUOTA_LIST_INCONSISTENT                                    = 0xC0000266
STATUS_FILE_IS_OFFLINE                                            = 0xC0000267
STATUS_EVALUATION_EXPIRATION                                      = 0xC0000268
STATUS_ILLEGAL_DLL_RELOCATION                                     = 0xC0000269
STATUS_LICENSE_VIOLATION                                          = 0xC000026A
STATUS_DLL_INIT_FAILED_LOGOFF                                     = 0xC000026B
STATUS_DRIVER_UNABLE_TO_LOAD                                      = 0xC000026C
STATUS_DFS_UNAVAILABLE                                            = 0xC000026D
STATUS_VOLUME_DISMOUNTED                                          = 0xC000026E
STATUS_WX86_INTERNAL_ERROR                                        = 0xC000026F
STATUS_WX86_FLOAT_STACK_CHECK                                     = 0xC0000270
STATUS_VALIDATE_CONTINUE                                          = 0xC0000271
STATUS_NO_MATCH                                                   = 0xC0000272
STATUS_NO_MORE_MATCHES                                            = 0xC0000273
STATUS_NOT_A_REPARSE_POINT                                        = 0xC0000275
STATUS_IO_REPARSE_TAG_INVALID                                     = 0xC0000276
STATUS_IO_REPARSE_TAG_MISMATCH                                    = 0xC0000277
STATUS_IO_REPARSE_DATA_INVALID                                    = 0xC0000278
STATUS_IO_REPARSE_TAG_NOT_HANDLED                                 = 0xC0000279
STATUS_REPARSE_POINT_NOT_RESOLVED                                 = 0xC0000280
STATUS_DIRECTORY_IS_A_REPARSE_POINT                               = 0xC0000281
STATUS_RANGE_LIST_CONFLICT                                        = 0xC0000282
STATUS_SOURCE_ELEMENT_EMPTY                                       = 0xC0000283
STATUS_DESTINATION_ELEMENT_FULL                                   = 0xC0000284
STATUS_ILLEGAL_ELEMENT_ADDRESS                                    = 0xC0000285
STATUS_MAGAZINE_NOT_PRESENT                                       = 0xC0000286
STATUS_REINITIALIZATION_NEEDED                                    = 0xC0000287
STATUS_ENCRYPTION_FAILED                                          = 0xC000028A
STATUS_DECRYPTION_FAILED                                          = 0xC000028B
STATUS_RANGE_NOT_FOUND                                            = 0xC000028C
STATUS_NO_RECOVERY_POLICY                                         = 0xC000028D
STATUS_NO_EFS                                                     = 0xC000028E
STATUS_WRONG_EFS                                                  = 0xC000028F
STATUS_NO_USER_KEYS                                               = 0xC0000290
STATUS_FILE_NOT_ENCRYPTED                                         = 0xC0000291
STATUS_NOT_EXPORT_FORMAT                                          = 0xC0000292
STATUS_FILE_ENCRYPTED                                             = 0xC0000293
STATUS_WMI_GUID_NOT_FOUND                                         = 0xC0000295
STATUS_WMI_INSTANCE_NOT_FOUND                                     = 0xC0000296
STATUS_WMI_ITEMID_NOT_FOUND                                       = 0xC0000297
STATUS_WMI_TRY_AGAIN                                              = 0xC0000298
STATUS_SHARED_POLICY                                              = 0xC0000299
STATUS_POLICY_OBJECT_NOT_FOUND                                    = 0xC000029A
STATUS_POLICY_ONLY_IN_DS                                          = 0xC000029B
STATUS_VOLUME_NOT_UPGRADED                                        = 0xC000029C
STATUS_REMOTE_STORAGE_NOT_ACTIVE                                  = 0xC000029D
STATUS_REMOTE_STORAGE_MEDIA_ERROR                                 = 0xC000029E
STATUS_NO_TRACKING_SERVICE                                        = 0xC000029F
STATUS_SERVER_SID_MISMATCH                                        = 0xC00002A0
STATUS_DS_NO_ATTRIBUTE_OR_VALUE                                   = 0xC00002A1
STATUS_DS_INVALID_ATTRIBUTE_SYNTAX                                = 0xC00002A2
STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED                                = 0xC00002A3
STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS                               = 0xC00002A4
STATUS_DS_BUSY                                                    = 0xC00002A5
STATUS_DS_UNAVAILABLE                                             = 0xC00002A6
STATUS_DS_NO_RIDS_ALLOCATED                                       = 0xC00002A7
STATUS_DS_NO_MORE_RIDS                                            = 0xC00002A8
STATUS_DS_INCORRECT_ROLE_OWNER                                    = 0xC00002A9
STATUS_DS_RIDMGR_INIT_ERROR                                       = 0xC00002AA
STATUS_DS_OBJ_CLASS_VIOLATION                                     = 0xC00002AB
STATUS_DS_CANT_ON_NON_LEAF                                        = 0xC00002AC
STATUS_DS_CANT_ON_RDN                                             = 0xC00002AD
STATUS_DS_CANT_MOD_OBJ_CLASS                                      = 0xC00002AE
STATUS_DS_CROSS_DOM_MOVE_FAILED                                   = 0xC00002AF
STATUS_DS_GC_NOT_AVAILABLE                                        = 0xC00002B0
STATUS_DIRECTORY_SERVICE_REQUIRED                                 = 0xC00002B1
STATUS_REPARSE_ATTRIBUTE_CONFLICT                                 = 0xC00002B2
STATUS_CANT_ENABLE_DENY_ONLY                                      = 0xC00002B3
STATUS_FLOAT_MULTIPLE_FAULTS                                      = 0xC00002B4
STATUS_FLOAT_MULTIPLE_TRAPS                                       = 0xC00002B5
STATUS_DEVICE_REMOVED                                             = 0xC00002B6
STATUS_JOURNAL_DELETE_IN_PROGRESS                                 = 0xC00002B7
STATUS_JOURNAL_NOT_ACTIVE                                         = 0xC00002B8
STATUS_NOINTERFACE                                                = 0xC00002B9
STATUS_DS_ADMIN_LIMIT_EXCEEDED                                    = 0xC00002C1
STATUS_DRIVER_FAILED_SLEEP                                        = 0xC00002C2
STATUS_MUTUAL_AUTHENTICATION_FAILED                               = 0xC00002C3
STATUS_CORRUPT_SYSTEM_FILE                                        = 0xC00002C4
STATUS_DATATYPE_MISALIGNMENT_ERROR                                = 0xC00002C5
STATUS_WMI_READ_ONLY                                              = 0xC00002C6
STATUS_WMI_SET_FAILURE                                            = 0xC00002C7
STATUS_COMMITMENT_MINIMUM                                         = 0xC00002C8
STATUS_REG_NAT_CONSUMPTION                                        = 0xC00002C9
STATUS_TRANSPORT_FULL                                             = 0xC00002CA
STATUS_DS_SAM_INIT_FAILURE                                        = 0xC00002CB
STATUS_ONLY_IF_CONNECTED                                          = 0xC00002CC
STATUS_DS_SENSITIVE_GROUP_VIOLATION                               = 0xC00002CD
STATUS_PNP_RESTART_ENUMERATION                                    = 0xC00002CE
STATUS_JOURNAL_ENTRY_DELETED                                      = 0xC00002CF
STATUS_DS_CANT_MOD_PRIMARYGROUPID                                 = 0xC00002D0
STATUS_SYSTEM_IMAGE_BAD_SIGNATURE                                 = 0xC00002D1
STATUS_PNP_REBOOT_REQUIRED                                        = 0xC00002D2
STATUS_POWER_STATE_INVALID                                        = 0xC00002D3
STATUS_DS_INVALID_GROUP_TYPE                                      = 0xC00002D4
STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN                      = 0xC00002D5
STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN                       = 0xC00002D6
STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER                           = 0xC00002D7
STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER                       = 0xC00002D8
STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER                        = 0xC00002D9
STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER                     = 0xC00002DA
STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER                = 0xC00002DB
STATUS_DS_HAVE_PRIMARY_MEMBERS                                    = 0xC00002DC
STATUS_WMI_NOT_SUPPORTED                                          = 0xC00002DD
STATUS_INSUFFICIENT_POWER                                         = 0xC00002DE
STATUS_SAM_NEED_BOOTKEY_PASSWORD                                  = 0xC00002DF
STATUS_SAM_NEED_BOOTKEY_FLOPPY                                    = 0xC00002E0
STATUS_DS_CANT_START                                              = 0xC00002E1
STATUS_DS_INIT_FAILURE                                            = 0xC00002E2
STATUS_SAM_INIT_FAILURE                                           = 0xC00002E3
STATUS_DS_GC_REQUIRED                                             = 0xC00002E4
STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY                              = 0xC00002E5
STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS                              = 0xC00002E6
STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED                          = 0xC00002E7
STATUS_CURRENT_DOMAIN_NOT_ALLOWED                                 = 0xC00002E9
STATUS_CANNOT_MAKE                                                = 0xC00002EA
STATUS_SYSTEM_SHUTDOWN                                            = 0xC00002EB
STATUS_DS_INIT_FAILURE_CONSOLE                                    = 0xC00002EC
STATUS_DS_SAM_INIT_FAILURE_CONSOLE                                = 0xC00002ED
STATUS_UNFINISHED_CONTEXT_DELETED                                 = 0xC00002EE
STATUS_NO_TGT_REPLY                                               = 0xC00002EF
STATUS_OBJECTID_NOT_FOUND                                         = 0xC00002F0
STATUS_NO_IP_ADDRESSES                                            = 0xC00002F1
STATUS_WRONG_CREDENTIAL_HANDLE                                    = 0xC00002F2
STATUS_CRYPTO_SYSTEM_INVALID                                      = 0xC00002F3
STATUS_MAX_REFERRALS_EXCEEDED                                     = 0xC00002F4
STATUS_MUST_BE_KDC                                                = 0xC00002F5
STATUS_STRONG_CRYPTO_NOT_SUPPORTED                                = 0xC00002F6
STATUS_TOO_MANY_PRINCIPALS                                        = 0xC00002F7
STATUS_NO_PA_DATA                                                 = 0xC00002F8
STATUS_PKINIT_NAME_MISMATCH                                       = 0xC00002F9
STATUS_SMARTCARD_LOGON_REQUIRED                                   = 0xC00002FA
STATUS_KDC_INVALID_REQUEST                                        = 0xC00002FB
STATUS_KDC_UNABLE_TO_REFER                                        = 0xC00002FC
STATUS_KDC_UNKNOWN_ETYPE                                          = 0xC00002FD
STATUS_SHUTDOWN_IN_PROGRESS                                       = 0xC00002FE
STATUS_SERVER_SHUTDOWN_IN_PROGRESS                                = 0xC00002FF
STATUS_NOT_SUPPORTED_ON_SBS                                       = 0xC0000300
STATUS_WMI_GUID_DISCONNECTED                                      = 0xC0000301
STATUS_WMI_ALREADY_DISABLED                                       = 0xC0000302
STATUS_WMI_ALREADY_ENABLED                                        = 0xC0000303
STATUS_MFT_TOO_FRAGMENTED                                         = 0xC0000304
STATUS_COPY_PROTECTION_FAILURE                                    = 0xC0000305
STATUS_CSS_AUTHENTICATION_FAILURE                                 = 0xC0000306
STATUS_CSS_KEY_NOT_PRESENT                                        = 0xC0000307
STATUS_CSS_KEY_NOT_ESTABLISHED                                    = 0xC0000308
STATUS_CSS_SCRAMBLED_SECTOR                                       = 0xC0000309
STATUS_CSS_REGION_MISMATCH                                        = 0xC000030A
STATUS_CSS_RESETS_EXHAUSTED                                       = 0xC000030B
STATUS_PKINIT_FAILURE                                             = 0xC0000320
STATUS_SMARTCARD_SUBSYSTEM_FAILURE                                = 0xC0000321
STATUS_NO_KERB_KEY                                                = 0xC0000322
STATUS_HOST_DOWN                                                  = 0xC0000350
STATUS_UNSUPPORTED_PREAUTH                                        = 0xC0000351
STATUS_EFS_ALG_BLOB_TOO_BIG                                       = 0xC0000352
STATUS_PORT_NOT_SET                                               = 0xC0000353
STATUS_DEBUGGER_INACTIVE                                          = 0xC0000354
STATUS_DS_VERSION_CHECK_FAILURE                                   = 0xC0000355
STATUS_AUDITING_DISABLED                                          = 0xC0000356
STATUS_PRENT4_MACHINE_ACCOUNT                                     = 0xC0000357
STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER                           = 0xC0000358
STATUS_INVALID_IMAGE_WIN_32                                       = 0xC0000359
STATUS_INVALID_IMAGE_WIN_64                                       = 0xC000035A
STATUS_BAD_BINDINGS                                               = 0xC000035B
STATUS_NETWORK_SESSION_EXPIRED                                    = 0xC000035C
STATUS_APPHELP_BLOCK                                              = 0xC000035D
STATUS_ALL_SIDS_FILTERED                                          = 0xC000035E
STATUS_NOT_SAFE_MODE_DRIVER                                       = 0xC000035F
STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT                          = 0xC0000361
STATUS_ACCESS_DISABLED_BY_POLICY_PATH                             = 0xC0000362
STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER                        = 0xC0000363
STATUS_ACCESS_DISABLED_BY_POLICY_OTHER                            = 0xC0000364
STATUS_FAILED_DRIVER_ENTRY                                        = 0xC0000365
STATUS_DEVICE_ENUMERATION_ERROR                                   = 0xC0000366
STATUS_MOUNT_POINT_NOT_RESOLVED                                   = 0xC0000368
STATUS_INVALID_DEVICE_OBJECT_PARAMETER                            = 0xC0000369
STATUS_MCA_OCCURED                                                = 0xC000036A
STATUS_DRIVER_BLOCKED_CRITICAL                                    = 0xC000036B
STATUS_DRIVER_BLOCKED                                             = 0xC000036C
STATUS_DRIVER_DATABASE_ERROR                                      = 0xC000036D
STATUS_SYSTEM_HIVE_TOO_LARGE                                      = 0xC000036E
STATUS_INVALID_IMPORT_OF_NON_DLL                                  = 0xC000036F
STATUS_NO_SECRETS                                                 = 0xC0000371
STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY                      = 0xC0000372
STATUS_FAILED_STACK_SWITCH                                        = 0xC0000373
STATUS_HEAP_CORRUPTION                                            = 0xC0000374
STATUS_SMARTCARD_WRONG_PIN                                        = 0xC0000380
STATUS_SMARTCARD_CARD_BLOCKED                                     = 0xC0000381
STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED                           = 0xC0000382
STATUS_SMARTCARD_NO_CARD                                          = 0xC0000383
STATUS_SMARTCARD_NO_KEY_CONTAINER                                 = 0xC0000384
STATUS_SMARTCARD_NO_CERTIFICATE                                   = 0xC0000385
STATUS_SMARTCARD_NO_KEYSET                                        = 0xC0000386
STATUS_SMARTCARD_IO_ERROR                                         = 0xC0000387
STATUS_DOWNGRADE_DETECTED                                         = 0xC0000388
STATUS_SMARTCARD_CERT_REVOKED                                     = 0xC0000389
STATUS_ISSUING_CA_UNTRUSTED                                       = 0xC000038A
STATUS_REVOCATION_OFFLINE_C                                       = 0xC000038B
STATUS_PKINIT_CLIENT_FAILURE                                      = 0xC000038C
STATUS_SMARTCARD_CERT_EXPIRED                                     = 0xC000038D
STATUS_DRIVER_FAILED_PRIOR_UNLOAD                                 = 0xC000038E
STATUS_SMARTCARD_SILENT_CONTEXT                                   = 0xC000038F
STATUS_PER_USER_TRUST_QUOTA_EXCEEDED                              = 0xC0000401
STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED                              = 0xC0000402
STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED                           = 0xC0000403
STATUS_DS_NAME_NOT_UNIQUE                                         = 0xC0000404
STATUS_DS_DUPLICATE_ID_FOUND                                      = 0xC0000405
STATUS_DS_GROUP_CONVERSION_ERROR                                  = 0xC0000406
STATUS_VOLSNAP_PREPARE_HIBERNATE                                  = 0xC0000407
STATUS_USER2USER_REQUIRED                                         = 0xC0000408
STATUS_STACK_BUFFER_OVERRUN                                       = 0xC0000409
STATUS_NO_S4U_PROT_SUPPORT                                        = 0xC000040A
STATUS_CROSSREALM_DELEGATION_FAILURE                              = 0xC000040B
STATUS_REVOCATION_OFFLINE_KDC                                     = 0xC000040C
STATUS_ISSUING_CA_UNTRUSTED_KDC                                   = 0xC000040D
STATUS_KDC_CERT_EXPIRED                                           = 0xC000040E
STATUS_KDC_CERT_REVOKED                                           = 0xC000040F
STATUS_PARAMETER_QUOTA_EXCEEDED                                   = 0xC0000410
STATUS_HIBERNATION_FAILURE                                        = 0xC0000411
STATUS_DELAY_LOAD_FAILED                                          = 0xC0000412
STATUS_AUTHENTICATION_FIREWALL_FAILED                             = 0xC0000413
STATUS_VDM_DISALLOWED                                             = 0xC0000414
STATUS_HUNG_DISPLAY_DRIVER_THREAD                                 = 0xC0000415
STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE    = 0xC0000416
STATUS_INVALID_CRUNTIME_PARAMETER                                 = 0xC0000417
STATUS_NTLM_BLOCKED                                               = 0xC0000418
STATUS_DS_SRC_SID_EXISTS_IN_FOREST                                = 0xC0000419
STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST                            = 0xC000041A
STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST                              = 0xC000041B
STATUS_INVALID_USER_PRINCIPAL_NAME                                = 0xC000041C
STATUS_ASSERTION_FAILURE                                          = 0xC0000420
STATUS_VERIFIER_STOP                                              = 0xC0000421
STATUS_CALLBACK_POP_STACK                                         = 0xC0000423
STATUS_INCOMPATIBLE_DRIVER_BLOCKED                                = 0xC0000424
STATUS_HIVE_UNLOADED                                              = 0xC0000425
STATUS_COMPRESSION_DISABLED                                       = 0xC0000426
STATUS_FILE_SYSTEM_LIMITATION                                     = 0xC0000427
STATUS_INVALID_IMAGE_HASH                                         = 0xC0000428
STATUS_NOT_CAPABLE                                                = 0xC0000429
STATUS_REQUEST_OUT_OF_SEQUENCE                                    = 0xC000042A
STATUS_IMPLEMENTATION_LIMIT                                       = 0xC000042B
STATUS_ELEVATION_REQUIRED                                         = 0xC000042C
STATUS_NO_SECURITY_CONTEXT                                        = 0xC000042D
STATUS_PKU2U_CERT_FAILURE                                         = 0xC000042E
STATUS_BEYOND_VDL                                                 = 0xC0000432
STATUS_ENCOUNTERED_WRITE_IN_PROGRESS                              = 0xC0000433
STATUS_PTE_CHANGED                                                = 0xC0000434
STATUS_PURGE_FAILED                                               = 0xC0000435
STATUS_CRED_REQUIRES_CONFIRMATION                                 = 0xC0000440
STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE                      = 0xC0000441
STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER                           = 0xC0000442
STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE                      = 0xC0000443
STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE                           = 0xC0000444
STATUS_CS_ENCRYPTION_FILE_NOT_CSE                                 = 0xC0000445
STATUS_INVALID_LABEL                                              = 0xC0000446
STATUS_DRIVER_PROCESS_TERMINATED                                  = 0xC0000450
STATUS_AMBIGUOUS_SYSTEM_DEVICE                                    = 0xC0000451
STATUS_SYSTEM_DEVICE_NOT_FOUND                                    = 0xC0000452
STATUS_RESTART_BOOT_APPLICATION                                   = 0xC0000453
STATUS_INSUFFICIENT_NVRAM_RESOURCES                               = 0xC0000454
STATUS_INVALID_TASK_NAME                                          = 0xC0000500
STATUS_INVALID_TASK_INDEX                                         = 0xC0000501
STATUS_THREAD_ALREADY_IN_TASK                                     = 0xC0000502
STATUS_CALLBACK_BYPASS                                            = 0xC0000503
STATUS_FAIL_FAST_EXCEPTION                                        = 0xC0000602
STATUS_IMAGE_CERT_REVOKED                                         = 0xC0000603
STATUS_PORT_CLOSED                                                = 0xC0000700
STATUS_MESSAGE_LOST                                               = 0xC0000701
STATUS_INVALID_MESSAGE                                            = 0xC0000702
STATUS_REQUEST_CANCELED                                           = 0xC0000703
STATUS_RECURSIVE_DISPATCH                                         = 0xC0000704
STATUS_LPC_RECEIVE_BUFFER_EXPECTED                                = 0xC0000705
STATUS_LPC_INVALID_CONNECTION_USAGE                               = 0xC0000706
STATUS_LPC_REQUESTS_NOT_ALLOWED                                   = 0xC0000707
STATUS_RESOURCE_IN_USE                                            = 0xC0000708
STATUS_HARDWARE_MEMORY_ERROR                                      = 0xC0000709
STATUS_THREADPOOL_HANDLE_EXCEPTION                                = 0xC000070A
STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED                  = 0xC000070B
STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED          = 0xC000070C
STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED              = 0xC000070D
STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED               = 0xC000070E
STATUS_THREADPOOL_RELEASED_DURING_OPERATION                       = 0xC000070F
STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING                      = 0xC0000710
STATUS_APC_RETURNED_WHILE_IMPERSONATING                           = 0xC0000711
STATUS_PROCESS_IS_PROTECTED                                       = 0xC0000712
STATUS_MCA_EXCEPTION                                              = 0xC0000713
STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE                             = 0xC0000714
STATUS_SYMLINK_CLASS_DISABLED                                     = 0xC0000715
STATUS_INVALID_IDN_NORMALIZATION                                  = 0xC0000716
STATUS_NO_UNICODE_TRANSLATION                                     = 0xC0000717
STATUS_ALREADY_REGISTERED                                         = 0xC0000718
STATUS_CONTEXT_MISMATCH                                           = 0xC0000719
STATUS_PORT_ALREADY_HAS_COMPLETION_LIST                           = 0xC000071A
STATUS_CALLBACK_RETURNED_THREAD_PRIORITY                          = 0xC000071B
STATUS_INVALID_THREAD                                             = 0xC000071C
STATUS_CALLBACK_RETURNED_TRANSACTION                              = 0xC000071D
STATUS_CALLBACK_RETURNED_LDR_LOCK                                 = 0xC000071E
STATUS_CALLBACK_RETURNED_LANG                                     = 0xC000071F
STATUS_CALLBACK_RETURNED_PRI_BACK                                 = 0xC0000720
STATUS_DISK_REPAIR_DISABLED                                       = 0xC0000800
STATUS_DS_DOMAIN_RENAME_IN_PROGRESS                               = 0xC0000801
STATUS_DISK_QUOTA_EXCEEDED                                        = 0xC0000802
STATUS_CONTENT_BLOCKED                                            = 0xC0000804
STATUS_BAD_CLUSTERS                                               = 0xC0000805
STATUS_VOLUME_DIRTY                                               = 0xC0000806
STATUS_FILE_CHECKED_OUT                                           = 0xC0000901
STATUS_CHECKOUT_REQUIRED                                          = 0xC0000902
STATUS_BAD_FILE_TYPE                                              = 0xC0000903
STATUS_FILE_TOO_LARGE                                             = 0xC0000904
STATUS_FORMS_AUTH_REQUIRED                                        = 0xC0000905
STATUS_VIRUS_INFECTED                                             = 0xC0000906
STATUS_VIRUS_DELETED                                              = 0xC0000907
STATUS_BAD_MCFG_TABLE                                             = 0xC0000908
STATUS_CANNOT_BREAK_OPLOCK                                        = 0xC0000909
STATUS_WOW_ASSERTION                                              = 0xC0009898
STATUS_INVALID_SIGNATURE                                          = 0xC000A000
STATUS_HMAC_NOT_SUPPORTED                                         = 0xC000A001
STATUS_IPSEC_QUEUE_OVERFLOW                                       = 0xC000A010
STATUS_ND_QUEUE_OVERFLOW                                          = 0xC000A011
STATUS_HOPLIMIT_EXCEEDED                                          = 0xC000A012
STATUS_PROTOCOL_NOT_SUPPORTED                                     = 0xC000A013
STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED                 = 0xC000A080
STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR                 = 0xC000A081
STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR                     = 0xC000A082
STATUS_XML_PARSE_ERROR                                            = 0xC000A083
STATUS_XMLDSIG_ERROR                                              = 0xC000A084
STATUS_WRONG_COMPARTMENT                                          = 0xC000A085
STATUS_AUTHIP_FAILURE                                             = 0xC000A086
STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS                      = 0xC000A087
STATUS_DS_OID_NOT_FOUND                                           = 0xC000A088
STATUS_HASH_NOT_SUPPORTED                                         = 0xC000A100
STATUS_HASH_NOT_PRESENT                                           = 0xC000A101
DBG_NO_STATE_CHANGE                                               = 0xC0010001
DBG_APP_NOT_IDLE                                                  = 0xC0010002
RPC_NT_INVALID_STRING_BINDING                                     = 0xC0020001
RPC_NT_WRONG_KIND_OF_BINDING                                      = 0xC0020002
RPC_NT_INVALID_BINDING                                            = 0xC0020003
RPC_NT_PROTSEQ_NOT_SUPPORTED                                      = 0xC0020004
RPC_NT_INVALID_RPC_PROTSEQ                                        = 0xC0020005
RPC_NT_INVALID_STRING_UUID                                        = 0xC0020006
RPC_NT_INVALID_ENDPOINT_FORMAT                                    = 0xC0020007
RPC_NT_INVALID_NET_ADDR                                           = 0xC0020008
RPC_NT_NO_ENDPOINT_FOUND                                          = 0xC0020009
RPC_NT_INVALID_TIMEOUT                                            = 0xC002000A
RPC_NT_OBJECT_NOT_FOUND                                           = 0xC002000B
RPC_NT_ALREADY_REGISTERED                                         = 0xC002000C
RPC_NT_TYPE_ALREADY_REGISTERED                                    = 0xC002000D
RPC_NT_ALREADY_LISTENING                                          = 0xC002000E
RPC_NT_NO_PROTSEQS_REGISTERED                                     = 0xC002000F
RPC_NT_NOT_LISTENING                                              = 0xC0020010
RPC_NT_UNKNOWN_MGR_TYPE                                           = 0xC0020011
RPC_NT_UNKNOWN_IF                                                 = 0xC0020012
RPC_NT_NO_BINDINGS                                                = 0xC0020013
RPC_NT_NO_PROTSEQS                                                = 0xC0020014
RPC_NT_CANT_CREATE_ENDPOINT                                       = 0xC0020015
RPC_NT_OUT_OF_RESOURCES                                           = 0xC0020016
RPC_NT_SERVER_UNAVAILABLE                                         = 0xC0020017
RPC_NT_SERVER_TOO_BUSY                                            = 0xC0020018
RPC_NT_INVALID_NETWORK_OPTIONS                                    = 0xC0020019
RPC_NT_NO_CALL_ACTIVE                                             = 0xC002001A
RPC_NT_CALL_FAILED                                                = 0xC002001B
RPC_NT_CALL_FAILED_DNE                                            = 0xC002001C
RPC_NT_PROTOCOL_ERROR                                             = 0xC002001D
RPC_NT_UNSUPPORTED_TRANS_SYN                                      = 0xC002001F
RPC_NT_UNSUPPORTED_TYPE                                           = 0xC0020021
RPC_NT_INVALID_TAG                                                = 0xC0020022
RPC_NT_INVALID_BOUND                                              = 0xC0020023
RPC_NT_NO_ENTRY_NAME                                              = 0xC0020024
RPC_NT_INVALID_NAME_SYNTAX                                        = 0xC0020025
RPC_NT_UNSUPPORTED_NAME_SYNTAX                                    = 0xC0020026
RPC_NT_UUID_NO_ADDRESS                                            = 0xC0020028
RPC_NT_DUPLICATE_ENDPOINT                                         = 0xC0020029
RPC_NT_UNKNOWN_AUTHN_TYPE                                         = 0xC002002A
RPC_NT_MAX_CALLS_TOO_SMALL                                        = 0xC002002B
RPC_NT_STRING_TOO_LONG                                            = 0xC002002C
RPC_NT_PROTSEQ_NOT_FOUND                                          = 0xC002002D
RPC_NT_PROCNUM_OUT_OF_RANGE                                       = 0xC002002E
RPC_NT_BINDING_HAS_NO_AUTH                                        = 0xC002002F
RPC_NT_UNKNOWN_AUTHN_SERVICE                                      = 0xC0020030
RPC_NT_UNKNOWN_AUTHN_LEVEL                                        = 0xC0020031
RPC_NT_INVALID_AUTH_IDENTITY                                      = 0xC0020032
RPC_NT_UNKNOWN_AUTHZ_SERVICE                                      = 0xC0020033
EPT_NT_INVALID_ENTRY                                              = 0xC0020034
EPT_NT_CANT_PERFORM_OP                                            = 0xC0020035
EPT_NT_NOT_REGISTERED                                             = 0xC0020036
RPC_NT_NOTHING_TO_EXPORT                                          = 0xC0020037
RPC_NT_INCOMPLETE_NAME                                            = 0xC0020038
RPC_NT_INVALID_VERS_OPTION                                        = 0xC0020039
RPC_NT_NO_MORE_MEMBERS                                            = 0xC002003A
RPC_NT_NOT_ALL_OBJS_UNEXPORTED                                    = 0xC002003B
RPC_NT_INTERFACE_NOT_FOUND                                        = 0xC002003C
RPC_NT_ENTRY_ALREADY_EXISTS                                       = 0xC002003D
RPC_NT_ENTRY_NOT_FOUND                                            = 0xC002003E
RPC_NT_NAME_SERVICE_UNAVAILABLE                                   = 0xC002003F
RPC_NT_INVALID_NAF_ID                                             = 0xC0020040
RPC_NT_CANNOT_SUPPORT                                             = 0xC0020041
RPC_NT_NO_CONTEXT_AVAILABLE                                       = 0xC0020042
RPC_NT_INTERNAL_ERROR                                             = 0xC0020043
RPC_NT_ZERO_DIVIDE                                                = 0xC0020044
RPC_NT_ADDRESS_ERROR                                              = 0xC0020045
RPC_NT_FP_DIV_ZERO                                                = 0xC0020046
RPC_NT_FP_UNDERFLOW                                               = 0xC0020047
RPC_NT_FP_OVERFLOW                                                = 0xC0020048
RPC_NT_CALL_IN_PROGRESS                                           = 0xC0020049
RPC_NT_NO_MORE_BINDINGS                                           = 0xC002004A
RPC_NT_GROUP_MEMBER_NOT_FOUND                                     = 0xC002004B
EPT_NT_CANT_CREATE                                                = 0xC002004C
RPC_NT_INVALID_OBJECT                                             = 0xC002004D
RPC_NT_NO_INTERFACES                                              = 0xC002004F
RPC_NT_CALL_CANCELLED                                             = 0xC0020050
RPC_NT_BINDING_INCOMPLETE                                         = 0xC0020051
RPC_NT_COMM_FAILURE                                               = 0xC0020052
RPC_NT_UNSUPPORTED_AUTHN_LEVEL                                    = 0xC0020053
RPC_NT_NO_PRINC_NAME                                              = 0xC0020054
RPC_NT_NOT_RPC_ERROR                                              = 0xC0020055
RPC_NT_SEC_PKG_ERROR                                              = 0xC0020057
RPC_NT_NOT_CANCELLED                                              = 0xC0020058
RPC_NT_INVALID_ASYNC_HANDLE                                       = 0xC0020062
RPC_NT_INVALID_ASYNC_CALL                                         = 0xC0020063
RPC_NT_PROXY_ACCESS_DENIED                                        = 0xC0020064
RPC_NT_NO_MORE_ENTRIES                                            = 0xC0030001
RPC_NT_SS_CHAR_TRANS_OPEN_FAIL                                    = 0xC0030002
RPC_NT_SS_CHAR_TRANS_SHORT_FILE                                   = 0xC0030003
RPC_NT_SS_IN_NULL_CONTEXT                                         = 0xC0030004
RPC_NT_SS_CONTEXT_MISMATCH                                        = 0xC0030005
RPC_NT_SS_CONTEXT_DAMAGED                                         = 0xC0030006
RPC_NT_SS_HANDLES_MISMATCH                                        = 0xC0030007
RPC_NT_SS_CANNOT_GET_CALL_HANDLE                                  = 0xC0030008
RPC_NT_NULL_REF_POINTER                                           = 0xC0030009
RPC_NT_ENUM_VALUE_OUT_OF_RANGE                                    = 0xC003000A
RPC_NT_BYTE_COUNT_TOO_SMALL                                       = 0xC003000B
RPC_NT_BAD_STUB_DATA                                              = 0xC003000C
RPC_NT_INVALID_ES_ACTION                                          = 0xC0030059
RPC_NT_WRONG_ES_VERSION                                           = 0xC003005A
RPC_NT_WRONG_STUB_VERSION                                         = 0xC003005B
RPC_NT_INVALID_PIPE_OBJECT                                        = 0xC003005C
RPC_NT_INVALID_PIPE_OPERATION                                     = 0xC003005D
RPC_NT_WRONG_PIPE_VERSION                                         = 0xC003005E
RPC_NT_PIPE_CLOSED                                                = 0xC003005F
RPC_NT_PIPE_DISCIPLINE_ERROR                                      = 0xC0030060
RPC_NT_PIPE_EMPTY                                                 = 0xC0030061
STATUS_PNP_BAD_MPS_TABLE                                          = 0xC0040035
STATUS_PNP_TRANSLATION_FAILED                                     = 0xC0040036
STATUS_PNP_IRQ_TRANSLATION_FAILED                                 = 0xC0040037
STATUS_PNP_INVALID_ID                                             = 0xC0040038
STATUS_IO_REISSUE_AS_CACHED                                       = 0xC0040039
STATUS_CTX_WINSTATION_NAME_INVALID                                = 0xC00A0001
STATUS_CTX_INVALID_PD                                             = 0xC00A0002
STATUS_CTX_PD_NOT_FOUND                                           = 0xC00A0003
STATUS_CTX_CLOSE_PENDING                                          = 0xC00A0006
STATUS_CTX_NO_OUTBUF                                              = 0xC00A0007
STATUS_CTX_MODEM_INF_NOT_FOUND                                    = 0xC00A0008
STATUS_CTX_INVALID_MODEMNAME                                      = 0xC00A0009
STATUS_CTX_RESPONSE_ERROR                                         = 0xC00A000A
STATUS_CTX_MODEM_RESPONSE_TIMEOUT                                 = 0xC00A000B
STATUS_CTX_MODEM_RESPONSE_NO_CARRIER                              = 0xC00A000C
STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE                             = 0xC00A000D
STATUS_CTX_MODEM_RESPONSE_BUSY                                    = 0xC00A000E
STATUS_CTX_MODEM_RESPONSE_VOICE                                   = 0xC00A000F
STATUS_CTX_TD_ERROR                                               = 0xC00A0010
STATUS_CTX_LICENSE_CLIENT_INVALID                                 = 0xC00A0012
STATUS_CTX_LICENSE_NOT_AVAILABLE                                  = 0xC00A0013
STATUS_CTX_LICENSE_EXPIRED                                        = 0xC00A0014
STATUS_CTX_WINSTATION_NOT_FOUND                                   = 0xC00A0015
STATUS_CTX_WINSTATION_NAME_COLLISION                              = 0xC00A0016
STATUS_CTX_WINSTATION_BUSY                                        = 0xC00A0017
STATUS_CTX_BAD_VIDEO_MODE                                         = 0xC00A0018
STATUS_CTX_GRAPHICS_INVALID                                       = 0xC00A0022
STATUS_CTX_NOT_CONSOLE                                            = 0xC00A0024
STATUS_CTX_CLIENT_QUERY_TIMEOUT                                   = 0xC00A0026
STATUS_CTX_CONSOLE_DISCONNECT                                     = 0xC00A0027
STATUS_CTX_CONSOLE_CONNECT                                        = 0xC00A0028
STATUS_CTX_SHADOW_DENIED                                          = 0xC00A002A
STATUS_CTX_WINSTATION_ACCESS_DENIED                               = 0xC00A002B
STATUS_CTX_INVALID_WD                                             = 0xC00A002E
STATUS_CTX_WD_NOT_FOUND                                           = 0xC00A002F
STATUS_CTX_SHADOW_INVALID                                         = 0xC00A0030
STATUS_CTX_SHADOW_DISABLED                                        = 0xC00A0031
STATUS_RDP_PROTOCOL_ERROR                                         = 0xC00A0032
STATUS_CTX_CLIENT_LICENSE_NOT_SET                                 = 0xC00A0033
STATUS_CTX_CLIENT_LICENSE_IN_USE                                  = 0xC00A0034
STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE                            = 0xC00A0035
STATUS_CTX_SHADOW_NOT_RUNNING                                     = 0xC00A0036
STATUS_CTX_LOGON_DISABLED                                         = 0xC00A0037
STATUS_CTX_SECURITY_LAYER_ERROR                                   = 0xC00A0038
STATUS_TS_INCOMPATIBLE_SESSIONS                                   = 0xC00A0039
STATUS_MUI_FILE_NOT_FOUND                                         = 0xC00B0001
STATUS_MUI_INVALID_FILE                                           = 0xC00B0002
STATUS_MUI_INVALID_RC_CONFIG                                      = 0xC00B0003
STATUS_MUI_INVALID_LOCALE_NAME                                    = 0xC00B0004
STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME                          = 0xC00B0005
STATUS_MUI_FILE_NOT_LOADED                                        = 0xC00B0006
STATUS_RESOURCE_ENUM_USER_STOP                                    = 0xC00B0007
STATUS_CLUSTER_INVALID_NODE                                       = 0xC0130001
STATUS_CLUSTER_NODE_EXISTS                                        = 0xC0130002
STATUS_CLUSTER_JOIN_IN_PROGRESS                                   = 0xC0130003
STATUS_CLUSTER_NODE_NOT_FOUND                                     = 0xC0130004
STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND                               = 0xC0130005
STATUS_CLUSTER_NETWORK_EXISTS                                     = 0xC0130006
STATUS_CLUSTER_NETWORK_NOT_FOUND                                  = 0xC0130007
STATUS_CLUSTER_NETINTERFACE_EXISTS                                = 0xC0130008
STATUS_CLUSTER_NETINTERFACE_NOT_FOUND                             = 0xC0130009
STATUS_CLUSTER_INVALID_REQUEST                                    = 0xC013000A
STATUS_CLUSTER_INVALID_NETWORK_PROVIDER                           = 0xC013000B
STATUS_CLUSTER_NODE_DOWN                                          = 0xC013000C
STATUS_CLUSTER_NODE_UNREACHABLE                                   = 0xC013000D
STATUS_CLUSTER_NODE_NOT_MEMBER                                    = 0xC013000E
STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS                               = 0xC013000F
STATUS_CLUSTER_INVALID_NETWORK                                    = 0xC0130010
STATUS_CLUSTER_NO_NET_ADAPTERS                                    = 0xC0130011
STATUS_CLUSTER_NODE_UP                                            = 0xC0130012
STATUS_CLUSTER_NODE_PAUSED                                        = 0xC0130013
STATUS_CLUSTER_NODE_NOT_PAUSED                                    = 0xC0130014
STATUS_CLUSTER_NO_SECURITY_CONTEXT                                = 0xC0130015
STATUS_CLUSTER_NETWORK_NOT_INTERNAL                               = 0xC0130016
STATUS_CLUSTER_POISONED                                           = 0xC0130017
STATUS_ACPI_INVALID_OPCODE                                        = 0xC0140001
STATUS_ACPI_STACK_OVERFLOW                                        = 0xC0140002
STATUS_ACPI_ASSERT_FAILED                                         = 0xC0140003
STATUS_ACPI_INVALID_INDEX                                         = 0xC0140004
STATUS_ACPI_INVALID_ARGUMENT                                      = 0xC0140005
STATUS_ACPI_FATAL                                                 = 0xC0140006
STATUS_ACPI_INVALID_SUPERNAME                                     = 0xC0140007
STATUS_ACPI_INVALID_ARGTYPE                                       = 0xC0140008
STATUS_ACPI_INVALID_OBJTYPE                                       = 0xC0140009
STATUS_ACPI_INVALID_TARGETTYPE                                    = 0xC014000A
STATUS_ACPI_INCORRECT_ARGUMENT_COUNT                              = 0xC014000B
STATUS_ACPI_ADDRESS_NOT_MAPPED                                    = 0xC014000C
STATUS_ACPI_INVALID_EVENTTYPE                                     = 0xC014000D
STATUS_ACPI_HANDLER_COLLISION                                     = 0xC014000E
STATUS_ACPI_INVALID_DATA                                          = 0xC014000F
STATUS_ACPI_INVALID_REGION                                        = 0xC0140010
STATUS_ACPI_INVALID_ACCESS_SIZE                                   = 0xC0140011
STATUS_ACPI_ACQUIRE_GLOBAL_LOCK                                   = 0xC0140012
STATUS_ACPI_ALREADY_INITIALIZED                                   = 0xC0140013
STATUS_ACPI_NOT_INITIALIZED                                       = 0xC0140014
STATUS_ACPI_INVALID_MUTEX_LEVEL                                   = 0xC0140015
STATUS_ACPI_MUTEX_NOT_OWNED                                       = 0xC0140016
STATUS_ACPI_MUTEX_NOT_OWNER                                       = 0xC0140017
STATUS_ACPI_RS_ACCESS                                             = 0xC0140018
STATUS_ACPI_INVALID_TABLE                                         = 0xC0140019
STATUS_ACPI_REG_HANDLER_FAILED                                    = 0xC0140020
STATUS_ACPI_POWER_REQUEST_FAILED                                  = 0xC0140021
STATUS_SXS_SECTION_NOT_FOUND                                      = 0xC0150001
STATUS_SXS_CANT_GEN_ACTCTX                                        = 0xC0150002
STATUS_SXS_INVALID_ACTCTXDATA_FORMAT                              = 0xC0150003
STATUS_SXS_ASSEMBLY_NOT_FOUND                                     = 0xC0150004
STATUS_SXS_MANIFEST_FORMAT_ERROR                                  = 0xC0150005
STATUS_SXS_MANIFEST_PARSE_ERROR                                   = 0xC0150006
STATUS_SXS_ACTIVATION_CONTEXT_DISABLED                            = 0xC0150007
STATUS_SXS_KEY_NOT_FOUND                                          = 0xC0150008
STATUS_SXS_VERSION_CONFLICT                                       = 0xC0150009
STATUS_SXS_WRONG_SECTION_TYPE                                     = 0xC015000A
STATUS_SXS_THREAD_QUERIES_DISABLED                                = 0xC015000B
STATUS_SXS_ASSEMBLY_MISSING                                       = 0xC015000C
STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET                            = 0xC015000E
STATUS_SXS_EARLY_DEACTIVATION                                     = 0xC015000F
STATUS_SXS_INVALID_DEACTIVATION                                   = 0xC0150010
STATUS_SXS_MULTIPLE_DEACTIVATION                                  = 0xC0150011
STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY                = 0xC0150012
STATUS_SXS_PROCESS_TERMINATION_REQUESTED                          = 0xC0150013
STATUS_SXS_CORRUPT_ACTIVATION_STACK                               = 0xC0150014
STATUS_SXS_CORRUPTION                                             = 0xC0150015
STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE                       = 0xC0150016
STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME                        = 0xC0150017
STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE                           = 0xC0150018
STATUS_SXS_IDENTITY_PARSE_ERROR                                   = 0xC0150019
STATUS_SXS_COMPONENT_STORE_CORRUPT                                = 0xC015001A
STATUS_SXS_FILE_HASH_MISMATCH                                     = 0xC015001B
STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT          = 0xC015001C
STATUS_SXS_IDENTITIES_DIFFERENT                                   = 0xC015001D
STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT                           = 0xC015001E
STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY                              = 0xC015001F
STATUS_ADVANCED_INSTALLER_FAILED                                  = 0xC0150020
STATUS_XML_ENCODING_MISMATCH                                      = 0xC0150021
STATUS_SXS_MANIFEST_TOO_BIG                                       = 0xC0150022
STATUS_SXS_SETTING_NOT_REGISTERED                                 = 0xC0150023
STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE                         = 0xC0150024
STATUS_SMI_PRIMITIVE_INSTALLER_FAILED                             = 0xC0150025
STATUS_GENERIC_COMMAND_FAILED                                     = 0xC0150026
STATUS_SXS_FILE_HASH_MISSING                                      = 0xC0150027
STATUS_TRANSACTIONAL_CONFLICT                                     = 0xC0190001
STATUS_INVALID_TRANSACTION                                        = 0xC0190002
STATUS_TRANSACTION_NOT_ACTIVE                                     = 0xC0190003
STATUS_TM_INITIALIZATION_FAILED                                   = 0xC0190004
STATUS_RM_NOT_ACTIVE                                              = 0xC0190005
STATUS_RM_METADATA_CORRUPT                                        = 0xC0190006
STATUS_TRANSACTION_NOT_JOINED                                     = 0xC0190007
STATUS_DIRECTORY_NOT_RM                                           = 0xC0190008
STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE                            = 0xC019000A
STATUS_LOG_RESIZE_INVALID_SIZE                                    = 0xC019000B
STATUS_REMOTE_FILE_VERSION_MISMATCH                               = 0xC019000C
STATUS_CRM_PROTOCOL_ALREADY_EXISTS                                = 0xC019000F
STATUS_TRANSACTION_PROPAGATION_FAILED                             = 0xC0190010
STATUS_CRM_PROTOCOL_NOT_FOUND                                     = 0xC0190011
STATUS_TRANSACTION_SUPERIOR_EXISTS                                = 0xC0190012
STATUS_TRANSACTION_REQUEST_NOT_VALID                              = 0xC0190013
STATUS_TRANSACTION_NOT_REQUESTED                                  = 0xC0190014
STATUS_TRANSACTION_ALREADY_ABORTED                                = 0xC0190015
STATUS_TRANSACTION_ALREADY_COMMITTED                              = 0xC0190016
STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER                        = 0xC0190017
STATUS_CURRENT_TRANSACTION_NOT_VALID                              = 0xC0190018
STATUS_LOG_GROWTH_FAILED                                          = 0xC0190019
STATUS_OBJECT_NO_LONGER_EXISTS                                    = 0xC0190021
STATUS_STREAM_MINIVERSION_NOT_FOUND                               = 0xC0190022
STATUS_STREAM_MINIVERSION_NOT_VALID                               = 0xC0190023
STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION        = 0xC0190024
STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT                   = 0xC0190025
STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS                       = 0xC0190026
STATUS_HANDLE_NO_LONGER_VALID                                     = 0xC0190028
STATUS_LOG_CORRUPTION_DETECTED                                    = 0xC0190030
STATUS_RM_DISCONNECTED                                            = 0xC0190032
STATUS_ENLISTMENT_NOT_SUPERIOR                                    = 0xC0190033
STATUS_FILE_IDENTITY_NOT_PERSISTENT                               = 0xC0190036
STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY                        = 0xC0190037
STATUS_CANT_CROSS_RM_BOUNDARY                                     = 0xC0190038
STATUS_TXF_DIR_NOT_EMPTY                                          = 0xC0190039
STATUS_INDOUBT_TRANSACTIONS_EXIST                                 = 0xC019003A
STATUS_TM_VOLATILE                                                = 0xC019003B
STATUS_ROLLBACK_TIMER_EXPIRED                                     = 0xC019003C
STATUS_TXF_ATTRIBUTE_CORRUPT                                      = 0xC019003D
STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION                             = 0xC019003E
STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED                             = 0xC019003F
STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE                      = 0xC0190040
STATUS_TRANSACTION_REQUIRED_PROMOTION                             = 0xC0190043
STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION                         = 0xC0190044
STATUS_TRANSACTIONS_NOT_FROZEN                                    = 0xC0190045
STATUS_TRANSACTION_FREEZE_IN_PROGRESS                             = 0xC0190046
STATUS_NOT_SNAPSHOT_VOLUME                                        = 0xC0190047
STATUS_NO_SAVEPOINT_WITH_OPEN_FILES                               = 0xC0190048
STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION                          = 0xC0190049
STATUS_TM_IDENTITY_MISMATCH                                       = 0xC019004A
STATUS_FLOATED_SECTION                                            = 0xC019004B
STATUS_CANNOT_ACCEPT_TRANSACTED_WORK                              = 0xC019004C
STATUS_CANNOT_ABORT_TRANSACTIONS                                  = 0xC019004D
STATUS_TRANSACTION_NOT_FOUND                                      = 0xC019004E
STATUS_RESOURCEMANAGER_NOT_FOUND                                  = 0xC019004F
STATUS_ENLISTMENT_NOT_FOUND                                       = 0xC0190050
STATUS_TRANSACTIONMANAGER_NOT_FOUND                               = 0xC0190051
STATUS_TRANSACTIONMANAGER_NOT_ONLINE                              = 0xC0190052
STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION                 = 0xC0190053
STATUS_TRANSACTION_NOT_ROOT                                       = 0xC0190054
STATUS_TRANSACTION_OBJECT_EXPIRED                                 = 0xC0190055
STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION                     = 0xC0190056
STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED                          = 0xC0190057
STATUS_TRANSACTION_RECORD_TOO_LONG                                = 0xC0190058
STATUS_NO_LINK_TRACKING_IN_TRANSACTION                            = 0xC0190059
STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION                     = 0xC019005A
STATUS_TRANSACTION_INTEGRITY_VIOLATED                             = 0xC019005B
STATUS_EXPIRED_HANDLE                                             = 0xC0190060
STATUS_TRANSACTION_NOT_ENLISTED                                   = 0xC0190061
STATUS_LOG_SECTOR_INVALID                                         = 0xC01A0001
STATUS_LOG_SECTOR_PARITY_INVALID                                  = 0xC01A0002
STATUS_LOG_SECTOR_REMAPPED                                        = 0xC01A0003
STATUS_LOG_BLOCK_INCOMPLETE                                       = 0xC01A0004
STATUS_LOG_INVALID_RANGE                                          = 0xC01A0005
STATUS_LOG_BLOCKS_EXHAUSTED                                       = 0xC01A0006
STATUS_LOG_READ_CONTEXT_INVALID                                   = 0xC01A0007
STATUS_LOG_RESTART_INVALID                                        = 0xC01A0008
STATUS_LOG_BLOCK_VERSION                                          = 0xC01A0009
STATUS_LOG_BLOCK_INVALID                                          = 0xC01A000A
STATUS_LOG_READ_MODE_INVALID                                      = 0xC01A000B
STATUS_LOG_METADATA_CORRUPT                                       = 0xC01A000D
STATUS_LOG_METADATA_INVALID                                       = 0xC01A000E
STATUS_LOG_METADATA_INCONSISTENT                                  = 0xC01A000F
STATUS_LOG_RESERVATION_INVALID                                    = 0xC01A0010
STATUS_LOG_CANT_DELETE                                            = 0xC01A0011
STATUS_LOG_CONTAINER_LIMIT_EXCEEDED                               = 0xC01A0012
STATUS_LOG_START_OF_LOG                                           = 0xC01A0013
STATUS_LOG_POLICY_ALREADY_INSTALLED                               = 0xC01A0014
STATUS_LOG_POLICY_NOT_INSTALLED                                   = 0xC01A0015
STATUS_LOG_POLICY_INVALID                                         = 0xC01A0016
STATUS_LOG_POLICY_CONFLICT                                        = 0xC01A0017
STATUS_LOG_PINNED_ARCHIVE_TAIL                                    = 0xC01A0018
STATUS_LOG_RECORD_NONEXISTENT                                     = 0xC01A0019
STATUS_LOG_RECORDS_RESERVED_INVALID                               = 0xC01A001A
STATUS_LOG_SPACE_RESERVED_INVALID                                 = 0xC01A001B
STATUS_LOG_TAIL_INVALID                                           = 0xC01A001C
STATUS_LOG_FULL                                                   = 0xC01A001D
STATUS_LOG_MULTIPLEXED                                            = 0xC01A001E
STATUS_LOG_DEDICATED                                              = 0xC01A001F
STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS                                = 0xC01A0020
STATUS_LOG_ARCHIVE_IN_PROGRESS                                    = 0xC01A0021
STATUS_LOG_EPHEMERAL                                              = 0xC01A0022
STATUS_LOG_NOT_ENOUGH_CONTAINERS                                  = 0xC01A0023
STATUS_LOG_CLIENT_ALREADY_REGISTERED                              = 0xC01A0024
STATUS_LOG_CLIENT_NOT_REGISTERED                                  = 0xC01A0025
STATUS_LOG_FULL_HANDLER_IN_PROGRESS                               = 0xC01A0026
STATUS_LOG_CONTAINER_READ_FAILED                                  = 0xC01A0027
STATUS_LOG_CONTAINER_WRITE_FAILED                                 = 0xC01A0028
STATUS_LOG_CONTAINER_OPEN_FAILED                                  = 0xC01A0029
STATUS_LOG_CONTAINER_STATE_INVALID                                = 0xC01A002A
STATUS_LOG_STATE_INVALID                                          = 0xC01A002B
STATUS_LOG_PINNED                                                 = 0xC01A002C
STATUS_LOG_METADATA_FLUSH_FAILED                                  = 0xC01A002D
STATUS_LOG_INCONSISTENT_SECURITY                                  = 0xC01A002E
STATUS_LOG_APPENDED_FLUSH_FAILED                                  = 0xC01A002F
STATUS_LOG_PINNED_RESERVATION                                     = 0xC01A0030
STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD                           = 0xC01B00EA
STATUS_FLT_NO_HANDLER_DEFINED                                     = 0xC01C0001
STATUS_FLT_CONTEXT_ALREADY_DEFINED                                = 0xC01C0002
STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST                           = 0xC01C0003
STATUS_FLT_DISALLOW_FAST_IO                                       = 0xC01C0004
STATUS_FLT_INVALID_NAME_REQUEST                                   = 0xC01C0005
STATUS_FLT_NOT_SAFE_TO_POST_OPERATION                             = 0xC01C0006
STATUS_FLT_NOT_INITIALIZED                                        = 0xC01C0007
STATUS_FLT_FILTER_NOT_READY                                       = 0xC01C0008
STATUS_FLT_POST_OPERATION_CLEANUP                                 = 0xC01C0009
STATUS_FLT_INTERNAL_ERROR                                         = 0xC01C000A
STATUS_FLT_DELETING_OBJECT                                        = 0xC01C000B
STATUS_FLT_MUST_BE_NONPAGED_POOL                                  = 0xC01C000C
STATUS_FLT_DUPLICATE_ENTRY                                        = 0xC01C000D
STATUS_FLT_CBDQ_DISABLED                                          = 0xC01C000E
STATUS_FLT_DO_NOT_ATTACH                                          = 0xC01C000F
STATUS_FLT_DO_NOT_DETACH                                          = 0xC01C0010
STATUS_FLT_INSTANCE_ALTITUDE_COLLISION                            = 0xC01C0011
STATUS_FLT_INSTANCE_NAME_COLLISION                                = 0xC01C0012
STATUS_FLT_FILTER_NOT_FOUND                                       = 0xC01C0013
STATUS_FLT_VOLUME_NOT_FOUND                                       = 0xC01C0014
STATUS_FLT_INSTANCE_NOT_FOUND                                     = 0xC01C0015
STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND                           = 0xC01C0016
STATUS_FLT_INVALID_CONTEXT_REGISTRATION                           = 0xC01C0017
STATUS_FLT_NAME_CACHE_MISS                                        = 0xC01C0018
STATUS_FLT_NO_DEVICE_OBJECT                                       = 0xC01C0019
STATUS_FLT_VOLUME_ALREADY_MOUNTED                                 = 0xC01C001A
STATUS_FLT_ALREADY_ENLISTED                                       = 0xC01C001B
STATUS_FLT_CONTEXT_ALREADY_LINKED                                 = 0xC01C001C
STATUS_FLT_NO_WAITER_FOR_REPLY                                    = 0xC01C0020
STATUS_MONITOR_NO_DESCRIPTOR                                      = 0xC01D0001
STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT                          = 0xC01D0002
STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM                        = 0xC01D0003
STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK                      = 0xC01D0004
STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED                  = 0xC01D0005
STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK                 = 0xC01D0006
STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK                 = 0xC01D0007
STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA                            = 0xC01D0008
STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK                      = 0xC01D0009
STATUS_MONITOR_INVALID_MANUFACTURE_DATE                           = 0xC01D000A
STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER                          = 0xC01E0000
STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER                           = 0xC01E0001
STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER                           = 0xC01E0002
STATUS_GRAPHICS_ADAPTER_WAS_RESET                                 = 0xC01E0003
STATUS_GRAPHICS_INVALID_DRIVER_MODEL                              = 0xC01E0004
STATUS_GRAPHICS_PRESENT_MODE_CHANGED                              = 0xC01E0005
STATUS_GRAPHICS_PRESENT_OCCLUDED                                  = 0xC01E0006
STATUS_GRAPHICS_PRESENT_DENIED                                    = 0xC01E0007
STATUS_GRAPHICS_CANNOTCOLORCONVERT                                = 0xC01E0008
STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED                      = 0xC01E000B
STATUS_GRAPHICS_PRESENT_UNOCCLUDED                                = 0xC01E000C
STATUS_GRAPHICS_NO_VIDEO_MEMORY                                   = 0xC01E0100
STATUS_GRAPHICS_CANT_LOCK_MEMORY                                  = 0xC01E0101
STATUS_GRAPHICS_ALLOCATION_BUSY                                   = 0xC01E0102
STATUS_GRAPHICS_TOO_MANY_REFERENCES                               = 0xC01E0103
STATUS_GRAPHICS_TRY_AGAIN_LATER                                   = 0xC01E0104
STATUS_GRAPHICS_TRY_AGAIN_NOW                                     = 0xC01E0105
STATUS_GRAPHICS_ALLOCATION_INVALID                                = 0xC01E0106
STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE                  = 0xC01E0107
STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED                  = 0xC01E0108
STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION                      = 0xC01E0109
STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE                          = 0xC01E0110
STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION                     = 0xC01E0111
STATUS_GRAPHICS_ALLOCATION_CLOSED                                 = 0xC01E0112
STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE                       = 0xC01E0113
STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE                         = 0xC01E0114
STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE                           = 0xC01E0115
STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST                           = 0xC01E0116
STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE                           = 0xC01E0200
STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY                            = 0xC01E0300
STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED                      = 0xC01E0301
STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED            = 0xC01E0302
STATUS_GRAPHICS_INVALID_VIDPN                                     = 0xC01E0303
STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE                      = 0xC01E0304
STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET                      = 0xC01E0305
STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED                      = 0xC01E0306
STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET                       = 0xC01E0308
STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET                       = 0xC01E0309
STATUS_GRAPHICS_INVALID_FREQUENCY                                 = 0xC01E030A
STATUS_GRAPHICS_INVALID_ACTIVE_REGION                             = 0xC01E030B
STATUS_GRAPHICS_INVALID_TOTAL_REGION                              = 0xC01E030C
STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE                 = 0xC01E0310
STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE                 = 0xC01E0311
STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET                    = 0xC01E0312
STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY                          = 0xC01E0313
STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET                           = 0xC01E0314
STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET                     = 0xC01E0315
STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET                     = 0xC01E0316
STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET                             = 0xC01E0317
STATUS_GRAPHICS_TARGET_ALREADY_IN_SET                             = 0xC01E0318
STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH                        = 0xC01E0319
STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY                     = 0xC01E031A
STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET                 = 0xC01E031B
STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE                    = 0xC01E031C
STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET                         = 0xC01E031D
STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET                     = 0xC01E031F
STATUS_GRAPHICS_STALE_MODESET                                     = 0xC01E0320
STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET                     = 0xC01E0321
STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE                       = 0xC01E0322
STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN                   = 0xC01E0323
STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE                            = 0xC01E0324
STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION   = 0xC01E0325
STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES           = 0xC01E0326
STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY                              = 0xC01E0327
STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE             = 0xC01E0328
STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET             = 0xC01E0329
STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET                      = 0xC01E032A
STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR                         = 0xC01E032B
STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET                      = 0xC01E032C
STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET                  = 0xC01E032D
STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE               = 0xC01E032E
STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE                  = 0xC01E032F
STATUS_GRAPHICS_RESOURCES_NOT_RELATED                             = 0xC01E0330
STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE                          = 0xC01E0331
STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE                          = 0xC01E0332
STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET                         = 0xC01E0333
STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER      = 0xC01E0334
STATUS_GRAPHICS_NO_VIDPNMGR                                       = 0xC01E0335
STATUS_GRAPHICS_NO_ACTIVE_VIDPN                                   = 0xC01E0336
STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY                              = 0xC01E0337
STATUS_GRAPHICS_MONITOR_NOT_CONNECTED                             = 0xC01E0338
STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY                            = 0xC01E0339
STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE                       = 0xC01E033A
STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE                        = 0xC01E033B
STATUS_GRAPHICS_INVALID_STRIDE                                    = 0xC01E033C
STATUS_GRAPHICS_INVALID_PIXELFORMAT                               = 0xC01E033D
STATUS_GRAPHICS_INVALID_COLORBASIS                                = 0xC01E033E
STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE                      = 0xC01E033F
STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY                            = 0xC01E0340
STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT                = 0xC01E0341
STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE                               = 0xC01E0342
STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN                          = 0xC01E0343
STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL                   = 0xC01E0344
STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION      = 0xC01E0345
STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED = 0xC01E0346
STATUS_GRAPHICS_INVALID_GAMMA_RAMP                                = 0xC01E0347
STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED                          = 0xC01E0348
STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED                       = 0xC01E0349
STATUS_GRAPHICS_MODE_NOT_IN_MODESET                               = 0xC01E034A
STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON      = 0xC01E034D
STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE                         = 0xC01E034E
STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE                       = 0xC01E034F
STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS                 = 0xC01E0350
STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING                         = 0xC01E0352
STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED                      = 0xC01E0353
STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS                  = 0xC01E0354
STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT                       = 0xC01E0355
STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM                    = 0xC01E0356
STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN                 = 0xC01E0357
STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT         = 0xC01E0358
STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED                             = 0xC01E0359
STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION                = 0xC01E035A
STATUS_GRAPHICS_INVALID_CLIENT_TYPE                               = 0xC01E035B
STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET                               = 0xC01E035C
STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED                 = 0xC01E0400
STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED                    = 0xC01E0401
STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER                              = 0xC01E0430
STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED                           = 0xC01E0431
STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED                         = 0xC01E0432
STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY                           = 0xC01E0433
STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED                            = 0xC01E0434
STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON                         = 0xC01E0435
STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE                    = 0xC01E0436
STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER                            = 0xC01E0438
STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED                       = 0xC01E043B
STATUS_GRAPHICS_OPM_NOT_SUPPORTED                                 = 0xC01E0500
STATUS_GRAPHICS_COPP_NOT_SUPPORTED                                = 0xC01E0501
STATUS_GRAPHICS_UAB_NOT_SUPPORTED                                 = 0xC01E0502
STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS                  = 0xC01E0503
STATUS_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL                     = 0xC01E0504
STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST                    = 0xC01E0505
STATUS_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME         = 0xC01E0506
STATUS_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP        = 0xC01E0507
STATUS_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED               = 0xC01E0508
STATUS_GRAPHICS_OPM_INVALID_POINTER                               = 0xC01E050A
STATUS_GRAPHICS_OPM_INTERNAL_ERROR                                = 0xC01E050B
STATUS_GRAPHICS_OPM_INVALID_HANDLE                                = 0xC01E050C
STATUS_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE      = 0xC01E050D
STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH                    = 0xC01E050E
STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED                         = 0xC01E050F
STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED                          = 0xC01E0510
STATUS_GRAPHICS_PVP_HFS_FAILED                                    = 0xC01E0511
STATUS_GRAPHICS_OPM_INVALID_SRM                                   = 0xC01E0512
STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP                  = 0xC01E0513
STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP                   = 0xC01E0514
STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA                 = 0xC01E0515
STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET                            = 0xC01E0516
STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH                           = 0xC01E0517
STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE              = 0xC01E0518
STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS             = 0xC01E051A
STATUS_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS               = 0xC01E051B
STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS = 0xC01E051C
STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST                   = 0xC01E051D
STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR                         = 0xC01E051E
STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS  = 0xC01E051F
STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED                       = 0xC01E0520
STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST                 = 0xC01E0521
STATUS_GRAPHICS_I2C_NOT_SUPPORTED                                 = 0xC01E0580
STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST                         = 0xC01E0581
STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA                       = 0xC01E0582
STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA                          = 0xC01E0583
STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED                           = 0xC01E0584
STATUS_GRAPHICS_DDCCI_INVALID_DATA                                = 0xC01E0585
STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE = 0xC01E0586
STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING                 = 0xC01E0587
STATUS_GRAPHICS_MCA_INTERNAL_ERROR                                = 0xC01E0588
STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND                     = 0xC01E0589
STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH                      = 0xC01E058A
STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM                    = 0xC01E058B
STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE                   = 0xC01E058C
STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS                          = 0xC01E058D
STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED                    = 0xC01E05E0
STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME             = 0xC01E05E1
STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP            = 0xC01E05E2
STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED                   = 0xC01E05E3
STATUS_GRAPHICS_INVALID_POINTER                                   = 0xC01E05E4
STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE          = 0xC01E05E5
STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL                         = 0xC01E05E6
STATUS_GRAPHICS_INTERNAL_ERROR                                    = 0xC01E05E7
STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS                   = 0xC01E05E8
STATUS_FVE_LOCKED_VOLUME                                          = 0xC0210000
STATUS_FVE_NOT_ENCRYPTED                                          = 0xC0210001
STATUS_FVE_BAD_INFORMATION                                        = 0xC0210002
STATUS_FVE_TOO_SMALL                                              = 0xC0210003
STATUS_FVE_FAILED_WRONG_FS                                        = 0xC0210004
STATUS_FVE_FAILED_BAD_FS                                          = 0xC0210005
STATUS_FVE_FS_NOT_EXTENDED                                        = 0xC0210006
STATUS_FVE_FS_MOUNTED                                             = 0xC0210007
STATUS_FVE_NO_LICENSE                                             = 0xC0210008
STATUS_FVE_ACTION_NOT_ALLOWED                                     = 0xC0210009
STATUS_FVE_BAD_DATA                                               = 0xC021000A
STATUS_FVE_VOLUME_NOT_BOUND                                       = 0xC021000B
STATUS_FVE_NOT_DATA_VOLUME                                        = 0xC021000C
STATUS_FVE_CONV_READ_ERROR                                        = 0xC021000D
STATUS_FVE_CONV_WRITE_ERROR                                       = 0xC021000E
STATUS_FVE_OVERLAPPED_UPDATE                                      = 0xC021000F
STATUS_FVE_FAILED_SECTOR_SIZE                                     = 0xC0210010
STATUS_FVE_FAILED_AUTHENTICATION                                  = 0xC0210011
STATUS_FVE_NOT_OS_VOLUME                                          = 0xC0210012
STATUS_FVE_KEYFILE_NOT_FOUND                                      = 0xC0210013
STATUS_FVE_KEYFILE_INVALID                                        = 0xC0210014
STATUS_FVE_KEYFILE_NO_VMK                                         = 0xC0210015
STATUS_FVE_TPM_DISABLED                                           = 0xC0210016
STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO                                  = 0xC0210017
STATUS_FVE_TPM_INVALID_PCR                                        = 0xC0210018
STATUS_FVE_TPM_NO_VMK                                             = 0xC0210019
STATUS_FVE_PIN_INVALID                                            = 0xC021001A
STATUS_FVE_AUTH_INVALID_APPLICATION                               = 0xC021001B
STATUS_FVE_AUTH_INVALID_CONFIG                                    = 0xC021001C
STATUS_FVE_DEBUGGER_ENABLED                                       = 0xC021001D
STATUS_FVE_DRY_RUN_FAILED                                         = 0xC021001E
STATUS_FVE_BAD_METADATA_POINTER                                   = 0xC021001F
STATUS_FVE_OLD_METADATA_COPY                                      = 0xC0210020
STATUS_FVE_REBOOT_REQUIRED                                        = 0xC0210021
STATUS_FVE_RAW_ACCESS                                             = 0xC0210022
STATUS_FVE_RAW_BLOCKED                                            = 0xC0210023
STATUS_FVE_NO_FEATURE_LICENSE                                     = 0xC0210026
STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED                    = 0xC0210027
STATUS_FVE_CONV_RECOVERY_FAILED                                   = 0xC0210028
STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG                              = 0xC0210029
STATUS_FVE_VOLUME_TOO_SMALL                                       = 0xC0210030
STATUS_FWP_CALLOUT_NOT_FOUND                                      = 0xC0220001
STATUS_FWP_CONDITION_NOT_FOUND                                    = 0xC0220002
STATUS_FWP_FILTER_NOT_FOUND                                       = 0xC0220003
STATUS_FWP_LAYER_NOT_FOUND                                        = 0xC0220004
STATUS_FWP_PROVIDER_NOT_FOUND                                     = 0xC0220005
STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND                             = 0xC0220006
STATUS_FWP_SUBLAYER_NOT_FOUND                                     = 0xC0220007
STATUS_FWP_NOT_FOUND                                              = 0xC0220008
STATUS_FWP_ALREADY_EXISTS                                         = 0xC0220009
STATUS_FWP_IN_USE                                                 = 0xC022000A
STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS                            = 0xC022000B
STATUS_FWP_WRONG_SESSION                                          = 0xC022000C
STATUS_FWP_NO_TXN_IN_PROGRESS                                     = 0xC022000D
STATUS_FWP_TXN_IN_PROGRESS                                        = 0xC022000E
STATUS_FWP_TXN_ABORTED                                            = 0xC022000F
STATUS_FWP_SESSION_ABORTED                                        = 0xC0220010
STATUS_FWP_INCOMPATIBLE_TXN                                       = 0xC0220011
STATUS_FWP_TIMEOUT                                                = 0xC0220012
STATUS_FWP_NET_EVENTS_DISABLED                                    = 0xC0220013
STATUS_FWP_INCOMPATIBLE_LAYER                                     = 0xC0220014
STATUS_FWP_KM_CLIENTS_ONLY                                        = 0xC0220015
STATUS_FWP_LIFETIME_MISMATCH                                      = 0xC0220016
STATUS_FWP_BUILTIN_OBJECT                                         = 0xC0220017
STATUS_FWP_TOO_MANY_BOOTTIME_FILTERS                              = 0xC0220018
STATUS_FWP_TOO_MANY_CALLOUTS                                      = 0xC0220018
STATUS_FWP_NOTIFICATION_DROPPED                                   = 0xC0220019
STATUS_FWP_TRAFFIC_MISMATCH                                       = 0xC022001A
STATUS_FWP_INCOMPATIBLE_SA_STATE                                  = 0xC022001B
STATUS_FWP_NULL_POINTER                                           = 0xC022001C
STATUS_FWP_INVALID_ENUMERATOR                                     = 0xC022001D
STATUS_FWP_INVALID_FLAGS                                          = 0xC022001E
STATUS_FWP_INVALID_NET_MASK                                       = 0xC022001F
STATUS_FWP_INVALID_RANGE                                          = 0xC0220020
STATUS_FWP_INVALID_INTERVAL                                       = 0xC0220021
STATUS_FWP_ZERO_LENGTH_ARRAY                                      = 0xC0220022
STATUS_FWP_NULL_DISPLAY_NAME                                      = 0xC0220023
STATUS_FWP_INVALID_ACTION_TYPE                                    = 0xC0220024
STATUS_FWP_INVALID_WEIGHT                                         = 0xC0220025
STATUS_FWP_MATCH_TYPE_MISMATCH                                    = 0xC0220026
STATUS_FWP_TYPE_MISMATCH                                          = 0xC0220027
STATUS_FWP_OUT_OF_BOUNDS                                          = 0xC0220028
STATUS_FWP_RESERVED                                               = 0xC0220029
STATUS_FWP_DUPLICATE_CONDITION                                    = 0xC022002A
STATUS_FWP_DUPLICATE_KEYMOD                                       = 0xC022002B
STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER                         = 0xC022002C
STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER                      = 0xC022002D
STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER                        = 0xC022002E
STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT                      = 0xC022002F
STATUS_FWP_INCOMPATIBLE_AUTH_METHOD                               = 0xC0220030
STATUS_FWP_INCOMPATIBLE_DH_GROUP                                  = 0xC0220031
STATUS_FWP_EM_NOT_SUPPORTED                                       = 0xC0220032
STATUS_FWP_NEVER_MATCH                                            = 0xC0220033
STATUS_FWP_PROVIDER_CONTEXT_MISMATCH                              = 0xC0220034
STATUS_FWP_INVALID_PARAMETER                                      = 0xC0220035
STATUS_FWP_TOO_MANY_SUBLAYERS                                     = 0xC0220036
STATUS_FWP_CALLOUT_NOTIFICATION_FAILED                            = 0xC0220037
STATUS_FWP_INCOMPATIBLE_AUTH_CONFIG                               = 0xC0220038
STATUS_FWP_INCOMPATIBLE_CIPHER_CONFIG                             = 0xC0220039
STATUS_FWP_DUPLICATE_AUTH_METHOD                                  = 0xC022003C
STATUS_FWP_TCPIP_NOT_READY                                        = 0xC0220100
STATUS_FWP_INJECT_HANDLE_CLOSING                                  = 0xC0220101
STATUS_FWP_INJECT_HANDLE_STALE                                    = 0xC0220102
STATUS_FWP_CANNOT_PEND                                            = 0xC0220103
STATUS_NDIS_CLOSING                                               = 0xC0230002
STATUS_NDIS_BAD_VERSION                                           = 0xC0230004
STATUS_NDIS_BAD_CHARACTERISTICS                                   = 0xC0230005
STATUS_NDIS_ADAPTER_NOT_FOUND                                     = 0xC0230006
STATUS_NDIS_OPEN_FAILED                                           = 0xC0230007
STATUS_NDIS_DEVICE_FAILED                                         = 0xC0230008
STATUS_NDIS_MULTICAST_FULL                                        = 0xC0230009
STATUS_NDIS_MULTICAST_EXISTS                                      = 0xC023000A
STATUS_NDIS_MULTICAST_NOT_FOUND                                   = 0xC023000B
STATUS_NDIS_REQUEST_ABORTED                                       = 0xC023000C
STATUS_NDIS_RESET_IN_PROGRESS                                     = 0xC023000D
STATUS_NDIS_INVALID_PACKET                                        = 0xC023000F
STATUS_NDIS_INVALID_DEVICE_REQUEST                                = 0xC0230010
STATUS_NDIS_ADAPTER_NOT_READY                                     = 0xC0230011
STATUS_NDIS_INVALID_LENGTH                                        = 0xC0230014
STATUS_NDIS_INVALID_DATA                                          = 0xC0230015
STATUS_NDIS_BUFFER_TOO_SHORT                                      = 0xC0230016
STATUS_NDIS_INVALID_OID                                           = 0xC0230017
STATUS_NDIS_ADAPTER_REMOVED                                       = 0xC0230018
STATUS_NDIS_UNSUPPORTED_MEDIA                                     = 0xC0230019
STATUS_NDIS_GROUP_ADDRESS_IN_USE                                  = 0xC023001A
STATUS_NDIS_FILE_NOT_FOUND                                        = 0xC023001B
STATUS_NDIS_ERROR_READING_FILE                                    = 0xC023001C
STATUS_NDIS_ALREADY_MAPPED                                        = 0xC023001D
STATUS_NDIS_RESOURCE_CONFLICT                                     = 0xC023001E
STATUS_NDIS_MEDIA_DISCONNECTED                                    = 0xC023001F
STATUS_NDIS_INVALID_ADDRESS                                       = 0xC0230022
STATUS_NDIS_PAUSED                                                = 0xC023002A
STATUS_NDIS_INTERFACE_NOT_FOUND                                   = 0xC023002B
STATUS_NDIS_UNSUPPORTED_REVISION                                  = 0xC023002C
STATUS_NDIS_INVALID_PORT                                          = 0xC023002D
STATUS_NDIS_INVALID_PORT_STATE                                    = 0xC023002E
STATUS_NDIS_LOW_POWER_STATE                                       = 0xC023002F
STATUS_NDIS_NOT_SUPPORTED                                         = 0xC02300BB
STATUS_NDIS_OFFLOAD_POLICY                                        = 0xC023100F
STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED                           = 0xC0231012
STATUS_NDIS_OFFLOAD_PATH_REJECTED                                 = 0xC0231013
STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED                             = 0xC0232000
STATUS_NDIS_DOT11_MEDIA_IN_USE                                    = 0xC0232001
STATUS_NDIS_DOT11_POWER_STATE_INVALID                             = 0xC0232002
STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL                              = 0xC0232003
STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL                         = 0xC0232004
STATUS_IPSEC_BAD_SPI                                              = 0xC0360001
STATUS_IPSEC_SA_LIFETIME_EXPIRED                                  = 0xC0360002
STATUS_IPSEC_WRONG_SA                                             = 0xC0360003
STATUS_IPSEC_REPLAY_CHECK_FAILED                                  = 0xC0360004
STATUS_IPSEC_INVALID_PACKET                                       = 0xC0360005
STATUS_IPSEC_INTEGRITY_CHECK_FAILED                               = 0xC0360006
STATUS_IPSEC_CLEAR_TEXT_DROP                                      = 0xC0360007
STATUS_IPSEC_AUTH_FIREWALL_DROP                                   = 0xC0360008
STATUS_IPSEC_THROTTLE_DROP                                        = 0xC0360009
STATUS_IPSEC_DOSP_BLOCK                                           = 0xC0368000
STATUS_IPSEC_DOSP_RECEIVED_MULTICAST                              = 0xC0368001
STATUS_IPSEC_DOSP_INVALID_PACKET                                  = 0xC0368002
STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED                             = 0xC0368003
STATUS_IPSEC_DOSP_MAX_ENTRIES                                     = 0xC0368004
STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED                              = 0xC0368005
STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES                     = 0xC0368006
STATUS_VOLMGR_MIRROR_NOT_SUPPORTED                                = 0xC038005B
STATUS_VOLMGR_RAID5_NOT_SUPPORTED                                 = 0xC038005C
STATUS_VIRTDISK_PROVIDER_NOT_FOUND                                = 0xC03A0014
STATUS_VIRTDISK_NOT_VIRTUAL_DISK                                  = 0xC03A0015
STATUS_VHD_PARENT_VHD_ACCESS_DENIED                               = 0xC03A0016
STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH                             = 0xC03A0017
STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED                      = 0xC03A0018
STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT                     = 0xC03A0019
