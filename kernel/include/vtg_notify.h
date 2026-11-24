#ifndef VTG_NOTIFY_H
#define VTG_NOTIFY_H

#include <ntifs.h>

NTSTATUS VtgNotifyInit(VOID);
VOID VtgNotifyUninit(VOID);

#endif /* VTG_NOTIFY_H */
