
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#include "Types.h"
#include "Ticket.h"
#include "Block.h"
#include "Winioctl.h"
#include "Disk.h"
#include "Net.h"
#include "QPACKET.h"
#include "TLS13.h"
#include "Http.h"
#include "QUIC.h"
#include "QMSG.h"
#include "State.h"

STATE_SERVICE* StateServicePtr;
auto&& StateService() { return *StateServicePtr; }

void StateServiceMain()
{
	StateServicePtr = &StackAlloc<STATE_SERVICE, GLOBAL_STACK>();
	StateService().init();

	StateService().scheduler.runTask([](PVOID context, NTSTATUS status, STASK_ARGV argv)
	{
			StateService().findVolumes();
	}, StateServicePtr);
}
