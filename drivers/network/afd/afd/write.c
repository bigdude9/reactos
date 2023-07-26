/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/write.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"

static IO_COMPLETION_ROUTINE SendComplete;
static NTSTATUS NTAPI SendComplete
( PDEVICE_OBJECT DeviceObject,
  PIRP Irp,
  PVOID Context ) {

    AFD_DbgPrint(1,("(PID %lx) SendComplete: called.\n", PsGetCurrentProcessId()));

    NTSTATUS Status = Irp->IoStatus.Status;
    PAFD_FCB FCB = (PAFD_FCB)Context;
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp = NULL;
    PIO_STACK_LOCATION NextIrpSp;
    PAFD_SEND_INFO SendReq = NULL;
    PAFD_MAPBUF Map;
    SIZE_T TotalBytesCopied = 0, TotalBytesProcessed = 0, SpaceAvail, i;
    UINT SendLength, BytesCopied;
    BOOLEAN HaltSendQueue;

    UNREFERENCED_PARAMETER(DeviceObject);

    /*
     * The Irp parameter passed in is the IRP of the stream between AFD and
     * TDI driver. It's not very useful to us. We need the IRPs of the stream
     * between usermode and AFD. Those are chained from
     * FCB->PendingIrpList[FUNCTION_SEND] and you'll see them in the code
     * below as "NextIrp" ('cause they are the next usermode IRP to be
     * processed).
     */

    AFD_DbgPrint(1,("(PID %lx) Called, status %x, %u bytes used\n", PsGetCurrentProcessId(),
                            Irp->IoStatus.Status,
                            Irp->IoStatus.Information));

    AFD_DbgPrint(1,("(PID %lx) SendComplete: Starting, status %x, %u bytes used\n", PsGetCurrentProcessId(),
                            Irp->IoStatus.Status,
                            Irp->IoStatus.Information));

    if( !SocketAcquireStateLock( FCB ) ) {
    	AFD_DbgPrint(1,("(PID %lx) SendComplete: failed to lock FCB, returning STATUS_FILE_CLOSED.\n", PsGetCurrentProcessId()));
        return STATUS_FILE_CLOSED;
    }

    ASSERT(FCB->SendIrp.InFlightRequest == Irp);
    FCB->SendIrp.InFlightRequest = NULL;
    /* Request is not in flight any longer */

    if( FCB->State == SOCKET_STATE_CLOSED ) {
        /* Cleanup our IRP queue because the FCB is being destroyed */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_SEND] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
            SendReq = GetLockedData(NextIrp, NextIrpSp);
            NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
            NextIrp->IoStatus.Information = 0;
    	    AFD_DbgPrint(1,("(PID %lx) SendComplete: Calling UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
            UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
            if( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            (void)IoSetCancelRoutine(NextIrp, NULL);
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }

        RetryDisconnectCompletion(FCB);

        SocketStateUnlock( FCB );
    	AFD_DbgPrint(1,("(PID %lx) SendComplete: detected FCB destruction/Socket close, returning STATUS_FILE_CLOSED.\n", PsGetCurrentProcessId()));
        return STATUS_FILE_CLOSED;
    }

    if( !NT_SUCCESS(Status) ) {
        /* Complete all following send IRPs with error */

        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_SEND] ) ) {
            NextIrpEntry =
                RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
            NextIrp =
                CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
            SendReq = GetLockedData(NextIrp, NextIrpSp);

    	    AFD_DbgPrint(1,("(PID %lx) SendComplete: Calling UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
            UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE );

            NextIrp->IoStatus.Status = Status;
            NextIrp->IoStatus.Information = 0;

            if ( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            (void)IoSetCancelRoutine(NextIrp, NULL);
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }

        RetryDisconnectCompletion(FCB);

        SocketStateUnlock( FCB );
    	AFD_DbgPrint(1,("(PID %lx) SendComplete: completed returning STATUS_SUCCESS.\n", PsGetCurrentProcessId()));
        return STATUS_SUCCESS;
    }

    RtlMoveMemory( FCB->Send.Window,
                   FCB->Send.Window + Irp->IoStatus.Information,
                   FCB->Send.BytesUsed - Irp->IoStatus.Information );

    TotalBytesProcessed = 0;
    SendLength = Irp->IoStatus.Information;
    HaltSendQueue = FALSE;
    while (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]) && SendLength > 0) {
        NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
        NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
        NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
        SendReq = GetLockedData(NextIrp, NextIrpSp);
        Map = (PAFD_MAPBUF)(SendReq->BufferArray + SendReq->BufferCount);

        TotalBytesCopied = (ULONG_PTR)NextIrp->Tail.Overlay.DriverContext[3];
        ASSERT(TotalBytesCopied != 0);

        /* If we didn't get enough, keep waiting */
        if (TotalBytesCopied > SendLength)
        {
            /* Update the bytes left to copy */
            TotalBytesCopied -= SendLength;
            NextIrp->Tail.Overlay.DriverContext[3] = (PVOID)TotalBytesCopied;

            /* Update the state variables */
            FCB->Send.BytesUsed -= SendLength;
            TotalBytesProcessed += SendLength;
            SendLength = 0;

            /* Pend the IRP */
            InsertHeadList(&FCB->PendingIrpList[FUNCTION_SEND],
                           &NextIrp->Tail.Overlay.ListEntry);
            HaltSendQueue = TRUE;
            break;
        }

        ASSERT(NextIrp->IoStatus.Information != 0);

        NextIrp->IoStatus.Status = Irp->IoStatus.Status;

        FCB->Send.BytesUsed -= TotalBytesCopied;
        TotalBytesProcessed += TotalBytesCopied;
        SendLength -= TotalBytesCopied;

        (void)IoSetCancelRoutine(NextIrp, NULL);

    	AFD_DbgPrint(1,("(PID %lx) SendComplete: Calling UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
        UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE );

        if (NextIrp->MdlAddress) UnlockRequest(NextIrp, NextIrpSp);

        IoCompleteRequest(NextIrp, IO_NETWORK_INCREMENT);
    }

    ASSERT(SendLength == 0);

   if ( !HaltSendQueue && !IsListEmpty( &FCB->PendingIrpList[FUNCTION_SEND] ) ) {
        NextIrpEntry = FCB->PendingIrpList[FUNCTION_SEND].Flink;
        NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
        NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
        SendReq = GetLockedData(NextIrp, NextIrpSp);
        Map = (PAFD_MAPBUF)(SendReq->BufferArray + SendReq->BufferCount);

        AFD_DbgPrint(1,("(PID %lx) SendComplete: SendReq @ %p\n", PsGetCurrentProcessId(), SendReq));

        SpaceAvail = FCB->Send.Size - FCB->Send.BytesUsed;
        TotalBytesCopied = 0;

        /* Count the total transfer size */
        SendLength = 0;
        for (i = 0; i < SendReq->BufferCount; i++)
        {
            SendLength += SendReq->BufferArray[i].len;
        }

        /* Make sure we've got the space */
        if (SendLength > SpaceAvail)
        {
           /* Blocking sockets have to wait here */
           if (SendLength <= FCB->Send.Size && !((SendReq->AfdFlags & AFD_IMMEDIATE) || (FCB->NonBlocking)))
           {
               FCB->PollState &= ~AFD_EVENT_SEND;

               NextIrp = NULL;
           }

           /* Check if we can send anything */
           if (SpaceAvail == 0)
           {
               FCB->PollState &= ~AFD_EVENT_SEND;

               /* We should never be non-overlapped and get to this point */
               ASSERT(SendReq->AfdFlags & AFD_OVERLAPPED);

               NextIrp = NULL;
           }
        }

        if (NextIrp != NULL)
        {
            for( i = 0; i < SendReq->BufferCount; i++ ) {
                BytesCopied = MIN(SendReq->BufferArray[i].len, SpaceAvail);

                Map[i].BufferAddress =
                   MmMapLockedPages( Map[i].Mdl, KernelMode );

                RtlCopyMemory( FCB->Send.Window + FCB->Send.BytesUsed,
                               Map[i].BufferAddress,
                               BytesCopied );

                MmUnmapLockedPages( Map[i].BufferAddress, Map[i].Mdl );

                TotalBytesCopied += BytesCopied;
                SpaceAvail -= BytesCopied;
                FCB->Send.BytesUsed += BytesCopied;
            }

            NextIrp->IoStatus.Information = TotalBytesCopied;
            NextIrp->Tail.Overlay.DriverContext[3] = (PVOID)NextIrp->IoStatus.Information;
        }
    }

    if (FCB->Send.Size - FCB->Send.BytesUsed != 0 && !FCB->SendClosed &&
        IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]))
    {
        FCB->PollState |= AFD_EVENT_SEND;
        FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    }
    else
    {
        FCB->PollState &= ~AFD_EVENT_SEND;
    }


    /* Some data is still waiting */
    if( FCB->Send.BytesUsed )
    {
    	AFD_DbgPrint(1,("(PID %lx) SendComplete: data found waiting, calling TdiSend().\n", PsGetCurrentProcessId()));
        Status = TdiSend( &FCB->SendIrp.InFlightRequest, FCB->Connection.Object, 0, FCB->Send.Window, FCB->Send.BytesUsed,
                          SendComplete, FCB );
    }
    else
    {
        /* Nothing is waiting so try to complete a pending disconnect */
        RetryDisconnectCompletion(FCB);
    }

    SocketStateUnlock( FCB );

    AFD_DbgPrint(1,("(PID %lx) SendComplete: completed returning STATUS_SUCCESS.\n", PsGetCurrentProcessId()));
    return STATUS_SUCCESS;
}

static IO_COMPLETION_ROUTINE PacketSocketSendComplete;
static NTSTATUS NTAPI PacketSocketSendComplete
( PDEVICE_OBJECT DeviceObject,
  PIRP Irp,
  PVOID Context ) {

    AFD_DbgPrint(1,("(PID %lx) PacketSocketSendComplete: called.\n", PsGetCurrentProcessId()));

    PAFD_FCB FCB = (PAFD_FCB)Context;
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp;
    PAFD_SEND_INFO SendReq;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(1,("(PID %lx) Called, status %x, %u bytes used\n", PsGetCurrentProcessId(),
                            Irp->IoStatus.Status,
                            Irp->IoStatus.Information));

    AFD_DbgPrint(1,("(PID %lx) PacketSendComplete: Starting, status %x, %u bytes used.\n", PsGetCurrentProcessId(), Irp->IoStatus.Status, Irp->IoStatus.Information));


    if( !SocketAcquireStateLock( FCB ) ) {
    	AFD_DbgPrint(1,("(PID %lx) PacketSendComplete: could not lock FCB, returning STATUS_FILE_CLOSED.\n", PsGetCurrentProcessId()));
        return STATUS_FILE_CLOSED;
    }

    ASSERT(FCB->SendIrp.InFlightRequest == Irp);
    FCB->SendIrp.InFlightRequest = NULL;
    /* Request is not in flight any longer */

    if( FCB->State == SOCKET_STATE_CLOSED ) {
        /* Cleanup our IRP queue because the FCB is being destroyed */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_SEND] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            SendReq = GetLockedData(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));
            NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
            NextIrp->IoStatus.Information = 0;
            (void)IoSetCancelRoutine(NextIrp, NULL);
    	    AFD_DbgPrint(1,("(PID %lx) PacketSendComplete: Calling UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
            UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
            UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }
        SocketStateUnlock( FCB );
    	AFD_DbgPrint(1,("(PID %lx) PacketSendComplete: detected FCB destruction/Socket Close, returning STATUS_FILE_CLOSED.\n", PsGetCurrentProcessId()));
        return STATUS_FILE_CLOSED;
    }

    ASSERT(!IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]));

    /* TDI spec guarantees FIFO ordering on IRPs */
    NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
    NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);

    SendReq = GetLockedData(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));

    NextIrp->IoStatus.Status = Irp->IoStatus.Status;
    NextIrp->IoStatus.Information = Irp->IoStatus.Information;

    (void)IoSetCancelRoutine(NextIrp, NULL);

    AFD_DbgPrint(1,("(PID %lx) PacketSendComplete: Calling UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
    UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);

    UnlockRequest(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));

    IoCompleteRequest(NextIrp, IO_NETWORK_INCREMENT);

    FCB->PollState |= AFD_EVENT_SEND;
    FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
    PollReeval(FCB->DeviceExt, FCB->FileObject);

    SocketStateUnlock(FCB);

    AFD_DbgPrint(1,("(PID %lx) PacketSendComplete: completed, returning STATUS_SUCCESS.\n", PsGetCurrentProcessId()));

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
AfdConnectedSocketWriteData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                            PIO_STACK_LOCATION IrpSp, BOOLEAN Short) {

    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: called.\n", PsGetCurrentProcessId()));

    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_SEND_INFO SendReq;
    UINT TotalBytesCopied = 0, i, SpaceAvail = 0, BytesCopied, SendLength;
    KPROCESSOR_MODE LockMode;
    // DLB hack start
    UINT FullSendLen, LoopIdx; /* DLB accumulator for packet structure length */
/*    char pktbuf[4096]; */ /* packet assembly buffer */
	// DLB hack end

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Short);

    AFD_DbgPrint(1 ,("(PID %lx) Called on %p\n", PsGetCurrentProcessId(), FCB));

	// DLB hack start
    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: Starting on FCB: %p\n", PsGetCurrentProcessId(), FCB));
if (FCB->State ==  SOCKET_STATE_CREATED) { // we may or may not need this, so we'll decide based on the state for now
        AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: HACK06a SOCKET_STATE_CREATED found.\n", PsGetCurrentProcessId()));
}
if (FCB->State ==  SOCKET_STATE_BOUND) { // we may or may not need this, so we'll decide based on the state for now
        AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: HACK06b SOCKET_STATE_BOUND found.\n", PsGetCurrentProcessId()));
}
	// DLB hack end

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    FCB->EventSelectDisabled &= ~AFD_EVENT_SEND;

    if( FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS )
    {
        PAFD_SEND_INFO_UDP SendReq;
        PTDI_CONNECTION_INFORMATION TargetAddress;

    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: processing CONNECTIONLESS send.\n", PsGetCurrentProcessId()));

        /* Check that the socket is bound */
        if( FCB->State != SOCKET_STATE_BOUND || !FCB->RemoteAddress )
        {
            /* AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n")); */
    	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: found incompatible FCB->State, returning STATUS_INVALID_PARAMETER.\n", PsGetCurrentProcessId()));
            return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );
        }

        if( !(SendReq = LockRequest( Irp, IrpSp, FALSE, &LockMode )) ) { 
    	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: LockRequest() failed, returning STATUS_NO_MEMORY.\n", PsGetCurrentProcessId()));
            return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp, 0 );
        }

        /* Must lock buffers before handing off user data */
        
        // DLB hack start
	/* LockBuffers figures out the size of allocation and lock space uses this code to figure out length of sendreq
	UINT Lock = LockAddress ? 2 : 0;
    	UINT Size = (sizeof(AFD_WSABUF) + sizeof(AFD_MAPBUF)) * (Count + Lock);
        -- I'm not sure what the lock component is, but excluding the +lock this all makes sense as the length for the total packet array
	-- SendReq is the entire array, so we may be able to use sizeof(SendReq), but it seems the most likely value will be (sizeof(SendReq) - (2 * (sizeof(AFD_WSABUF) + sizeof(AFD_MAPBUF))))
	-- or even better (sizeof(AFD_WSABUF) + sizeof(AFD_MAPBUF)) * (Count) it apears the last allocateion is a placeholder of sorts and only the address and len parts are used
	-- perhaps the issue here is that the code is trying to use that last entry and uses the first by mistake because it thinks the structure is built differently
        -- or perhaps the structure is built incorrectly and should have that 'wrapper' item at the beginning. since a lot of other routines use lockbuffers() we'll patch this here for now
	-- but AFD as a whole may have a bigger bug to be fixed!!
	-- when fillinf the target structure the LockBuffers routine only copies (sizeof(AFD_WSABUF) * Count) bytes from the older buffer to the new one, then it walks the list creating an
	-- MDL allocation for each and adds the mapped MDL address to the send request. there is an array of buffers here, but the send code seems to send only the first for datagrams.
        */

	if (SendReq->BufferCount > 1) {
	    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: DLB LB Hack - calling LockBuffers() with LockAddress=TRUE and (VOID *)0xFFFFFFFF Lock entry address and length - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
	} else {
	    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: DLB LB Hack - calling LockBuffers() with LockAddress=FALSE and NULL Lock entry address and length - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
        }

	/* LockBuffers now destoys the array replacing it with a single flat buffer so we need to preserve the length and pointer for later use */
        FullSendLen = 0;
	for (LoopIdx = 0; LoopIdx < SendReq->BufferCount; LoopIdx++) { 
            /* OskitDumpBuffer( SendReq->BufferArray[LoopIdx].buf, SendReq->BufferArray[LoopIdx].len ); // DLB added
			AFD_DbgPrint(1,("\n" ));            */
      	    FullSendLen = FullSendLen + SendReq->BufferArray[LoopIdx].len;
	}
	AFD_DbgPrint(1,("\n" ));            

    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: DLB LB Hack - prior to LockBuffers() Data length is %u.\n", PsGetCurrentProcessId(), FullSendLen ));

        /* ORIG SendReq->BufferArray = LockBuffers( SendReq->BufferArray, SendReq->BufferCount, NULL, NULL, FALSE, FALSE, LockMode ); */

    	if (SendReq->BufferCount > 1) {
		/* let's try the existing LockAddress mode and see what buffers look like */
    		AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: DLB LB Hack - multiple buffers in array, calling existing LockAddress mode. BufferArray base:%p count: %u\n", PsGetCurrentProcessId(), SendReq->BufferArray, SendReq->BufferCount ));
		for (LoopIdx = 0; LoopIdx < SendReq->BufferCount; LoopIdx++) { 
            		OskitDumpBuffer( SendReq->BufferArray[LoopIdx].buf, SendReq->BufferArray[LoopIdx].len ); /* DLB added this */
			AFD_DbgPrint(1,("\n" ));            
		}
		AFD_DbgPrint(1,("\n" ));    

		/* hacky PAD packet assembly code, probably not thread safe among other things */


		/* THE ONLY CALLER THAT USES LOCAKADDRESS=TRUE is the recv datagram routine and when it does use it the 
		caller provides address and length after buffercount when it makes the call, and the values are a wrapper
                containing all the smaller buffers witin it. Basically it starts at the first buffer and has the length of
		the sum of the buffer sizes. Lock sees it and creates one more entry and handles it just like the others */
		

	    	SendReq->BufferArray = LockBuffers( SendReq->BufferArray, SendReq->BufferCount, NULL, NULL, FALSE, TRUE, LockMode );
    		AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: DLB LB Hack - multiple buffers mode, LockBuffers complete displaying buffers. BufferArray base:%p count: %u\n", PsGetCurrentProcessId(), SendReq->BufferArray, SendReq->BufferCount ));
		for (LoopIdx = 0; LoopIdx < SendReq->BufferCount; LoopIdx++) { 
            		OskitDumpBuffer( SendReq->BufferArray[LoopIdx].buf, SendReq->BufferArray[LoopIdx].len ); /* DLB added this */
			AFD_DbgPrint(1,("\n" ));            
		}
		AFD_DbgPrint(1,("\n" ));            

/* magic hack routine, called by impossible values with lockaddress true 
    		AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: DLB LB Hack - multiple buffers in array, performing LockBuffers() gather operation - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray ));
	    	SendReq->BufferArray = LockBuffers( SendReq->BufferArray, SendReq->BufferCount, (VOID *)0xFFFFFFFF, (VOID *)0xFFFFFFFF, FALSE, TRUE, LockMode );
	    	SendReq->BufferCount = 1; 
*/  /* as a precaution to keep the structures valid */
    	} else {
    		AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: DLB LB Hack - SINGLE buffer in array, calling original LockBuffers() code - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray ));
	    	SendReq->BufferArray = LockBuffers( SendReq->BufferArray, SendReq->BufferCount, NULL, NULL, FALSE, FALSE, LockMode );
    	}		
		// DLB hack end        
      
       /* original 4.15 code
        
        SendReq->BufferArray = LockBuffers( SendReq->BufferArray,
                                            SendReq->BufferCount,
                                            NULL, NULL,
                                            FALSE, FALSE, LockMode );
	   */

        if( !SendReq->BufferArray ) {
  	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: LockBuffers() failed, returning STATUS_ACCESS_VIOLATION.\n", PsGetCurrentProcessId()));
            return UnlockAndMaybeComplete( FCB, STATUS_ACCESS_VIOLATION, Irp, 0 );
        }

	// DLB hack start
        OskitDumpBuffer( SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len ); /* DLB added this */

  	AFD_DbgPrint(1,("\n(PID %lx) AfdConnectedSocketWriteData: setting TargetAddress from FCB->RemoteAddress.\n", PsGetCurrentProcessId()));

    	AFD_DbgPrint
        	(1,("(PID %lx) AfdConnectedSocketWriteData: FCB->RemoteAddress Type: %x Address: %s Port: \n", PsGetCurrentProcessId(),
                    FCB->RemoteAddress->Address[0].AddressType, // word
		    FCB->RemoteAddress->Address[0].Address      // dword
		    /*, ntohs( FCB->RemoteAddress->Address[0].Port )		*/
		    ));
	// DLB hack end	
        Status = TdiBuildConnectionInfo( &TargetAddress, FCB->RemoteAddress );

        if( NT_SUCCESS(Status) ) {
            FCB->PollState &= ~AFD_EVENT_SEND;
  	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: nonblocking send requested, queueing user mode IRP.\n", PsGetCurrentProcessId()));
            Status = QueueUserModeIrp(FCB, Irp, FUNCTION_SEND);
            if (Status == STATUS_PENDING)
            {

		/* DLB may be a bug here. This assumes the buffer array has only a single element or has a lead element that wraps others. Based on a review of LockBuffers() which clones the structure
		   from userland into driver MDL area, there is no such wrapper element. Whenever multiple buffers are used this code is sending ONY the first element. This is a bug because the 
		   structure has a count associated with it to indicate how many buffers are present.. If this was always a single element there would be no counter.. */

	    /* DLB this looks just plain wrong.. the buffer array is supposed to be sent as a sent in a single packet. This sends the first element ignoring the rest altogether ! */
            /* Status = TdiSendDatagram(&FCB->SendIrp.InFlightRequest, FCB->AddressFile.Object, SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len, TargetAddress, PacketSocketSendComplete, FCB); */

		/* the total buffer size came in as a parameter so hopefully its in Sendreq somewhere.. If not we can walk the buffers summing the lengths and then 
                   add the size of the len and buf elements multiplied by the buffer count to get the total length. That is what the packet is supposed to contain. Not just the first buffer. 
                   we are supposed to send the whole buffer array at once. It is the callers responsibility to make sure the buffers and structures are set up with proper sizes for it and
                   that the datagram is split up before this point if it needs to be split up. */

	    /* DLB no such luck. reviewing LockBuffers we can see that SendReq->BufferArray contains only the buffer items sent in by the caller, there is no lead element that wraps the whole 
               array or buffer count inside it, those are addl elements parallel to the BufferArray. The code seems to assume there is a wrapper at head so it ends up sending first item alone.
               we will need to loop through the bufferarray collecting up its data length from its content items. as long as the allocations were consecutive this should work. if the allocations
               were not consecutive in memory we will fail to send the data.. right number of bytes, wrong content after first item.. If that happens we need to make significant changes to 
               LockBuffers so that the allocation of the buffer is done in a single operation and the elements are copied in at offsets. This is not it's current logic and would be full rewrite
               we are trying this simpler method first because changing LockBuffers could have wider reaching side effects as it is used by all of AFD and other bad assumptions may be present.
               Unfortunately if taht is the case it implies a full code review and rewrite of AFDs buffer handling will be required to truly fix this issue. */

	    /* if LockAddress parameter was being used with LockBuffers we would need Count-1 or could possibly use just SendReq->BufferArray[Count].len, but it is not used for this case so we 
	       cannot. If this method does not work we should try setting it true and see if that works.. That essentially does the same thing, but has LockBuffers handle it internally while
               doing its allocations. It may work there and not here because it may change the allocation method from individual to grouped with offset, don't recall. */

  	        AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: found STATUS_PENDING, calling TdiSendDatagram(x x %p %u %p x FCB ).\n", PsGetCurrentProcessId(), SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len, TargetAddress  ));

        	OskitDumpBuffer( SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len ); /* DLB added this */

                Status = TdiSendDatagram(&FCB->SendIrp.InFlightRequest, FCB->AddressFile.Object, SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len , TargetAddress, 
						PacketSocketSendComplete, FCB);

                if (Status != STATUS_PENDING)
                {
  		    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: did not find STATUS_PENDING, marking IoRequest as complete.\n", PsGetCurrentProcessId()));
                    NT_VERIFY(RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]) == &Irp->Tail.Overlay.ListEntry);
                    Irp->IoStatus.Status = Status;
                    Irp->IoStatus.Information = 0;
                    (void)IoSetCancelRoutine(Irp, NULL);
    	    	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: Calling UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
                    UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE); /* call original code as before */
		    /* UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, TRUE); // modified code */
                    UnlockRequest(Irp, IoGetCurrentIrpStackLocation(Irp));
                    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
                }
            }

            ExFreePoolWithTag(TargetAddress, TAG_AFD_TDI_CONNECTION_INFORMATION);

            SocketStateUnlock(FCB);

  	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: returning STATUS_PENDING.\n", PsGetCurrentProcessId()));

            return STATUS_PENDING;
        }
        else
        {
  	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: unlocking buffers and calling UnlockAndMaybeComplete() for IRP.\n", PsGetCurrentProcessId()));
            /* UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, TRUE); */ /* use our special buffer consolidation mode */
    	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: Calling UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
            UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE); /* use original code */
    	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: completed, returning via UnlockAndMaybeComplete().\n", PsGetCurrentProcessId()));
            return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
        }
	/* DATAGRAM CODE ENDS HERE */
    }

    if (FCB->PollState & AFD_EVENT_CLOSE)
    {
        AFD_DbgPrint(1,("(PID %lx) Connection reset by remote peer\n", PsGetCurrentProcessId()));
  	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: received AFD_EVENT_CLOSE, connection reset by peer.\n", PsGetCurrentProcessId()));
        /* This is an unexpected remote disconnect */
    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: completed(AFD_EVENT_CLOSE), returning via UnlockAndMaybeComplete().\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete(FCB, FCB->PollStatus[FD_CLOSE_BIT], Irp, 0);
    }

    if (FCB->PollState & AFD_EVENT_ABORT)
    {
        AFD_DbgPrint(1,("(PID %lx) Connection aborted\n", PsGetCurrentProcessId()));
  	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: received AFD_EVENT_ABORT, connection aborted.\n", PsGetCurrentProcessId()));
        /* This is an abortive socket closure on our side */
    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: completed(AFD_EVENT_ABORT), returning via UnlockAndMaybeComplete().\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete(FCB, FCB->PollStatus[FD_CLOSE_BIT], Irp, 0);
    }

    if (FCB->SendClosed)
    {
        AFD_DbgPrint(1,("(PID %lx) No more sends\n", PsGetCurrentProcessId()));
  	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: received FCB->SendClosed, No more sends (graceful send closure).\n", PsGetCurrentProcessId()));
        /* This is a graceful send closure */
    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: completed, returning (STATUS_FILE_CLOSE) via UnlockAndMaybeComplete().\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete(FCB, STATUS_FILE_CLOSED, Irp, 0);
    }

    if( !(SendReq = LockRequest( Irp, IrpSp, FALSE, &LockMode )) ) {
    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: LockRequest() failed, returning STATUS_NO_MEMORY.\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp, 0 );
    }

    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: Calling LockBuffers( SendReq->BufferArray, SendReq->BufferCount, NULL, NULL, FALSE, FALSE, LockMode ) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
    SendReq->BufferArray = LockBuffers( SendReq->BufferArray, SendReq->BufferCount, NULL, NULL, FALSE, FALSE, LockMode ); 

    if( !SendReq->BufferArray ) {
 	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: LockBuffers() failed, returning STATUS_ACCESS_VIOLATION.\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete( FCB, STATUS_ACCESS_VIOLATION, Irp, 0 );
    }

    AFD_DbgPrint(1,("(PID %lx) Socket state %u\n", PsGetCurrentProcessId(), PsGetCurrentProcessId(), FCB->State));
    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: socket state: %u.\n", PsGetCurrentProcessId(), FCB->State));

    if( FCB->State != SOCKET_STATE_CONNECTED ) {
        AFD_DbgPrint(1,("(PID %lx) Socket not connected\n", PsGetCurrentProcessId()));
  	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: FCB->State != SOCKET_STATE_CONNECTED, unlocking and completing as STATUS_INVALID_CONNECTION (socket is not connected).\n", PsGetCurrentProcessId()));
        AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE ) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
        UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE );
    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: completed, returning (STATUS_INVALID_CONNECTION) via UnlockAndMaybeComplete().\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_CONNECTION, Irp, 0 );
    }

    AFD_DbgPrint(1,("(Pid %lx) FCB->Send.BytesUsed = %u\n", PsGetCurrentProcessId(), FCB->Send.BytesUsed));

    SpaceAvail = FCB->Send.Size - FCB->Send.BytesUsed;

    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: We can accept %u bytes\n", PsGetCurrentProcessId(), SpaceAvail));

    /* Count the total transfer size */
    SendLength = 0;
    for (i = 0; i < SendReq->BufferCount; i++)
    {
        SendLength += SendReq->BufferArray[i].len;
    }

    /* Make sure we've got the space */
    if (SendLength > SpaceAvail)
    {
        /* Blocking sockets have to wait here */
        if (SendLength <= FCB->Send.Size && !((SendReq->AfdFlags & AFD_IMMEDIATE) || (FCB->NonBlocking)))
        {
            FCB->PollState &= ~AFD_EVENT_SEND;
  	    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: completed, calling LeaveIrpUntilLater(FUNCTION_SEND) - leaving on queue.\n", PsGetCurrentProcessId()));
            return LeaveIrpUntilLater(FCB, Irp, FUNCTION_SEND);
        }

        /* Check if we can send anything */
        if (SpaceAvail == 0)
        {
            FCB->PollState &= ~AFD_EVENT_SEND;

            /* Non-overlapped sockets will fail if we can send nothing */
            if (!(SendReq->AfdFlags & AFD_OVERLAPPED))
            {
        	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE ) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
                UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE );
  	    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: non-overlap socket failed, calling UnlcokAndMaybeComplete(STATUS_CANT_WAIT).\n", PsGetCurrentProcessId()));
                return UnlockAndMaybeComplete( FCB, STATUS_CANT_WAIT, Irp, 0 );
            }
            else
            {
                /* Overlapped sockets just pend */
  	    	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: completed, calling LeaveIrpUntilLater(FUNCTION_SEND) - leaving on queue.\n", PsGetCurrentProcessId()));
                return LeaveIrpUntilLater(FCB, Irp, FUNCTION_SEND);
            }
        }
    }

    for ( i = 0; SpaceAvail > 0 && i < SendReq->BufferCount; i++ )
    {
        BytesCopied = MIN(SendReq->BufferArray[i].len, SpaceAvail); /* DLB: this assumes the tail element on the buffer array has the array wrapping item present which depends on LockMode used */

/*        AFD_DbgPrint(MID_TRACE,("Copying Buffer %u, %p:%u to %p\n", i, SendReq->BufferArray[i].buf, BytesCopied, FCB->Send.Window + FCB->Send.BytesUsed)); */
        AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: Copying Buffer %u, %p:%u to %p\n", PsGetCurrentProcessId(), i, SendReq->BufferArray[i].buf, BytesCopied, FCB->Send.Window + FCB->Send.BytesUsed));

        RtlCopyMemory(FCB->Send.Window + FCB->Send.BytesUsed, SendReq->BufferArray[i].buf, BytesCopied);

        TotalBytesCopied += BytesCopied;
        SpaceAvail -= BytesCopied;
        FCB->Send.BytesUsed += BytesCopied;
    }

    Irp->IoStatus.Information = TotalBytesCopied;

    if( TotalBytesCopied == 0 ) {
        AFD_DbgPrint(1,("(PID %lx) Empty send\n", PsGetCurrentProcessId()));
        AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE ) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
        UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE );
  	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: Empty send, calling UnlockAndMaybeComplete(STATUS_SUCCESS).\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete( FCB, STATUS_SUCCESS, Irp, TotalBytesCopied );
    }

    if (SpaceAvail)
    {
        FCB->PollState |= AFD_EVENT_SEND;
        FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    }
    else
    {
        FCB->PollState &= ~AFD_EVENT_SEND;
    }

    /* We use the IRP tail for some temporary storage here */
    Irp->Tail.Overlay.DriverContext[3] = (PVOID)Irp->IoStatus.Information;

    Status = QueueUserModeIrp(FCB, Irp, FUNCTION_SEND);
    if (Status == STATUS_PENDING && !FCB->SendIrp.InFlightRequest)
    {
  	AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: calling TdiSend().\n", PsGetCurrentProcessId()));

        TdiSend(&FCB->SendIrp.InFlightRequest, FCB->Connection.Object, 0, FCB->Send.Window, FCB->Send.BytesUsed, SendComplete, FCB);
    }

    SocketStateUnlock(FCB);

    AFD_DbgPrint(1,("(PID %lx) AfdConnectedSocketWriteData: completed, returning STATUS_PENDING.\n", PsGetCurrentProcessId()));

    return STATUS_PENDING;
}

NTSTATUS NTAPI
AfdPacketSocketWriteData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                         PIO_STACK_LOCATION IrpSp) {

    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: called.\n", PsGetCurrentProcessId()));

    NTSTATUS Status = STATUS_SUCCESS;
    PTDI_CONNECTION_INFORMATION TargetAddress;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_SEND_INFO_UDP SendReq;
    KPROCESSOR_MODE LockMode;
    INT FullSendLen, LoopIdx; /* DLB accumulator for packet structure length */
/*    INT DataSize;  // part of buffer PAD hack */
    char pktbuf[4096];  /* packet assembly buffer */

    UNREFERENCED_PARAMETER(DeviceObject);

//    AFD_DbgPrint(1,("Called on %p\n", FCB));

    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: Starting on FCB: %p\n", PsGetCurrentProcessId(), FCB));

    if( !SocketAcquireStateLock( FCB ) ) {
    	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: failed to lock FCB %p, returning via LostSocket().\n", PsGetCurrentProcessId(), FCB));
	return LostSocket( Irp );
    }

    FCB->EventSelectDisabled &= ~AFD_EVENT_SEND;

    /* Check that the socket is bound */
    if( FCB->State != SOCKET_STATE_BOUND && FCB->State != SOCKET_STATE_CREATED)
    {
        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: Invalid socket state, calling UnlockAndMaybeComplete() as STATUS_INVALID_PARAMETER\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    if (FCB->SendClosed)
    {
        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: No more sends, calling UnlockAndMaybeComplete() as STATUS_FILE_CLOSED\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_FILE_CLOSED, Irp, 0);
    }

    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: calling LockRequest() to lock and copy request.\n", PsGetCurrentProcessId()));

    if( !(SendReq = LockRequest( Irp, IrpSp, FALSE, &LockMode )) ) {
    	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: LockRequest() failed, returning STATUS_NO_MEMORY.\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);
    }

    if (FCB->State == SOCKET_STATE_CREATED)
    {

        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: FCB->State == SOCKET_STATE_CREATED.\n", PsGetCurrentProcessId()));

        if (FCB->LocalAddress)
        {
            AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: FCB->LocalAddress is set, Calling ExFreePoolWithTag().\n", PsGetCurrentProcessId()));
            ExFreePoolWithTag(FCB->LocalAddress, TAG_AFD_TRANSPORT_ADDRESS);
        }

        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: Calling TaBuildNullTransportAddress() for type %u .\n", PsGetCurrentProcessId(), ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->Address[0].AddressType ));

        FCB->LocalAddress = TaBuildNullTransportAddress( ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->Address[0].AddressType );

        if( FCB->LocalAddress ) {
       	    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: Calling WarmSocketForBind().\n", PsGetCurrentProcessId()));
            Status = WarmSocketForBind( FCB, AFD_SHARE_WILDCARD );
            if( NT_SUCCESS(Status) ) {
    		AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: WarmSocketForBind() succeeded, setting FCB->STATE to Socket_STATE_BOUND.\n", PsGetCurrentProcessId()));
                FCB->State = SOCKET_STATE_BOUND;
            } else {
    		AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: call to WarmSocketForBind() did not return NT_SUCCESS, return through UnlockAndMaybeComplete().\n", PsGetCurrentProcessId()));
                return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
    }
    } else {
    	    	    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: call to TaBuildNullTransportAddress() did not get LocalAddress, skip local BIND and return through UnlockAndMaybeComplete() as STATUS_NO_MEMORY.\n", PsGetCurrentProcessId()));
            return UnlockAndMaybeComplete
            ( FCB, STATUS_NO_MEMORY, Irp, 0 );
    }
} else
        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: FCB->State <> SOCKET_STATE_CREATED, local bind skipped and FCB->State unchanged.\n", PsGetCurrentProcessId()));
    
    // DLB hack start
    if (SendReq->BufferCount > 1) {
	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB PAD Hack - Assembling local packet buffer from %u Buffer Array elements, clearing buffer.\n", PsGetCurrentProcessId(), SendReq->BufferCount));
    	RtlZeroMemory((&pktbuf[0]), 4096 );
    	/* save the data length for cross checking later */
    	FullSendLen = 0;
    	for (LoopIdx = 0; LoopIdx < SendReq->BufferCount; LoopIdx++) { 
    		AFD_DbgPrint(1,("(PID %lx) \n", PsGetCurrentProcessId()));
        	OskitDumpBuffer( SendReq->BufferArray[LoopIdx].buf, SendReq->BufferArray[LoopIdx].len ); /* DLB added this */
    		AFD_DbgPrint(1,("(PID %lx) Copying data shown above to: %p length: %u pkt_start: %p\n", PsGetCurrentProcessId(), (PCHAR)((&pktbuf[0]) + FullSendLen), SendReq->BufferArray[LoopIdx].len, (PCHAR)(&pktbuf[0]) ));
		/* create our full packet in local buffer */
		_SEH2_TRY {
			RtlCopyMemory((PCHAR)((&pktbuf[0]) + FullSendLen), SendReq->BufferArray[LoopIdx].buf, SendReq->BufferArray[LoopIdx].len ); 
		} _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        		AFD_DbgPrint(0,("(PID %lx) AfdPacketSocketWriteData: DLB PAD Hack Access violation copying buffer data from userland (%p %p), returning NULL\n", PsGetCurrentProcessId(), SendReq->BufferArray[LoopIdx].buf, SendReq->BufferArray[LoopIdx].len ));
	    		/* ExFreePoolWithTag(NewBuf, TAG_AFD_WSA_BUFFER); not allocated yet */
            		_SEH2_YIELD(return STATUS_NO_MEMORY);
		} _SEH2_END;
    		FullSendLen = FullSendLen + SendReq->BufferArray[LoopIdx].len; /* THIS WORKS FINE GIVES CORRECT LENGTH seen on windows */
    	}

	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB PAD Hack - Completed local buffer assembled.\n", PsGetCurrentProcessId()));

   	AFD_DbgPrint(1,("(PID %lx) \n", PsGetCurrentProcessId()));
        OskitDumpBuffer( &pktbuf[0], FullSendLen ); // DLB added this 
    	AFD_DbgPrint(1,("(PID %lx) \n", PsGetCurrentProcessId()));

	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB PAD-LB Hack - calling LockBuffers() with LockAddress=TRUE and (VOID *)0xFFFFFFFF Lock entry address and length - 0x%p:u\n", PsGetCurrentProcessId(), &pktbuf[0], FullSendLen));
    	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB - prior to LockBuffers() call Data length is %u.\n", PsGetCurrentProcessId(), FullSendLen ));
    } else {
	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB - calling LockBuffers() without hacks LockAddress=FALSE and NULL Lock entry address and length - 0x%p:%u\n", PsGetCurrentProcessId(), SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len));
    	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB - prior to LockBuffers() call Data length is %u.\n", PsGetCurrentProcessId(), SendReq->BufferArray[0].len ));
    }



    /* DLB TdiSendDatagram expects a single buffer so we use a hack in LockBuffers to collapse the array to a singel buffer this hack is activated by setting LockAddress = TRUE */
    /* ORIG SendReq->BufferArray = LockBuffers( SendReq->BufferArray, SendReq->BufferCount, NULL, NULL, FALSE, FALSE, LockMode ); */
    /* to prevent breakage of the existing users of this code we only call the 'new' code when multiple buffers are present in array */
    if (SendReq->BufferCount > 1) {
    	    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB LB Hack - multiple buffers in array, performing LockBuffers() gather mode - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray ));
	    SendReq->BufferArray = LockBuffers( SendReq->BufferArray, SendReq->BufferCount, (VOID *)0xFFFFFFFF, (VOID *)0xFFFFFFFF, FALSE, TRUE, LockMode );
	    /* SendReq->BufferCount = 1; // as a precaution keep the structures valid */
    } else {
    	    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB LB Hack - SINGLE buffer in array, calling original LockBuffers() code - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray ));
	    SendReq->BufferArray = LockBuffers( SendReq->BufferArray, SendReq->BufferCount, NULL, NULL, FALSE, FALSE, LockMode );
    }

    if( !SendReq->BufferArray ) {
    	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: failed call to LockBuffers(), return via UnlockAndMaybecomplete() as STATUS_ACCESS_VIOLATION.\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete( FCB, STATUS_ACCESS_VIOLATION, Irp, 0 );
    }

    if (SendReq->BufferCount > 1) {
    	AFD_DbgPrint(1,("(PID %lx) Buffer cout is > 1 \n", PsGetCurrentProcessId()));
    	OskitDumpBuffer(&pktbuf[0], FullSendLen );  /* DLB added this */
    	AFD_DbgPrint(1,("(PID %lx) \n", PsGetCurrentProcessId()));
    } else {
    	AFD_DbgPrint(1,("(PID %lx) Single Buffer\n", PsGetCurrentProcessId()));
    	OskitDumpBuffer( SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len );  /* DLB added this */
    	AFD_DbgPrint(1,("(PID %lx) \n", PsGetCurrentProcessId()));
    } 
    
    AFD_DbgPrint
        (1,("(PID %lx) AfdPacketSocketWriteData: RemoteAddress #%d Type %u\n", PsGetCurrentProcessId(),
                    ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->TAAddressCount,
                    ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->Address[0].AddressType));

    AFD_DbgPrint
        (1,("(PID %lx) AfdPacketSocketWriteData: SendReq->TdiConnection.RemoteAddress #%d Type: %x Address: %lx Port: %x\n", PsGetCurrentProcessId(),
                    ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->TAAddressCount,
                    ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->Address[0].AddressType, // word
		    ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->Address[0].Address      // dword
		    //, ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->Address[0].Port 		
		    ));

    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: Calling TdiBuildConnectionInfo() setting TargetAddress from SendReq->TdiConnection.RemoteAddress.\n", PsGetCurrentProcessId()));

    Status = TdiBuildConnectionInfo( &TargetAddress, ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress) );

    /* DLB hack, if the above operation failed we assume the remote address is not provided and check if we have connection information in the FCB to use */
    if( !NT_SUCCESS(Status) ) {
	if (FCB->ConnectCallInfo) {
    		AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: HACK1 settings TargetAddress from ConnectCallInfo->RemoteAddress.\n", PsGetCurrentProcessId() ));
		Status = TdiBuildConnectionInfo( &TargetAddress, ((PTRANSPORT_ADDRESS)FCB->ConnectCallInfo->RemoteAddress) );
	} else {
		if (FCB->ConnectReturnInfo) {
    			AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: HACK2 settings TargetAddress from ConnectReturnInfo->RemoteAddress.\n", PsGetCurrentProcessId() ));
			Status = TdiBuildConnectionInfo( &TargetAddress, ((PTRANSPORT_ADDRESS)FCB->ConnectReturnInfo->RemoteAddress) );
		}
	}
    }

    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: HACKs completed, send continuing.\n", PsGetCurrentProcessId() ));
       
    // DLB hack end
/*    

    SendReq->BufferArray = LockBuffers( SendReq->BufferArray,
                                        SendReq->BufferCount,
                                        NULL, NULL,
                                        FALSE, FALSE, LockMode );

    if( !SendReq->BufferArray )
        return UnlockAndMaybeComplete( FCB, STATUS_ACCESS_VIOLATION,
                                       Irp, 0 );

    AFD_DbgPrint
        (MID_TRACE,("RemoteAddress #%d Type %u\n",
                    ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->
                    TAAddressCount,
                    ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress)->
                    Address[0].AddressType));

    Status = TdiBuildConnectionInfo( &TargetAddress,
                            ((PTRANSPORT_ADDRESS)SendReq->TdiConnection.RemoteAddress) );
*/
    /* Check the size of the Address given ... */

    if( NT_SUCCESS(Status) ) {
        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: TdiBuildConnectionInfo() successful getting address, calling QueueUserModeIrp().\n", PsGetCurrentProcessId()));    	
        FCB->PollState &= ~AFD_EVENT_SEND;
        Status = QueueUserModeIrp(FCB, Irp, FUNCTION_SEND);
        if (Status == STATUS_PENDING)
        {
/* 4.15 code 
            Status = TdiSendDatagram(&FCB->SendIrp.InFlightRequest,
                                     FCB->AddressFile.Object,
                                     SendReq->BufferArray[0].buf,
                                     SendReq->BufferArray[0].len,
                                     TargetAddress,
                                     PacketSocketSendComplete,
                                     FCB);
*/

// DLB hack start

    	    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: Status is STATUS_PENDING, Calling TdiSendDatagram().\n", PsGetCurrentProcessId()));

	    /* DLB this looks just plain wrong.. the buffer array is supposed to be sent in a single packet. This sends the first element ignoring the rest altogether ! */
            /* Status = TdiSendDatagram(&FCB->SendIrp.InFlightRequest, FCB->AddressFile.Object, SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len, TargetAddress, PacketSocketSendComplete, FCB); */

	    /* this is just debug crosscheck output and should not remain in code permanently */
	    /* AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: sizeof(AFD_WSABUF): %u sizeof(AFD_MAPBUF): %u sizeof(UINT): %u sizeof(PCHAR): %u sizeof(PVOID): %u sizeof(PMDL): %u.\n", PsGetCurrentProcessId(), sizeof(AFD_WSABUF), sizeof(AFD_MAPBUF), sizeof(UINT), sizeof(PCHAR), sizeof(PVOID), sizeof(PMDL)  )); */

    	    if (SendReq->BufferCount > 1) { /* backpedalled all the PAD copying, just assume they are contigoupus and send.. */
	    	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: found STATUS_PENDING, calling TdiSendDatagram(x x %p %u %p x FCB ) buffer base is: %p.\n", PsGetCurrentProcessId(), SendReq->BufferArray[0].buf, 
									FullSendLen, TargetAddress, &SendReq->BufferArray[0].len  ));
    	    	AFD_DbgPrint(1,("(PID %lx) \n", PsGetCurrentProcessId()));
            	OskitDumpBuffer( &pktbuf[0], FullSendLen ); /* DLB added this */
    	    	AFD_DbgPrint(1,("(PID %lx) \n", PsGetCurrentProcessId()));

            	Status = TdiSendDatagram(&FCB->SendIrp.InFlightRequest, FCB->AddressFile.Object, &pktbuf[0], FullSendLen, TargetAddress, PacketSocketSendComplete, FCB);

		/* SECURITY NOTE, WE ARE NOT CLEARING BUFFER AFTER USE. INFORMATION LEAKAGE ON STACK COULD COMPROMISE SENSITIVE DATA */

    	    } else {
	    	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: found STATUS_PENDING, calling TdiSendDatagram(x x %p %u %p x FCB ) buffer base is: %p.\n", PsGetCurrentProcessId(), SendReq->BufferArray[0].buf, 
									SendReq->BufferArray[0].len, TargetAddress, &SendReq->BufferArray[0].len  ));
            	Status = TdiSendDatagram(&FCB->SendIrp.InFlightRequest, FCB->AddressFile.Object, SendReq->BufferArray[0].buf, SendReq->BufferArray[0].len, TargetAddress, PacketSocketSendComplete, FCB);
    	    }

	    /* DLB currently this is still broken because the allocations are not contiguous. the buffer array needs to be built in a contiguous fashion and currently it's not.
               this is a ROS issue because it works correctly on Windows 10, and it is an artifact of bad assumptions in the ROS codebase (AFD driver). */
// DLB hack end
            if (Status != STATUS_PENDING)
            {
                NT_VERIFY(RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]) == &Irp->Tail.Overlay.ListEntry);
                Irp->IoStatus.Status = Status;
                Irp->IoStatus.Information = 0;
		/* by the time we get here there is only a single buffer unless something went wrong.. */
/*
		if (SendReq->BufferCount > 1) {
    			AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB LB Hack - multiple buffers in array, calling revised UnlockBuffers() code - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray ));
        		AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, TRUE ) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
	                UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, TRUE);
		} else {
*/
    			AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: DLB LB Hack - calling original UnlockBuffers() code - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray ));
        		AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE ) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));

                UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
/*		} */
                UnlockRequest(Irp, IoGetCurrentIrpStackLocation(Irp));
                IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    	        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: error, Call to TdiSendDatagram() did not return STATUS_PENDING.\n", PsGetCurrentProcessId()));
            }
        } else
        	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: call to TdiBuildConnectionInfo() failed, call to TdiSendDatagram() skipped.\n", PsGetCurrentProcessId()));

        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: Send actions completed, freeing TargetAddress, calling ExFreePoolWithTag() then SocketStateUnlock(FCB).\n", PsGetCurrentProcessId()));

        ExFreePoolWithTag(TargetAddress, TAG_AFD_TDI_CONNECTION_INFORMATION);

        SocketStateUnlock(FCB);

        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: completed, returning STATUS_PENDING.\n", PsGetCurrentProcessId()));

        return STATUS_PENDING;
    }
    else
    {
     	AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE ) - 0x%p\n", PsGetCurrentProcessId(), SendReq->BufferArray));
        UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
        AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: completed, returning UnlockAndMaybeComplete().\n", PsGetCurrentProcessId()));
        return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
    }
    AFD_DbgPrint(1,("(PID %lx) AfdPacketSocketWriteData: completed (fallthrough).\n", PsGetCurrentProcessId()));
}
