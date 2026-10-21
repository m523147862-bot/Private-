#pragma once

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurface.h>

#include "macws_final_composite_protocol.h"

typedef void (^MacWSFinalCompositeAcceptedHandler)(
    IOSurfaceRef surface, MacWSFinalCompositeRecord record);
typedef void (^MacWSFinalCompositeReceiverLogHandler)(NSString *message);

// Starts the authenticated WindowServer-only Mach receiver on queue. The
// receiver owns envelope, audit-token and producer-path validation, maps the
// frame's Mach memory object, copies it into a surface this process owns, and
// only then reports the frame; displayd's presentation layer sees accepted
// immutable frames whose lifetime it controls.
BOOL MacWSStartFinalCompositeReceiver(
    dispatch_queue_t queue,
    MacWSFinalCompositeAcceptedHandler acceptedHandler,
    MacWSFinalCompositeReceiverLogHandler logHandler);

// Requests a fresh snapshot of WindowServer's latest completed composite.
// Calls are generation-coalesced by the receiver and never form a frame clock.
void MacWSRequestFinalCompositeReplay(uint64_t minimumCompletionTime);
