#import "MacWSFinalCompositeReceiver.h"

#import <IOSurface/IOSurface.h>

#include <limits.h>
#include <mach/bootstrap.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach/vm_statistics.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern pid_t audit_token_to_pid(audit_token_t token);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

static dispatch_source_t ReceiveSource;
static mach_port_t ReceivePort = MACH_PORT_NULL;
static _Atomic uint32_t RejectWitnesses;
static MacWSFinalCompositeAcceptedHandler AcceptedHandler;
static MacWSFinalCompositeReceiverLogHandler LogHandler;
static dispatch_queue_t ReceiverQueue;
static _Atomic bool FinalCompositeAccepted;
static _Atomic uint64_t ReplayRequestGeneration;
static _Atomic uint64_t ReplayMinimumCompletionTime;

static void ReceiverLog(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static void ReceiverLog(NSString *format, ...) {
    if (!LogHandler || !format) return;
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format
                                               arguments:args];
    va_end(args);
    LogHandler(message);
}

static BOOL ProducerIsWindowServer(pid_t pid) {
    if (pid <= 1) return NO;
    char path[PATH_MAX] = {0};
    int length = proc_pidpath(pid, path, sizeof(path));
    if (length <= 0 || length >= (int)sizeof(path)) return NO;
    path[sizeof(path) - 1] = '\0';
    // Runtime-confirmed on the Ventura 13.4 rootfs: proc_pidpath resolves the
    // public Resources symlink through Versions/A. These are the only accepted
    // executables after the audit-token PID matches the record PID.
    static const char versionedPath[] =
        "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/"
        "Resources/WindowServer";
    static const char publicPath[] =
        "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/"
        "WindowServer";
    return strcmp(path, versionedPath) == 0 || strcmp(path, publicPath) == 0;
}

static uint32_t NextRejectWitness(void) {
    return atomic_fetch_add_explicit(&RejectWitnesses, 1,
                                     memory_order_relaxed) + 1;
}

// A frame arrives as a Mach memory object, so this process has to produce its
// own surface to present: an IOSurface created in WindowServer's task is
// unreachable from this one by port and by ID alike
// (patches/a57e-P1-surface-registry-boundary-20261022.md).  Surfaces created
// here are the proven path -- every other stream in this daemon already hands
// one to Host over XPC.  Four slots keep one frame's GPU readers from colliding
// with the next frame's CPU write; a slot is rewritten only when
// IOSurfaceIsInUse reports nobody holds it, which covers this process's own
// current-frame count (DeliverFinalComposite's increment) and Host leases.
enum { MacWSFinalCompositeConsumerSurfaceCount = 4 };
typedef struct {
    IOSurfaceRef surface;
    uint32_t width;
    uint32_t height;
    uint32_t bytesPerRow;
    uint32_t pixelFormat;
    uint64_t lastDeliveredNS;
} MacWSFinalCompositeConsumerSurface;
// Touched only from ReceiveAvailableMessages, which the receiver dispatches on
// the serial display queue.
static MacWSFinalCompositeConsumerSurface ConsumerSurfaces[
    MacWSFinalCompositeConsumerSurfaceCount];
static NSUInteger NextConsumerSurface;
static _Atomic uint32_t AcceptedFrames;
static const uint64_t ConsumerSurfaceReuseNanoseconds = 16 * NSEC_PER_MSEC;

static uint64_t ReceiverMonotonicNanoseconds(void) {
    struct timespec now = {0};
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0
        ? (uint64_t)now.tv_sec * NSEC_PER_SEC + (uint64_t)now.tv_nsec : 0;
}

static IOSurfaceRef CreateConsumerSurface(uint32_t width, uint32_t height,
                                          uint32_t bytesPerRow,
                                          uint32_t pixelFormat) {
    NSDictionary *properties = @{
        (__bridge id)kIOSurfaceWidth: @(width),
        (__bridge id)kIOSurfaceHeight: @(height),
        (__bridge id)kIOSurfaceBytesPerElement: @4,
        (__bridge id)kIOSurfaceBytesPerRow: @(bytesPerRow),
        (__bridge id)kIOSurfaceAllocSize: @((uint64_t)bytesPerRow * height),
        (__bridge id)kIOSurfacePixelFormat: @(pixelFormat),
    };
    IOSurfaceRef surface = IOSurfaceCreate(
        (__bridge CFDictionaryRef)properties);
    if (!surface) {
        ReceiverLog(@"final-composite-consumer-surface-failed geometry=%ux%u "
                    "bpr=%u pf=%08x",
                    width, height, bytesPerRow, pixelFormat);
        return NULL;
    }
    // IOSurfaceCreate may round a geometry up.  A surface whose rows do not
    // match the producer's bytesPerRow cannot receive this payload verbatim, so
    // reject it here instead of corrupting the frame.
    if (IOSurfaceGetWidth(surface) != width ||
        IOSurfaceGetHeight(surface) != height ||
        IOSurfaceGetBytesPerRow(surface) != bytesPerRow ||
        (IOSurfaceGetPixelFormat(surface) != 0 &&
         IOSurfaceGetPixelFormat(surface) != pixelFormat)) {
        ReceiverLog(@"final-composite-consumer-surface-mismatch "
                    "expected=(%ux%u bpr=%u pf=%08x) "
                    "actual=(%zux%zu bpr=%zu pf=%08x)",
                    width, height, bytesPerRow, pixelFormat,
                    IOSurfaceGetWidth(surface), IOSurfaceGetHeight(surface),
                    IOSurfaceGetBytesPerRow(surface),
                    IOSurfaceGetPixelFormat(surface));
        CFRelease(surface);
        return NULL;
    }
    return surface;
}

// Returns the slot's surface without an extra retain: the accepted handler owns
// its own reference (DeliverFinalComposite CFRetains), and a slot's own
// reference outlives every handoff because a slot is only released on a
// geometry change, when no reader holds it.
static IOSurfaceRef AcquireConsumerSurface(
        const MacWSFinalCompositeRecord *record) {
    uint64_t nowNS = ReceiverMonotonicNanoseconds();
    for (NSUInteger attempt = 0;
         attempt < MacWSFinalCompositeConsumerSurfaceCount; attempt++) {
        NSUInteger index = (NextConsumerSurface + attempt) %
            MacWSFinalCompositeConsumerSurfaceCount;
        MacWSFinalCompositeConsumerSurface *slot = &ConsumerSurfaces[index];
        if (slot->surface &&
            (slot->width != record->width ||
             slot->height != record->height ||
             slot->bytesPerRow != record->bytesPerRow ||
             slot->pixelFormat != record->ioSurfacePixelFormat)) {
            if (IOSurfaceIsInUse(slot->surface)) continue;
            CFRelease(slot->surface);
            memset(slot, 0, sizeof(*slot));
        }
        if (!slot->surface) {
            IOSurfaceRef created = CreateConsumerSurface(
                record->width, record->height, record->bytesPerRow,
                record->ioSurfacePixelFormat);
            if (!created) continue;
            slot->surface = created;
            slot->width = record->width;
            slot->height = record->height;
            slot->bytesPerRow = record->bytesPerRow;
            slot->pixelFormat = record->ioSurfacePixelFormat;
            slot->lastDeliveredNS = 0;
        }
        if (IOSurfaceIsInUse(slot->surface)) continue;
        if (nowNS && slot->lastDeliveredNS &&
            nowNS - slot->lastDeliveredNS < ConsumerSurfaceReuseNanoseconds)
            continue;
        slot->lastDeliveredNS = nowNS;
        NextConsumerSurface = (index + 1) %
            MacWSFinalCompositeConsumerSurfaceCount;
        return slot->surface;
    }
    return NULL;
}

static bool CopyPayloadIntoSurface(const MacWSFinalCompositeRecord *record,
                                   const void *payload, IOSurfaceRef surface) {
    kern_return_t lockResult = IOSurfaceLock(surface, 0, NULL);
    if (lockResult != KERN_SUCCESS) {
        ReceiverLog(@"final-composite-rejected stage=consumer-surface-lock "
                    "sequence=%llu kr=%#x",
                    (unsigned long long)record->sequence, lockResult);
        return false;
    }
    uint8_t *destination = (uint8_t *)IOSurfaceGetBaseAddress(surface);
    uint64_t available = (uint64_t)IOSurfaceGetBytesPerRow(surface) *
        IOSurfaceGetHeight(surface);
    bool copied = destination != NULL && available >= record->vmSize;
    if (copied) memcpy(destination, payload, (size_t)record->vmSize);
    IOSurfaceUnlock(surface, 0, NULL);
    if (!copied) {
        ReceiverLog(@"final-composite-rejected stage=consumer-surface-storage "
                    "sequence=%llu bytes=%llu available=%llu",
                    (unsigned long long)record->sequence,
                    (unsigned long long)record->vmSize,
                    (unsigned long long)available);
    }
    return copied;
}

static void ReceiveAvailableMessages(void) {
    for (;;) {
        _Alignas(8) uint8_t bytes[
            sizeof(MacWSFinalCompositeMachMessage) + MAX_TRAILER_SIZE] = {0};
        MacWSFinalCompositeMachMessage *message =
            (MacWSFinalCompositeMachMessage *)bytes;
        mach_msg_return_t received = mach_msg(
            &message->header,
            MACH_RCV_MSG | MACH_RCV_TIMEOUT |
                MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
            0, sizeof(bytes), ReceivePort, 0, MACH_PORT_NULL);
        if (received == MACH_RCV_TIMED_OUT) break;
        if (received != MACH_MSG_SUCCESS) {
            ReceiverLog(@"final-composite receive failed kr=%d", received);
            break;
        }

        mach_port_t memoryObjectPort = message->memoryObjectPort.name;
        mach_msg_audit_trailer_t *trailer =
            (mach_msg_audit_trailer_t *)(bytes +
                round_msg(message->header.msgh_size));
        BOOL trailerValid =
            (uint8_t *)(trailer + 1) <= bytes + sizeof(bytes) &&
            trailer->msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0 &&
            trailer->msgh_trailer_size >= sizeof(*trailer);
        pid_t senderPID = trailerValid
            ? audit_token_to_pid(trailer->msgh_audit) : -1;
        BOOL envelopeValid =
            message->header.msgh_id ==
                MACWS_FINAL_COMPOSITE_MACH_MESSAGE_ID &&
            message->header.msgh_size == sizeof(*message) &&
            (message->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
            message->body.msgh_descriptor_count == 1 &&
            message->memoryObjectPort.type == MACH_MSG_PORT_DESCRIPTOR &&
            MACH_PORT_VALID(memoryObjectPort) && trailerValid;
        if (!envelopeValid) {
            BOOL receivedPortDescriptor =
                (message->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
                message->body.msgh_descriptor_count == 1 &&
                message->memoryObjectPort.type == MACH_MSG_PORT_DESCRIPTOR &&
                MACH_PORT_VALID(memoryObjectPort);
            if (receivedPortDescriptor)
                (void)mach_port_deallocate(mach_task_self(),
                                           memoryObjectPort);
            uint32_t witness = NextRejectWitness();
            if (witness <= 8) {
                ReceiverLog(@"final-composite-rejected stage=envelope "
                            "witness=%u id=%d size=%u bits=%#x "
                            "descriptors=%u type=%u port=%u trailer=%@",
                            witness, message->header.msgh_id,
                            message->header.msgh_size,
                            message->header.msgh_bits,
                            message->body.msgh_descriptor_count,
                            message->memoryObjectPort.type,
                            memoryObjectPort,
                            trailerValid ? @"valid" : @"invalid");
            }
            continue;
        }

        MacWSFinalCompositeRecord record = message->record;
        BOOL recordValid = MacWSFinalCompositeRecordIsValid(
            &record, sizeof(record));
        BOOL pidValid = record.producerPID == senderPID;
        BOOL producerValid = ProducerIsWindowServer(senderPID);
        if (!recordValid || !pidValid || !producerValid) {
            (void)mach_port_deallocate(mach_task_self(), memoryObjectPort);
            uint32_t witness = NextRejectWitness();
            if (witness <= 8) {
                char producerPath[PATH_MAX] = {0};
                (void)proc_pidpath(senderPID, producerPath,
                                  sizeof(producerPath));
                ReceiverLog(@"final-composite-rejected stage=identity "
                            "witness=%u record=%@ record-pid=%d sender-pid=%d "
                            "pid-match=%@ producer=%@ path=%s sequence=%llu "
                            "surface=%u",
                            witness, recordValid ? @"valid" : @"invalid",
                            record.producerPID, senderPID,
                            pidValid ? @"YES" : @"NO",
                            producerValid ? @"YES" : @"NO", producerPath,
                            (unsigned long long)record.sequence,
                            record.surfaceID);
            }
            continue;
        }

        // Freshness first: an obsolete frame costs nothing but a bounded map and
        // copy, and the replay catch-up path depends on this gate rejecting it.
        uint64_t requiredCompletionTime = atomic_load_explicit(
            &ReplayMinimumCompletionTime, memory_order_acquire);
        if (requiredCompletionTime != 0 &&
            record.completionTime < requiredCompletionTime) {
            (void)mach_port_deallocate(mach_task_self(), memoryObjectPort);
            uint32_t witness = NextRejectWitness();
            if (witness <= 8) {
                ReceiverLog(@"final-composite-rejected stage=freshness "
                            "witness=%u producer=%d sequence=%llu "
                            "completion=%llu required=%llu",
                            witness, senderPID,
                            (unsigned long long)record.sequence,
                            (unsigned long long)record.completionTime,
                            (unsigned long long)requiredCompletionTime);
            }
            continue;
        }

        mach_vm_address_t payloadAddress = 0;
        kern_return_t mapResult = mach_vm_map(
            mach_task_self(), &payloadAddress, (mach_vm_size_t)record.vmSize,
            0, VM_FLAGS_ANYWHERE, memoryObjectPort,
            (memory_object_offset_t)record.vmOffset, FALSE, VM_PROT_READ,
            VM_PROT_READ, VM_INHERIT_NONE);
        (void)mach_port_deallocate(mach_task_self(), memoryObjectPort);
        if (mapResult != KERN_SUCCESS || payloadAddress == 0) {
            uint32_t witness = NextRejectWitness();
            if (witness <= 8) {
                ReceiverLog(@"final-composite-rejected stage=vm-map "
                            "witness=%u producer=%d sequence=%llu "
                            "offset=%llu bytes=%llu kr=%#x",
                            witness, senderPID,
                            (unsigned long long)record.sequence,
                            (unsigned long long)record.vmOffset,
                            (unsigned long long)record.vmSize, mapResult);
            }
            continue;
        }

        IOSurfaceRef surface = AcquireConsumerSurface(&record);
        bool copied = surface && CopyPayloadIntoSurface(
            &record, (const void *)(uintptr_t)payloadAddress, surface);
        (void)mach_vm_deallocate(mach_task_self(), payloadAddress,
                                 (mach_vm_size_t)record.vmSize);
        if (!copied) {
            uint32_t witness = NextRejectWitness();
            if (witness <= 8) {
                ReceiverLog(@"final-composite-rejected stage=%@ "
                            "witness=%u producer=%d sequence=%llu "
                            "geometry=%ux%u bpr=%u",
                            surface ? @"consumer-copy" : @"consumer-surface",
                            witness, senderPID,
                            (unsigned long long)record.sequence, record.width,
                            record.height, record.bytesPerRow);
            }
            continue;
        }

        atomic_store_explicit(&FinalCompositeAccepted, true,
                              memory_order_release);
        uint32_t accepted = atomic_fetch_add_explicit(
            &AcceptedFrames, 1, memory_order_relaxed) + 1;
        if (accepted <= 8 || accepted % 128 == 0) {
            ReceiverLog(@"final-composite-accepted count=%u producer=%d "
                        "sequence=%llu geometry=%ux%u bpr=%u bytes=%llu "
                        "transport=vm consumer-surface=%u",
                        accepted, senderPID,
                        (unsigned long long)record.sequence, record.width,
                        record.height, record.bytesPerRow,
                        (unsigned long long)record.vmSize,
                        IOSurfaceGetID(surface));
        }
        if (AcceptedHandler) AcceptedHandler(surface, record);
    }
}

static void RequestFinalCompositeReplay(unsigned attempt,
                                        uint64_t generation) {
    if (generation != atomic_load_explicit(
            &ReplayRequestGeneration, memory_order_acquire)) return;
    if (atomic_load_explicit(&FinalCompositeAccepted, memory_order_acquire))
        return;
    mach_port_t service = MACH_PORT_NULL;
    kern_return_t lookup = bootstrap_look_up(
        bootstrap_port, MACWS_FINAL_COMPOSITE_REPLAY_MACH_SERVICE,
        &service);
    mach_msg_return_t sent = MACH_SEND_INVALID_DEST;
    if (lookup == BOOTSTRAP_SUCCESS && MACH_PORT_VALID(service)) {
        MacWSFinalCompositeReplayMachMessage message = {0};
        message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        message.header.msgh_size = sizeof(message);
        message.header.msgh_remote_port = service;
        message.header.msgh_local_port = MACH_PORT_NULL;
        message.header.msgh_id =
            MACWS_FINAL_COMPOSITE_REPLAY_MACH_MESSAGE_ID;
        message.record = (MacWSFinalCompositeReplayRecord) {
            .magic = MACWS_FINAL_COMPOSITE_REPLAY_MAGIC,
            .version = MACWS_FINAL_COMPOSITE_REPLAY_VERSION,
            .size = sizeof(MacWSFinalCompositeReplayRecord),
            .requesterPID = getpid(),
            .minimumCompletionTime = atomic_load_explicit(
                &ReplayMinimumCompletionTime, memory_order_acquire),
        };
        sent = mach_msg(&message.header,
                        MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                        sizeof(message), 0, MACH_PORT_NULL, 0,
                        MACH_PORT_NULL);
        (void)mach_port_deallocate(mach_task_self(), service);
    }
    ReceiverLog(@"final-composite-replay-request attempt=%u min-completion=%llu "
                "lookup=%#x service=%u send=%d", attempt + 1,
                (unsigned long long)atomic_load_explicit(
                    &ReplayMinimumCompletionTime, memory_order_acquire),
                lookup, service, sent);

    // WindowServer and displayd are independent launchd jobs.  Retry only for
    // a bounded startup window, and stop as soon as a validated final frame is
    // accepted.  This is recovery traffic, never a frame clock.
    static const int64_t retryDelaysNS[] = {
        250 * NSEC_PER_MSEC,
        750 * NSEC_PER_MSEC,
        2 * NSEC_PER_SEC,
        5 * NSEC_PER_SEC,
    };
    if (attempt < sizeof(retryDelaysNS) / sizeof(retryDelaysNS[0])) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     retryDelaysNS[attempt]),
                       ReceiverQueue, ^{
            RequestFinalCompositeReplay(attempt + 1, generation);
        });
    }
}

void MacWSRequestFinalCompositeReplay(uint64_t minimumCompletionTime) {
    if (!ReceiverQueue || !ReceiveSource) return;
    if (minimumCompletionTime == 0) minimumCompletionTime = 1;
    atomic_store_explicit(&ReplayMinimumCompletionTime,
                          minimumCompletionTime, memory_order_release);
    uint64_t generation = atomic_fetch_add_explicit(
        &ReplayRequestGeneration, 1, memory_order_acq_rel) + 1;
    atomic_store_explicit(&FinalCompositeAccepted, false,
                          memory_order_release);
    dispatch_async(ReceiverQueue, ^{
        RequestFinalCompositeReplay(0, generation);
    });
}

BOOL MacWSStartFinalCompositeReceiver(
        dispatch_queue_t queue,
        MacWSFinalCompositeAcceptedHandler acceptedHandler,
        MacWSFinalCompositeReceiverLogHandler logHandler) {
    if (!queue || ReceiveSource) return ReceiveSource != nil;
    AcceptedHandler = [acceptedHandler copy];
    LogHandler = [logHandler copy];
    ReceiverQueue = queue;
    atomic_store_explicit(&FinalCompositeAccepted, false,
                          memory_order_release);
    mach_port_t receivePort = MACH_PORT_NULL;
    kern_return_t result = bootstrap_check_in(
        bootstrap_port, MACWS_FINAL_COMPOSITE_MACH_SERVICE, &receivePort);
    if (result != BOOTSTRAP_SUCCESS || !MACH_PORT_VALID(receivePort)) {
        ReceiverLog(@"final-composite check-in failed service=%s kr=%d port=%u",
                    MACWS_FINAL_COMPOSITE_MACH_SERVICE, result, receivePort);
        return NO;
    }
    ReceivePort = receivePort;
    ReceiveSource = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)receivePort, 0, queue);
    dispatch_source_set_event_handler(ReceiveSource, ^{
        ReceiveAvailableMessages();
    });
    dispatch_resume(ReceiveSource);
    ReceiverLog(@"final-composite receiver-ready service=%s port=%u",
                MACWS_FINAL_COMPOSITE_MACH_SERVICE, receivePort);
    MacWSRequestFinalCompositeReplay(1);
    return YES;
}
