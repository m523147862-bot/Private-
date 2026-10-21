#ifndef MACWS_FINAL_COMPOSITE_PROTOCOL_H
#define MACWS_FINAL_COMPOSITE_PROTOCOL_H

#include <stdbool.h>
#include <mach/mach.h>
#include <stddef.h>
#include <stdint.h>

// WindowServer's coexist compositor already finishes each native AGX frame
// into a process-owned linear BGRA IOSurface.  VNC consumes a CPU copy of that
// final surface, which proves that it contains SkyLight effects absent from an
// exact-window DisplayStream: external shadows, backdrop materials and warped
// window animations.  Keep those final pixels and hand them to macwsdisplayd so
// fullscreen Host presentation needs neither RFB nor a Host-side upload.
//
// The pixels do NOT travel as the IOSurface itself.  On this kernel every
// IOSurface registry lookup is task-local (patches/a57e-P1-surface-registry-
// boundary-20261022.md: two entitled native processes, port lookup and ID
// lookup both NULL, kIOSurfaceIsGlobal included), so version 2 ships the
// backing bytes through a Mach memory object instead: the publisher copies the
// frame into an anonymous mapping it made a memory entry out of, and forwards
// that memory object's send right in this message.  displayd maps it read-only,
// copies it into a surface it owns, and drives its own scanout from there.
#define MACWS_FINAL_COMPOSITE_MAGIC 0x4d574643u /* "MWFC" */
#define MACWS_FINAL_COMPOSITE_VERSION 2u
#define MACWS_FINAL_COMPOSITE_MACH_SERVICE \
    "com.macwsguide.display.final-composite"
#define MACWS_FINAL_COMPOSITE_MACH_MESSAGE_ID 0x4d574643
#define MACWS_FINAL_COMPOSITE_REPLAY_MACH_SERVICE \
    "com.macwsguide.windowserver.final-composite-replay"
#define MACWS_FINAL_COMPOSITE_REPLAY_MACH_MESSAGE_ID 0x4d574652

#define MACWS_FINAL_COMPOSITE_MAX_DIMENSION 16384u
#define MACWS_FINAL_COMPOSITE_MAX_BYTES_PER_ROW \
    (MACWS_FINAL_COMPOSITE_MAX_DIMENSION * 16u)
#define MACWS_FINAL_COMPOSITE_BGRA 0x42475241u
#define MACWS_FINAL_COMPOSITE_METAL_BGRA8_UNORM 80u

// Value of MacWSFinalCompositeRecord.transport.  1 was the version-1
// surface-port transport; it is retired because the receiver can never resolve
// a surface created in another task on this host.  2 is a Mach memory object
// carrying the frame's bytes (see the comment above).
#define MACWS_FINAL_COMPOSITE_TRANSPORT_VM 2u

// The stripped iPhoneOS SDK used by the on-device Theos build omits
// servers/bootstrap.h even though these libSystem exports are present.
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(
    mach_port_t bootstrapPort, const char *serviceName,
    mach_port_t *servicePort);
extern kern_return_t bootstrap_check_in(
    mach_port_t bootstrapPort, const char *serviceName,
    mach_port_t *receivePort);
#ifndef BOOTSTRAP_SUCCESS
#define BOOTSTRAP_SUCCESS KERN_SUCCESS
#endif

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    int32_t producerPID;
    // The producer's own surface, kept as the frame's identity witness in logs
    // and state files.  The receiver never resolves it: the bytes arrive in
    // the memory object below.
    uint32_t surfaceID;
    uint64_t sequence;
    uint64_t completionTime;
    // Byte offset of this frame inside the received memory object, and the
    // number of frame bytes that are valid from there on.  The publisher maps
    // one frame per object today, so vmOffset is 0 and vmSize is
    // bytesPerRow * height; the receiver maps from the record, not from a
    // hardcoded zero.
    uint64_t vmOffset;
    uint64_t vmSize;
    uint32_t width;
    uint32_t height;
    uint32_t bytesPerRow;
    uint32_t ioSurfacePixelFormat;
    uint32_t metalPixelFormat;
    uint32_t transport;
} MacWSFinalCompositeRecord;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    // Send right of the Mach memory object whose pages hold this frame
    // (mach_make_memory_entry_64 in the publisher).  The receiver turns it into
    // a read-only mapping, copies out the bytes and drops the right.
    mach_msg_port_descriptor_t memoryObjectPort;
    MacWSFinalCompositeRecord record;
} MacWSFinalCompositeMachMessage;

// displayd is independently restartable.  A one-way producer push leaves a
// relaunched receiver on the exact-window fallback until WindowServer happens
// to submit another owned scanout.  This authenticated, payload-free request
// asks the live producer to snapshot its latest completed scanout again.  The
// response remains the normal surface message above, so there is only one
// ownership and validation path for final-composite frames.
#define MACWS_FINAL_COMPOSITE_REPLAY_MAGIC 0x4d574652u /* "MWFR" */
#define MACWS_FINAL_COMPOSITE_REPLAY_VERSION 1u
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    int32_t requesterPID;
    uint32_t reserved;
    // Earliest producer-side completion timestamp acceptable to the caller.
    // Startup uses 1 (latest available snapshot). Mutation catch-up uses the
    // earliest producer completion causally compatible with the catalog
    // observation. The receiver may subtract one runtime-measured, bounded
    // observation latency because displayd necessarily sees the topology
    // after the compositor command which created it has completed.
    uint64_t minimumCompletionTime;
} MacWSFinalCompositeReplayRecord;

typedef struct {
    mach_msg_header_t header;
    MacWSFinalCompositeReplayRecord record;
} MacWSFinalCompositeReplayMachMessage;

static inline bool MacWSFinalCompositeReplayRecordIsValid(
        const MacWSFinalCompositeReplayRecord *record, size_t byteCount) {
    return record && byteCount == sizeof(*record) &&
        record->magic == MACWS_FINAL_COMPOSITE_REPLAY_MAGIC &&
        record->version == MACWS_FINAL_COMPOSITE_REPLAY_VERSION &&
        record->size == sizeof(*record) && record->requesterPID > 1 &&
        record->reserved == 0 && record->minimumCompletionTime != 0;
}

static inline bool MacWSFinalCompositeRecordIsValid(
        const MacWSFinalCompositeRecord *record, size_t byteCount) {
    if (!record || byteCount != sizeof(*record) ||
        record->magic != MACWS_FINAL_COMPOSITE_MAGIC ||
        record->version != MACWS_FINAL_COMPOSITE_VERSION ||
        record->size != sizeof(*record) || record->producerPID <= 1 ||
        record->surfaceID == 0 || record->sequence == 0 ||
        record->completionTime == 0 || record->width == 0 ||
        record->height == 0 ||
        record->width > MACWS_FINAL_COMPOSITE_MAX_DIMENSION ||
        record->height > MACWS_FINAL_COMPOSITE_MAX_DIMENSION ||
        record->bytesPerRow > MACWS_FINAL_COMPOSITE_MAX_BYTES_PER_ROW ||
        record->ioSurfacePixelFormat != MACWS_FINAL_COMPOSITE_BGRA ||
        record->metalPixelFormat !=
            MACWS_FINAL_COMPOSITE_METAL_BGRA8_UNORM ||
        record->transport != MACWS_FINAL_COMPOSITE_TRANSPORT_VM ||
        record->vmOffset != 0)
        return false;
    if (record->bytesPerRow < record->width * 4u) return false;
    // The payload is exactly the published geometry: a memory object that is
    // smaller would be a partial frame and a larger one would hide a stale or
    // mismatched descriptor.
    return record->vmSize == (uint64_t)record->bytesPerRow * record->height;
}

#if defined(__cplusplus)
static_assert(sizeof(MacWSFinalCompositeRecord) == 72,
              "MacWS final composite record ABI");
#else
_Static_assert(sizeof(MacWSFinalCompositeRecord) == 72,
               "MacWS final composite record ABI");
#endif

#if defined(__cplusplus)
static_assert(sizeof(MacWSFinalCompositeReplayRecord) == 24,
              "MacWS final composite replay record ABI");
#else
_Static_assert(sizeof(MacWSFinalCompositeReplayRecord) == 24,
               "MacWS final composite replay record ABI");
#endif

#endif
