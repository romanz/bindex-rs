#!/usr/bin/env python3
import enum
import logging
import struct

import zmq
import zmq.asyncio

LOG = logging.getLogger(__name__)


class Event(enum.IntEnum):
    TX_ADD = ord("A")
    TX_REMOVE = ord("R")
    BLOCK_CONNECT = ord("C")
    BLOCK_DISCONNECT = ord("D")


PREFIX_FMT = "32s1s"
PREFIX_LEN = struct.calcsize(PREFIX_FMT)


async def subscribe_events(addr: str, emit_fn):
    try:
        ctx = zmq.asyncio.Context()

        sub = ctx.socket(zmq.SUB)
        sub.setsockopt(zmq.RCVHWM, 0)
        sub.setsockopt_string(zmq.SUBSCRIBE, "sequence")
        sub.connect(addr)

        next_seq = None
        while True:
            topic, body, seq = await sub.recv_multipart()
            seq = int.from_bytes(seq, "little")
            if next_seq is not None and next_seq != seq:
                LOG.warning("sequence # skipped: %d -> %d", next_seq, seq)
            next_seq = seq + 1
            if topic == b"sequence":
                hash, event = struct.unpack(PREFIX_FMT, body[:PREFIX_LEN])
                mempool_seq = body[PREFIX_LEN:]
                emit_fn(
                    Event(event[0]),
                    hash.hex(),
                    int.from_bytes(mempool_seq, "little") if mempool_seq else None,
                )
    except Exception:
        LOG.exception("subscribe_events() failed")
