# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

"""Classes for local RPC server and remote client TCP/SSL servers."""

import aiohttp
import argparse
import asyncio
import base64
import contextlib
import functools
import itertools
import json
import logging
import os
import sqlite3
import sys
import time

from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from asyncio.exceptions import TimeoutError
from aiohttp.client_exceptions import ClientError
from aiorpcx import TaskGroup
from aiorpcx import (
    JSONRPCAutoDetect,
    JSONRPCConnection,
    Request,
    RPCError,
    RPCSession,
    handler_invocation,
    serve_rs,
    NewlineFramer,
)

from . import merkle
from .events import Event, subscribe_events

import typing as t

BAD_REQUEST = 1
DAEMON_ERROR = 2

MAX_CHUNK_SIZE = 2016


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cache-db")
    parser.add_argument("-n", "--network", default="bitcoin")
    return parser.parse_args()


ARGS = parse_args()


class Env:
    def __init__(self, genesis_header):
        self.genesis_hash = hash_to_hex_str(merkle.double_sha256(genesis_header))
        self.max_recv = 10**7
        self.max_send = 10**7
        self.donation_address = None


VERSION = os.environ.get("ELECTRUM_VERSION", "electrs/0.999")
HOST = os.environ.get("ELECTRUM_HOST", "localhost")
PORT = int(os.environ.get("ELECTRUM_PORT", 50001))
ZMQ_ADDR = os.environ.get("ZMQ_ADDR")

(DEFAULT_PORT, DEFAULT_DIR) = {
    "bitcoin": (8332, "~/.bitcoin"),
    "signet": (38332, "~/.bitcoin/signet"),
    "testnet4": (48332, "~/.bitcoin/testnet4"),
}[ARGS.network]

BITCOIND_URL = os.environ.get("BITCOIND_URL", f"http://localhost:{DEFAULT_PORT}")
BITCOIND_COOKIE_PATH = Path(
    os.environ.get("BITCOIND_COOKIE_PATH", f"{DEFAULT_DIR}/.cookie")
).expanduser()


class DummyContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        pass


class NotFound(Exception):
    pass


class UnavailableDaemon(Exception):
    pass


LOG = logging.getLogger()


class HttpClient:
    def __init__(self, client_session: aiohttp.ClientSession):
        self.session = client_session

    async def rest_get(self, path, f) -> dict:
        for _ in range(60):
            try:
                async with self.session.get(f"{BITCOIND_URL}/rest/{path}") as response:
                    if response.status == 503:
                        LOG.warning("bitcoind is unavailable: %s", response)
                        time.sleep(1)
                        continue
                    if response.status == 404:
                        raise NotFound(response.url)
                    response.raise_for_status()
                    return await f(response)
            except ClientError as e:
                LOG.warning("%s", e)
                time.sleep(1)
                continue
        raise UnavailableDaemon()

    async def json_rpc(self, method, *params) -> dict:
        for _ in range(60):
            if not BITCOIND_COOKIE_PATH.exists():
                LOG.warning("%s is missing", BITCOIND_COOKIE_PATH)
                continue

            headers = {
                "Authorization": f"Basic {base64.b64encode(BITCOIND_COOKIE_PATH.read_bytes()).decode()}",
            }
            data = json.dumps(
                {"method": method, "params": params, "id": 0, "jsonrpc": "2.0"}
            )
            async with self.session.post(
                BITCOIND_URL, headers=headers, data=data
            ) as response:
                if response.status == 503:
                    LOG.warning("bitcoind is unavailable: %s", response)
                    time.sleep(1)
                    continue
                response.raise_for_status()
                json_obj = await response.json()
                if err := json_obj.get("error"):
                    raise RPCError(DAEMON_ERROR, err)
                return json_obj["result"]

            response.raise_for_status()
        raise UnavailableDaemon()


class MissingPrevout(Exception):
    pass


@dataclass
class MempoolEntry:
    tx: dict
    scripthashes: set[bytes]  # input & output scripthashes
    fee: int  # in sats (may be inexact)


@dataclass
class MempoolUpdate:
    scripthashes: set[bytes]
    new_tip: bool


class Mempool:
    def __init__(self, http: HttpClient):
        self.zmq_messages = asyncio.Queue()  # ZMQ message queue
        self.tx_entries = {}  # txid->MempoolEntry
        self.by_scripthash: dict[bytes, set[str]] = {}  # hashX -> set[txid_hex]
        self.next_seq = None
        self.http = http

    async def try_get_tx(self, txid_hex: str) -> dict | None:
        path = f"tx/{txid_hex}.json"
        try:
            return await self.http.rest_get(path, lambda r: r.json())
        except NotFound:
            return None

    async def try_get_utxo(self, txid_hex: str, vout: int) -> dict | None:
        path = f"getutxos/{txid_hex}-{vout}.json"
        try:
            return await self.http.rest_get(path, lambda r: r.json())
        except NotFound:
            return None

    async def _get_entry(self, tx: dict) -> MempoolEntry:
        spks_hex = [txo["scriptPubKey"]["hex"] for txo in tx["vout"]]
        fee = -sum(txo["value"] for txo in tx["vout"])

        for txi in tx["vin"]:
            prev_txid = txi["txid"]
            prev_vout = txi["vout"]
            entry = self.tx_entries.get(prev_txid)
            if entry is not None:
                txo = entry.tx["vout"][prev_vout]
            else:
                res = await self.try_get_utxo(prev_txid, prev_vout)
                utxos = res and res["utxos"]
                if not utxos:
                    # probably a new/stale block
                    raise MissingPrevout(prev_txid, prev_vout)
                txo = utxos[0]

            spks_hex.append(txo["scriptPubKey"]["hex"])
            fee += txo["value"]

        scripthashes = set(
            (sha256(bytes.fromhex(spk_hex)).digest() for spk_hex in spks_hex)
        )
        fee = round(fee * 1e8)  # good enough for fee estimation
        assert fee >= 0
        return MempoolEntry(tx, scripthashes, fee)

    async def add_tx(self, txid_hex: str, tx, scripthashes: set[bytes]):
        assert txid_hex == tx["txid"]
        if txid_hex in self.tx_entries:
            LOG.warning("add: tx %s already exists", txid_hex)
            return

        entry = await self._get_entry(tx)

        # collect input and output scripthashes for the added tx
        scripthashes.update(entry.scripthashes)

        for scripthash in entry.scripthashes:
            self.by_scripthash.setdefault(scripthash, set()).add(txid_hex)
        self.tx_entries[txid_hex] = entry

    def remove_tx(self, txid_hex: str, scripthashes: set[bytes]):
        entry = self.tx_entries.pop(txid_hex, None)
        if entry is None:
            LOG.warning("remove: tx %s not found", txid_hex)
            return

        # collect input and output scripthashes for the removed tx
        scripthashes.update(entry.scripthashes)

        for scripthash in entry.scripthashes:
            txids = self.by_scripthash.get(scripthash)
            if txids is not None:
                txids.discard(txid_hex)
                if not txids:
                    self.by_scripthash.pop(scripthash)

    def enqueue_message(self, *args):
        self.zmq_messages.put_nowait(args)

    async def resync(self, scripthashes: set[bytes]):
        t = time.time()
        resp = await self.http.rest_get(
            "mempool/contents.json?mempool_sequence=true&verbose=false",
            lambda r: r.json(),
        )
        new_txids = resp["txids"]
        new_txids_set = set(new_txids)
        old_txids_set = set(self.tx_entries)
        for txid_hex in old_txids_set - new_txids_set:
            # transaction is removed from mempool
            self.remove_tx(txid_hex, scripthashes=scripthashes)

        next_report = time.time() + 1  # at most once per second
        # iterate over new txids in original order
        total_size = 0
        for i, txid_hex in enumerate(new_txids):
            if txid_hex in old_txids_set:
                continue
            if time.time() > next_report:
                LOG.info(
                    "fetched %d mempool txs [%.1f%%] %.3f MB",
                    i,
                    100.0 * i / len(new_txids),
                    total_size / 1e6,
                )
                next_report += 1
            if tx := await self.try_get_tx(txid_hex):
                # transaction is added to mempool
                await self.add_tx(txid_hex, tx, scripthashes=scripthashes)
                total_size += tx["size"]

        # marks that mempool resync is over
        self.next_seq = resp["mempool_sequence"]
        LOG.info(
            "fetched %d mempool txs, next_seq=%s (%.3fs)",
            len(self.tx_entries),
            self.next_seq,
            time.time() - t,
        )

    def get_zmq_message(self) -> tuple | None:
        try:
            return self.zmq_messages.get_nowait()
        except asyncio.QueueEmpty:
            return None

    async def update(self) -> MempoolUpdate:
        t = time.time()
        result = MempoolUpdate(scripthashes=set(), new_tip=False)

        # Handle a batch of ZMQ messages (without blocking)
        # If a block is found, drop all previous mempool events (since we'll resync mempool anyway)
        messages = []
        for event, hash_hex, mempool_seq in iter(self.get_zmq_message, None):
            if event in (Event.BLOCK_CONNECT, Event.BLOCK_DISCONNECT):
                LOG.info("block %s event [%s]", hash_hex, chr(event))
                # resync mempool after new/stale block
                self.next_seq = None
                # will trigger `bindex` update and lookup
                result.new_tip = True
                messages.clear()
            else:
                assert mempool_seq is not None
                messages.append((event, hash_hex, mempool_seq))

        if self.next_seq is None and ZMQ_ADDR:
            # We are out of sync - resync mempool transactions (using REST API)
            await self.resync(scripthashes=result.scripthashes)

        stats = defaultdict(int)
        for event, hash_hex, mempool_seq in messages:
            if mempool_seq < self.next_seq:
                continue
            if mempool_seq > self.next_seq:
                LOG.warning("skipped seq: %d > %d", mempool_seq, self.next_seq)

            if event is Event.TX_ADD:
                if tx := await self.try_get_tx(hash_hex):
                    await self.add_tx(
                        hash_hex,
                        tx,
                        scripthashes=result.scripthashes,
                    )
            elif event is Event.TX_REMOVE:
                self.remove_tx(hash_hex, scripthashes=result.scripthashes)
            else:
                raise NotImplementedError(event)

            LOG.debug("%s @ %d (%s)", hash_hex, mempool_seq, event)
            self.next_seq = mempool_seq + 1
            stats[event] += 1

        LOG.info(
            "handled %d events: %d txs, seq=%s (%.3fs) %s",
            len(messages),
            len(self.tx_entries),
            self.next_seq,
            time.time() - t,
            ", ".join(f"{chr(k)}={v}" for k, v in stats.items()),
        )

        return result


class Manager:
    def __init__(self, http: HttpClient):
        self.db = sqlite3.connect(ARGS.cache_db)
        self.merkle = merkle.Merkle()
        self.subscription_queue = asyncio.Queue()
        self.mempool = Mempool(http)
        self.http = http
        self.sessions: set[ElectrumSession] = set()

    async def notify_sessions(self):
        for session in self.sessions:
            try:
                await session.notify()
            except Exception:
                LOG.exception("failed to notify session #%d", session.session_id)

    async def latest_header(self) -> dict:
        j = await self.chaininfo()
        height = j["blocks"]
        raw = await self.raw_header(height)
        return {"hex": raw.hex(), "height": height}

    async def chaininfo(self):
        return await self.http.rest_get("chaininfo.json", lambda r: r.json())

    async def get_history(self, hashx: bytes) -> list[dict]:
        query = """
SELECT DISTINCT
    t.tx_id,
    t.block_height
FROM
    transactions t,
    history h
WHERE
    t.block_offset = h.block_offset AND
    t.block_height = h.block_height AND
    h.script_hash = ?
ORDER BY
    t.block_height ASC,
    t.block_offset ASC
"""
        result = []

        confirmed = (
            (hash_to_hex_str(txid), height)
            for txid, height in self.db.execute(query, [hashx]).fetchall()
        )
        for tx_hash, height in confirmed:
            result.append({"tx_hash": tx_hash, "height": height})

        unconfirmed = (
            (txid_hex, self.mempool.tx_entries[txid_hex].fee)
            for txid_hex in self.mempool.by_scripthash.get(hashx, ())
        )
        for tx_hash, fee in sorted(unconfirmed):
            result.append({"tx_hash": tx_hash, "height": 0, "fee": fee})

        return result

    async def subscribe(self, hashX: bytes):
        event = asyncio.Event()
        await self.subscription_queue.put((hashX, event.set))
        await event.wait()

    async def _merkle_branch(self, height, tx_hashes, tx_pos):
        branch, _root = self.merkle.branch_and_root(tx_hashes, tx_pos)
        branch = [hash_to_hex_str(hash) for hash in branch]
        return branch

    async def merkle_branch_for_tx_hash(self, height, tx_hash):
        """Return a triple (branch, tx_pos)."""
        tx_hashes = await self.tx_hashes_at_blockheight(height)
        try:
            tx_pos = tx_hashes.index(tx_hash)
        except ValueError:
            raise RPCError(
                BAD_REQUEST,
                f"tx {hash_to_hex_str(tx_hash)} not in block at height {height:,d}",
            )
        branch = await self._merkle_branch(height, tx_hashes, tx_pos)
        return branch, tx_pos

    async def tx_hashes_at_blockheight(self, height):
        """Returns a pair (tx_hashes).

        tx_hashes is an ordered list of binary hashes.  Raises RPCError.
        """

        h = await self.http.rest_get(
            f"blockhashbyheight/{height}.hex", lambda r: r.text()
        )
        j = await self.http.rest_get(f"block/notxdetails/{h}.json", lambda r: r.json())
        tx_hashes = [hex_str_to_hash(h) for h in j["tx"]]
        return tx_hashes

    async def getrawtransaction(self, tx_hash, verbose) -> str:
        assert verbose is False
        rows = self.db.execute(
            "SELECT tx_bytes FROM transactions WHERE tx_id = ?", [tx_hash]
        ).fetchall()
        if len(rows) == 1:
            return rows[0][0].hex()

        if entry := self.mempool.tx_entries.get(hash_to_hex_str(tx_hash)):
            return entry.tx["hex"]

        raise RPCError(BAD_REQUEST, f"{tx_hash.hex()} not found")

    async def raw_header(self, height: int):
        raw, _ = await self.raw_headers(height, count=1)
        return raw

    async def raw_headers(self, height: int, count: int):
        chunks = []
        while count > 0:
            h = await self.http.rest_get(
                f"blockhashbyheight/{height}.hex", lambda r: r.text()
            )
            chunk_size = min(count, MAX_CHUNK_SIZE // 2)
            chunk = await self.http.rest_get(
                f"headers/{chunk_size}/{h}.bin", lambda r: r.read()
            )
            assert len(chunk) % 80 == 0
            chunk_size = len(chunk) // 80
            assert chunk_size <= count
            chunks.append(chunk)
            height += chunk_size
            count -= chunk_size

        raw = b"".join(chunks)
        return raw, len(raw) // 80


HASHX_LEN = 32


hex_to_bytes = bytes.fromhex


def hash_to_hex_str(x):
    """Convert a big-endian binary hash to displayed hex string.

    Display form of a binary hash is reversed and converted to hex.
    """
    return bytes(reversed(x)).hex()


def hex_str_to_hash(x: str) -> bytes:
    """Convert a displayed hex string to a binary hash."""
    return bytes(reversed(hex_to_bytes(x)))


def scripthash_to_hashX(scripthash: str):
    try:
        bin_hash = hex_str_to_hash(scripthash)
        if len(bin_hash) == 32:
            return bin_hash[:HASHX_LEN]
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f"{scripthash} is not a valid script hash")


def non_negative_integer(value):
    """Return param value it is or can be converted to a non-negative
    integer, otherwise raise an RPCError."""
    try:
        value = int(value)
        if value >= 0:
            return value
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f"{value} should be a non-negative integer")


def assert_boolean(value):
    """Return param value it is boolean otherwise raise an RPCError."""
    if value in (False, True):
        return value
    raise RPCError(BAD_REQUEST, f"{value} should be a boolean value")


def assert_tx_hash(value):
    """Raise an RPCError if the value is not a valid hexadecimal transaction hash.

    If it is valid, return it as 32-byte binary hash.
    """
    try:
        raw_hash = hex_str_to_hash(value)
        if len(raw_hash) == 32:
            return raw_hash
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f"{value} should be a transaction hash")


class SessionBase(RPCSession):
    """Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    """

    log_me = False
    initial_concurrent = 100

    session_counter = itertools.count()

    def __init__(
        self,
        transport,
        env,
    ):
        connection = JSONRPCConnection(JSONRPCAutoDetect)
        super().__init__(transport, connection=connection)
        self.env = env
        self.txs_sent = 0
        self.session_id = None
        self.session_id = next(self.session_counter)
        self.logger = logging.getLogger()
        self.request_handlers = {}

    def default_framer(self):
        return NewlineFramer(max_size=self.env.max_recv)

    async def connection_lost(self):
        """Handle client disconnection."""
        await super().connection_lost()
        msg = ""
        if self._incoming_concurrency.max_concurrent < self.initial_concurrent * 0.8:
            msg += " whilst throttled"
        if self.send_size >= 1_000_000:
            msg += f".  Sent {self.send_size:,d} bytes in {self.send_count:,d} messages"
        if msg:
            msg = "disconnected" + msg
            self.logger.info(msg)

    async def handle_request(self, request):
        """Handle an incoming request.  ElectrumX doesn't receive
        notifications from client sessions.
        """
        if isinstance(request, Request):
            handler = self.request_handlers.get(request.method)
        else:
            handler = None

        coro = handler_invocation(handler, request)()
        return await coro


def version_string(ptuple):
    """Convert a version tuple such as (1, 2) to "1.2".
    There is always at least one dot, so (1, ) becomes "1.0"."""
    while len(ptuple) < 2:
        ptuple += (0,)
    return ".".join(str(p) for p in ptuple)


class ElectrumSession(SessionBase):
    """A TCP server that handles incoming Electrum connections."""

    PROTOCOL_MIN = (1, 4)
    PROTOCOL_MAX = (1, 4, 3)

    def __init__(self, *args, mgr: Manager, **kwargs):
        super().__init__(*args, **kwargs)
        self.manager = mgr
        self.subscribe_headers: dict | None = None
        self.connection.max_response_size = self.env.max_send
        self.hashX_subs = {}
        self.sv_seen = False
        self.set_request_handlers()
        self.is_peer = False
        self.protocol_tuple = self.PROTOCOL_MIN
        self.manager.sessions.add(self)

    async def connection_lost(self):
        """Handle client disconnection."""
        await super().connection_lost()
        self.manager.sessions.remove(self)

    @classmethod
    def protocol_min_max_strings(cls):
        return [version_string(ver) for ver in (cls.PROTOCOL_MIN, cls.PROTOCOL_MAX)]

    @classmethod
    def server_features(cls, env):
        """Return the server features dictionary."""
        min_str, max_str = cls.protocol_min_max_strings()
        return {
            "hosts": {},
            "pruning": None,
            "server_version": VERSION,
            "protocol_min": min_str,
            "protocol_max": max_str,
            "genesis_hash": env.genesis_hash,
            "hash_function": "sha256",
            "services": [],
        }

    async def server_features_async(self):
        return self.server_features(self.env)

    @classmethod
    def server_version_args(cls):
        return [VERSION, cls.protocol_min_max_strings()]

    def protocol_version_string(self):
        return version_string(self.protocol_tuple)

    def unsubscribe_hashX(self, hashX):
        return self.hashX_subs.pop(hashX, None)

    async def subscribe_headers_result(self) -> dict:
        return await self.manager.latest_header()

    async def headers_subscribe(self):
        self.subscribe_headers = await self.subscribe_headers_result()
        return self.subscribe_headers

    async def add_peer(self, features):
        pass

    async def peers_subscribe(self):
        return []

    async def address_status(self, hashX):
        entries = await self.manager.get_history(hashX)
        status = "".join(f"{e['tx_hash']}:{e['height']:d}:" for e in entries)
        return merkle.sha256(status.encode()).hex() if status else None

    async def hashX_subscribe(self, hashX, alias):
        await self.manager.subscribe(hashX)

        # Store the subscription only after address_status succeeds
        result = await self.address_status(hashX)
        self.hashX_subs[hashX] = result
        return result

    async def notify(self):
        if self.subscribe_headers is not None:
            new_result = await self.subscribe_headers_result()
            if self.subscribe_headers != new_result:
                self.subscribe_headers = new_result
                await self.send_notification(
                    "blockchain.headers.subscribe", (new_result,)
                )

        for hashX in list(self.hashX_subs):
            new_status = await self.address_status(hashX)
            status = self.hashX_subs[hashX]
            if status != new_status:
                self.hashX_subs[hashX] = new_status
                await self.send_notification(
                    "blockchain.scripthash.subscribe", (hashX, new_status)
                )

    async def confirmed_history(self, hashX):
        return await self.manager.get_history(hashX)

    async def scripthash_get_history(self, scripthash):
        hashX = scripthash_to_hashX(scripthash)
        return await self.confirmed_history(hashX)

    async def scripthash_subscribe(self, scripthash):
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_subscribe(hashX, scripthash)

    async def scripthash_unsubscribe(self, scripthash):
        hashX = scripthash_to_hashX(scripthash)
        return self.unsubscribe_hashX(hashX) is not None

    async def block_header(self, height):
        height = non_negative_integer(height)
        raw_header_hex = (await self.manager.raw_header(height)).hex()
        return raw_header_hex

    async def block_headers(self, start_height, count):
        start_height = non_negative_integer(start_height)
        count = non_negative_integer(count)

        max_size = MAX_CHUNK_SIZE
        count = min(count, max_size)
        headers, count = await self.manager.raw_headers(start_height, count)
        result = {"hex": headers.hex(), "count": count, "max": max_size}
        return result

    async def donation_address(self):
        return self.env.donation_address

    async def banner(self):
        return ""

    async def relayfee(self):
        return 0

    async def estimatefee(self, number, mode=None):
        return 0

    async def ping(self):
        return None

    async def server_version(self, client_name="", protocol_version=None):
        return VERSION, self.protocol_version_string()

    async def transaction_get(self, tx_hash, verbose=False):
        tx_hash = assert_tx_hash(tx_hash)
        if verbose not in (True, False):
            raise RPCError(BAD_REQUEST, '"verbose" must be a boolean')

        return await self.manager.getrawtransaction(tx_hash, verbose)

    async def transaction_merkle(self, tx_hash, height):
        tx_hash = assert_tx_hash(tx_hash)
        height = non_negative_integer(height)

        branch, tx_pos = await self.manager.merkle_branch_for_tx_hash(height, tx_hash)
        return {"block_height": height, "merkle": branch, "pos": tx_pos}

    async def transaction_broadcast(self, tx_hex):
        assert hex_to_bytes(tx_hex)
        txid = await self.manager.http.json_rpc("sendrawtransaction", tx_hex)
        assert_tx_hash(txid)
        return txid

    async def compact_fee_histogram(self):
        return []

    def set_request_handlers(self):
        handlers = {
            "blockchain.block.header": self.block_header,
            "blockchain.block.headers": self.block_headers,
            "blockchain.estimatefee": self.estimatefee,
            "blockchain.headers.subscribe": self.headers_subscribe,
            "blockchain.relayfee": self.relayfee,
            "blockchain.scripthash.get_history": self.scripthash_get_history,
            "blockchain.scripthash.subscribe": self.scripthash_subscribe,
            "blockchain.transaction.get": self.transaction_get,
            "blockchain.transaction.get_merkle": self.transaction_merkle,
            "blockchain.transaction.broadcast": self.transaction_broadcast,
            "mempool.get_fee_histogram": self.compact_fee_histogram,
            "server.add_peer": self.add_peer,
            "server.banner": self.banner,
            "server.donation_address": self.donation_address,
            "server.features": self.server_features_async,
            "server.peers.subscribe": self.peers_subscribe,
            "server.ping": self.ping,
            "server.version": self.server_version,
        }
        handlers["blockchain.scripthash.unsubscribe"] = self.scripthash_unsubscribe

        self.request_handlers = handlers


async def get_items(
    q: asyncio.Queue, timeout=1.0
) -> list[tuple[bytes, t.Callable[[], None]]]:
    items = []
    try:
        while True:
            item = await asyncio.wait_for(q.get(), timeout)
            items.append(item)
            while not q.empty():
                items.append(q.get_nowait())
            # use a shorter timeout for coalescing subsequent subscriptions
            timeout = 0.01
    except TimeoutError:
        pass
    return items


@contextlib.contextmanager
def transaction(c: sqlite3.Cursor):
    # update bindex DB with the new scripthashes
    c.execute("BEGIN")
    try:
        yield
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise


def update_scripthashes(c: sqlite3.Cursor, scripthashes):
    # update bindex DB with the new scripthashes
    with transaction(c):
        r = c.executemany(
            "INSERT OR IGNORE INTO watch (script_hash) VALUES (?)",
            [(s,) for s in scripthashes],
        )
        if r.rowcount:
            LOG.info("watching %d new addresses", r.rowcount)


def get_scripthashes(c: sqlite3.Cursor) -> set[bytes]:
    c.execute("SELECT script_hash FROM watch")
    return set(s for (s,) in c.fetchall())


class Indexer:
    """Handle `bindex` connection."""

    def __init__(self):
        self.tip = None
        self._loop = asyncio.get_running_loop()

    async def _read_tip(self) -> str:
        """Wait for `bindex` to finish current indexing iteration, and return current chain tip hash."""
        line = await self._loop.run_in_executor(None, sys.stdin.readline)
        return line.strip()

    async def _notify_bindex(self):
        """Notify `bindex` to run another indexing iteration."""

        def write_fn():
            sys.stdout.write("\n")
            sys.stdout.flush()

        await self._loop.run_in_executor(None, write_fn)

    @classmethod
    async def start(cls) -> "Indexer":
        i = Indexer()
        i.tip = await i._read_tip()  # wait for initial index sync
        LOG.info("indexer at block=%r", i.tip)
        return i

    async def sync(self) -> bool:
        prev_tip = self.tip
        # update `bindex` (start an indexing iteration)
        await self._notify_bindex()
        self.tip = await self._read_tip()  # wait for the indexing iteration to finish
        LOG.debug("indexer at block=%r", self.tip)
        return prev_tip != self.tip


async def subscription_task(mgr: Manager, indexer: Indexer):
    try:
        # sending new scripthashes on subscription requests
        while True:
            reqs = await get_items(mgr.subscription_queue)
            update_scripthashes(mgr.db.cursor(), scripthashes=[s for s, _ in reqs])

            # update `bindex`
            chain_updated = await indexer.sync()

            # update mempool via ZMQ notifications (or resync, if needed)
            mempool_update = await mgr.mempool.update()

            if reqs or chain_updated:
                LOG.info("indexer at block=%r: %d reqs", indexer.tip, len(reqs))

            # mark subscription requests as done
            for _, fn in reqs:
                fn()

            # make sure all sessions are notified
            watched = get_scripthashes(mgr.db.cursor())
            if chain_updated or mempool_update.scripthashes.intersection(watched):
                await mgr.notify_sessions()
    except Exception:
        LOG.exception("sync_task() failed")


async def main():
    FMT = "[%(asctime)-27s %(levelname)-5s %(module)s] %(message)s"
    logging.basicConfig(level="INFO", format=FMT)

    async with aiohttp.ClientSession() as session:
        http = HttpClient(session)

        info = await http.rest_get("chaininfo.json", lambda r: r.json())
        chain = info["chain"]
        blocks = info["blocks"]
        logging.info("Electrum server '%s' @ %s:%s", VERSION, HOST, PORT)
        logging.info("Bitcoin Core %s @ %s, %d blocks", chain, BITCOIND_URL, blocks)

        info = await http.json_rpc("getblockchaininfo")
        assert info["chain"] == chain

        indexer = await Indexer.start()  # wait for initial index sync
        mgr = Manager(http)
        env = Env(await mgr.raw_header(0))
        cls = functools.partial(ElectrumSession, env=env, mgr=mgr)
        await serve_rs(cls, host=HOST, port=PORT)
        async with TaskGroup() as g:
            await g.spawn(subscription_task(mgr, indexer))
            if ZMQ_ADDR:
                # calls Mempool.notify() when ZMQ message is received
                await g.spawn(subscribe_events(ZMQ_ADDR, mgr.mempool.enqueue_message))
            else:
                logging.warning("Set ZMQ_ADDR to sync mempool")
            await g.join()


if __name__ == "__main__":
    asyncio.run(main())
