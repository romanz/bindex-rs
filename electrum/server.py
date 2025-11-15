# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

"""Classes for local RPC server and remote client TCP/SSL servers."""

import aiohttp
import asyncio
import base64
import functools
import itertools
import json
import logging
import os
import sqlite3
import sys
import time

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

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

(CACHE_DB,) = sys.argv[1:]


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

BITCOIND_URL = os.environ.get("BITCOIND_URL", "http://localhost:8332")
BITCOIND_COOKIE_PATH = Path(
    os.environ.get("BITCOIND_COOKIE_PATH", "~/.bitcoin/.cookie")
).expanduser()


class DummySession:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        pass


async def rest_get(path, f, ignore=(), session=None):
    ctx = aiohttp.ClientSession() if session is None else DummySession(session)
    async with ctx as session:
        for _ in range(60):
            try:
                async with session.get(f"{BITCOIND_URL}/rest/{path}") as response:
                    if response.status in ignore:
                        return None
                    if response.status == 503:
                        LOG.warning("bitcoind is unavailable: %s", response)
                        time.sleep(1)
                        continue
                    response.raise_for_status()
                    return await f(response)
            except aiohttp.client_exceptions.ClientError as e:
                LOG.warning("%s", e)
                time.sleep(1)
                continue


async def json_rpc(method, *params):
    for _ in range(60):
        async with aiohttp.ClientSession() as session:
            if not BITCOIND_COOKIE_PATH.exists():
                LOG.warning("%s is missing", BITCOIND_COOKIE_PATH)
                continue

            headers = {
                "Authorization": f"Basic {base64.b64encode(BITCOIND_COOKIE_PATH.read_bytes()).decode()}",
            }
            data = json.dumps(
                {"method": method, "params": params, "id": 0, "jsonrpc": "2.0"}
            )
            async with session.post(
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


LOG = logging.getLogger()


def try_get_tx(txid_hex: str, session=None) -> t.Awaitable[dict | None]:
    path = f"tx/{txid_hex}.json"
    result = rest_get(path, lambda r: r.json(), ignore=(404,), session=session)
    if result is None:
        LOG.warning("'%s' not found", path)
    return result


def try_get_utxo(txid_hex: str, vout: int, session=None) -> t.Awaitable[dict | None]:
    path = f"getutxos/{txid_hex}-{vout}.json"
    result = rest_get(path, lambda r: r.json(), ignore=(404,), session=session)
    if result is None:
        LOG.warning("'%s' not found", path)
    return result


class MissingPrevout(Exception):
    pass


@dataclass
class MempoolEntry:
    tx: dict
    scripthashes: tuple[bytes]
    fee: int  # in sats (may be inexact)


@dataclass
class MempoolUpdate:
    scripthashes: set[bytes]
    new_tip: bool


class Mempool:
    def __init__(self):
        self.notifications = asyncio.Queue()
        self.tx_entries = {}  # txid->MempoolEntry
        self.by_scripthash = {}  # hashX->[txids]
        self.next_seq = None

    async def _get_entry(self, tx: dict, session=None) -> list[bytes]:
        spks_hex = [txo["scriptPubKey"]["hex"] for txo in tx["vout"]]
        fee = -sum(txo["value"] for txo in tx["vout"])

        for txi in tx["vin"]:
            prev_txid = txi["txid"]
            prev_vout = txi["vout"]
            entry = self.tx_entries.get(prev_txid)
            if entry is not None:
                txo = entry.tx["vout"][prev_vout]
            else:
                res = await try_get_utxo(prev_txid, prev_vout, session=session)
                utxos = res["utxos"]
                if not utxos:
                    # probably a new/stale block
                    raise MissingPrevout(prev_txid, prev_vout)
                txo = utxos[0]

            spks_hex.append(txo["scriptPubKey"]["hex"])
            fee += txo["value"]

        scripthashes = tuple(
            (sha256(bytes.fromhex(spk_hex)).digest() for spk_hex in spks_hex)
        )
        fee = round(fee * 1e8)  # good enough for fee estimation
        assert fee >= 0
        return MempoolEntry(tx, scripthashes, fee)

    async def add(self, txid_hex: str, tx, session, scripthashes):
        assert txid_hex == tx["txid"]
        if txid_hex in self.tx_entries:
            LOG.warning("add: %s already exists", txid_hex)
            return

        entry = await self._get_entry(tx, session=session)
        scripthashes.update(entry.scripthashes)
        for scripthash in entry.scripthashes:
            self.by_scripthash.setdefault(scripthash, set()).add(txid_hex)
        self.tx_entries[txid_hex] = entry

    def remove(self, txid_hex: str, scripthashes):
        entry = self.tx_entries.pop(txid_hex, None)
        if entry is None:
            LOG.warning("remove: %s not found", txid_hex)
            return

        scripthashes.update(entry.scripthashes)
        for scripthash in entry.scripthashes:
            txids = self.by_scripthash.get(scripthash)
            if txids is not None:
                txids.discard(txid_hex)
                if not txids:
                    self.by_scripthash.pop(scripthash)

    def notify(self, *args):
        self.notifications.put_nowait(args)

    async def sync_all(self, session, scripthashes):
        t = time.time()
        resp = await rest_get(
            "mempool/contents.json?mempool_sequence=true&verbose=false",
            lambda r: r.json(),
            session=session,
        )
        new_txids = resp["txids"]
        new_txids_set = set(new_txids)
        old_txids_set = set(self.tx_entries)
        for txid_hex in old_txids_set - new_txids_set:
            self.remove(txid_hex, scripthashes=scripthashes)

        next_report = time.time() + 1
        # iterate over new txids in original order
        for i, txid_hex in enumerate(new_txids):
            if txid_hex in old_txids_set:
                continue
            if time.time() > next_report:
                LOG.info(
                    "fetched %d mempool txs [%.1f%%]", i, 100.0 * i / len(new_txids)
                )
                next_report += 1
            if tx := await try_get_tx(txid_hex, session):
                await self.add(txid_hex, tx, session=session, scripthashes=scripthashes)

        self.next_seq = resp["mempool_sequence"]
        LOG.info(
            "fetched %d mempool txs, next_seq=%s (%.3fs)",
            len(self.tx_entries),
            self.next_seq,
            time.time() - t,
        )

    async def sync(self) -> MempoolUpdate:
        t = time.time()
        count = self.notifications.qsize()
        events = []
        result = MempoolUpdate(scripthashes=set(), new_tip=False)
        for _ in range(count):
            (event, hash_hex, mempool_seq) = self.notifications.get_nowait()
            if event in (Event.BLOCK_CONNECT, Event.BLOCK_DISCONNECT):
                # resync mempool after new/stale block
                self.next_seq = None
                result.new_tip = True
                events.clear()
            else:
                assert mempool_seq is not None
                events.append((event, hash_hex, mempool_seq))

        async with aiohttp.ClientSession() as session:
            if self.next_seq is None:
                await self.sync_all(session, scripthashes=result.scripthashes)

            for event, hash_hex, mempool_seq in events:
                if mempool_seq < self.next_seq:
                    continue
                if mempool_seq > self.next_seq:
                    LOG.warning("skipped seq: %d > %d", mempool_seq, self.next_seq)

                if event is Event.TX_ADD:
                    if tx := await try_get_tx(hash_hex, session=session):
                        await self.add(
                            hash_hex,
                            tx,
                            session=session,
                            scripthashes=result.scripthashes,
                        )
                elif event is Event.TX_REMOVE:
                    self.remove(hash_hex, scripthashes=result.scripthashes)
                else:
                    raise NotImplementedError(event)

                LOG.debug("%s @ %d (%s)", hash_hex, mempool_seq, event)
                self.next_seq = mempool_seq + 1

            LOG.debug(
                "handled %d events: %d txs, seq=%s (%.2fs)",
                len(events),
                len(self.tx_entries),
                self.next_seq,
                time.time() - t,
            )

        return result


class Manager:
    def __init__(self):
        self.db = sqlite3.connect(CACHE_DB)
        self.merkle = merkle.Merkle()
        self.sync_queue = asyncio.Queue()
        self.notifications = asyncio.Queue()  # ZMQ notifications
        self.mempool = Mempool()
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
        return await rest_get("chaininfo.json", lambda r: r.json())

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
        await self.sync_queue.put((hashX, event.set))
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

        h = await rest_get(f"blockhashbyheight/{height}.hex", lambda r: r.text())
        j = await rest_get(f"block/notxdetails/{h}.json", lambda r: r.json())
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
            h = await rest_get(f"blockhashbyheight/{height}.hex", lambda r: r.text())
            chunk_size = min(count, MAX_CHUNK_SIZE // 2)
            chunk = await rest_get(f"headers/{chunk_size}/{h}.bin", lambda r: r.read())
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
    ):
        connection = JSONRPCConnection(JSONRPCAutoDetect)
        super().__init__(transport, connection=connection)
        self.txs_sent = 0
        self.session_id = None
        self.session_id = next(self.session_counter)
        self.logger = logging.getLogger()

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

    def __init__(self, *args, env: Env, mgr: Manager, **kwargs):
        super().__init__(*args, **kwargs)
        self.env = env
        self.session_mgr = mgr
        self.subscribe_headers: dict | None = None
        self.connection.max_response_size = self.env.max_send
        self.hashX_subs = {}
        self.sv_seen = False
        self.set_request_handlers()
        self.is_peer = False
        self.protocol_tuple = self.PROTOCOL_MIN
        self.session_mgr.sessions.add(self)

    async def connection_lost(self):
        """Handle client disconnection."""
        await super().connection_lost()
        self.session_mgr.sessions.remove(self)

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
        return await self.session_mgr.latest_header()

    async def headers_subscribe(self):
        self.subscribe_headers = await self.subscribe_headers_result()
        return self.subscribe_headers

    async def add_peer(self, features):
        pass

    async def peers_subscribe(self):
        return []

    async def address_status(self, hashX):
        entries = await self.session_mgr.get_history(hashX)
        status = "".join(f"{e['tx_hash']}:{e['height']:d}:" for e in entries)
        return merkle.sha256(status.encode()).hex() if status else None

    async def hashX_subscribe(self, hashX, alias):
        await self.session_mgr.subscribe(hashX)

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
                    "blockchain.scripthash.subscribe", (new_status,)
                )

    async def confirmed_history(self, hashX):
        return await self.session_mgr.get_history(hashX)

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
        raw_header_hex = (await self.session_mgr.raw_header(height)).hex()
        return raw_header_hex

    async def block_headers(self, start_height, count):
        start_height = non_negative_integer(start_height)
        count = non_negative_integer(count)

        max_size = MAX_CHUNK_SIZE
        count = min(count, max_size)
        headers, count = await self.session_mgr.raw_headers(start_height, count)
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

        return await self.session_mgr.getrawtransaction(tx_hash, verbose)

    async def transaction_merkle(self, tx_hash, height):
        tx_hash = assert_tx_hash(tx_hash)
        height = non_negative_integer(height)

        branch, tx_pos = await self.session_mgr.merkle_branch_for_tx_hash(
            height, tx_hash
        )
        return {"block_height": height, "merkle": branch, "pos": tx_pos}

    async def transaction_broadcast(self, tx_hex):
        assert hex_to_bytes(tx_hex)
        txid = await json_rpc("sendrawtransaction", tx_hex)
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


async def get_items(q: asyncio.Queue, timeout=1.0):
    items = []
    try:
        while True:
            item = await asyncio.wait_for(q.get(), timeout)
            items.append(item)
            while not q.empty():
                items.append(q.get_nowait())
            # use a shorter timeout for coalescing subsequent subscriptions
            timeout = 0.01
    except asyncio.exceptions.TimeoutError:
        pass
    return items


def update_scripthashes(c: sqlite3.Cursor, data: list[bytes]):
    # update bindex DB with the new scripthashes
    c.execute("BEGIN")
    try:
        r = c.executemany("INSERT OR IGNORE INTO watch (script_hash) VALUES (?1)", data)
        if r.rowcount:
            LOG.info("watching %d new addresses", r.rowcount)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise


def get_scripthashes(c: sqlite3.Cursor) -> set[bytes]:
    c.execute("BEGIN")
    try:
        c.execute("SELECT script_hash FROM watch")
        scripthashes = set(s for (s,) in c.fetchall())
        c.execute("COMMIT")
        return scripthashes
    except Exception:
        c.execute("ROLLBACK")
        raise


class Indexer:
    def __init__(self):
        self.tip = None
        self._loop = asyncio.get_running_loop()

    async def _readline(self) -> str:
        return await self._loop.run_in_executor(None, sys.stdin.readline)

    async def _write(self, data: bytes):
        def write_fn():
            sys.stdout.write(data)
            sys.stdout.flush()

        await self._loop.run_in_executor(None, write_fn)

    @classmethod
    async def start(cls) -> "Indexer":
        i = Indexer()
        line = await i._readline()  # wait for an index sync
        i.tip = line.strip()
        LOG.info("indexer at block=%r", i.tip)
        return i

    async def sync(self) -> bool:
        # update history index for the new scripthashes
        await self._write("\n")

        # wait for the index sync to finish
        line = await self._readline()
        prev_tip = self.tip
        self.tip = line.strip()
        LOG.debug("indexer at block=%r", self.tip)
        return prev_tip != self.tip


async def sync_task(mgr: Manager, indexer: Indexer):
    try:
        # sending new scripthashes on subscription requests
        while True:
            items = await get_items(mgr.sync_queue)
            data = [[i] for i, _ in items]
            update_scripthashes(mgr.db.cursor(), data)

            # update history index for the new scripthashes
            chain_updated = await indexer.sync()
            if items or chain_updated:
                LOG.info("indexer at block=%r: %d reqs", indexer.tip, len(items))

            # mark subscription requests as done
            for _, ack_fn in items:
                ack_fn()

            # fetch ZMQ notifications
            mempool_update = await mgr.mempool.sync()
            mempool_updated = mempool_update.scripthashes.intersection(
                get_scripthashes(mgr.db.cursor())
            )

            # make sure all sessions are notified
            if chain_updated or mempool_updated:
                await mgr.notify_sessions()
    except Exception:
        LOG.exception("sync_task() failed")


async def main():
    FMT = "[%(asctime)-27s %(levelname)-5s %(module)s] %(message)s"
    logging.basicConfig(level="INFO", format=FMT)

    info = await rest_get("chaininfo.json", lambda r: r.json())
    chain = info["chain"]
    blocks = info["blocks"]
    logging.info("Electrum server '%s' @ %s:%s", VERSION, HOST, PORT)
    logging.info("Bitcoin Core %s @ %s, %d blocks", chain, BITCOIND_URL, blocks)

    indexer = await Indexer.start()  # wait for initial sync
    mgr = Manager()
    env = Env(await mgr.raw_header(0))
    cls = functools.partial(ElectrumSession, env=env, mgr=mgr)
    await serve_rs(cls, host=HOST, port=PORT)
    async with TaskGroup() as g:
        await g.spawn(sync_task(mgr, indexer))
        if ZMQ_ADDR:
            await g.spawn(subscribe_events(ZMQ_ADDR, mgr.mempool.notify))
        await g.join()


if __name__ == "__main__":
    asyncio.run(main())
