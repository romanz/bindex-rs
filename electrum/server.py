# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

"""Classes for local RPC server and remote client TCP/SSL servers."""

import aiohttp
import asyncio
import functools
import itertools
import logging
import sqlite3
import subprocess
import sys
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
from .merkle import sha256

BAD_REQUEST = 1
DAEMON_ERROR = 2

MAX_CHUNK_SIZE = 2016

(CACHE_DB,) = sys.argv[1:]


class Env:
    max_recv = 10**7
    max_send = 10**7
    donation_address = None


VERSION = "bindex/0"

HERE = Path(__file__).resolve()
BINARY = HERE.parent.parent / "target" / "release" / "indexer"
assert BINARY.exists(), BINARY

LOG = logging.getLogger()


class Manager:
    def __init__(self):
        self.db = sqlite3.connect(CACHE_DB)
        self.merkle = merkle.Merkle()
        self.sync = asyncio.Queue(50)

    async def latest_header(self) -> dict:
        j = await self.chaininfo()
        height = j["blocks"]
        raw = await self.raw_header(height)
        return {"hex": raw.hex(), "height": height}

    async def get(self, path, f):
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://localhost:8332/rest/{path}") as response:
                response.raise_for_status()
                return await f(response)

    async def chaininfo(self):
        return await self.get("chaininfo.json", lambda r: r.json())

    async def limited_history(self, hashx: bytes):
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
        return self.db.execute(query, [hashx]).fetchall()

    async def subscribe(self, hashX: bytes):
        event = asyncio.Event()
        await self.sync.put((hashX, event.set))
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

        h = await self.get(f"blockhashbyheight/{height}.hex", lambda r: r.text())
        j = await self.get(f"block/notxdetails/{h}.json", lambda r: r.json())
        tx_hashes = [hex_str_to_hash(h) for h in j["tx"]]
        return tx_hashes

    async def getrawtransaction(self, tx_hash, verbose):
        assert verbose is False
        rows = self.db.execute(
            "SELECT tx_bytes FROM transactions WHERE tx_id = ?", [tx_hash]
        ).fetchall()
        if len(rows) != 1:
            raise RPCError(BAD_REQUEST, f"{tx_hash.hex()} not found in DB")
        return rows[0][0]

    async def raw_header(self, height: int):
        raw, _ = await self.raw_headers(height, count=1)
        return raw

    async def raw_headers(self, height: int, count: int):
        chunks = []
        while count > 0:
            h = await self.get(f"blockhashbyheight/{height}.hex", lambda r: r.text())
            chunk_size = min(count, MAX_CHUNK_SIZE // 2)
            chunk = await self.get(f"headers/{chunk_size}/{h}.bin", lambda r: r.read())
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

    log_me = True

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


class ElectrumX(SessionBase):
    """A TCP server that handles incoming Electrum connections."""

    PROTOCOL_MIN = (1, 4)
    PROTOCOL_MAX = (1, 4, 3)

    def __init__(self, *args, mgr, **kwargs):
        super().__init__(*args, **kwargs)
        self.env = Env()
        self.session_mgr = mgr
        self.subscribe_headers = False
        self.connection.max_response_size = self.env.max_send
        self.hashX_subs = {}
        self.sv_seen = False
        self.mempool_statuses = {}
        self.set_request_handlers()
        self.is_peer = False
        self.protocol_tuple = self.PROTOCOL_MIN

    @classmethod
    def protocol_min_max_strings(cls):
        return [version_string(ver) for ver in (cls.PROTOCOL_MIN, cls.PROTOCOL_MAX)]

    @classmethod
    def server_features(cls, env):
        """Return the server features dictionary."""
        hosts_dict = {}
        for service in env.report_services:
            port_dict = hosts_dict.setdefault(str(service.host), {})
            if service.protocol not in port_dict:
                port_dict[f"{service.protocol}_port"] = service.port

        min_str, max_str = cls.protocol_min_max_strings()
        return {
            "hosts": hosts_dict,
            "pruning": None,
            "server_version": VERSION,
            "protocol_min": min_str,
            "protocol_max": max_str,
            "hash_function": "sha256",
            "services": [],
        }

    async def server_features_async(self):
        return self.server_features(self.env)

    @classmethod
    def server_version_args(cls):
        """The arguments to a server.version RPC call to a peer."""
        return [VERSION, cls.protocol_min_max_strings()]

    def protocol_version_string(self):
        return version_string(self.protocol_tuple)

    def unsubscribe_hashX(self, hashX):
        self.mempool_statuses.pop(hashX, None)
        return self.hashX_subs.pop(hashX, None)

    async def subscribe_headers_result(self):
        """The result of a header subscription or notification."""
        return await self.session_mgr.latest_header()

    async def headers_subscribe(self):
        """Subscribe to get raw headers of new blocks."""
        self.subscribe_headers = True
        return await self.subscribe_headers_result()

    async def add_peer(self, features):
        """Add a peer (but only if the peer resolves to the source)."""

    async def peers_subscribe(self):
        """Return the server peers as a list of (ip, host, details) tuples."""
        return []

    async def address_status(self, hashX):
        """Returns an address status.

        Status is a hex string, but must be None if there is no history.
        """
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if it has unconfirmed inputs, otherwise 0
        db_history = await self.session_mgr.limited_history(hashX)
        mempool = []  ### await self.mempool.transaction_summaries(hashX)

        status = "".join(
            f"{hash_to_hex_str(tx_hash)}:{height:d}:" for tx_hash, height in db_history
        )
        status += "".join(
            f"{hash_to_hex_str(tx.hash)}:{-tx.has_unconfirmed_inputs:d}:"
            for tx in mempool
        )

        if status:
            status = sha256(status.encode()).hex()
        else:
            status = None

        if mempool:
            self.mempool_statuses[hashX] = status
        else:
            self.mempool_statuses.pop(hashX, None)

        return status

    async def hashX_subscribe(self, hashX, alias):
        await self.session_mgr.subscribe(hashX)

        # Store the subscription only after address_status succeeds
        result = await self.address_status(hashX)
        self.hashX_subs[hashX] = alias
        return result

    async def unconfirmed_history(self, hashX):
        # Note unconfirmed history is unordered in electrum-server
        # height is -1 if it has unconfirmed inputs, otherwise 0
        return []

    async def confirmed_and_unconfirmed_history(self, hashX):
        # Note history is ordered but unconfirmed is unordered in e-s
        history = await self.session_mgr.limited_history(hashX)
        conf = [
            {"tx_hash": hash_to_hex_str(tx_hash), "height": height}
            for tx_hash, height in history
        ]
        return conf + await self.unconfirmed_history(hashX)

    async def scripthash_get_history(self, scripthash):
        """Return the confirmed and unconfirmed history of a scripthash."""
        hashX = scripthash_to_hashX(scripthash)
        return await self.confirmed_and_unconfirmed_history(hashX)

    async def scripthash_subscribe(self, scripthash):
        """Subscribe to a script hash.

        scripthash: the SHA256 hash of the script to subscribe to"""
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_subscribe(hashX, scripthash)

    async def scripthash_unsubscribe(self, scripthash):
        """Unsubscribe from a script hash."""
        hashX = scripthash_to_hashX(scripthash)
        return self.unsubscribe_hashX(hashX) is not None

    async def _merkle_proof(self, cp_height, height):
        max_height = self.db.db_height
        if not height <= cp_height <= max_height:
            raise RPCError(
                BAD_REQUEST,
                f"require header height {height:,d} <= "
                f"cp_height {cp_height:,d} <= "
                f"chain height {max_height:,d}",
            )
        branch, root = await self.db.header_branch_and_root(cp_height + 1, height)
        return {
            "branch": [hash_to_hex_str(elt) for elt in branch],
            "root": hash_to_hex_str(root),
        }

    async def block_header(self, height):
        """Return a raw block header as a hexadecimal string, or as a
        dictionary with a merkle proof."""
        height = non_negative_integer(height)
        raw_header_hex = (await self.session_mgr.raw_header(height)).hex()
        return raw_header_hex

    async def block_headers(self, start_height, count):
        """Return count concatenated block headers as hex for the main chain;
        starting at start_height.

        start_height and count must be non-negative integers.  At most
        MAX_CHUNK_SIZE headers will be returned.
        """
        start_height = non_negative_integer(start_height)
        count = non_negative_integer(count)

        max_size = MAX_CHUNK_SIZE
        count = min(count, max_size)
        headers, count = await self.session_mgr.raw_headers(start_height, count)
        result = {"hex": headers.hex(), "count": count, "max": max_size}
        return result

    async def donation_address(self):
        """Return the donation address as a string, empty if there is none."""
        return self.env.donation_address

    async def banner(self):
        """Return the server banner text."""
        return ""

    async def relayfee(self):
        return 0

    async def estimatefee(self, number, mode=None):
        """The estimated transaction fee per kilobyte to be paid for a
        transaction to be included within a certain number of blocks.

        number: the number of blocks
        mode: CONSERVATIVE or ECONOMICAL estimation mode
        """
        return 0

    async def ping(self):
        """Serves as a connection keep-alive mechanism and for the client to
        confirm the server is still responding.
        """
        return None

    async def server_version(self, client_name="", protocol_version=None):
        """Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        """
        return VERSION, self.protocol_version_string()

    async def transaction_get(self, tx_hash, verbose=False):
        """Return the serialized raw transaction given its hash

        tx_hash: the transaction hash as a hexadecimal string
        verbose: passed on to the daemon
        """
        tx_hash = assert_tx_hash(tx_hash)
        if verbose not in (True, False):
            raise RPCError(BAD_REQUEST, '"verbose" must be a boolean')

        raw = await self.session_mgr.getrawtransaction(tx_hash, verbose)
        return raw.hex()

    async def transaction_merkle(self, tx_hash, height):
        """Return the merkle branch to a confirmed transaction given its hash
        and height.

        tx_hash: the transaction hash as a hexadecimal string
        height: the height of the block it is in
        """
        tx_hash = assert_tx_hash(tx_hash)
        height = non_negative_integer(height)

        branch, tx_pos = await self.session_mgr.merkle_branch_for_tx_hash(
            height, tx_hash
        )
        return {"block_height": height, "merkle": branch, "pos": tx_pos}

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


async def sync_task(sync_queue, db):
    try:
        indexer = await asyncio.create_subprocess_exec(
            BINARY,
            "-c",
            CACHE_DB,
            env={"RUST_LOG": "INFO", "RUST_BACKTRACE": "full"},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        line = await indexer.stdout.readline()  # wait for an index sync
        tip = line.decode().strip()
        LOG.info("pid=%s indexer at block=%s", indexer.pid, tip)

        while True:
            items = []
            timeout = 1.0
            try:
                while True:
                    item = await asyncio.wait_for(sync_queue.get(), timeout)
                    items.append(item)
                    for _ in range(sync_queue.qsize()):
                        items.append(sync_queue.get_nowait())
                    timeout = 0.1
            except asyncio.exceptions.TimeoutError:
                pass

            c = db.cursor()
            c.execute("BEGIN")
            try:
                data = [[h] for h, _ in items]
                r = c.executemany(
                    "INSERT OR IGNORE INTO watch (script_hash) VALUES (?1)", data
                )
                if r.rowcount:
                    LOG.info("watching %d new addresses", r.rowcount)
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise

            indexer.stdin.write(b"\n")
            await indexer.stdin.drain()
            line = await indexer.stdout.readline()  # wait for an index sync
            if items:
                LOG.info("indexer at block=%s: %d ACKs", tip, len(items))
            for _, ack_fn in items:
                ack_fn()
    except Exception:
        LOG.exception("sync_task() failed")


async def main():
    FMT = "[%(asctime)-27s %(levelname)-5s %(module)s] %(message)s"
    logging.basicConfig(level="INFO", format=FMT)
    # wait for initial index sync
    mgr = Manager()
    cls = functools.partial(ElectrumX, mgr=mgr)
    await serve_rs(cls, host="localhost", port=50001)
    async with TaskGroup() as g:
        await g.spawn(sync_task(mgr.sync, mgr.db))
        await g.join()


if __name__ == "__main__":
    asyncio.run(main())
