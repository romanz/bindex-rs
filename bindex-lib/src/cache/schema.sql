CREATE TABLE IF NOT EXISTS headers (
    block_height INTEGER NOT NULL,
    block_hash BLOB NOT NULL,
    header_bytes BLOB NOT NULL,
    PRIMARY KEY (block_height),
    UNIQUE (block_hash)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS transactions (
    block_height INTEGER NOT NULL,
    block_offset INTEGER NOT NULL,
    tx_id BLOB,
    tx_bytes BLOB,
    PRIMARY KEY (block_height, block_offset),
    UNIQUE (tx_id),
    FOREIGN KEY (block_height) REFERENCES headers (block_height) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS history (
    script_hash BLOB NOT NULL REFERENCES watch (script_hash) ON DELETE CASCADE,
    block_height INTEGER NOT NULL,
    block_offset INTEGER NOT NULL,
    is_output BOOLEAN NOT NULL,     -- is it funding the address or not (= spending from it)
    index_ INTEGER NOT NULL,        -- input/output index within a transaction
    amount INTEGER NOT NULL,        -- in Satoshis (positive=funding, negative=spending)
    PRIMARY KEY (script_hash, block_height, block_offset, is_output, index_)
    FOREIGN KEY (block_height, block_offset) REFERENCES transactions (block_height, block_offset) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS watch (
    script_hash BLOB NOT NULL,
    script_bytes BLOB,
    address TEXT,
    PRIMARY KEY (script_hash)
) WITHOUT ROWID;
