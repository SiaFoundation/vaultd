CREATE TABLE seeds (
	id INTEGER PRIMARY KEY,
	seed_mac BLOB UNIQUE NOT NULL CHECK(length(seed_mac) = 32),
	encrypted_seed BLOB UNIQUE NOT NULL CHECK(length(encrypted_seed) = 72),
	date_created INTEGER NOT NULL
);
CREATE INDEX seeds_date_created_idx ON seeds (date_created ASC);

CREATE TABLE signing_keys (
	public_key BLOB PRIMARY KEY CHECK(length(public_key) = 32),
	seed_id INTEGER NOT NULL REFERENCES seeds (id),
	seed_index INTEGER NOT NULL
);
CREATE INDEX signing_keys_seed_id_idx ON signing_keys (seed_id);
CREATE INDEX signing_keys_seed_id_seed_index_idx ON signing_keys (seed_id, seed_index ASC);

CREATE TABLE global_settings (
	id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0), -- enforce a single row
	db_version INTEGER NOT NULL, -- used for migrations
	key_salt BLOB -- the salt used for deriving keys
);
