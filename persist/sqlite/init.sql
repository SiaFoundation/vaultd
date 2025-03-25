CREATE TABLE seeds (
	id INTEGER PRIMARY KEY,
	seed_mac BLOB UNIQUE NOT NULL,
	encrypted_seed BLOB UNIQUE NOT NULL,
	date_created INTEGER NOT NULL
);

CREATE TABLE signing_keys (
	public_key BLOB PRIMARY KEY,
	seed_id INTEGER NOT NULL REFERENCES seeds (id),
	seed_index INTEGER NOT NULL
);
CREATE INDEX signing_keys_seed_id_idx ON signing_keys (seed_id);
CREATE INDEX signing_keys_seed_id_seed_index_idx ON signing_keys (seed_id, seed_index ASC);

CREATE TABLE syncer_peers (
	peer_address TEXT PRIMARY KEY NOT NULL,
	first_seen INTEGER NOT NULL
);

CREATE TABLE syncer_bans (
	net_cidr TEXT PRIMARY KEY NOT NULL,
	expiration INTEGER NOT NULL,
	reason TEXT NOT NULL
);
CREATE INDEX syncer_bans_expiration_idx ON syncer_bans (expiration);

CREATE TABLE global_settings (
	id INTEGER PRIMARY KEY NOT NULL DEFAULT 0 CHECK (id = 0), -- enforce a single row
	db_version INTEGER NOT NULL, -- used for migrations
	key_salt BLOB -- the salt used for deriving keys
);
