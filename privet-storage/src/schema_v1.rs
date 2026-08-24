//! v1 baseline schema。
//! 注：`schema_version` 表由迁移运行器自举创建（migration.rs），不在此。

pub const V1_SQL: &str = r#"
-- trust_store
CREATE TABLE trust_store (
  device_fingerprint          TEXT    PRIMARY KEY,
  peer_spki          BLOB    NOT NULL,
  peer_device_name   TEXT    NOT NULL,
  trust_state        TEXT    NOT NULL DEFAULT 'Trusted',
  share_with_peers   INTEGER NOT NULL DEFAULT 0,
  first_paired_ts    INTEGER NOT NULL,
  last_seen_ts       INTEGER NOT NULL,
  revoked_ts         INTEGER,
  revocation_reason  TEXT,
  CHECK (trust_state IN ('Trusted','Revoked'))
);
CREATE INDEX idx_trust_last_seen ON trust_store(last_seen_ts);

-- known_device_addresses
CREATE TABLE known_device_addresses (
  device_fingerprint      TEXT    NOT NULL REFERENCES trust_store(device_fingerprint) ON DELETE CASCADE,
  subnet_cidr    TEXT    NOT NULL,
  gateway_ip     TEXT,
  addr           TEXT    NOT NULL,
  quic_port      INTEGER NOT NULL,
  tcp_port       INTEGER NOT NULL,
  source         TEXT    NOT NULL DEFAULT 'self',
  last_seen_ts   INTEGER NOT NULL,
  success_count  INTEGER NOT NULL DEFAULT 0,
  fail_count     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_fingerprint, subnet_cidr, addr),
  CHECK (source IN ('self','referral'))
);
CREATE INDEX idx_kda_device_lastseen ON known_device_addresses(device_fingerprint, last_seen_ts DESC);
CREATE INDEX idx_kda_subnet         ON known_device_addresses(subnet_cidr);

-- transfer_history
CREATE TABLE transfer_history (
  transfer_id     TEXT    PRIMARY KEY,
  direction       TEXT    NOT NULL,
  peer_device_fingerprint  TEXT    REFERENCES trust_store(device_fingerprint) ON DELETE SET NULL,
  peer_name       TEXT,
  root_name       TEXT,
  file_count      INTEGER NOT NULL,
  total_bytes     INTEGER NOT NULL,
  status          TEXT    NOT NULL,
  error           TEXT,
  started_ts      INTEGER NOT NULL,
  finished_ts     INTEGER,
  save_dir        TEXT,
  send_intent     TEXT NOT NULL,
  CHECK (direction IN ('send','receive')),
  CHECK (status IN ('completed','cancelled','failed','partial'))
);
CREATE INDEX idx_history_started ON transfer_history(started_ts DESC);
CREATE INDEX idx_history_peer    ON transfer_history(peer_device_fingerprint);

-- transfer_files
CREATE TABLE transfer_files (
  transfer_id    TEXT    NOT NULL REFERENCES transfer_history(transfer_id) ON DELETE CASCADE,
  file_id        TEXT    NOT NULL,
  relative_path  TEXT    NOT NULL,
  size           INTEGER NOT NULL,
  hash_type      TEXT,
  hash_value     TEXT,
  status         TEXT    NOT NULL,
  PRIMARY KEY (transfer_id, file_id),
  CHECK (status IN ('completed','failed','skipped'))
);
"#;
