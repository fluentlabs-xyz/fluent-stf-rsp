use std::sync::{Mutex, MutexGuard, OnceLock};

use revm_primitives::B256;
use rusqlite::{params, Connection};
use tracing::error;

static DB: OnceLock<Mutex<Db>> = OnceLock::new();

pub(crate) fn init(path: &str) -> eyre::Result<()> {
    let db = Db::open(path).map_err(|e| eyre::eyre!("Failed to open proxy database: {e}"))?;
    DB.set(Mutex::new(db)).map_err(|_| eyre::eyre!("Db already initialized"))
}

pub(crate) fn db() -> Option<MutexGuard<'static, Db>> {
    let mutex = DB.get()?;
    match mutex.lock() {
        Ok(guard) => Some(guard),
        Err(e) => {
            error!("DB mutex poisoned: {e}");
            None
        }
    }
}

pub(crate) struct Db {
    conn: Connection,
}

impl Db {
    fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS attestation_request (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                request_id  BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS challenges (
                challenge_id     BLOB PRIMARY KEY,
                sp1_request_id   BLOB,
                block_number     INTEGER NOT NULL,
                status           TEXT NOT NULL DEFAULT 'pending',
                proof_bytes      BLOB,
                public_values    BLOB,
                vk_hash          BLOB,
                error            TEXT,
                created_at       INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Self { conn })
    }

    // ── Attestation request_id ──────────────────────────────────────────

    pub(crate) fn save_attestation_request_id(&self, request_id: B256) {
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO attestation_request(id, request_id) VALUES(1, ?1)",
            params![request_id.as_slice()],
        ) {
            error!(err = %e, "Failed to save attestation request_id");
        }
    }

    pub(crate) fn load_attestation_request_id(&self) -> Option<B256> {
        let bytes: Vec<u8> = self
            .conn
            .query_row("SELECT request_id FROM attestation_request WHERE id = 1", [], |row| {
                row.get(0)
            })
            .ok()?;
        B256::try_from(bytes.as_slice()).ok()
    }

    pub(crate) fn delete_attestation_request_id(&self) {
        if let Err(e) = self.conn.execute("DELETE FROM attestation_request WHERE id = 1", []) {
            error!(err = %e, "Failed to delete attestation request_id");
        }
    }

    // ── Challenge tracking ──────────────────────────────────────────────

    pub(crate) fn create_challenge(&self, challenge_id: B256, block_number: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Err(e) = self.conn.execute(
            "INSERT INTO challenges(challenge_id, block_number, status, created_at)
             VALUES(?1, ?2, 'pending', ?3)",
            params![challenge_id.as_slice(), block_number, now],
        ) {
            error!(err = %e, "Failed to create challenge");
        }
    }

    pub(crate) fn update_challenge_sp1_request_id(&self, challenge_id: B256, sp1_request_id: B256) {
        if let Err(e) = self.conn.execute(
            "UPDATE challenges SET sp1_request_id = ?2 WHERE challenge_id = ?1",
            params![challenge_id.as_slice(), sp1_request_id.as_slice()],
        ) {
            error!(err = %e, "Failed to update challenge sp1_request_id");
        }
    }

    pub(crate) fn set_challenge_completed(
        &self,
        challenge_id: B256,
        proof_bytes: &[u8],
        public_values: &[u8],
        vk_hash: &[u8],
    ) {
        if let Err(e) = self.conn.execute(
            "UPDATE challenges SET status = 'completed', proof_bytes = ?2, public_values = ?3, vk_hash = ?4
             WHERE challenge_id = ?1",
            params![
                challenge_id.as_slice(),
                proof_bytes,
                public_values,
                vk_hash,
            ],
        ) {
            error!(err = %e, "Failed to set challenge completed");
        }
    }

    pub(crate) fn set_challenge_failed(&self, challenge_id: B256, err_msg: &str) {
        if let Err(e) = self.conn.execute(
            "UPDATE challenges SET status = 'failed', error = ?2 WHERE challenge_id = ?1",
            params![challenge_id.as_slice(), err_msg],
        ) {
            error!(err = %e, "Failed to set challenge failed");
        }
    }

    pub(crate) fn get_challenge(&self, challenge_id: B256) -> Option<ChallengeRow> {
        self.conn
            .query_row(
                "SELECT status, proof_bytes, public_values, vk_hash, error
                 FROM challenges WHERE challenge_id = ?1",
                params![challenge_id.as_slice()],
                |row| {
                    Ok(ChallengeRow {
                        status: row.get(0)?,
                        proof_bytes: row.get(1)?,
                        public_values: row.get(2)?,
                        vk_hash: row.get(3)?,
                        error: row.get(4)?,
                    })
                },
            )
            .ok()
    }
}

pub(crate) struct ChallengeRow {
    pub status: String,
    pub proof_bytes: Option<Vec<u8>>,
    pub public_values: Option<Vec<u8>>,
    pub vk_hash: Option<Vec<u8>>,
    pub error: Option<String>,
}
