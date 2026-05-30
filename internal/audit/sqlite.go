package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore is an append-only, hash-chained audit log backed by SQLite.
type SQLiteStore struct {
	db        *sql.DB
	mu        sync.Mutex // serialises all writes (hash chain requires ordering)
	hmacKey   []byte     // optional 32-byte key for HMAC-signed rows
	injectErr bool       // test injection
}

// Open opens (or creates) the SQLite audit database at path.
func Open(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := ensureGenesis(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

// OpenWithHMAC opens the audit database with an HMAC key for signed rows.
// key must be exactly 32 bytes.
func OpenWithHMAC(path string, key []byte) (*SQLiteStore, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("audit: HMAC key must be 32 bytes, got %d", len(key))
	}
	s, err := Open(path)
	if err != nil {
		return nil, err
	}
	s.hmacKey = key
	return s, nil
}


func migrate(db *sql.DB) error {
	// v0.1: initial schema
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit_log (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		seq      INTEGER UNIQUE NOT NULL,
		method   TEXT,
		server   TEXT,
		name     TEXT,
		args     TEXT,
		verdict  TEXT,
		reason   TEXT,
		ts_unix  INTEGER,
		hash     TEXT NOT NULL,
		status   TEXT NOT NULL DEFAULT 'DONE'
	)`); err != nil {
		return err
	}
	// v0.3: HMAC signature per row (empty string = no HMAC)
	_, err := db.Exec(`ALTER TABLE audit_log ADD COLUMN hmac_sig TEXT NOT NULL DEFAULT ""`)
	if err != nil && !isSQLiteAlreadyExists(err) {
		return err
	}
	return nil
}

// isSQLiteAlreadyExists returns true when the ALTER TABLE fails because the column
// already exists — this is the standard incremental migration pattern for SQLite.
func isSQLiteAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

// ensureGenesis writes the GENESIS sentinel row if the table is empty.
func ensureGenesis(db *sql.DB) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&count); err != nil {
		return fmt.Errorf("audit: check genesis: %w", err)
	}
	if count > 0 {
		return nil // already initialised
	}
	// Write genesis with seq=1 (prevHash="").
	fields := map[string]any{
		"method":  "GENESIS",
		"server":  "",
		"name":    runtime.Version(),
		"args":    "",
		"verdict": "GENESIS",
		"reason":  "startup",
		"seq":     int64(1),
		"ts":      time.Now().UTC().Unix(),
	}
	entryBytes := canonicalJSON(fields)
	combined := append([]byte(""), entryBytes...)
	h := sha256.Sum256(combined)
	hash := hex.EncodeToString(h[:])

	_, err := db.Exec(
		`INSERT INTO audit_log (seq,method,server,name,args,verdict,reason,ts_unix,hash,status,hmac_sig)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		1, "GENESIS", "", runtime.Version(), "", "GENESIS", "startup",
		time.Now().UTC().Unix(), hash, "DONE", "")
	return err
}

// Append writes an entry to the log. Fail-closed: any error must cause the caller to DENY.
func (s *SQLiteStore) Append(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.injectErr {
		s.injectErr = false
		return errors.New("injected write failure")
	}

	prevHash, seq, err := s.lastHashAndSeq()
	if err != nil {
		return fmt.Errorf("audit: get last hash: %w", err)
	}
	seq++
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}

	fields := map[string]any{
		"method":  e.Method,
		"server":  e.Server,
		"name":    e.Name,
		"args":    e.Args,
		"verdict": e.Verdict,
		"reason":  e.Reason,
		"seq":     seq,
		"ts":      e.Ts.Unix(),
	}
	entryBytes := canonicalJSON(fields)
	combined := append([]byte(prevHash), entryBytes...)
	h := sha256.Sum256(combined)
	hashHex := hex.EncodeToString(h[:])

	hmacSig := ""
	if s.hmacKey != nil {
		input := strconv.FormatInt(seq, 10) + ":" + string(entryBytes)
		mac := hmac.New(sha256.New, s.hmacKey)
		mac.Write([]byte(input))
		hmacSig = hex.EncodeToString(mac.Sum(nil))
	}

	_, err = s.db.Exec(
		`INSERT INTO audit_log(seq,method,server,name,args,verdict,reason,ts_unix,hash,status,hmac_sig)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		seq, e.Method, e.Server, e.Name, e.Args, e.Verdict, e.Reason, e.Ts.Unix(), hashHex, "DONE", hmacSig,
	)
	return err
}

func (s *SQLiteStore) lastHashAndSeq() (string, int64, error) {
	row := s.db.QueryRow(`SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`)
	var seq int64
	var hash string
	if err := row.Scan(&seq, &hash); err == sql.ErrNoRows {
		return "", 0, nil
	} else if err != nil {
		return "", 0, err
	}
	return hash, seq, nil
}

// VerifyChain recomputes every hash and returns false if any mismatch is found.
func (s *SQLiteStore) VerifyChain() (bool, error) {
	rows, err := s.db.Query(
		`SELECT seq,method,server,name,args,verdict,reason,ts_unix,hash,hmac_sig FROM audit_log ORDER BY seq`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	prevHash := ""
	for rows.Next() {
		var seq, ts int64
		var method, server, name, args, verdict, reason, storedHash, storedHMACsig string
		if err := rows.Scan(&seq, &method, &server, &name, &args,
			&verdict, &reason, &ts, &storedHash, &storedHMACsig); err != nil {
			return false, err
		}
		fields := map[string]any{
			"method": method, "server": server, "name": name,
			"args": args, "verdict": verdict, "reason": reason,
			"seq": seq, "ts": ts,
		}
		entryBytes := canonicalJSON(fields)
		combined := append([]byte(prevHash), entryBytes...)
		h := sha256.Sum256(combined)
		computed := hex.EncodeToString(h[:])
		if computed != storedHash {
			return false, nil
		}
		// Skip HMAC verification for GENESIS row (bootstrap record before key config)
		if s.hmacKey != nil && method != "GENESIS" {
			input := strconv.FormatInt(seq, 10) + ":" + string(entryBytes)
			mac := hmac.New(sha256.New, s.hmacKey)
			mac.Write([]byte(input))
			expectedSig := hex.EncodeToString(mac.Sum(nil))
			if expectedSig != storedHMACsig {
				return false, nil
			}
		}
		prevHash = storedHash
	}
	return true, rows.Err()
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// GetDB returns the underlying *sql.DB for testing purposes only.
func (s *SQLiteStore) GetDB() *sql.DB { return s.db }

// Recent returns the n most recent audit entries, newest first.
func (s *SQLiteStore) Recent(n int) ([]Entry, error) {
	rows, err := s.db.Query(
		`SELECT id, seq, method, server, name, args, verdict, reason, ts_unix FROM audit_log
		 ORDER BY seq DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Seq, &e.Method, &e.Server, &e.Name,
			&e.Args, &e.Verdict, &e.Reason, &ts); err != nil {
			return nil, err
		}
		e.Ts = time.Unix(ts, 0).UTC()
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// TestCorruptRow directly updates a row's verdict — for tamper-detection tests only.
func (s *SQLiteStore) TestCorruptRow(seq int64, newVerdict string) {
	s.db.Exec(`UPDATE audit_log SET verdict=? WHERE seq=?`, newVerdict, seq)
}

// InjectWriteError causes the next Append call to return an error.
func (s *SQLiteStore) InjectWriteError(v bool) { s.injectErr = v }

// VerifyGap checks for truncation by detecting sequence number gaps.
// Returns true if a gap is found (rows were deleted).
func (s *SQLiteStore) VerifyGap() (bool, error) {
	rows, err := s.db.Query(`SELECT seq FROM audit_log ORDER BY seq`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	var prev int64 = 0
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return false, err
		}
		if prev > 0 && seq != prev+1 {
			return true, nil // gap detected
		}
		prev = seq
	}
	return false, rows.Err()
}
