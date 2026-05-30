package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore is an append-only, hash-chained audit log backed by SQLite.
type SQLiteStore struct {
	db        *sql.DB
	mu        sync.Mutex // serialises all writes (hash chain requires ordering)
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
	return &SQLiteStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit_log (
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
	)`)
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

	_, err = s.db.Exec(
		`INSERT INTO audit_log(seq,method,server,name,args,verdict,reason,ts_unix,hash,status)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		seq, e.Method, e.Server, e.Name, e.Args, e.Verdict, e.Reason, e.Ts.Unix(), hashHex, "DONE",
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
		`SELECT seq,method,server,name,args,verdict,reason,ts_unix,hash FROM audit_log ORDER BY seq`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	prevHash := ""
	for rows.Next() {
		var seq, ts int64
		var method, server, name, args, verdict, reason, storedHash string
		if err := rows.Scan(&seq, &method, &server, &name, &args,
			&verdict, &reason, &ts, &storedHash); err != nil {
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
		prevHash = storedHash
	}
	return true, rows.Err()
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// TestCorruptRow directly updates a row's verdict — for tamper-detection tests only.
func (s *SQLiteStore) TestCorruptRow(seq int64, newVerdict string) {
	s.db.Exec(`UPDATE audit_log SET verdict=? WHERE seq=?`, newVerdict, seq)
}

// InjectWriteError causes the next Append call to return an error.
func (s *SQLiteStore) InjectWriteError(v bool) { s.injectErr = v }
