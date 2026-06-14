package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// ExportedRow is the shape of each line in a JSON Lines export.
type ExportedRow struct {
	Seq            int64  `json:"seq"`
	Method         string `json:"method"`
	Server         string `json:"server"`
	Name           string `json:"name"`
	Args           string `json:"args"`
	Verdict        string `json:"verdict"`
	Reason         string `json:"reason"`
	ApprovalSource string `json:"approval_source,omitempty"`
	Ts             string `json:"ts"` // RFC3339
	Hash           string `json:"hash"`
	HMACsig        string `json:"hmac_sig"`
	Warnings       string `json:"warnings,omitempty"`
}

// VerifyFile reads JSON Lines from r and verifies the hash chain.
// key is optional (nil = no HMAC check).
// Returns (true, nil) on success, (false, nil) if tampered, (false, err) on I/O error.
func VerifyFile(r io.Reader, key []byte) (bool, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	prevHash := ""
	var expectedSeq int64 = 1
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var row ExportedRow
		if err := json.Unmarshal(line, &row); err != nil {
			return false, fmt.Errorf("line %d: invalid JSON: %w", lineNum, err)
		}
		if row.Seq != expectedSeq {
			return false, nil
		}
		isGenesis := row.Seq == 1 && row.Method == "GENESIS"
		if row.Method == "GENESIS" && !isGenesis {
			return false, nil
		}

		t, err := time.Parse(time.RFC3339, row.Ts)
		if err != nil {
			return false, fmt.Errorf("line %d: parse ts %q: %w", lineNum, row.Ts, err)
		}
		tsUnix := t.Unix()

		fields := map[string]any{
			"method":  row.Method,
			"server":  row.Server,
			"name":    row.Name,
			"args":    row.Args,
			"verdict": row.Verdict,
			"reason":  row.Reason,
			"seq":     row.Seq,
			"ts":      tsUnix,
		}
		if row.Warnings != "" {
			fields["warnings"] = row.Warnings
		}
		if row.ApprovalSource != "" {
			fields["approval_source"] = row.ApprovalSource
		}
		entryBytes := canonicalJSON(fields)
		combined := append([]byte(prevHash), entryBytes...)
		h := sha256.Sum256(combined)
		computed := hex.EncodeToString(h[:])

		if computed != row.Hash {
			return false, nil
		}

		// Verify HMAC when key provided; only the bootstrap seq=1 GENESIS row is unsigned.
		if key != nil && !isGenesis {
			if row.HMACsig == "" {
				return false, nil
			}
			input := strconv.FormatInt(row.Seq, 10) + ":" + string(entryBytes)
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(input))
			got, err := hex.DecodeString(row.HMACsig)
			if err != nil {
				return false, nil
			}
			if !hmac.Equal(mac.Sum(nil), got) {
				return false, nil
			}
		}

		prevHash = row.Hash
		expectedSeq++
	}
	return scanner.Err() == nil, scanner.Err()
}
