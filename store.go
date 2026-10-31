// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// [diverges from QuickShare] The table uses the schema in CLAUDE.md (Data
// Model): renamed columns, a stored filename, a revoked flag, NULL for "never
// expires", an onion_session column for diagnostics, and serve_path /
// metadata_stripped for metadata-stripped copies. The Go API (Share,
// Add, Get, List, Increment, Prune, CountActive) keeps QuickShare's names and
// semantics so the server and daemon code stay portable.

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Share is one shared file. ExpiresAt == 0 means no expiry (NULL in the
// database); MaxDownloads == 0 means unlimited downloads.
type Share struct {
	Token        string `json:"token"`
	Path         string `json:"path"`
	Filename     string `json:"filename"`
	Created      int64  `json:"created"`
	ExpiresAt    int64  `json:"expires_at"`
	MaxDownloads int    `json:"max_downloads"`
	Count        int    `json:"count"`
	Revoked      bool   `json:"revoked"`
	// OnionSession identifies the daemon session that served the share.
	// Diagnostic only. It is never the onion key.
	OnionSession string `json:"-"`
	// ServePath is the metadata-stripped copy in the state directory that
	// is served instead of Path; empty means Path is served as-is.
	ServePath string `json:"-"`
	// MetadataStripped is true when the served file carries no metadata
	// ghostshare knows how to find.
	MetadataStripped bool `json:"metadata_stripped"`
}

// ServedPath is the file actually sent to recipients.
func (s Share) ServedPath() string {
	if s.ServePath != "" {
		return s.ServePath
	}
	return s.Path
}

// Servable reports whether the share's files are still there. Deleting the
// original ends the share even when a stripped copy is being served, as in
// QuickShare, so deleting a file always cancels its share.
func (s Share) Servable() bool {
	return fileExists(s.Path) && (s.ServePath == "" || fileExists(s.ServePath))
}

// Active reports whether the share can still be downloaded at time now.
func (s Share) Active(now time.Time) bool {
	if s.Revoked {
		return false
	}
	if s.ExpiresAt != 0 && now.Unix() >= s.ExpiresAt {
		return false
	}
	if s.MaxDownloads != 0 && s.Count >= s.MaxDownloads {
		return false
	}
	return true
}

var errNotFound = errors.New("share not found")

type Store struct {
	db *sql.DB
}

const schema = `CREATE TABLE IF NOT EXISTS shares (
	token         TEXT PRIMARY KEY,
	file_path     TEXT NOT NULL,
	filename      TEXT NOT NULL,
	expires_at    INTEGER,           -- unix ts; NULL = never
	max_downloads INTEGER,           -- 0 = unlimited
	downloads     INTEGER DEFAULT 0,
	created_at    INTEGER NOT NULL,
	revoked       INTEGER DEFAULT 0,
	onion_session TEXT,              -- session id, diagnostic only; not the key
	serve_path    TEXT,              -- stripped copy to serve; NULL = file_path
	metadata_stripped INTEGER DEFAULT 0
)`

// addedColumns were added after the first schema; openStore adds them to
// older databases.
var addedColumns = []struct{ name, def string }{
	{"serve_path", "TEXT"},
	{"metadata_stripped", "INTEGER DEFAULT 0"},
}

const shareColumns = `token, file_path, filename, created_at, expires_at, max_downloads, downloads, revoked, onion_session, serve_path, metadata_stripped`

func openStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	// One connection serialises all writes, which keeps increments atomic.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init database: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("upgrade database: %w", err)
	}
	os.Chmod(path, 0o600)
	return &Store{db: db}, nil
}

// migrate adds columns that an older state.db lacks.
func migrate(db *sql.DB) error {
	rows, err := db.Query(`SELECT name FROM pragma_table_info('shares')`)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	for _, c := range addedColumns {
		if !have[c.name] {
			if _, err := db.Exec(`ALTER TABLE shares ADD COLUMN ` + c.name + ` ` + c.def); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Add(sh Share) error {
	if sh.Filename == "" {
		sh.Filename = filepath.Base(sh.Path)
	}
	_, err := s.db.Exec(`INSERT INTO shares(`+shareColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		sh.Token, sh.Path, sh.Filename, sh.Created, nullInt(sh.ExpiresAt), sh.MaxDownloads,
		sh.Count, sh.Revoked, nullString(sh.OnionSession), nullString(sh.ServePath), sh.MetadataStripped)
	return err
}

type scanner interface{ Scan(dest ...any) error }

func scanShare(row scanner) (Share, error) {
	var sh Share
	var expires sql.NullInt64
	var session, servePath sql.NullString
	var stripped sql.NullBool
	err := row.Scan(&sh.Token, &sh.Path, &sh.Filename, &sh.Created, &expires,
		&sh.MaxDownloads, &sh.Count, &sh.Revoked, &session, &servePath, &stripped)
	sh.ExpiresAt = expires.Int64
	sh.OnionSession = session.String
	sh.ServePath = servePath.String
	sh.MetadataStripped = stripped.Bool
	return sh, err
}

func (s *Store) Get(token string) (Share, error) {
	sh, err := scanShare(s.db.QueryRow(`SELECT `+shareColumns+` FROM shares WHERE token = ?`, token))
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, errNotFound
	}
	return sh, err
}

func (s *Store) List() ([]Share, error) {
	rows, err := s.db.Query(`SELECT ` + shareColumns + ` FROM shares ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		sh, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}

func (s *Store) Delete(token string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM shares WHERE token = ?`, token)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Revoke marks a share as revoked, so it stops serving at once. The row is
// removed by the next Prune. It reports whether a live share was revoked.
//
// [diverges from QuickShare] QuickShare deletes the row on revoke.
func (s *Store) Revoke(token string) (bool, error) {
	res, err := s.db.Exec(`UPDATE shares SET revoked = 1 WHERE token = ? AND revoked = 0`, token)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Increment atomically adds one completed download, never exceeding
// max_downloads. It returns the share as it is after the update.
func (s *Store) Increment(token string) (Share, error) {
	_, err := s.db.Exec(`UPDATE shares SET downloads = downloads + 1
		WHERE token = ? AND (max_downloads = 0 OR downloads < max_downloads)`, token)
	if err != nil {
		return Share{}, err
	}
	return s.Get(token)
}

// Prune deletes shares that are revoked, expired, exhausted, or whose file
// is gone. It returns the removed shares.
func (s *Store) Prune(now time.Time) ([]Share, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	var removed []Share
	for _, sh := range all {
		if sh.Active(now) && sh.Servable() {
			continue
		}
		if _, err := s.Delete(sh.Token); err != nil {
			return removed, err
		}
		removed = append(removed, sh)
	}
	return removed, nil
}

func (s *Store) CountActive(now time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM shares
		WHERE revoked = 0
		AND (expires_at IS NULL OR expires_at > ?)
		AND (max_downloads = 0 OR downloads < max_downloads)`, now.Unix()).Scan(&n)
	return n, err
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// nullInt stores 0 as NULL ("never expires").
func nullInt(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: v != 0} }

func nullString(v string) sql.NullString { return sql.NullString{String: v, Valid: v != ""} }
