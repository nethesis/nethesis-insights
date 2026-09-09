// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package sqlitex opens a SQLite database with the runtime settings this
// project requires everywhere: WAL, a busy timeout, a single connection, and
// a mutex that serializes writes. The spec asks for a single writer
// goroutine; a mutex gives the same guarantee with no lifecycle to leak.
package sqlitex

import (
	"database/sql"
	"fmt"
	"sync"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"
)

// DB is a *bun.DB plus the write mutex. Every store in this repository
// embeds one; Lock/Unlock is what makes "single writer" true across three
// processes that each own their own file.
type DB struct {
	*bun.DB
	mu sync.Mutex
}

func (d *DB) Lock()   { d.mu.Lock() }
func (d *DB) Unlock() { d.mu.Unlock() }

func (d *DB) Close() error { return d.DB.DB.Close() }

func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlitex: open: %w", err)
	}
	sqldb.SetMaxOpenConns(1)
	return &DB{DB: bun.NewDB(sqldb, sqlitedialect.New())}, nil
}
