package storage

import "errors"

var ErrSQLiteNotImplemented = errors.New("sqlite backend is not implemented in v1; use STORAGE_BACKEND=jsonl")

