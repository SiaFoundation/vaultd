package sqlite

import (
	"database/sql/driver"
	"errors"
	"time"

	"go.sia.tech/core/types"
)

type (
	sqlTime time.Time
)

func (st sqlTime) Value() (driver.Value, error) {
	return time.Time(st).UnixMilli(), nil
}

func (st *sqlTime) Scan(src any) error {
	if t, ok := src.(int64); ok {
		*st = sqlTime(time.UnixMilli(t))
		return nil
	}
	return errors.New("invalid type")
}

type sqlPublicKey types.PublicKey

func (pk sqlPublicKey) Value() (driver.Value, error) {
	return pk[:], nil
}

func (pk *sqlPublicKey) Scan(src any) error {
	if b, ok := src.([]byte); ok {
		copy((*pk)[:], b)
		return nil
	}
	return errors.New("invalid type")
}

type sqlHash256 types.Hash256

func (h sqlHash256) Value() (driver.Value, error) {
	return h[:], nil
}

func (h *sqlHash256) Scan(src any) error {
	if b, ok := src.([]byte); ok {
		copy((*h)[:], b)
		return nil
	}
	return errors.New("invalid type")
}
