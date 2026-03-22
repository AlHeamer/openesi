package sde

import (
	"strconv"

	"golang.org/x/exp/constraints"
)

func nullableFloat[T constraints.Float](val T) string {
	if val != 0.0 {
		return strconv.FormatFloat(float64(val), 'e', -1, 64)
	}
	return "NULL"
}

func nullableInt[T constraints.Integer](val T) string {
	if int64(val) != 0 {
		return strconv.FormatInt(int64(val), 10)
	}

	return "NULL"
}

func nullableBool(val bool) string {
	if val {
		return "1"
	}
	return "0"
}
