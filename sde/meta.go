package sde

import "time"

type Meta struct {
	Key         string    `json:"_key,omitempty"`
	BuildNumber int64     `json:"buildNumber,omitempty"`
	ReleaseDate time.Time `json:"releaseDate"`
}
