package model

type Model struct {
	ID        uint64 `json:"-"`
	UUID      string `json:"uuid"`
	CreatedAt int    `json:"created_at"`
	UpdatedAt int    `json:"updated_at"`
	DeletedAt uint   `json:"-"`
}
