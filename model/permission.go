package model

type Permission struct {
	Model

	Action   string
	Resource string
}
