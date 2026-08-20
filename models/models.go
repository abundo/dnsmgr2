package models

import "gorm.io/gorm"

type Zone struct {
	gorm.Model
	Name       string `json:"name"`
	SerialDate string `json:"serial_date"` // 20241230
	SerialSeq  int    `json:"serial_seq"`  // 00-99
}
