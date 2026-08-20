package internal

import (
	"log/slog"

	"github.com/abundo/dnsmgr2/models"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func ConnectDatabase(dbfile string) (*gorm.DB, error) {
	slog.Info("Opening", "database", dbfile)
	db, err := gorm.Open(sqlite.Open(dbfile), &gorm.Config{})

	if err != nil {
		return nil, err
	}
	return db, nil
}

func MigrateDatabase(db *gorm.DB) error {
	err := db.AutoMigrate(
		&models.Zone{},
	)
	if err != nil {
		return err
	}
	return nil
}

func ConnectMigrate(dbfile string) (*gorm.DB, error) {
	db, err := ConnectDatabase(dbfile)
	if err != nil {
		return nil, err
	}
	err = MigrateDatabase(db)
	if err != nil {
		return nil, err
	}
	return db, nil
}
