package internal

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/abundo/dnsmgr2/models"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func ConnectDatabase(dbfile string) (*gorm.DB, error) {
	if strings.TrimSpace(dbfile) == "" {
		return nil, errors.New("dbfile is empty")
	}
	if dir := filepath.Dir(dbfile); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
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

func CloseDB(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
