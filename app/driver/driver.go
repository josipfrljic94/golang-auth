package driver

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v4"
	_ "github.com/jackc/pgx/v4/stdlib"
)

type DB struct {
	SQL *sql.DB
}

var dbConn = &DB{}

const maxOpenDBConn = 5
const maxIdleDBConn = 5
const maxDBLifeTime = 5 * time.Minute

func ConnectPostgres(dsn string) (*DB, error) {
	d, err := sql.Open("pgx", dsn)

	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(maxOpenDBConn)
	d.SetMaxIdleConns(maxIdleDBConn)
	d.SetConnMaxLifetime(maxDBLifeTime)

	err = testDB(err, d)

	dbConn.SQL = d
	return dbConn, err
}

func testDB(err error, d *sql.DB) error {
	err = d.Ping()
	if err != nil {
		fmt.Println("error: ", err)
	} else {
		fmt.Println("** Pinged db succesfully*")
	}
	return err

}
