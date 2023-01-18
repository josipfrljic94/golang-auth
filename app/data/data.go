package data

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const dbTimeout = time.Second * 3

var db *sql.DB

func New(dbPool *sql.DB) Models {
	db = dbPool
	return Models{
		User:  User{},
		Token: Token{},
	}
}

type Models struct {
	User  User
	Token Token
}

type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name",omitempty"`
	LastName  string    `json:"last_name",omitempty"`
	UserName  string    `json:"user_name"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Token     Token     `json:"token"`
}

func (u *User) GetAll() ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select select id, email, first_name, last_name,user_name, password, created_at, update_at from users order by last_name`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User

	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.FirstName,
			&user.LastName,
			&user.UserName,
			&user.Password,
			&user.UpdatedAt,
			&user.CreatedAt,
		)

		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, nil
}

func getByEmail(email string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name,user_name, password, created_at, update_at from users where email = $1`
	row := db.QueryRowContext(ctx, query, email)
	var user User
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.UserName,
		&user.Password,
		&user.UpdatedAt,
		&user.CreatedAt,
	)

	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (u *User) Update() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	stmt, err := db.PrepareContext(ctx, `UPDATE users SET 
	email=$1,
	first_name=$2,
	last_name=$3,
	user_name=$4,
	password=$5,
	updated_at=$6,
	where id=$7
	`)

	if err != nil {
		return err
	}

	defer stmt.Close()
	_, err = stmt.Exec(ctx, u.Email, u.FirstName, u.LastName, u.UserName, u.Password, time.Now(), u.ID)

	if err != nil {
		return err
	}

	return nil
}

func (u *User) Delete() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	stmt := `delete from users where id = $1`

	_, err := db.ExecContext(ctx, stmt, u.ID)

	if err != nil {
		return err
	}

	return nil
}

func (u *User) Insert(user User) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	// stmtString:=`INSERT INTO users (email, first_name, last_name,user_name,password, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`
	// stmt,err := db.PrepareContext(ctx,stmtString)

	// if err != nil {
	// 	return 0, err
	// }

	// defer stmt.Close()

	// _, err = stmt.Exec(ctx, user.ID)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	if err != nil {
		fmt.Printf("Error generating %v", err)
		return 0, err
	}
	var newId int
	stmt := `INSERT INTO users (email, first_name, last_name,user_name,password, created_at, updated_at) VALUES ($1, $2, $3, $4, $5,$6,$7)`
	err = db.QueryRowContext(ctx, stmt, user.Email, user.FirstName, user.LastName, user.UserName, hashedPassword, time.Now(), time.Now()).Scan(&newId)

	if err != nil {
		return 0, err
	}

	return newId, nil
}

func (u *User) ResetPassword(password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)

	if err != nil {
		return err
	}

	stmt := `update users set password = $1 WHERE id=$2`

	_, err = db.ExecContext(ctx, stmt, hashedPassword, u.ID)

	if err != nil {
		return err
	}

	return nil
}

// func (u *User) PasswordMatches(plainText string) (bool, error) {
// 	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(plainText))

// 	if err != nil {
// 		switch {

// 		}
// 	}
// }

type Token struct {
	ID        int       `json:"id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
	TokenHash []byte    `json:"_"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Expiry    time.Time `json:"expiry"`
}
