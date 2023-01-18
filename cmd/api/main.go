package main

import (
	// "context"

	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/danilopolani/gocialite"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt"
	_ "github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v4"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/josipfrljic94/go-login-system/app/data"
	"github.com/josipfrljic94/go-login-system/app/driver"
)

var db *sql.DB
var gocial = gocialite.NewDispatcher()

var (
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:3000/auth/google/callback",
		ClientID:     "70286887762-k24a0qsvu48av6j2r8n4ivn35c86be6g.apps.googleusercontent.com",
		ClientSecret: "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",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
	oauthStateString = "random"
)

func main() {
	// Initialize the database connection

	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USERNAME")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	DSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s",
		host, port, user, password, dbname)
	dsn := DSN
	fmt.Println(dsn)
	db, err := driver.ConnectPostgres(dsn)
	if err != nil {
		log.Fatal("Cannot connect to database")
	}
	defer db.SQL.Close()

	data.New(db.SQL)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Basic CORS
	// for more ideas, see: https://developer.github.com/v3/#cross-origin-resource-sharing
	r.Use(cors.Handler(cors.Options{
		// AllowedOrigins:   []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins: []string{"https://*", "http://*"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
	}))

	r.Get("/auth/google", handleGoogleLogin)
	r.Get("/auth/google/callback", handleGoogleCallback)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello\n"))
	})
	r.Post("/register", func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.JSON(w, r, map[string]string{"error": err.Error()})
			return
		}

		// Hash the password
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			render.JSON(w, r, map[string]string{"error": err.Error()})
			return
		}

		// Insert the new user into the database
		_, err = db.SQL.ExecContext(r.Context(), "INSERT INTO golang_users (email, password, name, created_at) VALUES ($1, $2, $3, $4)", req.Email, hash, req.Name, time.Now())
		if err != nil {
			render.JSON(w, r, map[string]string{"error": err.Error()})
			return
		}

		render.JSON(w, r, map[string]string{"message": "Successfully registered"})
	})
	r.Post("/login", Login)

	http.ListenAndServe(":3000", r)
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// func GetUsers(w *http.ResponseWriter, r *http.Request){

// }

func Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.JSON(w, r, map[string]string{"error": err.Error()})
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		render.JSON(w, r, map[string]string{"error": err.Error()})
		return
	}

	// Insert the new user into the database
	_, err = db.ExecContext(r.Context(), "INSERT INTO golang_users (email, password, name, created_at) VALUES ($1, $2, $3, $4)", req.Email, hash, req.Name, time.Now())
	if err != nil {
		render.JSON(w, r, map[string]string{"error": err.Error()})
		return
	}

	render.JSON(w, r, map[string]string{"message": "Successfully registered"})
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.JSON(w, r, map[string]string{"error": err.Error()})
		return
	}

	// Get the hashed password from the database
	var hashedPassword []byte
	err := db.QueryRowContext(r.Context(), "SELECT password FROM users WHERE email = $1", req.Email).Scan(&hashedPassword)
	if err != nil {
		render.JSON(w, r, map[string]string{"error": "Invalid email or password"})
		return
	}

	// Compare the provided password with the hashed password
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(req.Password))
	if err != nil {
		render.JSON(w, r, map[string]string{"error": "Invalid email or password"})
		return
	}

	// Generate a JSON web token
	token, err := generateJWT(req.Email)
	if err != nil {
		render.JSON(w, r, map[string]string{"error": err.Error()})
		return
	}

	render.JSON(w, r, map[string]string{"token": token})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	// Invalidate the JSON web token
	// This can be done by adding the token to a blacklist or by setting its expiration time
	// ...
	render.JSON(w, r, map[string]string{"message": "Successfully logged out"})
}

var jwtSecret = []byte("YOUR_SECRET_KEY")

func generateJWT(email string) (string, error) {
	// Create a new token object with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
	})

	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	content, err := getUserInfo(r.FormValue("state"), r.FormValue("code"))
	if err != nil {
		fmt.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Fprintf(w, "Content: %s\n", content)
}

func getUserInfo(state string, code string) ([]byte, error) {
	if state != oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	return contents, nil
}
