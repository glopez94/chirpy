// import (
// 	"net/http"
// )

// func main() {
// 	mux := http.NewServeMux()
// 	server := &http.Server{
// 		Addr:    ":8080",
// 		Handler: mux,
// 	}

// 	server.ListenAndServe()
// }

// func main() {
// 	mux := http.NewServeMux()
// 	fileServer := http.FileServer(http.Dir("."))
// 	mux.Handle("/", fileServer)

// 	server := &http.Server{
// 		Addr:    ":8080",
// 		Handler: mux,
// 	}

// 	server.ListenAndServe()
// }

// func main() {
// 	mux := http.NewServeMux()
// 	mux.HandleFunc("/healthz", healthzHandler)

// 	fileServer := http.FileServer(http.Dir("."))
// 	mux.Handle("/app/", http.StripPrefix("/app", fileServer))

// 	server := &http.Server{
// 		Addr:    ":8080",
// 		Handler: mux,
// 	}

// 	server.ListenAndServe()
// }

//	type Handler interface {
//		ServeHTTP(ResponseWriter, *Request)
//	}
// func (cfg *apiConfig) validateChirpHandler(w http.ResponseWriter, r *http.Request) {
// 	type chirp struct {
// 		Body string `json:"body"`
// 	}

// 	var c chirp
// 	decoder := json.NewDecoder(r.Body)
// 	err := decoder.Decode(&c)
// 	if err != nil {
// 		log.Printf("Error decoding chirp: %s", err)
// 		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
// 		return
// 	}

// 	if len(c.Body) > 140 {
// 		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
// 		return
// 	}

//		cleanedBody := replaceProfaneWords(c.Body)
//		respondWithJSON(w, http.StatusOK, map[string]string{"cleaned_body": cleanedBody})
//	}

// func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
// 	type request struct {
// 		Email    string `json:"email"`
// 		Password string `json:"password"`
// 	}

// 	var req request
// 	decoder := json.NewDecoder(r.Body)
// 	err := decoder.Decode(&req)
// 	if err != nil {
// 		log.Printf("Error decoding request: %s", err)
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), req.Email)
// 	if err != nil {
// 		log.Printf("Error retrieving user: %s", err)
// 		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
// 		return
// 	}

// 	err = auth.CheckPasswordHash(req.Password, user.HashedPassword)
// 	if err != nil {
// 		log.Printf("Error comparing password: %s", err)
// 		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
// 		return
// 	}

// 	respondWithJSON(w, http.StatusOK, User{
// 		ID:        user.ID,
// 		CreatedAt: user.CreatedAt,
// 		UpdatedAt: user.UpdatedAt,
// 		Email:     user.Email,
// 	})
// }

// func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
// 	type request struct {
// 		Body   string    `json:"body"`
// 		UserID uuid.UUID `json:"user_id"`
// 	}

// 	var req request
// 	decoder := json.NewDecoder(r.Body)
// 	err := decoder.Decode(&req)
// 	if err != nil {
// 		log.Printf("Error decoding request: %s", err)
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	if len(req.Body) > 140 {
// 		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
// 		return
// 	}

// 	cleanedBody := replaceProfaneWords(req.Body)

// 	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
// 		Body:   cleanedBody,
// 		UserID: uuid.NullUUID{UUID: req.UserID, Valid: true},
// 	})
// 	if err != nil {
// 		log.Printf("Error creating chirp: %s", err)
// 		respondWithError(w, http.StatusInternalServerError, "Could not create chirp")
// 		return
// 	}

//		respondWithJSON(w, http.StatusCreated, Chirp{
//			ID:        chirp.ID,
//			CreatedAt: chirp.CreatedAt,
//			UpdatedAt: chirp.UpdatedAt,
//			Body:      chirp.Body,
//			UserID:    chirp.UserID.UUID,
//		})
//	}

// func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
// 	type request struct {
// 		Email            string `json:"email"`
// 		Password         string `json:"password"`
// 		ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
// 	}

// 	var req request
// 	decoder := json.NewDecoder(r.Body)
// 	err := decoder.Decode(&req)
// 	if err != nil {
// 		log.Printf("Error decoding request: %s", err)
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), req.Email)
// 	if err != nil {
// 		log.Printf("Error retrieving user: %s", err)
// 		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
// 		return
// 	}

// 	err = auth.CheckPasswordHash(req.Password, user.HashedPassword)
// 	if err != nil {
// 		log.Printf("Error comparing password: %s", err)
// 		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
// 		return
// 	}

// 	expiresIn := time.Hour
// 	if req.ExpiresInSeconds > 0 {
// 		expiresIn = time.Duration(req.ExpiresInSeconds) * time.Second
// 		if expiresIn > time.Hour {
// 			expiresIn = time.Hour
// 		}
// 	}

// 	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, expiresIn)
// 	if err != nil {
// 		log.Printf("Error creating JWT: %s", err)
// 		respondWithError(w, http.StatusInternalServerError, "Could not create token")
// 		return
// 	}

//		respondWithJSON(w, http.StatusOK, map[string]any{ //interface{}
//			"id":         user.ID,
//			"created_at": user.CreatedAt,
//			"updated_at": user.UpdatedAt,
//			"email":      user.Email,
//			"token":      token,
//		})
//	}

// func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
// 	type requestData struct {
// 		UserID uuid.UUID `json:"user_id"`
// 	}

// 	type request struct {
// 		Event string      `json:"event"`
// 		Data  requestData `json:"data"`
// 	}

// 	var req request
// 	decoder := json.NewDecoder(r.Body)
// 	err := decoder.Decode(&req)
// 	if err != nil {
// 		log.Printf("Error decoding request: %s", err)
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	if req.Event != "user.upgraded" {
// 		w.WriteHeader(http.StatusNoContent)
// 		return
// 	}

// 	err = cfg.dbQueries.UpgradeUserToChirpyRed(r.Context(), req.Data.UserID)
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			respondWithError(w, http.StatusNotFound, "User not found")
// 		} else {
// 			log.Printf("Error upgrading user to Chirpy Red: %s", err)
// 			respondWithError(w, http.StatusInternalServerError, "Could not upgrade user")
// 		}
// 		return
// 	}

//		w.WriteHeader(http.StatusNoContent)
//	}
package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	// if r.Method != http.MethodGet {
	// 	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	// 	return
	// }
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type User struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	hits := cfg.fileserverHits.Load()
	html := `
        <html>
        <body>
            <h1>Welcome, Chirpy Admin</h1>
            <p>Chirpy has been visited ` + strconv.Itoa(int(hits)) + ` times!</p>
        </body>
        </html>`
	w.Write([]byte(html))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}

	err := cfg.dbQueries.DeleteAllUsers(r.Context())
	if err != nil {
		log.Printf("Error deleting all users: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not delete users")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "All users deleted"})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write([]byte(`{"error":"` + msg + `"}`))
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Something went wrong"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func replaceProfaneWords(text string) string {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Split(text, " ")
	for i, word := range words {
		for _, profaneWord := range profaneWords {
			if strings.ToLower(word) == profaneWord {
				words[i] = "****"
			}
		}
	}
	return strings.Join(words, " ")
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var req request
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not hash password")
		return
	}

	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		log.Printf("Error creating user: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create user")
		return
	}

	respondWithJSON(w, http.StatusCreated, User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	type request struct {
		Body string `json:"body"`
	}

	var req request
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&req)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if len(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleanedBody := replaceProfaneWords(req.Body)

	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: uuid.NullUUID{UUID: userID, Valid: true},
	})
	if err != nil {
		log.Printf("Error creating chirp: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create chirp")
		return
	}

	respondWithJSON(w, http.StatusCreated, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID.UUID,
	})
}

func (cfg *apiConfig) getAllChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.dbQueries.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("Error retrieving chirps: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not retrieve chirps")
		return
	}

	var response []Chirp
	for _, chirp := range chirps {
		response = append(response, Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID.UUID,
		})
	}

	respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	chirpID, err := uuid.Parse(vars["chirpID"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
		} else {
			log.Printf("Error retrieving chirp: %s", err)
			respondWithError(w, http.StatusInternalServerError, "Could not retrieve chirp")
		}
		return
	}

	respondWithJSON(w, http.StatusOK, Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID.UUID,
	})
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	user, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), tokenString)
	if err != nil {
		log.Printf("Error retrieving user from refresh token: %s", err)
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		log.Printf("Error creating JWT: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create token")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
	})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	err = cfg.dbQueries.RevokeRefreshToken(r.Context(), database.RevokeRefreshTokenParams{
		Token:     tokenString,
		RevokedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		log.Printf("Error revoking refresh token: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not revoke refresh token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var req request
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		log.Printf("Error retrieving user: %s", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	err = auth.CheckPasswordHash(req.Password, user.HashedPassword)
	if err != nil {
		log.Printf("Error comparing password: %s", err)
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		log.Printf("Error creating JWT: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create token")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Error creating refresh token: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not create refresh token")
		return
	}

	err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
		ExpiresAt: time.Now().UTC().Add(60 * 24 * time.Hour),
	})
	if err != nil {
		log.Printf("Error storing refresh token: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not store refresh token")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"id":            user.ID,
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
		"email":         user.Email,
		"is_chirpy_red": user.IsChirpyRed,
		"token":         token,
		"refresh_token": refreshToken,
	})
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var req request
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&req)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not hash password")
		return
	}

	user, err := cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		log.Printf("Error updating user: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not update user")
		return
	}

	respondWithJSON(w, http.StatusOK, User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid token")
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	vars := mux.Vars(r)
	chirpID, err := uuid.Parse(vars["chirpID"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
		} else {
			log.Printf("Error retrieving chirp: %s", err)
			respondWithError(w, http.StatusInternalServerError, "Could not retrieve chirp")
		}
		return
	}

	if chirp.UserID.UUID != userID {
		respondWithError(w, http.StatusForbidden, "You are not the author of this chirp")
		return
	}

	err = cfg.dbQueries.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		log.Printf("Error deleting chirp: %s", err)
		respondWithError(w, http.StatusInternalServerError, "Could not delete chirp")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}

	type requestData struct {
		UserID uuid.UUID `json:"user_id"`
	}

	type request struct {
		Event string      `json:"event"`
		Data  requestData `json:"data"`
	}

	var req request
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&req)
	if err != nil {
		log.Printf("Error decoding request: %s", err)
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	err = cfg.dbQueries.UpgradeUserToChirpyRed(r.Context(), req.Data.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
		} else {
			log.Printf("Error upgrading user to Chirpy Red: %s", err)
			respondWithError(w, http.StatusInternalServerError, "Could not upgrade user")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	dbQueries := database.New(db)
	platform := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	apiCfg := &apiConfig{
		dbQueries: dbQueries,
		platform:  platform,
		jwtSecret: jwtSecret,
		polkaKey:  polkaKey,
	}

	r := mux.NewRouter()
	r.HandleFunc("/api/healthz", healthzHandler).Methods("GET")
	r.HandleFunc("/admin/metrics", apiCfg.metricsHandler).Methods("GET")
	r.HandleFunc("/admin/reset", apiCfg.resetHandler).Methods("POST")
	r.HandleFunc("/api/chirps", apiCfg.createChirpHandler).Methods("POST")
	r.HandleFunc("/api/chirps", apiCfg.getAllChirpsHandler).Methods("GET")
	r.HandleFunc("/api/chirps/{chirpID}", apiCfg.getChirpByIDHandler).Methods("GET")
	r.HandleFunc("/api/users", apiCfg.createUserHandler).Methods("POST")
	r.HandleFunc("/api/login", apiCfg.loginHandler).Methods("POST")
	r.HandleFunc("/api/refresh", apiCfg.refreshHandler).Methods("POST")
	r.HandleFunc("/api/revoke", apiCfg.revokeHandler).Methods("POST")
	r.HandleFunc("/api/users", apiCfg.updateUserHandler).Methods("PUT")
	r.HandleFunc("/api/chirps/{chirpID}", apiCfg.deleteChirpHandler).Methods("DELETE")
	r.HandleFunc("/api/polka/webhooks", apiCfg.polkaWebhookHandler).Methods("POST")

	fileServer := http.FileServer(http.Dir("."))
	r.PathPrefix("/app/").Handler(apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fileServer)))

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	server.ListenAndServe()
}
