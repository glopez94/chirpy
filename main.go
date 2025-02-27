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
package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
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
	html := fmt.Sprintf(`
		<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
		</html>`, hits)
	w.Write([]byte(html))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("Hits reset to 0"))
}

func main() {
	apiCfg := &apiConfig{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	fileServer := http.FileServer(http.Dir("."))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fileServer)))

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()
}
