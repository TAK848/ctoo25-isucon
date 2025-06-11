// package chiinteg

// import (
// 	"github.com/go-chi/chi/v5"
// 	"github.com/kaz/pprotein/integration"
// )

// // Integrate sets up debugging for the chi router
// func Integrate(r *chi.Mux) {
// 	EnableDebugHandler(r)
// 	EnableDebugMode(r)
// }

// // EnableDebugHandler registers debug handlers to the router
// func EnableDebugHandler(r *chi.Mux) {
// 	integration.RegisterDebugHandlers(r)
// }

// // EnableDebugMode enables debugging mode (currently a no-op)
// func EnableDebugMode(r *chi.Mux) {
// 	// This function does nothing for now
// 	return
// }

package chiinteg

import (
	"github.com/go-chi/chi/v5"
	"github.com/kaz/pprotein/integration"
)

func Integrate(r *chi.Mux) {
	EnableDebugHandler(r)
	EnableDebugMode(r)
}

func EnableDebugHandler(r *chi.Mux) {
	// ginやecho版のように /debug/* へのアクセスを integration.NewDebugHandler() に委譲
	r.Handle("/debug/*", integration.NewDebugHandler())
}

func EnableDebugMode(r *chi.Mux) {
	// chiにはginやechoのように直接デバッグモードを有効化する仕組みはないため、
	// 必要に応じてログやリカバリ用のミドルウェアを追加するなどしてください。
	// 例:
	// r.Use(middleware.RequestLogger(&middleware.DefaultLogFormatter{}))
	// r.Use(middleware.Recoverer)
	return
}
