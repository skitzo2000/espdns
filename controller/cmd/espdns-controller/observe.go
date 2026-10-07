package main

// The Dashboard and Query log pages' APIs (internal/observe): GET only, JSON. The dashboard
// is open as the node list is (read-only without a password); the query log and the names
// in it need a login, as the configs do: they say who asked for what.

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/skitzo2000/espdns/controller/internal/observe"
)

type observeServer struct {
	store *observe.Store
}

func (o observeServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/dashboard", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, o.store.Dashboard())
	})
	// ?node=<key>&client=&name=&result=&qtype=&after=<id>&run=<its run>&limit=
	mux.HandleFunc("GET /api/querylog", needLogin("the query log needs", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := observe.Filter{Node: q.Get("node"), Client: q.Get("client"), Name: q.Get("name"),
			Result: q.Get("result"), QType: q.Get("qtype"), Run: q.Get("run")}
		if s := q.Get("after"); s != "" {
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				httpErr(w, http.StatusBadRequest, errors.New("after: a whole number"))
				return
			}
			f.After = n
		}
		if s := q.Get("limit"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				httpErr(w, http.StatusBadRequest, errors.New("limit: a whole number, 1 or more"))
				return
			}
			f.Limit = n
		}
		writeJSON(w, o.store.Log(f))
	}))
	// The names asked most in what the controller holds of the query log (?node=<key>).
	mux.HandleFunc("GET /api/querylog/top", needLogin("the query log needs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, o.store.Top(r.URL.Query().Get("node")))
	}))
}
