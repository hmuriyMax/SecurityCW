package httpservice

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hmuriyMax/SecurityCW/internal/authservise"
	"log"
	"net/http"
	"time"
)

const symLength = 5

type HTTPService struct {
	port       int
	host       string
	mux        *mux.Router
	server     *http.Server
	auth       *authservise.AuthService
	errChan    chan error
	ctx        context.Context
	cancel     context.CancelFunc
	logger     *log.Logger
	IDEditable bool
}

func NewHTTPService(port int, host string, lg *log.Logger, IDEditable bool) (srv HTTPService) {
	srv.port = port
	srv.host = host
	srv.errChan = make(chan error)
	srv.ctx, srv.cancel = context.WithCancel(context.Background())
	srv.logger = lg
	srv.logger.SetFlags(log.Ldate | log.Lmicroseconds)
	srv.mux = mux.NewRouter()
	srv.IDEditable = IDEditable

	srv.server = &http.Server{
		Addr:        fmt.Sprintf("%s:%d", srv.host, srv.port),
		Handler:     srv.mux,
		ReadTimeout: 1 * time.Second,
	}
	return
}

func (s *HTTPService) Start() {
	s.logger.Printf("Starting HTTP server on http://%v:%v\n", s.host, s.port)
	go s.serve()
}

func (s *HTTPService) serve() {
	if s.server == nil || s.mux == nil {
		s.errChan <- fmt.Errorf("server or router is not initialized")
	}
	s.addHandlers()

	go func() {
		err := s.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			s.errChan <- err
		}
	}()

	select {
	case err := <-s.errChan:
		s.errChan <- fmt.Errorf("server start failed: %v", err)
	case <-s.ctx.Done():
		shutCtx, cFunc := context.WithTimeout(context.Background(), 2*time.Second)
		defer cFunc()
		err := s.server.Shutdown(shutCtx)
		if err == shutCtx.Err() {
			s.errChan <- fmt.Errorf("server shutdown context exceeded: %v", err)
		}
	}
}

func (s *HTTPService) GetErrChan() <-chan error {
	return s.errChan
}

func (s *HTTPService) Stop() {
	if s.auth != nil {
		s.auth.Close()
	}
	s.cancel()
}

func (s *HTTPService) ConnectAuthService(service *authservise.AuthService) {
	s.auth = service
}

func (s *HTTPService) addHandlers() {
	fileServer := http.FileServer(http.Dir("./web/res"))
	s.mux.PathPrefix("/res").Handler(http.StripPrefix("/res/", fileServer))
	s.mux.HandleFunc("/", s.indexHandler)
	s.mux.HandleFunc("/auth", s.authHandler)
	s.mux.HandleFunc("/newpass", s.newPassHandler)
	s.mux.HandleFunc("/firstsign", s.firstSignHandler)
	s.mux.HandleFunc("/changepass", s.changePassHandler)
	s.mux.HandleFunc("/adduser", s.adduserHandler)
	s.mux.HandleFunc("/checklogin", s.checkLogHandler)
	s.mux.HandleFunc("/changeblock", s.changeBlockHandler)
	s.mux.HandleFunc("/changerestr", s.changeRestrHandler)
	s.mux.HandleFunc("/logout", s.logoutHandler)
}
