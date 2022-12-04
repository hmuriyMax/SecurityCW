package main

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hmuriyMax/SecurityCW/internal/authservise"
	"github.com/hmuriyMax/SecurityCW/internal/httpservice"
	"log"
	"net/http"
	"os"
)

var users authservise.Database

const usersPath = "./database"
const tokensPath = "./tokens"

var tokens authservise.Tokens

func main() {
	_, err := users.Open(usersPath)
	if err != nil {
		log.Fatal(err)
	}
	defer users.Close()

	_, err = tokens.Open(tokensPath)
	if err != nil {
		return
	}
	defer tokens.Close()

	port := "80"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	router := mux.NewRouter()
	server := http.Server{Handler: router}
	ctx, canselfunc := context.WithCancel(context.Background())
	defer func() { _ = server.Shutdown(ctx); canselfunc() }()
	router.StrictSlash(false)
	fileServer := http.FileServer(http.Dir("./web/res"))
	router.PathPrefix("/res").Handler(http.StripPrefix("/res/", fileServer))
	router.HandleFunc("/", httpservice.indexHandler)
	router.HandleFunc("/auth", httpservice.authHandler)
	router.HandleFunc("/newpass", httpservice.newPassHandler)
	router.HandleFunc("/firstsign", httpservice.firstSignHandler)
	router.HandleFunc("/changepass", httpservice.changePassHandler)
	router.HandleFunc("/adduser", httpservice.adduserHandler)
	router.HandleFunc("/checklogin", httpservice.checkLogHandler)
	router.HandleFunc("/changeblock", httpservice.changeBlockHandler)
	router.HandleFunc("/changerestr", httpservice.changeRestrHandler)
	router.HandleFunc("/logout", httpservice.logoutHandler)
	log.Printf("HTTP-server started! http://localhost:%s\n", port)
	go func() {
		err = http.ListenAndServe(":"+port, router)
		if err != nil {
			log.Fatal(err)
		}
	}()
	fmt.Println("To stop server enter \"stop\" command")
	var command string
	for {
		_, err := fmt.Fscanln(os.Stdin, &command)
		if command == "stop" || err != nil {
			break
		}
	}
}
