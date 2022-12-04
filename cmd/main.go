package main

import (
	"fmt"
	"github.com/hmuriyMax/SecurityCW/internal/authservise"
	"github.com/hmuriyMax/SecurityCW/internal/httpservice"
	"log"
	"os"
)

const usersPath = "./database"
const tokensPath = "./tokens"

func main() {
	logger := log.Default()
	logger.SetFlags(log.Ldate | log.Lmicroseconds)

	authSvc, err := authservise.NewAuthService(usersPath, tokensPath)
	if err != nil {
		log.Fatal(err)
	}

	httpSvc := httpservice.NewHTTPService(80, "127.0.0.1", logger, true)
	httpSvc.ConnectAuthService(authSvc)
	httpSvc.Start()

	go func() {
		select {
		case err := <-httpSvc.GetErrChan():
			if err != nil {
				log.Println(err)
				return
			}
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
	httpSvc.Stop()
}
