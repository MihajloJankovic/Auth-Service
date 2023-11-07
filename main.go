package main

import (
	"context"
	"log"
	"net"
	"os"
	"time"

	"github.com/MihajloJankovic/Auth-Service/handlers"
	protos "github.com/MihajloJankovic/Auth-Service/protos/main"
	"google.golang.org/grpc"
)

func main() {

	lis, err := net.Listen("tcp", ":9094")
	if err != nil {
		log.Fatal(err)
	}
	serverRegistar := grpc.NewServer()

	timeoutContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := log.New(os.Stdout, "[auth-main] ", log.LstdFlags)
	authlog := log.New(os.Stdout, "[auth-repo-log] ", log.LstdFlags)

	authRepo, err := handlers.New(timeoutContext, authlog)
	if err != nil {
		logger.Fatal(err)
	}
	defer authRepo.Disconnect(timeoutContext)

	// NoSQL: Checking if the connection was established
	authRepo.Ping()

	//Initialize the handler and inject said logger
	service := handlers.NewServer(logger, authRepo)

	protos.RegisterAuthServer(serverRegistar, service)
	err = serverRegistar.Serve(lis)
	if err != nil {
		log.Fatal(err)
	}
}
