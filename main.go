package main

import (
	"context"
	protosava "github.com/MihajloJankovic/Aviability-Service/protos/main"
	protosAcc "github.com/MihajloJankovic/accommodation-service/protos/main"
	protosprof "github.com/MihajloJankovic/profile-service/protos/main"
	protosRes "github.com/MihajloJankovic/reservation-service/protos/genfiles"
	"google.golang.org/grpc/credentials/insecure"
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
//acc,profile,ava,res
	conn, err := grpc.Dial("profile-service:9091", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)
	cc := protosprof.NewProfileClient(conn)
	connAva, err := grpc.Dial("avaibility-service:9095", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			log.Println(err)
		}
	}(connAva)

	ccava := protosava.NewAccommodationAviabilityClient(connAva)
	connRes, err := grpc.Dial("reservation-service:9096", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer func(connRes *grpc.ClientConn) {
		err := connRes.Close()
		if err != nil {

		}
	}(connRes)
	resc := protosRes.NewReservationClient(connRes)
	connAcc, err := grpc.Dial("accommodation-service:9093", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer func(connAcc *grpc.ClientConn) {
		err := connAcc.Close()
		if err != nil {

		}
	}(connAcc)
	acc := protosAcc.NewAccommodationClient(connAcc)
	//Initialize the handler and inject said logger
	service := handlers.NewServer(logger, authRepo,acc,cc,ccava,resc)

	protos.RegisterAuthServer(serverRegistar, service)
	err = serverRegistar.Serve(lis)
	if err != nil {
		log.Fatal(err)
	}
}
