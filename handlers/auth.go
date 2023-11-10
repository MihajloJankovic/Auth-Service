package handlers

import (
	"context"
	"errors"
	"log"

	protos "github.com/MihajloJankovic/Auth-Service/protos/main"
)

type myAuthServer struct {
	protos.UnimplementedAuthServer
	logger *log.Logger
	// NoSQL: injecting product repository
	repo *AuthRepo
}

func NewServer(l *log.Logger, r *AuthRepo) *myAuthServer {
	return &myAuthServer{*new(protos.UnimplementedAuthServer), l, r}
}

func (s myAuthServer) Register(ctx context.Context, in *protos.AuthRequest) (*protos.AuthEmpty, error) {
	out := new(protos.AuthResponse)
	out.Email = in.GetEmail()
	out.Password = in.GetPassword()
	out.Ticket = RandomString(18)
	out.Activated = false

	err := s.repo.Create(out)
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	return new(protos.AuthEmpty), nil
}

func (s myAuthServer) Login(ctx context.Context, in *protos.AuthRequest) (*protos.AuthGet, error) {
	success, email, err := s.repo.Login(in.GetEmail(), in.GetPassword())
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	if !success {
		return nil, errors.New("login failed")
	}
	return &protos.AuthGet{Email: email}, nil
}

func (s myAuthServer) GetTicket(ctx context.Context, in *protos.AuthGet) (*protos.AuthTicket, error) {
	out, err := s.repo.GetTicketByEmail(in.GetEmail())
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	return &protos.AuthTicket{Ticket: out.Ticket}, nil
}

func (s myAuthServer) Activate(ctx context.Context, in *protos.ActivateRequest) (*protos.AuthResponse, error) {
	out, err := s.repo.Activate(in.GetEmail(), in.GetTicket())
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	return out, nil
}
