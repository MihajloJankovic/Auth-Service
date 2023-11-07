package handlers

import (
	"context"
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
// OVE METODE MORAJU BIT IMPLEMENTIRANE BAS OVAKO JER SI IH TAKO U APP PROTO . MORAS PROMENITI
//U APP PROTO AKO ZELIS DA KORISTIS OVE METODE , JER NISU U INTERFEJUS KOJI IMA KLIJENT .
//DODAJ LOGIN OVDE KAO METODU I OVE KOJE IMAS OVDE A NEMAS U INTERFEJSU MORAS DODATI I APP.PROTO

//Register(context.Context, *AuthRequest) (*Empty, error)
//Login(context.Context, *AuthRequest) (*Empty, error)
//GetAuth(context.Context, *AuthGet) (*AuthResponse, error)

// add edit,create user ,delete user
func (s myAuthServer) GetAuth(ctx context.Context, in *protos.AuthGet) (*protos.AuthResponse, error) {

	out, err := s.repo.GetByUsername(in.GetUsername())
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	return out, nil
}

func (s myAuthServer) Register(ctx context.Context, in *protos.AuthRequest) (*protos.Empty, error) {

	out := new(protos.AuthResponse)
	out.Username = in.GetUsername()
	out.Password = in.GetPassword()

	err := s.repo.Create(out)
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	return new(protos.Empty), nil
}
func (s myAuthServer) UpdateAuth(kon context.Context, in *protos.AuthResponse) (*protos.Empty, error) {
	err := s.repo.Update(in)
	if err != nil {
		return nil, err
	}
	return new(protos.Empty), nil
}
