package handlers

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"os"
	"strings"

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

	if isPasswordInBlacklist(in.GetPassword()) {
		return nil, errors.New("Please try another password!")
	}

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

	// Send activation link to the user via email
	activationLink := fmt.Sprintf("http://localhost:9090/activate/%s/%s", out.Email, out.Ticket)

	if err := sendActivationEmail(out.Email, activationLink); err != nil {
		s.logger.Println("Failed to send activation email:", err)
		// You can choose to return an error or handle it as appropriate for your application
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

func (s myAuthServer) ChangePassword(ctx context.Context, in *protos.ChangePasswordRequest) (*protos.Empty, error) {

	currentAuth, err := s.repo.GetByEmail(in.GetEmail())
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}

	if isPasswordInBlacklist(in.GetNewPassword()) {
		return nil, errors.New("New password blacklisted!")
	}

	// Check if the provided current password matches the stored password
	if err := bcrypt.CompareHashAndPassword([]byte(currentAuth.GetPassword()), []byte(in.GetCurrentPassword())); err != nil {
		s.logger.Println(err)
		return nil, errors.New("current password is incorrect")
	}

	// Generate and set the new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(in.GetNewPassword()), 14)
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	currentAuth.Password = string(newPasswordHash)

	if err := s.repo.Update(currentAuth); err != nil {
		s.logger.Println(err)
		return nil, err
	}

	return new(protos.Empty), nil
}

func isPasswordInBlacklist(password string) bool {
	blacklistFile, err := os.Open("password-blacklist.txt")
	if err != nil {

		log.Println("Warning: Unable to open password blacklist file")
		return false
	}
	defer blacklistFile.Close()

	blacklistData, err := ioutil.ReadAll(blacklistFile)
	if err != nil {

		log.Println("Warning: Unable to read password blacklist file")
		return false
	}

	blacklistLines := strings.Split(string(blacklistData), "\n")

	for _, line := range blacklistLines {
		if strings.TrimSpace(line) == password {
			return true
		}
	}

	return false
}
