package handlers

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
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

// isValidEmailFormat checks if the given email is in a valid format.
func isValidEmailFormat(email string) bool {
	// Perform a simple check for '@' and '.com'
	return strings.Contains(email, "@") && strings.HasSuffix(email, ".com")
}
func (s myAuthServer) Register(ctx context.Context, in *protos.AuthRequest) (*protos.AuthEmpty, error) {

	// Validate email and password here
	if in.GetEmail() == "" || in.GetPassword() == "" {
		return nil, errors.New("Invalid input. Email and password are required.")
	}
	// Check if it's a valid email format
	if !isValidEmailFormat(in.GetEmail()) {
		return nil, errors.New("Invalid email format.")
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
	// Validate email and password here
	if in.GetEmail() == "" || in.GetPassword() == "" {
		return nil, errors.New("Invalid input. Email and password are required.")
	}
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

func (s myAuthServer) ChangePassword(ctx context.Context, in *protos.ChangePasswordRequest) (*protos.AuthEmpty, error) {
	// Validate email, currentPassword, and newPassword here
	if in.GetEmail() == "" || in.GetCurrentPassword() == "" || in.GetNewPassword() == "" {
		return nil, errors.New("Invalid input. Email, current password, and new password are required.")
	}

	currentAuth, err := s.repo.GetByEmail(in.GetEmail())
	if err != nil {
		s.logger.Println(err)
		return nil, err
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

	return new(protos.AuthEmpty), nil
}
