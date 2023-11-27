package handlers

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
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

// trimSpace trims leading and trailing whitespaces from a string.
func trimSpace(s string) string {
	return strings.TrimSpace(s)
}
func (s myAuthServer) Register(ctx context.Context, in *protos.AuthRequest) (*protos.AuthEmpty, error) {
	// Validate email and password here
	if in.GetEmail() == "" || in.GetPassword() == "" {
		return nil, errors.New("Invalid input. Email and password are required.")
	}

	// Trim leading and trailing whitespaces from email and password
	email := trimSpace(in.GetEmail())
	password := trimSpace(in.GetPassword())

	// Check if it's a valid email format
	if !isValidEmailFormat(email) {
		return nil, errors.New("Invalid email format.")
	}

	if isPasswordInBlacklist(password) {
		return nil, errors.New("Password on blacklist!")
	}

	out := new(protos.AuthResponse)
	out.Email = email
	out.Password = password
	out.Ticket = RandomString(18)
	out.Activated = false
	out.TicketReset = RandomString(24)
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

	// Trim leading and trailing whitespaces from email and password
	email := trimSpace(in.GetEmail())
	password := trimSpace(in.GetPassword())

	success, userEmail, err := s.repo.Login(email, password)
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	if !success {
		return nil, errors.New("login failed")
	}
	return &protos.AuthGet{Email: userEmail}, nil
}

func (s myAuthServer) GetTicket(ctx context.Context, in *protos.AuthGet) (*protos.AuthTicket, error) {
	out, err := s.repo.GetTicketByEmail(in.GetEmail())
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}
	return &protos.AuthTicket{Ticket: out.Ticket}, nil
}
func (s myAuthServer) Delete(ctx context.Context, in *protos.AuthGet) (*protos.AuthEmpty, error) {
	// Validate email
	if in.GetEmail() == "" {
		return nil, errors.New("Invalid input. Email is required.")
	}

	// Perform the delete operation
	err := s.repo.DeleteByEmail(in.GetEmail())
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}

	return new(protos.AuthEmpty), nil
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

	return new(protos.AuthEmpty), nil
}

func (s myAuthServer) RequestPasswordReset(ctx context.Context, in *protos.AuthGet) (*protos.AuthEmpty, error) {
	if in.GetEmail() == "" {
		return nil, errors.New("Invalid input. Email is required.")
	}

	// Generate a new random string for ticketReset and store it in the database
	newTicketReset := RandomString(24)
	if err := s.repo.UpdateResetTicket(in.GetEmail(), newTicketReset); err != nil {
		s.logger.Println(err)
		return nil, err
	}

	// Send the reset link to the user via email
	resetLink := fmt.Sprintf("http://localhost:9090/reset/%s/%s", in.GetEmail(), newTicketReset)

	if err := sendResetLinkEmail(in.GetEmail(), resetLink); err != nil {
		s.logger.Println("Failed to send reset email:", err)
		// You can choose to return an error or handle it as appropriate for your application
	}

	return new(protos.AuthEmpty), nil
}

func (s myAuthServer) ResetPassword(ctx context.Context, in *protos.ResetRequest) (*protos.AuthGet, error) {
	// Validate email and reset ticket
	if in.GetEmail() == "" || in.GetTicketReset() == "" {
		return nil, errors.New("Invalid input. Email and reset ticket are required.")
	}

	// Check if the provided reset ticket is valid
	isValid, err := s.repo.ValidateResetTicket(in.GetEmail(), in.GetTicketReset())
	if err != nil {
		s.logger.Println(err)
		return nil, err
	}

	if !isValid {
		return nil, errors.New("Invalid or expired reset ticket.")
	}

	// Use the provided new password and update it in the database
	if err := s.repo.ResetPasswordByEmail(in.GetEmail(), in.GetNewPassword()); err != nil {
		s.logger.Println(err)
		return nil, err
	}

	return &protos.AuthGet{Email: in.GetEmail()}, nil
}

func isPasswordInBlacklist(password string) bool {

	blacklistData, err := ioutil.ReadFile("/root/password-blacklist.txt")
	if err != nil {
		log.Println("Error reading blacklist file:", err)
		return true
	}

	blacklistLines := strings.Split(string(blacklistData), "\n")

	for _, line := range blacklistLines {
		if strings.TrimSpace(line) == password {
			return true
		}
	}

	return false
}
