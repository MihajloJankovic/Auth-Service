package controller

import (
	"log"
	"net/http"

	"github.com/MihajloJankovic/Auth-Service/controller/json"
	"github.com/MihajloJankovic/Auth-Service/model"
	"github.com/MihajloJankovic/Auth-Service/service"
	"github.com/gorilla/mux"
)

type AuthController struct {
	authService *service.AuthService
}

func NewAuthController(authService *service.AuthService) *AuthController {
	return &AuthController{
		authService,
	}
}

func (c *AuthController) RegisterUser(w http.ResponseWriter, req *http.Request) {
	pr, err := json.DecodeJson[model.RegisterUser](req.Body)
	log.Println("Registracija " + pr.Username)
	if err != nil {
		return
	}

	err = c.authService.RegisterUser(&pr)
	if err != nil {
		return
	}
}

func (c *AuthController) LoginUser(w http.ResponseWriter, req *http.Request) {
	l, err := json.DecodeJson[model.Login](req.Body)

	if err != nil {
		log.Println("Login 1 ")
		return
	}

	token, err := c.authService.LoginUser(&l)
	if err != nil {
		log.Println("Login 2 ")
		return
	}

	w.Write([]byte(token))
}

func (c *AuthController) VerifyRegistration(w http.ResponseWriter, req *http.Request) {
	verificationId := mux.Vars(req)["verificationId"]

	err := c.authService.VerifyRegistration(verificationId)
	if err != nil {
		return
	}
}
