package repository

import "github.com/MihajloJankovic/Auth-Service/model"

type AuthRepository interface {
	UsernameExists(username string) (bool, error)
	GetUser(username string) (*model.User, error)
	SaveUser(u *model.User) error
	SaveVerification(uuid string, username string) error
	GetVerification(uuid string) (string, error)
	DeleteVerification(uuid string) error
}
