package handlers

import (
	"context"
	"errors"
	"fmt"
	protos "github.com/MihajloJankovic/Auth-Service/protos/main"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"log"
	"math/rand"
	"os"
	"time"
	// NoSQL: module containing Mongo api client

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

type AuthRepo struct {
	cli    *mongo.Client
	logger *log.Logger
}

func New(ctx context.Context, logger *log.Logger) (*AuthRepo, error) {
	dburi := os.Getenv("MONGO_DB_URI")

	client, err := mongo.NewClient(options.Client().ApplyURI(dburi))
	if err != nil {
		return nil, err
	}

	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return &AuthRepo{
		cli:    client,
		logger: logger,
	}, nil
}

// Disconnect from database
func (pr *AuthRepo) Disconnect(ctx context.Context) error {
	err := pr.cli.Disconnect(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (pr *AuthRepo) Ping() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check connection -> if no error, connection is established
	err := pr.cli.Ping(ctx, readpref.Primary())
	if err != nil {
		pr.logger.Println(err)
	}

	// Print available databases
	databases, err := pr.cli.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		pr.logger.Println(err)
	}
	fmt.Println(databases)
}
func (pr *AuthRepo) GetAll() (*[]protos.AuthResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authCollection := pr.getCollection()
	var authsSlice []protos.AuthResponse

	authCursor, err := authCollection.Find(ctx, bson.M{})
	if err != nil {
		pr.logger.Println(err)
		return nil, err
	}
	if err = authCursor.All(ctx, &authsSlice); err != nil {
		pr.logger.Println(err)
		return nil, err
	}
	return &authsSlice, nil
}
func (pr *AuthRepo) GetById(emaila string) (*protos.AuthResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authCollection := pr.getCollection()
	var auth protos.AuthResponse

	err := authCollection.FindOne(ctx, bson.M{"email": emaila}).Decode(&auth)
	if err != nil {
		pr.logger.Println(err)
		return nil, err
	}

	return &auth, nil
}

func (pr *AuthRepo) Create(auth *protos.AuthResponse) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authCollection := pr.getCollection()
	bytes, err := bcrypt.GenerateFromPassword([]byte(auth.GetPassword()), 14)
	if err != nil {
		pr.logger.Println(err)
		return err
	}
	auth.Password = string(bytes)
	result, err := authCollection.InsertOne(ctx, &auth)
	if err != nil {
		pr.logger.Println(err)
		return err
	}
	pr.logger.Printf("Documents ID: %v\n", result.InsertedID)
	return nil
}

func (pr *AuthRepo) Update(auth *protos.AuthResponse) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authCollection := pr.getCollection()

	filter := bson.M{"email": auth.GetEmail()}
	update := bson.M{"$set": bson.M{
		"email":     auth.GetEmail(),
		"password":  auth.GetPassword(),
		"ticket":    auth.GetTicket(),
		"activated": auth.GetActivated(),
	}}
	result, err := authCollection.UpdateOne(ctx, filter, update)
	pr.logger.Printf("Documents matched: %v\n", result.MatchedCount)
	pr.logger.Printf("Documents updated: %v\n", result.ModifiedCount)

	if err != nil {
		pr.logger.Println(err)
		return err
	}
	return nil
}

func (pr *AuthRepo) getCollection() *mongo.Collection {
	authDatabase := pr.cli.Database("mongoAuth")
	authCollection := authDatabase.Collection("auths")
	return authCollection
}

func (pr *AuthRepo) Login(email, password string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authCollection := pr.getCollection()

	var auth protos.AuthResponse

	err := authCollection.FindOne(ctx, bson.M{"email": email}).Decode(&auth)
	if err != nil {
		pr.logger.Println(err)
		return false, "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(auth.GetPassword()), []byte(password))
	if err != nil {
		pr.logger.Println(err)
		return false, "", err
	}
	if auth.Email == "" || !auth.Activated {
		return false, "", nil
	}

	return true, auth.Email, nil
}
func (pr *AuthRepo) GetTicketByEmail(email string) (*protos.AuthResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authCollection := pr.getCollection()

	var auth protos.AuthResponse

	err := authCollection.FindOne(ctx, bson.M{"email": email}).Decode(&auth)
	if err != nil {
		pr.logger.Println(err)
		return nil, err
	}

	return &auth, nil
}
func (pr *AuthRepo) Activate(email, ticket string) (*protos.AuthResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authCollection := pr.getCollection()

	filter := bson.M{"email": email, "ticket": ticket}
	update := bson.M{"$set": bson.M{"activated": true}}

	result, err := authCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		pr.logger.Println(err)
		return nil, err
	}

	if result.ModifiedCount == 0 {
		return nil, errors.New("activation failed")
	}

	activatedAuth, err := pr.GetById(email)
	if err != nil {
		pr.logger.Println(err)
		return nil, err
	}

	return activatedAuth, nil
}
func sendActivationEmail(email, activationLink string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "goprojekat@gmail.com")
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Account Activation")
	m.SetBody("text/html", fmt.Sprintf("Click the following link to activate your account: <a href=\"%s\">Activate Account</a>", activationLink))

	// Set up the SMTP dialer
	d := gomail.NewDialer("smtp.gmail.com", 587, "stefan.milosavljevic01@gmail.com", "hzsm gmhy tqyp cikp")

	// Send the email
	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}
func RandomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
