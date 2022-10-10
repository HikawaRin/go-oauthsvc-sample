package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var (
	router = gin.Default()

	root = User{
		ID:       1,
		Username: "username",
		Password: "passwd",
	}
)

func main() {
	router.POST("/login", Login)
	log.Fatal(router.Run(":8080"))
}

type User struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}
	if !isUser(&u) {
		c.JSON(http.StatusUnauthorized, "Unkown User")
		return
	}
	token, err := CreateToken(u.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	c.JSON(http.StatusOK, token)
}

func isUser(u *User) bool {
	if u.Username != root.Username || u.Password != root.Password {
		return false
	}
	return true
}

func CreateToken(uid uint64) (string, error) {
	var err error

	os.Setenv("ACCESS_SECRET", "1145141919810")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = uid
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodES256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	return token, err
}
