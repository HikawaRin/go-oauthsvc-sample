package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v7"
	"github.com/twinj/uuid"
)

var (
	router = gin.Default()

	root = User{
		ID:       1,
		Username: "username",
		Password: "passwd",
	}

	client *redis.Client
)

func main() {
	init_redis()
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
	// token, err := CreateToken(u.ID)
	ts, err := CreateTokenV2(u.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	saveErr := CreateAuth(u.ID, ts)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}
	token := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
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

	os.Setenv("ACCESS_SECRET", "114514")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = uid
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	return token, err
}

func init_redis() {
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr: dsn,
	})
	_, err := client.Ping().Result()
	if err != nil {
		log.Panic(err)
	}
}

type TokenDetail struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

func CreateTokenV2(uid uint64) (*TokenDetail, error) {
	var err error

	td := &TokenDetail{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUuid = uuid.NewV4().String()
	td.AccessToken, err = CreateToken(uid)
	if err != nil {
		return nil, err
	}

	td.RtExpires = time.Now().Add(time.Hour).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	os.Setenv("REFRESH_SECRET", "1919810")
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = uid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func CreateAuth(uid uint64, td *TokenDetail) error {
	at := time.Unix(td.AtExpires, 0)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(td.AccessUuid, strconv.Itoa(int(uid)), at.Sub((now))).Err()
	if errAccess != nil {
		return errAccess
	}

	errRefresh := client.Set(td.RefreshUuid, strconv.Itoa(int(uid)), rt.Sub((now))).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}
