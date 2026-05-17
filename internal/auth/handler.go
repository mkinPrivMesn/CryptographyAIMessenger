package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

//		########################################
//		#####         Registration         #####
//		########################################

func (h *Handler) Register(c *gin.Context) {

	// вот эта переменная создается для занесения сюда данных из JSON'a
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, "error of ShouldBind")
		return
	}

	// вот тут проверка на занятость ника
	nickExists, err := h.service.FindTheNameInDataBase(req.Username)
	if err != nil {
		log.Println("Error:", err)
		c.JSON(500, gin.H{"error": "error finding username in database"})
		return
	}

	if nickExists {
		c.JSON(409, gin.H{"error": "username already taken"})
		return
	}

	// далее передаю данные пользователя из переменной на регистрацию
	accessToken, reefreshToken, err2 := h.service.Register(req)

	if err2 != nil {
		c.JSON(500, gin.H{"error": err2})
		return
	}

	c.SetCookie(
		"refresh_token",
		reefreshToken,
		60*60*24*30, // 30 дней в секундах
		"/",
		"",
		true, // Secure
		true, // HttpOnly
	)

	c.JSON(200, gin.H{
		"access_token": accessToken,
	})
}

//		########################################
//		#####     First stage of login     #####
//		########################################

func (h *Handler) LoginSalt(c *gin.Context) {
	// вот эта переменная создается для занесения сюда данных из JSON'a
	var req LoginSaltRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, "error of ShouldBind")
		return
	}

	// username exists or no?
	nickNameExists, err := h.service.FindTheNameInDataBase(req.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": "error on findingNickName stage in DB"})
		return
	}

	// return response to  clietn
	if nickNameExists {
		// get Salt #2 from database
		salt2, err := h.service.LoginSalt(req.Username)
		if err != nil {
			c.JSON(500, gin.H{"error": "cant get salt #2 from database"})
			return
		}
		c.JSON(200, gin.H{"salt2": salt2})
	} else {
		// generate fake salt by SERVER_SECRET, username and HMAC-SHA256
		// return it to client
		serverSecretBin := os.Getenv("SERVER_SECRET")
		serverSecret, err := hex.DecodeString(serverSecretBin)
		if err != nil {
			log.Println("Error:", err)
			c.JSON(500, gin.H{"error": "cant get decode .env value to hex"})
			return
		}

		fakeHash := hmac.New(sha256.New, []byte(serverSecret))
		fakeHash.Write([]byte(req.Username + "auth_hash"))
		salt2 := hex.EncodeToString(fakeHash.Sum(nil))

		c.JSON(200, gin.H{"salt2": salt2})
	}

}

//		########################################
//		#####    Second stage of login     #####
//		########################################

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	// username exists or no?
	nickNameExists, err := h.service.FindTheNameInDataBase(req.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": "error finding username in DB"})
		return
	}

	// return response to client
	if nickNameExists {
		// comparing authHash from req and authHash from database, using timeSafeEqual
		// if okay, returns to client blob, salt #1, acces token and refresh token (funcs from jwt.go)
		// if not okay, returns to client "wrong username or password"
	} else {
		// this part of code works when client is scammer and cheks usernames for existing
		// so if nickname does not exists
		// creating fake authHash and comparing it with authHash from req, using timeSafeEequal
		// returns to client "wrong username of password PART TWO" (for tests, it will be reemoved it the future)
	}
}
