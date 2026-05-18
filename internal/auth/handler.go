package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"time"

	"github.com/MkinPrivMesn/CryptographyAIMessenger/pkg/crypto"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func MakeJsonParseToVar(req any, c *gin.Context) any {
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return ""
	}

	return req
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
	// ##### i should add code for timeSafeEequal for hash generation and getting hash from DB
	if nickNameExists {
		// get Salt #2 from database
		salt2, err := h.service.GetSalt2ByLogin(req.Username)
		if err != nil {
			c.JSON(500, gin.H{"error": "cant get salt #2 from database"})
			return
		}
		c.JSON(200, gin.H{"salt2": salt2})
		return
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

		fakeHash := hmac.New(sha256.New, serverSecret)
		fakeHash.Write([]byte(req.Username + "salt2"))
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

		AuthHashFromDataBase, err := h.service.FindAuthHashInDB(req.Username)
		if err != nil {
			c.JSON(500, gin.H{"error": "unexpected error"})
			return
		}

		if hmac.Equal([]byte(req.AuthHash), []byte(AuthHashFromDataBase)) {
			Blob, Salt1, err := h.service.FindBlobAndSalt1InDB(req.Username)
			if err != nil {
				c.JSON(500, gin.H{"error": "unexpected error"})
				return
			}

			jwtSecret := os.Getenv("JWT_SECRET")
			if err != nil {
				c.JSON(500, gin.H{"error": "unexpected  error"})
				return
			}

			UserID, TokenVersion, err := h.service.GetUserIDAndTokenVersionInDB(req.Username)
			if err != nil {
				c.JSON(500, gin.H{"error": "unexpected  error"})
				return
			}

			accesForLogin, err := crypto.GenerateAccessToken(UserID, TokenVersion, jwtSecret)
			if err != nil {
				c.JSON(500, gin.H{"error": "unexpected  error"})
				return
			}

			refreshForLogin, hashRefreshForLogin, err := crypto.GenerateRefreshToken()
			if err != nil {
				c.JSON(500, gin.H{"error": "unexpected error"})
				return
			}
			expiresAt := time.Now().Add(30 * 24 * time.Hour)
			err2 := h.service.SaveRefreshTokenForLogin(UserID, hashRefreshForLogin, expiresAt)
			if err2 != nil {
				c.JSON(500, gin.H{"error": "unexpected  error"})
				return
			}

			c.SetCookie(
				"refresh_token",
				refreshForLogin,
				60*60*24*30,
				"/",
				"",
				true,
				true,
			)
			c.JSON(200, gin.H{"blob": Blob, "salt1": Salt1, "acces": accesForLogin})
		} else {
			c.JSON(400, gin.H{"error": "wrong username or password"})
			return
		}

	} else {
		serverSecretHex := os.Getenv("SERVER_SECRET")
		serverSecret, err := hex.DecodeString(serverSecretHex)
		if err != nil {
			c.JSON(500, gin.H{"error": "unexpected error"})
			return
		}

		fakeHash := hmac.New(sha256.New, serverSecret)
		fakeHash.Write([]byte(req.Username + "auth_hash"))
		fakeAuthHash := hex.EncodeToString(fakeHash.Sum(nil))

		if hmac.Equal([]byte(req.AuthHash), []byte(fakeAuthHash)) {
			// никогда не будет true — это просто для одинакового времени ответа
		}
		c.JSON(400, gin.H{"error": "wrong username or password"})
	}
}
