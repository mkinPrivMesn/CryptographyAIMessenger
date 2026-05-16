package auth

import (
	"log"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Register(c *gin.Context) {

	// вот эта переменная создается для занесения сюда данных из JSON'a
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, "error of ShouldBind")
		return
	}

	// вот тут проверка на занятость ника
	nickExists, err := h.service.FindTheNameInDataBase(req)
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
