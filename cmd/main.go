package main

import (
	"log"
	"os"

	"github.com/MkinPrivMesn/CryptographyAIMessenger/internal/auth"
	"github.com/MkinPrivMesn/CryptographyAIMessenger/pkg/database"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// получение порта из .env
	port := os.Getenv("PORT")

	// создание сервера в переменной r с дефолтными настройками
	r := gin.Default()

	// postgresql
	pool, err := database.NewPool()
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}
	defer pool.Close()

	// заношу сюда хендлер, сервис, репозиторий и модель из пакета auth
	authRepo := auth.NewRepository(pool)
	authService := auth.NewService(authRepo)
	authHandler := auth.NewHandler(authService)

	// вся логика приема и обработки запросов находится тут
	r.POST("/register", authHandler.Register)
	r.POST("/login/salt", authHandler.LoginSalt)
	r.POST("/login", authHandler.Login)

	// запуск сервера на порте из .env
	r.Run(":" + port)
}
