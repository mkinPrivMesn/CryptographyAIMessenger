package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	port := os.Getenv("PORT")

	r := gin.Default()

	r.POST("/register", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "register works"})
	})

	r.Run(":" + port)
}
