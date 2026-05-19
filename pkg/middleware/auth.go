package middleware

import (
	"os"
	"strings"

	"github.com/MkinPrivMesn/CryptographyAIMessenger/internal/auth"
	"github.com/MkinPrivMesn/CryptographyAIMessenger/pkg/crypto"
	"github.com/gin-gonic/gin"
)

// this func checks acces token
func AuthRequired(repo *auth.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authoration")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(401, gin.H{"error": "missing or invalid auth header"})
			c.Abort()
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		jwtSecret := os.Getenv("JWT_SECRET")

		claims, err := crypto.ValidateAccessToken(tokenStr, jwtSecret)
		if err != nil {
			c.JSON(401, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		// ...
		tokenVersionInDB, err := repo.GetTokenVersionInDB(claims.UserID)
		if err != nil {
			c.JSON(500, gin.H{"error": "unexpected error"})
			c.Abort()
			return
		}

		if tokenVersionInDB != claims.TokenVersion {
			c.JSON(401, gin.H{"error": "invalid acces token (invalid token version)"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("token_version", claims.TokenVersion)
		c.Next()
	}
}
