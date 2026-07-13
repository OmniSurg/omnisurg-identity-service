package handler

import (
	"errors"
	"net/http"

	apperr "github.com/OmniSurg/omnisurg-go-common/errors"
	"github.com/OmniSurg/omnisurg-go-common/logger"
	"github.com/gin-gonic/gin"
)

func respondSuccess(c *gin.Context, status int, data any) {
	c.JSON(status, gin.H{"success": true, "data": data})
}

func respondError(c *gin.Context, err error) {
	var ae *apperr.AppError
	if errors.As(err, &ae) {
		body := gin.H{"code": ae.Code, "message": ae.Message}
		if ae.Details != nil {
			body["details"] = ae.Details
		}
		c.JSON(ae.HTTPStatus, gin.H{"success": false, "error": body})
		return
	}
	log := logger.FromContext(c.Request.Context())
	log.Error().Err(err).Msg("unhandled error")
	c.JSON(http.StatusInternalServerError, gin.H{
		"success": false,
		"error":   gin.H{"code": "INTERNAL_ERROR", "message": "an unexpected error occurred"},
	})
}
