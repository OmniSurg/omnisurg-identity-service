package model_test

import (
	"net/http"
	"testing"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestErrorSentinelsCarryStatusAndCode(t *testing.T) {
	assert.Equal(t, "AUTH_BAD_CREDENTIALS", model.ErrBadCredentials.Code)
	assert.Equal(t, http.StatusUnauthorized, model.ErrBadCredentials.HTTPStatus)
	assert.Equal(t, "AUTH_TENANT_MISSING", model.ErrTenantMissing.Code)
	assert.Equal(t, "USER_NOT_FOUND", model.ErrUserNotFound.Code)
	assert.Equal(t, http.StatusNotFound, model.ErrUserNotFound.HTTPStatus)
	assert.Equal(t, "USER_EMAIL_TAKEN", model.ErrEmailTaken.Code)
	assert.Equal(t, http.StatusConflict, model.ErrEmailTaken.HTTPStatus)
	assert.Equal(t, "VALIDATION_FAILED", model.ErrValidation.Code)
	assert.Equal(t, http.StatusUnprocessableEntity, model.ErrValidation.HTTPStatus)
}
