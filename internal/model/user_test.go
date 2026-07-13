package model_test

import (
	"testing"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
)

func TestPlatformTenantIDIsReserved(t *testing.T) {
	if model.PlatformTenantID.String() != "00000000-0000-0000-0000-0000000000aa" {
		t.Fatalf("PlatformTenantID = %s", model.PlatformTenantID)
	}
}
