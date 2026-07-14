// Command smoke is the identity-service Contract Smoke Test runner. It reads the
// OpenAPI spec, asserts x-fr and x-nfr coverage, then exercises the live local
// service across the declared scenarios. Any failure exits non zero.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"gopkg.in/yaml.v3"
)

type credentials struct {
	BaseURL          string `json:"base_url"`
	IdentityLoginURL string `json:"identity_login_url"`
	TenantID         string `json:"tenant_id"`
	Users            []struct {
		Role     string `json:"role"`
		Email    string `json:"email"`
		Password string `json:"password"`
	} `json:"users"`
	CrossTenantUser struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenant_id"`
	} `json:"cross_tenant_user"`
	ProviderUser struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		ProviderRole string `json:"provider_role"`
		TotpSecret   string `json:"totp_secret"`
	} `json:"provider_user"`
}

// spec is the minimal OpenAPI view the runner needs.
type spec struct {
	Paths map[string]map[string]struct {
		OperationID string         `yaml:"operationId"`
		XFR         []string       `yaml:"x-fr"`
		XNFR        map[string]any `yaml:"x-nfr"`
	} `yaml:"paths"`
}

type runner struct {
	creds   credentials
	client  *http.Client
	tokens  map[string]string // role -> JWT
	crossTk string
	fails   int
	total   int
}

func main() {
	credPath := flag.String("credentials", "credentials.json", "path to credentials json")
	specPath := flag.String("spec", "../docs/api-contract/openapi.yaml", "path to openapi yaml")
	flag.Parse()

	r := &runner{client: &http.Client{Timeout: 10 * time.Second}, tokens: map[string]string{}}
	if err := r.loadCreds(*credPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := r.checkSpecCoverage(*specPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := r.login(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	r.testHealth()
	r.testLogin()
	r.testActivateNegatives()
	r.testProviderLogin()
	r.testProviderTotp()
	r.testMe()
	createdID := r.testCreateUser()
	r.testListUsers(createdID)
	r.testGetUser(createdID)
	r.testUpdateUser(createdID)
	r.testDeleteUser()
	r.testTenantIsolation(createdID)
	r.testIdempotency()
	r.testLatency()

	fmt.Printf("\nSummary: %d of %d scenarios passed. ", r.total-r.fails, r.total)
	if r.fails > 0 {
		fmt.Printf("CST FAIL.\n")
		os.Exit(1)
	}
	fmt.Printf("CST PASS.\n")
}

func (r *runner) loadCreds(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read credentials: %w", err)
	}
	if err := json.Unmarshal(b, &r.creds); err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}
	return nil
}

// checkSpecCoverage asserts every operation declares x-fr and x-nfr.
func (r *runner) checkSpecCoverage(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}
	var s spec
	if err := yaml.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("parse spec: %w", err)
	}
	requiredNFR := []string{"latency_ms_p99", "rate_limit", "auth_required", "tenant_scoped"}
	var missing []string
	for p, methods := range s.Paths {
		for m, op := range methods {
			if len(op.XFR) == 0 || len(op.XNFR) == 0 {
				missing = append(missing, fmt.Sprintf("%s %s (%s): missing x-fr or x-nfr", m, p, op.OperationID))
				continue
			}
			for _, k := range requiredNFR {
				if _, ok := op.XNFR[k]; !ok {
					missing = append(missing, fmt.Sprintf("%s %s (%s): x-nfr missing key %s", m, p, op.OperationID, k))
				}
			}
		}
	}
	sort.Strings(missing)
	for _, mm := range missing {
		r.record("spec-coverage", false, "missing x-fr or x-nfr: "+mm)
	}
	if len(missing) > 0 {
		return fmt.Errorf("spec coverage gate failed for %d operations", len(missing))
	}
	r.record("spec-coverage", true, "every operation declares x-fr and x-nfr")
	return nil
}

func (r *runner) login() error {
	for _, u := range r.creds.Users {
		tok, err := r.doLogin(u.Email, u.Password, r.creds.TenantID)
		if err != nil {
			return fmt.Errorf("login %s: %w", u.Role, err)
		}
		r.tokens[u.Role] = tok
	}
	tok, err := r.doLogin(r.creds.CrossTenantUser.Email, r.creds.CrossTenantUser.Password, r.creds.CrossTenantUser.TenantID)
	if err != nil {
		return fmt.Errorf("login cross tenant: %w", err)
	}
	r.crossTk = tok
	return nil
}

func (r *runner) doLogin(email, password, tenantID string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, _ := http.NewRequest(http.MethodPost, r.creds.IdentityLoginURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var parsed struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if parsed.Data.Token == "" {
		return "", fmt.Errorf("empty token")
	}
	return parsed.Data.Token, nil
}

// request is the generic call helper. role "" means no Authorization header.
// It returns the response status code (0 on transport error) and the fully read
// body. The response body is read and closed inside the helper so callers never
// hold an open connection.
func (r *runner) request(method, path, role string, headers map[string]string, body any) (int, []byte) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, r.creds.BaseURL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if role != "" {
		req.Header.Set("Authorization", "Bearer "+r.tokenFor(role))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (r *runner) tokenFor(role string) string {
	if role == "cross_tenant" {
		return r.crossTk
	}
	return r.tokens[role]
}

func (r *runner) record(name string, pass bool, detail string) {
	r.total++
	status := "PASS"
	if !pass {
		status = "FAIL"
		r.fails++
	}
	fmt.Printf("[%s] %s :: %s\n", status, name, detail)
}

func bodyHas(b []byte, substr string) bool { return bytes.Contains(b, []byte(substr)) }

// ---- scenario batteries ----

func (r *runner) testHealth() {
	code, b := r.request(http.MethodGet, "/health", "", nil, nil)
	r.record("GET /health x-fr happy", code == 200 && bodyHas(b, "\"status\":\"ok\""), statusStr(code))
}

func (r *runner) testLogin() {
	// happy
	tok, err := r.doLogin(r.creds.Users[0].Email, r.creds.Users[0].Password, r.creds.TenantID)
	r.record("POST /login x-fr happy", err == nil && tok != "", "issued token")
	// missing tenant
	body, _ := json.Marshal(map[string]string{"email": r.creds.Users[0].Email, "password": r.creds.Users[0].Password})
	req, _ := http.NewRequest(http.MethodPost, r.creds.IdentityLoginURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := r.client.Do(req)
	var mb []byte
	code := 0
	if resp != nil {
		mb, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		code = resp.StatusCode
	}
	r.record("POST /login x-fr missing tenant -> 401 AUTH_TENANT_MISSING", code == 401 && bodyHas(mb, "AUTH_TENANT_MISSING"), fmt.Sprintf("status=%d", code))
	// bad credentials
	code2, b2 := r.request(http.MethodPost, "/login", "", map[string]string{"X-Tenant-ID": r.creds.TenantID},
		map[string]string{"email": r.creds.Users[0].Email, "password": "wrong-password"})
	r.record("POST /login x-fr bad creds -> 401 AUTH_BAD_CREDENTIALS", code2 == 401 && bodyHas(b2, "AUTH_BAD_CREDENTIALS"), statusStr(code2))
	// validation
	code3, b3 := r.request(http.MethodPost, "/login", "", map[string]string{"X-Tenant-ID": r.creds.TenantID},
		map[string]string{"email": "x@acme.test"})
	r.record("POST /login x-fr validation -> 422", code3 == 422 && bodyHas(b3, "VALIDATION_FAILED"), statusStr(code3))
	// audit emission
	r.record("POST /login x-nfr audit identity.login", r.auditCount("identity.login") >= 1, "audit row present")
}

// testActivateNegatives exercises the public account activation endpoint's
// NEGATIVE cases only. Provisioning a real pending user and its activation
// token is a gRPC-only operation (there is no REST surface for it), so this
// standalone curl-only runner cannot mint a valid token; the activate HAPPY
// path is proven end to end in the admin-bff cross-service smoke, which CAN
// provision via gRPC. Both negatives below are checked BEFORE any token
// lookup (the password shape is validated first), so a garbage token string
// exercises them deterministically.
func (r *runner) testActivateNegatives() {
	code, b := r.postNoTenant("/activate", []byte(`{"token":"totally-unknown-token-value","new_password":"GoodPassword1!"}`))
	r.record("POST /activate x-fr unknown token -> 401 AUTH_ACTIVATION_INVALID", code == 401 && bodyHas(b, "AUTH_ACTIVATION_INVALID"), statusStr(code))

	code2, b2 := r.postNoTenant("/activate", []byte(`{"token":"totally-unknown-token-value","new_password":"short"}`))
	r.record("POST /activate x-fr short password -> 422 VALIDATION_FAILED", code2 == 422 && bodyHas(b2, "VALIDATION_FAILED"), statusStr(code2))

	code3, b3 := r.postNoTenant("/activate", []byte(`{"token":"totally-unknown-token-value"}`))
	r.record("POST /activate x-fr missing new_password -> 422 VALIDATION_FAILED", code3 == 422 && bodyHas(b3, "VALIDATION_FAILED"), statusStr(code3))
}

// testProviderLogin exercises the public provider (platform) login. It takes no
// tenant header and the issued token must decode to a provider role with an
// empty tenant scope.
func (r *runner) testProviderLogin() {
	// happy path: 200 with a token, sent with NO X-Tenant-ID header.
	body, _ := json.Marshal(map[string]string{"email": r.creds.ProviderUser.Email, "password": r.creds.ProviderUser.Password})
	code, b := r.postNoTenant("/provider/login", body)
	var parsed struct {
		Data struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expires_at"`
			MfaStatus string `json:"mfa_status"`
		} `json:"data"`
	}
	_ = json.Unmarshal(b, &parsed)
	r.record("POST /provider/login x-fr happy (no tenant header) -> 200", code == 200 && parsed.Data.Token != "", statusStr(code))

	// the token decodes to a provider role claim, an empty tenant, and is partial
	// (mfa_verified false): the second factor is not yet satisfied at login.
	claims := decodeJWTClaims(parsed.Data.Token)
	providerRole, _ := claims["provider_role"].(string)
	tenantID, _ := claims["tenant_id"].(string)
	mfaVerified, _ := claims["mfa_verified"].(bool)
	r.record("POST /provider/login x-fr token carries provider_role, empty tenant, partial",
		providerRole == r.creds.ProviderUser.ProviderRole && tenantID == "" && !mfaVerified,
		fmt.Sprintf("provider_role=%q tenant_id=%q mfa_verified=%v", providerRole, tenantID, mfaVerified))

	// the seeded provider is pre-enrolled, so login reports TOTP_REQUIRED.
	r.record("POST /provider/login x-fr mfa_status TOTP_REQUIRED for an enrolled provider",
		parsed.Data.MfaStatus == "TOTP_REQUIRED", fmt.Sprintf("mfa_status=%q", parsed.Data.MfaStatus))

	// the reported expires_at matches the token's real exp (computed once at
	// signing time), so it does not drift from the JWT the client holds.
	exp, _ := claims["exp"].(float64)
	expReported, _ := time.Parse(time.RFC3339, parsed.Data.ExpiresAt)
	r.record("POST /provider/login x-fr expires_at matches token exp",
		exp > 0 && !expReported.IsZero() && math.Abs(exp-float64(expReported.Unix())) <= 1,
		fmt.Sprintf("exp=%d reported=%s", int64(exp), parsed.Data.ExpiresAt))

	// bad password -> 401 AUTH_BAD_CREDENTIALS (no enumeration).
	badBody, _ := json.Marshal(map[string]string{"email": r.creds.ProviderUser.Email, "password": "wrong-password"})
	code2, b2 := r.postNoTenant("/provider/login", badBody)
	r.record("POST /provider/login x-fr bad password -> 401 AUTH_BAD_CREDENTIALS", code2 == 401 && bodyHas(b2, "AUTH_BAD_CREDENTIALS"), statusStr(code2))

	// missing body fields -> 422.
	code3, b3 := r.postNoTenant("/provider/login", []byte(`{"email":"provider.admin@omnisurg.test"}`))
	r.record("POST /provider/login x-fr validation -> 422", code3 == 422 && bodyHas(b3, "VALIDATION_FAILED"), statusStr(code3))
}

// providerLoginToken signs in the seeded provider and returns its partial token
// plus the reported mfa_status, with no X-Tenant-ID header.
func (r *runner) providerLoginToken() (token, mfaStatus string) {
	body, _ := json.Marshal(map[string]string{"email": r.creds.ProviderUser.Email, "password": r.creds.ProviderUser.Password})
	_, b := r.postNoTenant("/provider/login", body)
	var parsed struct {
		Data struct {
			Token     string `json:"token"`
			MfaStatus string `json:"mfa_status"`
		} `json:"data"`
	}
	_ = json.Unmarshal(b, &parsed)
	return parsed.Data.Token, parsed.Data.MfaStatus
}

// postProvider posts a json body with a provider Bearer token and no
// X-Tenant-ID header; provider routes carry no tenant scope.
func (r *runner) postProvider(path, token string, body []byte) (int, []byte) {
	req, _ := http.NewRequest(http.MethodPost, r.creds.BaseURL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// testProviderTotp exercises the two factor loop end to end: the pre-enrolled
// provider signs in (TOTP_REQUIRED), supplies a code from the fixed test secret
// to verify into a full session, a wrong code is rejected, the super admin
// resets itself back to enrol-required, then enrols and confirms a fresh secret.
// The next make seed restores the fixed test secret idempotently.
func (r *runner) testProviderTotp() {
	partial, status := r.providerLoginToken()
	r.record("provider totp: login returns a partial token and TOTP_REQUIRED",
		partial != "" && status == "TOTP_REQUIRED", fmt.Sprintf("status=%q", status))

	// A wrong code on verify is rejected.
	badCode, _ := json.Marshal(map[string]string{"code": "000000"})
	code, b := r.postProvider("/provider/totp/verify", partial, badCode)
	r.record("provider totp: verify with a wrong code -> 401 MFA_INVALID_CODE",
		code == 401 && bodyHas(b, "MFA_INVALID_CODE"), statusStr(code))

	// A code from the fixed test secret verifies into a full session token.
	validCode, gerr := totp.GenerateCode(r.creds.ProviderUser.TotpSecret, time.Now())
	if gerr != nil {
		r.record("provider totp: compute a code from the test secret", false, gerr.Error())
		return
	}
	codeBody, _ := json.Marshal(map[string]string{"code": validCode})
	vcode, vb := r.postProvider("/provider/totp/verify", partial, codeBody)
	var verifyResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	_ = json.Unmarshal(vb, &verifyResp)
	fullClaims := decodeJWTClaims(verifyResp.Data.Token)
	fullVerified, _ := fullClaims["mfa_verified"].(bool)
	r.record("provider totp: verify with a valid code -> 200 full token (mfa_verified)",
		vcode == 200 && fullVerified, fmt.Sprintf("%s mfa_verified=%v", statusStr(vcode), fullVerified))

	// The full token can reset the provider's own second factor (super admin).
	sub, _ := fullClaims["sub"].(string)
	rcode, _ := r.postProvider("/provider/users/"+sub+"/totp/reset", verifyResp.Data.Token, nil)
	r.record("provider totp: super admin reset -> 200", rcode == 200, statusStr(rcode))

	// After a reset the next login is ENROLL_REQUIRED.
	enrolPartial, enrolStatus := r.providerLoginToken()
	r.record("provider totp: after reset login -> ENROLL_REQUIRED",
		enrolStatus == "ENROLL_REQUIRED", fmt.Sprintf("status=%q", enrolStatus))

	// Enrol a fresh secret then confirm a code computed from it -> full token.
	ecode, eb := r.postProvider("/provider/totp/enroll", enrolPartial, nil)
	var enrollResp struct {
		Data struct {
			Secret     string `json:"secret"`
			OtpauthURI string `json:"otpauth_uri"`
		} `json:"data"`
	}
	_ = json.Unmarshal(eb, &enrollResp)
	r.record("provider totp: enrol returns a secret and otpauth uri",
		ecode == 200 && enrollResp.Data.Secret != "" && strings.HasPrefix(enrollResp.Data.OtpauthURI, "otpauth://totp/"), statusStr(ecode))

	confirmCode, cerr := totp.GenerateCode(enrollResp.Data.Secret, time.Now())
	if cerr != nil {
		r.record("provider totp: compute a code from the enrolled secret", false, cerr.Error())
		return
	}
	confirmBody, _ := json.Marshal(map[string]string{"code": confirmCode})
	ccode, cb := r.postProvider("/provider/totp/confirm", enrolPartial, confirmBody)
	confirmClaims := decodeJWTClaims(gjson(cb))
	confirmVerified, _ := confirmClaims["mfa_verified"].(bool)
	r.record("provider totp: confirm with a valid code -> 200 full token (mfa_verified)",
		ccode == 200 && confirmVerified, fmt.Sprintf("%s mfa_verified=%v", statusStr(ccode), confirmVerified))
}

// gjson pulls the data.token field out of a success envelope body.
func gjson(b []byte) string {
	var parsed struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	_ = json.Unmarshal(b, &parsed)
	return parsed.Data.Token
}

// postNoTenant posts a raw json body with no Authorization and no X-Tenant-ID
// header; the response is read and the connection closed inside the helper.
func (r *runner) postNoTenant(path string, body []byte) (int, []byte) {
	req, _ := http.NewRequest(http.MethodPost, r.creds.BaseURL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// decodeJWTClaims base64url decodes the JWT payload segment into a claims map.
// It is a read only decode for assertion; it does not verify the signature
// (the service already signs and the unit tests verify the signature path).
func decodeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return map[string]any{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return map[string]any{}
	}
	return claims
}

func (r *runner) testMe() {
	code, b := r.request(http.MethodGet, "/me", "practice_admin", nil, nil)
	r.record("GET /me x-fr happy", code == 200 && bodyHas(b, "@acme.test"), statusStr(code))
	code2, b2 := r.request(http.MethodGet, "/me", "", nil, nil)
	r.record("GET /me x-fr no auth -> 401", code2 == 401 && bodyHas(b2, "AUTH_UNAUTHORIZED"), statusStr(code2))
}

func (r *runner) testCreateUser() string {
	email := fmt.Sprintf("smoke+%d@acme.test", time.Now().UnixNano())
	code, b := r.request(http.MethodPost, "/users", "practice_admin", nil,
		map[string]any{"email": email, "password": "password123", "display_name": "Smoke", "role": "reception"})
	created := code == 201 && bodyHas(b, email)
	r.record("POST /users x-fr happy admin -> 201", created, statusStr(code))

	code2, b2 := r.request(http.MethodPost, "/users", "reception", nil,
		map[string]any{"email": "nope@acme.test", "password": "password123", "display_name": "X", "role": "reception"})
	r.record("POST /users x-fr reception forbidden -> 403", code2 == 403 && bodyHas(b2, "AUTH_FORBIDDEN"), statusStr(code2))

	code3, b3 := r.request(http.MethodPost, "/users", "practice_admin", nil,
		map[string]any{"email": "bad", "password": "short", "display_name": "", "role": "nope"})
	r.record("POST /users x-fr validation -> 422", code3 == 422 && bodyHas(b3, "VALIDATION_FAILED"), statusStr(code3))

	r.record("POST /users x-fr no password hash leak", created && !bodyHas(b, "password_hash"), "response omits password hash")
	r.record("POST /users x-nfr audit identity.user.create", r.auditCount("identity.user.create") >= 1, "audit row present")

	// duplicate email -> 409
	dupEmail := fmt.Sprintf("dup+%d@acme.test", time.Now().UnixNano())
	dupBody := map[string]any{"email": dupEmail, "password": "password123", "display_name": "Dup", "role": "reception"}
	_, _ = r.request(http.MethodPost, "/users", "practice_admin", nil, dupBody)
	codeDup, bDup := r.request(http.MethodPost, "/users", "practice_admin", nil, dupBody)
	r.record("POST /users x-fr duplicate email -> 409 USER_EMAIL_TAKEN", codeDup == 409 && bodyHas(bDup, "USER_EMAIL_TAKEN"), statusStr(codeDup))

	return extractID(b)
}

func (r *runner) testListUsers(createdID string) {
	code, b := r.request(http.MethodGet, "/users", "practice_admin", nil, nil)
	r.record("GET /users x-fr happy admin -> 200", code == 200 && bodyHas(b, "users"), statusStr(code))
	code2, _ := r.request(http.MethodGet, "/users", "clinician_ophthalmologist", nil, nil)
	r.record("GET /users x-fr clinician forbidden -> 403", code2 == 403, statusStr(code2))
}

func (r *runner) testGetUser(createdID string) {
	code, _ := r.request(http.MethodGet, "/users/"+createdID, "practice_admin", nil, nil)
	r.record("GET /users/{id} x-fr happy -> 200", code == 200, statusStr(code))
	code2, b2 := r.request(http.MethodGet, "/users/00000000-0000-0000-0000-0000000000ff", "practice_admin", nil, nil)
	r.record("GET /users/{id} x-fr unknown -> 404", code2 == 404 && bodyHas(b2, "USER_NOT_FOUND"), statusStr(code2))
	code3, _ := r.request(http.MethodGet, "/users/"+createdID, "clinician_ophthalmologist", nil, nil)
	r.record("GET /users/{id} x-fr clinician forbidden -> 403", code3 == 403, statusStr(code3))
}

func (r *runner) testUpdateUser(createdID string) {
	code, _ := r.request(http.MethodPatch, "/users/"+createdID, "practice_admin", nil, map[string]any{"display_name": "Renamed"})
	r.record("PATCH /users/{id} x-fr happy -> 200", code == 200, statusStr(code))
	code2, _ := r.request(http.MethodPatch, "/users/"+createdID, "reception", nil, map[string]any{"display_name": "X"})
	r.record("PATCH /users/{id} x-fr reception forbidden -> 403", code2 == 403, statusStr(code2))
	code3, _ := r.request(http.MethodPatch, "/users/00000000-0000-0000-0000-0000000000ff", "practice_admin", nil, map[string]any{"display_name": "X"})
	r.record("PATCH /users/{id} x-fr unknown -> 404", code3 == 404, statusStr(code3))
	r.record("PATCH /users/{id} x-nfr audit identity.user.update", r.auditCount("identity.user.update") >= 1, "audit row present")
}

func (r *runner) testDeleteUser() {
	// create a throwaway user then delete it
	email := fmt.Sprintf("delete+%d@acme.test", time.Now().UnixNano())
	_, cb := r.request(http.MethodPost, "/users", "practice_admin", nil,
		map[string]any{"email": email, "password": "password123", "display_name": "Del", "role": "reception"})
	id := extractID(cb)
	code, b := r.request(http.MethodDelete, "/users/"+id, "practice_admin", nil, nil)
	r.record("DELETE /users/{id} x-fr happy -> 200 deleted", code == 200 && bodyHas(b, "deleted"), statusStr(code))
	code2, _ := r.request(http.MethodDelete, "/users/"+id, "reception", nil, nil)
	r.record("DELETE /users/{id} x-fr reception forbidden -> 403", code2 == 403, statusStr(code2))
	r.record("DELETE /users/{id} x-nfr audit identity.user.delete", r.auditCount("identity.user.delete") >= 1, "audit row present")
}

func (r *runner) testTenantIsolation(acmeUserID string) {
	code, b := r.request(http.MethodGet, "/users/"+acmeUserID, "cross_tenant", nil, nil)
	r.record("GET /users/{id} x-nfr tenant_scoped cross tenant -> 404", code == 404 && bodyHas(b, "USER_NOT_FOUND"), statusStr(code))

	// cross tenant list must not include the Acme user
	code2, b2 := r.request(http.MethodGet, "/users", "cross_tenant", nil, nil)
	r.record("GET /users x-fr cross tenant list excludes other tenant users", code2 == 200 && !bodyHas(b2, acmeUserID), "acme user id absent from cross tenant list")
}

func (r *runner) testIdempotency() {
	email := fmt.Sprintf("idem+%d@acme.test", time.Now().UnixNano())
	key := fmt.Sprintf("idem-key-%d", time.Now().UnixNano())
	body := map[string]any{"email": email, "password": "password123", "display_name": "Idem", "role": "reception"}
	code1, b1 := r.request(http.MethodPost, "/users", "practice_admin", map[string]string{"X-Idempotency-Key": key}, body)
	code2, b2 := r.request(http.MethodPost, "/users", "practice_admin", map[string]string{"X-Idempotency-Key": key}, body)
	ok := code1 == 201 && code2 == 201 && bytes.Equal(b1, b2)
	r.record("POST /users x-nfr idempotency replay returns first response", ok, "two calls, identical body")
}

func (r *runner) testLatency() {
	const n = 20
	var samples []time.Duration
	for i := 0; i < n; i++ {
		start := time.Now()
		code, _ := r.request(http.MethodGet, "/me", "practice_admin", nil, nil)
		if code != 200 {
			r.record("GET /me x-nfr latency", false, "call failed")
			return
		}
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	idx := int(math.Ceil(0.99*float64(len(samples)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(samples) {
		idx = len(samples) - 1
	}
	p99 := samples[idx]
	r.record("GET /me x-nfr latency_ms_p99 budget 200ms", p99 <= 200*time.Millisecond, fmt.Sprintf("p99=%dms", p99.Milliseconds()))
}

// auditCount queries the non production debug endpoint for an action count.
func (r *runner) auditCount(action string) int {
	code, b := r.request(http.MethodGet, "/_debug/audit?action="+action, "practice_admin", nil, nil)
	if code != 200 {
		return 0
	}
	var parsed struct {
		Data struct {
			Count int `json:"count"`
		} `json:"data"`
	}
	_ = json.Unmarshal(b, &parsed)
	return parsed.Data.Count
}

func extractID(b []byte) string {
	var parsed struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(b, &parsed)
	return parsed.Data.ID
}

func statusStr(code int) string {
	if code == 0 {
		return "no response"
	}
	return fmt.Sprintf("status=%d", code)
}
