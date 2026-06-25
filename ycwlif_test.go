package ycwlif

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// makeJWT создаёт минимальный JWT с заданным jti для тестов.
// Подпись фиктивная — мы её не верифицируем.
func makeJWT(jti string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]interface{}{
		"jti": jti,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".fakesignature"
}

// writeTokenFile записывает JWT в временный файл и возвращает путь к нему.
func writeTokenFile(t *testing.T, jwt string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "k8s-token-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(jwt); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

// oauthServer запускает тестовый HTTP-сервер, имитирующий OAuth Token Exchange.
func oauthServer(t *testing.T, accessToken string, expiresIn int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oauthResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
		})
	}))
}

func TestNew_MissingServiceAccountID(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error when ServiceAccountID is empty")
	}
}

func TestNew_OK(t *testing.T) {
	_, err := New(Config{ServiceAccountID: "test-sa"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetToken_Success(t *testing.T) {
	const wantToken = "test-iam-token"

	srv := oauthServer(t, wantToken, 43200)
	defer srv.Close()

	tokenFile := writeTokenFile(t, makeJWT("jti-001"))

	mgr, err := New(Config{
		ServiceAccountID: "test-sa",
		TokenFile:        tokenFile,
		OAuthURL:         srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := mgr.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken error: %v", err)
	}
	if tok.AccessToken != wantToken {
		t.Errorf("got token %q, want %q", tok.AccessToken, wantToken)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("got token type %q, want Bearer", tok.TokenType)
	}
	if tok.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
}

func TestIAMToken_ReturnsCachedToken(t *testing.T) {
	const wantToken = "cached-token"

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oauthResponse{
			AccessToken: wantToken,
			TokenType:   "Bearer",
			ExpiresIn:   43200,
		})
	}))
	defer srv.Close()

	tokenFile := writeTokenFile(t, makeJWT("jti-002"))

	mgr, _ := New(Config{
		ServiceAccountID: "test-sa",
		TokenFile:        tokenFile,
		OAuthURL:         srv.URL,
	})

	ctx := context.Background()

	// Первый вызов — идёт в OAuth.
	token1, err := mgr.IAMToken(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Второй вызов — должен вернуть кэш без HTTP-запроса.
	token2, err := mgr.IAMToken(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if token1 != token2 {
		t.Errorf("tokens differ: %q != %q", token1, token2)
	}
	if callCount != 1 {
		t.Errorf("expected 1 OAuth call, got %d", callCount)
	}
}

func TestGetToken_OAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()

	tokenFile := writeTokenFile(t, makeJWT("jti-003"))

	mgr, _ := New(Config{
		ServiceAccountID: "test-sa",
		TokenFile:        tokenFile,
		OAuthURL:         srv.URL,
	})

	_, err := mgr.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error on OAuth 401")
	}
}

func TestGetToken_EmptyTokenFile(t *testing.T) {
	srv := oauthServer(t, "token", 43200)
	defer srv.Close()

	tokenFile := writeTokenFile(t, "   ") // пустой токен

	mgr, _ := New(Config{
		ServiceAccountID: "test-sa",
		TokenFile:        tokenFile,
		OAuthURL:         srv.URL,
	})

	_, err := mgr.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error for empty token file")
	}
}

func TestGetToken_MissingTokenFile(t *testing.T) {
	srv := oauthServer(t, "token", 43200)
	defer srv.Close()

	mgr, _ := New(Config{
		ServiceAccountID: "test-sa",
		TokenFile:        "/nonexistent/path/token",
		OAuthURL:         srv.URL,
	})

	_, err := mgr.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error for missing token file")
	}
}

func TestParseJTI(t *testing.T) {
	const wantJTI = "test-jti-value"

	jwt := makeJWT(wantJTI)
	got, err := parseJTI(jwt)
	if err != nil {
		t.Fatalf("parseJTI error: %v", err)
	}
	if got != wantJTI {
		t.Errorf("got jti %q, want %q", got, wantJTI)
	}
}

func TestParseJTI_InvalidJWT(t *testing.T) {
	_, err := parseJTI("notajwt")
	if err == nil {
		t.Fatal("expected error for invalid JWT")
	}
}

func TestTokenStillFresh(t *testing.T) {
	if tokenStillFresh(nil) {
		t.Error("nil token should not be fresh")
	}

	// Свежий токен.
	fresh := &Token{RefreshedAt: time.Now()}
	if !tokenStillFresh(fresh) {
		t.Error("just-refreshed token should be fresh")
	}

	// Протухший токен.
	stale := &Token{RefreshedAt: time.Now().Add(-(refreshInterval + time.Second))}
	if tokenStillFresh(stale) {
		t.Error("stale token should not be fresh")
	}
}

func TestStart_RefreshesTokenInBackground(t *testing.T) {
	const wantToken = "start-token"

	srv := oauthServer(t, wantToken, 43200)
	defer srv.Close()

	tokenFile := writeTokenFile(t, makeJWT("jti-start"))

	mgr, _ := New(Config{
		ServiceAccountID: "test-sa",
		TokenFile:        tokenFile,
		OAuthURL:         srv.URL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start должен синхронно получить первый токен.
	mgr.Start(ctx)

	mgr.mu.RLock()
	tok := mgr.token
	mgr.mu.RUnlock()

	if tok == nil {
		t.Fatal("token should not be nil after Start")
	}
	if tok.AccessToken != wantToken {
		t.Errorf("got %q, want %q", tok.AccessToken, wantToken)
	}
}
