// Package ycwlif реализует обмен Kubernetes ServiceAccount токена
// на Yandex Cloud IAM-токен через OAuth Token Exchange (RFC 8693,
// Workload Identity Federation).
//
// IAM-токен обновляется каждые 6 часов — достаточно, так как его срок
// жизни составляет 12 часов. k8s ServiceAccount токен может ротироваться
// kubelet-ом независимо; при каждом обновлении файл перечитывается заново,
// поэтому всегда используется актуальный токен. В логах фиксируется jti
// k8s токена для отслеживания ротаций.
package ycwlif

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// DefaultTokenFile — стандартный путь к файлу ServiceAccount токена в k8s.
	DefaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// DefaultOAuthURL — эндпоинт OAuth Token Exchange Yandex Cloud.
	DefaultOAuthURL = "https://auth.yandex.cloud/oauth/token"

	// refreshInterval — интервал обновления IAM-токена.
	// IAM-токен живёт 12 часов, обновляем каждые 6 — с двукратным запасом.
	refreshInterval = 6 * time.Hour

	// refreshRetryDelay — задержка перед повторной попыткой при ошибке.
	refreshRetryDelay = 5 * time.Second

	// maxErrBodySize ограничивает размер тела ошибки от OAuth,
	// чтобы предотвратить утечку токена в логи.
	maxErrBodySize = 512
)

// Config содержит параметры для обмена k8s-токена на IAM-токен.
type Config struct {
	// TokenFile — путь к файлу k8s ServiceAccount токена.
	// Если не задан — используется DefaultTokenFile.
	TokenFile string

	// ServiceAccountID — ID сервисного аккаунта Yandex Cloud,
	// от имени которого выдаётся IAM-токен. Обязательный параметр.
	ServiceAccountID string

	// OAuthURL — URL эндпоинта OAuth Token Exchange.
	// Если не задан — используется DefaultOAuthURL.
	OAuthURL string

	// HTTPTimeout — таймаут HTTP-запроса к OAuth-серверу.
	// Если не задан — используется 10 секунд.
	HTTPTimeout time.Duration

	// Logger — slog-логгер. Если не задан — используется slog.Default().
	Logger *slog.Logger
}

func (c *Config) tokenFile() string {
	if c.TokenFile != "" {
		return c.TokenFile
	}
	return DefaultTokenFile
}

func (c *Config) oauthURL() string {
	if c.OAuthURL != "" {
		return c.OAuthURL
	}
	return DefaultOAuthURL
}

func (c *Config) httpTimeout() time.Duration {
	if c.HTTPTimeout > 0 {
		return c.HTTPTimeout
	}
	return 10 * time.Second
}

func (c *Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// Token хранит полученный IAM-токен и метаданные о его жизненном цикле.
type Token struct {
	// AccessToken — IAM-токен для использования в запросах к Yandex Cloud API.
	AccessToken string

	// TokenType — тип токена, обычно "Bearer".
	TokenType string

	// ExpiresAt — время истечения IAM-токена (из ответа OAuth).
	ExpiresAt time.Time

	// RefreshedAt — время последнего успешного обновления.
	RefreshedAt time.Time
}

// Manager управляет жизненным циклом IAM-токена:
// получает его при старте, кэширует и автоматически обновляет каждые 6 часов.
// При каждом обновлении перечитывает файл k8s токена — корректно работает
// с автоматической ротацией, которую выполняет kubelet.
type Manager struct {
	cfg        Config
	httpClient *http.Client
	log        *slog.Logger

	mu    sync.RWMutex
	token *Token

	sf singleflight.Group
}

// New создаёт новый Manager с указанной конфигурацией.
// Возвращает ошибку если ServiceAccountID не задан.
func New(cfg Config) (*Manager, error) {
	if cfg.ServiceAccountID == "" {
		return nil, errors.New("ycwlif: ServiceAccountID is required")
	}
	return &Manager{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.httpTimeout(),
		},
		log: cfg.logger(),
	}, nil
}

// Start запускает фоновую горутину обновления токена.
// Первый токен получается синхронно — Start возвращается только после
// успешного получения или ошибки (ошибка логируется, но не фатальна).
// ctx должен жить всё время работы приложения.
func (m *Manager) Start(ctx context.Context) {
	if _, err := m.refreshToken(ctx); err != nil {
		m.log.Error("ycwlif: initial token fetch failed", "err", err)
	}
	go m.refreshLoop(ctx)
}

func (m *Manager) refreshLoop(ctx context.Context) {
	for {
		// Отдельный ключ singleflight — фоновый refresh не мешает клиентским запросам.
		v, err, _ := m.sf.Do("refresh-loop", func() (interface{}, error) {
			m.mu.RLock()
			tok := m.token
			m.mu.RUnlock()

			if tokenStillFresh(tok) {
				return tok, nil
			}
			return m.refreshToken(ctx)
		})

		if err != nil {
			m.log.Error("ycwlif: background refresh failed", "err", err)
			select {
			case <-time.After(refreshRetryDelay):
				continue
			case <-ctx.Done():
				return
			}
		}

		tok := v.(*Token)
		wait := max(time.Until(tok.RefreshedAt.Add(refreshInterval)), 0)

		m.log.Debug("ycwlif: next IAM token refresh scheduled",
			"in", wait.Round(time.Second),
			"iam_expires_at", tok.ExpiresAt.Format(time.RFC3339),
		)

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
	}
}

// GetToken возвращает актуальный IAM-токен.
// Если токен ещё свежий — возвращается из кэша без сетевых запросов.
// Иначе — выполняется обновление с дедупликацией через singleflight.
func (m *Manager) GetToken(ctx context.Context) (*Token, error) {
	m.mu.RLock()
	tok := m.token
	m.mu.RUnlock()

	if tokenStillFresh(tok) {
		return tok, nil
	}

	// Отдельный ключ от refresh-loop — отмена клиентского контекста
	// не прерывает фоновое обновление.
	v, err, shared := m.sf.Do("get-token", func() (interface{}, error) {
		m.mu.RLock()
		tok := m.token
		m.mu.RUnlock()

		if tokenStillFresh(tok) {
			return tok, nil
		}
		return m.refreshToken(ctx)
	})
	if err != nil {
		return nil, err
	}

	if shared {
		m.log.Debug("ycwlif: token served from singleflight (coalesced request)")
	}
	return v.(*Token), nil
}

// IAMToken возвращает строку IAM-токена для использования в заголовке Authorization
// или напрямую в Yandex Cloud SDK.
func (m *Manager) IAMToken(ctx context.Context) (string, error) {
	tok, err := m.GetToken(ctx)
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// oauthResponse — ответ OAuth Token Exchange endpoint.
type oauthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// jwtClaims содержит поля JWT, используемые только для логирования.
type jwtClaims struct {
	JTI string `json:"jti"`
}

// parseJTI извлекает jti из JWT без верификации подписи.
// Доверяем файлу на диске — он смонтирован kubelet-ом.
func parseJTI(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("ycwlif: invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("ycwlif: decode JWT payload: %w", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("ycwlif: parse JWT claims: %w", err)
	}
	return claims.JTI, nil
}

func (m *Manager) refreshToken(ctx context.Context) (*Token, error) {
	k8sTokenBytes, err := os.ReadFile(m.cfg.tokenFile())
	if err != nil {
		return nil, fmt.Errorf("ycwlif: read token file %q: %w", m.cfg.tokenFile(), err)
	}

	k8sToken := strings.TrimSpace(string(k8sTokenBytes))
	if k8sToken == "" {
		return nil, errors.New("ycwlif: token file is empty")
	}

	// Извлекаем jti для логирования — позволяет отследить ротацию k8s токена.
	jti, err := parseJTI(k8sToken)
	if err != nil {
		m.log.Warn("ycwlif: failed to parse JWT jti", "err", err)
		jti = "<unknown>"
	}

	// Обмениваем k8s токен на IAM через OAuth Token Exchange (RFC 8693).
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", m.cfg.ServiceAccountID)
	form.Set("subject_token", k8sToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		m.cfg.oauthURL(),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("ycwlif: build oauth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ycwlif: oauth request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBodySize*10))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody := body
		if len(errBody) > maxErrBodySize {
			errBody = errBody[:maxErrBodySize]
		}
		return nil, fmt.Errorf("ycwlif: oauth request failed: status=%d body=%q", resp.StatusCode, errBody)
	}

	var parsed oauthResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("ycwlif: parse oauth response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, errors.New("ycwlif: empty access_token in response")
	}
	if parsed.TokenType == "" {
		parsed.TokenType = "Bearer"
	}
	if parsed.ExpiresIn <= 0 {
		return nil, errors.New("ycwlif: invalid expires_in in response")
	}

	now := time.Now()
	tok := &Token{
		AccessToken: parsed.AccessToken,
		TokenType:   parsed.TokenType,
		ExpiresAt:   now.Add(time.Duration(parsed.ExpiresIn) * time.Second),
		RefreshedAt: now,
	}

	m.mu.Lock()
	m.token = tok
	m.mu.Unlock()

	m.log.Info("ycwlif: obtained IAM token",
		"k8s_token_jti", jti,
		"iam_expires_at", tok.ExpiresAt.Format(time.RFC3339),
		"next_refresh_in", refreshInterval,
	)

	return tok, nil
}

// tokenStillFresh возвращает true, если IAM-токен не требует обновления.
func tokenStillFresh(tok *Token) bool {
	if tok == nil {
		return false
	}
	return time.Now().Before(tok.RefreshedAt.Add(refreshInterval))
}