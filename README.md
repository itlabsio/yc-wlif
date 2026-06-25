# yc-wlif

Go-библиотека для обмена Kubernetes ServiceAccount токена на Yandex Cloud IAM-токен через [OAuth Token Exchange (RFC 8693)](https://datatracker.ietf.org/doc/html/rfc8693) — Workload Identity Federation.

## Установка

```bash
go get github.com/itlabsio/yc-wlif
```

## Быстрый старт

```go
import "github.com/itlabsio/yc-wlif"

mgr, err := ycwlif.New(ycwlif.Config{
    ServiceAccountID: "aje1234567890abcdef",
})
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()
mgr.Start(ctx) // получает первый токен синхронно, затем обновляет каждые 6 часов

token, err := mgr.IAMToken(ctx)
if err != nil {
    log.Fatal(err)
}
// token — строка IAM-токена, готовая к использованию в Yandex Cloud API
```

## Конфигурация

```go
cfg := ycwlif.Config{
    // Обязательный. ID сервисного аккаунта Yandex Cloud.
    ServiceAccountID: "aje1234567890abcdef",

    // Путь к файлу k8s ServiceAccount токена.
    // По умолчанию: /var/run/secrets/kubernetes.io/serviceaccount/token
    TokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",

    // URL OAuth Token Exchange endpoint.
    // По умолчанию: https://auth.yandex.cloud/oauth/token
    OAuthURL: "https://auth.yandex.cloud/oauth/token",

    // Таймаут HTTP-запроса к OAuth-серверу.
    // По умолчанию: 10 секунд.
    HTTPTimeout: 10 * time.Second,

    // slog-логгер. По умолчанию: slog.Default().
    Logger: slog.Default(),
}
```

## API

### `New(cfg Config) (*Manager, error)`
Создаёт Manager. Возвращает ошибку если `ServiceAccountID` не задан.

### `(*Manager) Start(ctx context.Context)`
Получает первый IAM-токен синхронно, затем запускает фоновое обновление каждые 6 часов. `ctx` должен жить всё время работы приложения.

### `(*Manager) IAMToken(ctx context.Context) (string, error)`
Возвращает актуальный IAM-токен. Если токен свежий — отдаёт из кэша без сетевых запросов.

### `(*Manager) GetToken(ctx context.Context) (*Token, error)`
Возвращает `*Token` с полными метаданными: `AccessToken`, `TokenType`, `ExpiresAt`, `RefreshedAt`.

## Как это работает

```
kubelet
  │  монтирует JWT в файл, автоматически ротирует до истечения
  ▼
/var/run/secrets/kubernetes.io/serviceaccount/token
  │
  │  Manager читает файл при каждом обновлении IAM-токена
  ▼
https://auth.yandex.cloud/oauth/token
  │  OAuth Token Exchange (RFC 8693)
  │  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  ▼
IAM-токен Yandex Cloud (TTL 12 часов)
  │
  │  Manager кэширует, обновляет каждые 6 часов
  ▼
Yandex Cloud API
```

Yandex Cloud верифицирует подпись JWT через OIDC Discovery endpoint кластера (`/.well-known/openid-configuration`).

## Требования к кластеру

1. Кластер опубликовал OIDC Discovery endpoint, доступный из интернета (или для Yandex Cloud)
2. В Yandex Cloud создан федеративный сервисный аккаунт, привязанный к k8s ServiceAccount
3. Сервисному аккаунту выданы необходимые роли

## Монтирование токена в Pod

### Вариант 1 — автоматическое монтирование (проще)

Kubernetes монтирует токен автоматически при `automountServiceAccountToken: true` (значение по умолчанию). Никакой дополнительной конфигурации не требуется — библиотека читает токен из стандартного пути.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: default
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      serviceAccountName: my-app
      # automountServiceAccountToken: true  # по умолчанию, можно не указывать
      containers:
        - name: app
          # TokenFile не нужен — используется путь по умолчанию
```

> **Важно:** audience стандартного токена определяется настройками кластера (обычно `https://kubernetes.default.svc`). При настройке федерации сервисных аккаунтов в Yandex Cloud необходимо указать именно тот audience, который выдаёт ваш кластер.

### Вариант 2 — projected volume с явным audience

Используйте этот вариант если нужно явно задать audience токена, отличный от стандартного.

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      serviceAccountName: my-app
      automountServiceAccountToken: false  # отключаем стандартный токен
      containers:
        - name: app
          volumeMounts:
            - name: workload-token
              mountPath: /var/run/secrets/kubernetes.io/serviceaccount
              readOnly: true
      volumes:
        - name: workload-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 86400
                  audience: https://kubernetes.default.svc  # должен совпадать с настройками федерации в YC
```

## Зависимости

- Go 1.26+
- `golang.org/x/sync` (singleflight)
- Стандартная библиотека (`log/slog`, `net/http`, `encoding/json`)