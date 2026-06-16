#
Встраиваемый в конвейер echo модуль авторизации для валидации входящих запросов.
Модуль проверяет цифровую подпись JWT токенов авторизации по публичному ключу для защищенных запросов и, в случае успешной проверки, подготавливает пользовательские данные для их прямого использования в пользовательском коде приложения.
Метод считается защищенным если он подпадает в условия, заданные регулярными выражениями в настройках модуля.
Открытые методы доступны без авторизации, но если в запросе к открытым методам представлен JWT токен он будет также провалидирован.

#
Валидация токенов происходит по issuer из токена (`iss`):
- из payload токена извлекается `iss` без криптографической проверки только для выбора ключа;
- выбирается конфигурация с соответствующим issuer;
- выполняется полная проверка подписи, issuer и audience выбранным ключом;
- claims из unverified parse не считаются доверенными.

Поддерживаются два способа инициализации валидатора:
- `NewJwtValidator(publicKey, issuer, audience)` — legacy-конструктор для одного ключа;
- `NewJwtValidatorFromConfigs([]IssuerConfig)` — конструктор для нескольких ключей.

Правила обработки массива ключей:
- при дубликате `issuer` используется последний элемент (`overwrite`);
- записи с пустым `issuer` или `public_key` игнорируются;
- если после фильтрации не осталось валидных ключей, конструктор возвращает ошибку.

#
Пример конфигурации сервиса, использующего модуль авторизации
```
jwt:
  keys:
    - issuer: 'apps.moby.city'
      public_key: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE35pY9Ig4aK6Qvq0cZMLJOJXit3Jx
        T2J+iVkAVn1X8f4szENyvvPzWfat5VlNo+lagIww2l/jdAeiCg1sQMAUmQ==
        -----END PUBLIC KEY-----
      audience: 'https://apps.moby.city'
```

# Спецификация защищенных маршрутов передается в мидлвари в виде коллекции регулярных выражений securutyRoutes:
```
securityRoutes := make(map[string][]string)
	securityRoutes["POST"] = []string{"^/post$","^/comments$"}
	securityRoutes["PUT"] = []string{"^/post/"}
	securityRoutes["DELETE"] = []string{"^/post/"}
```

#
Подключение модуля в конвейер echo.
> app.go
```
import (
...
PetAuth "github.com/altatec-sources/go-jwt-middleware"
...
)

func Run(cfg *config.Config) {
	...
	issuerConfigs, err := cfg.BuildJwtIssuerConfigs()
	if err != nil {
		panic(err)
	}

	validator, err := PetAuth.NewJwtValidatorFromConfigs(issuerConfigs)
	if err != nil {
		panic(err)
	}

	mw := PetAuth.NewJwtValidatorMiddleware(validator, securityRoutes)
	e.Use(mw.JwtParseMiddleware)
	...
	// codegen
	codegen.RegisterHandlers(e, ps)
	
}
```

Legacy-инициализация для одного ключа:
```
validator := PetAuth.NewJwtValidator(cfg.PublicKey, cfg.Issuer, cfg.Audience)
```

#
Получение объекта токена авторизации и распарсенных клаймов в пользовательском коде
>server.go
```
import (
...
PetAuth "github.com/altatec-sources/go-jwt-middleware"
...
)
func (ps *PostServer) PostPost(ctx echo.Context) error {
	cc, ok := ctx.(*PetAuth.JwtContext)
	if ok {
		token := cc.Token
		uniqueName := cc.UniqueName
		emailHash := cc.EmailHash
		roles := cc.Roles
	}

```
