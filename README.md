#
Встраиваемый в конвейер echo модуль авторизации для валидации входящих запросов
Модуль закрытый, для подключения требуются права на доступ в репозиторий git
Права могут быть выданы через выпуск access-token в TFS.
#
Валидация токенов происходит по трем параметрам: 
- Публичному ключу для проверки цифровой подписи токена. 
- Issuer
- Audience

#
Пример конфигурации сервиса, использующего модуль авторизации
```
jwt:
  public_key: |
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE35pY9Ig4aK6Qvq0cZMLJOJXit3Jx
    T2J+iVkAVn1X8f4szENyvvPzWfat5VlNo+lagIww2l/jdAeiCg1sQMAUmQ==
    -----END PUBLIC KEY-----
  issuer: 'apps.m-ticket.ru/ra/ru-sak'
  audience: 'https://apps.m-ticket.ru/ra/ru-sak'
```
#
Генератор спецификации swagger 
oapi-codegen -generate spec -o openapi_spec.echo.gen.go -package codegen post.yaml. 
Спецификация используется модулем для пропуска без авторизации публичных запросов 

#
Подключение модуля в конвейер echo. 
> app.go
```
improt (
...
PetAuth "tfs.i.altatec.ru/tfs/Altatec/Pets/_git/PetAuth.git"
...
)

func Run(cfg *config.Config) {
	...
	//jwt
	validator := PetAuth.NewJwtValidator(cfg.PublicKey, cfg.Issuer, cfg.Audience)
	//codegen swagger 
	spec, err := codegen.GetSwagger()
	if err != nil {
		panic(fmt.Errorf("loading spec: %w", err))
	}

	mw := PetAuth.NewJwtValidatorMiddleware(validator, spec)
	e.Use(mw.JwtParseMiddleware)
	...
	// codegen
	codegen.RegisterHandlers(e, ps)
	
}
```
#
Получение объекта токена авторизации и распарсенных клаймов в пользовательском коде
>server.go
```
improt (
...
PetAuth "tfs.i.altatec.ru/tfs/Altatec/Pets/_git/PetAuth.git"
...
)
func (ps *PostServer) PostPost(ctx echo.Context) error {

	cc := ctx.(*PetAuth.JwtContext)
	token := cc.Token
	uniqueName := cc.UniqueName
	emailHash := cc.EmailHash
	roles := cc.Roles
```

