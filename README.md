## OpenAPI Generated ESI

Generated using
``` sh
docker run --rm -v .:/local openapitools/openapi-generator-cli generate \
	-i /local/openapi.yaml \
	-g go \
	-o /local/esi \
	-p packageName=esi \
	-p packageVersion=2020.01.01
```

