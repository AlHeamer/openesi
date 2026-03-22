## OpenAPI Generated ESI

Generated using
``` sh
curl -O "https://esi.evetech.net/meta/openapi.yaml?compatibility_date=2025-12-16"

docker run --rm -v .:/local openapitools/openapi-generator-cli generate \
	-i /local/openapi.yaml \
	-g go \
	-o /local/esi \
	-p packageName=esi \
	-p packageVersion=2025.12.16 \
	--git-user-id AlHeamer \
	--git-repo-id openesi/esi
```

