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

## sdeutil

`sdeutil` is a small program that will download the latest or a specific build of the [EVE Online Static Data Export](https://developers.eveonline.com/static-data) (SDE.)

`sdeutil download .` will download the latest SDE build into a directory matching the build id.

`sdeutil keycheck <buildID>` parses through the SDE files, matching the fileds in the jsonl with those in the golang structs. Any differences are noted in the output and should be addressed before conversion.

`sdeutil convert <buildID>` performs a conversion from jsonl to the desired format. Currently, only a fuzzwork-compatible .sql is supported, and only the `invTypes` and `invGroups` tables are exported.

### Building `sdeutil`

``` sh
docker run --rm -v $PWD:/build golang:1 /bin/sh -c "cd /build/cmd/sdeutil; env GOOS=linux GOARCH=arm64 go build"
```
