package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/AlHeamer/sde"
)

const (
	argDownload        = "download"
	sdeBaseUrl         = "https://developers.eveonline.com/static-data/tranquility/"
	sdeSchemaChangelog = sdeBaseUrl + "schema-changelog.yaml"
	sdeChangelog       = sdeBaseUrl + "changes/%d.jsonl"
	sdeVersionUrl      = sdeBaseUrl + "latest.jsonl"
	sdeUrlPattern      = sdeBaseUrl + "eve-online-static-data-%d-%s.zip"
	sdeUrlLatest       = sdeBaseUrl + "eve-online-static-data-latest-%s.zip"
	sdeVariantJsonl    = "jsonl"
	sdeVariantYaml     = "yaml"
)

var helpDownload string = `The download command downloads and unzips the EVE Online Static data export
into the specified directory.

Usage:
	` + path.Base(os.Args[0]) + ` download [arguments] <directory>

Arguments are:`

func cmdDownload() {
	var (
		build   int64
		variant string
		err     error
	)

	flagSet := flag.NewFlagSet(argDownload, flag.ExitOnError)
	flagSet.StringVar(&variant, "variant", sdeVariantJsonl, "the sde variant to fetch. [jsonl|yaml]")
	flagSet.Int64Var(&build, "build", 0, "specific build number to download. leave blank for latest.")
	flagSet.Parse(os.Args[1:])

	if flagSet.Arg(0) == argHelp {
		usage(helpDownload, flagSet)
	}

	outDir := flagSet.Arg(1)
	if outDir == "" {
		usage(helpDownload, flagSet)
	}

	if build == 0 {
		if build, err = checkLatestVersion(); err != nil {
			log.Fatalf("error checking for latest version: %s", err.Error())
		}
	}

	outDir = path.Clean(path.Join(outDir, strconv.FormatInt(build, 10)))
	if err = os.MkdirAll(outDir, os.ModePerm); err != nil {
		log.Fatalf("unable to create dir: %s", err.Error())
	}

	zipReader := downloadSde(build, variant)
	for _, file := range zipReader.File {
		log.Println("processing", file.Name)

		src, err := file.Open()
		if err != nil {
			log.Fatalf("error opening file: %s", err.Error())
		}

		dst, err := os.Create(path.Join(outDir, file.Name))
		if err != nil {
			log.Fatalf("error creating file: %s", err.Error())
		}

		// copy archive file to local disk
		if _, err = io.Copy(dst, src); err != nil {
			log.Fatalf("error copying data: %s", err.Error())
		}

		src.Close()
	}
}

func downloadSde(build int64, variant string) *zip.Reader {
	var (
		resp *http.Response
		err  error
		url  = fmt.Sprintf(sdeUrlLatest, variant)
	)
	if build > 0 {
		url = fmt.Sprintf(sdeUrlPattern, build, variant)
	}

	resp, err = http.Get(url)
	if err != nil {
		log.Fatal("error fetching sde")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("fetching sde response not ok: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("error reading body: %s", err.Error())
	}

	reader, err := zip.NewReader(bytes.NewReader(b), resp.ContentLength)
	if err != nil {
		log.Fatalf("error creating zip reader: %s", err.Error())
	}

	return reader
}

func checkLatestVersion() (int64, error) {
	log.Printf("checking for latest sde build")
	resp, err := http.Get(sdeVersionUrl)
	if err != nil {
		return 0, fmt.Errorf("error fetching latest sde build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("sde build response not ok: %s", resp.Status)
	}

	dec := json.NewDecoder(resp.Body)
	for dec.More() {
		var bd sde.Meta
		if err = dec.Decode(&bd); err != nil {
			return 0, fmt.Errorf("error decoding json: %w", err)
		}

		if bd.Key == "sde" {
			log.Printf("found latest sde build: %d released %v", bd.BuildNumber, bd.ReleaseDate)
			return bd.BuildNumber, nil
		}
	}

	return 0, errors.New("sde build data not found")
}
