package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"time"
)

const (
	argHelp = "help"
)

func baseUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
	%s <command> [arguments]

Commands:
	help
	convert
	download
	keycheck

Use "%s help <command>" for more information about a command.
`, path.Base(os.Args[0]), path.Base(os.Args[0]))
	os.Exit(1)
}

func usage(description string, flagSet *flag.FlagSet) {
	if flagSet == nil {
		baseUsage()
	}

	fmt.Fprintf(os.Stderr, "%s\n", description)
	flagSet.PrintDefaults()

	os.Exit(1)
}

func main() {
	startTime := time.Now()
	argc := len(os.Args)
	if argc < 2 {
		baseUsage()
	}

	command := os.Args[1]
	if command == argHelp {
		if argc >= 3 {
			command = os.Args[2]
		}
	}

	switch command {
	case argConvert:
		cmdConvert()

	case argDownload:
		cmdDownload()

	case argKeycheck:
		cmdKeycheck()
	}

	log.Println("completed in " + time.Since(startTime).String())
}
