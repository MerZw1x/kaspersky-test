package main

import (
	"flag"
	"fmt"
	"os"

	"backend/internal/app"
)

var (
	configPath = flag.String("config", "./config/local/config.yaml", "path to config file")
)

func main() {
	flag.Parse()

	application, err := app.New(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to create app:", err)
		os.Exit(1)
	}

	err = application.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to run app:", err)
		os.Exit(1)
	}
}
