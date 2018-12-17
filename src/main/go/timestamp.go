package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/privacybydesign/irmago"
)

func parseCliArgs() (conf *irma.Configuration, abs *irma.SignedMessage, err error) {
	if len(os.Args) < 3 {
		err = errors.New("Missing SignedMessage argument")
		return
	}
	conf, err = parseIrmaConfiguration(os.Args[1])
	if err != nil {
		return
	}
	abs = new(irma.SignedMessage)
	err = json.Unmarshal([]byte(os.Args[2]), abs)
	return
}

func parseIrmaConfiguration(path string) (conf *irma.Configuration, err error) {
	if conf, err = irma.NewConfiguration(path, ""); err != nil {
		return
	}
	err = conf.ParseFolder()
	return
}

func main() {
	var err error
	defer func() {
		exitCode := 0
		if err != nil {
			exitCode = 1
			fmt.Printf(err.Error())
		}
		os.Exit(exitCode)
	}()

	conf, irmaSignature, err := parseCliArgs()
	if err != nil {
		return
	}

	err = irmaSignature.VerifyTimestamp(irmaSignature.Message, conf)
}
