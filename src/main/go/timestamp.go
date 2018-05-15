package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/privacybydesign/irmago"
)

func getJsonErrorString(e error) string {
	return fmt.Sprintf("{\"error\":\"%v\"}", e)
}

func parseCliArgs() (*irma.Configuration, *irma.IrmaSignedMessage, error) {
	if len(os.Args) < 3 {
		return nil, nil, errors.New("Missing IrmaSignedMessage argument")
	}
	conf, err := parse(os.Args[1])
	if err != nil {
		return nil, nil, err
	}
	abs := new(irma.IrmaSignedMessage)
	return conf, abs, json.Unmarshal([]byte(os.Args[2]), abs)
}

func parse(path string) (conf *irma.Configuration, err error) {
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
			fmt.Print(getJsonErrorString(err))
		}
		os.Exit(exitCode)
	}()

	// Parse CLI args
	conf, irmaSignature, err := parseCliArgs()
	if err != nil {
		return
	}

	status, _ := irma.VerifySigWithoutRequest(conf, irmaSignature)
	bts, err := json.Marshal(status)
	if err != nil {
		return
	}
	fmt.Println(string(bts))
}
