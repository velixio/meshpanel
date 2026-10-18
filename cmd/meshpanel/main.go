// Command meshpanel is a control panel for headscale: device approvals over
// the web and Telegram, local accounts with 2FA, and a live dashboard.
package main

import (
	"fmt"
	"os"
	"strings"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `meshpanel: a control panel for headscale

Usage:
  meshpanel serve   [-c config.yaml]           run the panel
  meshpanel setup   [-c config.yaml] -u NAME   create the first owner account
  meshpanel user reset-2fa   [-c …] NAME       make NAME set up two-factor again
  meshpanel user set-password [-c …] NAME      set a new password for NAME
  meshpanel user list        [-c …]            list panel accounts
  meshpanel backup  [-c config.yaml] DEST      write a consistent copy of the database
  meshpanel doctor  [-c config.yaml]           check the installation
  meshpanel version

The config path defaults to $MESHPANEL_CONFIG, then /etc/meshpanel/config.yaml
(if it exists). Every key can be set with MESHPANEL_* environment variables.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "setup":
		err = runSetup(args)
	case "user":
		err = runUser(args)
	case "backup":
		err = runBackup(args)
	case "doctor":
		err = runDoctor(args)
	case "version", "--version", "-v":
		fmt.Println("meshpanel", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		msg := err.Error()
		if !strings.HasSuffix(msg, "\n") {
			msg += "\n"
		}
		fmt.Fprint(os.Stderr, "meshpanel: "+msg)
		os.Exit(1)
	}
}
