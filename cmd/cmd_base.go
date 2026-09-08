package cmdbase

import (
	"fmt"
	"os"

	"github.com/GiGurra/boa/pkg/boa"

	dnsmgr "github.com/abundo/dnsmgr2/internal"
)

type Params struct {
	ConfigFile string `configfile:"true" optional:"true" default:"/etc/dnsmgr2/dnsmgr2.yaml"`
	Debug      bool   `descr:"Enable verbose debug logging" short:"d"`
	Loglevel   string `descr:"Set log level" alts:"error,warning,info,debug" default:"info"`
	// Config is YAML-only. boa:"ignore" keeps nested slices such as
	// dhcp.dns_servers from becoming required CLI flags (missing
	// config-dhcpdns-servers) when the key is omitted; prefixes may
	// supply per-subnet servers instead.
	Config dnsmgr.ConfigRoot `yaml:",inline" boa:"ignore"`
}

// osExit is os.Exit, swapped in tests so Run can be exercised without
// terminating the test process.
var osExit = os.Exit

// Run executes a boa command without dumping cobra usage/help on error.
// boa.Cmd.Run always prints UsageString() before the error — including for
// runtime failures from RunFuncE — which dumps every config flag on crash.
// --help still works. Failures print "Error: ..." to stderr and exit 1.
func Run(c boa.CmdIfc) {
	cmd := c.ToCobra()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		osExit(1)
	}
}
