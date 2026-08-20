package cmdbase

import dnsmgr "github.com/abundo/dnsmgr2/internal"

type Params struct {
	ConfigFile string            `configfile:"true" optional:"true" default:"/etc/dnsmgr2/dnsmgr2.yaml"`
	Debug      bool              `descr:"Enable verbose debug logging" short:"d"`
	Loglevel   string            `descr:"Set log level" alts:"error,warning,info,debug" default:"info"`
	Config     dnsmgr.ConfigRoot `yaml:",inline"`
}
