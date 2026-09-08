package main

import (
	"github.com/GiGurra/boa/pkg/boa"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	cmdbase "github.com/abundo/dnsmgr2/cmd"
	dnsmgr "github.com/abundo/dnsmgr2/dnsmgr"
)

// Set by GoReleaser via -ldflags.
var version = "dev"

func main() {
	boa.RegisterConfigFormat(".yaml", yaml.Unmarshal)

	cmdbase.Run(boa.CmdT[struct{}]{
		Use:     "dnsmgr2",
		Short:   "Manage DNS and DHCP servers",
		Version: version,
		SubCmds: boa.SubCmds(

			boa.CmdT[cmdbase.Params]{
				Use:   "load",
				Short: "Load and print records",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					cmdbase.ApplyParams(p)
					dm, err := dnsmgr.NewDnsManager(p.Config)
					if err != nil {
						return err
					}
					if err := dm.Load(); err != nil {
						return err
					}
					dm.PrintRecords()
					return nil
				},
			},

			boa.CmdT[cmdbase.Params]{
				Use:   "restart",
				Short: "Restart services",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					cmdbase.ApplyParams(p)
					dm, err := dnsmgr.NewDnsManager(p.Config)
					if err != nil {
						return err
					}
					return dm.Restart()
				},
			},

			boa.CmdT[cmdbase.Params]{
				Use:   "show-config",
				Short: "Show loaded configuration",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					cmdbase.ApplyParams(p)
					dnsmgr.Pprint(p)
					return nil
				},
			},

			boa.CmdT[cmdbase.Params]{
				Use:   "status",
				Short: "Show status on services",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					cmdbase.ApplyParams(p)
					dm, err := dnsmgr.NewDnsManager(p.Config)
					if err != nil {
						return err
					}
					return dm.Status()
				},
			},

			boa.CmdT[cmdbase.Params]{
				Use:   "sync",
				Short: "Sync DNS and DHCP records",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					cmdbase.ApplyParams(p)
					dm, err := dnsmgr.NewDnsManager(p.Config)
					if err != nil {
						return err
					}
					if err := dm.Load(); err != nil {
						return err
					}
					return dm.Sync()
				},
			},
		),
	})
}
