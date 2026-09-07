package main

import (
	"github.com/GiGurra/boa/pkg/boa"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	cmdbase "github.com/abundo/dnsmgr2/cmd"
	dnsmgr "github.com/abundo/dnsmgr2/internal"
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
					dm, err := dnsmgr.NewDnsManager(p.Config)
					if err != nil {
						return err
					}
					err = dm.Load()
					if err != nil {
						return err
					}
					dm.PrintRecords()
					return err
				},
			},

			boa.CmdT[cmdbase.Params]{
				Use:   "restart",
				Short: "Restart services",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					dm, err := dnsmgr.NewDnsManager(p.Config)
					if err != nil {
						return err
					}
					err = dm.Restart()
					return err
				},
			},

			boa.CmdT[cmdbase.Params]{
				Use:   "show-config",
				Short: "Show loaded configuration",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					dnsmgr.Pprint(p)
					return nil
				},
			},

			boa.CmdT[cmdbase.Params]{
				Use:   "status",
				Short: "Show status on services",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					dm, err := dnsmgr.NewDnsManager(p.Config)
					if err != nil {
						return err
					}
					err = dm.Status()
					return err
				},
			},

			boa.CmdT[cmdbase.Params]{
				Use:   "sync",
				Short: "Sync DNS and DHCP records",
				RunFuncE: func(p *cmdbase.Params, cmd *cobra.Command, args []string) error {
					dm, err := dnsmgr.NewDnsManager(p.Config)
					if err != nil {
						return err
					}
					err = dm.Load()
					if err != nil {
						return err
					}
					err = dm.Sync()
					if err != nil {
						return err
					}
					return nil
				},
			},
		),
	})
}
