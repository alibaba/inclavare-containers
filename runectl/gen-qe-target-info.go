package main // import "github.com/inclavare-containers/runectl"

import (
	"github.com/opencontainers/runc/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io/ioutil"
)

var generateQeTargetInfoCommand = cli.Command{
	Name:  "gen-qe-target-info",
	Usage: "retrieve the target information about Quoting Enclave from aesmd",
	ArgsUsage: `[command options]

EXAMPLE:
For example, save the target information file about Quoting Enclave retrieved from aesmd:

	# runectl gen-qe-target-info --targetinfo foo`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "targetinfo",
			Usage: "path to the output target information file containing TARGETINFO",
		},
	},
	Action: func(context *cli.Context) error {
		if context.GlobalBool("verbose") {
			logrus.SetLevel(logrus.DebugLevel)
		}

		ti, err := intelsgx.GetQeTargetInfo()
		if err != nil {
			logrus.Print(err)
			return err
		}

		tiPath := context.String("targetinfo")
		if tiPath == "" {
			tiPath = "qe_targetinfo.bin"
		}

		if err := ioutil.WriteFile(tiPath, ti, 0664); err != nil {
			return err
		}

		logrus.Infof("quoting enclave's target info file %s saved", tiPath)

		return nil
	},
	SkipArgReorder: true,
}
