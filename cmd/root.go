package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/dominant-strategies/go-quai/cmd/utils"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/constants"
	"github.com/dominant-strategies/go-quai/log"
)

var rootCmd = &cobra.Command{
	PersistentPreRunE: rootCmdPreRun,
}

func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		return err
	}
	return nil
}

func init() {
	// Location for default config directory
	rootCmd.PersistentFlags().StringP(utils.ConfigDirFlag.Name, utils.ConfigDirFlag.Abbreviation, utils.ConfigDirFlag.DefaultValue, utils.ConfigDirFlag.Usage)
	viper.BindPFlag(utils.ConfigDirFlag.Name, rootCmd.PersistentFlags().Lookup(utils.ConfigDirFlag.Name))

	// Location for default runtime data directory
	rootCmd.PersistentFlags().StringP(utils.DataDirFlag.Name, utils.DataDirFlag.Abbreviation, utils.DataDirFlag.DefaultValue, utils.DataDirFlag.Usage)
	viper.BindPFlag(utils.DataDirFlag.Name, rootCmd.PersistentFlags().Lookup(utils.DataDirFlag.Name))

	// Log level to use (trace, debug, info, warn, error, fatal, panic)
	rootCmd.PersistentFlags().StringP(utils.LogLevelFlag.Name, utils.LogLevelFlag.Abbreviation, utils.LogLevelFlag.DefaultValue, utils.LogLevelFlag.Usage)
	viper.BindPFlag(utils.LogLevelFlag.Name, rootCmd.PersistentFlags().Lookup(utils.LogLevelFlag.Name))

	// When set to true saves or updates the config file with the current config parameters
	rootCmd.PersistentFlags().BoolP(utils.SaveConfigFlag.Name, utils.SaveConfigFlag.Abbreviation, utils.SaveConfigFlag.DefaultValue, utils.SaveConfigFlag.Usage)
	viper.BindPFlag(utils.SaveConfigFlag.Name, rootCmd.PersistentFlags().Lookup(utils.SaveConfigFlag.Name))
}

func rootCmdPreRun(cmd *cobra.Command, args []string) error {
	// set logger inmediately after parsing cobra flags
	logLevel := cmd.Flag(utils.LogLevelFlag.Name).Value.String()
	log.ConfigureLogger(log.WithLevel(logLevel))
	// set config path to read config file
	configDir := cmd.Flag(utils.ConfigDirFlag.Name).Value.String()
	viper.SetConfigFile(configDir + constants.CONFIG_FILE_NAME)
	viper.SetConfigType("yaml")
	// load config from file and environment variables
	common.InitConfig()
	// bind cobra flags to viper instance
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		return fmt.Errorf("error binding flags: %s", err)
	}

	// Make sure data dir and config dir exist
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return err
		}
	}

	// save config file if SAVE_CONFIG_FILE flag is set to true
	saveConfigFile := viper.GetBool(utils.SaveConfigFlag.Name)
	if saveConfigFile {
		err := common.SaveConfig()
		if err != nil {
			log.Errorf("error saving config file: %s . Skipping...", err)
		} else {
			log.Debugf("config file saved successfully")
		}
	}

	log.Tracef("config options loaded: %+v", viper.AllSettings())
	return nil
}
