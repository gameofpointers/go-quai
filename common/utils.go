package common

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/dominant-strategies/go-quai/cmd/utils"
	"github.com/dominant-strategies/go-quai/common/constants"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/spf13/viper"
)

// InitConfig initializes the viper config instance ensuring that environment variables
// take precedence over config file parameters.
// Environment variables should be prefixed with the application name (e.g. QUAI_LOG_LEVEL).
// If the flag SAVE_CONFIG_FILE is set to true, the config file will be saved or updated with the current config parameters.
// It panics if an error occurs while reading the config file.
func InitConfig() {
	// read in config file and merge with defaults
	log.Infof("Loading config from file: %s", viper.ConfigFileUsed())
	err := viper.ReadInConfig()
	if err != nil {
		// if error is type ConfigFileNotFoundError or fs.PathError, ignore error
		if _, ok := err.(*fs.PathError); ok || errors.Is(err, viper.ConfigFileNotFoundError{}) {
			log.Warnf("Config file not found: %s", viper.ConfigFileUsed())
		} else {
			log.Errorf("Error reading config file: %s", err)
			// config file was found but another error was produced. Cannot continue
			panic(err)
		}
	}

	log.Info("Printing all flags and their values")
	fmt.Println("IP Address:", viper.GetString("ipaddr"))
	fmt.Println("P2P Port:", viper.GetString("port"))
	fmt.Println("Bootnode:", viper.GetBool("bootnode"))
	fmt.Println("Bootpeers:", viper.GetStringSlice("bootpeers"))
	fmt.Println("Portmap:", viper.GetBool("portmap"))
	fmt.Println("Private Key File:", viper.GetString("private.key"))
	fmt.Println("Minimum Peers:", viper.GetString("min-peers"))
	fmt.Println("Maximum Peers:", viper.GetString("max-peers"))
	fmt.Println("Location:", viper.GetString("location"))
	fmt.Println("Config Directory:", viper.GetString("config-dir"))
	fmt.Println("Data Directory:", viper.GetString("data-dir"))
	fmt.Println("Log Level:", viper.GetString("log-level"))
	fmt.Println("Save Config:", viper.GetBool("save-config"))

	log.Infof("Loading config from environment variables with prefix: '%s_'", constants.ENV_PREFIX)
	viper.SetEnvPrefix(constants.ENV_PREFIX)
	viper.AutomaticEnv()
}

// saves the config file with the current config parameters.
//
// If the config file does not exist, it creates it.
//
// If the config file exists, it creates a backup copy ending with .bak
// and overwrites the existing config file.
// TODO: consider using one single utility function to save/update/append files throughout the codebase
func SaveConfig() error {
	// check if config file exists
	configFile := viper.ConfigFileUsed()
	log.Debugf("saving/updating config file: %s", configFile)
	if _, err := os.Stat(configFile); err == nil {
		// config file exists, create backup copy
		err := os.Rename(configFile, configFile+".bak")
		if err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		// config file does not exist, create directory if it does not exist
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			configDir := viper.GetString(utils.ConfigDirFlag.Name)
			if err := os.MkdirAll(configDir, 0755); err != nil {
				return err
			}
		}
		_, err := os.Create(configFile)
		if err != nil {
			return err
		}
	} else {
		return err
	}

	// write config file
	err := viper.WriteConfigAs(configFile)
	if err != nil {
		return err
	}
	return nil
}
