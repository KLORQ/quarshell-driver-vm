package vm

import "github.com/KLORQ/quarshell-driver/driver"

func init() {
	if err := driver.RegisterBackendWithConfigAndInfoAndValidator("vm", (&Driver{}).backendInfo(), func(values map[string]any) (driver.Backend, error) {
		config, err := hostConfigFromMap(values)
		if err != nil {
			return nil, err
		}
		return NewWithHostConfig(config), nil
	}, func(values map[string]any) error {
		_, err := hostConfigFromMap(values)
		return err
	}); err != nil {
		panic(err)
	}
	if err := driver.RegisterBackendHostToolPreflight("vm", preflightVMHostTools); err != nil {
		panic(err)
	}
}
