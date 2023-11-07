/*
 * UDR Configuration Factory
 */

package factory

import (
	"fmt"
	"sync"

	"github.com/asaskevich/govalidator"

	"github.com/free5gc/udr/internal/logger"
)

const (
	UdrDefaultTLSKeyLogPath  = "./log/udrsslkey.log"
	UdrDefaultCertPemPath    = "./cert/udr.pem"
	UdrDefaultPrivateKeyPath = "./cert/udr.key"
	UdrDefaultConfigPath     = "./config/udrcfg.yaml"
	UdrSbiDefaultIPv4        = "127.0.0.9"
	UdrSbiDefaultPort        = 8000
	UdrSbiDefaultScheme      = "https"
	UdrDefaultNrfUri         = "https://127.0.0.10:8000"
	UdrDrResUriPrefix        = "/nudr-dr/v1"
)

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"required"`
	sync.RWMutex
}

func (c *Config) Validate() (bool, error) {
	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"required,in(1.0.2)"`
	Description string `yaml:"description,omitempty" valid:"type(string),optional"`
}

const (
	UDR_DEFAULT_IPV4     = "127.0.0.4"
	UDR_DEFAULT_PORT     = "8000"
	UDR_DEFAULT_PORT_INT = 8000
)

type ServiceList struct {
	ServiceName    string   `yaml:"serviceName" valid:"required"`
	AllowedNfTypes []string `yaml:"allowedNfTypes,omitempty" valid:"required"`
}

type Configuration struct {
	Sbi        *Sbi     `yaml:"sbi" valid:"required"`
	Mongodb    *Mongodb `yaml:"mongodb" valid:"required"`
	NrfUri     string   `yaml:"nrfUri" valid:"url,required"`
	NrfCertPem string   `yaml:"nrfCertPem,omitempty" valid:"type(string),minstringlength(1),optional"`
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
}

func (c *Configuration) validate() (bool, error) {
	govalidator.TagMap["scheme"] = govalidator.Validator(func(str string) bool {
		return str == "https" || str == "http"
	})
	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Sbi struct {
	Scheme       string `yaml:"scheme" valid:"scheme,required"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty" valid:"host,optional"` // IP that is registered at NRF.
	// IPv6Addr string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty" valid:"host,optional"` // IP used to run the server in the node.
	Port        int    `yaml:"port" valid:"port,required"`
	Tls         *Tls   `yaml:"tls,omitempty" valid:"optional"`
	OAuth       bool   `yaml:"oauth,omitempty" valid:"optional"`
}

func (c *Config) VerifyServiceAllowType(nfTypeName string, serviceName string) error {
	c.RLock()
	defer c.RUnlock()

	serviceFound := false
	for _, service := range c.Configuration.ServiceList {
		if service.ServiceName == serviceName {
			serviceFound = true
			for _, allowNf := range service.AllowedNfTypes {
				if nfTypeName == "All" {
					return nil
				}
				if nfTypeName == allowNf {
					return nil
				}
			}
			break
		}
	}
	if serviceFound {
		return fmt.Errorf("Not allow NF Type: %+v", nfTypeName)
	}
	return fmt.Errorf("ServiceName not found: %+v", serviceName)
}

func (c *Config) GetNrfCertPemPath() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.NrfCertPemPath
}

func (c *Config) GetOAuth() bool {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.Sbi.OAuth
}

type Tls struct {
	Pem string `yaml:"pem,omitempty" valid:"type(string),minstringlength(1),required"`
	Key string `yaml:"key,omitempty" valid:"type(string),minstringlength(1),required"`
}

type Mongodb struct {
	Name string `yaml:"name" valid:"type(string),required"`
	Url  string `yaml:"url" valid:"requrl,required"`
}

func appendInvalid(err error) error {
	var errs govalidator.Errors

	if err == nil {
		return nil
	}

	es := err.(govalidator.Errors).Errors()
	for _, e := range es {
		errs = append(errs, fmt.Errorf("Invalid %w", e))
	}

	return error(errs)
}

func (c *Config) GetVersion() string {
	c.RLock()
	defer c.RUnlock()

	if c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Enable: enable,
			Level:  "info",
		}
	} else {
		c.Logger.Enable = enable
	}
}

func (c *Config) SetLogLevel(level string) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level: level,
		}
	} else {
		c.Logger.Level = level
	}
}

func (c *Config) SetLogReportCaller(reportCaller bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level:        "info",
			ReportCaller: reportCaller,
		}
	} else {
		c.Logger.ReportCaller = reportCaller
	}
}

func (c *Config) GetLogEnable() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.Enable
}

func (c *Config) GetLogLevel() string {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return "info"
	}
	return c.Logger.Level
}

func (c *Config) GetLogReportCaller() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.ReportCaller
}
