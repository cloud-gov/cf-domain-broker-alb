package config

import (
	"github.com/kelseyhightower/envconfig"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/lib/pq"
)

type Settings struct {
	Port                 string `envconfig:"port" default:"3000"`
	BrokerUsername       string `envconfig:"broker_username" required:"true"`
	BrokerPassword       string `envconfig:"broker_password" required:"true"`
	DatabaseUrl          string `envconfig:"database_url" required:"true"`
	Email                string `envconfig:"email" required:"true"`
	AcmeUrl              string `envconfig:"acme_url" required:"true"`
	MaxRoutes            int    `envconfig:"max_routes" default:"24"`
	Bucket               string `envconfig:"bucket" required:"true"`
	ALBPrefix            string `envconfig:"alb_prefix" default:"domains-broker"`
	IamPathPrefix        string `envconfig:"iam_path_prefix" default:"/domains-broker/"`
	AwsAccessKeyId       string `envconfig:"aws_access_key_id" required:"true"`
	AwsSecretAccessKey   string `envconfig:"aws_secret_access_key" required:"true"`
	AwsDefaultRegion     string `envconfig:"aws_default_region" required:"true"`
	ServerSideEncryption string `envconfig:"server_side_encryption"`
	APIAddress           string `envconfig:"api_address" required:"true"`
	ClientID             string `envconfig:"client_id" required:"true"`
	ClientSecret         string `envconfig:"client_secret" required:"true"`
	Schedule             string `envconfig:"schedule" default:"0 0 * * * *"`
	RenewDays            int    `envconfig:"renew_days" default:"30"`
}

func NewSettings() (Settings, error) {
	var settings Settings
	err := envconfig.Process("cdn", &settings)
	if err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func Connect(settings Settings) (*gorm.DB, error) {
	return gorm.Open("postgres", settings.DatabaseUrl)
}
