package main

import (
	"fmt"
	"net/http"
	"os"

	"code.cloudfoundry.org/lager"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/pivotal-cf/brokerapi"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/18F/cf-domain-broker-alb/broker"
	"github.com/18F/cf-domain-broker-alb/config"
	"github.com/18F/cf-domain-broker-alb/healthchecks"
	"github.com/18F/cf-domain-broker-alb/models"
	"github.com/18F/cf-domain-broker-alb/utils"
)

func main() {
	logger := lager.NewLogger("cf-domain-broker-alb")
	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.INFO))

	settings, err := config.NewSettings()
	if err != nil {
		logger.Fatal("new-settings", err)
	}

	db, err := config.Connect(settings)
	if err != nil {
		logger.Fatal("connect", err)
	}

	cfClient, err := cfclient.NewClient(&cfclient.Config{
		ApiAddress:   settings.APIAddress,
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
	})
	if err != nil {
		logger.Fatal("cf-client", err)
	}

	session := session.New(aws.NewConfig().WithRegion(settings.AwsDefaultRegion))

	if err := db.AutoMigrate(&models.Route{}, &models.ALBProxy{}, &models.Certificate{}, &models.UserData{}).Error; err != nil {
		logger.Fatal("migrate", err)
	}

	manager := models.NewManager(
		logger,
		&utils.Iam{iam.New(session)},
		elbv2.New(session),
		settings,
		db,
	)
	broker := broker.New(
		&manager,
		cfClient,
		settings,
		logger,
	)
	credentials := brokerapi.BrokerCredentials{
		Username: settings.BrokerUsername,
		Password: settings.BrokerPassword,
	}

	if err := manager.Populate(); err != nil {
		logger.Fatal("populate", err)
	}

	brokerAPI := brokerapi.New(broker, logger, credentials)
	server := bindHTTPHandlers(brokerAPI, settings)
	http.ListenAndServe(fmt.Sprintf(":%s", settings.Port), server)
}

func bindHTTPHandlers(handler http.Handler, settings config.Settings) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	healthchecks.Bind(mux, settings)

	return mux
}
