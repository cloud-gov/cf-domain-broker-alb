package broker_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"

	"code.cloudfoundry.org/lager"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/pivotal-cf/brokerapi"

	"github.com/18F/cf-domain-broker-alb/broker"
	cfmock "github.com/18F/cf-domain-broker-alb/cf/mocks"
	"github.com/18F/cf-domain-broker-alb/config"
	"github.com/18F/cf-domain-broker-alb/models"
	"github.com/18F/cf-domain-broker-alb/models/mocks"
)

func TestProvisioning(t *testing.T) {
	suite.Run(t, new(ProvisionSuite))
}

type ProvisionSuite struct {
	suite.Suite
	Manager  mocks.RouteManagerIface
	Broker   *broker.DomainBroker
	cfclient cfmock.Client
	settings config.Settings
	logger   lager.Logger
	ctx      context.Context
}

func (s *ProvisionSuite) SetupTest() {
	s.Manager = mocks.RouteManagerIface{}
	s.cfclient = cfmock.Client{}
	s.logger = lager.NewLogger("broker.provision.test")
	s.Broker = broker.New(
		&s.Manager,
		&s.cfclient,
		s.settings,
		s.logger,
	)
	s.ctx = context.Background()

	s.cfclient.On("GetOrgByGuid", "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5").Return(cfclient.Org{Name: "my-org"}, nil)

}

func (s *ProvisionSuite) TestSync() {
	_, err := s.Broker.Provision(s.ctx, "", brokerapi.ProvisionDetails{}, false)
	s.Equal(err, brokerapi.ErrAsyncRequired)
}

func (s *ProvisionSuite) TestWithoutDetails() {
	_, err := s.Broker.Provision(s.ctx, "", brokerapi.ProvisionDetails{}, true)
	s.NotNil(err)
	s.Equal(err.Error(), "must be invoked with configuration parameters")
}

func (s *ProvisionSuite) TestWithoutOptions() {
	details := brokerapi.ProvisionDetails{
		RawParameters: []byte(`{}`),
	}
	_, err := s.Broker.Provision(s.ctx, "", details, true)
	s.NotNil(err)
	s.Equal(err.Error(), "must pass non-empty `domains`")
}

func (s *ProvisionSuite) TestInstanceExists() {
	route := &models.Route{
		State: models.Provisioned,
	}
	s.cfclient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
	s.Manager.On("Get", "123").Return(route, nil)

	details := brokerapi.ProvisionDetails{
		RawParameters: []byte(`{"domains": ["domain.gov"]}`),
	}
	_, err := s.Broker.Provision(s.ctx, "123", details, true)
	s.Equal(err, brokerapi.ErrInstanceAlreadyExists)
}

func (s *ProvisionSuite) TestSuccess() {
	s.Manager.On("Get", "123").Return(&models.Route{}, errors.New("not found"))
	route := &models.Route{State: models.Provisioning}
	s.cfclient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
	s.Manager.On("Create", "123", []string{"domain.gov"}).Return(route, nil)

	details := brokerapi.ProvisionDetails{
		RawParameters: []byte(`{"domains": ["domain.gov"]}`),
	}
	_, err := s.Broker.Provision(s.ctx, "123", details, true)
	s.Nil(err)
}

func (s *ProvisionSuite) TestDomainNotExists() {
	s.cfclient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, errors.New("fail"))
	details := brokerapi.ProvisionDetails{
		OrganizationGUID: "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5",
		RawParameters:    []byte(`{"domains": ["domain.gov"]}`),
	}
	_, err := s.Broker.Provision(s.ctx, "123", details, true)
	s.NotNil(err)
	s.Contains(err.Error(), "cf create-domain")
}

func (s *ProvisionSuite) TestMultipleDomainsOneNotExists() {
	s.cfclient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
	s.cfclient.On("GetDomainByName", "domain2.gov").Return(cfclient.Domain{}, errors.New("fail"))
	details := brokerapi.ProvisionDetails{
		OrganizationGUID: "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5",
		RawParameters:    []byte(`{"domains": ["domain.gov", "domain2.gov"]}`),
	}
	_, err := s.Broker.Provision(s.ctx, "123", details, true)
	s.NotNil(err)
	s.Contains(err.Error(), "Domain does not exist")
	s.NotContains(err.Error(), "domain.gov")
	s.Contains(err.Error(), "domain2.gov")
}

func (s *ProvisionSuite) TestMultipleDomainsMoreThanOneNotExists() {
	s.cfclient.On("GetDomainByName", "domain.gov").Return(cfclient.Domain{}, nil)
	s.cfclient.On("GetDomainByName", "domain2.gov").Return(cfclient.Domain{}, errors.New("fail"))
	s.cfclient.On("GetDomainByName", "domain3.gov").Return(cfclient.Domain{}, errors.New("fail"))
	details := brokerapi.ProvisionDetails{
		OrganizationGUID: "dfb39134-ab7d-489e-ae59-4ed5c6f42fb5",
		RawParameters:    []byte(`{"domains": ["domain.gov", "domain2.gov", "domain3.gov"]}`),
	}
	_, err := s.Broker.Provision(s.ctx, "123", details, true)
	s.NotNil(err)
	s.Contains(err.Error(), "Multiple domains do not exist")
	s.NotContains(err.Error(), "domain.gov")
	s.Contains(err.Error(), "domain2.gov")
	s.Contains(err.Error(), "domain3.gov")
}
