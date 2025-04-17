module github.com/18F/cf-domain-broker-alb

go 1.23.0

toolchain go1.23.7

require (
	code.cloudfoundry.org/lager v2.0.0+incompatible
	github.com/18F/cf-cdn-service-broker v0.0.0-20240618191525-6def76a83329
	github.com/aws/aws-sdk-go v1.55.5
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20220930021109-9c4e6c59ccf1
	github.com/jinzhu/gorm v1.9.16
	github.com/jmcarp/lego v0.3.2-0.20170424160445-b4deb96f1082
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.10.9
	github.com/pivotal-cf/brokerapi v3.0.1+incompatible
	github.com/robfig/cron v1.2.0
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/miekg/dns v1.1.25 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/square/go-jose.v1 v1.1.1 // indirect
)

replace github.com/miekg/dns v1.1.25 => github.com/miekg/dns v1.0.5

require (
	github.com/Masterminds/semver v1.4.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	// indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/oauth2 v0.21.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
