module github.com/18F/cf-domain-broker-alb

go 1.12

require (
	code.cloudfoundry.org/lager v0.0.0-20180322215153-25ee72f227fe
	github.com/18F/cf-cdn-service-broker v0.0.0-20180402200151-f1f308020e14
	github.com/aws/aws-sdk-go v1.13.34
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20180404210329-cfc053bbd960
	github.com/cloudfoundry/gofileutils v0.0.0-20170111115228-4d0c80011a0f
	github.com/davecgh/go-spew v1.1.0
	github.com/go-ini/ini v1.36.0
	github.com/golang/protobuf v1.0.0
	github.com/gorilla/context v0.0.0-20160226214623-1ea25387ff6f
	github.com/gorilla/mux v1.6.1
	github.com/jinzhu/gorm v1.9.1
	github.com/jinzhu/inflection v0.0.0-20180308033659-04140366298a
	github.com/jmespath/go-jmespath v0.0.0-20160202185014-0b12d6b521d8
	github.com/kelseyhightower/envconfig v1.3.0
	github.com/lib/pq v0.0.0-20180327071824-d34b9ff171c2
	github.com/miekg/dns v1.0.5
	github.com/pivotal-cf/brokerapi v3.0.1+incompatible
	github.com/pkg/errors v0.8.0
	github.com/pmezard/go-difflib v1.0.0
	github.com/robfig/cron v1.0.0
	github.com/stretchr/objx v0.1.0
	github.com/stretchr/testify v1.2.1
	github.com/xenolf/lego v0.0.0-20170424160445-b4deb96f1082
	golang.org/x/crypto v0.0.0-20180423110133-2b6c08872f4b
	golang.org/x/net v0.0.0-20180420171651-5f9ae10d9af5
	golang.org/x/oauth2 v0.0.0-20180416194528-6881fee410a5
	golang.org/x/text v0.3.0
	google.golang.org/appengine v1.0.0
	gopkg.in/square/go-jose.v1 v1.1.1
	gopkg.in/yaml.v2 v2.2.1
)
