# Custom Domain Service Broker

A [Cloud Foundry](https://www.cloudfoundry.org/) [service broker](https://docs.cloudfoundry.org/services/) that provides a custom domain service. Traffic is encrypted using an SSL certificate generated by [Let's Encrypt](https://letsencrypt.org/).

For the CDN version of this broker: https://github.com/18F/cf-cdn-service-broker

## Deployment

### Automated

The easiest/recommended way to deploy the broker is via the [Concourse](http://concourse.ci/) pipeline.

1. Create a `ci/credentials.yml` file, and fill in the templated values from [the pipeline](ci/pipeline.yml).
1. Deploy the pipeline.

    ```bash
    fly -t lite set-pipeline -n -c ci/pipeline.yml -p deploy-cdn-broker -l ci/credentials.yml
    ```

### Manual

1. Clone this repository, and `cd` into it.
1. Target the space you want to deploy the broker to.

    ```bash
    $ cf target -o <org> -s <space>
    ```

1. Set the `environment_variables` listed in [the deploy pipeline](ci/pipeline.yml).
1. Deploy the broker as an application.

    ```bash
    $ cf push
    ```

1. [Register the broker](http://docs.cloudfoundry.org/services/managing-service-brokers.html#register-broker).

    ```bash
    $ cf create-service-broker cdn-route [username] [password] [app-url] --space-scoped
    ```

## Usage

1. Target the space your application is running in.

    ```bash
    $ cf target -o <org> -s <space>
    ```

1. Add your domain to your Cloud Foundry organization:

    ````bash
    $ cf create-domain <org> my.domain.gov
    ```

1. Create a service instance.

    ```bash
    $ cf create-service cdn-route cdn-route my-cdn-route -c '{"domain": "my.domain.gov"}'

    Create in progress. Use 'cf services' or 'cf service my-cdn-route' to check operation status.
    ```

    If you have more than one domain you can pass a comma-delimited list to the `domain` parameter, just keep in mind that the broker will wait until all domains are CNAME'd:

    ```bash
    $ cf create-service cdn-route cdn-route my-cdn-route -c '{"domain": "my.domain.gov,www.my.domain.gov"}'

    Create in progress. Use 'cf services' or 'cf service my-cdn-route' to check operation status.
    ```

1. Get the DNS instructions.

    ```bash
    $ cf service my-cdn-route

    Last Operation
    Status: create in progress
    Message: Provisioning in progress; CNAME domain "my.domain.gov" to "d3kajwa62y9xrp.cloudfront.net."
    ```

1. Create/update your DNS configuration.

1. Wait up to 30 minutes for the CloudFront distribution to be provisioned and the DNS changes to propagate.

1. Visit `my.domain.gov`, and see that you have a valid certificate (i.e. that visiting your site in a modern browser doesn't give you a certificate warning).

1. Add your domain to a Cloud Foundry application:

    ```bash
    $ cf map-route <app> my.domain.gov
    ```

## Custom origins

If you are pointing your domain to a non-Cloud Foundry application, such as a public S3 bucket, you can pass a custom origin to the broker:

```bash
$ cf create-service cdn-route cdn-route my-cdn-route \
    -c '{"domain": "my.domain.gov", "origin": "my-app.apps.cloud.gov"}'

Create in progress. Use 'cf services' or 'cf service my-cdn-route' to check operation status.
```

If you need to add a path to your origin, you can pass it in as a parameter:

```bash
$ cf create-service cdn-route cdn-route my-cdn-route \
    -c '{"domain": "my.domain.gov", "origin": "my-app.apps.cloud.gov", "path": "/myfolder"}'

Create in progress. Use 'cf services' or 'cf service my-cdn-route' to check operation status.
```
    
If your origin is non-HTTPS, you'll need to add another parameter:

```bash
$ cf create-service cdn-route cdn-route my-cdn-route \
    -c '{"domain": "my.domain.gov", "origin": "my-app.apps.cloud.gov", "insecure_origin": true}'

Create in progress. Use 'cf services' or 'cf service my-cdn-route' to check operation status.
```

## Cookie Forwarding

If you do not want cookies forwarded to your origin, you'll need to add another parameter:

```bash
$ cf create-service cdn-route cdn-route my-cdn-route \
    -c '{"domain": "my.domain.gov", "cookies": false}'

Create in progress. Use 'cf services' or 'cf service my-cdn-route' to check operation status.
```

## Header Forwarding

CloudFront forwards a [limited set of headers](http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html#request-custom-headers-behavior) by default. If you want extra headers forwarded to your origin, you'll want to add another parameter. Here we forward both the `User-Agent` and `Referer` headers:

```bash
$ cf create-service cdn-route cdn-route my-cdn-route \
    -c '{"domain": "my.domain.gov", "headers": ["User-Agent", "Referer"]}'

Create in progress. Use 'cf services' or 'cf service my-cdn-route' to check operation status.
```

CloudFront can forward up to 10 custom headers. Because this broker automatically forwards the `Host` header when not using a [custom origin](#custom-origins), you can whitelist up to nin headers by default; if using a custom origin, you can whitelist up to 10 headers. If you want to exceed this limit or forward all headers, you can use a wildcard:

```bash
$ cf create-service cdn-route cdn-route my-cdn-route \
    -c '{"domain": "my.domain.gov", "headers": ["*"]}'

Create in progress. Use 'cf services' or 'cf service my-cdn-route' to check operation status.
```

When making requests to the origin, CloudFront's caching mechanism associates HTTP requests with their response. The more variation within the forwarded request, the fewer cache hits and the less effective the cache. Limiting the headers forwarded is therefore key to cache performance. Caching is disabled altogether when using a wildcard.

## Debugging

By default, Cloud Controller will expire asynchronous service instances that have been pending for over one week. If your instance expires, run a dummy update
to restore it to the pending state so that Cloud Controller will continue to check for updates:

```bash
cf update-service my-cdn-route -c '{"timestamp": 20161001}'
```

## Tests

```bash
go test -v $(go list ./... | grep -v /vendor/)
```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.
