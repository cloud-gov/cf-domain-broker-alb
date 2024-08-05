package utils

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/xenolf/lego/acme"
)

type IamUtilsIface interface {
	UploadCertificate(name, path string, cert acme.CertificateResource) (string, string, error)
	DeleteCertificate(name string) error
	ListCertificates(path string, callback func(iam.ServerCertificateMetadata) bool) error
}

type IamUtils struct {
	Service iamiface.IAMAPI
}

func (i *IamUtils) UploadCertificate(name, path string, cert acme.CertificateResource) (string, string, error) {
	resp, err := i.Service.UploadServerCertificate(&iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(cert.Certificate)),
		PrivateKey:            aws.String(string(cert.PrivateKey)),
		ServerCertificateName: aws.String(name),
		Path:                  aws.String(path),
	})
	if err != nil {
		return "", "", err
	}

	return *resp.ServerCertificateMetadata.Arn, *resp.ServerCertificateMetadata.ServerCertificateName, nil
}

func (i *IamUtils) ListCertificates(path string, callback func(iam.ServerCertificateMetadata) bool) error {
	return i.Service.ListServerCertificatesPages(
		&iam.ListServerCertificatesInput{
			PathPrefix: aws.String(path),
		},
		func(page *iam.ListServerCertificatesOutput, lastPage bool) bool {
			for _, v := range page.ServerCertificateMetadataList {
				// stop iteration if the callback tells us to
				if callback(*v) == false {
					return false
				}
			}

			return true
		},
	)
}

func (i *IamUtils) DeleteCertificate(name string) error {
	_, err := i.Service.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
		ServerCertificateName: aws.String(name),
	})

	// If the certificate was already deleted, do not return an error
	if awsErr, ok := err.(awserr.Error); ok {
		if awsErr.Code() == "NoSuchEntity" {
			return nil
		}
	}

	return err
}
