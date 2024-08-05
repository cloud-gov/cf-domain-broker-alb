package utils

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

type mockIAM struct {
	iamiface.IAMAPI
}

func (m mockIAM) DeleteServerCertificate(*iam.DeleteServerCertificateInput) (*iam.DeleteServerCertificateOutput, error) {
	// Only need to return mocked response output
	return nil, nil
}

func TestDeleteCertificate(t *testing.T) {
	iamUtils := &IamUtils{
		Service: &mockIAM{},
	}

	err := iamUtils.DeleteCertificate("fake-cert")
	if err != nil {
		t.Error(err)
	}
}
