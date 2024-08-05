package utils

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

type mockIAM struct {
	iamiface.IAMAPI
	deleteCertificateErr error
}

func (m mockIAM) DeleteServerCertificate(*iam.DeleteServerCertificateInput) (*iam.DeleteServerCertificateOutput, error) {
	if m.deleteCertificateErr != nil {
		return nil, m.deleteCertificateErr
	}
	return nil, nil
}

func TestDeleteCertificate(t *testing.T) {
	deleteCertificateErr := errors.New("error deleting certificate")
	noSuchEntityErr := awserr.New("NoSuchEntity", "user does not exist", errors.New("original error"))

	testCases := map[string]struct {
		iamUtils    *IamUtils
		expectedErr error
	}{
		"no error": {
			iamUtils: &IamUtils{
				Service: &mockIAM{},
			},
		},
		"should error": {
			iamUtils: &IamUtils{
				Service: &mockIAM{
					deleteCertificateErr: deleteCertificateErr,
				},
			},
			expectedErr: deleteCertificateErr,
		},
		"no error for NoSuchEntity": {
			iamUtils: &IamUtils{
				Service: &mockIAM{
					deleteCertificateErr: noSuchEntityErr,
				},
			},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			err := test.iamUtils.DeleteCertificate("fake-cert")
			if !errors.Is(err, test.expectedErr) {
				t.Errorf("expected error: %s, got: %s", test.expectedErr, err)
			}
		})
	}
}
