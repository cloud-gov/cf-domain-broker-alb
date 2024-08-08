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
	getCertificateError     error
	deleteCertificateErr    error
	deleteCertificateCalled bool
}

func (m mockIAM) GetServerCertificate(*iam.GetServerCertificateInput) (*iam.GetServerCertificateOutput, error) {
	if m.getCertificateError != nil {
		return nil, m.getCertificateError
	}
	return nil, nil
}

func (m mockIAM) DeleteServerCertificate(*iam.DeleteServerCertificateInput) (*iam.DeleteServerCertificateOutput, error) {
	m.deleteCertificateCalled = true
	if m.deleteCertificateErr != nil {
		return nil, m.deleteCertificateErr
	}
	return nil, nil
}

func TestDeleteCertificate(t *testing.T) {
	deleteCertificateErr := errors.New("error deleting certificate")
	getCertificateErr := errors.New("error getting certificate")
	noSuchEntityErr := awserr.New("NoSuchEntity", "user does not exist", errors.New("original error"))

	testCases := map[string]struct {
		iamUtils                      *IamUtils
		expectedErr                   error
		expectDeleteCertificateCalled bool
	}{
		"no error": {
			iamUtils: &IamUtils{
				Service: &mockIAM{},
			},
		},
		"unexpected get error should not be returned": {
			iamUtils: &IamUtils{
				Service: &mockIAM{
					getCertificateError: getCertificateErr,
				},
			},
		},
		"NoSuchEntity get error should not be returned": {
			iamUtils: &IamUtils{
				Service: &mockIAM{
					getCertificateError: noSuchEntityErr,
				},
			},
		},
		"unexpected delete error should be returned": {
			iamUtils: &IamUtils{
				Service: &mockIAM{
					deleteCertificateErr: deleteCertificateErr,
				},
			},
			expectedErr:                   deleteCertificateErr,
			expectDeleteCertificateCalled: true,
		},
		"NoSuchEntity delete error should be ignored": {
			iamUtils: &IamUtils{
				Service: &mockIAM{
					deleteCertificateErr: noSuchEntityErr,
				},
			},
			expectDeleteCertificateCalled: true,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			err := test.iamUtils.DeleteCertificate("fake-cert")
			if !errors.Is(err, test.expectedErr) {
				t.Errorf("expected error: %s, got: %s", test.expectedErr, err)
			}

			if mockIamUtils, ok := test.iamUtils.Service.(*mockIAM); ok {
				if test.expectDeleteCertificateCalled != mockIamUtils.deleteCertificateCalled {
					t.Errorf("expected delete certificate called: %t, got: %t", test.expectDeleteCertificateCalled, mockIamUtils.deleteCertificateCalled)
				}
			}
		})
	}
}
