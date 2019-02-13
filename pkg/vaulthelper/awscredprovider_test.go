package vaulthelper

import "testing"

func TestStsEndpoint(t *testing.T) {
	cases := []struct {
		name         string
		credProvider *VaultAwsStsCredentials
		expected     string
	}{
		{
			"default backend",
			&VaultAwsStsCredentials{
				VaultRole: "test-role",
			},
			"aws/sts/test-role",
		},
		{
			"custom backend",
			&VaultAwsStsCredentials{
				VaultRole:    "test-role",
				VaultBackend: "custom-aws",
			},
			"custom-aws/sts/test-role",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(st *testing.T) {
			ep := c.credProvider.stsEndpoint()
			if ep != c.expected {
				st.Errorf("Sts Endpoint didn't match expected: got %s, expected %s", ep, c.expected)
			}
		})
	}
}
