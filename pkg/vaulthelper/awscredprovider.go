package vaulthelper

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"

	vault "github.com/hashicorp/vault/api"
)

type VaultAwsStsCredentials struct {
	VaultClient *vault.Client
	VaultRole   string
	creds       *credentials.Value
	expiresAt   time.Time
}

func (v *VaultAwsStsCredentials) Retrieve() (credentials.Value, error) {
	if v.creds != nil && !v.IsExpired() {
		return *v.creds, nil
	}
	creds := credentials.Value{}

	secret, err := v.VaultClient.Logical().Write(fmt.Sprintf("aws/sts/%s", v.VaultRole), map[string]interface{}{})
	if err != nil {
		return creds, fmt.Errorf("unable to get sts token using vault role: %v", err)
	}

	creds.ProviderName = fmt.Sprintf("vault-sts-%s", v.VaultRole)
	creds.AccessKeyID = secret.Data["access_key"].(string)
	creds.SecretAccessKey = secret.Data["secret_key"].(string)
	creds.SessionToken = secret.Data["security_token"].(string)

	v.expiresAt = time.Now().Add(time.Second * time.Duration(secret.LeaseDuration))
	v.creds = &creds
	return creds, nil
}

func (v *VaultAwsStsCredentials) IsExpired() bool {
	return time.Now().Unix() < v.expiresAt.Unix()
}
