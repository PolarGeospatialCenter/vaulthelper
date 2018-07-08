package vaulthelper

import (
	"fmt"

	vault "github.com/hashicorp/vault/api"
)

func NewClient(config *vault.Config) (*vault.Client, error) {
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to vault: %v", err)
	}

	token, err := NewDefaultChainProvider(client).RetrieveToken()
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}
