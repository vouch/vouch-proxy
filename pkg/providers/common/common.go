/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package common

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

var log *zap.SugaredLogger

// Configure see main.go configure()
func Configure() {
	log = cfg.Logging.Logger
}

// PrepareTokensAndClient setup the client, usually for a UserInfo request
func PrepareTokensAndClient(r *http.Request, ptokens *structs.PTokens, setProviderToken bool, opts ...oauth2.AuthCodeOption) (*http.Client, *oauth2.Token, error) {
	sslClient := ClientWithCert(&http.Client{})
	ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, sslClient)
	providerToken, err := cfg.OAuthClient.Exchange(ctx, r.URL.Query().Get("code"), opts...)
	if err != nil {
		return nil, nil, err
	}
	ptokens.PAccessToken = providerToken.AccessToken

	if setProviderToken {
		if providerToken.Extra("id_token") != nil {
			// Certain providers (eg. gitea) don't provide an id_token
			// and it's not necessary for the authentication phase
			ptokens.PIdToken = providerToken.Extra("id_token").(string)
		} else {
			log.Debugf("id_token missing - may not be supported by this provider")
		}
	}

	log.Debugf("ptokens: accessToken length: %d, IdToken length: %d", len(ptokens.PAccessToken), len(ptokens.PIdToken))
	client := cfg.OAuthClient.Client(context.TODO(), providerToken)

	return ClientWithCert(client), providerToken, err
}

func ClientWithCert(client *http.Client) *http.Client {
	log.Debugf("ClientWithCert")
	certFile := cfg.Cfg.TLS.ClientCertFile
	keyFile := cfg.Cfg.TLS.ClientKeyFile
	if certFile == "" || keyFile == "" {
		log.Debugf("client ssl is null")
		return client
	}
	// 加载客户端证书
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Debugf("client ssl load error: %v", err)
		return client
	}

	// 给 Transport 注入 TLS，仅发送客户端证书
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// 给 Transport 注入 TLS
	switch tr := client.Transport.(type) {
	case *http.Transport:
		tr.TLSClientConfig = tlsConfig
	case *oauth2.Transport: // 如果是 oauth2.Transport 包装的
		if baseTr, ok := tr.Base.(*http.Transport); ok {
			baseTr.TLSClientConfig = tlsConfig
		} else {
			tr.Base = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
		}
	default:
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	log.Debugf("ClientWithCert success")
	return client
}

// MapClaims populate CustomClaims from userInfo for each configure claims header
func MapClaims(claims []byte, customClaims *structs.CustomClaims) error {
	var f interface{}
	err := json.Unmarshal(claims, &f)
	if err != nil {
		log.Error("Error unmarshaling claims")
		return err
	}
	m := f.(map[string]interface{})
	for k := range m {
		var found = false
		for claim := range cfg.Cfg.Headers.ClaimsCleaned {
			if k == claim {
				found = true
			}
		}
		if !found {
			delete(m, k)
		}
	}
	customClaims.Claims = m
	return nil
}
