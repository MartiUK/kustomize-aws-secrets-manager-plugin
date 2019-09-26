package main

import (
	"encoding/json"
	"fmt"

	"sigs.k8s.io/kustomize/v3/pkg/ifc"
	"sigs.k8s.io/kustomize/v3/pkg/resmap"
	"sigs.k8s.io/kustomize/v3/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type plugin struct {
	rf                 *resmap.Factory
	ldr                ifc.Loader
	Name               string   `json:"name,omitempty" yaml:"name,omitempty"`
	Namespace          string   `json:"namespace,omitempty" yaml:"name,omitempty"`
	Secret             string   `json:"secret,omitempty" yaml:"secret,omitempty"`
	Plaintext          bool     `json:"plaintext,omitempty" yaml:"plaintext,omitempty"`
	Keys               []string `json:"keys,omitempty" yaml:"keys,omitempty"`
	AwsRegion          string   `json:"aws_region,omitempty" yaml:"aws_region,omitempty"`
	AwsAccessKeyID     string   `json:"aws_access_key_id,omitempty" yaml:"aws_access_key_id,omitempty"`
	AwsSecretAccessKey string   `json:"aws_secret_access_key,omitempty" yaml:"aws_secret_access_key,omitempty"`
	AwsSessionToken    string   `json:"aws_session_token,omitempty" yaml:"aws_session_token,omitempty"`
}

//noinspection GoUnusedGlobalVariable
var SMPlugin plugin

func (p *plugin) Config(ldr ifc.Loader, rf *resmap.Factory, c []byte) error {
	p.rf = rf
	p.ldr = ldr
	return yaml.Unmarshal(c, p)
}

func (p *plugin) Generate() (resmap.ResMap, error) {
	secrets, err := p.loadSecretsFromSM()
	if err != nil {
		return nil, err
	}
	return p.makeK8sSecret(secrets)
}

func (p *plugin) loadSecretsFromSM() (secrets map[string]string, err error) {
	cfg := &aws.Config{}

	if p.Secret == "" {
		return nil, fmt.Errorf("secret name is required")
	}

	if p.AwsRegion != "" {
		cfg.Region = aws.String(p.AwsRegion)
	}

	if p.AwsAccessKeyID != "" && p.AwsSecretAccessKey != "" {
		staticCredentials := credentials.NewStaticCredentials(p.AwsAccessKeyID, p.AwsSecretAccessKey, p.AwsSessionToken)
		cfg.WithCredentials(staticCredentials)
	}

	sess, err := session.NewSession(cfg)
	if err != nil {
		return nil, err
	}

	svc := secretsmanager.New(sess)

	input := &secretsmanager.GetSecretValueInput{
		SecretId: &p.Secret,
	}

	resp, err := svc.GetSecretValue(input)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(sanitize(resp.SecretString)), &secrets)
	if err != nil {
		fmt.Printf("unable to unmarshal secret, assuming simple format")
		secrets[p.Secret] = sanitize(resp.SecretString)
	}

	return secrets, nil
}

func sanitize(v *string) string {
	return aws.StringValue(v)
}

func (p *plugin) makeK8sSecret(secrets map[string]string) (resmap.ResMap, error) {
	args := types.SecretArgs{}
	args.Name = p.Name
	args.Namespace = p.Namespace
	for _, k := range p.Keys {
		if v, ok := secrets[k]; ok {
			args.LiteralSources = append(args.LiteralSources, k+"="+v)
		}
	}
	return p.rf.FromSecretArgs(p.ldr, nil, args)
}
