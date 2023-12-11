package domain

import "github.com/kelseyhightower/envconfig"

const (
	UserContextKey  = "user"
	LegacyU2FCredID = "u2f"
)

func Init() {
	envconfig.MustProcess("", &Env)
	Env.setAWSConfig()
}
