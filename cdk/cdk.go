package main

import (
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsapigateway"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3assets"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

type CdkStackProps struct {
	awscdk.StackProps
}

func NewCdkStack(scope constructs.Construct, id string, props *CdkStackProps) awscdk.Stack {
	var sprops awscdk.StackProps
	if props != nil {
		sprops = props.StackProps
	}
	stack := awscdk.NewStack(scope, &id, &sprops)

	env := getEnv("ENVIRONMENT", "dev")
	apiKeyTable := getEnv("API_KEY_TABLE", "api-key")
	totpTable := getEnv("TOTP_TABLE", "totp")
	webauthnTable := getEnv("WEBAUTHN_TABLE", "webauthn")
	lambdaRoleArn := getEnv("LAMBDA_ROLE", "")
	if lambdaRoleArn == "" {
		panic("LAMBDA_ROLE environment variable must be set")
	}

	functionName := id

	logGroup := awslogs.NewLogGroup(stack, jsii.String("LogGroup"), &awslogs.LogGroupProps{
		LogGroupName:  jsii.String("/aws/lambda/" + functionName),
		Retention:     awslogs.RetentionDays_TWO_MONTHS,
		RemovalPolicy: awscdk.RemovalPolicy_RETAIN, // Retain logs when stack is deleted
	})

	role := awsiam.Role_FromRoleArn(stack, jsii.String("Role"), jsii.String(lambdaRoleArn), nil)

	function := awslambda.NewFunction(stack, jsii.String("Function"), &awslambda.FunctionProps{
		Code: awslambda.Code_FromAsset(jsii.String("../"), &awss3assets.AssetOptions{
			// include only the bootstrap file
			Exclude: jsii.Strings("**", "!bootstrap"),
		}),
		Environment: &map[string]*string{
			"API_KEY_TABLE":  jsii.String(apiKeyTable),
			"TOTP_TABLE":     jsii.String(totpTable),
			"WEBAUTHN_TABLE": jsii.String(webauthnTable),
		},
		FunctionName:  &functionName,
		Handler:       jsii.String("bootstrap"),
		LoggingFormat: awslambda.LoggingFormat_JSON,
		LogGroup:      logGroup,
		MemorySize:    jsii.Number(1024.0),
		Role:          role,
		Runtime:       awslambda.Runtime_PROVIDED_AL2023(),
		Timeout:       awscdk.Duration_Seconds(jsii.Number(5)),
	})

	api := awsapigateway.NewRestApi(stack, jsii.String("API"), &awsapigateway.RestApiProps{
		RestApiName: jsii.String(functionName),
		DeployOptions: &awsapigateway.StageOptions{
			StageName: jsii.String(env),
		},
	})

	proxy := api.Root().AddResource(jsii.String("{webauthn+}"), nil)
	proxy.AddMethod(jsii.String("ANY"), awsapigateway.NewLambdaIntegration(function,
		&awsapigateway.LambdaIntegrationOptions{AllowTestInvoke: jsii.Bool(false)}), nil)

	if sprops.Tags != nil {
		for k, v := range *sprops.Tags {
			awscdk.Tags_Of(stack).Add(jsii.String(k), v, nil)
		}
	}

	return stack
}

func main() {
	defer jsii.Close()

	app := awscdk.NewApp(nil)

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "dev"
	}

	NewCdkStack(app, "twosv-api-"+env, &CdkStackProps{
		awscdk.StackProps{
			Env: &awscdk.Environment{
				Region: jsii.String(os.Getenv("AWS_REGION")),
			},
			Tags: &map[string]*string{
				"managed_by":        jsii.String("cdk"),
				"itse_app_name":     jsii.String("twosv-api"),
				"itse_app_customer": jsii.String("shared"),
				"itse_app_env":      jsii.String(env),
			},
		},
	})

	app.Synth(nil)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
