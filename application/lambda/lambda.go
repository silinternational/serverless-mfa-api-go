package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
	"github.com/silinternational/serverless-mfa-api-go/actions"
	"github.com/silinternational/serverless-mfa-api-go/domain"
)

var ginLambda *ginadapter.GinLambda

func init() {
	domain.Init()

	app := actions.App()
	ginLambda = ginadapter.New(app)
}

func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return ginLambda.ProxyWithContext(ctx, req)
}

func main() {
	lambda.Start(Handler)
}
