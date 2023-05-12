terraform {
  cloud {
    organization = "gtis"

    workspaces {
      tags = ["serverless-mfa-api-go"]
    }
  }
}
