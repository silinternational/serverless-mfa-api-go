
terraform {
  required_version = ">= 1.0"
  required_providers {

    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0.0, < 6.0.0"
    }

    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 2.0.0, < 4.39.0"
    }

    template = {
      source  = "hashicorp/template"
      version = "~> 2.2"
    }
  }
}
