terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  cloud {
    organization = "OrdinalScale"
    workspaces {
      name = "meshgate-aws"
    }
  }
}

provider "aws" {
  region = "us-east-2"
} 