terraform {
  required_version = ">= 1.9.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.10"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.6"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.5"
    }
  }
}
