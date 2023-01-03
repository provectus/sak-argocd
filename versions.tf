terraform {
  required_version = ">= 0.15"

  required_providers {
    aws        = ">= 4.0"
    helm       = ">= 2.0"
    kubernetes = ">= 2.0"
    random     = ">= 3.1.0"
    local      = ">=2.1.0"
  }
}
