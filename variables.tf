variable "namespace" {
  type        = string
  default     = ""
  description = "A name of the existing namespace"
}

variable "namespace_name" {
  type        = string
  default     = "argocd"
  description = "A name of namespace for creating"
}

variable "kubeversion" {
  type        = string
  description = "A Kubernetes API version"
  default     = "1.18"
}

variable "chart_version" {
  type        = string
  description = "A Helm Chart version"
  default     = "3.33.5"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "A tags for attaching to new created AWS resources"
}

variable "conf" {
  type        = map(string)
  description = "A custom configuration for deployment"
  default     = {}
}

variable "sensitive_conf" {
  type        = any
  description = "A custom configuration with sensitive data for deployment"
  default     = {}
}

variable "repo_conf" {
  type        = string
  description = "A custom configuration for deployment"
  default     = ""
}

variable "branch" {
  type        = string
  default     = ""
  description = "A GitHub reference"
}

variable "repository" {
  type        = string
  default     = ""
  description = "A GitHub repository wich would be used for IaC needs"
}

variable "owner" {
  type        = string
  default     = ""
  description = "An owner of GitHub repository"
}

variable "cluster_name" {
  type        = string
  default     = null
  description = "A name of the Amazon EKS cluster"
}

variable "domains" {
  type        = list(string)
  default     = []
  description = "A list of domains to use for ingresses"
}

variable "vcs" {
  type        = string
  description = "An URI of VCS"
  default     = "https://github.com"
}

variable "path_prefix" {
  type        = string
  description = "A path inside a repository, it should contain a trailing slash"
}

variable "apps_dir" {
  type        = string
  description = "A folder for ArgoCD apps"
  default     = "apps"
}

variable "ingress_annotations" {
  type        = map(string)
  description = "A set of annotations for ArgoCD Ingress"
  default     = {}
}

variable "oidc" {
  type        = map(string)
  description = "A set of variables required for enabling OIDC"
  default = {
    pool   = null
    id     = null
    secret = null
  }
}

variable "project_name" {
  type        = string
  description = "A name of the ArgoCD project for deploying SAK"
  default     = "default"
}

variable "ssh_private_key" {
  type        = string
  description = "An SSH key for a private Repo from which to sync"
  default     = ""
}

variable "known_hosts" {
  type        = string
  description = "It will be used to construct a known_hosts file"
  default     = ""
}

variable "https_username" {
  type        = string
  description = "An HTTPS username for a private Repo from which to sync"
  default     = ""
}


variable "https_password" {
  type        = string
  description = "An HTTPS password (or token) for a private Repo from which to sync"
  default     = ""
}

variable "github_secret" {
  type        = string
  description = "A secret for GitHub Webhooks"
  default     = ""
}


variable "gitlab_secret" {
  type        = string
  description = "A secret for GitLab Webhooks"
  default     = ""
}


variable "bitbucket_server_secret" {
  type        = string
  description = "A secret for BitBucket Server Webhooks"
  default     = ""
}


variable "bitbucket_uuid" {
  type        = string
  description = "A secret for Bitbucket Webhooks"
  default     = ""
}


variable "gogs_secret" {
  type        = string
  description = "A secret for Gogs Webhooks"
  default     = ""
}
