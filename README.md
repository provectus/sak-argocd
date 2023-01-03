# ArgoCD
Module install ArgoCD application to Kubernetes cluster and optionally configure it to track changes of the repository. To read more about ArgoCD please follow to official [documentation](https://argoproj.github.io/argo-cd/).
ArgoCD helm chart used with terraform helm_release provider as deployment option.

## Example
Simple use-case without ingresses and authentication, for accessing ArgoCD UI need to configure port-forwarding.
``` hcl
module argocd {
  source        = "git::https://github.com/provectus/sak-argocd.git"

  branch        = "master"
  owner         = "test-github-onwer"
  repository    = "test-github-iac-repo-name"
  cluster_name  = "testing"
  path_prefix   = "path/for/tf/files/folder/in/repo/"
}
```

## Requirements

```
terraform >= 0.15
Kubernetes cluster version >= 1.22
 ```

For using this module with clusters <1.22, use following code inside module declaration:
```
source     = "github.com/provectus/sak-argocd.git?ref=v0.1.1"
```

## Providers

| Name | Version |
|------|---------|
| aws | >= 3.0 |
| helm | >= 1.0 |
| kubernetes | >= 1.11 |
| local | >=2.1.0 |
| random | >= 3.1.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:-----:|
| apps\_dir | A folder for ArgoCD apps | `string` | `"apps"` | no |
| branch | A GitHub reference | `string` | n/a | yes, in case of enabling native ArgoCD behaviour  |
| chart\_version | An ArgoCD Helm Chart version | `string` | `"2.7.4"` | no |
| cluster\_name | A name of the EKS cluster | `string` | n/a | yes |
| conf | A custom configuration for ArgoCD deployment | `map(string)` | `{}` | no |
| domains | A list of domains to use | `list(string)` | `[]` | no |
| ingress\_annotations | A set of annotations for ArgoCD Ingress | `map(string)` | `{}` | no |
| module\_depends\_on | A dependency list | `list(any)` | `[]` | no |
| namespace | A name of the existing namespace | `string` | `""` | no |
| namespace\_name | A name of namespace for creating | `string` | `"argocd"` | no |
| oidc | A set of variables required for enabling OIDC | `map(string)` | <pre>{<br>  "id": null,<br>  "pool": null,<br>  "secret": null<br>}</pre> | no |
| owner | An owner of GitHub repository | `string` | n/a | yes, in case of enabling native ArgoCD behaviour  |
| path\_prefix | A path inside a repository,if it redefined then should contain a trailing slash | `string` | n/a | yes, in case of enabling native ArgoCD behaviour |
| project\_name | A name of the ArgoCD project for deploying SAK | `string` | `"default"` | no |
| repository | A GitHub repository wich would be used for IaC needs | `string` | n/a | yes, in case of enabling native ArgoCD behaviour  |
| vcs | A host name of VCS | `string` | `"github.com"` | no |

## Outputs

| Name | Description |
|------|-------------|
| state | A set of values that required for other modules in case of enabling ArgoCD |
