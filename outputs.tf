output "state" {
  description = "A set of values that required for other modules in case of enabling ArgoCD"
  value = local.enabled ? {
    repository = local.repo_url
    branch     = var.branch
    namespace  = local.namespace
    path       = var.apps_dir
    full_path  = "${var.path_prefix}${var.apps_dir}"
    kms_key_id = coalesce(one(aws_kms_key.this[*].key_id), null)
    project    = "default"
  } : {}
}
