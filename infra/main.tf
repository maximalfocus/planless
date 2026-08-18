# The Halloway platform, declared for the real infrastructure-as-code toolchain.
#
# Read this file the way a reviewer would: every resource block below is
# unremarkable. Two encrypted buckets, two objects, and a module call. Nothing
# here says who may read anything, or from where.
#
# That is the point. The security-relevant values live in a variable file and in
# the module's own defaults, so they exist only in the *resolved* desired state.

terraform {
  required_version = ">= 1.12.0"

  required_providers {
    democloud = {
      # A reserved .example hostname that cannot resolve, installed from a local
      # filesystem mirror. Initialization needs no network at all.
      source  = "democloud.example/planless/democloud"
      version = "0.1.0"
    }
  }
}

provider "democloud" {
  # Deliberately empty: the provider has no configurable endpoint, region,
  # account or credential of any kind.
}

resource "democloud_bucket" "fare_exports" {
  name               = "fare-exports"
  encrypted          = true
  log_retention_days = var.log_retention_days
}

resource "democloud_bucket" "status_page" {
  name               = "status-page"
  encrypted          = true
  log_retention_days = var.log_retention_days
}

resource "democloud_bucket" "status_assets" {
  name               = "status-assets"
  encrypted          = true
  log_retention_days = var.log_retention_days
}

resource "democloud_object" "refund_export" {
  bucket         = democloud_bucket.fare_exports.name
  key            = "rider-refunds-2026-03.csv"
  content_type   = "text/csv"
  content_base64 = filebase64("${path.root}/data/rider-refunds-2026-03.csv")
}

resource "democloud_object" "status" {
  bucket         = democloud_bucket.status_page.name
  key            = "status.json"
  content_type   = "application/json"
  content_base64 = filebase64("${path.root}/data/status.json")
}

resource "democloud_object" "assets" {
  bucket         = democloud_bucket.status_assets.name
  key            = "assets.json"
  content_type   = "application/json"
  content_base64 = filebase64("${path.root}/data/assets.json")
}

module "platform" {
  source = "./modules/platform"

  export_bucket = democloud_bucket.fare_exports.name
  status_bucket = democloud_bucket.status_page.name
  assets_bucket = democloud_bucket.status_assets.name

  export_readers        = var.export_readers
  export_reader_sources = var.export_reader_sources
  status_readers        = var.status_readers
  status_reader_sources = var.status_reader_sources
  assets_readers        = var.assets_readers
  assets_reader_sources = var.assets_reader_sources

  # The fare engine's ingress ranges and bind addresses are not passed here.
  # They resolve from the module's own defaults.
}
