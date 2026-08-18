# Grants, the fare engine, and its ingress rules.
#
# Every security-relevant value on this page is a variable reference. Read the
# source and you learn the shape of the platform; you do not learn who can reach
# it. Only the resolved plan knows that.

terraform {
  required_providers {
    democloud = {
      source  = "democloud.example/planless/democloud"
      version = "0.1.0"
    }
  }
}

resource "democloud_grant" "fare_exports_read" {
  id            = "grant-fare-exports-finance-read"
  resource_kind = "bucket"
  resource_name = var.export_bucket
  principals    = var.export_readers
  actions       = ["read"]
  source_ranges = var.export_reader_sources
}

resource "democloud_grant" "status_page_read" {
  id            = "grant-status-page-public-read"
  resource_kind = "bucket"
  resource_name = var.status_bucket
  principals    = var.status_readers
  actions       = ["read"]
  source_ranges = var.status_reader_sources
}

resource "democloud_workload" "fare_engine" {
  name    = var.workload_name
  address = var.workload_address

  ports {
    name   = "service"
    number = 8080
    bind   = var.service_bind
  }

  ports {
    name   = "admin"
    number = 8081
    bind   = var.admin_bind
  }
}

resource "democloud_network_rule" "fare_engine_service" {
  id            = "rule-fare-engine-service"
  workload      = democloud_workload.fare_engine.name
  port          = "service"
  source_ranges = var.service_source_ranges
}

resource "democloud_network_rule" "fare_engine_admin" {
  id            = "rule-fare-engine-admin"
  workload      = democloud_workload.fare_engine.name
  port          = "admin"
  source_ranges = var.admin_source_ranges
}
