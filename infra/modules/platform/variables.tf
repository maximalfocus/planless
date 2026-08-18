variable "export_bucket" {
  type        = string
  description = "Bucket holding the refund export."
}

variable "status_bucket" {
  type        = string
  description = "Bucket holding the public status page."
}

variable "export_readers" {
  type        = list(string)
  description = "Principals admitted to read the refund export."
}

variable "export_reader_sources" {
  type        = list(string)
  description = "Source address ranges from which the refund export may be read."
}

variable "status_readers" {
  type        = list(string)
  description = "Principals admitted to read the status page."
}

variable "status_reader_sources" {
  type        = list(string)
  description = "Source address ranges from which the status page may be read."
}

variable "workload_name" {
  type        = string
  default     = "fare-engine"
  description = "Name of the fare engine workload."
}

variable "workload_address" {
  type        = string
  default     = "10.20.1.20"
  description = "Address the fare engine runs on."
}

# The ingress ranges and bind addresses below are module defaults. The root
# module never passes them, so they appear in no resource block and in no
# variable file — they exist only in the resolved desired state.

variable "service_source_ranges" {
  type        = list(string)
  default     = ["10.20.0.0/16"]
  description = "Source address ranges permitted to reach the fare engine service port."
}

variable "service_bind" {
  type        = string
  default     = "10.20.1.20"
  description = "Address the fare engine service listener binds."
}

variable "admin_source_ranges" {
  type        = list(string)
  default     = ["10.20.7.0/24"]
  description = "Source address ranges permitted to reach the fare engine admin port."
}

variable "admin_bind" {
  type        = string
  default     = "10.20.1.20"
  description = "Address the fare engine admin listener binds."
}
