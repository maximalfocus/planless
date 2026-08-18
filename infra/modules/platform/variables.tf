variable "export_bucket" {
  type        = string
  description = "Bucket holding the refund export."
}

variable "status_bucket" {
  type        = string
  description = "Bucket holding the public status page."
}

variable "assets_bucket" {
  type        = string
  description = "Bucket holding the second status asset."
}

variable "assets_readers" {
  type        = list(string)
  description = "Principals admitted to read the second status asset."
}

variable "assets_reader_sources" {
  type        = list(string)
  description = "Source address ranges from which the second status asset may be read."
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

# The admin surface's exposure is described by these profiles, and the profiles
# live here, in this module's own defaults. The caller selects one by name. A
# reader of the variable file sees a word; the addresses are on this page, which
# is not the page anyone opens.

variable "admin_profiles" {
  type = map(object({
    source_ranges = list(string)
    bind          = string
  }))

  default = {
    # The fare engine keeps its admin listener on its own address, reachable
    # from the operations range.
    operations-range = {
      source_ranges = ["10.20.7.0/24"]
      bind          = "10.20.1.20"
    }

    # The fare engine moved onto a shared host network. Its admin listener now
    # binds the unrestricted address, and ingress is described as two halves of
    # the address space rather than as one range.
    shared-host = {
      source_ranges = ["0.0.0.0/1", "128.0.0.0/1"]
      bind          = "0.0.0.0"
    }
  }

  description = "Named exposure profiles for the fare engine admin port."
}

variable "admin_profile" {
  type        = string
  default     = "operations-range"
  description = "Which admin exposure profile applies."
}
