# These have no defaults on purpose: their values arrive from a variable file,
# and therefore appear nowhere in any resource block.

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

variable "assets_readers" {
  type        = list(string)
  description = "Principals admitted to read the second status asset."
}

variable "assets_reader_sources" {
  type        = list(string)
  description = "Source address ranges from which the second status asset may be read."
}

# An ordinary operational setting with no security meaning at all. It is here to
# show that a routine change passes the gate untouched.
variable "log_retention_days" {
  type        = number
  default     = 30
  description = "How long bucket access logs are kept."
}

variable "admin_profile" {
  type        = string
  default     = "operations-range"
  description = "Which of the module's admin exposure profiles applies."
}
