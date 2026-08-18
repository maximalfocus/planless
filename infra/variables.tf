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
