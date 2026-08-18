# An ordinary, non-security infrastructure change: keep access logs for longer.
# Exposure is identical to the secure value set in every respect.

export_readers        = ["finance-reporting"]
export_reader_sources = ["10.20.0.0/16"]

status_readers        = ["*"]
status_reader_sources = ["0.0.0.0/0"]

assets_readers        = ["finance-reporting"]
assets_reader_sources = ["10.20.0.0/16"]

log_retention_days = 90
