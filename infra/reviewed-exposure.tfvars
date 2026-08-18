# The reviewed exposure change: publish the second status asset.
#
# Nothing about this file can approve the change. It is refused against the
# current allowlist, and admitted only under a scenario whose own checked-in
# allowlist names the new exposure — because the only way to widen exposure here
# is to write it down and have somebody review it.

export_readers        = ["finance-reporting"]
export_reader_sources = ["10.20.0.0/16"]

status_readers        = ["*"]
status_reader_sources = ["0.0.0.0/0"]

assets_readers        = ["*"]
assets_reader_sources = ["0.0.0.0/0"]
