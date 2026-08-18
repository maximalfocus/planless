# The secure value set. Everything security-relevant about the storage grants is
# decided here, in a file no resource block references by value.

export_readers        = ["finance-reporting"]
export_reader_sources = ["10.20.0.0/16"]

# The status page is deliberately, reviewably public. It is the demonstration's
# proof that the fix is not "nothing may be public".
status_readers        = ["*"]
status_reader_sources = ["0.0.0.0/0"]

# The second status asset is not published: finance reads it from the corporate
# segment while it is being prepared.
assets_readers        = ["finance-reporting"]
assets_reader_sources = ["10.20.0.0/16"]
