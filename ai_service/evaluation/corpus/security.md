# Management trust

Engine management uses authenticated HTTPS and explicit certificate enrollment. Validate the server certificate identity and refuse redirects. Possession of a management bearer token can authorize administrative operations; it is not a read-only credential scope. Keep authentication material out of diagnostic tools and application logs.
