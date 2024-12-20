package security.authentication

default allow = false

# Policy logic: Allow if the token is valid
allow {
    input.token.payload.exp > input.now  # Compare expiration with 'now' passed in input
    input.token.payload.sub != ""        # Subject field must exist
}