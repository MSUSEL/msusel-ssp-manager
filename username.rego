package security.authentication

import rego.v1

default allow_authentication := false  # Rename to make it specific

# Policy logic: Allow if the token is valid. Note that it is named differently from previous policy.
# Can't have two defult allow.
allow_authentication if {
  input.token.payload.exp > input.now # Compare expiration with 'now' passed in input
  valid_username(input.token.payload.sub) # Validate the username
}

# Function to validate the username
# The username must be between 5 and 20 characters long.
# It must contain only alphanumeric characters, dots (.), underscores (_), and hyphens (-).
valid_username(username) if {
	length := count(username)
	length >= 5 # Minimum length requirement
	length <= 20 # Maximum length requirement
	regex.match(`^[a-zA-Z0-9._-]+$`, username) # Use raw string for regex
}
