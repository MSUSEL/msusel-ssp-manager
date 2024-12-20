package security.authentication

# Test Case 1: Valid token
test_valid_token {
    input := {
        "token": {"payload": {"sub": "testuser", "exp": 1702722300}},
        "now": 1702722000  # Mock the current time
    }
    result := allow with input as input
    result == true
}

# Test Case 2: Expired token
test_expired_token {
    input := {
        "token": {"payload": {"sub": "testuser", "exp": 12345678}},
        "now": 1702722000  # Mock the current time
    }
    result := allow with input as input
    result == false
}
