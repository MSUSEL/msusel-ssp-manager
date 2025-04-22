control 'session-crypto-policy' do
  impact 1.0
  title 'Validate Session and Cryptographic Controls'
  desc 'Ensure that session authenticity and cryptographic protections are properly enforced (SC-23, SC-12, SC-13)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'

  # Test case 1: Valid session token
  describe 'Valid session token' do
    # First login to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'test_user', 
                            password: 'TestPassword123'
                          }.to_json)
    
    token = JSON.parse(login_response.body)['access_token']
    
    # Validate session
    session_response = http("#{app_url}/validate_session",
                            method: 'POST',
                            headers: { 
                              'Content-Type' => 'application/json',
                              'Authorization' => "Bearer #{token}"
                            },
                            data: {}.to_json)

    it 'should validate active session' do
      expect(session_response.status).to eq(200)
      expect(JSON.parse(session_response.body)['valid']).to eq(true)
    end
  end

  # Test case 2: Inactive session timeout
  describe 'Inactive session timeout' do
    # First login to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'test_user', 
                            password: 'TestPassword123'
                          }.to_json)
    
    token = JSON.parse(login_response.body)['access_token']
    
    # Validate session with simulated inactivity
    session_response = http("#{app_url}/validate_session?simulate_inactivity=1800",
                            method: 'POST',
                            headers: { 
                              'Content-Type' => 'application/json',
                              'Authorization' => "Bearer #{token}"
                            },
                            data: {}.to_json)

    it 'should invalidate inactive session' do
      expect(session_response.status).to eq(401)
      expect(JSON.parse(session_response.body)['valid']).to eq(false)
      expect(JSON.parse(session_response.body)['reason']).to include('inactive')
    end
  end

  # Test case 3: Revoked session token
  describe 'Revoked session token' do
    # Use a token that is known to be revoked
    revoked_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.revoked1'
    
    # Validate session
    session_response = http("#{app_url}/validate_session",
                            method: 'POST',
                            headers: { 
                              'Content-Type' => 'application/json',
                              'Authorization' => "Bearer #{revoked_token}"
                            },
                            data: {}.to_json)

    it 'should reject revoked token' do
      expect(session_response.status).to eq(401)
      expect(JSON.parse(session_response.body)['valid']).to eq(false)
      expect(JSON.parse(session_response.body)['reason']).to include('revoked')
    end
  end

  # Test case 4: TLS version check
  describe 'TLS version validation' do
    # Check TLS version of the server
    tls_response = http("#{app_url}/tls_info",
                        method: 'GET',
                        headers: { 'Content-Type' => 'application/json' })

    it 'should use TLS 1.2 or higher' do
      tls_version = JSON.parse(tls_response.body)['tls_version']
      expect(['TLS 1.2', 'TLS 1.3']).to include(tls_version)
    end
  end

  # Test case 5: Cipher suite check
  describe 'Cipher suite validation' do
    # Check cipher suite of the server
    cipher_response = http("#{app_url}/tls_info",
                           method: 'GET',
                           headers: { 'Content-Type' => 'application/json' })

    it 'should use approved cipher suites' do
      cipher_suite = JSON.parse(cipher_response.body)['cipher_suite']
      approved_ciphers = [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
      ]
      expect(approved_ciphers).to include(cipher_suite)
    end
  end

  # Test case 6: Encryption at rest
  describe 'Encryption at rest' do
    # Check encryption configuration
    encryption_response = http("#{app_url}/storage_info",
                               method: 'GET',
                               headers: { 'Content-Type' => 'application/json' })

    it 'should use AES-256 for encryption at rest' do
      encryption_algorithm = JSON.parse(encryption_response.body)['encryption_algorithm']
      expect(encryption_algorithm).to eq('AES-256')
    end

    it 'should use enterprise key management' do
      key_management = JSON.parse(encryption_response.body)['key_management']
      expect(key_management).to eq('enterprise_kms')
    end
  end

  # Validate OPA logs for session and crypto decisions
  describe file(log_file_path) do
    its('content') { should include 'session_crypto' }
    its('content') { should include 'session_token_valid' }
    its('content') { should include 'tls_version_acceptable' }
    its('content') { should include 'cipher_suite_acceptable' }
    its('content') { should include 'encryption_at_rest_valid' }
  end
end
