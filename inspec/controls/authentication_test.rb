# Change the control ID to match what the frontend expects
control 'ia-2' do
  impact 1.0
  title 'Validate Authentication Controls'
  desc 'Ensure that identification and authentication controls are properly enforced (IA-2)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'

  # Test case 1: Regular user with valid credentials
  describe 'Regular user authentication' do
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'regular_user', 
                            password: 'SecurePassword123',
                            type: 'regular',
                            factors: 1
                          }.to_json)

    it 'should authenticate regular user with password' do
      expect(login_response.status).to eq(200)
      expect(JSON.parse(login_response.body)['authenticated']).to eq(true)
      expect(JSON.parse(login_response.body)).to include('access_token')
    end
  end

  # Test case 2: Staff user without MFA
  describe 'Staff user authentication without MFA' do
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'staff_user', 
                            password: 'StaffSecurePass789',
                            type: 'staff',
                            factors: 1
                          }.to_json)

    it 'should reject staff authentication without MFA' do
      expect(login_response.status).to eq(401)
      expect(JSON.parse(login_response.body)['authenticated']).to eq(false)
      expect(JSON.parse(login_response.body)['reason']).to include('MFA required')
    end
  end

  # Test case 3: Staff user with MFA
  describe 'Staff user authentication with MFA' do
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'staff_user', 
                            password: 'StaffSecurePass789',
                            mfa_code: '123456',
                            type: 'staff',
                            factors: 2
                          }.to_json)

    it 'should authenticate staff user with MFA' do
      expect(login_response.status).to eq(200)
      expect(JSON.parse(login_response.body)['authenticated']).to eq(true)
      expect(JSON.parse(login_response.body)).to include('access_token')
    end
  end

  # Test case 4: Admin user with MFA
  describe 'Admin user authentication with MFA' do
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456',
                            mfa_code: '654321',
                            type: 'admin',
                            factors: 2
                          }.to_json)

    it 'should authenticate admin user with MFA' do
      expect(login_response.status).to eq(200)
      expect(JSON.parse(login_response.body)['authenticated']).to eq(true)
      expect(JSON.parse(login_response.body)).to include('access_token')
    end
  end

  # Test case 5: Brute force detection
  describe 'Brute force detection' do
    # Simulate multiple failed login attempts
    5.times do
      http("#{app_url}/login",
           method: 'POST',
           headers: { 'Content-Type' => 'application/json' },
           data: { 
             username: 'target_user', 
             password: 'WrongPassword',
             type: 'regular',
             factors: 1
           }.to_json)
    end

    # Try one more login attempt
    final_attempt = http("#{app_url}/login",
                         method: 'POST',
                         headers: { 'Content-Type' => 'application/json' },
                         data: { 
                           username: 'target_user', 
                           password: 'WrongPasswordAgain',
                           type: 'regular',
                           factors: 1
                         }.to_json)

    it 'should detect brute force attempts' do
      expect(final_attempt.status).to eq(429)
      expect(JSON.parse(final_attempt.body)['authenticated']).to eq(false)
      expect(JSON.parse(final_attempt.body)['reason']).to include('too many failed attempts')
    end
  end

  # Test case 6: Expired token
  describe 'Expired token validation' do
    # Use a token that is known to be expired
    expired_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleHBpcmVkX3VzZXIiLCJleHAiOjE1MTYyMzkwMjIsImlhdCI6MTUxNjIzOTAyMn0.expired_signature'
    
    validate_response = http("#{app_url}/validate_token",
                             method: 'POST',
                             headers: { 'Content-Type' => 'application/json' },
                             data: { token: expired_token }.to_json)

    it 'should reject expired tokens' do
      expect(validate_response.status).to eq(401)
      expect(JSON.parse(validate_response.body)['valid']).to eq(false)
      expect(JSON.parse(validate_response.body)['reason']).to include('expired')
    end
  end

  # Validate OPA logs for authentication decisions
  describe file(log_file_path) do
    its('content') { should include 'authentication' }
    its('content') { should include 'authentication_valid' }
    its('content') { should include 'token_is_valid' }
    its('content') { should include 'mfa_used' }
  end
end
