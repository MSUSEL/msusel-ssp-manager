control 'access-control-policy' do
  impact 1.0
  title 'Validate Role-Based Access Control (RBAC)'
  desc 'Ensure that role-based access control is properly enforced (AC-2, AC-3)'

  # Use mock-server hostname when running in Docker container, localhost otherwise
  app_url = ENV['MOCK_SERVER_URL'] || 'http://mock-server:8000'
  log_file_path = '/shared/logs/opa_interactions.log'

  # Test case 1: Regular user accessing allowed resource
  describe 'Regular user accessing user profile' do
    # Simulate login as regular user
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { username: 'regular_user', password: 'SecurePassword123' }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Try to access user profile (should be allowed)
    profile_response = http("#{app_url}/user_profile",
                            method: 'GET',
                            headers: { 'Authorization' => "Bearer #{token}" })

    it 'should allow access to user profile' do
      expect(profile_response.status).to eq(200)
      expect(JSON.parse(profile_response.body)['allowed']).to eq(true)
    end
  end

  # Test case 2: Regular user accessing admin resource
  describe 'Regular user accessing admin panel' do
    # Simulate login as regular user
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { username: 'regular_user', password: 'SecurePassword123' }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Try to access admin panel (should be denied)
    admin_response = http("#{app_url}/admin_panel",
                          method: 'GET',
                          headers: { 'Authorization' => "Bearer #{token}" })

    it 'should deny access to admin panel' do
      expect(admin_response.status).to eq(403)
      expect(JSON.parse(admin_response.body)['allowed']).to eq(false)
    end
  end

  # Test case 3: Admin user accessing admin resource
  describe 'Admin user accessing admin panel' do
    # Simulate login as admin user
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { username: 'admin_user', password: 'AdminSecurePass456' }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Try to access admin panel (should be allowed)
    admin_response = http("#{app_url}/admin_panel",
                          method: 'GET',
                          headers: { 'Authorization' => "Bearer #{token}" })

    it 'should allow admin access to admin panel' do
      expect(admin_response.status).to eq(200)
      expect(JSON.parse(admin_response.body)['allowed']).to eq(true)
    end
  end

  # Test case 4: Access outside business hours
  describe 'Regular user accessing resources outside business hours' do
    # Simulate login as regular user
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { username: 'regular_user', password: 'SecurePassword123' }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Try to access resource outside business hours (should be denied)
    # Note: This test assumes the server can simulate different times or the test is run outside business hours
    after_hours_response = http("#{app_url}/user_profile?simulate_time=20:00:00",
                                method: 'GET',
                                headers: { 'Authorization' => "Bearer #{token}" })

    it 'should deny access outside business hours for regular users' do
      expect(after_hours_response.status).to eq(403)
      expect(JSON.parse(after_hours_response.body)['allowed']).to eq(false)
      expect(JSON.parse(after_hours_response.body)['reason']).to include('outside business hours')
    end
  end

  # Validate OPA logs for access control decisions
  describe file(log_file_path) do
    its('content') { should include 'access_control' }
    its('content') { should include 'allow_access' }
    its('content') { should include 'deny_access' }
  end
end
