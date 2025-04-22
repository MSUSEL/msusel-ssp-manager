control 'role_based_access_control' do
  impact 1.0
  title 'Validate role-based access control'
  desc 'Ensure that role-based access control is properly enforced'

  app_login_url = 'http://localhost:8000/login'
  app_admin_url = 'http://localhost:8000/admin'
  log_file_path = './logs/opa_interactions.log'

  # Login as regular user
  login_response = http(app_login_url,
                        method: 'POST',
                        headers: { 'Content-Type' => 'application/json' },
                        data: { username: 'testuser', password: 'SecurePassword123' }.to_json)

  token = JSON.parse(login_response.body)['access_token']

  # Try to access admin route with regular user token
  admin_response = http(app_admin_url,
                        method: 'GET',
                        headers: { 'Authorization' => "Bearer #{token}" })

  describe admin_response do
    its('status') { should cmp 403 }  # Should be forbidden
    its('body') { should include 'Admin access required' }
  end

  # Validate OPA logs for admin access attempt
  describe file(log_file_path) do
    its('content') { should include 'access_denied' }
  end
end