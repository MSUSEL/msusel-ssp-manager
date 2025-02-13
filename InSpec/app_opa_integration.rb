control 'app_opa_integration' do
  impact 1.0
  title 'Validate app integration with OPA'
  desc 'Ensure the app logs in, queries OPA with correct data, and handles responses properly.'

  app_login_url = 'http://192.168.49.2:30534/login'
  app_protected_url = 'http://192.168.49.2:30534/protected'
  log_file_path = './logs/opa_interactions.log'

  # Debugging: Output log for the login request
  login_response = http(app_login_url,
                        method: 'POST',
                        headers: { 'Content-Type' => 'application/json' },
                        data: { username: 'testuser', password: 'SecurePassword123' }.to_json)

  puts "Login Response: #{login_response.body}"  # Debugging

  describe login_response do
    its('status') { should cmp 200 }
    its('body') { should include 'access_token' }
  end

  token = JSON.parse(login_response.body)['access_token']

  # Debugging: Output log for the protected route request
  protected_response = http(app_protected_url,
                             method: 'GET',
                             headers: { 'Authorization' => "Bearer #{token}" })

  puts "Protected Route Response: #{protected_response.body}"  # Debugging

  describe protected_response do
    its('status') { should cmp 200 }
    its('body') { should include 'Access granted' }
  end

  # Debugging: Check if the log file exists and output content
  if File.exist?(log_file_path)
    puts "Log file content:\n#{File.read(log_file_path)}"
  else
    puts "Log file not found: #{log_file_path}"
  end

  # Validate OPA logs
  describe file(log_file_path) do
    its('content') { should include '"sub":"testuser"' }
    its('content') { should include '"allow":true' }
  end
end
