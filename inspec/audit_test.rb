control 'audit-policy' do
  impact 1.0
  title 'Validate Audit Controls'
  desc 'Ensure that audit events are properly captured and formatted (AU-2, AU-3, AU-6)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'
  audit_log_path = './logs/audit.log'

  # Test case 1: Login event auditing
  describe 'Login event auditing' do
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'test_user', 
                            password: 'TestPassword123'
                          }.to_json)

    it 'should generate audit record for login' do
      # Check if audit log contains the login event
      audit_log_content = file(audit_log_path).content
      expect(audit_log_content).to include('login')
      expect(audit_log_content).to include('test_user')
      
      # Parse the latest audit entry
      audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
      latest_entry = audit_entries.last
      
      # Verify required fields
      expect(latest_entry).to include('timestamp')
      expect(latest_entry).to include('user_id')
      expect(latest_entry).to include('event_type')
      expect(latest_entry).to include('resource')
      expect(latest_entry).to include('outcome')
      expect(latest_entry).to include('ip_address')
      expect(latest_entry).to include('auth_method')
    end
  end

  # Test case 2: Resource access auditing
  describe 'Resource access auditing' do
    # First login to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'test_user', 
                            password: 'TestPassword123'
                          }.to_json)
    
    token = JSON.parse(login_response.body)['access_token']
    
    # Access a resource
    http("#{app_url}/user_profile",
         method: 'GET',
         headers: { 'Authorization' => "Bearer #{token}" })

    it 'should generate audit record for resource access' do
      # Check if audit log contains the resource access event
      audit_log_content = file(audit_log_path).content
      expect(audit_log_content).to include('data_access')
      
      # Parse the latest audit entry
      audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
      latest_entry = audit_entries.last
      
      # Verify required fields
      expect(latest_entry).to include('timestamp')
      expect(latest_entry).to include('user_id')
      expect(latest_entry).to include('event_type')
      expect(latest_entry).to include('resource')
      expect(latest_entry).to include('outcome')
    end
  end

  # Test case 3: Configuration change auditing
  describe 'Configuration change auditing' do
    # First login as admin to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456',
                            mfa_code: '654321'
                          }.to_json)
    
    token = JSON.parse(login_response.body)['access_token']
    
    # Make a configuration change
    http("#{app_url}/system_settings",
         method: 'POST',
         headers: { 
           'Authorization' => "Bearer #{token}",
           'Content-Type' => 'application/json'
         },
         data: {
           setting_name: 'max_users',
           old_value: 100,
           new_value: 200
         }.to_json)

    it 'should generate audit record for configuration change' do
      # Check if audit log contains the configuration change event
      audit_log_content = file(audit_log_path).content
      expect(audit_log_content).to include('configuration_change')
      
      # Parse the latest audit entry
      audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
      latest_entry = audit_entries.last
      
      # Verify required fields
      expect(latest_entry).to include('timestamp')
      expect(latest_entry).to include('user_id')
      expect(latest_entry).to include('event_type')
      expect(latest_entry).to include('resource')
      expect(latest_entry).to include('outcome')
      expect(latest_entry).to include('old_value')
      expect(latest_entry).to include('new_value')
    end
  end

  # Test case 4: Failed login auditing
  describe 'Failed login auditing' do
    http("#{app_url}/login",
         method: 'POST',
         headers: { 'Content-Type' => 'application/json' },
         data: { 
           username: 'test_user', 
           password: 'WrongPassword'
         }.to_json)

    it 'should generate audit record for failed login' do
      # Check if audit log contains the failed login event
      audit_log_content = file(audit_log_path).content
      expect(audit_log_content).to include('login')
      expect(audit_log_content).to include('failure')
      
      # Parse the latest audit entry
      audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
      latest_entry = audit_entries.last
      
      # Verify required fields
      expect(latest_entry).to include('timestamp')
      expect(latest_entry).to include('user_id')
      expect(latest_entry).to include('event_type')
      expect(latest_entry).to include('outcome')
      expect(latest_entry['outcome']).to eq('failure')
    end
  end

  # Validate OPA logs for audit decisions
  describe file(log_file_path) do
    its('content') { should include 'audit' }
    its('content') { should include 'should_audit' }
    its('content') { should include 'audit_record_valid' }
    its('content') { should include 'flag_for_review' }
  end
end
