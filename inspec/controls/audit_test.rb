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

    audit_log_content = file(audit_log_path).content
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
    latest_entry = audit_entries.last

    it 'should include "login" and "test_user" in the audit log' do
      unless audit_log_content.include?('login') && audit_log_content.include?('test_user')
        fail "Login event not found in audit log.\nExpected 'login' and 'test_user' in the log.\nLast lines:\n#{audit_log_content.lines.last(5).join}"
      end
    end

    it 'should include required audit fields' do
      missing_fields = %w[timestamp user_id event_type resource outcome ip_address auth_method].reject { |f| latest_entry.key?(f) }
      fail "Missing required fields: #{missing_fields.join(', ')}\nLatest entry: #{latest_entry}" unless missing_fields.empty?
    end
  end

  # Test case 2: Resource access auditing
  describe 'Resource access auditing' do
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'test_user', 
                            password: 'TestPassword123'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    http("#{app_url}/user_profile",
         method: 'GET',
         headers: { 'Authorization' => "Bearer #{token}" })

    audit_log_content = file(audit_log_path).content
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
    latest_entry = audit_entries.last

    it 'should log data access in the audit log' do
      unless audit_log_content.include?('data_access')
        fail "Expected 'data_access' in audit log but it was not found.\nLast lines:\n#{audit_log_content.lines.last(5).join}"
      end
    end

    it 'should include required fields' do
      missing_fields = %w[timestamp user_id event_type resource outcome].reject { |f| latest_entry.key?(f) }
      fail "Missing fields in resource access audit: #{missing_fields.join(', ')}\nLatest entry: #{latest_entry}" unless missing_fields.empty?
    end
  end

  # Test case 3: Configuration change auditing
  describe 'Configuration change auditing' do
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456',
                            mfa_code: '654321'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

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

    audit_log_content = file(audit_log_path).content
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
    latest_entry = audit_entries.last

    it 'should log configuration change in the audit log' do
      unless audit_log_content.include?('configuration_change')
        fail "Expected 'configuration_change' in audit log but not found.\nLast lines:\n#{audit_log_content.lines.last(5).join}"
      end
    end

    it 'should include all change tracking fields' do
      required_fields = %w[timestamp user_id event_type resource outcome old_value new_value]
      missing_fields = required_fields.reject { |f| latest_entry.key?(f) }
      fail "Missing fields in config change audit: #{missing_fields.join(', ')}\nLatest entry: #{latest_entry}" unless missing_fields.empty?
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

    audit_log_content = file(audit_log_path).content
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
    latest_entry = audit_entries.last

    it 'should record failed login in the audit log' do
      unless audit_log_content.include?('login') && audit_log_content.include?('failure')
        fail "Expected 'login' and 'failure' in audit log but they were missing.\nLast lines:\n#{audit_log_content.lines.last(5).join}"
      end
    end

    it 'should include outcome: failure in audit entry' do
      unless latest_entry['outcome'] == 'failure'
        fail "Expected 'outcome' to be 'failure' but got '#{latest_entry['outcome']}'\nEntry: #{latest_entry}"
      end
    end

    it 'should include required fields for failed login' do
      required_fields = %w[timestamp user_id event_type outcome]
      missing_fields = required_fields.reject { |f| latest_entry.key?(f) }
      fail "Missing fields in failed login audit: #{missing_fields.join(', ')}\nEntry: #{latest_entry}" unless missing_fields.empty?
    end
  end

  # Test case 5: Validate OPA logs contain audit-relevant decisions
  describe 'OPA interaction log should include audit keywords' do
    opa_log_content = file(log_file_path).content

    %w[audit should_audit audit_record_valid flag_for_review].each do |keyword|
      it "should contain '#{keyword}'" do
        unless opa_log_content.include?(keyword)
          fail "Expected keyword '#{keyword}' not found in OPA log.\nLast lines:\n#{opa_log_content.lines.last(5).join}"
        end
      end
    end
  end
end

