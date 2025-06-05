control 'audit-content' do
  impact 1.0
  title 'Validate Audit Content Controls'
  desc 'Ensure that audit records include sufficient information to establish what events occurred, the sources of the events, and the outcomes of the events (AU-3)'

  app_url = 'http://mock-server:8000'
  log_file_path = '/logs/opa_interactions.log'
  audit_log_path = '/logs/audit.log'

  # Test case 1: Basic audit record content
  describe 'Basic audit record content' do
    # Generate some audit events by making requests
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: {
                            username: 'test_user',
                            password: 'TestPassword123'
                          }.to_json)

    audit_log_content = file(audit_log_path).content
    # Handle case where file content might be nil or empty
    if audit_log_content.nil? || audit_log_content.empty?
      fail "Audit log file is empty or not found at #{audit_log_path}"
    end
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact
    latest_entry = audit_entries.last

    it 'should include all basic required fields' do
      required_fields = %w[timestamp user_id event_type resource outcome]
      missing_fields = required_fields.reject { |f| latest_entry.key?(f) }
      fail "Missing basic required fields: #{missing_fields.join(', ')}\nLatest entry: #{latest_entry}" unless missing_fields.empty?
    end

    it 'should have timestamp in ISO 8601 format' do
      timestamp = latest_entry['timestamp']
      unless timestamp =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/
        fail "Timestamp '#{timestamp}' is not in ISO 8601 format"
      end
    end

    it 'should have a valid event type' do
      valid_event_types = %w[login logout access_denied admin_action configuration_change data_access data_modification system_event security_event network_event]
      unless valid_event_types.include?(latest_entry['event_type'])
        fail "Event type '#{latest_entry['event_type']}' is not valid. Valid types: #{valid_event_types.join(', ')}"
      end
    end

    it 'should have a valid outcome' do
      valid_outcomes = %w[success failure error unknown]
      unless valid_outcomes.include?(latest_entry['outcome'])
        fail "Outcome '#{latest_entry['outcome']}' is not valid. Valid outcomes: #{valid_outcomes.join(', ')}"
      end
    end
  end

  # Test case 2: Login event content
  describe 'Login event content' do
    # Generate a login event
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: {
                            username: 'test_user',
                            password: 'TestPassword123'
                          }.to_json)

    audit_log_content = file(audit_log_path).content
    # Handle case where file content might be nil or empty
    if audit_log_content.nil? || audit_log_content.empty?
      fail "Audit log file is empty or not found at #{audit_log_path}"
    end
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact

    # Find the login entry
    login_entry = audit_entries.find { |entry| entry['event_type'] == 'login' && entry['outcome'] == 'success' }

    it 'should have a login entry in the audit log' do
      fail "No successful login entry found in the audit log" unless login_entry
    end

    it 'should include login-specific fields' do
      required_fields = %w[ip_address auth_method]
      missing_fields = required_fields.reject { |f| login_entry.key?(f) }
      fail "Missing login-specific fields: #{missing_fields.join(', ')}\nLogin entry: #{login_entry}" unless missing_fields.empty?
    end
  end

  # Test case 3: Data access event content
  describe 'Data access event content' do
    # First login to get a token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: {
                            username: 'test_user',
                            password: 'TestPassword123'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Generate a data access event
    http("#{app_url}/user_profile",
         method: 'GET',
         headers: { 'Authorization' => "Bearer #{token}" })

    audit_log_content = file(audit_log_path).content
    # Handle case where file content might be nil or empty
    if audit_log_content.nil? || audit_log_content.empty?
      fail "Audit log file is empty or not found at #{audit_log_path}"
    end
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact

    # Find the data access entry
    data_access_entry = audit_entries.find { |entry| entry['event_type'] == 'data_access' }

    it 'should have a data access entry in the audit log' do
      fail "No data access entry found in the audit log" unless data_access_entry
    end

    it 'should include data access-specific fields' do
      required_fields = %w[data_id]
      missing_fields = required_fields.reject { |f| data_access_entry.key?(f) }
      fail "Missing data access-specific fields: #{missing_fields.join(', ')}\nData access entry: #{data_access_entry}" unless missing_fields.empty?
    end
  end

  # Test case 4: Configuration change event content
  describe 'Configuration change event content' do
    # First login as admin to get a token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: {
                            username: 'admin_user',
                            password: 'AdminSecurePass456'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Generate a configuration change event
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
    # Handle case where file content might be nil or empty
    if audit_log_content.nil? || audit_log_content.empty?
      fail "Audit log file is empty or not found at #{audit_log_path}"
    end
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact

    # Find the configuration change entry
    config_change_entry = audit_entries.find { |entry| entry['event_type'] == 'configuration_change' }

    it 'should have a configuration change entry in the audit log' do
      fail "No configuration change entry found in the audit log" unless config_change_entry
    end

    it 'should include configuration change-specific fields' do
      required_fields = %w[old_value new_value]
      missing_fields = required_fields.reject { |f| config_change_entry.key?(f) }
      fail "Missing configuration change-specific fields: #{missing_fields.join(', ')}\nConfiguration change entry: #{config_change_entry}" unless missing_fields.empty?
    end
  end

  # Test case 5: Failed login event content
  describe 'Failed login event content' do
    # Generate a failed login event
    http("#{app_url}/login",
         method: 'POST',
         headers: { 'Content-Type' => 'application/json' },
         data: {
           username: 'test_user',
           password: 'WrongPassword'
         }.to_json)

    audit_log_content = file(audit_log_path).content
    # Handle case where file content might be nil or empty
    if audit_log_content.nil? || audit_log_content.empty?
      fail "Audit log file is empty or not found at #{audit_log_path}"
    end
    audit_entries = audit_log_content.split("\n").map { |line| JSON.parse(line) rescue nil }.compact

    # Find the failed login entry
    failed_login_entry = audit_entries.find { |entry| entry['event_type'] == 'login' && entry['outcome'] == 'failure' }

    it 'should have a failed login entry in the audit log' do
      fail "No failed login entry found in the audit log" unless failed_login_entry
    end

    it 'should include reason for failure' do
      fail "Failed login entry does not include reason for failure" unless failed_login_entry.key?('reason')
    end
  end

  # Test case 6: OPA validation of audit content
  describe 'OPA validation of audit content' do
    # Check OPA logs for audit content validation
    opa_log_content = file(log_file_path).content

    it 'should contain audit content validation in OPA logs' do
      # Handle case where file content might be nil or empty
      if opa_log_content.nil? || opa_log_content.empty?
        fail "OPA log file is empty or not found at #{log_file_path}"
      end

      keywords = %w[audit_content_valid basic_content_valid timestamp_valid event_type_valid outcome_valid]
      missing_keywords = keywords.reject { |keyword| opa_log_content.include?(keyword) }

      unless missing_keywords.empty?
        fail "OPA logs do not contain audit content validation keywords: #{missing_keywords.join(', ')}"
      end
    end
  end
end
