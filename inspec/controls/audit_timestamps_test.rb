control 'audit-timestamps' do
  impact 1.0
  title 'Validate Time Stamps Controls'
  desc 'Ensure that the system uses internal system clocks to generate time stamps for audit records and records time stamps that can be mapped to UTC or GMT (AU-8)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'
  audit_log_path = './logs/audit.log'

  # Test case 1: Verify time source configuration
  describe 'Time source configuration' do
    # Get time source configuration information
    time_source_response = http("#{app_url}/time_source_config",
                              method: 'GET',
                              headers: {
                                'Content-Type' => 'application/json',
                                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                              })

    time_source = JSON.parse(time_source_response.body)

    it 'should have time source enabled' do
      unless time_source['enabled'] == true
        fail "Time source is not enabled"
      end
    end

    it 'should have a valid time source type' do
      valid_types = ['internal_clock', 'ntp', 'gps', 'atomic_clock']
      unless valid_types.include?(time_source['type'])
        fail "Invalid time source type: #{time_source['type']}"
      end
    end

    it 'should have NTP servers configured if using NTP' do
      if time_source['type'] == 'ntp'
        unless time_source['ntp_servers'] && time_source['ntp_servers'].length > 0
          fail "NTP time source selected but no NTP servers configured"
        end
      end
    end
  end

  # Test case 2: Verify time format configuration
  describe 'Time format configuration' do
    # Get time format configuration information
    time_format_response = http("#{app_url}/time_format_config",
                              method: 'GET',
                              headers: {
                                'Content-Type' => 'application/json',
                                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                              })

    time_format = JSON.parse(time_format_response.body)

    it 'should use ISO 8601 standard' do
      unless time_format['standard'] == 'iso8601'
        fail "Time format standard is not ISO 8601"
      end
    end

    it 'should have sufficient precision' do
      valid_precision = ['millisecond', 'microsecond', 'nanosecond']
      unless valid_precision.include?(time_format['precision'])
        fail "Insufficient time precision: #{time_format['precision']}"
      end
    end

    it 'should use UTC/GMT or have UTC mapping' do
      unless time_format['time_zone'] == 'UTC' || time_format['time_zone'] == 'GMT' || time_format['utc_mapping'] == true
        fail "Time zone not UTC/GMT and no UTC mapping configured"
      end
    end
  end

  # Test case 3: Verify time synchronization status
  describe 'Time synchronization status' do
    # Get time synchronization status
    time_sync_response = http("#{app_url}/time_sync_status",
                            method: 'GET',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                            })

    time_sync = JSON.parse(time_sync_response.body)

    it 'should have time synchronization enabled' do
      unless time_sync['enabled'] == true
        fail "Time synchronization is not enabled"
      end
    end

    it 'should have appropriate synchronization interval' do
      unless time_sync['interval_minutes'] <= 1440 # At least daily
        fail "Synchronization interval too long: #{time_sync['interval_minutes']} minutes (should be <= 1440)"
      end
    end

    it 'should have synchronization sources configured' do
      unless time_sync['sources'] && time_sync['sources'].length > 0
        fail "No time synchronization sources configured"
      end
    end

    it 'should have acceptable drift tolerance' do
      unless time_sync['max_drift_ms'] <= 1000 # Maximum 1 second drift
        fail "Drift tolerance too high: #{time_sync['max_drift_ms']} ms (should be <= 1000)"
      end
    end

    it 'should have recent synchronization' do
      unless time_sync['last_sync_time']
        fail "No last synchronization time recorded"
      end

      # Check if last sync was within the last 24 hours + interval
      last_sync_time = Time.parse(time_sync['last_sync_time'])
      max_time_since_sync = (time_sync['interval_minutes'] + 1440) * 60 # interval + 24 hours in seconds

      unless Time.now - last_sync_time <= max_time_since_sync
        fail "Last synchronization too old: #{time_sync['last_sync_time']}"
      end
    end
  end

  # Test case 4: Verify timestamp validation
  describe 'Timestamp validation' do
    # Get timestamp validation configuration
    validation_response = http("#{app_url}/timestamp_validation_config",
                              method: 'GET',
                              headers: {
                                'Content-Type' => 'application/json',
                                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                              })

    validation = JSON.parse(validation_response.body)

    it 'should have timestamp validation enabled' do
      unless validation['enabled'] == true
        fail "Timestamp validation is not enabled"
      end
    end

    it 'should have validation methods configured' do
      unless validation['methods'] && validation['methods'].length > 0
        fail "No timestamp validation methods configured"
      end
    end
  end

  # Test case 5: Validate timestamps in audit records
  describe 'Audit record timestamps' do
    # Generate an audit event
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: {
                            username: 'test_user',
                            password: 'TestPassword123'
                          }.to_json)

    # Get audit records
    audit_records_response = http("#{app_url}/audit_records",
                                method: 'GET',
                                headers: {
                                  'Content-Type' => 'application/json',
                                  'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                })

    audit_records = JSON.parse(audit_records_response.body)

    it 'should have audit records with timestamps' do
      unless audit_records['records'] && audit_records['records'].length > 0
        fail "No audit records found"
      end

      records_without_timestamps = audit_records['records'].select { |record| !record['timestamp'] }
      unless records_without_timestamps.empty?
        fail "Found #{records_without_timestamps.length} audit records without timestamps"
      end
    end

    it 'should have timestamps in ISO 8601 format' do
      invalid_timestamps = audit_records['records'].select do |record|
        timestamp = record['timestamp']
        !timestamp.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/)
      end

      unless invalid_timestamps.empty?
        fail "Found #{invalid_timestamps.length} audit records with invalid timestamp format"
      end
    end

    it 'should have timestamps with timezone information' do
      missing_timezone = audit_records['records'].select do |record|
        timestamp = record['timestamp']
        !timestamp.match(/(Z|[+-]\d{2}:\d{2})$/)
      end

      unless missing_timezone.empty?
        fail "Found #{missing_timezone.length} audit records with missing timezone information"
      end
    end
  end

  # Test case 6: Validate timestamp validation endpoint
  describe 'Timestamp validation endpoint' do
    # Test valid timestamp
    valid_timestamp = Time.now.utc.iso8601(3) # Current time in ISO 8601 with millisecond precision

    validate_response = http("#{app_url}/validate_timestamp",
                            method: 'POST',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                            },
                            data: { timestamp: valid_timestamp }.to_json)

    validation_result = JSON.parse(validate_response.body)

    it 'should validate correct timestamps' do
      unless validation_result['valid'] == true
        fail "Valid timestamp not recognized: #{valid_timestamp}"
      end
    end

    # Test invalid timestamp
    invalid_timestamp = "2023/01/01 12:34:56"

    invalid_response = http("#{app_url}/validate_timestamp",
                          method: 'POST',
                          headers: {
                            'Content-Type' => 'application/json',
                            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                          },
                          data: { timestamp: invalid_timestamp }.to_json)

    invalid_result = JSON.parse(invalid_response.body)

    it 'should reject incorrect timestamps' do
      unless invalid_result['valid'] == false
        fail "Invalid timestamp not rejected: #{invalid_timestamp}"
      end
    end
  end

  # Test case 7: Verify OPA policy validation
  describe 'OPA policy validation for timestamps' do
    # Check OPA logs for timestamp validation
    opa_log_content = file(log_file_path).content

    it 'should contain timestamp validation in OPA logs' do
      keywords = %w[time_source_configured time_format_configured time_sync_configured timestamp_validation_configured timestamp_format_valid]
      missing_keywords = keywords.reject { |keyword| opa_log_content.include?(keyword) }

      unless missing_keywords.empty?
        fail "OPA logs do not contain timestamp validation keywords: #{missing_keywords.join(', ')}"
      end
    end
  end
end
