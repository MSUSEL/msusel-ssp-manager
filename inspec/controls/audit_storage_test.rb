control 'audit-storage' do
  impact 1.0
  title 'Validate Audit Storage Capacity Controls'
  desc 'Ensure that sufficient audit record storage capacity is allocated and configured to prevent capacity being exceeded (AU-4)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'
  audit_log_path = './logs/audit.log'

  # Test case 1: Verify audit storage capacity configuration
  describe 'Audit storage capacity configuration' do
    # Get storage capacity information
    storage_info_response = http("#{app_url}/audit_storage_info",
                                method: 'GET',
                                headers: { 'Content-Type' => 'application/json' })

    storage_info = JSON.parse(storage_info_response.body)

    it 'should have sufficient storage capacity' do
      unless storage_info['capacity_gb'] >= storage_info['required_capacity_gb']
        fail "Insufficient storage capacity. Required: #{storage_info['required_capacity_gb']}GB, Allocated: #{storage_info['capacity_gb']}GB"
      end
    end

    it 'should have monitoring enabled' do
      unless storage_info['monitoring_enabled'] == true
        fail "Storage monitoring is not enabled"
      end
    end

    it 'should have appropriate monitoring interval' do
      unless storage_info['monitoring_interval_minutes'] <= 60
        fail "Monitoring interval too long: #{storage_info['monitoring_interval_minutes']} minutes (should be <= 60)"
      end
    end

    it 'should have alerts configured' do
      unless storage_info['alerts_enabled'] == true
        fail "Storage alerts are not enabled"
      end
    end

    it 'should have appropriate warning threshold' do
      unless storage_info['warning_threshold_percent'] <= 80
        fail "Warning threshold too high: #{storage_info['warning_threshold_percent']}% (should be <= 80%)"
      end
    end

    it 'should have appropriate critical threshold' do
      unless storage_info['critical_threshold_percent'] <= 90
        fail "Critical threshold too high: #{storage_info['critical_threshold_percent']}% (should be <= 90%)"
      end
    end

    it 'should have alert recipients configured' do
      unless storage_info['alert_recipients'] && storage_info['alert_recipients'].length > 0
        fail "No alert recipients configured"
      end
    end
  end

  # Test case 2: Verify retention policy configuration
  describe 'Audit retention policy configuration' do
    # Get retention policy information
    retention_info_response = http("#{app_url}/audit_retention_info",
                                  method: 'GET',
                                  headers: { 'Content-Type' => 'application/json' })

    retention_info = JSON.parse(retention_info_response.body)

    it 'should have retention policy enabled' do
      unless retention_info['retention_policy_enabled'] == true
        fail "Retention policy is not enabled"
      end
    end

    it 'should have appropriate retention period' do
      unless retention_info['retention_period_days'] >= 180
        fail "Retention period too short: #{retention_info['retention_period_days']} days (should be >= 180)"
      end
    end

    it 'should have archiving enabled' do
      unless retention_info['archiving_enabled'] == true
        fail "Archiving is not enabled"
      end
    end
  end

  # Test case 3: Verify current storage usage
  describe 'Current storage usage' do
    # Get current storage usage
    usage_info_response = http("#{app_url}/audit_storage_usage",
                              method: 'GET',
                              headers: { 'Content-Type' => 'application/json' })

    usage_info = JSON.parse(usage_info_response.body)
    usage_percent = (usage_info['used_gb'].to_f / usage_info['capacity_gb'].to_f) * 100

    it 'should be within acceptable limits' do
      unless usage_percent < usage_info['critical_threshold_percent']
        fail "Storage usage at critical level: #{usage_percent.round(2)}% (threshold: #{usage_info['critical_threshold_percent']}%)"
      end
    end

    it 'should generate appropriate alerts when approaching capacity' do
      if usage_percent >= usage_info['warning_threshold_percent'] && usage_percent < usage_info['critical_threshold_percent']
        # Check if warning alert was generated
        opa_log_content = file(log_file_path).content
        unless opa_log_content.include?('storage_approaching_capacity') && opa_log_content.include?('true')
          fail "Warning alert not generated for storage approaching capacity"
        end
      end
    end

    it 'should generate appropriate alerts when at critical capacity' do
      if usage_percent >= usage_info['critical_threshold_percent']
        # Check if critical alert was generated
        opa_log_content = file(log_file_path).content
        unless opa_log_content.include?('storage_at_critical_capacity') && opa_log_content.include?('true')
          fail "Critical alert not generated for storage at critical capacity"
        end
      end
    end
  end

  # Test case 4: Verify automatic actions for capacity management
  describe 'Automatic actions for capacity management' do
    # Get automatic actions configuration
    actions_info_response = http("#{app_url}/audit_automatic_actions",
                                method: 'GET',
                                headers: { 'Content-Type' => 'application/json' })

    actions_info = JSON.parse(actions_info_response.body)

    it 'should have automatic actions enabled' do
      unless actions_info['automatic_actions_enabled'] == true
        fail "Automatic actions are not enabled"
      end
    end

    it 'should have at least one action configured' do
      unless actions_info['automatic_actions'] && actions_info['automatic_actions'].length > 0
        fail "No automatic actions configured"
      end
    end
  end

  # Test case 5: Verify OPA policy validation
  describe 'OPA policy validation for audit storage' do
    # Check OPA logs for audit storage validation
    opa_log_content = file(log_file_path).content

    it 'should contain audit storage validation in OPA logs' do
      keywords = %w[audit_storage_compliant storage_capacity_sufficient storage_monitoring_configured storage_alerts_configured]
      missing_keywords = keywords.reject { |keyword| opa_log_content.include?(keyword) }
      
      unless missing_keywords.empty?
        fail "OPA logs do not contain audit storage validation keywords: #{missing_keywords.join(', ')}"
      end
    end
  end

  # Test case 6: Simulate approaching capacity and verify response
  describe 'System response to approaching capacity' do
    # Simulate approaching capacity
    simulate_response = http("#{app_url}/simulate_storage_usage",
                            method: 'POST',
                            headers: { 'Content-Type' => 'application/json' },
                            data: { usage_percent: 75 }.to_json)

    simulate_result = JSON.parse(simulate_response.body)

    it 'should detect approaching capacity' do
      unless simulate_result['storage_approaching_capacity'] == true
        fail "System did not detect approaching capacity"
      end
    end

    it 'should generate warning alert' do
      unless simulate_result['alert_generated'] == true && simulate_result['alert_level'] == 'warning'
        fail "Warning alert not generated for approaching capacity"
      end
    end
  end

  # Test case 7: Simulate critical capacity and verify response
  describe 'System response to critical capacity' do
    # Simulate critical capacity
    simulate_response = http("#{app_url}/simulate_storage_usage",
                            method: 'POST',
                            headers: { 'Content-Type' => 'application/json' },
                            data: { usage_percent: 95 }.to_json)

    simulate_result = JSON.parse(simulate_response.body)

    it 'should detect critical capacity' do
      unless simulate_result['storage_at_critical_capacity'] == true
        fail "System did not detect critical capacity"
      end
    end

    it 'should generate critical alert' do
      unless simulate_result['alert_generated'] == true && simulate_result['alert_level'] == 'critical'
        fail "Critical alert not generated for critical capacity"
      end
    end

    it 'should trigger automatic actions' do
      unless simulate_result['automatic_actions_triggered'] == true
        fail "Automatic actions not triggered for critical capacity"
      end
    end
  end
end
