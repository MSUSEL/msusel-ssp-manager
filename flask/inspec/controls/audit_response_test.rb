control 'audit-response' do
  impact 1.0
  title 'Validate Audit Processing Failure Response Controls'
  desc 'Ensure that the system responds appropriately to audit processing failures (AU-5)'

  app_url = 'http://mock-server:8000'
  log_file_path = './logs/opa_interactions.log'
  audit_log_path = './logs/audit.log'

  # Test case 1: Verify audit failure alert configuration
  describe 'Audit failure alert configuration' do
    # Get alert configuration information
    alert_config_response = http("#{app_url}/audit_alert_config",
                              method: 'GET',
                              headers: {
                                'Content-Type' => 'application/json',
                                'Authorization' => 'Bearer admin_user_token'
                              })

    alert_config = JSON.parse(alert_config_response.body)

    it 'should have alerts enabled' do
      unless alert_config['alerts_enabled'] == true
        fail "Audit failure alerts are not enabled"
      end
    end

    it 'should have alert recipients configured' do
      unless alert_config['alert_recipients'] && alert_config['alert_recipients'].length > 0
        fail "No alert recipients configured for audit failures"
      end
    end

    it 'should have appropriate notification methods' do
      unless alert_config['notification_methods'] && alert_config['notification_methods'].length > 0
        fail "No notification methods configured for audit failures"
      end
    end
  end

  # Test case 2: Verify audit failure actions configuration
  describe 'Audit failure actions configuration' do
    # Get actions configuration information
    actions_config_response = http("#{app_url}/audit_actions_config",
                                method: 'GET',
                                headers: {
                                  'Content-Type' => 'application/json',
                                  'Authorization' => 'Bearer admin_user_token'
                                })

    actions_config = JSON.parse(actions_config_response.body)

    it 'should have actions enabled' do
      unless actions_config['actions_enabled'] == true
        fail "Audit failure actions are not enabled"
      end
    end

    it 'should have appropriate actions configured' do
      unless actions_config['actions'] && actions_config['actions'].length > 0
        fail "No actions configured for audit failures"
      end
    end

    it 'should include system shutdown for critical failures' do
      has_shutdown = false
      if actions_config['actions']
        actions_config['actions'].each do |action|
          if action['type'] == 'shutdown' && action['trigger'] == 'critical_failure'
            has_shutdown = true
            break
          end
        end
      end

      unless has_shutdown
        fail "System shutdown not configured for critical audit failures"
      end
    end
  end

  # Test case 3: Verify audit capacity protection
  describe 'Audit capacity protection' do
    # Get capacity protection information
    capacity_config_response = http("#{app_url}/audit_capacity_protection",
                                  method: 'GET',
                                  headers: {
                                    'Content-Type' => 'application/json',
                                    'Authorization' => 'Bearer admin_user_token'
                                  })

    capacity_config = JSON.parse(capacity_config_response.body)

    it 'should have capacity protection enabled' do
      unless capacity_config['capacity_protection_enabled'] == true
        fail "Audit capacity protection is not enabled"
      end
    end

    it 'should have appropriate capacity threshold' do
      unless capacity_config['capacity_threshold_percent'] <= 90
        fail "Capacity threshold too high: #{capacity_config['capacity_threshold_percent']}% (should be <= 90%)"
      end
    end

    it 'should have appropriate actions for capacity threshold breaches' do
      unless capacity_config['capacity_actions'] && capacity_config['capacity_actions'].length > 0
        fail "No actions configured for capacity threshold breaches"
      end
    end
  end

  # Test case 4: Verify real-time monitoring
  describe 'Real-time audit monitoring' do
    # Get monitoring configuration information
    monitoring_config_response = http("#{app_url}/audit_monitoring_config",
                                    method: 'GET',
                                    headers: {
                                      'Content-Type' => 'application/json',
                                      'Authorization' => 'Bearer admin_user_token'
                                    })

    monitoring_config = JSON.parse(monitoring_config_response.body)

    it 'should have real-time monitoring enabled' do
      unless monitoring_config['real_time_monitoring_enabled'] == true
        fail "Real-time audit monitoring is not enabled"
      end
    end

    it 'should have appropriate monitoring interval' do
      unless monitoring_config['monitoring_interval_seconds'] <= 300
        fail "Monitoring interval too long: #{monitoring_config['monitoring_interval_seconds']} seconds (should be <= 300)"
      end
    end
  end

  # Test case 5: Verify OPA policy validation
  describe 'OPA policy validation for audit response' do
    # Check OPA logs for audit response validation
    opa_log_content = file(log_file_path).content

    it 'should contain audit response validation in OPA logs' do
      keywords = %w[audit_alerts_configured audit_actions_configured audit_capacity_protection_configured real_time_monitoring_configured audit_failure_handled]
      missing_keywords = keywords.reject { |keyword| opa_log_content.include?(keyword) }

      unless missing_keywords.empty?
        fail "OPA logs do not contain audit response validation keywords: #{missing_keywords.join(', ')}"
      end
    end
  end

  # Test case 6: Simulate audit failure and verify response
  describe 'System response to audit failure' do
    # Simulate audit failure
    simulate_response = http("#{app_url}/simulate_audit_failure",
                            method: 'POST',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer admin_user_token'
                            },
                            data: { failure_type: 'storage_error' }.to_json)

    simulate_result = JSON.parse(simulate_response.body)

    it 'should detect audit failure' do
      unless simulate_result['failure_detected'] == true
        fail "System did not detect audit failure"
      end
    end

    it 'should generate alert for audit failure' do
      unless simulate_result['alert_generated'] == true
        fail "Alert not generated for audit failure"
      end
    end

    it 'should take appropriate actions for audit failure' do
      unless simulate_result['actions_taken'] && simulate_result['actions_taken'].length > 0
        fail "No actions taken for audit failure"
      end
    end
  end

  # Test case 7: Simulate critical audit failure and verify response
  describe 'System response to critical audit failure' do
    # Simulate critical audit failure
    simulate_response = http("#{app_url}/simulate_audit_failure",
                            method: 'POST',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer admin_user_token'
                            },
                            data: { failure_type: 'critical_failure' }.to_json)

    simulate_result = JSON.parse(simulate_response.body)

    it 'should detect critical audit failure' do
      unless simulate_result['failure_detected'] == true && simulate_result['failure_severity'] == 'critical'
        fail "System did not detect critical audit failure"
      end
    end

    it 'should generate critical alert' do
      unless simulate_result['alert_generated'] == true && simulate_result['alert_level'] == 'critical'
        fail "Critical alert not generated for critical audit failure"
      end
    end

    it 'should initiate system shutdown or override' do
      unless simulate_result['actions_taken'] && simulate_result['actions_taken'].any? { |action| action['type'] == 'shutdown' || action['type'] == 'override' }
        fail "System shutdown or override not initiated for critical audit failure"
      end
    end
  end
end
