control 'baseline-configuration' do
  impact 1.0
  title 'Validate Baseline Configuration Controls'
  desc 'Ensure that the system maintains a current baseline configuration of the system (CM-2)'

  app_url = 'http://mock-server:8000'
  log_file_path = './logs/opa_interactions.log'

  # Test case 1: Verify baseline configuration documentation
  describe 'Baseline configuration documentation' do
    # Get baseline configuration documentation
    baseline_doc_response = http("#{app_url}/baseline_configuration_doc",
                              method: 'GET',
                              headers: {
                                'Content-Type' => 'application/json',
                                'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                              })

    baseline_doc = JSON.parse(baseline_doc_response.body)

    it 'should have baseline configuration documented' do
      unless baseline_doc['documented'] == true
        fail "Baseline configuration is not documented"
      end
    end

    it 'should include all required components' do
      unless baseline_doc['components'] && baseline_doc['components'].length > 0
        fail "Baseline configuration does not include required components"
      end
    end

    it 'should have complete settings for each component' do
      unless baseline_doc['components'].all? { |component| component['settings'] && component['settings'].length > 0 }
        fail "Not all components have complete settings"
      end
    end
  end

  # Test case 2: Verify baseline configuration currency
  describe 'Baseline configuration currency' do
    # Get baseline configuration currency information
    baseline_currency_response = http("#{app_url}/baseline_configuration_currency",
                                   method: 'GET',
                                   headers: {
                                     'Content-Type' => 'application/json',
                                     'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                   })

    baseline_currency = JSON.parse(baseline_currency_response.body)

    it 'should have a recently updated baseline configuration' do
      last_updated = DateTime.parse(baseline_currency['last_updated'])
      ninety_days_ago = DateTime.now - 90
      
      unless last_updated > ninety_days_ago
        fail "Baseline configuration has not been updated in the last 90 days"
      end
    end

    it 'should match current system state' do
      unless baseline_currency['matches_current_state'] == true
        fail "Baseline configuration does not match current system state"
      end
    end
  end

  # Test case 3: Verify baseline configuration review process
  describe 'Baseline configuration review process' do
    # Get baseline configuration review information
    baseline_review_response = http("#{app_url}/baseline_configuration_review",
                                 method: 'GET',
                                 headers: {
                                   'Content-Type' => 'application/json',
                                   'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                 })

    baseline_review = JSON.parse(baseline_review_response.body)

    it 'should have a recently reviewed baseline configuration' do
      last_review = DateTime.parse(baseline_review['last_review'])
      ninety_days_ago = DateTime.now - 90
      
      unless last_review > ninety_days_ago
        fail "Baseline configuration has not been reviewed in the last 90 days"
      end
    end

    it 'should have a documented review process' do
      unless baseline_review['review_process'] && baseline_review['review_process']['documented'] == true
        fail "Baseline configuration review process is not documented"
      end
    end

    it 'should include all required review steps' do
      unless baseline_review['review_process'] && baseline_review['review_process']['steps'] && baseline_review['review_process']['steps'].length >= 3
        fail "Baseline configuration review process does not include all required steps"
      end
    end
  end

  # Test case 4: Verify configuration control
  describe 'Configuration control' do
    # Get configuration control information
    config_control_response = http("#{app_url}/baseline_configuration_control",
                                method: 'GET',
                                headers: {
                                  'Content-Type' => 'application/json',
                                  'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                })

    config_control = JSON.parse(config_control_response.body)

    it 'should have configuration control enabled' do
      unless config_control['enabled'] == true
        fail "Configuration control is not enabled"
      end
    end

    it 'should have a documented change management process' do
      unless config_control['change_management'] && config_control['change_management']['documented'] == true
        fail "Change management process is not documented"
      end
    end

    it 'should require approvals for changes' do
      unless config_control['change_management'] && config_control['change_management']['requires_approval'] == true
        fail "Change management process does not require approvals"
      end
    end

    it 'should track changes' do
      unless config_control['change_management'] && config_control['change_management']['changes_tracked'] == true
        fail "Changes are not tracked"
      end
    end
  end

  # Test case 5: Verify change authorization
  describe 'Change authorization' do
    # First login as admin to get a token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: {
                            username: 'admin_user',
                            password: 'AdminSecurePass456'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Test change authorization
    change_auth_response = http("#{app_url}/baseline_change_authorization",
                             method: 'POST',
                             headers: {
                               'Authorization' => "Bearer #{token}",
                               'Content-Type' => 'application/json'
                             },
                             data: {
                               change: {
                                 component: 'web_server',
                                 setting: 'max_connections',
                                 old_value: 1000,
                                 new_value: 1500,
                                 ticket_id: 'CHG-12345',
                                 approved_by: 'security_admin'
                               }
                             }.to_json)

    change_auth = JSON.parse(change_auth_response.body)

    it 'should authorize valid changes' do
      unless change_auth['authorized'] == true
        fail "Valid change was not authorized"
      end
    end
  end

  # Test case 6: Verify unauthorized change detection
  describe 'Unauthorized change detection' do
    # Get unauthorized change detection information
    change_detection_response = http("#{app_url}/baseline_change_detection",
                                  method: 'GET',
                                  headers: {
                                    'Content-Type' => 'application/json',
                                    'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                  })

    change_detection = JSON.parse(change_detection_response.body)

    it 'should have monitoring enabled' do
      unless change_detection['monitoring_enabled'] == true
        fail "Monitoring for unauthorized changes is not enabled"
      end
    end

    it 'should have automated monitoring' do
      unless change_detection['automated_monitoring'] == true
        fail "Monitoring for unauthorized changes is not automated"
      end
    end

    it 'should have alerts configured' do
      unless change_detection['alerts_configured'] == true
        fail "Alerts for unauthorized changes are not configured"
      end
    end
  end
end
