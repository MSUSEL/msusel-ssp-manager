control 'configuration-management-policy' do
  impact 1.0
  title 'Validate Configuration Management Controls'
  desc 'Ensure that configuration management controls are properly enforced (CM-2, CM-5, CM-8)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'

  # Test case 1: Authorized configuration change
  describe 'Authorized configuration change' do
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
    
    # Make an authorized configuration change
    change_response = http("#{app_url}/config_change",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             change: {
                               ticket_id: 'CHG-12345',
                               approved_by: 'approver_user',
                               component: 'web-server-01',
                               setting: 'max_connections',
                               value: 1200
                             }
                           }.to_json)

    it 'should allow authorized configuration change' do
      expect(change_response.status).to eq(200)
      expect(JSON.parse(change_response.body)['allowed']).to eq(true)
    end
  end

  # Test case 2: Unauthorized configuration change (non-admin user)
  describe 'Unauthorized configuration change (non-admin user)' do
    # First login as regular user to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'regular_user', 
                            password: 'SecurePassword123'
                          }.to_json)
    
    token = JSON.parse(login_response.body)['access_token']
    
    # Attempt unauthorized configuration change
    change_response = http("#{app_url}/config_change",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             change: {
                               ticket_id: 'CHG-12345',
                               approved_by: 'approver_user',
                               component: 'web-server-01',
                               setting: 'max_connections',
                               value: 1200
                             }
                           }.to_json)

    it 'should deny configuration change by non-admin user' do
      expect(change_response.status).to eq(403)
      expect(JSON.parse(change_response.body)['allowed']).to eq(false)
      expect(JSON.parse(change_response.body)['reason']).to include('not authorized')
    end
  end

  # Test case 3: Unauthorized configuration change (outside allowed hours)
  describe 'Unauthorized configuration change (outside allowed hours)' do
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
    
    # Attempt configuration change outside allowed hours
    change_response = http("#{app_url}/config_change?simulate_time=03:00:00",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             change: {
                               ticket_id: 'CHG-12345',
                               approved_by: 'approver_user',
                               component: 'web-server-01',
                               setting: 'max_connections',
                               value: 1200
                             }
                           }.to_json)

    it 'should deny configuration change outside allowed hours' do
      expect(change_response.status).to eq(403)
      expect(JSON.parse(change_response.body)['allowed']).to eq(false)
      expect(JSON.parse(change_response.body)['reason']).to include('outside allowed hours')
    end
  end

  # Test case 4: Configuration compliance check
  describe 'Configuration compliance check' do
    # Check configuration compliance
    compliance_response = http("#{app_url}/check_compliance",
                               method: 'POST',
                               headers: { 'Content-Type' => 'application/json' },
                               data: {
                                 component: {
                                   id: 'web-server-01',
                                   type: 'web_server',
                                   settings: {
                                     max_connections: 1000,
                                     timeout: 60,
                                     ssl_enabled: true,
                                     min_tls_version: 'TLS 1.2',
                                     default_charset: 'UTF-8'
                                   }
                                 }
                               }.to_json)

    it 'should validate compliant configuration' do
      expect(compliance_response.status).to eq(200)
      expect(JSON.parse(compliance_response.body)['compliant']).to eq(true)
    end
  end

  # Test case 5: Configuration non-compliance check
  describe 'Configuration non-compliance check' do
    # Check configuration with non-compliant settings
    compliance_response = http("#{app_url}/check_compliance",
                               method: 'POST',
                               headers: { 'Content-Type' => 'application/json' },
                               data: {
                                 component: {
                                   id: 'web-server-01',
                                   type: 'web_server',
                                   settings: {
                                     max_connections: 1000,
                                     timeout: 60,
                                     ssl_enabled: false,  # Non-compliant: should be true
                                     min_tls_version: 'TLS 1.1',  # Non-compliant: should be TLS 1.2
                                     default_charset: 'UTF-8'
                                   }
                                 }
                               }.to_json)

    it 'should identify non-compliant configuration' do
      expect(compliance_response.status).to eq(200)
      expect(JSON.parse(compliance_response.body)['compliant']).to eq(false)
      expect(JSON.parse(compliance_response.body)['non_compliant_settings']).to include('ssl_enabled')
      expect(JSON.parse(compliance_response.body)['non_compliant_settings']).to include('min_tls_version')
    end
  end

  # Test case 6: Component inventory check
  describe 'Component inventory check' do
    # Check if component is in inventory
    inventory_response = http("#{app_url}/check_inventory",
                              method: 'POST',
                              headers: { 'Content-Type' => 'application/json' },
                              data: {
                                component: {
                                  id: 'web-server-01'
                                }
                              }.to_json)

    it 'should validate component in inventory' do
      expect(inventory_response.status).to eq(200)
      expect(JSON.parse(inventory_response.body)['in_inventory']).to eq(true)
    end
  end

  # Test case 7: Component not in inventory
  describe 'Component not in inventory' do
    # Check if unknown component is in inventory
    inventory_response = http("#{app_url}/check_inventory",
                              method: 'POST',
                              headers: { 'Content-Type' => 'application/json' },
                              data: {
                                component: {
                                  id: 'unknown-server-99'
                                }
                              }.to_json)

    it 'should identify component not in inventory' do
      expect(inventory_response.status).to eq(200)
      expect(JSON.parse(inventory_response.body)['in_inventory']).to eq(false)
    end
  end

  # Test case 8: Dependency check
  describe 'Dependency check' do
    # Check if dependencies are approved
    dependency_response = http("#{app_url}/check_dependencies",
                               method: 'POST',
                               headers: { 'Content-Type' => 'application/json' },
                               data: {
                                 component: {
                                   id: 'web-server-01',
                                   dependencies: [
                                     'express@4.18.2',
                                     'react@18.2.0',
                                     'node@18.12.1'
                                   ]
                                 }
                               }.to_json)

    it 'should validate approved dependencies' do
      expect(dependency_response.status).to eq(200)
      expect(JSON.parse(dependency_response.body)['approved']).to eq(true)
    end
  end

  # Test case 9: Unapproved dependency check
  describe 'Unapproved dependency check' do
    # Check with unapproved dependencies
    dependency_response = http("#{app_url}/check_dependencies",
                               method: 'POST',
                               headers: { 'Content-Type' => 'application/json' },
                               data: {
                                 component: {
                                   id: 'web-server-01',
                                   dependencies: [
                                     'express@4.18.2',
                                     'react@18.2.0',
                                     'vulnerable-package@1.0.0'  # Unapproved dependency
                                   ]
                                 }
                               }.to_json)

    it 'should identify unapproved dependencies' do
      expect(dependency_response.status).to eq(200)
      expect(JSON.parse(dependency_response.body)['approved']).to eq(false)
      expect(JSON.parse(dependency_response.body)['unapproved_dependencies']).to include('vulnerable-package@1.0.0')
    end
  end

  # Validate OPA logs for configuration management decisions
  describe file(log_file_path) do
    its('content') { should include 'configuration_management' }
    its('content') { should include 'config_change_authorized' }
    its('content') { should include 'config_compliant_with_baseline' }
    its('content') { should include 'component_in_inventory' }
    its('content') { should include 'dependencies_approved' }
  end
end
