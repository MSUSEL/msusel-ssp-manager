control 'access-restrictions-for-change' do
  impact 1.0
  title 'Validate Access Restrictions for Change Controls'
  desc 'Ensure that the system enforces access restrictions for changes to the system (CM-5)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'

  # Test case 1: Verify user authorization for changes
  describe 'User authorization for changes' do
    # Get user authorization information
    user_auth_response = http("#{app_url}/change_authorization_roles",
                           method: 'GET',
                           headers: {
                             'Content-Type' => 'application/json',
                             'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                           })

    user_auth = JSON.parse(user_auth_response.body)

    it 'should have authorized roles defined' do
      unless user_auth['authorized_roles'] && user_auth['authorized_roles'].length > 0
        fail "No authorized roles defined for changes"
      end
    end

    it 'should include admin role in authorized roles' do
      unless user_auth['authorized_roles'].include?('admin')
        fail "Admin role is not included in authorized roles"
      end
    end

    it 'should include config_admin role in authorized roles' do
      unless user_auth['authorized_roles'].include?('config_admin')
        fail "Config admin role is not included in authorized roles"
      end
    end
  end

  # Test case 2: Verify change documentation requirements
  describe 'Change documentation requirements' do
    # Get change documentation requirements
    change_doc_response = http("#{app_url}/change_documentation_requirements",
                            method: 'GET',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                            })

    change_doc = JSON.parse(change_doc_response.body)

    it 'should require ticket ID' do
      unless change_doc['required_fields'] && change_doc['required_fields'].include?('ticket_id')
        fail "Ticket ID is not a required field for change documentation"
      end
    end

    it 'should require description' do
      unless change_doc['required_fields'] && change_doc['required_fields'].include?('description')
        fail "Description is not a required field for change documentation"
      end
    end

    it 'should require approver' do
      unless change_doc['required_fields'] && change_doc['required_fields'].include?('approved_by')
        fail "Approver is not a required field for change documentation"
      end
    end
  end

  # Test case 3: Verify change workflow
  describe 'Change workflow' do
    # Get change workflow information
    change_workflow_response = http("#{app_url}/change_workflow",
                                 method: 'GET',
                                 headers: {
                                   'Content-Type' => 'application/json',
                                   'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                 })

    change_workflow = JSON.parse(change_workflow_response.body)

    it 'should require testing' do
      unless change_workflow['required_steps'] && change_workflow['required_steps'].include?('testing')
        fail "Testing is not a required step in the change workflow"
      end
    end

    it 'should require review' do
      unless change_workflow['required_steps'] && change_workflow['required_steps'].include?('review')
        fail "Review is not a required step in the change workflow"
      end
    end

    it 'should require approval' do
      unless change_workflow['required_steps'] && change_workflow['required_steps'].include?('approval')
        fail "Approval is not a required step in the change workflow"
      end
    end
  end

  # Test case 4: Verify change logging
  describe 'Change logging' do
    # Get change logging information
    change_logging_response = http("#{app_url}/change_logging_config",
                                method: 'GET',
                                headers: {
                                  'Content-Type' => 'application/json',
                                  'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                })

    change_logging = JSON.parse(change_logging_response.body)

    it 'should have logging enabled' do
      unless change_logging['enabled'] == true
        fail "Change logging is not enabled"
      end
    end

    it 'should have protected logs' do
      unless change_logging['protected'] == true
        fail "Change logs are not protected"
      end
    end

    it 'should include required fields in logs' do
      required_log_fields = ['timestamp', 'user_id', 'change_type', 'component', 'description', 'ticket_id']
      missing_fields = required_log_fields - (change_logging['log_fields'] || [])
      
      unless missing_fields.empty?
        fail "Change logs are missing required fields: #{missing_fields.join(', ')}"
      end
    end
  end

  # Test case 5: Verify physical access restrictions for hardware changes
  describe 'Physical access restrictions' do
    # Get physical access restriction information
    physical_access_response = http("#{app_url}/physical_access_restrictions",
                                 method: 'GET',
                                 headers: {
                                   'Content-Type' => 'application/json',
                                   'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                 })

    physical_access = JSON.parse(physical_access_response.body)

    it 'should have physical access restrictions enabled' do
      unless physical_access['enabled'] == true
        fail "Physical access restrictions are not enabled"
      end
    end

    it 'should require authentication for physical access' do
      unless physical_access['requires_authentication'] == true
        fail "Physical access does not require authentication"
      end
    end

    it 'should log physical access' do
      unless physical_access['logged'] == true
        fail "Physical access is not logged"
      end
    end
  end

  # Test case 6: Verify emergency change process
  describe 'Emergency change process' do
    # Get emergency change process information
    emergency_change_response = http("#{app_url}/emergency_change_process",
                                  method: 'GET',
                                  headers: {
                                    'Content-Type' => 'application/json',
                                    'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                  })

    emergency_change = JSON.parse(emergency_change_response.body)

    it 'should have emergency change process defined' do
      unless emergency_change['process_defined'] == true
        fail "Emergency change process is not defined"
      end
    end

    it 'should require post-change review for emergency changes' do
      unless emergency_change['requires_post_review'] == true
        fail "Emergency changes do not require post-change review"
      end
    end

    it 'should require executive approval for emergency changes' do
      unless emergency_change['requires_executive_approval'] == true
        fail "Emergency changes do not require executive approval"
      end
    end
  end

  # Test case 7: Verify change authorization
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

    # Test normal change authorization
    normal_change_response = http("#{app_url}/authorize_change",
                               method: 'POST',
                               headers: {
                                 'Authorization' => "Bearer #{token}",
                                 'Content-Type' => 'application/json'
                               },
                               data: {
                                 change: {
                                   type: 'software',
                                   component: 'web_server',
                                   description: 'Update web server configuration',
                                   ticket_id: 'CHG-12345',
                                   approved_by: 'security_admin',
                                   tested: true,
                                   reviewed: true,
                                   approved: true,
                                   emergency: false
                                 }
                               }.to_json)

    normal_change = JSON.parse(normal_change_response.body)

    it 'should authorize valid normal changes' do
      unless normal_change['authorized'] == true
        fail "Valid normal change was not authorized"
      end
    end

    # Test emergency change authorization
    emergency_change_response = http("#{app_url}/authorize_change",
                                  method: 'POST',
                                  headers: {
                                    'Authorization' => "Bearer #{token}",
                                    'Content-Type' => 'application/json'
                                  },
                                  data: {
                                    change: {
                                      type: 'software',
                                      component: 'web_server',
                                      description: 'Emergency security patch',
                                      ticket_id: 'CHG-12346',
                                      approved_by: 'security_admin',
                                      tested: false,
                                      reviewed: false,
                                      approved: true,
                                      emergency: true,
                                      emergency_approved_by: 'cio'
                                    }
                                  }.to_json)

    emergency_change = JSON.parse(emergency_change_response.body)

    it 'should authorize valid emergency changes' do
      unless emergency_change['authorized'] == true
        fail "Valid emergency change was not authorized"
      end
    end
  end
end
