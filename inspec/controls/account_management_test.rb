control 'ac-2' do
  impact 1.0
  title 'Validate Account Management Controls'
  desc 'Ensure that account management controls are properly enforced (AC-2)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'

  # Test case 1: Account creation with proper approval
  describe 'Account creation with proper approval' do
    # Login as admin to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Create a new user account with proper approval
    create_response = http("#{app_url}/create_user",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             user: {
                               id: 'new_test_user',
                               roles: ['user'],
                               approved_by: 'admin_user',
                               expiration_date: (Time.now + 90*24*60*60).iso8601 # 90 days from now
                             }
                           }.to_json)

    it 'should allow account creation with proper approval' do
      expect(create_response.status).to eq(200)
      expect(JSON.parse(create_response.body)['account_created']).to eq(true)
    end
  end

  # Test case 2: Account creation without proper approval
  describe 'Account creation without proper approval' do
    # Login as admin to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Attempt to create a new user account without approval
    create_response = http("#{app_url}/create_user",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             user: {
                               id: 'new_test_user',
                               roles: ['user'],
                               expiration_date: (Time.now + 90*24*60*60).iso8601 # 90 days from now
                             }
                           }.to_json)

    it 'should deny account creation without proper approval' do
      expect(create_response.status).to eq(400)
      expect(JSON.parse(create_response.body)['error']).to eq('missing_required_fields')
      expect(JSON.parse(create_response.body)['message']).to eq('missing_approval')
    end
  end

  # Test case 3: Account creation by non-admin
  describe 'Account creation by non-admin' do
    # Login as regular user to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'regular_user', 
                            password: 'SecurePassword123'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Attempt to create a new user account as non-admin
    create_response = http("#{app_url}/create_user",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             user: {
                               id: 'new_test_user',
                               roles: ['user'],
                               approved_by: 'regular_user',
                               expiration_date: (Time.now + 90*24*60*60).iso8601 # 90 days from now
                             }
                           }.to_json)

    it 'should deny account creation by non-admin' do
      expect(create_response.status).to eq(401)
      expect(JSON.parse(create_response.body)['error']).to eq('unauthorized')
    end
  end

  # Test case 4: Account modification with proper authorization
  describe 'Account modification with proper authorization' do
    # Login as admin to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Modify a user account with proper authorization
    modify_response = http("#{app_url}/modify_user",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             user_id: 'regular_user',
                             changes: {
                               roles: ['user', 'staff'],
                               approved_by: 'admin_user'
                             }
                           }.to_json)

    it 'should allow account modification with proper authorization' do
      expect(modify_response.status).to eq(200)
      expect(JSON.parse(modify_response.body)['account_modified']).to eq(true)
    end
  end

  # Test case 5: Account modification without proper authorization
  describe 'Account modification without proper authorization' do
    # Login as regular user to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'regular_user', 
                            password: 'SecurePassword123'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Attempt to modify another user's account
    modify_response = http("#{app_url}/modify_user",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             user_id: 'staff_user',
                             changes: {
                               roles: ['user', 'admin']
                             }
                           }.to_json)

    it 'should deny account modification without proper authorization' do
      expect(modify_response.status).to eq(403)
      expect(JSON.parse(modify_response.body)['error']).to eq('unauthorized')
    end
  end

  # Test case 6: Self-modification of non-privileged information
  describe 'Self-modification of non-privileged information' do
    # Login as regular user to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'regular_user', 
                            password: 'SecurePassword123'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Modify own non-privileged information
    modify_response = http("#{app_url}/modify_user",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             user_id: 'regular_user',
                             changes: {
                               display_name: 'Regular Test User',
                               email: 'regular.user@example.com'
                             }
                           }.to_json)

    it 'should allow self-modification of non-privileged information' do
      expect(modify_response.status).to eq(200)
      expect(JSON.parse(modify_response.body)['account_modified']).to eq(true)
    end
  end

  # Test case 7: Account disabling with proper authorization
  describe 'Account disabling with proper authorization' do
    # Login as admin to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Disable a user account with proper authorization
    disable_response = http("#{app_url}/disable_user",
                            method: 'POST',
                            headers: { 
                              'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json'
                            },
                            data: {
                              user_id: 'test_user_to_disable',
                              reason: 'No longer with organization'
                            }.to_json)

    it 'should allow account disabling with proper authorization' do
      expect(disable_response.status).to eq(200)
      expect(JSON.parse(disable_response.body)['account_disabled']).to eq(true)
    end
  end

  # Test case 8: Account disabling without proper authorization
  describe 'Account disabling without proper authorization' do
    # Login as regular user to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'regular_user', 
                            password: 'SecurePassword123'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Attempt to disable a user account without proper authorization
    disable_response = http("#{app_url}/disable_user",
                            method: 'POST',
                            headers: { 
                              'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json'
                            },
                            data: {
                              user_id: 'staff_user',
                              reason: 'Testing unauthorized disabling'
                            }.to_json)

    it 'should deny account disabling without proper authorization' do
      expect(disable_response.status).to eq(403)
      expect(JSON.parse(disable_response.body)['error']).to eq('unauthorized')
    end
  end

  # Test case 9: Account removal with proper authorization
  describe 'Account removal with proper authorization' do
    # Login as admin to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Remove a user account with proper authorization
    remove_response = http("#{app_url}/remove_user",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             user_id: 'test_user_to_remove',
                             removal: {
                               approved_by: 'admin_user',
                               reason: 'Account no longer needed'
                             }
                           }.to_json)

    it 'should allow account removal with proper authorization' do
      expect(remove_response.status).to eq(200)
      expect(JSON.parse(remove_response.body)['account_removed']).to eq(true)
    end
  end

  # Test case 10: Account removal without proper authorization
  describe 'Account removal without proper authorization' do
    # Login as regular user to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'regular_user', 
                            password: 'SecurePassword123'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Attempt to remove a user account without proper authorization
    remove_response = http("#{app_url}/remove_user",
                           method: 'POST',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           },
                           data: {
                             user_id: 'staff_user',
                             removal: {
                               approved_by: 'regular_user',
                               reason: 'Testing unauthorized removal'
                             }
                           }.to_json)

    it 'should deny account removal without proper authorization' do
      expect(remove_response.status).to eq(403)
      expect(JSON.parse(remove_response.body)['error']).to eq('unauthorized')
    end
  end

  # Test case 11: Account expiration enforcement
  describe 'Account expiration enforcement' do
    # Check an expired account
    check_response = http("#{app_url}/check_user",
                          method: 'GET',
                          headers: { 
                            'Authorization' => 'Bearer expired_user_token',
                            'Content-Type' => 'application/json'
                          })

    it 'should enforce account expiration' do
      expect(check_response.status).to eq(401)
      expect(JSON.parse(check_response.body)['error']).to eq('unauthorized')
      expect(JSON.parse(check_response.body)['message']).to eq('account_expired')
    end
  end

  # Test case 12: Account review
  describe 'Account review' do
    # Login as admin to get token
    login_response = http("#{app_url}/login",
                          method: 'POST',
                          headers: { 'Content-Type' => 'application/json' },
                          data: { 
                            username: 'admin_user', 
                            password: 'AdminSecurePass456'
                          }.to_json)

    token = JSON.parse(login_response.body)['access_token']

    # Get account review report
    review_response = http("#{app_url}/account_review",
                           method: 'GET',
                           headers: { 
                             'Authorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json'
                           })

    it 'should provide account review information' do
      expect(review_response.status).to eq(200)
      expect(JSON.parse(review_response.body)).to include('expired_accounts')
      expect(JSON.parse(review_response.body)).to include('inactive_accounts')
      expect(JSON.parse(review_response.body)).to include('locked_accounts')
      expect(JSON.parse(review_response.body)).to include('accounts_requiring_review')
    end
  end

  # Validate OPA logs for account management decisions
  describe file(log_file_path) do
    its('content') { should include 'account_management' }
    its('content') { should include 'account_creation_valid' }
    its('content') { should include 'account_modification_valid' }
    its('content') { should include 'account_disabling_valid' }
    its('content') { should include 'account_removal_valid' }
  end
end
