control 'system-component-inventory' do
  impact 1.0
  title 'Validate System Component Inventory Controls'
  desc 'Ensure that the system maintains an accurate inventory of system components (CM-8)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'

  # Test case 1: Verify inventory completeness
  describe 'Inventory completeness' do
    # Get inventory information
    inventory_response = http("#{app_url}/inventory_information",
                           method: 'GET',
                           headers: {
                             'Content-Type' => 'application/json',
                             'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                           })

    inventory = JSON.parse(inventory_response.body)

    it 'should have inventory documented' do
      unless inventory['documented'] == true
        fail "Inventory is not documented"
      end
    end

    it 'should include all required components' do
      unless inventory['components'] && inventory['components'].length > 0
        fail "Inventory does not include required components"
      end
    end

    it 'should have complete information for each component' do
      required_fields = ['id', 'type', 'owner', 'location', 'status']
      
      inventory['components'].each do |component|
        missing_fields = required_fields.select { |field| component[field].nil? || component[field].empty? }
        
        unless missing_fields.empty?
          fail "Component #{component['id']} is missing required fields: #{missing_fields.join(', ')}"
        end
      end
    end
  end

  # Test case 2: Verify inventory accuracy
  describe 'Inventory accuracy' do
    # Get inventory accuracy information
    accuracy_response = http("#{app_url}/inventory_accuracy",
                          method: 'GET',
                          headers: {
                            'Content-Type' => 'application/json',
                            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                          })

    accuracy = JSON.parse(accuracy_response.body)

    it 'should match actual system state' do
      unless accuracy['matches_actual_state'] == true
        fail "Inventory does not match actual system state"
      end
    end

    it 'should have been recently verified' do
      last_verified = DateTime.parse(accuracy['last_verified'])
      thirty_days_ago = DateTime.now - 30
      
      unless last_verified > thirty_days_ago
        fail "Inventory has not been verified in the last 30 days"
      end
    end
  end

  # Test case 3: Verify no duplicate components
  describe 'No duplicate components' do
    # Get duplicate check information
    duplicates_response = http("#{app_url}/inventory_duplicates",
                            method: 'GET',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                            })

    duplicates = JSON.parse(duplicates_response.body)

    it 'should not have duplicate components' do
      unless duplicates['has_duplicates'] == false
        fail "Inventory contains duplicate components: #{duplicates['duplicate_ids'].join(', ')}"
      end
    end

    it 'should not include components assigned to other systems' do
      unless duplicates['has_components_from_other_systems'] == false
        fail "Inventory includes components assigned to other systems: #{duplicates['other_system_components'].join(', ')}"
      end
    end
  end

  # Test case 4: Verify appropriate granularity
  describe 'Appropriate granularity' do
    # Get granularity information
    granularity_response = http("#{app_url}/inventory_granularity",
                             method: 'GET',
                             headers: {
                               'Content-Type' => 'application/json',
                               'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                             })

    granularity = JSON.parse(granularity_response.body)

    it 'should have appropriate granularity' do
      unless granularity['granularity_appropriate'] == true
        fail "Inventory does not have appropriate granularity"
      end
    end

    it 'should include hardware components' do
      unless granularity['has_hardware_components'] == true
        fail "Inventory does not include hardware components"
      end
    end

    it 'should include software components' do
      unless granularity['has_software_components'] == true
        fail "Inventory does not include software components"
      end
    end

    it 'should include firmware components' do
      unless granularity['has_firmware_components'] == true
        fail "Inventory does not include firmware components"
      end
    end
  end

  # Test case 5: Verify required information
  describe 'Required information' do
    # Get required information check
    required_info_response = http("#{app_url}/inventory_required_info",
                               method: 'GET',
                               headers: {
                                 'Content-Type' => 'application/json',
                                 'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                               })

    required_info = JSON.parse(required_info_response.body)

    it 'should include all required information fields' do
      unless required_info['includes_all_required_fields'] == true
        fail "Inventory does not include all required information fields: #{required_info['missing_fields'].join(', ')}"
      end
    end

    it 'should include acquisition dates' do
      unless required_info['includes_acquisition_dates'] == true
        fail "Inventory does not include acquisition dates for all components"
      end
    end

    it 'should include component owners' do
      unless required_info['includes_component_owners'] == true
        fail "Inventory does not include owners for all components"
      end
    end
  end

  # Test case 6: Verify regular updates
  describe 'Regular updates' do
    # Get update information
    updates_response = http("#{app_url}/inventory_updates",
                         method: 'GET',
                         headers: {
                           'Content-Type' => 'application/json',
                           'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                         })

    updates = JSON.parse(updates_response.body)

    it 'should have been recently updated' do
      last_updated = DateTime.parse(updates['last_updated'])
      thirty_days_ago = DateTime.now - 30
      
      unless last_updated > thirty_days_ago
        fail "Inventory has not been updated in the last 30 days"
      end
    end

    it 'should have a documented update process' do
      unless updates['update_process_documented'] == true
        fail "Inventory update process is not documented"
      end
    end

    it 'should include all required update steps' do
      unless updates['update_process_steps'] && updates['update_process_steps'].length >= 3
        fail "Inventory update process does not include all required steps"
      end
    end
  end

  # Test case 7: Verify inventory maintenance
  describe 'Inventory maintenance' do
    # Get maintenance information
    maintenance_response = http("#{app_url}/inventory_maintenance",
                             method: 'GET',
                             headers: {
                               'Content-Type' => 'application/json',
                               'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                             })

    maintenance = JSON.parse(maintenance_response.body)

    it 'should have a documented maintenance process' do
      unless maintenance['maintenance_process_documented'] == true
        fail "Inventory maintenance process is not documented"
      end
    end

    it 'should include regular reviews' do
      unless maintenance['includes_regular_reviews'] == true
        fail "Inventory maintenance does not include regular reviews"
      end
    end

    it 'should include verification' do
      unless maintenance['includes_verification'] == true
        fail "Inventory maintenance does not include verification"
      end
    end
  end

  # Test case 8: Verify inventory protection
  describe 'Inventory protection' do
    # Get protection information
    protection_response = http("#{app_url}/inventory_protection",
                            method: 'GET',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                            })

    protection = JSON.parse(protection_response.body)

    it 'should have access controls enabled' do
      unless protection['access_controls_enabled'] == true
        fail "Inventory access controls are not enabled"
      end
    end

    it 'should log inventory changes' do
      unless protection['changes_logged'] == true
        fail "Inventory changes are not logged"
      end
    end

    it 'should have backup' do
      unless protection['has_backup'] == true
        fail "Inventory does not have backup"
      end
    end
  end
end
