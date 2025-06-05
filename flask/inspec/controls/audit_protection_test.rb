control 'audit-protection' do
  impact 1.0
  title 'Validate Audit Protection Controls'
  desc 'Ensure that audit information and audit tools are protected from unauthorized access, modification, and deletion (AU-9)'

  app_url = 'http://mock-server:8000'
  log_file_path = './logs/opa_interactions.log'
  audit_log_path = './logs/audit.log'

  # Test case 1: Verify audit access control configuration
  describe 'Audit access control configuration' do
    # Get access control configuration information
    access_control_response = http("#{app_url}/audit_access_control",
                                method: 'GET',
                                headers: {
                                  'Content-Type' => 'application/json',
                                  'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                })

    access_control = JSON.parse(access_control_response.body)

    it 'should have access controls enabled' do
      unless access_control['enabled'] == true
        fail "Access controls are not enabled"
      end
    end

    it 'should have authorized roles configured' do
      unless access_control['authorized_roles'] && access_control['authorized_roles'].length > 0
        fail "No authorized roles configured for audit access"
      end
    end

    it 'should have appropriate access control mechanisms' do
      unless access_control['mechanisms'] && access_control['mechanisms'].length > 0
        fail "No access control mechanisms configured"
      end
    end

    it 'should restrict access to authorized personnel only' do
      unless access_control['authorized_roles'].all? { |role| ['admin', 'security', 'auditor'].include?(role) }
        fail "Access controls allow non-administrative roles: #{access_control['authorized_roles'].join(', ')}"
      end
    end
  end

  # Test case 2: Verify audit encryption configuration
  describe 'Audit encryption configuration' do
    # Get encryption configuration information
    encryption_response = http("#{app_url}/audit_encryption_config",
                            method: 'GET',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                            })

    encryption = JSON.parse(encryption_response.body)

    it 'should have encryption enabled' do
      unless encryption['enabled'] == true
        fail "Encryption is not enabled for audit data"
      end
    end

    it 'should use strong encryption algorithm' do
      strong_algorithms = ['AES-256', 'AES-192', 'AES-128']
      unless strong_algorithms.include?(encryption['algorithm'])
        fail "Weak encryption algorithm: #{encryption['algorithm']}"
      end
    end

    it 'should have key management enabled' do
      unless encryption['key_management'] && encryption['key_management']['enabled'] == true
        fail "Key management is not enabled"
      end
    end

    it 'should have appropriate key rotation policy' do
      unless encryption['key_management']['rotation_days'] <= 90
        fail "Key rotation period too long: #{encryption['key_management']['rotation_days']} days (should be <= 90)"
      end
    end
  end

  # Test case 3: Verify audit integrity configuration
  describe 'Audit integrity configuration' do
    # Get integrity configuration information
    integrity_response = http("#{app_url}/audit_integrity_config",
                            method: 'GET',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                            })

    integrity = JSON.parse(integrity_response.body)

    it 'should have integrity verification enabled' do
      unless integrity['enabled'] == true
        fail "Integrity verification is not enabled"
      end
    end

    it 'should have appropriate integrity mechanisms' do
      unless integrity['mechanisms'] && integrity['mechanisms'].length > 0
        fail "No integrity verification mechanisms configured"
      end
    end

    it 'should have appropriate verification frequency' do
      unless integrity['verification_frequency_hours'] <= 24
        fail "Verification frequency too long: #{integrity['verification_frequency_hours']} hours (should be <= 24)"
      end
    end

    it 'should use cryptographic mechanisms for integrity' do
      crypto_mechanisms = ['hash', 'digital_signature', 'hmac']
      has_crypto = integrity['mechanisms'].any? { |m| crypto_mechanisms.include?(m['type']) }
      unless has_crypto
        fail "No cryptographic mechanisms used for integrity verification"
      end
    end
  end

  # Test case 4: Verify audit backup configuration
  describe 'Audit backup configuration' do
    # Get backup configuration information
    backup_response = http("#{app_url}/audit_backup_config",
                          method: 'GET',
                          headers: {
                            'Content-Type' => 'application/json',
                            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                          })

    backup = JSON.parse(backup_response.body)

    it 'should have backup enabled' do
      unless backup['enabled'] == true
        fail "Backup is not enabled for audit logs"
      end
    end

    it 'should have appropriate backup frequency' do
      unless backup['frequency_hours'] <= 24
        fail "Backup frequency too long: #{backup['frequency_hours']} hours (should be <= 24)"
      end
    end

    it 'should have backup storage location configured' do
      unless backup['storage_location'] && !backup['storage_location'].empty?
        fail "No backup storage location configured"
      end
    end

    it 'should have appropriate backup retention period' do
      unless backup['retention_days'] >= 90
        fail "Backup retention period too short: #{backup['retention_days']} days (should be >= 90)"
      end
    end

    it 'should have backup verification process' do
      unless backup['verification_enabled'] == true
        fail "Backup verification is not enabled"
      end
    end
  end

  # Test case 5: Verify audit tools protection
  describe 'Audit tools protection' do
    # Get tools protection configuration information
    tools_protection_response = http("#{app_url}/audit_tools_protection",
                                    method: 'GET',
                                    headers: {
                                      'Content-Type' => 'application/json',
                                      'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                    })

    tools_protection = JSON.parse(tools_protection_response.body)

    it 'should have tools protection enabled' do
      unless tools_protection['enabled'] == true
        fail "Audit tools protection is not enabled"
      end
    end

    it 'should have appropriate protection mechanisms' do
      unless tools_protection['mechanisms'] && tools_protection['mechanisms'].length > 0
        fail "No protection mechanisms configured for audit tools"
      end
    end

    it 'should restrict tools access to authorized personnel only' do
      unless tools_protection['authorized_roles'] && 
             tools_protection['authorized_roles'].all? { |role| ['admin', 'security', 'auditor'].include?(role) }
        fail "Tools access controls allow non-administrative roles: #{tools_protection['authorized_roles'].join(', ')}"
      end
    end

    it 'should have integrity verification for audit tools' do
      has_integrity = tools_protection['mechanisms'].any? { |m| m['type'] == 'integrity_verification' }
      unless has_integrity
        fail "No integrity verification mechanism for audit tools"
      end
    end
  end

  # Test case 6: Verify deletion protection
  describe 'Deletion protection' do
    # Get deletion protection configuration information
    deletion_protection_response = http("#{app_url}/audit_deletion_protection",
                                      method: 'GET',
                                      headers: {
                                        'Content-Type' => 'application/json',
                                        'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                      })

    deletion_protection = JSON.parse(deletion_protection_response.body)

    it 'should have deletion protection enabled' do
      unless deletion_protection['enabled'] == true
        fail "Deletion protection is not enabled"
      end
    end

    it 'should have appropriate protection mechanisms' do
      unless deletion_protection['mechanisms'] && deletion_protection['mechanisms'].length > 0
        fail "No mechanisms configured for deletion protection"
      end
    end

    it 'should require approval for deletion' do
      unless deletion_protection['requires_approval'] == true
        fail "Approval is not required for audit log deletion"
      end
    end

    it 'should log all deletion attempts' do
      unless deletion_protection['log_attempts'] == true
        fail "Deletion attempts are not logged"
      end
    end
  end

  # Test case 7: Verify modification protection
  describe 'Modification protection' do
    # Get modification protection configuration information
    modification_protection_response = http("#{app_url}/audit_modification_protection",
                                          method: 'GET',
                                          headers: {
                                            'Content-Type' => 'application/json',
                                            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                          })

    modification_protection = JSON.parse(modification_protection_response.body)

    it 'should have modification protection enabled' do
      unless modification_protection['enabled'] == true
        fail "Modification protection is not enabled"
      end
    end

    it 'should have appropriate protection mechanisms' do
      unless modification_protection['mechanisms'] && modification_protection['mechanisms'].length > 0
        fail "No mechanisms configured for modification protection"
      end
    end

    it 'should log all modification attempts' do
      unless modification_protection['log_modifications'] == true
        fail "Modification attempts are not logged"
      end
    end

    it 'should use write-once or immutable storage' do
      has_immutable = modification_protection['mechanisms'].any? { |m| 
        m['type'] == 'write_once' || m['type'] == 'immutable_storage'
      }
      unless has_immutable
        fail "No write-once or immutable storage mechanism configured"
      end
    end
  end

  # Test case 8: Verify OPA policy validation
  describe 'OPA policy validation for audit protection' do
    # Check OPA logs for audit protection validation
    opa_log_content = file(log_file_path).content

    it 'should contain audit protection validation in OPA logs' do
      keywords = %w[audit_access_controls_configured audit_encryption_configured audit_integrity_configured 
                    audit_backup_configured audit_tools_protection_configured deletion_protection_configured 
                    modification_protection_configured]
      missing_keywords = keywords.reject { |keyword| opa_log_content.include?(keyword) }

      unless missing_keywords.empty?
        fail "OPA logs do not contain audit protection validation keywords: #{missing_keywords.join(', ')}"
      end
    end
  end

  # Test case 9: Verify file permissions on audit log
  describe 'Audit log file permissions' do
    # Get file permissions information
    file_permissions_response = http("#{app_url}/audit_file_permissions",
                                    method: 'GET',
                                    headers: {
                                      'Content-Type' => 'application/json',
                                      'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                    })

    file_permissions = JSON.parse(file_permissions_response.body)

    it 'should have restricted file permissions' do
      unless file_permissions['restricted'] == true
        fail "Audit log file permissions are not restricted"
      end
    end

    it 'should have appropriate owner and group' do
      unless ['root', 'audit', 'admin'].include?(file_permissions['owner']) &&
             ['root', 'audit', 'admin'].include?(file_permissions['group'])
        fail "Inappropriate owner/group for audit logs: #{file_permissions['owner']}/#{file_permissions['group']}"
      end
    end

    it 'should have appropriate permission mode' do
      # Check if permission mode is 600, 640, or 644
      unless file_permissions['mode'] == '600' || file_permissions['mode'] == '640' || file_permissions['mode'] == '644'
        fail "Inappropriate permission mode for audit logs: #{file_permissions['mode']}"
      end
    end
  end
end
