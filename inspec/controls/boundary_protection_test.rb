# encoding: utf-8
# copyright: 2023, The Authors

title 'Validate Boundary Protection'

control 'boundary-protection-policy' do
  impact 1.0
  title 'Validate Boundary Protection'
  desc 'Verify that boundary protection mechanisms are properly implemented and enforced'

  # Test firewall configuration
  describe 'Firewall configuration' do
    it 'should have firewall enabled' do
      response = http('http://localhost:8000/firewall_config',
                     method: 'GET',
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(200)
      json_response = JSON.parse(response.body)
      expect(json_response['enabled']).to eq(true)
    end
  end

  # Test default deny policy
  describe 'Default deny policy' do
    it 'should have default deny policy configured' do
      response = http('http://localhost:8000/firewall_config',
                     method: 'GET',
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(200)
      json_response = JSON.parse(response.body)
      expect(json_response['default_policy']).to eq('deny')
    end
  end

  # Test for overly permissive rules
  describe 'Firewall rules' do
    it 'should not have overly permissive rules' do
      response = http('http://localhost:8000/firewall_rules',
                     method: 'GET',
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(200)
      json_response = JSON.parse(response.body)
      
      # Check for overly permissive rules
      overly_permissive = json_response['rules'].any? do |rule|
        rule['source'] == 'any' && 
        rule['destination'] == 'any' && 
        rule['port'] == 'any' && 
        rule['action'] == 'allow'
      end
      
      expect(overly_permissive).to eq(false)
    end
  end

  # Test network segmentation
  describe 'Network segmentation' do
    it 'should have proper network segmentation' do
      response = http('http://localhost:8000/network_zones',
                     method: 'GET',
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(200)
      json_response = JSON.parse(response.body)
      
      # Check for at least 2 zones
      expect(json_response['zones'].length).to be >= 2
    end
  end

  # Test zone access controls
  describe 'Zone access controls' do
    it 'should have access controls between zones' do
      response = http('http://localhost:8000/zone_access_controls',
                     method: 'GET',
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(200)
      json_response = JSON.parse(response.body)
      
      # Check that there are access controls defined
      expect(json_response['access_controls'].length).to be > 0
    end
  end

  # Test intrusion detection
  describe 'Intrusion detection' do
    it 'should have intrusion detection enabled' do
      response = http('http://localhost:8000/intrusion_detection',
                     method: 'GET',
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(200)
      json_response = JSON.parse(response.body)
      
      expect(json_response['enabled']).to eq(true)
      expect(json_response['updated_within_days']).to be <= 7
      expect(json_response['monitoring_active']).to eq(true)
    end
  end

  # Test boundary monitoring
  describe 'Boundary monitoring' do
    it 'should have boundary monitoring enabled' do
      response = http('http://localhost:8000/boundary_monitoring',
                     method: 'GET',
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(200)
      json_response = JSON.parse(response.body)
      
      expect(json_response['enabled']).to eq(true)
      expect(json_response['alert_on_unauthorized']).to eq(true)
      expect(json_response['monitored_points'].length).to be > 0
    end
  end

  # Test unauthorized access attempt
  describe 'Unauthorized access attempt' do
    it 'should block unauthorized access attempts' do
      response = http('http://localhost:8000/test_boundary_access',
                     method: 'POST',
                     data: { source_ip: '203.0.113.1', destination: 'database' }.to_json,
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(403)
      json_response = JSON.parse(response.body)
      expect(json_response['allowed']).to eq(false)
    end
  end

  # Test authorized access attempt
  describe 'Authorized access attempt' do
    it 'should allow authorized access attempts' do
      response = http('http://localhost:8000/test_boundary_access',
                     method: 'POST',
                     data: { source_ip: '10.0.0.5', source_type: 'internal', destination: 'web' }.to_json,
                     headers: { 'Content-Type' => 'application/json' })
      
      expect(response.status).to eq(200)
      json_response = JSON.parse(response.body)
      expect(json_response['allowed']).to eq(true)
    end
  end

  # Check OPA interactions log for boundary protection decisions
  describe file('./logs/opa_interactions.log') do
    its('content') { should include 'security.boundary_protection' }
    its('content') { should include 'allow_network_traffic' }
    its('content') { should include 'firewall_rules_valid' }
    its('content') { should include 'network_segmentation_valid' }
  end
end
