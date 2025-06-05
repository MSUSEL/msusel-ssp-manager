# Simple InSpec test to trigger license activation
# Run with: inspec exec license_activation_test.rb

control 'license-activation' do
  impact 0.1
  title 'InSpec License Activation Test'
  desc 'This is a simple test to trigger the InSpec license activation prompt'

  describe file('/tmp') do
    it { should exist }
    it { should be_directory }
  end

  describe os.family do
    it { should be_in ['redhat', 'debian', 'windows', 'darwin'] }
  end

  describe 'License activation' do
    skip 'This test is just to trigger the license activation prompt'
  end
end