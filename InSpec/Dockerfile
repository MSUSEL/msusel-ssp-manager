FROM ruby:3.0-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    expect \
    && rm -rf /var/lib/apt/lists/*

# Install InSpec and required gems
RUN gem install inspec-bin && \
    gem install parser && \
    gem install ast

# Create directory for InSpec configuration and licenses
RUN mkdir -p /root/.chef/accepted_licenses

# Copy the InSpec test files
WORKDIR /tests
COPY app_opa_integration.rb .

# Copy and set up scripts
COPY run_tests.sh .
COPY entrypoint.sh .
RUN chmod +x run_tests.sh entrypoint.sh

# Set environment variable for non-interactive license acceptance
ENV CHEF_LICENSE="accept-no-persist"

ENTRYPOINT ["./entrypoint.sh"]
