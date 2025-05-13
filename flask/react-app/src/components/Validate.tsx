import React from 'react';
import { Box, Heading, Flex, Card, Text, Badge, Grid } from '@radix-ui/themes';
import { MagnifyingGlassIcon, GearIcon, CheckCircledIcon, CrossCircledIcon } from '@radix-ui/react-icons';
import FileUploader from './FileUploader';
import './Validate.css';

const Validate: React.FC = () => {
  return (
    <Box as="div" className="main-content">
      <Heading size="6" className="validate-heading">
        <MagnifyingGlassIcon className="heading-icon" /> Process OSCAL Document
      </Heading>

      <Card className="validate-card">
        <Flex direction="column" gap="4">
          <Box className="validate-description">
            <Text as="p" size="3">
              Upload and process <Badge color="blue">OSCAL</Badge> documents to validate their structure,
              convert between formats, or resolve references. Select the document type and operation below.
            </Text>
          </Box>

          <Grid columns="3" gap="4" className="features-grid">
            <Card className="feature-card">
              <Flex direction="column" align="center" gap="2">
                <Box className="feature-icon validate-icon">
                  <CheckCircledIcon width="24" height="24" />
                </Box>
                <Text as="h3" size="3" weight="bold">Validate</Text>
                <Text as="p" size="2" align="center">
                  Check document structure and content against OSCAL schemas
                </Text>
              </Flex>
            </Card>

            <Card className="feature-card">
              <Flex direction="column" align="center" gap="2">
                <Box className="feature-icon convert-icon">
                  <GearIcon width="24" height="24" />
                </Box>
                <Text as="h3" size="3" weight="bold">Convert</Text>
                <Text as="p" size="2" align="center">
                  Transform between JSON, YAML, and XML formats
                </Text>
              </Flex>
            </Card>

            <Card className="feature-card">
              <Flex direction="column" align="center" gap="2">
                <Box className="feature-icon resolve-icon">
                  <CrossCircledIcon width="24" height="24" />
                </Box>
                <Text as="h3" size="3" weight="bold">Resolve</Text>
                <Text as="p" size="2" align="center">
                  Resolve references and dependencies in profiles
                </Text>
              </Flex>
            </Card>
          </Grid>

          <Box className="uploader-container">
            <FileUploader apiEndpoint="/api/validate/shared"/>
          </Box>
        </Flex>
      </Card>
    </Box>
  );
};

export default Validate;
