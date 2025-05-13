import React from 'react';
import { Box, Heading, Flex, Card, Text, Badge } from '@radix-ui/themes';
import { FileIcon, LightningBoltIcon, CheckCircledIcon } from '@radix-ui/react-icons';
import GenTemplateFileUploader from './GenTemplateFileUploader';
import './GenerateTemplate.css';

const GenerateTemplate: React.FC = () => {
  return (
    <Box as="div" className="main-content">
      <Heading size="6" className="template-heading">
        <FileIcon className="heading-icon" /> Generate Template
      </Heading>

      <Card className="template-card">
        <Flex direction="column" gap="4">
          <Box className="template-description">
            <Text as="p" size="3">
              Create a standardized <Badge color="blue">OSCAL</Badge> System Security Plan template
              from your profile document. This process helps you establish a consistent
              security baseline for your system.
            </Text>
          </Box>

          <Flex className="process-steps" gap="3">
            <Box className="step">
              <Badge color="blue" radius="full">1</Badge>
              <Text size="2">Select Profile</Text>
            </Box>
            <Box className="step-arrow">→</Box>
            <Box className="step">
              <Badge color="blue" radius="full">2</Badge>
              <Text size="2">Upload File</Text>
            </Box>
            <Box className="step-arrow">→</Box>
            <Box className="step">
              <Badge color="green" radius="full">
                <CheckCircledIcon />
              </Badge>
              <Text size="2">Generate SSP</Text>
            </Box>
          </Flex>

          <Box className="uploader-container">
            <LightningBoltIcon className="lightning-icon" />
            <GenTemplateFileUploader apiEndpoint="/api/generate/ssp"/>
          </Box>
        </Flex>
      </Card>
    </Box>
  );
};

export default GenerateTemplate;
