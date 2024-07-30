import React from 'react';
import { Box, Heading, Text } from '@radix-ui/themes';

const Sidebar: React.FC = () => {
  return (
    <Box as="div" style={{ padding: '20px', width: '250px', backgroundColor: 'lightgray', height: '100vh' }}>
      <Heading>OSCAL</Heading>
      <Text>Generate Template</Text><br />
      <Text>Edit</Text><br />
      <Text>Validate</Text><br />
      <Text>Convert</Text><br />
      <Text>Current Status</Text><br />
      <Heading>Vulnerability Effectiveness</Heading>
      <Text>Test Dependencies</Text><br />
      <Text>Attack Techniques</Text><br />
      <Text>Attack Paths</Text><br />
      <Text>Priority Controls</Text><br />
      <Text>Vulnerable Functions</Text><br />
      <Heading>BRON Database</Heading>
      <Heading>External Links:</Heading>
      <Text>OSCAL Documentation</Text><br />
      <Text>Tool Documentation</Text>
    </Box>
  );
};

export default Sidebar;
