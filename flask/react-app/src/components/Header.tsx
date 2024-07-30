import React from 'react';
import { Flex, Heading } from '@radix-ui/themes';

const Header: React.FC = () => {
  return (
    <Flex as="div" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '20px', backgroundColor: 'white' }}>
      <img src="/assets/cisa.png" alt="img" style={{ height: '40px' }} />
      <Heading>SSP Manager</Heading>
      <img src="/assets/MSU-core.png" alt="img" style={{ height: '40px' }} />
    </Flex>
  );
};

export default Header;
