import React from 'react';
import { Flex, Heading } from '@radix-ui/themes';
import './Header.css';

const Header: React.FC = () => {
  return (
    <Flex as="div" className="header">
      <img src="/assets/cisa.png" alt="CISA Logo" className="logo" />
      <Heading className="title">SSP Manager</Heading>
      <img src="/assets/MSU-core.png" alt="MSU Logo" className="logo" />
    </Flex>
  );
};

export default Header;
