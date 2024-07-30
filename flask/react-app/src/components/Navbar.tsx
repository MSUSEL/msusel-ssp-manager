import React from 'react';
import { Link } from 'react-router-dom';
import { Flex, Box } from '@radix-ui/themes';

const Navbar: React.FC = () => {
  return (
    <Flex as="nav" justifyContent="space-between" alignItems="center" padding="20px" style={{ backgroundColor: 'white' }}>
      <Box>
        <Link to="/">Home</Link>
      </Box>
      {/* Add more links here if needed */}
    </Flex>
  );
};

export default Navbar;
