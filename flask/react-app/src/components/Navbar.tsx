import React from 'react';
import { Box, Flex } from '@radix-ui/themes';
import { Link } from 'react-router-dom';
import './Navbar.css';

const Navbar: React.FC = () => {
  return (
    <Flex as="nav" justifycontent="center" alignitems="center" padding="20px" className="navbar">
      <Link to="/" className="nav-link">Home</Link>
      <Link to="/another-page" className="nav-link">Another Page</Link>
    </Flex>
  );
};

export default Navbar;
