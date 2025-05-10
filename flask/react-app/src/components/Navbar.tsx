import React from 'react';
import { Flex } from '@radix-ui/themes';
import { Link } from 'react-router-dom';
import './Navbar.css';

const Navbar: React.FC = () => {
  return (
    <Flex as="nav" justifycontent="center" alignitems="center" className="navbar">
      <Link to="/" className="nav-link">Home</Link>
    </Flex>
  );
};

export default Navbar;
