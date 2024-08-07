import unittest
from flask import Flask
from app import create_app
import logging


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Create a test class that inherits from unittest.TestCase
class RouteTests(unittest.TestCase): 

    @classmethod
    def setUpClass(cls):
        logger.info("Setting up the Flask test client and environment...")


    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        logger.info("Flask test client set up.")


    def tearDown(self):
        logger.info("Tearing down the test client and environment.")


    # Use the test client to send requests to the routes 
    # and verify the responses using assertions.
    def test_home_route(self):
        response = self.client.get('/api/home/data') # Sends a Get request to the /api/home/data route
        self.assertEqual(response.status_code, 200) # Asserts that the response status code is 200 (OK).
        self.assertIn(b'Hello, World!', response.data) # Asserts that the response data contains the string 'Hello, World!'.
        logger.info("Home route test passed.")
    

    def test_generate_route(self):
        response = self.client.get('/api/generate/ssp') # Sends a Get request to the /api/home/data route
        self.assertEqual(response.status_code, 200) # Asserts that the response status code is 200 (OK).
        self.assertIn(b'SSP generated successfully', response.data) # Asserts that the response data contains the string 'Hello, World!'.
        logger.info("generate route test passed.")

    # Add more tests for service4 to service10 similarly

if __name__ == '__main__':
    unittest.main()