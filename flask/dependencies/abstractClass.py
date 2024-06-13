# Abstract classes are useful for defining a common interface that multiple classes can adhere to 
# while enforcing certain methods to be implemented by subclasses.

'''Abstract classes define a common interface through abstract methods, 
ensuring that all subclasses adhere to the same method signatures 
but allowing each subclass to implement those methods differently based on its specific requirements. 
This promotes a consistent structure across related classes while allowing for variations in behavior.'''

# Importing the ABC (Abstract Base Class) module from the abc package
# ABC is the base class for all abstract classes in Python.
# which is the base class for all abstract classes in Python? In what module is it defined?
from abc import ABC, abstractmethod
import requests
import os

# Defining an abstract class named MyAbstractClass that inherits from ABC
class MyAbstractClass(ABC):
    def __init__(self, value):
        self.value = value
        super().__init__()

    # @abstractmethod is a decorator used to declare abstract methods. Abstract methods 
    # have no implementation in the abstract class itself, 
    # and subclasses are required to provide concrete implementations.
    
    @abstractmethod
    def do_something(self):
        pass

   
    @abstractmethod
    def do_something_else(self):
        pass

# Defining a concrete class named DoAdd42 that inherits from AbstractClass
class DoAdd42(MyAbstractClass):
    def do_something(self):
        curDir = os.getcwd()
        print(f"Current directory: {curDir}")
        return self.value + 42

    def do_something_else(self):
        return self.value + 42  
    
    def getWebPage(self):
        # Define the URL you want to make a request to
        url = 'https://google.com/'

        # Send a GET request to the URL
        response = requests.get(url)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Print the response content (the data retrieved from the server)
            print(response.text)
        else:
            # Print an error message if the request was not successful
            print(f"Error: {response.status_code}")

def main_function():
    myObject = DoAdd42(10)
    myObject.getWebPage()
    print(myObject.do_something())
    print(myObject.do_something_else())

# Checking if the current module is the main module
if __name__ == "__main__":
    main_function()
