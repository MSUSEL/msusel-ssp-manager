#!/usr/bin/env python3
"""
Profile Launcher - Clean Subprocess Isolation

This script launches the Python profiler in a completely isolated subprocess
to prevent module name shadowing issues. User projects often contain files
with names that shadow Python's standard library modules (e.g., importlib.py,
os.py, pstats.py, token.py, etc.). This launcher ensures that the profiler
runs in a clean environment where Python's standard library always takes
precedence.

Key Features:
- Clean Python environment (no inherited sys.path contamination)
- Isolated subprocess execution
- Proper error handling and communication
- Environment variable-based configuration
"""

import os
import sys
import subprocess
import logging
import json
from pathlib import Path

logging.basicConfig(level=logging.INFO)

class ProfilerLauncher:
    """
    Handles clean subprocess execution of the Python profiler.
    """
    
    def __init__(self, module_name, function_name, dependencies_path, artifacts_path):
        """
        Initialize the profiler launcher.
        
        Args:
            module_name (str): Name of the user module to profile
            function_name (str): Name of the function to profile
            dependencies_path (str): Path to the user's project dependencies
            artifacts_path (str): Path where profile output should be saved
        """
        self.module_name = module_name
        self.function_name = function_name
        self.dependencies_path = os.path.abspath(dependencies_path)
        self.artifacts_path = os.path.abspath(artifacts_path)
        self.profiler_script_path = None
        
        logging.info(f"ProfilerLauncher initialized:")
        logging.info(f"  Module: {self.module_name}")
        logging.info(f"  Function: {self.function_name}")
        logging.info(f"  Dependencies: {self.dependencies_path}")
        logging.info(f"  Artifacts: {self.artifacts_path}")
    
    def prepare_profiler_script(self):
        """
        Copy the dynamicCallGraph.py script to a temporary location.
        
        Returns:
            str: Path to the copied profiler script
        """
        try:
            # Get the current directory and source script path
            current_dir = os.getcwd()

            # Check if we're already in the app directory or need to navigate to it
            if os.path.basename(current_dir) == "app":
                # We're already in the app directory
                source_script = os.path.join(current_dir, "dynamicCallGraph.py")
            else:
                # We're in the project root, need to go to app directory
                source_script = os.path.join(current_dir, "app", "dynamicCallGraph.py")
            
            # Create temporary directory for the profiler script
            temp_dir = os.path.join(current_dir, "tmp")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Copy the profiler script to temp directory
            import shutil
            temp_script_path = os.path.join(temp_dir, "dynamicCallGraph.py")
            shutil.copy2(source_script, temp_script_path)
            
            self.profiler_script_path = temp_script_path
            logging.info(f"Profiler script copied to: {temp_script_path}")
            
            return temp_script_path
            
        except Exception as e:
            logging.error(f"Failed to prepare profiler script: {e}")
            raise
    
    def create_clean_environment(self):
        """
        Create a clean Python environment for the subprocess.
        
        Returns:
            dict: Clean environment variables for subprocess
        """
        # Start with a minimal environment
        clean_env = {
            # Essential system variables
            'PATH': os.environ.get('PATH', ''),
            'HOME': os.environ.get('HOME', ''),
            'USER': os.environ.get('USER', ''),
            'LANG': os.environ.get('LANG', 'C.UTF-8'),
            'LC_ALL': os.environ.get('LC_ALL', 'C.UTF-8'),
            
            # Python-specific variables (clean slate)
            'PYTHONPATH': '',  # Start with empty PYTHONPATH
            'PYTHONDONTWRITEBYTECODE': '1',  # Prevent .pyc files
            'PYTHONUNBUFFERED': '1',  # Unbuffered output
            
            # Custom variables for our profiler
            'USER_PROJECT_PATH': self.dependencies_path,
            'ARTIFACTS_PATH': self.artifacts_path,
            'PROFILER_MODULE_NAME': self.module_name,
            'PROFILER_FUNCTION_NAME': self.function_name,
        }
        
        logging.info("Created clean environment for subprocess:")
        logging.info(f"  USER_PROJECT_PATH: {clean_env['USER_PROJECT_PATH']}")
        logging.info(f"  ARTIFACTS_PATH: {clean_env['ARTIFACTS_PATH']}")
        logging.info(f"  PYTHONPATH: '{clean_env['PYTHONPATH']}'")
        
        return clean_env
    
    def launch_profiler_subprocess(self):
        """
        Launch the profiler in a clean subprocess.
        
        Returns:
            tuple: (success: bool, stdout: str, stderr: str, returncode: int)
        """
        try:
            # Prepare the profiler script
            profiler_script = self.prepare_profiler_script()
            
            # Create clean environment
            clean_env = self.create_clean_environment()
            
            # Prepare the command
            command = [
                sys.executable,  # Use the same Python interpreter
                profiler_script,
                self.module_name,
                self.function_name
            ]
            
            logging.info(f"Launching profiler subprocess:")
            logging.info(f"  Command: {' '.join(command)}")
            logging.info(f"  Working directory: {os.path.dirname(profiler_script)}")
            
            # Launch the subprocess with clean environment
            result = subprocess.run(
                command,
                cwd=os.path.dirname(profiler_script),  # Run from temp directory
                env=clean_env,  # Use clean environment
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            success = result.returncode == 0
            
            logging.info(f"Profiler subprocess completed:")
            logging.info(f"  Return code: {result.returncode}")
            logging.info(f"  Success: {success}")
            
            if result.stdout:
                logging.info(f"  Stdout: {result.stdout}")
            
            if result.stderr:
                if success:
                    logging.info(f"  Stderr: {result.stderr}")
                else:
                    logging.error(f"  Stderr: {result.stderr}")
            
            return success, result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired as e:
            error_msg = f"Profiler subprocess timed out after 5 minutes"
            logging.error(error_msg)
            return False, "", error_msg, -1
            
        except Exception as e:
            error_msg = f"Failed to launch profiler subprocess: {e}"
            logging.error(error_msg)
            return False, "", error_msg, -1
    
    def cleanup(self):
        """
        Clean up temporary files created during profiling.
        """
        try:
            if self.profiler_script_path and os.path.exists(self.profiler_script_path):
                os.remove(self.profiler_script_path)
                logging.info(f"Cleaned up temporary profiler script: {self.profiler_script_path}")
                
                # Also try to remove the temp directory if it's empty
                temp_dir = os.path.dirname(self.profiler_script_path)
                try:
                    os.rmdir(temp_dir)
                    logging.info(f"Cleaned up temporary directory: {temp_dir}")
                except OSError:
                    # Directory not empty, that's fine
                    pass
                    
        except Exception as e:
            logging.warning(f"Failed to cleanup temporary files: {e}")
    
    def run(self):
        """
        Execute the complete profiling process.
        
        Returns:
            bool: True if profiling succeeded, False otherwise
        """
        try:
            logging.info("=== Starting Clean Subprocess Profiling ===")
            
            # Launch the profiler in clean subprocess
            success, stdout, stderr, returncode = self.launch_profiler_subprocess()
            
            if success:
                logging.info("=== Profiling Completed Successfully ===")
                
                # Verify that the output file was created
                expected_output = os.path.join(self.artifacts_path, "profile_data.json")
                if os.path.exists(expected_output):
                    logging.info(f"Profile output verified at: {expected_output}")
                else:
                    logging.warning(f"Profile output not found at expected location: {expected_output}")
                    success = False
            else:
                logging.error("=== Profiling Failed ===")
                logging.error(f"Return code: {returncode}")
                if stderr:
                    logging.error(f"Error output: {stderr}")
            
            return success
            
        except Exception as e:
            logging.error(f"Profiling process failed with exception: {e}")
            return False
            
        finally:
            # Always cleanup temporary files
            self.cleanup()


def main():
    """
    Main entry point for the profiler launcher.
    Can be called directly or imported as a module.
    """
    if len(sys.argv) != 5:
        print("Usage: python3 profileLauncher.py <module_name> <function_name> <dependencies_path> <artifacts_path>")
        sys.exit(1)
    
    module_name = sys.argv[1]
    function_name = sys.argv[2]
    dependencies_path = sys.argv[3]
    artifacts_path = sys.argv[4]
    
    launcher = ProfilerLauncher(module_name, function_name, dependencies_path, artifacts_path)
    success = launcher.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
