import cProfile
import pstats
import json
import importlib
import sys
import logging
import os

logging.basicConfig(level=logging.INFO)

def dynamic_import(module_name, function_name):
    try:
        logging.info(f"Importing module '{module_name}'...")
        # Import the module dynamically
        module = importlib.import_module(module_name)
        function = getattr(module, function_name)
        print(f"Module '{module_name}' imported successfully!")
    except ImportError:
        print(f"Failed to import module '{module_name}'")
    
    return module, function


def runProfiler(main_function):
    # Start profiling
    profiler = cProfile.Profile()
    profiler.enable()

    # Run program
    main_function()

    # Stop profiling
    profiler.disable()

    # Save profiling data in a Stats object
    stats = pstats.Stats(profiler)

    # Convert profiling data to a JSON-compatible dictionary
    stats_dict = {
        "functions": [],
        "total_time": stats.total_tt,
        "primitive_calls": stats.prim_calls,
        "total_calls": stats.total_calls,
    }

    for func in stats.stats:
        filename, line_number, func_name = func
        stats_dict["functions"].append({
            "filename": filename,
            "line_number": line_number,
            "function_name": func_name,
            "total_time": stats.stats[func][2],
            "ncalls": stats.stats[func][0],
            "ccalls": stats.stats[func][1],
            "nactualcalls": stats.stats[func][3],
        })

    # Save the JSON data to a file
    # get current directory
    currentDir = os.getcwd()
    logging.info(f"Current directory: {currentDir}")
    with open("./app/artifacts/profile_data.json", "w") as json_file:
        json.dump(stats_dict, json_file, indent=4)

'''
def startProfiler(module_name, function_name):
    module, function_name  = dynamic_import(module_name, function_name)
    runProfiler(function_name)
'''

if __name__ == "__main__":
    module_name = sys.argv[1]
    function_name = sys.argv[2]
    module, function_name  = dynamic_import(module_name, function_name)
    logging.info(f"Running profiler for function '{function_name}' in module '{module_name}'")
    runProfiler(function_name)
    logging.info("Profiling completed!")