#!/usr/bin/env python

import ast
import sys
import os
import logging
from collections import defaultdict
import json
import importlib
import importlib.util

# Configure a logger for this specific script
def configure_script_logging():
    # Define a custom logging format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - Line: %(lineno)d - %(message)s"

    # Create a specific logger for this script
    script_logger = logging.getLogger('script_logger')
    script_logger.setLevel(logging.INFO)  # Set the logging level

    # Disable propagation to avoid duplicate logs in the root logger
    script_logger.propagate = False

    # Remove all existing handlers attached to this logger (if any)
    if script_logger.hasHandlers():
        script_logger.handlers.clear()

    # Create a console handler with the formatter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))

    # Create a file handler for logging to a file
    file_handler = logging.FileHandler('index.log')
    file_handler.setFormatter(logging.Formatter(log_format))

    # Add the handlers to the logger
    script_logger.addHandler(console_handler)
    script_logger.addHandler(file_handler)

    return script_logger

# Initialize the logger
logger = configure_script_logging()



# Rest of your script
class ReferenceTracker(ast.NodeVisitor):
    def __init__(self, file_name):
        self.file_name = file_name
        self.functions = {}
        self.variables = defaultdict(lambda: {"defined": [], "used": [], "file": self.file_name})
        self.function_calls = defaultdict(lambda: {"lines": [], "file": self.file_name})
        self.classes = {}
        self.imports = []

    def visit_FunctionDef(self, node):
        is_route = False
        # Check for route decorators
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and hasattr(decorator.func, 'attr') and decorator.func.attr == 'route':
                is_route = True

        self.functions[node.name] = {
            "line": node.lineno,
            "args": [arg.arg for arg in node.args.args],
            "returns": self.get_return_type(node),
            "calls": [],
            "docstring": ast.get_docstring(node),
            "file": self.file_name,
            "is_route": is_route  # Flag if this function is a route handler
        }
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.classes[node.name] = {
            "line": node.lineno,
            "methods": [m.name for m in node.body if isinstance(m, ast.FunctionDef)],
        }
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(
                {
                    "name": alias.name,
                    "line": node.lineno,
                    "file": self.file_name,  # Include the file key here
                    "doc_link": self.get_import_doc_link(alias.name),
                }
            )

    def visit_ImportFrom(self, node):
        for alias in node.names:
            full_name = f"{node.module}.{alias.name}"
            self.imports.append(
                {
                    "name": full_name,
                    "line": node.lineno,
                    "file": self.file_name,  # Include the file key here
                    "doc_link": self.get_import_doc_link(full_name),
                }
            )

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.variables[node.id]["defined"].append(node.lineno)
        elif isinstance(node.ctx, ast.Load):
            self.variables[node.id]["used"].append(node.lineno)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            self.function_calls[node.func.id]['lines'].append(node.lineno)
        self.generic_visit(node)

    @staticmethod
    def get_import_doc_link(import_name):
        module_name = import_name.split(".")[0]

        try:
            # Attempt to find the module's specification
            spec = importlib.util.find_spec(module_name)
            if not spec:
                return "No documentation link available"

            # Ensure the spec.origin is an absolute path
            if spec.origin:
                spec_origin_abs = os.path.abspath(spec.origin)
                # Determine if it's a custom module (part of the project)
                if os.path.commonpath([os.getcwd(), spec_origin_abs]) == os.getcwd():
                    return "This is a custom module within the project."

            # Check if it's a standard library module
            if hasattr(sys, 'stdlib_module_names'):
                stdlib_modules = sys.stdlib_module_names  # Available from Python 3.10+
            else:
                stdlib_modules = sys.builtin_module_names

            if module_name in stdlib_modules:
                return f"https://docs.python.org/3/library/{module_name}.html"

            # Otherwise, it must be a third-party module
            return "This is a third-party module. Please refer to the package's documentation."

        except ImportError:
            return "No documentation link available"

    @staticmethod
    def get_return_type(node):
        return_nodes = [n for n in node.body if isinstance(n, ast.Return)]
        if return_nodes and hasattr(return_nodes[0], "annotation"):
            return ast.unparse(return_nodes[0].annotation)
        return "Unknown"



def analyze_python_file(file_path):
    with open(file_path, "r") as file:
        code = file.read()

    tree = ast.parse(code)
    file_name = os.path.basename(file_path)  # Extract the file name from the file path
    tracker = ReferenceTracker(file_name=file_name)  # Pass the file_name to ReferenceTracker
    tracker.visit(tree)

    return {
        "file_path": file_path,
        "filesize": len(code),
        "num_lines": len(code.splitlines()),
        "functions": tracker.functions,
        "classes": tracker.classes,
        "imports": tracker.imports,
        "variables": tracker.variables,
        "function_calls": tracker.function_calls,
    }


def print_file_analysis_terminal(analysis):
    logger.info(f"Analysis of {analysis['file_path']}:")

    def fsize_full(fsize):  # this makes rounded filesize
        if fsize < 1000:
            return f"{fsize} B"
        elif 1000 < fsize < 1000000:
            kib = round(fsize / 1024, 1)
            return f"{kib} KiB"
        else:
            mib = round(fsize / 1048576, 1)
            return f"{mib} MiB"

    fsize = fsize_full(analysis['filesize'])
    logger.info(f"Filesize: {fsize}")
    logger.info(f"Number of lines: {analysis['num_lines']}")

    logger.info("\nFunctions:")
    for name, info in analysis["functions"].items():
        if info.get("is_route"):
            route_info = " (route handler, endpoint)"
            return_type = "Endpoint"
        else:
            route_info = ""
            return_type = info['returns'] if info['returns'] != "Unknown" else "Unknown return type"

        logger.info(
            f"- {name}({', '.join(info['args'])}) -> {return_type} (line {info['line']}) in {info['file']}{route_info}"
        )
        if info["docstring"]:
            logger.info(f"  Docstring: {info['docstring'].split()[0]}...")
        else:
            logger.info("  Adding a docstring would greatly improve the readability and maintainability of the code.")

        if info["calls"]:
            logger.info(f"  Called on lines: {', '.join(map(str, info['calls']))}")

    logger.info("\nClasses:")
    for name, info in analysis["classes"].items():
        logger.info(f"- {name} (line {info['line']}) in {info['file']}")
        for method in info["methods"]:
            logger.info(f"  - {method}")

    logger.info("\nImports:")
    for imp in analysis["imports"]:
        logger.info(f"- {imp['name']} (line {imp['line']}) in {imp['file']}")
        logger.info(f"  Documentation: {imp['doc_link']}")

    logger.info("\nVariables:")
    for var, info in analysis["variables"].items():
        if info["defined"] or info["used"]:
            logger.info(f"- {var} (in {info['file']}):")

            if info["defined"]:
                defined = ", ".join(map(str, info["defined"]))
                logger.info(f"  Defined on lines: {defined}")
            else:
                logger.info(f"  {var} is not defined in this file; likely imported from elsewhere.")

            if info["used"]:
                used = ", ".join(map(str, info["used"]))
                logger.info(f"  Used on lines: {used}")
            else:
                logger.info("  Not used in this file.")

    logger.info("\nFunction Calls:")
    for func, data in analysis["function_calls"].items():
        lines = ', '.join(map(str, data["lines"]))
        logger.info(f"- {func}: called on lines {lines} in {data['file']}")



def generate_json_report(analysis):
    return json.dumps(analysis, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        logger.error("Usage: python analyzer.py <path_to_python_file_or_project> [--json]")
        sys.exit(1)

    path = sys.argv[1]
    output_json = len(sys.argv) == 3 and sys.argv[2] == "--json"

    if os.path.isfile(path):
        if not path.endswith(".py"):
            logger.error(f"Error: {path} is not a Python file")
            sys.exit(1)
        analysis = analyze_python_file(path)
        if output_json:
            print(generate_json_report(analysis))
        else:
            print_file_analysis_terminal(analysis)
    else:
        logger.error(f"Error: {path} is not a valid file")
        sys.exit(1)
