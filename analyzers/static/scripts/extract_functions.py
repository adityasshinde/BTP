import r2pipe
import sys


def extract_function_names(binary_path):
    # Open the binary file in radare2
    r2 = r2pipe.open(binary_path)

    # Perform an analysis to identify functions
    r2.cmd("aaa")  # Analyze all functions and references

    # List all functions and extract their names
    functions = r2.cmdj("aflj")  # aflj returns functions in JSON format
    function_names = [func["name"] for func in functions] if functions else []

    return function_names


def main():
    # Ensure a binary path is provided
    if len(sys.argv) < 2:
        print("Usage: python extract_functions.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    function_names = extract_function_names(binary_path)

    # Output the extracted function names
    print("Extracted Function Names:")
    for name in function_names:
        print(name)

    print("Termination: extract_functions.py script completed successfully.")


if __name__ == "__main__":
    main()
