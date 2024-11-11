import r2pipe
import sys


def analyze_stylometry(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all
    functions = r2.cmd("afl")  # List functions
    return functions


def main():
    binary_path = sys.argv[1]
    result = analyze_stylometry(binary_path)
    print("Code Stylometry Result:")
    print(result)
    print("Termination: stylometry.py script completed successfully.")


if __name__ == "__main__":
    main()
