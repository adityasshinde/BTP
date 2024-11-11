import r2pipe
import sys


def detect_subroutines(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all
    functions = r2.cmd("afl")  # Get all functions
    return functions


def main():
    binary_path = sys.argv[1]
    result = detect_subroutines(binary_path)
    print("Subroutine Detection Result:")
    print(result)
    print("Termination: subroutine_detection.py script completed successfully.")


if __name__ == "__main__":
    main()
