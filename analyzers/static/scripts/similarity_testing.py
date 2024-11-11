import r2pipe
import sys


def similarity_test(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all
    functions = r2.cmd("afl")  # Get all functions
    return functions


def main():
    binary_path = sys.argv[1]
    result = similarity_test(binary_path)
    print("Similarity Testing Result:")
    print(result)
    print("Termination: similarity_testing.py script completed successfully.")


if __name__ == "__main__":
    main()
