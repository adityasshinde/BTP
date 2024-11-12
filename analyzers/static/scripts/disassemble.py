import r2pipe
import sys


def decompile(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all
    decomp = r2.cmd("pd 1000")
    return decomp


def main():
    binary_path = sys.argv[1]
    result = decompile(binary_path)
    print("Decompilation Result:")
    print(result)
    print("Termination: decompilation.py script completed successfully.")


if __name__ == "__main__":
    main()
