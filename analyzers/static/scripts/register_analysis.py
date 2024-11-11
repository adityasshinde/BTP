import r2pipe
import sys


def analyze_registers(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all
    register_data = r2.cmd("drr")  # Display register content
    return register_data


def main():
    binary_path = sys.argv[1]
    result = analyze_registers(binary_path)
    print("Register Analysis Result:")
    print(result)
    print("Termination: register_analysis.py script completed successfully.")


if __name__ == "__main__":
    main()
