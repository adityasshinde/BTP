import r2pipe
import sys


def collect_statistics(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all
    instructions = r2.cmd("pd 1000")  # Disassemble the first 100 bytes
    instruction_count = {}

    for line in instructions.splitlines():
        instr = line.split(" ")[1]
        instruction_count[instr] = instruction_count.get(instr, 0) + 1

    return instruction_count


def main():
    binary_path = sys.argv[1]
    result = collect_statistics(binary_path)
    print("Instruction Statistics:")
    print(result)
    print("Termination: statistics.py script completed successfully.")


if __name__ == "__main__":
    main()
