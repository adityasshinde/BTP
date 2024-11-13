import r2pipe
import sys


def disassemble(binary_path):
    # Open the binary in radare2
    r2 = r2pipe.open(binary_path)

    # Perform full analysis to identify functions and entry points
    r2.cmd("aaa")  # Analyze all functions and references
    entry_points = r2.cmdj("aflj")  # Get function list in JSON format for entry points

    # Disassemble the code starting from each function's entry point
    disassembly = {}
    for entry in entry_points:
        entry_addr = entry["offset"]
        disassembly[entry_addr] = r2.cmd(
            f"pd 10000 @ {entry_addr}"
        )  # Disassemble 10000 bytes from each entry point

    return disassembly


def main():
    if len(sys.argv) < 2:
        print("Usage: python disassemble.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    disassembly = disassemble(binary_path)

    print("Disassembly Results:")
    for entry, disasm in disassembly.items():
        print(f"Entry point at {entry}:")
        print(disasm)

    print("Termination: disassemble.py script completed successfully.")


if __name__ == "__main__":
    main()
