import pefile
import sys


def analyze_file_relations(binary_path):
    pe = pefile.PE(binary_path)
    relations = {
        "imports": [entry.name for entry in pe.DIRECTORY_ENTRY_IMPORT],
        "exports": [entry.name for entry in pe.DIRECTORY_ENTRY_EXPORT],
    }
    return relations


def main():
    binary_path = sys.argv[1]
    result = analyze_file_relations(binary_path)
    print("File Relations (Imports/Exports):")
    print(result)
    print("Termination: file_relations.py script completed successfully.")


if __name__ == "__main__":
    main()
