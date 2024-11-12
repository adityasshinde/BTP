import os
import json
import hashlib
import pefile
import mimetypes  # Built-in Python library for file type detection

def get_file_info(file_path):
    """Get basic file information"""
    info = {}
    
    # Get file size
    info['size'] = os.path.getsize(file_path)
    
    # Get file hashes
    with open(file_path, 'rb') as f:
        content = f.read()
        info['md5'] = hashlib.md5(content).hexdigest()
        info['sha1'] = hashlib.sha1(content).hexdigest()
        info['sha256'] = hashlib.sha256(content).hexdigest()
    
    # Get file type using mimetypes
    file_type, encoding = mimetypes.guess_type(file_path)
    info['file_type'] = file_type or "unknown"
    info['file_extension'] = os.path.splitext(file_path)[1]
    
    # Get basic file stats
    stat = os.stat(file_path)
    info['created_time'] = stat.st_ctime
    info['modified_time'] = stat.st_mtime
    info['accessed_time'] = stat.st_atime
    
    return info

def analyze_pe(file_path):
    """Analyze PE file structure"""
    try:
        pe = pefile.PE(file_path)
        pe_info = {
            'machine_type': hex(pe.FILE_HEADER.Machine),
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'characteristics': hex(pe.FILE_HEADER.Characteristics),
            'sections': [],
            'imports': [],
            'exports': []
        }
        
        # Get sections information
        for section in pe.sections:
            pe_info['sections'].append({
                'name': section.Name.decode().rstrip('\x00'),
                'virtual_size': hex(section.Misc_VirtualSize),
                'virtual_address': hex(section.VirtualAddress),
                'raw_size': hex(section.SizeOfRawData),
                'characteristics': hex(section.Characteristics)
            })
        
        # Get imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_imports = {
                    'dll': entry.dll.decode(),
                    'functions': []
                }
                for imp in entry.imports:
                    if imp.name:
                        dll_imports['functions'].append(imp.name.decode())
                pe_info['imports'].append(dll_imports)
        
        # Get exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    pe_info['exports'].append(exp.name.decode())
        
        return pe_info
    except Exception as e:
        return {'error': str(e)}

def run_static_analysis(file_path,output_path):
    print("[INFO] Running static analysis")
        
    try:
        # Gather all analysis results
        analysis_results = {
            'file_info': get_file_info(file_path),
            'pe_analysis': analyze_pe(file_path) if file_path.lower().endswith('.exe') else None
        }
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save results
        with open(output_path, 'w') as f:
            json.dump(analysis_results, f, indent=4)
            
        print(f"[INFO] Static analysis completed. Report saved to {output_path}")
        
    except Exception as e:
        print(f"[ERROR] Static analysis failed: {str(e)}")
        return None

    return output_path
