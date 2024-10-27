# analyzers/dynamic_analyzer.py
import subprocess
import json
import os
import time
import psutil

def monitor_process(pid, duration=30):
    """Monitor process activities"""
    activities = {
        'cpu_usage': [],
        'memory_usage': [],
        'open_files': [],
        'network_connections': [],
        'children': []
    }
    
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            process = psutil.Process(pid)
            
            # Record CPU and memory usage
            activities['cpu_usage'].append(process.cpu_percent())
            activities['memory_usage'].append(process.memory_percent())
            
            # Record open files
            try:
                activities['open_files'].extend([f.path for f in process.open_files()])
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Record network connections
            try:
                activities['network_connections'].extend([
                    {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    }
                    for conn in process.connections()
                ])
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Record child processes
            try:
                children = process.children(recursive=True)
                for child in children:
                    activities['children'].append({
                        'pid': child.pid,
                        'name': child.name(),
                        'status': child.status()
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            time.sleep(1)
            
        except psutil.NoSuchProcess:
            print("[INFO] Process has terminated")
            break
        except Exception as e:
            print(f"[ERROR] Monitoring error: {str(e)}")
            break
    
    return activities

def run_dynamic_analysis(file_path,sandbox_name,output_path):
    print("[INFO] Running dynamic analysis")
    
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Start the process and get its PID
        process = subprocess.Popen([file_path], shell=True)
        pid = process.pid
        
        print(f"[INFO] Started process with PID: {pid}")
        
        # Monitor the process
        activities = monitor_process(pid)
        
        # Save results
        with open(output_path, 'w') as f:
            json.dump(activities, f, indent=4)
            
        print(f"[INFO] Dynamic analysis completed. Report saved to {output_path}")
        
    except Exception as e:
        print(f"[ERROR] Dynamic analysis failed: {str(e)}")
        return None

    return output_path