import subprocess
import psutil
import json
import time
import os
import winreg
from datetime import datetime
import socket
from collections import defaultdict

class DynamicAnalyzer:
    def __init__(self, file_path, analysis_time=120):
        self.file_path = file_path
        self.analysis_time = analysis_time
        self.report = defaultdict(dict)
        self.process_list = []
        
    def start_monitoring(self):
        # Initialize report structure
        self.report['analysis_metadata'] = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'file_path': self.file_path,
            'sample_name': os.path.basename(self.file_path),
            'sample_hash': self._get_file_hash(self.file_path)
        }
        
    def _get_file_hash(self, file_path):
        import hashlib
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
            
    def _monitor_process(self, pid):
        try:
            process = psutil.Process(pid)
            proc_info = {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'status': process.status(),
                'threads': len(process.threads()),
                'children': [p.pid for p in process.children()]
            }
            return proc_info
        except:
            return None

    def _monitor_network(self, pid):
        try:
            process = psutil.Process(pid)
            connections = []
            for conn in process.connections():
                connection_info = {
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'type': conn.type
                }
                connections.append(connection_info)
            return connections
        except:
            return []

    def _monitor_file_operations(self, pid):
        try:
            process = psutil.Process(pid)
            files = []
            for file in process.open_files():
                file_info = {
                    'path': file.path,
                    'mode': file.mode,
                    'position': file.position if hasattr(file, 'position') else None
                }
                files.append(file_info)
            return files
        except:
            return []

    def run_analysis(self):
        print("[+] Starting dynamic analysis...")
        
        try:
            # Start the sample in sandbox
            sandboxie_start = r"C:\Program Files\Sandboxie-Plus\Start.exe"
            cmd = [sandboxie_start, "/box:Malware_Analysis", self.file_path]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            main_pid = process.pid
            
            # Initialize monitoring
            self.start_monitoring()
            
            # Monitor for specified duration
            start_time = time.time()
            while time.time() - start_time < self.analysis_time:
                # Get all processes
                current_processes = psutil.process_iter(['pid', 'name', 'ppid'])
                print(current_processes)
                
                for proc in current_processes:
                    if proc.info['ppid'] == main_pid or proc.pid == main_pid:
                        pid = proc.info['pid']
                        
                        # Process information
                        proc_info = self._monitor_process(pid)
                        if proc_info:
                            self.report['processes'][str(pid)] = proc_info
                        
                        # Network activity
                        network_info = self._monitor_network(pid)
                        if network_info:
                            self.report['network_activity'][str(pid)] = network_info
                        
                        # File operations
                        file_ops = self._monitor_file_operations(pid)
                        if file_ops:
                            self.report['file_operations'][str(pid)] = file_ops
                
                time.sleep(1)  # Polling interval
                
            # Terminate the process
            process.terminate()
            
            # Add final analysis metadata
            self.report['analysis_metadata']['duration'] = time.time() - start_time
            self.report['analysis_metadata']['status'] = 'completed'
            
            return self.report
            
        except Exception as e:
            self.report['analysis_metadata']['status'] = 'failed'
            self.report['analysis_metadata']['error'] = str(e)
            return self.report

    def save_report(self, output_path):
        """Save the analysis report to a JSON file"""
        with open(output_path, 'w') as f:
            json.dump(self.report, f, indent=4)
        print(f"[+] Report saved to {output_path}")

    def get_feature_vector(self):
        """Extract features from the report for machine learning"""
        features = {
            'process_count': len(self.report['processes']),
            'network_connection_count': sum(len(conns) for conns in self.report['network_activity'].values()),
            'file_operation_count': sum(len(files) for files in self.report['file_operations'].values()),
            'unique_ips': len(set(conn['remote_addr'].split(':')[0] 
                               for conns in self.report['network_activity'].values() 
                               for conn in conns 
                               if conn['remote_addr'])),
            'max_cpu_usage': max((float(p['cpu_percent']) for p in self.report['processes'].values()), default=0),
            'max_memory_usage': max((float(p['memory_percent']) for p in self.report['processes'].values()), default=0),
            'child_process_count': sum(len(p['children']) for p in self.report['processes'].values()),
        }
        return features

def run_dynamic_analysis2(file_path,sandbox_name,output_path):
    # Configuration
    analysis_time = 120 
    
    # Create analyzer instance
    analyzer = DynamicAnalyzer(file_path, analysis_time)
    
    # Run analysis
    print(f"[+] Analyzing sample: {file_path}")
    analyzer.run_analysis()
    
    # Save detailed report
    analyzer.save_report(output_path)
    
    # Extract features for machine learning
    # features = analyzer.get_feature_vector()
    # print("\n[+] Extracted Features:")
    # print(json.dumps(features, indent=4))
