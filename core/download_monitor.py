import time
import os
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.sandbox_manager import create_sandbox, move_to_sandbox, discard_file
from analyzers.static.static_analysis_master import run_static_analysis
from analyzers.dynamic_analyzer import run_dynamic_analysis
from analyzers.dyn import run_dynamic_analysis2

# Get the Downloads folder path dynamically
DOWNLOADS_FOLDER = os.path.join(os.path.expanduser('~'), 'Downloads')

class DownloadHandler():
    def __init__(self):
        super().__init__()
        self.processing_files = set()
        logging.info(f"Monitoring directory: {DOWNLOADS_FOLDER}")

    def on_downloaded(self, event):
        try:

            file_path = event.src_path
            if file_path in self.processing_files:
                return

            # Check if it's a file and ends with .exe
            if not os.path.isfile(file_path) or not file_path.lower().endswith('.exe'):
                return

            self.processing_files.add(file_path)
            logging.info(f"New .exe file detected: {file_path}")

            # Wait for the file to be completely downloaded
            self._wait_for_file_completion(file_path)

            # Process the file
            sandboxed_file=self._process_executable(file_path)
            
            #To be implemented
            # ML classification model to determine if the file is benign or malicious
            
            # if sandboxed_file: # If the file is benign
            #     # Move the file to the Downloads folder
            #     move_to_downloads(sandboxed_file)
            # else:    
            #     discard_file(file_path)
            
            
        except Exception as e:
            logging.error(f"Error processing file {event.src_path}: {str(e)}")
        # finally:
        #     if event.src_path in self.processing_files:
        #         self.processing_files.remove(event.src_path)

    def _wait_for_file_completion(self, file_path, timeout=5, check_interval=1):
        """Wait for the file to be completely downloaded."""
        start_time = time.time()
        last_size = -1

        while time.time() - start_time < timeout:
            try:
                current_size = os.path.getsize(file_path)
                if current_size == last_size and current_size > 0:
                    logging.info(f"File {file_path} appears to be completely downloaded")
                    return True
                last_size = current_size
                time.sleep(check_interval)
            except (OSError, FileNotFoundError) as e:
                logging.warning(f"Error checking file size: {str(e)}")
                time.sleep(check_interval)

        logging.warning(f"Timeout waiting for file {file_path} to complete downloading")
        return False

    def _process_executable(self, file_path):
        """Process the detected executable file."""
        try:
            # Generate a unique ID for this analysis
            analysis_id = str(int(time.time()))
            
            # Create output directories
            result_dir = os.path.join("results", analysis_id)
            os.makedirs(os.path.join(result_dir, "static"), exist_ok=True)
            os.makedirs(os.path.join(result_dir, "dynamic"), exist_ok=True)

            # Step 1: Create sandbox and move file
            sandbox_name = create_sandbox()
            sandboxed_file = move_to_sandbox(file_path)
            logging.info(f"File moved to sandbox: {sandboxed_file}")
            
            # Step 2: Run analyses
            static_report = os.path.join(result_dir, "static", "static_report.json")
            dynamic_report = os.path.join(result_dir, "dynamic", "dynamic_report.json")
            
            run_static_analysis(sandboxed_file, output_path=static_report)
            #run_dynamic_analysis(sandboxed_file, sandbox_name, output_path=dynamic_report)
            #run_dynamic_analysis2(sandboxed_file, sandbox_name, output_path=dynamic_report)
            
            logging.info(f"Analysis completed. Reports saved in {result_dir}")
            return sandboxed_file

        except Exception as e:
            logging.error(f"Error processing executable {file_path}: {str(e)}")

def created(event):
    print(f"{event.src_path} has been created!")

def modified(event):
    print(f"{event.src_path} has been modified")
    
def deleted(event):
    print(f"{event.src_path} has been deleted")
 
def moved(event):
    print(f"{event.src_path} has been moved to {event.dest_path}")      
    
def monitor_downloads():
    try:
        if not os.path.exists(DOWNLOADS_FOLDER):
            raise FileNotFoundError(f"Downloads folder not found: {DOWNLOADS_FOLDER}")
        
        event_handler = FileSystemEventHandler()
        
        download_handler = DownloadHandler()
        event_handler.on_created = download_handler.on_downloaded
        event_handler.on_modified = download_handler.on_downloaded
        event_handler.on_deleted = deleted
        event_handler.on_moved = moved
        
        observer = Observer()
        observer.schedule(event_handler, DOWNLOADS_FOLDER, recursive=True)
        observer.start()
        logging.info(f"Successfully started monitoring {DOWNLOADS_FOLDER}")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Stopping download monitor...")
            observer.stop()
            
        observer.join()

    except Exception as e:
        logging.error(f"Failed to start download monitor: {str(e)}")
        raise
    
def move_to_downloads(file_path):
    """Move the file to the Downloads folder."""
    try:
        if not os.path.exists(DOWNLOADS_FOLDER):
            os.makedirs(DOWNLOADS_FOLDER, exist_ok=True)
        
        # Get the filename
        filename = os.path.basename(file_path)
        dest_path = os.path.join(DOWNLOADS_FOLDER, filename)
        
        # Move the file
        os.replace(file_path, dest_path)
        logging.info(f"File moved to Downloads folder: {dest_path}")
        return dest_path
    
    except Exception as e:
        logging.error(f"Error moving file to Downloads folder: {str(e)}")
        return None