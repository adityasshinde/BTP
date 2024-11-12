from core.download_monitor import monitor_downloads
import logging
import time
import psutil
import tracemalloc

def measure_performance():
    # Start the timer and tracemalloc for memory tracking
    start_time = time.time()
    tracemalloc.start()
    
    # Measure the initial memory usage and CPU time
    process = psutil.Process()
    initial_cpu_times = process.cpu_times()
    initial_memory = process.memory_info().rss  # Resident Set Size (RSS) in bytes

    # Run the function
    print("Starting download monitor...")
    monitor_downloads()

    # Capture the end memory usage and CPU time
    end_memory = process.memory_info().rss
    end_cpu_times = process.cpu_times()
    
    # Stop tracemalloc and calculate time
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    end_time = time.time()
    
    # Calculate results
    execution_time = end_time - start_time
    memory_usage = end_memory - initial_memory
    cpu_time_user = end_cpu_times.user - initial_cpu_times.user
    cpu_time_system = end_cpu_times.system - initial_cpu_times.system
    
    # Log the results
    logging.info(f"Up Time: {execution_time:.2f} seconds")
    logging.info(f"CPU Time (User): {cpu_time_user:.2f} seconds")
    logging.info(f"CPU Time (System): {cpu_time_system:.2f} seconds")
    logging.info(f"Memory Usage (Current): {current / 1024**2:.2f} MB")
    logging.info(f"Memory Usage (Peak): {peak / 1024**2:.2f} MB")
    logging.info(f"RAM Usage Difference: {memory_usage / 1024**2:.2f} MB")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(levelname)s - %(message)s')
    measure_performance()
