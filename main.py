from core.download_monitor import monitor_downloads
import logging

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(levelname)s - %(message)s')
    print("Starting download monitor...")
    monitor_downloads()