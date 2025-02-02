import json
import logging

def save_json(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def process_reports(static_report_path, dynamic_report_path):
    logging.info(f"started processing reports")
    """
    Processes static and dynamic JSON reports into features.
    """
    # Load static and dynamic reports
    with open(static_report_path, 'r') as f:
        static_features = json.load(f)
    # with open(dynamic_report_path, 'r') as f:
    #     dynamic_features = json.load(f)
    
    # Combine features
    return {**static_features}