import os
import subprocess

def run_bulk_extractor(target_image, output_dir):
    """
    Run Bulk Extractor to extract digital artifacts from the target disk image.
    """
    bulk_extractor_output = os.path.join(output_dir, "bulk_extractor_output")
    
    # Run Bulk Extractor
    print("Running Bulk Extractor...")
    subprocess.run(["bulk_extractor", "-o", bulk_extractor_output, target_image])
    
    return bulk_extractor_output

def run_yara(artifact_dir, yara_rules, output_file):
    """
    Run YARA to analyze the extracted artifacts using specified YARA rules.
    """
    # Create an output file to store YARA results
    with open(output_file, "w") as out:
        # Iterate through the files in the artifact directory
        for root, _, files in os.walk(artifact_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # Run YARA on each extracted file
                subprocess.run(["yara", "-r", yara_rules, file_path], stdout=out)
    
    print(f"YARA analysis complete. Results saved to {output_file}")

def generate_report(bulk_extractor_output, yara_output, report_file):
    """
    Generate a consolidated report from Bulk Extractor and YARA outputs.
    """
    with open(report_file, "w") as report:
        report.write("Bulk Extractor Artifact Analysis:\n")
        report.write("-" * 70 + "\n")
        # Write a summary of Bulk Extractor analysis
        for root, _, files in os.walk(bulk_extractor_output):
            for file in files:
                with open(os.path.join(root, file), "r") as f:
                    report.write(f.read())
        
        report.write("\nYARA Pattern-Based Analysis:\n")
        report.write("-" * 70 + "\n")
        # Write the YARA analysis results
        with open(yara_output, "r") as yara_results:
            report.write(yara_results.read())
    
    print(f"Report generated at {report_file}")

def main():
    target_image = "/path/to/target_image.dd"  # Specify the path to the disk image
    yara_rules = "/path/to/yara_rules.yar"    # Specify the path to the YARA rules
    output_dir = "/path/to/output"            # Specify the directory to store outputs
    yara_output_file = "/path/to/yara_results.txt"  # Specify the file for YARA results
    report_file = "/path/to/final_report.txt" # Specify the path for the final report
    
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Step 1: Run Bulk Extractor
    bulk_extractor_output = run_bulk_extractor(target_image, output_dir)  # Activates Bulk Extractor
    
    # Step 2: Run YARA
    run_yara(bulk_extractor_output, yara_rules, yara_output_file)  # Activates YARA
    
    # Step 3: Generate Consolidated Report
    generate_report(bulk_extractor_output, yara_output_file, report_file)

if __name__ == "__main__":
    main()
