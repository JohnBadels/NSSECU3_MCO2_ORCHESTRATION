import os
import shutil
import subprocess
import json

def get_input_path():
    return input("Enter the path of the input file or directory: ")

def get_output_path():
    return input("Enter the path for the output directory: ")

def clear_output_directory(output_path):
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    os.makedirs(output_path)

def run_bulk_extractor(input_path, output_path):
    print(f"Running Bulk Extractor on {input_path}...")
    command = f"bulk_extractor -o {output_path} {input_path}"
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Bulk Extractor scan completed. Results saved to {output_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error running Bulk Extractor: {e}")
        exit(1)

def run_yara(yara_rule, bulk_extractor_output, output_path):
    yara_output = os.path.join(output_path, "yara_results.txt")
    print(f"Running YARA on {bulk_extractor_output}...")
    command = f"yara -r {yara_rule} {bulk_extractor_output} > {yara_output}"
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"YARA scan completed. Results saved to {yara_output}")
    except subprocess.CalledProcessError as e:
        print(f"Error running YARA: {e}")
        exit(1)
    except FileNotFoundError:
        print("YARA is not installed or not in the system PATH.")
        exit(1)
    return yara_output

def create_consolidated_report(bulk_output_path, yara_output_file, report_file):
    report_data = {
        "bulk_extractor_results": {},
        "yara_results": []
    }

    # Add Bulk Extractor results
    bulk_files = os.listdir(bulk_output_path)
    for file in bulk_files:
        file_path = os.path.join(bulk_output_path, file)
        if os.path.isfile(file_path):
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                report_data["bulk_extractor_results"][file] = content

    # Add YARA results
    with open(yara_output_file, 'r', errors='ignore') as yara_file:
        yara_results = yara_file.readlines()
        for line in yara_results:
            report_data["yara_results"].append(line.strip())

    with open(report_file, 'w') as json_report:
        json.dump(report_data, json_report, indent=4)

    print(f"Consolidated JSON report created at {report_file}")

def main():
    yara_rule = input("Enter the path to the YARA rule file: ")
    input_path = get_input_path()
    output_path = get_output_path()

    # Clear the output directory to avoid conflicts
    clear_output_directory(output_path)

    # Run Bulk Extractor first
    run_bulk_extractor(input_path, output_path)

    # Assume the Bulk Extractor output directory is the input for YARA
    yara_output_file = run_yara(yara_rule, output_path, output_path)

    # Create a consolidated JSON report
    report_file = os.path.join(output_path, "consolidated_report.json")
    create_consolidated_report(output_path, yara_output_file, report_file)

if __name__ == "__main__":
    main()
