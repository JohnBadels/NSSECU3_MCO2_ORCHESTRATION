import subprocess
import os
import yara
import argparse

# Function to run Bulk Extractor
def run_bulk_extractor(input_image, output_dir):
    try:
        os.makedirs(output_dir, exist_ok=True)
        if os.path.isdir(input_image):
            cmd = ['bulk_extractor', '-R', '-o', output_dir, input_image]
        else:
            cmd = ['bulk_extractor', '-o', output_dir, input_image]
        subprocess.run(cmd, check=True)
        print(f"Bulk Extractor finished. Results are in {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error running Bulk Extractor: {e}")

# Function to load YARA rules
def load_yara_rules(rule_path):
    try:
        rules = yara.compile(filepath=rule_path)
        return rules
    except yara.SyntaxError as e:
        print(f"YARA Syntax Error: {e}")
    except Exception as e:
        print(f"Error loading YARA rules: {e}")
    return None

# Function to apply YARA rules on extracted data
def apply_yara_rules(rules, extracted_files):
    matches = []
    for file in extracted_files:
        with open(file, 'rb') as f:
            data = f.read()
            match = rules.match(data=data)
            if match:
                matches.append((file, match))
    return matches

# Function to find all files in a directory
def get_all_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            files.append(os.path.join(root, filename))
    return files

# Function to parse Bulk Extractor output files for artifacts
def parse_bulk_extractor_output(output_dir):
    artifacts = {
        "emails": [],
        "domains": [],
        "credit_cards": [],
        "telephone_numbers": [],
    }
    
    file_mappings = {
        "email.txt": "emails",
        "domain_histogram.txt": "domains",
        "ccn_track2.txt": "credit_cards",
        "telephone.txt": "telephone_numbers",
    }
    
    for file_name, key in file_mappings.items():
        file_path = os.path.join(output_dir, file_name)
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                artifacts[key].extend(f.readlines())
    
    return artifacts

# Function to write YARA results to a file
def write_yara_results(matches, output_file):
    with open(output_file, 'w') as f:
        for file, match in matches:
            for rule in match:
                f.write(f"{rule.rule} {file}\n")

# Function to write a final report
def write_final_report(output_dir, matches, artifacts):
    report_file = os.path.join(output_dir, 'final_report.txt')
    with open(report_file, 'w') as f:
        f.write("Bulk Extractor Artifact Analysis:\n")
        f.write("----------------------------------------------------------------------\n")
        
        f.write("Extracted Email Addresses:\n")
        for email in artifacts["emails"]:
            f.write(email)
        
        f.write("\nExtracted Domain Names:\n")
        for domain in artifacts["domains"]:
            f.write(domain)
        
        f.write("\nExtracted Credit Card Numbers:\n")
        for cc in artifacts["credit_cards"]:
            f.write(cc)
        
        f.write("\nExtracted Telephone Numbers:\n")
        for phone in artifacts["telephone_numbers"]:
            f.write(phone)
        
        f.write("\nYARA Pattern-Based Analysis:\n")
        f.write("----------------------------------------------------------------------\n")
        for file, match in matches:
            for rule in match:
                f.write(f"{rule.rule} {file}\n")

# Main function to orchestrate the forensic analysis
def forensic_analysis(input_image, output_dir, yara_rule_path):
    # Step 1: Run Bulk Extractor
    run_bulk_extractor(input_image, output_dir)
    
    # Step 2: Load YARA rules
    rules = load_yara_rules(yara_rule_path)
    if not rules:
        return
    
    # Step 3: Get all extracted files
    extracted_files = get_all_files(output_dir)
    
    # Step 4: Apply YARA rules to extracted files
    matches = apply_yara_rules(rules, extracted_files)
    
    # Step 5: Report matches
    if matches:
        yara_results_file = os.path.join(output_dir, 'yara_results.txt')
        write_yara_results(matches, yara_results_file)
        print(f"YARA results written to {yara_results_file}")
    else:
        print("No YARA matches found.")
    
    # Step 6: Parse Bulk Extractor output for artifacts
    artifacts = parse_bulk_extractor_output(output_dir)
    
    # Step 7: Write final report
    write_final_report(output_dir, matches, artifacts)
    print(f"Final report written to {os.path.join(output_dir, 'final_report.txt')}")

# Command-line interface
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Forensic Analysis Tool combining Bulk Extractor and YARA")
    parser.add_argument('input_image', help="Input disk image or directory for analysis")
    parser.add_argument('output_dir', help="Directory to store Bulk Extractor results")
    parser.add_argument('yara_rule_path', help="Path to YARA rules file")
    
    args = parser.parse_args()
    forensic_analysis(args.input_image, args.output_dir, args.yara_rule_path)
