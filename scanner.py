import os, subprocess, argparse, shutil
from tqdm import tqdm

def analyze_class_file(class_file_path):
    try:
        # Decompile the .class file
        result = subprocess.run(['uncompyle6', '-o', '-', class_file_path], capture_output=True, text=True)
        source_code = result.stdout

        # Examples of patterns to search for:
        network_patterns = [
            'Socket', 'ServerSocket', 'DatagramSocket', 'MulticastSocket',
            'HttpURLConnection', 'URLConnection', 'URL', 'HtttUrlConnection'
        ]
        
        file_operations_patterns = [
            'FileInputStream', 'FileOutputStream', 'RandomAccessFile',
            'FileWriter', 'BufferedWriter', 'BufferedReader'
        ]

        reflection_patterns = [
            'Method.invoke', 'Class.forName', 'Constructor.newInstance'
        ]
        
        process_executions_patterns = [
            'Runtime.getRuntime().exec', 'ProcessBuilder'
        ]
        
        # Search by patterns
        warnings = 0
        for pattern in (network_patterns + file_operations_patterns + reflection_patterns + process_executions_patterns):
            if pattern in source_code:
                print(f"[WARNING] Potential dangerous operation [{pattern}] detected in {class_file_path}")
                warnings += 1
    except Exception as e:
        print(f"Error analyzing {class_file_path}: {e}")

    return warnings

def check_warns(warnings):
    if warnings > 0:
        print (f"Found {warnings} warnings!")
    else:
        print ("Safety! :)")

def extract_and_scan_jar(jar_path, jdk_dir, extracted_dir):
    # Unpack the JAR file
    subprocess.run([f'{jdk_dir}/bin/jar', 'xf', jar_path], cwd=extracted_dir)

    # First, count the number of .class files to initialize the progress bar
    total_class_files = 0
    for root, dirs, files in os.walk(extracted_dir):
        total_class_files += sum(1 for file in files if file.endswith('.class'))

    # Create the progress bar
    progress_bar = tqdm(total=total_class_files, desc="Scanning .class files")

    # Traverse all .class files
    for root, dirs, files in os.walk(extracted_dir):
        for file in files:
            if file.endswith('.class'):
                class_path = os.path.join(root, file)
                warnings = analyze_class_file(class_path)
                progress_bar.update(1)
    
    progress_bar.close()
    check_warns(warnings)

def extract(extracted_dir):
    # Create a temporary directory for unpacking the JAR
    shutil.rmtree(extracted_dir, ignore_errors=True)
    os.makedirs(extracted_dir, exist_ok=True)

def arg_parser():
    # Create a parser
    parser = argparse.ArgumentParser(description="Supported args:")
    
    # Add args
    parser.add_argument('--path', type=str, help='path to jar file (/tmp/my_jar.jar)')
    parser.add_argument('--java', type=str, help='path to JAVA_HOME (/opt/jdk-17/)')

    # Parse args
    args = parser.parse_args()

    # Using args
    if args.path == None:
        print ("Select a file")
        os._exit(2)

    if args.java == None:
        print ("Set JAVA_HOME")
        os._exit(2)

    return args.path, args.java

def main():
    extracted_dir = '/tmp/jar_extracted'
    jar_path, jdk_dir = arg_parser()
    
    extract(extracted_dir)
    extract_and_scan_jar(jar_path, jdk_dir, extracted_dir)

if __name__ == '__main__':
    main()