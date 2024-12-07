import os, argparse, re
from jawa.classloader import ClassLoader

def init_patterns():
    '''Patterns to search for:'''

    network_patterns = [
       'Socket', 'ServerSocket', 'DatagramSocket', 'MulticastSocket',
        'HttpURLConnection', 'URLConnection', 'URL'
    ]

    file_operations_patterns = [
        'FileInputStream', 'FileOutputStream', 'RandomAccessFile',
        'FileWriter', 'BufferedWriter', 'BufferedReader',
        'Files', 'Paths'
    ]

    reflection_patterns = [
        'Method.invoke', 'Class.forName', 'Constructor.newInstance',
        'Field.setAccessible'
    ]

    process_executions_patterns = [
        'Runtime.getRuntime().exec', 'ProcessBuilder'
    ]

    cryptographic_patterns = [
        'Cipher', 'MessageDigest', 'KeyGenerator',
        'SecretKeySpec', 'Mac'
    ]

    dynamic_loading_patterns = [
        'URLClassLoader', 'ClassLoader.loadClass'
    ]

    thread_manipulation_patterns = [
        'Thread', 'ExecutorService'
    ]

    serialization_patterns = [
        'ObjectInputStream', 'ObjectOutputStream', 'Serializable',
        'Externalizable'
    ]

    unsafe_operations_patterns = [
        'Unsafe', 'sun.misc.Unsafe'
    ]

    native_code_execution_patterns = [
        'System.loadLibrary', 'System.load'
    ]

    scripting_and_dynamic_execution_patterns = [
        'ScriptEngineManager', 'GroovyShell', 'NashornScriptEngine',
        'JavaCompiler', 'javax.script'
    ]

    sensitive_information_access_patterns = [
        'System.getProperty', 'System.getenv'
    ]

    database_access_patterns = [
        'DriverManager.getConnection', 'Connection.prepareStatement',
        'Connection.createStatement', 'Connection.executeQuery',
        'Connection', 'ConnectionImpl'
    ]

    all_patterns = (
            network_patterns +
            file_operations_patterns +
            reflection_patterns +
            process_executions_patterns +
            process_executions_patterns +
            cryptographic_patterns +
            dynamic_loading_patterns +
            thread_manipulation_patterns +
            serialization_patterns +
            unsafe_operations_patterns +
            native_code_execution_patterns +
            scripting_and_dynamic_execution_patterns +
            sensitive_information_access_patterns +
            database_access_patterns
    )

    return all_patterns

def check_warns(warnings):
    reset = '\033[0m'
    red = '\033[1;91m'
    green = '\033[1;92m'

    if warnings > 0:
        print (f"\n{red}Found {warnings} warnings!{reset}")
    else:
        print (f"{green}Safety! :){reset}")

def extract_and_scan_jar(jar_path, out_path, in_file=False):
    if out_path != None:
        in_file = True
    else:
        os.rmdir(out_path)
    all_patterns = init_patterns()
    loader = ClassLoader(jar_path)
    warnings = 0
    try:
        for class_path in loader.classes:
            cf = loader[class_path]
            # Using a regular expression for object search
            match = re.search(r"value='([^']+)'", str(cf.this.name))
            if match:
                value_content = match.group(1)
                # Search by patterns
                for pattern in all_patterns:
                    if pattern in value_content:
                        if in_file:
                            try:
                                with open(out_path, 'a') as file:
                                    print(f"[WARNING] Potential dangerous operation [{pattern}] detected in {value_content}", file=file)
                            except:
                                print ("Error opening th file")
                        else:
                            print(f"[WARNING] Potential dangerous operation [{pattern}] detected in {value_content}")
                        warnings += 1        
            else:
                print("I don't know what happened 🤷🏽‍♂️")
        check_warns(warnings)
    except Exception as e:
        print(f"Error analyzing {jar_path}: {e}")

def arg_parser():
    # Create a parser
    parser = argparse.ArgumentParser(description="Supported args:")
    
    # Add args
    parser.add_argument('--path', type=str, help='path to jar file (/tmp/my_jar.jar)')
    parser.add_argument('--out', type=str, help='path to log output file (/tmp/scan_result.txt)')

    # Parse args
    args = parser.parse_args()

    try:
        args = parser.parse_args()
    except SystemExit:
        # If we have a parser error, it will print and program will be closed
        parser.print_help()
        os._exit(2)
    
    if args.path[-4:] != '.jar':
        parser.print_help()
        raise TypeError('Only *.jar file')

    return args.path, args.out

def main():
    jar_path, out_path = arg_parser()
    extract_and_scan_jar(jar_path, out_path)

if __name__ == '__main__':
    main()