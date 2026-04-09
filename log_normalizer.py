#==============================================================================
#                           Log Normalization
#==============================================================================

# Libraries

import re                           # For extraction of text from different logs

from datetime import datetime       # For extracting date and time

# recompiler

# in these compilers we are going to extract the text from different logs.

# ssh session logs recompiler

ssh_auth = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
    r'\S+\s+'
    r'\S+:\s+'
    r'(Failed|Accepted)\s+'
    r'password for\s+'
    r'(\S+)\s+'
    r'from\s+(\S+)'
)


# Windows even logs recomiler

windows_event = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s+'  
    r'(\w+)\s+'                                          
    r'(\w+)\s+'                                          
    r'(.*)'                                              
)

# Apache  Access logs recompiler

apache_access = re.compile(
    r'(\S+)\s+'                          
    r'\S+\s+'                            
    r'(\S+)\s+'                          
    r'\[(.+?)\]\s+'                     
    r'"(\S+)\s+(\S+)\s+\S+"\s+'         
    r'(\d+)'                             
)

# Apache Error logs recompiler

apache_error = re.compile(
    r'\[(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\]\s+'
    r'\[(\w+)\]\s+'
    r'(.*)'
)

# Linux systems log recompiler

linux_syslog = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
    r'\S+\s+'                            
    r'(\S+):\s+'                         
    r'(.*)'                              
)

# MacOS syslog recompiler

macos_log = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'   
    r'\S+\s+'                             
    r'(\S+):\s+'                          
    r'(.*)'                               
)


# Log parser

def parse_log(raw_line):

    # SSH LOG PARSER
    
    match = ssh_auth.search(raw_line)

    if match:
        if match.group(2) == 'Failed':
            event_type = 'FAILED_LOGIN'

        else:
            event_type = 'LOGIN'

        description = f"{match.group(2)} password for '{match.group(3)}' from {match.group(4)}"
            
        return{
                "timestamp":   match.group(1),
                "event_type":  event_type,
                "description": description
            }


    # Windows Log parser

    match = windows_event.search(raw_line)

    if match:
        level = match.group(2)
        service = match.group(3)
        message = match.group(4).strip()

        if level.lower() == 'error':
            event_type = 'WINDOWS_ERROR'
        elif level.lower() == 'warning':
            event_type = 'WINDOWS_WARNING'
        else:
            event_type = 'WINDOWS_INFO'

        description = f"{service} [{level}]: {message[:150]}"

        return {
            "timestamp":   match.group(1),
            "event_type":  event_type,
            "description": description
        }


    # Apache Access Log

    match = apache_access.search(raw_line)

    if match:
        if match.group(6) == '200':
            event_type = 'WEB_ACCESS'
        else:
            event_type = 'ERROR'

        description = f"{match.group(4)} {match.group(5)} by {match.group(2)} from {match.group(1)} - HTTP {match.group(6)}"

        return{
            "timestamp":    match.group(3),
            "event_type":   event_type,
            "description":  description
        }


    # Apache Error Log

    match = apache_error.search(raw_line)

    if match:
        level = match.group(2)
        message = match.group(3).strip()

        if level.lower() == 'error':
            event_type = 'APACHE_ERROR'
        else:
            event_type = 'APACHE_NOTICE'

        description = f"[{level}] {message[:150]}"

        return {
            "timestamp":   match.group(1),
            "event_type":  event_type,
            "description": description
        }


    # Linux Syslog parser


    match = linux_syslog.search(raw_line)

    if match:
        service = match.group(2)
        message = match.group(3)
        event_type = "SUDO" if "sudo" in service.lower() else "SYSTEM_EVENT"
        description = f"{service}: {message.strip()}"
        return {
            "timestamp":   match.group(1),
            "event_type":  event_type,
            "description": description
        }


    # macOS Log

    match = macos_log.search(raw_line)

    if match:
        process = match.group(2)
        message = match.group(3).strip()

        if 'kernel' in process.lower():
            event_type = 'MACOS_KERNEL'
        elif 'sudo' in process.lower():
            event_type = 'MACOS_SUDO'
        else:
            event_type = 'MACOS_SYSTEM'

        description = f"{process}: {message[:150]}"

        return {
            "timestamp":   match.group(1),
            "event_type":  event_type,
            "description": description
        }


    return None


# Normalizing function to normalize logs making sure they stay in consistent format

def normalize(parsed):
    if parsed is None:
        return None

    return {
        "timestamp":   parsed["timestamp"],
        "event_type":  parsed["event_type"].upper(),
        "description": parsed["description"].strip()[:200]
    }

# Importing logs function to import logs from the file to normalize and add to the system

def import_logs(filepath, conn, cursor, get_last_hash, hash_function):

    # Opening the log file to import the logs

    try: 
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except:
        print("[!]  Logs file dont exist on the given location!!!")
        return None
        
    # removing the unnecessary '\n' and spaces from the logs

    for line in lines:
        line = line.strip()

        if not line:
            continue

        
        parsed = parse_log(line)

        normalized = normalize(parsed)

        if normalized is not None:

            timestamp = normalized["timestamp"]
            event_type = normalized["event_type"]
            description = normalized["description"]

            last_hash = get_last_hash(cursor)
            entry_hash = hash_function(timestamp, event_type, description, last_hash)

            cursor.execute("""
            INSERT INTO logs (timestamp, event_type, description, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?)
            """, (timestamp, event_type, description, last_hash, entry_hash))

            conn.commit()
            print(f"[+] Imported — {event_type}: {description[:50]}")

        else:
            print(f"[!] Skipped — format not recognized: {line[:50]}")