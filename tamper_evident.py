#    Tamper_Evident_Logging_System

# Libraries

from datetime import datetime               # To get the local time when the logs were entered

import hashlib                              # To use SHA256 Hashing algo for file integrity

import sqlite3                              # To store the data in Database

from log_normalizer import import_logs      # To use log normalizing feature of this system.

# Database to store logs

def connect_db():
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            description TEXT NOT NULL,
            prev_hash   TEXT NOT NULL,
            entry_hash  TEXT NOT NULL
        )
    """)

    conn.commit()
    return conn


# fetching last entry's hash to form a chain

def get_last_hash(cursor):
    cursor.execute("SELECT entry_hash FROM logs ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()

    # Testing Edge case

    if result is None:
        return "0" * 64      # no previous hash
    else:
        return result[0]


# Hashing Function

def hash_function(timestamp, event_type, description, prev_hash):
    data = timestamp + event_type + description + prev_hash
    return hashlib.sha256(data.encode()).hexdigest()  


# Add event Function

def event_add(conn, cursor):

    # Event data

    current_timestamp = datetime.now().isoformat()
    current_event_type = input("Enter Event Type : ")
    current_event_description = input("Desciption of Event: ")

    # Hash

    last_hash = get_last_hash(cursor)
    current_hash = hash_function(current_timestamp, current_event_type, current_event_description, last_hash)

    cursor.execute("""  
        INSERT INTO logs (timestamp, event_type, description, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?) 
    """, (current_timestamp, current_event_type, current_event_description, last_hash, current_hash))

    conn.commit()
    print(f"\n[+] Entry added successfully!")
    print(f"    Hash: {current_hash[:24]}...")


# Display Logs Function

def display_logs(cursor):
    cursor.execute("SELECT * FROM logs ORDER BY id ASC")
    rows = cursor.fetchall()

    if not rows:
        print("\n[!] No Entries found. Database is empty!!")
        return 

    print(f"\n{'ID':<5} {'Timestamp':<28} {'Event':<15} {'Description':<35} {'Hash (first 16)'}")
    print("=" * 100)

    for row in rows:
        print(f"{row[0]:<5} {row[1]:<28} {row[2]:<15} {row[3][:33]:<35} {row[5][:16]}...")


# Verifying chain function

def chain_verification(cursor):
    cursor.execute("SELECT * FROM logs ORDER BY id ASC")
    rows = cursor.fetchall()

    if not rows:
        print("\n[!] No Entries found. Database is empty!!")
        return

    print(f"\n Verifying {len(rows)} entries........\n")
    tampered = False

    for i, row in enumerate(rows):
        id_, timestamp, event_type, description, prev_hash, entry_hash = row

        # Regenerating hash to verify integrity
        
        hash_regenerated = hash_function(timestamp, event_type, description, prev_hash)
        if hash_regenerated != entry_hash:
            print(f"\n [!] Entry #{id_} -- HASH MISMATCH!!! \n DATA WAS MODIFIED")
            tampered = True
            continue

        # Checking breakage in chain

        expected_prev = "0" * 64 if i == 0 else rows[i - 1][5]      # since prev_hash of first row/ node will be "0" * 64, so this is why we put expected_

        if prev_hash != expected_prev:
            print(f"\n [!] Entry #{id_} -- CHAIN BROKEN!!!! ENTRY EITHER DELETED 0R REORDERED")
            tampered = True
            continue

        print(f" [*] Entry #{id_} -- OK  ({event_type} at {timestamp})")

    print()
    if tampered:
        print(" [!] INTEGRITY CHECK FAILED --- LOG WAS TAMPERED!!!")
    else:
        print(" [*] INTEGRITY CHECK PASSES --- LOG IS CORRECT AND CLEAN")


# Simulation of Log tampering

def log_tampering_simulation(cursor, conn):

    cursor.execute("SELECT * FROM logs ORDER BY id ASC")
    rows = cursor.fetchall()

    if not rows:
        print("\n[!] No Entries found. Database is empty!!")
        return

    display_logs(cursor)

    try:
        target_id = int(input("\n Enter entry ID you want to Tamper: "))

    except ValueError:
            print("[!] Invalid input!!!")
            return

    # validating the ids entered

    valid_ids = [row[0] for row in rows]
    if target_id not in valid_ids:
        print("\n[!] That ID doesn't exist in the log.")
        return

    cursor.execute("""
        UPDATE logs SET description = 'Modified data. Threat actor modified the data'
        WHERE id = ?
    """, (target_id,))

    conn.commit()
    print(f"\n [!] Entry #{target_id} tampered -- hash NOT updated!!!")
    print("     Run Verify to detect it.")


# Simulation of Logs Deletion

def simulate_deletion(cursor, conn):
    cursor.execute("SELECT id FROM logs ORDER BY id ASC LIMIT 1 OFFSET 1")
    row = cursor.fetchone()

    if not row:
        print("\n[!] Need at least 2 entries to simulate deletion.")
        return

    cursor.execute("DELETE FROM logs WHERE id = ?", (row[0],))
    conn.commit()
    print(f"\n[!] Entry #{row[0]} deleted from database.")
    print("    Run Verify to detect chain break.")


# Reorder Simulation

def simulate_reorder(cursor, conn):
    cursor.execute("SELECT id FROM logs ORDER BY id ASC")
    rows = cursor.fetchall()

    if len(rows) < 2:
        print("\n[!] Need at least 2 entries to simulate reordering.")
        return

    display_logs(cursor)

    try:
        id1 = int(input("\n Enter first entry ID to swap: "))
        id2 = int(input(" Enter second entry ID to swap: "))
    except ValueError:
        print("\n[!] Invalid input!")
        return

    # Checking if ID's Actually exist

    valid_ids = [row[0] for row in rows]
    if id1 not in valid_ids or id2 not in valid_ids:
        print("\n[!] One or both IDs don't exist in the log.")
        return

    if id1 == id2:
        print("\n[!] Can't swap an entry with itself.")
        return

    cursor.execute("SELECT description FROM logs WHERE id = ?", (id1,))
    description1 = cursor.fetchone()[0]

    cursor.execute("SELECT description FROM logs WHERE id = ?", (id2,))
    description2 = cursor.fetchone()[0]

    cursor.execute("UPDATE logs SET description = ? WHERE id = ?", (description2, id1))
    cursor.execute("UPDATE logs SET description = ? WHERE id = ?", (description1, id2))

    conn.commit()
    print(f"\n[!] Entry #{id1} and #{id2} descriptions swapped.")
    print("    Run Verify to detect the mismatch.")


# Main CLI Menu

def main():
    conn = connect_db()
    cursor = conn.cursor()

    try:
        while True:
            print("\n" + "═" * 45)
            print("   TAMPER-EVIDENT LOGGING SYSTEM")
            print("═" * 45)
            print("  1. Add log entry")
            print("  2. Show all entries")
            print("  3. Verify chain integrity")
            print("  4. Simulate tampering")
            print("  5. Simulate Deletion")
            print("  6. Simulate ReOrder")
            print("  7. Import logs")
            print("  8. Exit")
            print("─" * 45)

            choice = input("  Choose option: ").strip()

            if choice == "1":
                event_add(conn, cursor)

            elif choice == "2":
                display_logs(cursor)

            elif choice == "3":
                chain_verification(cursor)

            elif choice == "4":
                log_tampering_simulation(cursor, conn)

            elif choice == "5":
                simulate_deletion(cursor, conn)

            elif choice == "6":
                simulate_reorder(cursor, conn)

            elif choice == "7":
                filepath = input("Enter log file path: ").strip()
                import_logs(filepath, conn, cursor, get_last_hash, hash_function)

            elif choice == "8":
                print("\n Goodbye!\n")
                break
            
            else:
                print("\n [!] Invalid option.")

    finally:
        conn.close()
        print("\n[*] Database connection closed.")

if __name__ == "__main__":
    main()