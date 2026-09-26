import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def run_script(script_name):
    script_path = os.path.join(BASE_DIR, script_name)

    if not os.path.exists(script_path):
        print(f"\nERROR: {script_name} not found.")
        return

    print("\n" + "=" * 65)
    print(f"Running: {script_name}")
    print("=" * 65)

    subprocess.run([sys.executable, script_path])


def show_menu():
    while True:
        print("\n")
        print("=" * 65)
        print("        THREAT INTELLIGENCE SECURITY CONSOLE")
        print("=" * 65)

        print("\n1. Process Threat Feeds")
        print("2. Search IOC")
        print("3. View High-Risk IOCs")
        print("4. View Database Summary")
        print("5. Generate Security Report")
        print("6. Generate Blocklists")
        print("7. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            run_script("main.py")

        elif choice == "2":
            run_script("ioc_search.py")

        elif choice == "3":
            run_script("high_risk_iocs.py")

        elif choice == "4":
            print("\nDatabase summary is available through main.py.")
            print("Run option 1 to process feeds and view the database summary.")

        elif choice == "5":
            print("\nSecurity report is generated automatically by main.py.")
            print("Run option 1 to generate the latest report.")

        elif choice == "6":
            print("\nBlocklists are generated automatically by main.py.")
            print("Run option 1 to generate the latest blocklists.")

        elif choice == "7":
            print("\nExiting Threat Intelligence Security Console...")
            break

        else:
            print("\nInvalid choice. Please enter a number from 1 to 7.")


if __name__ == "__main__":
    show_menu()