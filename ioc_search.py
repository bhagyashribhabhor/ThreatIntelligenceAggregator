import os
import sqlite3


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_FILE = os.path.join(
    BASE_DIR,
    "threat_intelligence.db"
)


def search_ioc():

    print("=" * 65)
    print("              IOC SEARCH")
    print("=" * 65)

    search_value = input(
        "\nEnter IOC to search: "
    ).strip().lower()

    if not search_value:

        print("\nSearch value cannot be empty.")

        return

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT indicator,
               ioc_type,
               risk_level,
               source,
               first_seen,
               last_seen,
               occurrences
        FROM iocs
        WHERE LOWER(indicator) = ?
        ORDER BY last_seen DESC
    """, (search_value,))

    results = cursor.fetchall()

    connection.close()

    if not results:

        print("\nIOC NOT FOUND")

        print(
            "No matching indicator exists "
            "in the database."
        )

        return

    print("\nIOC FOUND")
    print("-" * 65)

    for row in results:

        indicator = row[0]
        ioc_type = row[1]
        risk_level = row[2]
        source = row[3]
        first_seen = row[4]
        last_seen = row[5]
        occurrences = row[6]

        print(f"IOC         : {indicator}")
        print(f"Type        : {ioc_type.upper()}")
        print(f"Risk Level  : {risk_level}")
        print(f"Source      : {source}")
        print(f"First Seen  : {first_seen}")
        print(f"Last Seen   : {last_seen}")
        print(f"Occurrences : {occurrences}")

        print("-" * 65)


if __name__ == "__main__":

    search_ioc()