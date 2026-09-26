import os
import sqlite3


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_FILE = os.path.join(
    BASE_DIR,
    "threat_intelligence.db"
)


def show_high_risk_iocs():

    print("=" * 65)
    print("                 HIGH-RISK IOC VIEWER")
    print("=" * 65)

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT indicator,
               ioc_type,
               source,
               last_seen,
               occurrences
        FROM iocs
        WHERE risk_level = 'HIGH'
        ORDER BY ioc_type, indicator
    """)

    results = cursor.fetchall()

    connection.close()

    if not results:

        print("\nNo HIGH-risk IOCs found.")

        return

    print(
        f"\nTotal HIGH-risk IOCs: {len(results)}"
    )

    print("-" * 65)

    for row in results:

        indicator = row[0]
        ioc_type = row[1]
        source = row[2]
        last_seen = row[3]
        occurrences = row[4]

        print(
            f"\nIOC         : {indicator}"
        )

        print(
            f"Type        : {ioc_type.upper()}"
        )

        print(
            f"Source      : {source}"
        )

        print(
            f"Last Seen   : {last_seen}"
        )

        print(
            f"Occurrences : {occurrences}"
        )

        print("-" * 65)


if __name__ == "__main__":

    show_high_risk_iocs()