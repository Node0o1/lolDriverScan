import os
import utils
import time

def main() -> None:
    try:
        print(f"{chr(0x0a)}Downloading CSV file of vulnerable driver details...")
        csv_file, curr_path = utils.get_csv()
        print(f"Download complete.")
        print(f"Exporting {csv_file} to an sqlite database...")
        db_file:str = utils.csv_to_db(csv_file= csv_file, curr_path= curr_path)
        print(f"Database {db_file} created.")
        print(f"Removing {csv_file}...")
        os.remove(csv_file)
        print(f"Collecting list of known vulnerable driver names...")
        file_tags:list = utils.get_file_tags(db_file= db_file)
        print(f"Creating empty logfile... ")
        logfile:str = utils.set_logfile(curr_path= curr_path)
        print(f"Crawling system files for potential driver threats...")
        vuln:bool = utils.crawl_system_files(db_file, file_tags, logfile)
        if(not(vuln)): utils.log_no_err(logfile)
        print(f"{chr(0x0a)}Scan finished. Openning {logfile}...")
        time.sleep(3)
        os.system(f"notepad {logfile}")
    except Exception as e: print(f"{type(e).__name__} {e.args}")
    input("Press [ENTER] to Exit")
