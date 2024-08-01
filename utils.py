import os
import sqlite3
import pandas as pd
import hashlib
from globals import SYSTEM_DRIVE, LOGFILE_NAME

def get_csv() -> tuple:
    curr_path:str = os.getcwd()
    outfile:str = "loldrivers.csv"
    csv_file:str = os.path.join(curr_path, outfile)
    print(csv_file)
    os.system(f'curl https://www.loldrivers.io/api/drivers.csv > {csv_file}')
    return (csv_file, curr_path)
    
def csv_to_db(csv_file:str, curr_path:str) -> str:
    db_name:str = "loldrivers.db"
    db_file:str = os.path.join(curr_path, db_name)
    conn:object = sqlite3.connect(db_file)
    csv_data:object = pd.read_csv(csv_file)
    csv_data.to_sql("drivers", conn, if_exists="replace", index=True)
    conn.close()
    return db_file

def get_file_tags(db_file:str) -> list:
    file_tags:list = list()
    conn:object = sqlite3.connect(db_file)
    cursor:object = conn.cursor()
    query:str = "SELECT Tags FROM drivers;"
    cursor.execute(query)
    file_tags:list = cursor.fetchall()
    conn.close()
    return file_tags

def crawl_system_files(db_file:str, file_tags:list, logfile:str) -> None:
    for rootdir, _, files in os.walk(SYSTEM_DRIVE):
        for file in files:
            if(not(file.endswith(r'sys'))): continue
            for tags in file_tags:
                for tag in tags:
                    if(tag == file):
                        driver_file:str = os.path.join(rootdir, tag)
                        print(f"{chr(0x0a)}Found Driver File: {driver_file}")
                        attrs:list = get_tag_attrs(db_file, tags)
                        compare_driver_hash_SHA256(driver_file, attrs, logfile)

def compare_driver_hash_SHA256(driver_file:str, attrs:list, logfile:str) -> None:
    chunk_size:int = 1024
    hash_object:object = hashlib.sha256()
    with open(driver_file, mode="rb") as fhandle:
        while read_chunk := fhandle.read(chunk_size):
            hash_object.update(read_chunk)
    sha256_value = hash_object.hexdigest()
    vulnerable_hashes:list = attrs[2].split(',')
    print(f"Known vulnerable file-hashes for {driver_file.split('\\')[-1]} (SHA-256): {len(vulnerable_hashes)}")
    print(f"Local Driver Hash (SHA-256): {sha256_value}")
    print("Comparing hashes...")
    for i, hash in enumerate(vulnerable_hashes):
        print(f"Threat Hash #{i+1}: {hash}")
        if(not(hash == sha256_value)): 
            print("Hash does not match.")
            continue
        print("Hash Match! Vulnerable/ Malicious Driver Found.")
        export_threat_details(driver_file, sha256_value, attrs, logfile)

def export_threat_details(driver_file:str, sha256_value:str, attrs:list, logfile:str) -> None:
    print("Exporting details...")
    with open(logfile, mode='a') as fhandle:
        fhandle.write(f"{chr(0x0a)}{driver_file} Threat Details{chr(0x0a)}")
        fhandle.write(('='*50)+chr(0x0a))
        fhandle.write(f"{chr(0x09)}Hash Found: {sha256_value}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Threat Hashes: {attrs[2]}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Category: {attrs[0]}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Description: {attrs[3]}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Resources: {attrs[1]}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Verified Threat: {bool(attrs[4])}{chr(0x0a)}")
        fhandle.write(('='*50)+chr(0x0a))
    
def get_tag_attrs(db_file:str, tags:tuple) -> list:
    conn:object = sqlite3.connect(db_file)
    cursor:object = conn.cursor()
    query:str = f'''
    SELECT drivers.Category, drivers.Resources, drivers.KnownVulnerableSamples_SHA256, drivers.KnownVulnerableSamples_Description, drivers.Verified 
    FROM drivers
    WHERE drivers.Tags = ?
    ;'''
    cursor.execute(query, tags)
    attrs:tuple = cursor.fetchone()
    cursor.close()
    return attrs

def set_logfile(curr_path:str) -> str:
    logfile:str = os.path.join(curr_path, LOGFILE_NAME)
    with open(logfile, mode='w') as fhandle:
        fhandle.write('Vulnerable/ Malicious Driver Log File\n')
    return logfile