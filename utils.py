import os
import requests as req
import sqlite3
import pandas as pd
import hashlib
from enum import Enum
from globals import SYSTEM_DRIVE, LOGFILE_NAME

logged:bool = False

def get_csv() -> tuple:
    curr_path:str = os.getcwd()
    outfile:str = "loldrivers.csv"
    csv_file:str = os.path.join(curr_path, outfile)
    print(f"Filepath: {csv_file}")
    with open(csv_file, mode='wb') as fhandle:
        fhandle.write(req.get("https://www.loldrivers.io/api/drivers.csv").content)
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
    class Hashtypes(Enum):
        SHA256:int = 2
        SHA1:int = 3
        MD5:int = 4

    for rootdir, _, files in os.walk(SYSTEM_DRIVE):
        for file in files:
            if(not(file.endswith(r'sys'))): continue
            for tags in file_tags:
                for tag in tags:
                    if(tag == file):
                        driver_file:str = os.path.join(rootdir, tag)
                        print(f"{chr(0x0a)}Found Driver File: {driver_file}")
                        attrs:list = get_tag_attrs(db_file, tags)
                        sha1_hash, sha256_hash, md5_hash = get_hash_set(driver_file)
                        compare_file_hash(driver_file, sha1_hash, Hashtypes.SHA1.name, attrs[Hashtypes.SHA1.value].split(','), attrs, logfile)
                        compare_file_hash(driver_file, sha256_hash, Hashtypes.SHA256.name, attrs[Hashtypes.SHA256.value].split(','), attrs, logfile)
                        compare_file_hash(driver_file, md5_hash, Hashtypes.MD5.name, attrs[Hashtypes.MD5.value].split(','), attrs, logfile)
    return logged

def get_hash_set(driver_file:str) -> tuple:
    chunk_size:int = 1024
    sha1:object = hashlib.sha1()
    sha256:object = hashlib.sha256()
    md5:object = hashlib.md5()
    with open(driver_file, mode="rb") as fhandle:
        while read_chunk := fhandle.read(chunk_size):
            sha1.update(read_chunk)
            sha256.update(read_chunk)
            md5.update(read_chunk)
    return (sha1.hexdigest(), sha256.hexdigest(), md5.hexdigest())

def compare_file_hash(driver_file:str, file_hash:str, hashtype:str, hashlist:list, attrs:list, logfile:str ) -> None:
    print(f"Known vulnerable file-hashes for {driver_file.split('\\')[-1]} ({hashtype}): {len(hashlist)}")
    print(f"Local Driver Hash ({hashtype}): {file_hash}")
    print("Comparing hashes...")
    for i, hash in enumerate(hashlist):
        print(f"Threat Hash #{i+1} ({hashtype}): {hash}")
        if(not(hash == file_hash)): 
            print("Hash does not match.")
            continue
        print("Hash Match! Vulnerable/ Malicious Driver Found.")
        export_threat_details(driver_file, file_hash, hashtype, hashlist, attrs, logfile)
        logged = True

def export_threat_details(driver_file:str, hash_value:str, hashtype:str, hashlist:str, attrs:list, logfile:str) -> None:
    print("Exporting details...")
    with open(logfile, mode='a') as fhandle:
        fhandle.write(f'{chr(0x0a)}')
        fhandle.write(('='*50)+chr(0x0a))
        fhandle.write(f"{chr(0x09)}File Path: {driver_file}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Hash Type: {hashtype}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Hash Found: {hash_value}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Threat Hashes: {hashlist}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Category: {attrs[0]}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Description: {attrs[5]}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Resources: {attrs[1]}{chr(0x0a)}")
        fhandle.write(f"{chr(0x09)}Verified Threat: {bool(attrs[6])}{chr(0x0a)}")
        fhandle.write(('='*50)+chr(0x0a))
    
def get_tag_attrs(db_file:str, tags:tuple) -> list:
    conn:object = sqlite3.connect(db_file)
    cursor:object = conn.cursor()
    query:str = f'''
    SELECT drivers.Category, drivers.Resources, drivers.KnownVulnerableSamples_SHA256, drivers.KnownVulnerableSamples_SHA1, drivers.KnownVulnerableSamples_MD5, drivers.KnownVulnerableSamples_Description, drivers.Verified 
    FROM drivers
    WHERE drivers.Tags = ?
    ;'''
    cursor.execute(query, tags)
    attrs:tuple = cursor.fetchone()
    cursor.close()
    return attrs

def set_logfile(curr_path:str) -> str:
    logfile:str = os.path.join(curr_path, LOGFILE_NAME)
    print(f"Filepath: {logfile}")
    with open(logfile, mode='w') as fhandle:
        fhandle.write('Vulnerable/ Malicious Driver Log File\n')
    return logfile

def log_no_err(logfile:str) -> None:
    with open(logfile, mode="a") as fhandle:
        fhandle.write("No known malicious/ vulnerable drivers found.")
