# lolDriverScan
#### ***type: console application***

## Description
<center>
<p>Scans the OS system drivers and compares them to a curated list of known vulnerable and malicous drivers from "Living Off the Land" at https://www.loldrivers.io/</p>
<p>Hash types for file comparison include SHA1, SHA256, and MD5.</p>
<p>Logs all found driver threats to a log file.
<p>Runs the System File Checker Utility to scan system files for integrity violations.</p>
</center>

## Whats New
<ul><li>Writes "No malicious / vulnerable driver found" to error log when no match exist</li></ul>

## About
> This program uses resources from https://www.loldrivers.io/ (Living Off the Land) which is responsible for the collection of known malicious or exploited drivers used in this scanner. This script imports their csv file into an sqlite database and scans your system drive searching for these threats. If one is found, the script will generate the SHA1, SHA256, and MD5 hashes of the driver version found on your device and compare it to all the known ill hashes of this driver from within the database. Matching a hash to a known malicious or vulnerable driver will export details to a log file including the filename, filepath, local file-hash, known malicious hashes of the driver, the generated hashes of the local installation (SHA1, SHA256, MD5), details of the driver (if exist), the category of whether the driver is malicious or vulnerable, and whether or not this threat has actually been verified. Identified maliciuos or vulnerable drivers that are not currently in use on the system should be removed and those drivers that are needed should be updated or replaced. All created files such as the csv, databse, and log file will appear in the current working directory. The csv file will be deleted once the export to the database has completed.</p>
<p><bold>Every time this script is ran, the most recent csv file will be downloaded to ensure that the resources are as up to date as they can be.</bold></p>

## Directions
<p>After downloading, navigate to the directory containing the python files within your terminal. Be sure to run <b style= "font-style: italic; color: red;">pip install -r requirements.txt</b> for first tiime use to ensure dependancies are installed.</p>

- <p>Requires Pandas to be installed and can be done by running the following from within the same directory as the requirements.txt file.</p>
```sh
python -m pip install -r requirements.txt

```
- <p>Once setup is complete, simply run main() from within the lolDriverScan directory where the python files reside.</p>
```sh
python ./main.py

```
