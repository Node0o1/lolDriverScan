# lolDriverScan
#### ***type: console application***

## Description
<p>Check Windows OS for known malicious or vulnerable drivers. Uses resources from https://www.loldrivers.io/</p>

## About
> This script uses resources from https://www.loldrivers.io/ (Living Off the Land) which is a collection of known malicious or exploited drivers. The script downloads a csv file of the details and then exports that csv into an sqlite database. From there it will create a list of all the names of the known malicious or vulnerable drivers. After the list is created, the script will scan the entire system drive searching for any of the files listed. If found, the script then generates the sha-256 hash of the file on your pc and compares it to all the known ill sha-256 hashes from that exact driver (many variants of a single driver). Matching hashes to a known malicious or vulnerable driver will export the file path and name, local file-hash, known hashes, details of the driver (if details exist), category of malicious or vulnerable, and whether or not this threat has actually been verified. All to a log file. The downloaded csv file will be deleted once the database has been created and all created files will appear in the current working directory.  I assume that AV's already check for all of the stuff listed here, but it was a fun project anyway.</p>
<p>Every time this script is ran, the most recent csv file will be downloaded to ensure that the resources are as up to date as they can be.
<br/>

## Directions
<p>After downloading, navigate to the directory containing the python files within your terminal. Be sure to run ***pip install -r requirements.txt*** for first tiime use to ensure dependancies are installed.</p>
<p>Requires Pandas to be installed</p>

```ps
python -m pip install -r requirements.txt

```
<p>Once setup is complete, simply run main() from within the lolDriverScan directory where the python files reside.</p>

### Example:

```ps
python ./main.py

```
