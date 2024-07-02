# Exporter of AWS GuardDuty Alerts

A Python script to export AWS GuardDuty alerts received during the last week into a CSV file can be found in this repository. The script records the findings with a timestamped filename and filters alerts based on their severity.

## Features

- Retrieves last week's GuardDuty findings.
- Connects names with human-readable severity levels.
- Creates a CSV file for the findings.
- Creates filenames with the current timestamp, region, and account ID.

## Requirements

- Python 3.x
- boto3 library

## Setup

- Clone the repo & change the directory
   
```
bash git clone https://github.com/yourusername/aws-guardduty-alerts-exporter.git cd aws-guardduty-alerts-exporter
cd aws-guardduty-alerts-exporter
```
- Install the required Python packages:

```
python3 -m pip install boto3
```

## Usage

- Run the script with your AWS account ID and region as arguments:

```
python3 download_guardduty_findings.py <account_id> <region>
```


Thanks to 
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html
- https://aws.amazon.com/q/developer/
