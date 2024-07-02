import boto3
import csv
import sys
from datetime import datetime, timedelta
import time

severityMapping = {
    "Low": range(1, 4),
    "Medium": range(4, 7),
    "High": range(7, 9)
}
def mapSeverity(severityValue):
    for severityName, severityRange in severityMapping.items():
        if severityValue in severityRange:
            return severityName
    return "Unknown"
def getGuardDutyFindings(accountId, region):
    session = boto3.Session(region_name=region)
    guardduty = session.client('guardduty')
    detectors = guardduty.list_detectors()
    if not detectors['DetectorIds']:
        print("No GuardDuty detectors found for the given account.")
        return []
    detectorId = detectors['DetectorIds'][0]
    oneWeekAgo = datetime.now() - timedelta(days=7)
    oneWeekAgoUnix = int(time.mktime(oneWeekAgo.timetuple()))
    findings = guardduty.list_findings(
        DetectorId=detectorId,
        FindingCriteria={
            'Criterion': {
                'updatedAt': {
                    'Gte': oneWeekAgoUnix
                }
            }
        }
    )
    findingIds = findings['FindingIds']
    if not findingIds:
        print("No findings found for the last week.")
        return []
    findingDetails = guardduty.get_findings(
        DetectorId=detectorId,
        FindingIds=findingIds
    )
    return findingDetails['Findings']
def saveFindingsToCsv(findings, accountId, region):
    currentTime = datetime.now().strftime("%Y%m%d_%H%M%S")
    fileName = f"guardduty_findings_{accountId}_{region}_{currentTime}_weekly_report.csv"
    csvColumns = ['Title', 'Description', 'Severity', 'SeverityName', 'Type', 'CreatedAt']
    try:
        with open(fileName, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csvColumns)
            writer.writeheader()
            for finding in findings:
                severityValue = finding.get('Severity', 0)
                writer.writerow({
                    'Title': finding.get('Title', ''),
                    'Description': finding.get('Description', ''),
                    'Severity': severityValue,
                    'SeverityName': mapSeverity(int(severityValue)),
                    'Type': finding.get('Type', ''),
                    'CreatedAt': finding.get('CreatedAt', '')
                })
        print(f"Findings have been written to {fileName}")
    except IOError:
        print("Input Output error")

def main(accountId, region):
    findings = getGuardDutyFindings(accountId, region)
    if findings:
        saveFindingsToCsv(findings, accountId, region)
        print(f"Total number of alerts received in the last week: {len(findings)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <account_id> <region>")
    else:
        accountId = sys.argv[1]
        region = sys.argv[2]
        main(accountId, region)
