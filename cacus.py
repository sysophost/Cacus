import argparse
import logging
import sys
from xml.etree import ElementTree as ET

from modules import output, parser

PARSER = argparse.ArgumentParser()
PARSER.add_argument('--inputfile', '-if', type=str, required=True, help='Path to input .nessus file')
PARSER.add_argument('--outputfile', '-of', type=str, default='./compliance_results.csv', help='Path to output CSV file')
PARSER.add_argument('--outputdelim', '-od', type=str, default=',', help='Output file delimiter (default: "%(default)s")')
PARSER.add_argument('--aggregate', '-ag', action='store_true', help='Aggregate issues')
ARGS = PARSER.parse_args()

logging.basicConfig(format='%(message)s', level=logging.INFO, stream=sys.stderr)


def main():
    # define namespaces for non-default elements to stop search breaking
    xml_namespaces = {'cm': 'http://www.nessus.org/cm'}

    logging.info(f"[i] Reading file from: {ARGS.inputfile}")
    try:
        # get document root
        xml_doc = ET.parse(ARGS.inputfile).getroot()

        # iterate through all Report elements within the provided .nessus file
        for report in xml_doc.findall('Report'):
            report_hosts = parser.parse_hosts(report)

            report_issues = list()
            for host in report_hosts:
                logging.info(f"[i] Parsing compliance issues for host: {host.get('name')}")
                compliance_issues = parser.parse_compliance(host, xml_namespaces)

                # get lists for pass/fail items
                passed = list(filter(lambda x: x.result == 'PASSED', compliance_issues))
                failed = list(filter(lambda x: x.result == 'FAILED', compliance_issues))

                # get pass/fail percentages
                passed_percent = round(len(passed) / len(compliance_issues) * 100, 2) if len(passed) > 0 else 0
                failed_percent = round(len(failed) / len(compliance_issues) * 100, 2) if len(failed) > 0 else 0

                # strip out anything with a status of WARNING or ERROR
                compliance_issues = list(filter(lambda x: x.result in ['PASSED', 'FAILED'], compliance_issues))

                # Remove the last element from the list that just contains info about what compliance check was run
                compliance_issues.pop()
                logging.info(f"[i] Found {len(compliance_issues)} compliance issues\n\tPassed: {len(passed)} ({passed_percent}%)\n\tFailed: {len(failed)} ({failed_percent}%)")

                # append list of issues from this host to overall list
                report_issues = [*report_issues, *compliance_issues]

            if ARGS.aggregate:
                report_issues = parser.aggregate_issues(report_issues)

            # sort issues by name
            report_issues = sorted(report_issues, key=lambda x: x.name)
            headers = ['Check Name', 'Host', 'Configured Value', 'Expected Value', 'Info', 'Solution', 'Result']
            output.write_output(ARGS.outputfile, headers, report_issues, ARGS.outputdelim)
            logging.info(f"[i] Output file written to: {ARGS.outputfile}")

    except Exception as err:
        logging.error(f"[!] {err}")


if __name__ == '__main__':
    main()
