import argparse
import logging
import sys
from xml.etree import ElementTree as ET

from modules import output, parser

PARSER = argparse.ArgumentParser()
PARSER.add_argument('--inputfile', '-if', type=str, required=True, help='Path to input .nessus file')
PARSER.add_argument('--outputfile', '-of', type=str, default='./compliance_results.csv', help='Path to output CSV file')
PARSER.add_argument('--outdelim', '-od', type=str, default=',', help='Output file delimiter (default: "%(default)s")')
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
            for host in report_hosts:
                logging.info(f"[i] Parsing compliance issues for host: {host.get('name')}")
                compliance_issues = parser.parse_compliance(host, xml_namespaces)
                compliance_issues = sorted(compliance_issues, key=lambda x: x.name)

                passed = list(filter(lambda x: x.result == 'PASSED', compliance_issues))
                failed = list(filter(lambda x: x.result == 'FAILED', compliance_issues))

                # strip out anything with a status of WARNING
                compliance_issues = list(filter(lambda x: x.result in ['PASSED', 'FAILED'], compliance_issues))
                logging.info(f"[i] Found {len(compliance_issues)} compliance issues\n\tPassed:{len(passed)}\n\tFailed:{len(failed)}")

                headers = ['Host', 'Check Name', 'Configured Value', 'Expected Value', 'Info', 'Solution', 'Result']
                output.write_output(ARGS.outputfile, headers, compliance_issues, ARGS.outdelim)
                logging.info(f"[i] Output file written to: {ARGS.outputfile}")

    except Exception as err:
        logging.error(f"[!] {err}")


if __name__ == '__main__':
    main()
