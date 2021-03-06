# Cacus

Tool to extract CIS compliance results from `.nessus` files

This was knocked together very quickly so currently only supports exporting results for a single host from the supplied `.nessus` file.  If your file has multiple hosts, or multiple report entries, the final item will clobber the output of the rest

## Usage

`python cacus.py --inputfile <input .nessus file> [--outputfile <output file>] [--outputdelim <delim>]`

### Required args

`--inputfile` / `-if`

Path to the input `.nessus` file to parse

### Optional args

`--outputfile` / `-of`

Path to write results (defaults to `compliance_results.csv`)

`--outputdelim` / `-od`

Use in conjunction with `--outputfile` to specify the file delimiter to use (defaults to `,`)

*If you want to use tab as a delimiter you have to specify it as `--outputdelim $'\t'`*

`--aggregate` / `-ag`

Aggregate issues by host

`--nopadding` / `-np`

Disable vertical padding between aggregated hosts

## TODO

* ~~Support multiple hosts in a single `.nessus`~~ and aggregate results
* ~~Support multiple reports in a single `.nessus` file~~
* Make the output a bit prettier and remove ugly whitespace in the output file
* Generate summary for each host with pass/fail count and percentage
