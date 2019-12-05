import os
import subprocess
import traceback
import argparse

yaraParams = "-s"
tempFileName = "yaraOneLiner.tmp"
lineNumber = 1

arguments = argparse.ArgumentParser("yaraOneLine.py -e yara64.exe -f input.csv -r rule.yar")
arguments.add_argument("-e", "--yaraExe", type=str, required=True, help="Yara executable to use")
arguments.add_argument("-f", "--inputFileName", type=str, required=True, help="Input file to yara scan")
arguments.add_argument("-r", "--yaraRuleFile", type=str, required=True, help="Yara rule file to scan against")
settings = arguments.parse_args()

lines = open(settings.inputFileName, "r")

for line in lines:
 line = line.rstrip()
 tempfile = open(tempFileName,"w")
 tempfile.write(line)
 tempfile.close
 yaraCommand = ("%s %s %s %s" % (settings.yaraExe, yaraParams, settings.yaraRuleFile, settings.inputFileName))
 output = str(subprocess.check_output(yaraCommand, shell=True)).replace("b'","").rstrip()[:-1]
 if settings.inputFileName in output:
  print("MATCH LINE NUMBER %s:" % str(lineNumber))
  print(" LINE: %s" + line)
  print(" YARA:")
  for row in output.split("\\r\\n"):
   if row.startswith("0x"):
    print("   %s" % row)
   else:
    print("  %s" % row)
 lineNumber = lineNumber + 1

lines.close()
