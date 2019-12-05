import os
import subprocess
import traceback
import argparse
import sys

yaraParams = "-s"
tempFileName = "yaraOneLiner.tmp"
lineNumber = 1
output = ""

arguments = argparse.ArgumentParser("yaraOneLine.py -e yara64.exe -f input.csv -r rule.yar")
arguments.add_argument("-e", "--yaraExe", type=str, required=True, help="Yara executable to use") 
arguments.add_argument("-f", "--inputFileName", type=str, required=True, help="Input file to yara scan") 
arguments.add_argument("-r", "--yaraRuleFile", type=str, required=True, help="Yara rule file to scan against")
arguments.add_argument("-d", "--debug", action="store_true", required=False, help="Enable debugging messages")
arguments.add_argument("-s", "--status", action="store_true", required=False, help="Enable status tracking for large files")
settings = arguments.parse_args()

with open(settings.inputFileName, "r") as lines:
 for line in lines:
  line = line.rstrip()
  if settings.debug:
   print("\r\n---\r\nLINE %s: %s" % (str(lineNumber) , line))
  if settings.status:
   if (lineNumber % 50) == 0 and lineNumber != 0:
    print("STATUS: processing line %s" % (str(lineNumber)))
  with open(tempFileName,"w") as tempfile:
   tempfile.write(line)
  try:
   yaraCommand = ("%s %s %s %s" % (settings.yaraExe, yaraParams, settings.yaraRuleFile, tempFileName))
   if settings.debug:
    print("ABOUT TO RUN: %s" % yaraCommand)
   if settings.debug:
    pause = input()
   if settings.debug:
    print("STARTED: YARA")
   output = subprocess.check_output(yaraCommand, shell=True)
   if settings.debug:
    print("OUTPUT: %s" % str(output))
  except Exception as e:
   error = str(e)
   print("COMMAND: %s" % yaraCommand)
   print("OUTPUT: %s" % output)
   print("ERROR: %s" % error)
   output = ""
  if output is None or len(output) == 0:
   if settings.debug:
    print("MATCHES: 0 (no output)")
  else:
   output = str(output).replace("b'","").rstrip()
   if output[-1:] == "'":
    output = output[:-1]
   if tempFileName in output:
    if settings.debug:
     print("MATCHES: 1+")
    print("MATCH LINE NUMBER %s:" % str(lineNumber))
    print(" LINE: %s" + line)
    print(" YARA:")
    for row in output.split("\\r\\n"):
     row = row.replace("\\r\\n", "")
     if row.startswith("0x"):
      print("   %s" % row)
     else:
      print("  %s" % row)
   else:
    print("MATCHES: 0 (with output)")
  lineNumber = lineNumber + 1
