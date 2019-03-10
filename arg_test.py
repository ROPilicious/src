from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-f", "--file", dest="filename",
                    help="vulnerable executable", metavar="FILE")
parser.add_argument("-l", "--length", dest="length",
                    help="Max number of bytes to traverse above c3", metavar="NUM")
# parser.add_argument("-q", "--quiet",
#                     action="store_false", dest="verbose", default=True,
#                     help="don't print status messages to stdout")

args = parser.parse_args()

vulnExecutable = args.filename

gadgetLength = args.length

if(vulnExecutable== None):
    print("Use the --flag or -f flag to enter the vulnerable executable!")

if(gadgetLength == None):
    print("Use the --length or -l flag to enter the max number of bytes to traverse above c3!")
