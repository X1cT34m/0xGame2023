import string
import sys

class helloOutput:

    def __init__(self, original_stdout):
        self.original_stdout = original_stdout

    def write(self, text):
        self.original_stdout.write("ni hao")

    def flush(self):
        self.original_stdout.write("ni hao")

def check(input):
  if any(i in input for i in ["import", "_", "[", "]", "{", "}", ".", "eval", "exec", "'", "\"", "breakpoint", "help"]):
    print("hacker!!!")
    exit()
  if any(i not in string.printable for i in input):
    print("only ascii!!!")
    exit()

flag = open("flag.txt").read()

yourinput = input(">>> ")
check(yourinput)
original_stdout = sys.stdout
hello_output = helloOutput(original_stdout)
sys.stdout = hello_output
del sys
exec(yourinput)