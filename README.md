# sdev245-mod8

This Scanner uses a dictionary of popular patterns used in tokens, API keys, Access Keys and passcodes from many popular webpages and services. Each pattern is stored in the dictionary with the key being the type of pattern it is.
I created two separate methods for scanning depending on the type of input given. If the user gives a file then the FileScan() method goes line by line checking for each of the different patterns in the secret pattern set.
If the user enters a directory, then PathScan() will search the directory for all files within it. It will then run FileScan() on each file and add the results to the report.
I used the logging library to create a logger that records when I get errors in openning or finding folders or paths.
The ReportFindings() method makes a stylized report that prints all the findings from the scan.
Scanner() is a method that uses argparse to direct the scan through the various methods built above.
