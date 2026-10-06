# OpenSSH Log Security Analyzer

#### Video Demo: https://youtu.be/ZZnORu0ShTI

#### Description:

The OpenSSH Log Security Analyzer is a Python-based security analysis tool developed as my final project for CS50's Introduction to Programming with Python (CS50P).

The purpose of this project is to analyze an OpenSSH authentication log and summarize authentication activity by IP address. Instead of manually reading hundreds or thousands of log entries, the program extracts relevant authentication events, groups them by IP address, and calculates a risk score based on several indicators of suspicious activity.

The project was developed using the OpenSSH log file `OpenSSH/OpenSSH_2k.log`. The program is designed around the log patterns found in this type of OpenSSH authentication log rather than attempting to support every possible SSH log format.

For each IP address, the program records the number of failed password attempts, failed `none` authentication attempts, successful password logins, targeted usernames, invalid users, whether the `root` account was targeted, whether a possible break-in attempt was reported, and failed authentication attempts grouped by hour.

### How the Program Works

The program reads the log file one line at a time. The `parse_line` function identifies relevant events and extracts information such as the IP address and username. Regular expressions are used where they make extracting information from the log easier.

The program recognizes several important events, including `Failed password`, `Failed none`, `Accepted password`, `Invalid user`, and `POSSIBLE BREAK-IN ATTEMPT`.

Not every message in an OpenSSH log represents a new authentication attempt. For example, messages such as `Authentication failure`, `Connection closed`, and `Received disconnect` are not counted as separate attempts because they can be related to an authentication event that has already been recorded.

The program also handles OpenSSH messages such as `message repeated N times`. When such a message contains a repeated failed authentication event, the repeated number is added to the corresponding failed authentication count. For example, one original failed password message followed by `message repeated 5 times` is counted as six failed password attempts.

### Risk Analysis

The program calculates a risk score for each IP address using both overall activity and activity within a single hour.

The general risk score considers the total number of failed authentication attempts, the number of different targeted usernames, whether the `root` account was targeted, the number of invalid users, and whether a `POSSIBLE BREAK-IN ATTEMPT` warning was detected.

The program also checks the highest number of failed authentication attempts made by an IP address during a single hour. A high number of failures within a short period can be an indication of automated or brute-force activity, so this contributes additional points to the risk score.

The final score is classified into three levels: `LOW`, `MEDIUM`, and `HIGH`. The program also reports the reasons that contributed to the risk score so that the result is not just a number without explanation.

### Design Choices

One important design decision was to group activity by IP address rather than by SSH process ID (PID). A single SSH connection can produce multiple log messages, and the same PID can therefore be associated with multiple actions within that connection. Using the IP address as the main grouping method makes it more useful for measuring the activity coming from a particular source.

Another design decision was to distinguish between actual authentication attempts and messages that describe or accompany an authentication event. `Failed password` and `Failed none` are counted as failed authentication attempts, while messages such as `Authentication failure`, `input_userauth_request`, `check pass; user unknown`, `Received disconnect`, and `Connection closed` are not counted as independent attempts.

`Invalid user` is treated as an additional security indicator rather than an independent failed authentication attempt. The program records the invalid usernames and also records them as targeted usernames.

The `root` account is treated as a separate risk indicator because it is a high-privilege account. A `POSSIBLE BREAK-IN ATTEMPT` message is also treated as a risk indicator rather than as a new authentication attempt.

For the hourly analysis, the program stores the hour as an integer rather than storing the complete timestamp. This makes it simpler to group failed authentication attempts by hour and find the highest level of activity within a single hour.

### Files

- `project.py` contains the main program and the functions responsible for parsing log entries, extracting the hour, handling repeated messages, storing information for each IP address, calculating risk scores, and generating the final report.

- `test_project.py` contains the `pytest` tests for the custom functions in `project.py`.

- `requirements.txt` contains the external Python libraries required by the project.

- `README.md` contains the documentation for the project and the link to the video demonstration.

- `OpenSSH/OpenSSH_2k.log` is the OpenSSH authentication log used as the input data for the project.

### External Library

The project uses the `rich` library to display the analysis results as a formatted table in the terminal. This makes the output easier to read than printing every result as plain text.

### Running the Program

First, install the required dependencies:

```bash
pip install -r requirements.txt
```

Run unit tests:

```bash
pytest test_project.py
```

Run the analyzer:

```bash
python project.py
```
