# CyberTrace – Test Cases

| Test ID | Test Scenario | Expected Result |
|---|---|---|
| TC-01 | Launch the application | Main menu is displayed |
| TC-02 | Select a valid menu option | Corresponding operation is performed |
| TC-03 | Load sample_normal.txt | Normal log records are processed |
| TC-04 | Load sample_attack.txt | Attack-related records are processed |
| TC-05 | Load sample_mixed.txt | Mixed log records are processed |
| TC-06 | Enter a non-existing filename | File-opening error is handled |
| TC-07 | Load an empty log file | Empty file is handled |
| TC-08 | Enter an invalid menu option | Invalid input is handled |
| TC-09 | Process an incomplete log record | Malformed record is handled |
| TC-10 | Process an invalid numeric field | Invalid data is handled |
| TC-11 | Perform event investigation | Investigation results are displayed |
| TC-12 | Generate an investigation report | Report is generated or displayed |
| TC-13 | View the event timeline | Available events are displayed |
| TC-14 | Select the Exit option | Application terminates normally |

## Test Status

All test cases are pending execution. Actual results should be recorded after testing.
