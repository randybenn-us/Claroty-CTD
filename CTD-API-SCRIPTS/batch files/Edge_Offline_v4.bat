@echo off
cls
REM Prompt the user for the password variable
SET /P "output-file-password=Enter the password for the output file: "

REM Prompt the user for the system description
SET /P "system-description=Enter a short system description (e.g., 'HVAC', 'Electric'): "

@Echo Loading Claroty Edge...

REM --- Create Timestamp (HHMMSS) ---
REM %TIME% returns format: HH:MM:SS.xx (e.g., 11:55:37.89)

REM Extract the Hour (HH)
SET "HH=%time:~0,2%"
REM Check if the Hour has a leading space (e.g., " 9" for 9 AM), and remove it
if "%HH%" LSS "10" SET "HH=0%HH: =%"

REM Extract the Minute (MM)
SET "MM=%time:~3,2%"

REM Extract the Second (SS)
SET "SS=%time:~6,2%"

REM Combine for the final timestamp
SET "timestamp=%HH%%MM%%SS%"

REM Construct the output file name using the system description AND the timestamp
REM Example: .\claroty_edge_results_HVAC_115537.results
SET "output-file-base=.\claroty_edge_results"
SET "output-file-name=%output-file-base%_%system-description%_%timestamp%.results"

REM Execute the command using the user-provided variables
REM *** ADDED DOUBLE QUOTES AROUND THE EXECUTABLE ***
".\ClarotyEdge_CTD_Windows_3_11_signed.exe" discover --accept-eula --online no --output-path "%output-file-name%" --output-file-password "%output-file-password%"

pause