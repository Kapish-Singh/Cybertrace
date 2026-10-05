**Mini Incident-Response Investigation Tool** — a C++ cybersecurity investigation simulator built to demonstrate core Data Structures and Object-Oriented Programming concepts.

> Team DSCPP-III-2026-T280

## Overview

CyberTrace analyzes simulated security logs (failed logins, successful logins, privileged access, suspicious file transfers) to reconstruct incident timelines, flag suspicious event sequences, and generate structured investigation reports.

## Objectives

- Store and organize security events efficiently
- Provide fast searching of events and IP addresses
- Reconstruct the chronological timeline of an incident
- Identify suspicious sequences of events
- Calculate a basic risk score
- Maintain investigation history with undo support
- Generate a structured incident report

## Tech stack

C++ (C++11+) 
· custom Linked List 
· custom Hash Table 
· custom Stack 
· GCC 
· VS Code 
· Makefile 
· fstream (file I/O) 
· text/CSV logs 
· console interface

## DSA / OOP concept mapping

| Concept | Application |
|---|---|
| Linked List | Incident event timeline |
| Hash Table | Fast event/IP searching |
| Stack | Investigation history & undo |
| Classes & Objects | Events, incidents, investigators |
| Encapsulation | Protecting event/incident data |
| Abstraction | Hiding internal analysis logic |
| File Handling | Reading simulated log files |



## Project structure

```
CyberTrace/
├── include/          # header files (class declarations)
├── src/               # implementation files
├── logs/              # sample simulated log files
├── docs/              # proposal, architecture diagram, report
├── Makefile
└── README.md
```



## Team

| Name | Student ID |
|---|---|
| Kapish Singh (Lead) | 2510350007 |
| Ushmeet Singh | 2510014223 |
| Sarthak Bhandari | 2510360017 |
| Shourya Bisht | 2510011729 |

## Status

 In development — core implementation in progress.
