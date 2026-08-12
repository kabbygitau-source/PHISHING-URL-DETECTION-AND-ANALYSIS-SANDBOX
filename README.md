# PHISHING-URL-DETECTION-AND-ANALYSIS-SANDBOX
Developed a Python-based Phishing URL Analyzer that detects suspicious URL indicators, analyzes redirects, and generates risk scores. Built in Kali Linux using Requests, the project provides hands-on experience in threat detection, security automation, URL analysis, and cybersecurity tool development.
The analyzer checks several URL characteristics, including HTTPS usage, IP addresses, suspicious keywords, URL length, the @ symbol, and hostname structure. It also performs HTTP redirect analysis using the Python Requests library, displaying redirect counts, redirect chains, final URLs, HTTP status codes, and connection errors when a destination cannot be reached. Testing was performed using both legitimate and simulated suspicious URLs to evaluate the system's behavior.

This project demonstrates practical cybersecurity skills in Python programming, URL analysis, HTTP requests, risk assessment, Linux-based development, testing, and troubleshooting. The project was developed as a hands-on cybersecurity learning project and provides a foundation for further development of URL security analysis capabilities. Detailed project documentation and testing evidence are included in the repository.

Technologies Used
Python
Kali Linux
Requests Library
Regular Expressions
Git & GitHub

Project Structure

`
PHISHING-URL-DETECTION-AND-ANALYSIS-SANDBOX
                    │
                    ▼
                    
                  app/
                    │
                  
                    ▼
                    
             url_analyzer.py
                    │
                    ▼
                    
             URL Analysis
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
     HTTPS      IP Address   Keywords
      Check        Check       Check
        │           │           │
        └───────────┼───────────┘
                    ▼
                    
          URL Characteristics
                    │
                    ▼
                    
              Risk Scoring
                    │
                    ▼
                    
           Risk Classification
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
         LOW      MEDIUM      HIGH
                    │
                    ▼
                    
           Redirect Analysis
                    │
                    ▼
                    
             Results Display
                    │
                    ▼
                    
        ┌───────────┼───────────┐
        ▼           ▼           ▼
Documentation   Screenshots   Reports
        │           │           │
        └───────────┼───────────┘
                    ▼
                    
              GitHub Repository
```



Author

Joy Gitau
