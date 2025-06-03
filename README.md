# apache-log-analyzer
A lightweight Python script for parsing Apache access logs to detect suspicious activity.
This project is part of my ongoing cybersecurity learning journey, with a focus on log analysis and threat detection using Python.

---

##  Features

-  Detects repeated **failed login attempts** (HTTP 401/403)
-  Flags **potential scanning behavior** based on request volume
-  Identifies requests to sensitive paths like `/login`, `/admin`, and `/wp-login`
-  Outputs a simple, human-readable incident report
-  Easy to customize and extend (GeoIP, real-time tailing, etc.)
