# CamShield

## Anti-Spyware Webcam Security System

CamShield is a Python-based webcam security system developed to help monitor webcam activity and improve user privacy. The system uses OpenCV for webcam access and image processing, while maintaining security logs and capturing snapshots of relevant events.

The project is designed as a defensive security application that helps users monitor and document webcam-related activity on their system.

## Features

- Webcam access and real-time monitoring using OpenCV
- Detection and handling of webcam availability
- Snapshot capture during relevant security events
- Security event logging
- Activity logging for monitoring system activity
- Email-based security notification support
- Local storage of captured snapshots and security logs
- Error handling for unavailable or inaccessible webcams
- PyInstaller configuration for building a standalone application

## Technologies Used

- Python
- OpenCV
- SMTP / Email Services
- PyInstaller
- File-based Logging

## How It Works

The application starts by attempting to access the system webcam. Once the webcam is available, CamShield monitors the webcam and handles relevant events.

When a security-related event occurs, the system can capture a snapshot and record information about the event in a security log. Email notification functionality can also be used to notify the user about relevant events.

The overall workflow is:

1. Start the CamShield application.
2. Initialize the webcam using OpenCV.
3. Check whether the webcam is available.
4. Monitor webcam activity.
5. Handle relevant security events.
6. Capture a snapshot when required.
7. Record the event in the security log.
8. Send an email notification when configured.
9. Continue monitoring.

## Project Structure

```text
CamShield/
│
├── main.py
├── main.spec
├── no_camera.jpg
├── Project_Info.pdf
├── README.md
└── .gitignore
```

## Runtime Files

During execution, CamShield may generate runtime files and directories locally.

```text
CamShield/
│
├── snapshots/
│   └── Captured webcam images
│
├── activity_log.txt
│
└── security_logs_*.txt
```

### snapshots/

Stores images captured during relevant security events.

### activity_log.txt

Stores application activity and related event information.

### security_logs_*.txt

Stores security-related events detected during application execution.

These runtime-generated files are excluded from the Git repository using `.gitignore`.

## Installation

### Prerequisites

Before running CamShield, make sure the following are installed:

- Windows operating system
- Python 3.x
- Git
- A working webcam

### 1. Clone the Repository

Clone the repository using:

```bash
git clone https://github.com/USahu25/CamShield.git
```

### 2. Navigate to the Project Directory

```bash
cd CamShield
```

### 3. Create a Virtual Environment

It is recommended to use a virtual environment:

```bash
python -m venv .venv
```

### 4. Activate the Virtual Environment

For Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

For Windows Command Prompt:

```cmd
.venv\Scripts\activate
```

### 5. Install Dependencies

Install OpenCV:

```bash
pip install opencv-python
```

If additional dependencies are required by the current implementation, install them using pip.

## Running the Application

After installing the required dependencies, run:

```bash
python main.py
```

Make sure that:

- A working webcam is connected.
- Camera permissions are enabled.
- Python has permission to access the webcam.
- Required email configuration is available if email notifications are enabled.

## Email Configuration

CamShield supports email-based security notifications.

For security reasons, email credentials should never be hard-coded into the source code or uploaded to GitHub.

The following information must remain private:

- Email passwords
- Application passwords
- API keys
- Authentication tokens
- Other sensitive credentials

Local configuration files containing sensitive information should be excluded from version control using `.gitignore`.

For local execution, configure the required email settings according to the configuration used by the application.

## Logging and Snapshots

CamShield maintains local records of application and security-related events.

### Activity Logs

Activity logs record relevant application activity and events during execution.

### Security Logs

Security logs store information related to security events detected by the application.

### Snapshots

Snapshots can be captured during relevant security events and stored locally in the `snapshots/` directory.

Runtime-generated logs and snapshots are excluded from the public repository.

## Error Handling

CamShield handles common webcam-related problems such as:

- Webcam not detected
- Webcam unavailable
- Webcam access failure
- Invalid camera input
- Runtime errors
- Email configuration issues

The application provides appropriate handling when the webcam cannot be accessed.

## Building the Executable

The repository includes a PyInstaller specification file:

```text
main.spec
```

Install PyInstaller using:

```bash
pip install pyinstaller
```

Build the application using:

```bash
pyinstaller main.spec
```

PyInstaller generates the packaged application files in the `build/` and `dist/` directories.

These generated directories are excluded from the Git repository using `.gitignore`.

## Security and Privacy

CamShield is designed as a defensive privacy and security application.

The project focuses on:

- Monitoring webcam activity
- Recording security events
- Capturing relevant snapshots
- Maintaining local security logs
- Providing optional email notifications

CamShield should only be used on computers and webcams that you own or have explicit permission to monitor.

The application does not attempt to bypass operating-system security mechanisms or obtain unauthorized access to webcams.

Users should also ensure that captured snapshots and security logs are stored securely because they may contain sensitive information.

## Applications

CamShield can be used as a learning and security-awareness project in the following areas:

- Webcam privacy
- Personal computer security
- Cybersecurity monitoring
- Computer vision
- Security event monitoring
- Python application development
- OpenCV-based applications

## Future Enhancements

Potential future improvements include:

- Real-time desktop notifications
- Face recognition for authorized users
- AI-based suspicious activity detection
- Security event dashboard
- Improved event classification
- Encrypted snapshot storage
- Secure cloud-based event storage
- Mobile notifications
- Improved authentication and access control

## Project Documentation

Additional project information is available in the project documentation:

[Project_Info.pdf](Project_Info.pdf)

## Repository

[View CamShield on GitHub](https://github.com/USahu25/CamShield)

## Author

**Sahithi Uppala**

[GitHub Profile](https://github.com/USahu25)
