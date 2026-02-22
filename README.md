# Azxion Admin Panel

A secure license key management system with hardware ID (HWID) locking and library file management capabilities.

## Features

- **License Key Management**
  - Generate keys with configurable durations (1 day to lifetime)
  - Track key status (unused, active, expired, banned)
  - Hardware ID locking with device limit controls
  - Device count reset functionality

- **Library Management**
  - Upload and manage .so library files
  - Version tracking and descriptions
  - Secure file storage with size limits (20 MB max)

- **Admin Interface**
  - Real-time statistics dashboard
  - Searchable key database with status filtering
  - Batch operations for keys and libraries
  - Session-based authentication with configurable timeouts

## Technology Stack

- **Backend**: Python Flask
- **Database**: MongoDB
- **Encryption**: AES-256-GCM
- **Frontend**: HTML, CSS, JavaScript

## Installation

### Prerequisites
- Python 3.8+
- MongoDB instance
- Git

### Setup

1. Clone the repository
```bash
git clone https://github.com/yourusername/azxion-admin.git
cd azxion-admin
