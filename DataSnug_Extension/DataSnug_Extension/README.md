# DataSnug Extension — Installation Guide

## Load in Chrome / Edge

1. Open Chrome and go to: chrome://extensions/
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select the DataSnug_Extension folder
5. Done! The shield icon appears in your toolbar.

## What it blocks
- File uploads containing SSN, Credit Cards, Passwords, Aadhaar
- Suspicious filenames (passwords.txt, employee_data.csv, etc.)
- Works on ALL websites: Google Drive, WeTransfer, Gmail, etc.

## Test it
1. Create a file called test.txt with content: SSN: 123-45-6789
2. Try uploading it to any website
3. DataSnug will block it and show a warning overlay
