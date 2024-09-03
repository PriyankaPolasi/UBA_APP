import os.path
import base64
import re
import json
import spacy
import mysql.connector
import pandas as pd
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
import Main
import email.utils
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Configure logging
logging.basicConfig(filename='debug.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

# SCOPES for Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Load spaCy model
nlp = spacy.load("en_core_web_sm")


def get_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('clientcredientials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)
    return service


def extract_html_links(html):
    soup = BeautifulSoup(html, 'html.parser')
    urls = set()

    for tag in soup.find_all(True):  # Find all tags
        for attr in ['href', 'src', 'action', 'data', 'link']:
            if tag.has_attr(attr):
                url = tag[attr]
                if isinstance(url, str) and url.strip():
                    urls.add(url)

    return list(urls)


def parse_email_body(body, html_body=None):
    url_pattern = re.compile(r'https?://[^\s\'"()<>]+|www\.[^\s\'"()<>]+', re.IGNORECASE)
    file_patterns = [
        re.compile(
            r'\b[\w\-\\\/\.]+\.(exe|dll|bat|cmd|sh|bin|msi|scr|pif|application|gadget|cpl|msc|msp|reg|vb|vbs|vbe|js|jse|ws|wsf|wsc|wsh|ps1|ps1xml|ps2|ps2xml|psc1|psc2|msh|msh1|msh2|mshxml|msh1xml|msh2xml|scf|lnk|inf)\b',
            re.IGNORECASE),
        re.compile(
            r'\b[\w\-\\\/\.]+\.(py|pyc|pyo|pyw|rb|rbw|pl|pm|php|php3|php4|php5|phps|phtml|htaccess|cgi|asp|aspx|cer|jsp|jsf|jspx|cfm|cfml|cfm|cfc|lua|r|rdata|rs)\b',
            re.IGNORECASE),
        re.compile(
            r'\b[\w\-\\\/\.]+\.(doc|docx|xls|xlsx|ppt|pptx|odt|ods|odp|rtf|pdf|txt|csv|tsv|xml|json|yaml|yml|md|html|htm|css|js|scss|sass|less|ini|config|bat|log)\b',
            re.IGNORECASE)
    ]

    doc = nlp(body)
    tokens = [token.text for token in doc]

    urls = [token for token in tokens if url_pattern.match(token)]

    if html_body:
        html_urls = extract_html_links(html_body)
        urls.extend(html_urls)

    exec_files = [token for token in tokens if any(pattern.match(token) for pattern in file_patterns)]

    return urls, exec_files


def store_email_data(email_data, urls, malurls, exec_files, all_emails):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="123456789",
        database="Phishing"
    )
    cursor = conn.cursor()

    cursor.execute('''INSERT INTO emails (sender, subject, date, body, malicious, time) 
                      VALUES (%s, %s, %s, %s, %s, %s)''',
                   (email_data['from'], email_data['subject'], email_data['date'], email_data['body'],
                    email_data['malicious'], email_data['time']))
    email_id = cursor.lastrowid

    for url in urls:
        cursor.execute('''INSERT INTO urls (email_id, url) 
                          VALUES (%s, %s)''',
                       (email_id, url))

    for url in malurls:
        cursor.execute('''INSERT INTO malurls (email_id, url) 
                          VALUES (%s, %s)''',
                       (email_id, url))

    for exec_file in exec_files:
        cursor.execute('''INSERT INTO exec_files (email_id, file_name) 
                          VALUES (%s, %s)''',
                       (email_id, exec_file))

    conn.commit()
    conn.close()

    all_emails.append(email_data)
    print(f"Appended email: {email_data['subject']}")


def generate_report(all_emails, filename="email_report.csv"):
    if not all_emails:
        print("No emails to report.")
        return

    output_dir = "output"  # Ensure this directory exists or change to a valid path
    output_path = os.path.join(output_dir, filename)

    # Debugging: Confirm directory and path
    print(f"Saving report to: {output_path}")

    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created directory: {output_dir}")

    print(f"Generating report with {len(all_emails)} emails...")
    df = pd.DataFrame(all_emails)
    df.to_csv(output_path, index=False)
    print(f"Report generated: {output_path}")

    # Email the report
    send_email_report(output_path, 'priyankapolasi206@gmail.com')


def send_email_report(filename, recipient_email):
    sender_email = 'priyankapolasi206@gmail.com'
    sender_password = os.environ.get('ABCabc012')  # Ensure this environment variable is set correctly

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = recipient_email
    message['Subject'] = 'Email Report - Malicious and Non-Malicious Emails'

    body = 'Please find attached the report of processed emails.'
    message.attach(MIMEText(body, 'plain'))

    # Attach the report
    with open(filename, 'rb') as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename= {filename}',
        )
        message.attach(part)

    # Send the email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = message.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")


def get_emails(service, user_id='me', label_ids=['INBOX'], max_results=500):
    results = service.users().messages().list(userId=user_id, labelIds=label_ids, maxResults=max_results).execute()
    messages = results.get('messages', [])

    emails = []
    all_emails = []  # To store all processed email data for the report

    if not messages:
        print('No messages found.')
    else:
        for message in messages:
            msg = service.users().messages().get(userId=user_id, id=message['id']).execute()
            payload = msg['payload']
            headers = payload['headers']
            parts = payload.get('parts', [])

            email_data = {}
            for header in headers:
                if header['name'] == 'From':
                    email_data['from'] = header['value']
                if header['name'] == 'Subject':
                    email_data['subject'] = header['value']
                if header['name'] == 'Date':
                    email_date = header['value']
                    email_data['date'], email_data['time'] = parse_date(email_date)

            body = ''
            html_body = ''
            if parts:
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        if 'data' in part['body']:
                            body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    elif part['mimeType'] == 'text/html':
                        if 'data' in part['body']:
                            html_body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                            soup = BeautifulSoup(html_body, 'html.parser')
                            body = soup.get_text()
            else:
                if 'data' in payload.get('body', {}):
                    body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')

            urls, exec_files = parse_email_body(body, html_body if html_body else None)
            email_data['body'] = body
            email_data['urls'] = urls
            email_data['exec_files'] = exec
