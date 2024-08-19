import os
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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Set up logging
logging.basicConfig(filename='debug.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

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
    for tag in soup.find_all(True):
        for attr in ['href', 'src', 'action', 'data', 'link']:
            if tag.has_attr(attr):
                url = tag[attr]
                if isinstance(url, str) and url.strip():
                    urls.add(url)
    return list(urls)

def parse_email_body(body, html_body=None):
    url_pattern = re.compile(r'https?://[^\s\'"()<>]+|www\.[^\s\'"()<>]+', re.IGNORECASE)
    file_patterns = [
        re.compile(r'\b[\w\-\\\/\.]+\.(exe|dll|bat|cmd|sh|bin|msi|scr|pif|application|gadget|cpl|msc|msp|reg|vb|vbs|vbe|js|jse|ws|wsf|wsc|wsh|ps1|ps1xml|ps2|ps2xml|psc1|psc2|msh|msh1|msh2|mshxml|msh1xml|msh2xml|scf|lnk|inf)\b', re.IGNORECASE),
        re.compile(r'\b[\w\-\\\/\.]+\.(py|pyc|pyo|pyw|rb|rbw|pl|pm|php|php3|php4|php5|phps|phtml|htaccess|cgi|asp|aspx|cer|jsp|jsf|jspx|cfm|cfml|cfm|cfc|lua|r|rdata|rs)\b', re.IGNORECASE),
        re.compile(r'\b[\w\-\\\/\.]+\.(doc|docx|xls|xlsx|ppt|pptx|odt|ods|odp|rtf|pdf|txt|csv|tsv|xml|json|yaml|yml|md|html|htm|css|js|scss|sass|less|ini|config|bat|log)\b', re.IGNORECASE)
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
                   (email_data['from'], email_data['subject'], email_data['date'], email_data['body'], email_data['malicious'], email_data['time']))
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
    logging.info(f"Appended email: {email_data['subject']}")

def generate_report(all_emails, filename="email_report.csv"):
    if not all_emails:
        logging.info("No emails to report.")
        return
    output_path = os.path.join(os.getcwd(), filename)
    logging.info(f"Generating report with {len(all_emails)} emails...")
    df = pd.DataFrame(all_emails)
    df.to_csv(output_path, index=False)
    logging.info(f"Report generated: {output_path}")
    return output_path

def send_email_report(filename, recipient_email):
    sender_email = "priyankapolasi206@gmail.com"
    sender_password = os.environ.get("EMAIL_PASSWORD")  # Securely get the password from environment variables

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = recipient_email
    message['Subject'] = "Email Report - Malicious and Non-Malicious Emails"

    body = "Please find attached the report of processed emails."
    message.attach(MIMEText(body, 'plain'))

    with open(filename, "rb") as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {filename}",
        )
        message.attach(part)

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    text = message.as_string()
    server.sendmail(sender_email, recipient_email, text)
    server.quit()
    logging.info(f"Report sent to {recipient_email}")

def get_emails(service, user_id='me', label_ids=['INBOX'], max_results=500):
    results = service.users().messages().list(userId=user_id, labelIds=label_ids, maxResults=max_results).execute()
    messages = results.get('messages', [])

    emails = []
    all_emails = []

    if not messages:
        logging.info('No messages found.')
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
            email_data['exec_files'] = exec_files

            email_data['malicious'] = "0"
            malurls = []
            norurls = []
            for url in urls:
                result = Main.predict_malicious_url(url)
                if result == 1 or len(exec_files) > 0:
                    email_data['malicious'] = "1"
                    malurls.append(url)
                else:
                    norurls.append(url)
            email_data['norurls'] = norurls
            email_data['malurls'] = malurls
            logging.info(json.dumps(email_data, indent=4))
            store_email_data(email_data, norurls, malurls, exec_files, all_emails)
            emails.append(email_data)

    report_path = generate_report(all_emails)
    send_email_report(report_path, "priyankapolasi206@gmail.com")
    return emails

def parse_date(date_str):
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        date = dt.date().strftime('%Y-%m-%d')
        time = dt.time().strftime('%H:%M:%S')
        return date, time
    except Exception as e:
        logging.error(f"Error parsing date: {e}")
        return '', ''

def main():
    logging.info("Current Working Directory: " + os.getcwd())
    service = get_service()
    emails = get_emails(service)
    for email in emails:
        logging.info(json.dumps(email, indent=4))

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise
