import os.path
import base64
import re
import json
import spacy
import mysql.connector
from google.auth.transport.requests import Request
from google.oauth2.credentials import  Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
import Main
import email.utils

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Load spaCy model
nlp = spacy.load("en_core_web_sm")



def get_service():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'clientcredientials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)
    return service


def extract_html_links(html):
    """Extract all URLs from HTML content, including various attributes."""
    soup = BeautifulSoup(html, 'html.parser')
    urls = set()

    # Extract URLs from common attributes
    for tag in soup.find_all(True):  # Find all tags
        for attr in ['href', 'src', 'action', 'data', 'link']:
            if tag.has_attr(attr):
                url = tag[attr]
                if isinstance(url, str) and url.strip():
                    urls.add(url)

    return list(urls)


def parse_email_body(body, html_body=None):
    """Extract URLs and executable file names from the email body."""
    # Regular expression patterns for URLs and file types
    url_pattern = re.compile(r'https?://[^\s\'"()<>]+|www\.[^\s\'"()<>]+', re.IGNORECASE)
    file_patterns = [
        re.compile(r'\b[\w\-\\\/\.]+\.(exe|dll|bat|cmd|sh|bin|msi|scr|pif|application|gadget|cpl|msc|msp|reg|vb|vbs|vbe|js|jse|ws|wsf|wsc|wsh|ps1|ps1xml|ps2|ps2xml|psc1|psc2|msh|msh1|msh2|mshxml|msh1xml|msh2xml|scf|lnk|inf)\b', re.IGNORECASE),
        re.compile(r'\b[\w\-\\\/\.]+\.(py|pyc|pyo|pyw|rb|rbw|pl|pm|php|php3|php4|php5|phps|phtml|htaccess|cgi|asp|aspx|cer|jsp|jsf|jspx|cfm|cfml|cfm|cfc|lua|r|rdata|rs)\b', re.IGNORECASE),
        re.compile(r'\b[\w\-\\\/\.]+\.(doc|docx|xls|xlsx|ppt|pptx|odt|ods|odp|rtf|pdf|txt|csv|tsv|xml|json|yaml|yml|md|html|htm|css|js|scss|sass|less|ini|config|bat|log)\b', re.IGNORECASE)
    ]

    # Tokenize the email body using spaCy
    doc = nlp(body)
    tokens = [token.text for token in doc]

    # Extract URLs and file names
    urls = [token for token in tokens if url_pattern.match(token)]

    # Extract URLs from HTML if available
    if html_body:
        html_urls = extract_html_links(html_body)
        urls.extend(html_urls)

    exec_files = [token for token in tokens if any(pattern.match(token) for pattern in file_patterns)]

    return urls, exec_files

def store_email_data(email_data, urls, malurls, exec_files):
    """Store the email data, URLs, and executable files in the database."""
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="123456789",
        database="Phishing"
    )
    cursor = conn.cursor()

    cursor.execute('''INSERT INTO emails (sender, subject, date, body, malicious,time) 
                      VALUES (%s, %s, %s, %s, %s,%s)''',
                   (email_data['from'], email_data['subject'], email_data['date'], email_data['body'], email_data['malicious'],email_data['time']))
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


def get_emails(service, user_id='me', label_ids=['INBOX'], max_results=500):
    results = service.users().messages().list(userId=user_id, labelIds=label_ids, maxResults=max_results).execute()
    messages = results.get('messages', [])

    emails = []
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
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    elif part['mimeType'] == 'text/html':
                        html_body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                        soup = BeautifulSoup(html_body, 'html.parser')
                        body = soup.get_text()
            else:
                body = base64.urlsafe_b64decode(payload.get('body', {}).get('data', '')).decode('utf-8')

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
            print(json.dumps(email_data, indent=4))
            store_email_data(email_data, norurls, malurls, exec_files)
            emails.append(email_data)

    return emails

def parse_date(date_str):
    try:
        # Parse the date header to extract date and time separately
        dt = email.utils.parsedate_to_datetime(date_str)
        date = dt.date().strftime('%Y-%m-%d')
        time = dt.time().strftime('%H:%M:%S')
        return date, time
    except Exception as e:
        print(f"Error parsing date: {e}")
        return '', ''

def main():
    service = get_service()
    emails = get_emails(service)
    for email in emails:
        print(json.dumps(email, indent=4))


if __name__ == '__main__':
    main()
