from django import forms
from rest_framework import serializers
import imaplib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

class LoginForm(forms.Form):
    username = forms.EmailField()
    password = forms.CharField(max_length=50, widget=forms.PasswordInput)

class MailFolderForm(forms.Form):
    options = [
        ('inbox', 'Inbox'),
        ('Gmail/spam', 'Spam'),
    ]
    folder = forms.ChoiceField(choices=options, help_text="From which folder do you want to detect phishing attempts")


#creating a serializer for the imap4 ssl
#i really need the host and port number 

#class ImapSerializer(serializers.Serializer):
    #initialize fields
    #host = serializers.URLField()
    #port = serializers.IntegerField()

def serialize_imap(imap_obj):
    return {
        "host": imap_obj.host,
        "port": imap_obj.port,
        #"timeout": imap_obj.timeout,
        #"is_authenticated": imap_obj.state == 'AUTH'
    }

def deserialize_imap(data, username, password):
    try:
        # Create a new IMAP4_SSL object
        mail = imaplib.IMAP4_SSL(data['host'], data['port'])
        
        # Login to the mailbox
        mail.login(username, password)
        
        logging.info("Successfully deserialized and logged in to the mailbox.")
        return mail
    except imaplib.IMAP4.error as e:
        logging.error(f"Failed to log in: {e}")
        return None


def connect_to_mailbox(email, password, host='imap.gmail.com', port=993):
    try:
        # Connect to the IMAP server
        mail = imaplib.IMAP4_SSL(host, port)
        
        # Login to the mailbox
        mail.login(email, password)
        
        logging.info("Connected and logged in to the mailbox.")
        return mail
    except imaplib.IMAP4.error as e:
        logging.error(f"Failed to connect to the mailbox: {e}")
        return None