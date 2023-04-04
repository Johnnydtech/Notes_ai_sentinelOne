import requests
import json
import openai
import datetime

class ThreatAnalyzer:
    def __init__(self, openai_key):
        self.openai_key = openai_key
        self.notes = None

    def note_response(self, file_path, originating_process, commandLine_arg):
        openai.api_key = self.openai_key
       # Note: you need to be using OpenAI Python v0.27.0 for the code below to work
        response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
                {"role": "system", "content": "analyzes alerts for malicious content using multiple varaibles from the user."},
                {"role": "user", "content": f"analyze the alert using the filepath, orignating process and command line argument provided {file_path}, {originating_process}, and {commandLine_arg}. If the data is insufficient, just use the filepath to analyze the alert and share you need more info for detailed analysis. Always show the filepath on your response. Additionally, classify the alert into theses groups ,Legitimate, Investigation needed or  Malicious"}    
            ]
        )
        self.notes = response['choices'][0]['message']['content']
        
